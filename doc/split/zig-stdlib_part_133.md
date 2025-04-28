```
Size,
    alwaysinline,
    builtin,
    cold,
    convergent,
    disable_sanitizer_information,
    fn_ret_thunk_extern,
    hot,
    inlinehint,
    jumptable,
    memory: Memory,
    minsize,
    naked,
    nobuiltin,
    nocallback,
    noduplicate,
    //nofree,
    noimplicitfloat,
    @"noinline",
    nomerge,
    nonlazybind,
    noprofile,
    skipprofile,
    noredzone,
    noreturn,
    norecurse,
    willreturn,
    nosync,
    nounwind,
    nosanitize_bounds,
    nosanitize_coverage,
    null_pointer_is_valid,
    optforfuzzing,
    optnone,
    optsize,
    //preallocated: Type,
    returns_twice,
    safestack,
    sanitize_address,
    sanitize_memory,
    sanitize_thread,
    sanitize_hwaddress,
    sanitize_memtag,
    speculative_load_hardening,
    speculatable,
    ssp,
    sspstrong,
    sspreq,
    strictfp,
    uwtable: UwTable,
    nocf_check,
    shadowcallstack,
    mustprogress,
    vscale_range: VScaleRange,

    // Global Attributes
    no_sanitize_address,
    no_sanitize_hwaddress,
    //sanitize_memtag,
    sanitize_address_dyninit,

    string: struct { kind: String, value: String },
    none: noreturn,

    pub const Index = enum(u32) {
        _,

        pub fn getKind(self: Index, builder: *const Builder) Kind {
            return self.toStorage(builder).kind;
        }

        pub fn toAttribute(self: Index, builder: *const Builder) Attribute {
            @setEvalBranchQuota(2_000);
            const storage = self.toStorage(builder);
            if (storage.kind.toString()) |kind| return .{ .string = .{
                .kind = kind,
                .value = @enumFromInt(storage.value),
            } } else return switch (storage.kind) {
                inline .zeroext,
                .signext,
                .inreg,
                .byval,
                .byref,
                .preallocated,
                .inalloca,
                .sret,
                .elementtype,
                .@"align",
                .@"noalias",
                .nocapture,
                .nofree,
                .nest,
                .returned,
                .nonnull,
                .dereferenceable,
                .dereferenceable_or_null,
                .swiftself,
                .swiftasync,
                .swifterror,
                .immarg,
                .noundef,
                .nofpclass,
                .alignstack,
                .allocalign,
                .allocptr,
                .readnone,
                .readonly,
                .writeonly,
                //.alignstack,
                .allockind,
                .allocsize,
                .alwaysinline,
                .builtin,
                .cold,
                .convergent,
                .disable_sanitizer_information,
                .fn_ret_thunk_extern,
                .hot,
                .inlinehint,
                .jumptable,
                .memory,
                .minsize,
                .naked,
                .nobuiltin,
                .nocallback,
                .noduplicate,
                //.nofree,
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
                //.preallocated,
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
                .uwtable,
                .nocf_check,
                .shadowcallstack,
                .mustprogress,
                .vscale_range,
                .no_sanitize_address,
                .no_sanitize_hwaddress,
                .sanitize_address_dyninit,
                => |kind| {
                    const field = comptime blk: {
                        @setEvalBranchQuota(10_000);
                        for (@typeInfo(Attribute).@"union".fields) |field| {
                            if (std.mem.eql(u8, field.name, @tagName(kind))) break :blk field;
                        }
                        unreachable;
                    };
                    comptime assert(std.mem.eql(u8, @tagName(kind), field.name));
                    return @unionInit(Attribute, field.name, switch (field.type) {
                        void => {},
                        u32 => storage.value,
                        Alignment, String, Type, UwTable => @enumFromInt(storage.value),
                        AllocKind, AllocSize, FpClass, Memory, VScaleRange => @bitCast(storage.value),
                        else => @compileError("bad payload type: " ++ field.name ++ ": " ++
                            @typeName(field.type)),
                    });
                },
                .string, .none => unreachable,
                _ => unreachable,
            };
        }

        const FormatData = struct {
            attribute_index: Index,
            builder: *const Builder,
        };
        fn format(
            data: FormatData,
            comptime fmt_str: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            if (comptime std.mem.indexOfNone(u8, fmt_str, "\"#")) |_|
                @compileError("invalid format string: '" ++ fmt_str ++ "'");
            const attribute = data.attribute_index.toAttribute(data.builder);
            switch (attribute) {
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
                => try writer.print(" {s}", .{@tagName(attribute)}),
                .byval,
                .byref,
                .preallocated,
                .inalloca,
                .sret,
                .elementtype,
                => |ty| try writer.print(" {s}({%})", .{ @tagName(attribute), ty.fmt(data.builder) }),
                .@"align" => |alignment| try writer.print("{ }", .{alignment}),
                .dereferenceable,
                .dereferenceable_or_null,
                => |size| try writer.print(" {s}({d})", .{ @tagName(attribute), size }),
                .nofpclass => |fpclass| {
                    const Int = @typeInfo(FpClass).@"struct".backing_integer.?;
                    try writer.print(" {s}(", .{@tagName(attribute)});
                    var any = false;
                    var remaining: Int = @bitCast(fpclass);
                    inline for (@typeInfo(FpClass).@"struct".decls) |decl| {
                        const pattern: Int = @bitCast(@field(FpClass, decl.name));
                        if (remaining & pattern == pattern) {
                            if (!any) {
                                try writer.writeByte(' ');
                                any = true;
                            }
                            try writer.writeAll(decl.name);
                            remaining &= ~pattern;
                        }
                    }
                    try writer.writeByte(')');
                },
                .alignstack => |alignment| try writer.print(
                    if (comptime std.mem.indexOfScalar(u8, fmt_str, '#') != null)
                        " {s}={d}"
                    else
                        " {s}({d})",
                    .{ @tagName(attribute), alignment.toByteUnits() orelse return },
                ),
                .allockind => |allockind| {
                    try writer.print(" {s}(\"", .{@tagName(attribute)});
                    var any = false;
                    inline for (@typeInfo(AllocKind).@"struct".fields) |field| {
                        if (comptime std.mem.eql(u8, field.name, "_")) continue;
                        if (@field(allockind, field.name)) {
                            if (!any) {
                                try writer.writeByte(',');
                                any = true;
                            }
                            try writer.writeAll(field.name);
                        }
                    }
                    try writer.writeAll("\")");
                },
                .allocsize => |allocsize| {
                    try writer.print(" {s}({d}", .{ @tagName(attribute), allocsize.elem_size });
                    if (allocsize.num_elems != AllocSize.none)
                        try writer.print(",{d}", .{allocsize.num_elems});
                    try writer.writeByte(')');
                },
                .memory => |memory| {
                    try writer.print(" {s}(", .{@tagName(attribute)});
                    var any = memory.other != .none or
                        (memory.argmem == .none and memory.inaccessiblemem == .none);
                    if (any) try writer.writeAll(@tagName(memory.other));
                    inline for (.{ "argmem", "inaccessiblemem" }) |kind| {
                        if (@field(memory, kind) != memory.other) {
                            if (any) try writer.writeAll(", ");
                            try writer.print("{s}: {s}", .{ kind, @tagName(@field(memory, kind)) });
                            any = true;
                        }
                    }
                    try writer.writeByte(')');
                },
                .uwtable => |uwtable| if (uwtable != .none) {
                    try writer.print(" {s}", .{@tagName(attribute)});
                    if (uwtable != UwTable.default) try writer.print("({s})", .{@tagName(uwtable)});
                },
                .vscale_range => |vscale_range| try writer.print(" {s}({d},{d})", .{
                    @tagName(attribute),
                    vscale_range.min.toByteUnits().?,
                    vscale_range.max.toByteUnits() orelse 0,
                }),
                .string => |string_attr| if (comptime std.mem.indexOfScalar(u8, fmt_str, '"') != null) {
                    try writer.print(" {\"}", .{string_attr.kind.fmt(data.builder)});
                    if (string_attr.value != .empty)
                        try writer.print("={\"}", .{string_attr.value.fmt(data.builder)});
                },
                .none => unreachable,
            }
        }
        pub fn fmt(self: Index, builder: *const Builder) std.fmt.Formatter(format) {
            return .{ .data = .{ .attribute_index = self, .builder = builder } };
        }

        fn toStorage(self: Index, builder: *const Builder) Storage {
            return builder.attributes.keys()[@intFromEnum(self)];
        }
    };

    pub const Kind = enum(u32) {
        // Parameter Attributes
        zeroext = 34,
        signext = 24,
        inreg = 5,
        byval = 3,
        byref = 69,
        preallocated = 65,
        inalloca = 38,
        sret = 29, // TODO: ?
        elementtype = 77,
        @"align" = 1,
        @"noalias" = 9,
        nocapture = 11,
        nofree = 62,
        nest = 8,
        returned = 22,
        nonnull = 39,
        dereferenceable = 41,
        dereferenceable_or_null = 42,
        swiftself = 46,
        swiftasync = 75,
        swifterror = 47,
        immarg = 60,
        noundef = 68,
        nofpclass = 87,
        alignstack = 25,
        allocalign = 80,
        allocptr = 81,
        readnone = 20,
        readonly = 21,
        writeonly = 52,

        // Function Attributes
        //alignstack,
        allockind = 82,
        allocsize = 51,
        alwaysinline = 2,
        builtin = 35,
        cold = 36,
        convergent = 43,
        disable_sanitizer_information = 78,
        fn_ret_thunk_extern = 84,
        hot = 72,
        inlinehint = 4,
        jumptable = 40,
        memory = 86,
        minsize = 6,
        naked = 7,
        nobuiltin = 10,
        nocallback = 71,
        noduplicate = 12,
        //nofree,
        noimplicitfloat = 13,
        @"noinline" = 14,
        nomerge = 66,
        nonlazybind = 15,
        noprofile = 73,
        skipprofile = 85,
        noredzone = 16,
        noreturn = 17,
        norecurse = 48,
        willreturn = 61,
        nosync = 63,
        nounwind = 18,
        nosanitize_bounds = 79,
        nosanitize_coverage = 76,
        null_pointer_is_valid = 67,
        optforfuzzing = 57,
        optnone = 37,
        optsize = 19,
        //preallocated,
        returns_twice = 23,
        safestack = 44,
        sanitize_address = 30,
        sanitize_memory = 32,
        sanitize_thread = 31,
        sanitize_hwaddress = 55,
        sanitize_memtag = 64,
        speculative_load_hardening = 59,
        speculatable = 53,
        ssp = 26,
        sspstrong = 28,
        sspreq = 27,
        strictfp = 54,
        uwtable = 33,
        nocf_check = 56,
        shadowcallstack = 58,
        mustprogress = 70,
        vscale_range = 74,

        // Global Attributes
        no_sanitize_address = 100,
        no_sanitize_hwaddress = 101,
        //sanitize_memtag,
        sanitize_address_dyninit = 102,

        string = std.math.maxInt(u31),
        none = std.math.maxInt(u32),
        _,

        pub const len = @typeInfo(Kind).@"enum".fields.len - 2;

        pub fn fromString(str: String) Kind {
            assert(!str.isAnon());
            const kind: Kind = @enumFromInt(@intFromEnum(str));
            assert(kind != .none);
            return kind;
        }

        fn toString(self: Kind) ?String {
            assert(self != .none);
            const str: String = @enumFromInt(@intFromEnum(self));
            return if (str.isAnon()) null else str;
        }
    };

    pub const FpClass = packed struct(u32) {
        signaling_nan: bool = false,
        quiet_nan: bool = false,
        negative_infinity: bool = false,
        negative_normal: bool = false,
        negative_subnormal: bool = false,
        negative_zero: bool = false,
        positive_zero: bool = false,
        positive_subnormal: bool = false,
        positive_normal: bool = false,
        positive_infinity: bool = false,
        _: u22 = 0,

        pub const all = FpClass{
            .signaling_nan = true,
            .quiet_nan = true,
            .negative_infinity = true,
            .negative_normal = true,
            .negative_subnormal = true,
            .negative_zero = true,
            .positive_zero = true,
            .positive_subnormal = true,
            .positive_normal = true,
            .positive_infinity = true,
        };

        pub const nan = FpClass{ .signaling_nan = true, .quiet_nan = true };
        pub const snan = FpClass{ .signaling_nan = true };
        pub const qnan = FpClass{ .quiet_nan = true };

        pub const inf = FpClass{ .negative_infinity = true, .positive_infinity = true };
        pub const ninf = FpClass{ .negative_infinity = true };
        pub const pinf = FpClass{ .positive_infinity = true };

        pub const zero = FpClass{ .positive_zero = true, .negative_zero = true };
        pub const nzero = FpClass{ .negative_zero = true };
        pub const pzero = FpClass{ .positive_zero = true };

        pub const sub = FpClass{ .positive_subnormal = true, .negative_subnormal = true };
        pub const nsub = FpClass{ .negative_subnormal = true };
        pub const psub = FpClass{ .positive_subnormal = true };

        pub const norm = FpClass{ .positive_normal = true, .negative_normal = true };
        pub const nnorm = FpClass{ .negative_normal = true };
        pub const pnorm = FpClass{ .positive_normal = true };
    };

    pub const AllocKind = packed struct(u32) {
        alloc: bool,
        realloc: bool,
        free: bool,
        uninitialized: bool,
        zeroed: bool,
        aligned: bool,
        _: u26 = 0,
    };

    pub const AllocSize = packed struct(u32) {
        elem_size: u16,
        num_elems: u16,

        pub const none = std.math.maxInt(u16);

        fn toLlvm(self: AllocSize) packed struct(u64) { num_elems: u32, elem_size: u32 } {
            return .{ .num_elems = switch (self.num_elems) {
                else => self.num_elems,
                none => std.math.maxInt(u32),
            }, .elem_size = self.elem_size };
        }
    };

    pub const Memory = packed struct(u32) {
        argmem: Effect = .none,
        inaccessiblemem: Effect = .none,
        other: Effect = .none,
        _: u26 = 0,

        pub const Effect = enum(u2) { none, read, write, readwrite };

        fn all(effect: Effect) Memory {
            return .{ .argmem = effect, .inaccessiblemem = effect, .other = effect };
        }
    };

    pub const UwTable = enum(u32) {
        none,
        sync,
        @"async",

        pub const default = UwTable.@"async";
    };

    pub const VScaleRange = packed struct(u32) {
        min: Alignment,
        max: Alignment,
        _: u20 = 0,

        fn toLlvm(self: VScaleRange) packed struct(u64) { max: u32, min: u32 } {
            return .{
                .max = @intCast(self.max.toByteUnits() orelse 0),
                .min = @intCast(self.min.toByteUnits().?),
            };
        }
    };

    pub fn getKind(self: Attribute) Kind {
        return switch (self) {
            else => self,
            .string => |string_attr| Kind.fromString(string_attr.kind),
        };
    }

    const Storage = extern struct {
        kind: Kind,
        value: u32,
    };

    fn toStorage(self: Attribute) Storage {
        return switch (self) {
            inline else => |value, tag| .{ .kind = @as(Kind, self), .value = switch (@TypeOf(value)) {
                void => 0,
                u32 => value,
                Alignment, String, Type, UwTable => @intFromEnum(value),
                AllocKind, AllocSize, FpClass, Memory, VScaleRange => @bitCast(value),
                else => @compileError("bad payload type: " ++ @tagName(tag) ++ @typeName(@TypeOf(value))),
            } },
            .string => |string_attr| .{
                .kind = Kind.fromString(string_attr.kind),
                .value = @intFromEnum(string_attr.value),
            },
            .none => unreachable,
        };
    }
};

pub const Attributes = enum(u32) {
    none,
    _,

    pub fn slice(self: Attributes, builder: *const Builder) []const Attribute.Index {
        const start = builder.attributes_indices.items[@intFromEnum(self)];
        const end = builder.attributes_indices.items[@intFromEnum(self) + 1];
        return @ptrCast(builder.attributes_extra.items[start..end]);
    }

    const FormatData = struct {
        attributes: Attributes,
        builder: *const Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        fmt_opts: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        for (data.attributes.slice(data.builder)) |attribute_index| try Attribute.Index.format(.{
            .attribute_index = attribute_index,
            .builder = data.builder,
        }, fmt_str, fmt_opts, writer);
    }
    pub fn fmt(self: Attributes, builder: *const Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .attributes = self, .builder = builder } };
    }
};

pub const FunctionAttributes = enum(u32) {
    none,
    _,

    const function_index = 0;
    const return_index = 1;
    const params_index = 2;

    pub const Wip = struct {
        maps: Maps = .{},

        const Map = std.AutoArrayHashMapUnmanaged(Attribute.Kind, Attribute.Index);
        const Maps = std.ArrayListUnmanaged(Map);

        pub fn deinit(self: *Wip, builder: *const Builder) void {
            for (self.maps.items) |*map| map.deinit(builder.gpa);
            self.maps.deinit(builder.gpa);
            self.* = undefined;
        }

        pub fn addFnAttr(self: *Wip, attribute: Attribute, builder: *Builder) Allocator.Error!void {
            try self.addAttr(function_index, attribute, builder);
        }

        pub fn addFnAttrIndex(
            self: *Wip,
            attribute_index: Attribute.Index,
            builder: *const Builder,
        ) Allocator.Error!void {
            try self.addAttrIndex(function_index, attribute_index, builder);
        }

        pub fn removeFnAttr(self: *Wip, attribute_kind: Attribute.Kind) Allocator.Error!bool {
            return self.removeAttr(function_index, attribute_kind);
        }

        pub fn addRetAttr(self: *Wip, attribute: Attribute, builder: *Builder) Allocator.Error!void {
            try self.addAttr(return_index, attribute, builder);
        }

        pub fn addRetAttrIndex(
            self: *Wip,
            attribute_index: Attribute.Index,
            builder: *const Builder,
        ) Allocator.Error!void {
            try self.addAttrIndex(return_index, attribute_index, builder);
        }

        pub fn removeRetAttr(self: *Wip, attribute_kind: Attribute.Kind) Allocator.Error!bool {
            return self.removeAttr(return_index, attribute_kind);
        }

        pub fn addParamAttr(
            self: *Wip,
            param_index: usize,
            attribute: Attribute,
            builder: *Builder,
        ) Allocator.Error!void {
            try self.addAttr(params_index + param_index, attribute, builder);
        }

        pub fn addParamAttrIndex(
            self: *Wip,
            param_index: usize,
            attribute_index: Attribute.Index,
            builder: *const Builder,
        ) Allocator.Error!void {
            try self.addAttrIndex(params_index + param_index, attribute_index, builder);
        }

        pub fn removeParamAttr(
            self: *Wip,
            param_index: usize,
            attribute_kind: Attribute.Kind,
        ) Allocator.Error!bool {
            return self.removeAttr(params_index + param_index, attribute_kind);
        }

        pub fn finish(self: *const Wip, builder: *Builder) Allocator.Error!FunctionAttributes {
            const attributes = try builder.gpa.alloc(Attributes, self.maps.items.len);
            defer builder.gpa.free(attributes);
            for (attributes, self.maps.items) |*attribute, map|
                attribute.* = try builder.attrs(map.values());
            return builder.fnAttrs(attributes);
        }

        fn addAttr(
            self: *Wip,
            index: usize,
            attribute: Attribute,
            builder: *Builder,
        ) Allocator.Error!void {
            const map = try self.getOrPutMap(builder.gpa, index);
            try map.put(builder.gpa, attribute.getKind(), try builder.attr(attribute));
        }

        fn addAttrIndex(
            self: *Wip,
            index: usize,
            attribute_index: Attribute.Index,
            builder: *const Builder,
        ) Allocator.Error!void {
            const map = try self.getOrPutMap(builder.gpa, index);
            try map.put(builder.gpa, attribute_index.getKind(builder), attribute_index);
        }

        fn removeAttr(self: *Wip, index: usize, attribute_kind: Attribute.Kind) Allocator.Error!bool {
            const map = self.getMap(index) orelse return false;
            return map.swapRemove(attribute_kind);
        }

        fn getOrPutMap(self: *Wip, allocator: Allocator, index: usize) Allocator.Error!*Map {
            if (index >= self.maps.items.len)
                try self.maps.appendNTimes(allocator, .{}, index + 1 - self.maps.items.len);
            return &self.maps.items[index];
        }

        fn getMap(self: *Wip, index: usize) ?*Map {
            return if (index >= self.maps.items.len) null else &self.maps.items[index];
        }

        fn ensureTotalLength(self: *Wip, new_len: usize) Allocator.Error!void {
            try self.maps.appendNTimes(
                .{},
                std.math.sub(usize, new_len, self.maps.items.len) catch return,
            );
        }
    };

    pub fn func(self: FunctionAttributes, builder: *const Builder) Attributes {
        return self.get(function_index, builder);
    }

    pub fn ret(self: FunctionAttributes, builder: *const Builder) Attributes {
        return self.get(return_index, builder);
    }

    pub fn param(self: FunctionAttributes, param_index: usize, builder: *const Builder) Attributes {
        return self.get(params_index + param_index, builder);
    }

    pub fn toWip(self: FunctionAttributes, builder: *const Builder) Allocator.Error!Wip {
        var wip: Wip = .{};
        errdefer wip.deinit(builder);
        const attributes_slice = self.slice(builder);
        try wip.maps.ensureTotalCapacityPrecise(builder.gpa, attributes_slice.len);
        for (attributes_slice) |attributes| {
            const map = wip.maps.addOneAssumeCapacity();
            map.* = .{};
            const attribute_slice = attributes.slice(builder);
            try map.ensureTotalCapacity(builder.gpa, attribute_slice.len);
            for (attributes.slice(builder)) |attribute|
                map.putAssumeCapacityNoClobber(attribute.getKind(builder), attribute);
        }
        return wip;
    }

    fn get(self: FunctionAttributes, index: usize, builder: *const Builder) Attributes {
        const attribute_slice = self.slice(builder);
        return if (index < attribute_slice.len) attribute_slice[index] else .none;
    }

    fn slice(self: FunctionAttributes, builder: *const Builder) []const Attributes {
        const start = builder.attributes_indices.items[@intFromEnum(self)];
        const end = builder.attributes_indices.items[@intFromEnum(self) + 1];
        return @ptrCast(builder.attributes_extra.items[start..end]);
    }
};

pub const Linkage = enum(u4) {
    private = 9,
    internal = 3,
    weak = 1,
    weak_odr = 10,
    linkonce = 4,
    linkonce_odr = 11,
    available_externally = 12,
    appending = 2,
    common = 8,
    extern_weak = 7,
    external = 0,

    pub fn format(
        self: Linkage,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .external) try writer.print(" {s}", .{@tagName(self)});
    }

    fn formatOptional(
        data: ?Linkage,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (data) |linkage| try writer.print(" {s}", .{@tagName(linkage)});
    }
    pub fn fmtOptional(self: ?Linkage) std.fmt.Formatter(formatOptional) {
        return .{ .data = self };
    }
};

pub const Preemption = enum {
    dso_preemptable,
    dso_local,
    implicit_dso_local,

    pub fn format(
        self: Preemption,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self == .dso_local) try writer.print(" {s}", .{@tagName(self)});
    }
};

pub const Visibility = enum(u2) {
    default = 0,
    hidden = 1,
    protected = 2,

    pub fn format(
        self: Visibility,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .default) try writer.print(" {s}", .{@tagName(self)});
    }
};

pub const DllStorageClass = enum(u2) {
    default = 0,
    dllimport = 1,
    dllexport = 2,

    pub fn format(
        self: DllStorageClass,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .default) try writer.print(" {s}", .{@tagName(self)});
    }
};

pub const ThreadLocal = enum(u3) {
    default = 0,
    generaldynamic = 1,
    localdynamic = 2,
    initialexec = 3,
    localexec = 4,

    pub fn format(
        self: ThreadLocal,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self == .default) return;
        try writer.print("{s}thread_local", .{prefix});
        if (self != .generaldynamic) try writer.print("({s})", .{@tagName(self)});
    }
};

pub const Mutability = enum { global, constant };

pub const UnnamedAddr = enum(u2) {
    default = 0,
    unnamed_addr = 1,
    local_unnamed_addr = 2,

    pub fn format(
        self: UnnamedAddr,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .default) try writer.print(" {s}", .{@tagName(self)});
    }
};

pub const AddrSpace = enum(u24) {
    default,
    _,

    // See llvm/lib/Target/X86/X86.h
    pub const x86 = struct {
        pub const gs: AddrSpace = @enumFromInt(256);
        pub const fs: AddrSpace = @enumFromInt(257);
        pub const ss: AddrSpace = @enumFromInt(258);

        pub const ptr32_sptr: AddrSpace = @enumFromInt(270);
        pub const ptr32_uptr: AddrSpace = @enumFromInt(271);
        pub const ptr64: AddrSpace = @enumFromInt(272);
    };
    pub const x86_64 = x86;

    // See llvm/lib/Target/AVR/AVR.h
    pub const avr = struct {
        pub const data: AddrSpace = @enumFromInt(0);
        pub const program: AddrSpace = @enumFromInt(1);
        pub const program1: AddrSpace = @enumFromInt(2);
        pub const program2: AddrSpace = @enumFromInt(3);
        pub const program3: AddrSpace = @enumFromInt(4);
        pub const program4: AddrSpace = @enumFromInt(5);
        pub const program5: AddrSpace = @enumFromInt(6);
    };

    // See llvm/lib/Target/NVPTX/NVPTX.h
    pub const nvptx = struct {
        pub const generic: AddrSpace = @enumFromInt(0);
        pub const global: AddrSpace = @enumFromInt(1);
        pub const constant: AddrSpace = @enumFromInt(2);
        pub const shared: AddrSpace = @enumFromInt(3);
        pub const param: AddrSpace = @enumFromInt(4);
        pub const local: AddrSpace = @enumFromInt(5);
    };

    // See llvm/lib/Target/AMDGPU/AMDGPU.h
    pub const amdgpu = struct {
        pub const flat: AddrSpace = @enumFromInt(0);
        pub const global: AddrSpace = @enumFromInt(1);
        pub const region: AddrSpace = @enumFromInt(2);
        pub const local: AddrSpace = @enumFromInt(3);
        pub const constant: AddrSpace = @enumFromInt(4);
        pub const private: AddrSpace = @enumFromInt(5);
        pub const constant_32bit: AddrSpace = @enumFromInt(6);
        pub const buffer_fat_pointer: AddrSpace = @enumFromInt(7);
        pub const buffer_resource: AddrSpace = @enumFromInt(8);
        pub const buffer_strided_pointer: AddrSpace = @enumFromInt(9);
        pub const param_d: AddrSpace = @enumFromInt(6);
        pub const param_i: AddrSpace = @enumFromInt(7);
        pub const constant_buffer_0: AddrSpace = @enumFromInt(8);
        pub const constant_buffer_1: AddrSpace = @enumFromInt(9);
        pub const constant_buffer_2: AddrSpace = @enumFromInt(10);
        pub const constant_buffer_3: AddrSpace = @enumFromInt(11);
        pub const constant_buffer_4: AddrSpace = @enumFromInt(12);
        pub const constant_buffer_5: AddrSpace = @enumFromInt(13);
        pub const constant_buffer_6: AddrSpace = @enumFromInt(14);
        pub const constant_buffer_7: AddrSpace = @enumFromInt(15);
        pub const constant_buffer_8: AddrSpace = @enumFromInt(16);
        pub const constant_buffer_9: AddrSpace = @enumFromInt(17);
        pub const constant_buffer_10: AddrSpace = @enumFromInt(18);
        pub const constant_buffer_11: AddrSpace = @enumFromInt(19);
        pub const constant_buffer_12: AddrSpace = @enumFromInt(20);
        pub const constant_buffer_13: AddrSpace = @enumFromInt(21);
        pub const constant_buffer_14: AddrSpace = @enumFromInt(22);
        pub const constant_buffer_15: AddrSpace = @enumFromInt(23);
        pub const streamout_register: AddrSpace = @enumFromInt(128);
    };

    pub const spirv = struct {
        pub const function: AddrSpace = @enumFromInt(0);
        pub const cross_workgroup: AddrSpace = @enumFromInt(1);
        pub const uniform_constant: AddrSpace = @enumFromInt(2);
        pub const workgroup: AddrSpace = @enumFromInt(3);
        pub const generic: AddrSpace = @enumFromInt(4);
        pub const device_only_intel: AddrSpace = @enumFromInt(5);
        pub const host_only_intel: AddrSpace = @enumFromInt(6);
        pub const input: AddrSpace = @enumFromInt(7);
    };

    // See llvm/include/llvm/CodeGen/WasmAddressSpaces.h
    pub const wasm = struct {
        pub const default: AddrSpace = @enumFromInt(0);
        pub const variable: AddrSpace = @enumFromInt(1);
        pub const externref: AddrSpace = @enumFromInt(10);
        pub const funcref: AddrSpace = @enumFromInt(20);
    };

    pub fn format(
        self: AddrSpace,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self != .default) try writer.print("{s}addrspace({d})", .{ prefix, @intFromEnum(self) });
    }
};

pub const ExternallyInitialized = enum {
    default,
    externally_initialized,

    pub fn format(
        self: ExternallyInitialized,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (self == .default) return;
        try writer.writeByte(' ');
        try writer.writeAll(@tagName(self));
    }
};

pub const Alignment = enum(u6) {
    default = std.math.maxInt(u6),
    _,

    pub fn fromByteUnits(bytes: u64) Alignment {
        if (bytes == 0) return .default;
        assert(std.math.isPowerOfTwo(bytes));
        assert(bytes <= 1 << 32);
        return @enumFromInt(@ctz(bytes));
    }

    pub fn toByteUnits(self: Alignment) ?u64 {
        return if (self == .default) null else @as(u64, 1) << @intFromEnum(self);
    }

    pub fn toLlvm(self: Alignment) u6 {
        return if (self == .default) 0 else (@intFromEnum(self) + 1);
    }

    pub fn format(
        self: Alignment,
        comptime prefix: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        try writer.print("{s}align {d}", .{ prefix, self.toByteUnits() orelse return });
    }
};

pub const CallConv = enum(u10) {
    ccc,

    fastcc = 8,
    coldcc,
    ghccc,

    webkit_jscc = 12,
    anyregcc,
    preserve_mostcc,
    preserve_allcc,
    swiftcc,
    cxx_fast_tlscc,
    tailcc,
    cfguard_checkcc,
    swifttailcc,

    x86_stdcallcc = 64,
    x86_fastcallcc,
    arm_apcscc,
    arm_aapcscc,
    arm_aapcs_vfpcc,
    msp430_intrcc,
    x86_thiscallcc,
    ptx_kernel,
    ptx_device,

    spir_func = 75,
    spir_kernel,
    intel_ocl_bicc,
    x86_64_sysvcc,
    win64cc,
    x86_vectorcallcc,
    hhvmcc,
    hhvm_ccc,
    x86_intrcc,
    avr_intrcc,
    avr_signalcc,
    avr_builtincc,

    amdgpu_vs = 87,
    amdgpu_gs,
    amdgpu_ps,
    amdgpu_cs,
    amdgpu_kernel,
    x86_regcallcc,
    amdgpu_hs,
    msp430_builtincc,

    amdgpu_ls = 95,
    amdgpu_es,
    aarch64_vector_pcs,
    aarch64_sve_vector_pcs,

    amdgpu_gfx = 100,

    m68k_intrcc,

    aarch64_sme_preservemost_from_x0 = 102,
    aarch64_sme_preservemost_from_x2,

    m68k_rtdcc = 106,

    riscv_vectorcallcc = 110,

    _,

    pub const default = CallConv.ccc;

    pub fn format(
        self: CallConv,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        switch (self) {
            default => {},
            .fastcc,
            .coldcc,
            .ghccc,
            .webkit_jscc,
            .anyregcc,
            .preserve_mostcc,
            .preserve_allcc,
            .swiftcc,
            .cxx_fast_tlscc,
            .tailcc,
            .cfguard_checkcc,
            .swifttailcc,
            .x86_stdcallcc,
            .x86_fastcallcc,
            .arm_apcscc,
            .arm_aapcscc,
            .arm_aapcs_vfpcc,
            .msp430_intrcc,
            .x86_thiscallcc,
            .ptx_kernel,
            .ptx_device,
            .spir_func,
            .spir_kernel,
            .intel_ocl_bicc,
            .x86_64_sysvcc,
            .win64cc,
            .x86_vectorcallcc,
            .hhvmcc,
            .hhvm_ccc,
            .x86_intrcc,
            .avr_intrcc,
            .avr_signalcc,
            .avr_builtincc,
            .amdgpu_vs,
            .amdgpu_gs,
            .amdgpu_ps,
            .amdgpu_cs,
            .amdgpu_kernel,
            .x86_regcallcc,
            .amdgpu_hs,
            .msp430_builtincc,
            .amdgpu_ls,
            .amdgpu_es,
            .aarch64_vector_pcs,
            .aarch64_sve_vector_pcs,
            .amdgpu_gfx,
            .m68k_intrcc,
            .aarch64_sme_preservemost_from_x0,
            .aarch64_sme_preservemost_from_x2,
            .m68k_rtdcc,
            .riscv_vectorcallcc,
            => try writer.print(" {s}", .{@tagName(self)}),
            _ => try writer.print(" cc{d}", .{@intFromEnum(self)}),
        }
    }
};

pub const StrtabString = enum(u32) {
    none = std.math.maxInt(u31),
    empty,
    _,

    pub fn isAnon(self: StrtabString) bool {
        assert(self != .none);
        return self.toIndex() == null;
    }

    pub fn slice(self: StrtabString, builder: *const Builder) ?[]const u8 {
        const index = self.toIndex() orelse return null;
        const start = builder.strtab_string_indices.items[index];
        const end = builder.strtab_string_indices.items[index + 1];
        return builder.strtab_string_bytes.items[start..end];
    }

    const FormatData = struct {
        string: StrtabString,
        builder: *const Builder,
    };
    fn format(
        data: FormatData,
        comptime fmt_str: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (comptime std.mem.indexOfNone(u8, fmt_str, "\"r")) |_|
            @compileError("invalid format string: '" ++ fmt_str ++ "'");
        assert(data.string != .none);
        const string_slice = data.string.slice(data.builder) orelse
            return writer.print("{d}", .{@intFromEnum(data.string)});
        if (comptime std.mem.indexOfScalar(u8, fmt_str, 'r')) |_|
            return writer.writeAll(string_slice);
        try printEscapedString(
            string_slice,
            if (comptime std.mem.indexOfScalar(u8, fmt_str, '"')) |_|
                .always_quote
            else
                .quote_unless_valid_identifier,
            writer,
        );
    }
    pub fn fmt(self: StrtabString, builder: *const Builder) std.fmt.Formatter(format) {
        return .{ .data = .{ .string = self, .builder = builder } };
    }

    fn fromIndex(index: ?usize) StrtabString {
        return @enumFromInt(@as(u32, @intCast((index orelse return .none) +
            @intFromEnum(StrtabString.empty))));
    }

    fn toIndex(self: StrtabString) ?usize {
        return std.math.sub(u32, @intFromEnum(self), @intFromEnum(StrtabString.empty)) catch null;
    }

    const Adapter = struct {
        builder: *const Builder,
        pub fn hash(_: Adapter, key: []const u8) u32 {
            return @truncate(std.hash.Wyhash.hash(0, key));
        }
        pub fn eql(ctx: Adapter, lhs_key: []const u8, _: void, rhs_index: usize) bool {
            return std.mem.eql(u8, lhs_key, StrtabString.fromIndex(rhs_index).slice(ctx.builder).?);
        }
    };
};

pub fn strtabString(self: *Builder, bytes: []const u8) Allocator.Error!StrtabString {
    try self.strtab_string_bytes.ensureUnusedCapacity(self.gpa, bytes.len);
    try self.strtab_string_indices.ensureUnusedCapacity(self.gpa, 1);
    try self.strtab_string_map.ensureUnusedCapacity(self.gpa, 1);

    const gop = self.strtab_string_map.getOrPutAssumeCapacityAdapted(bytes, StrtabString.Adapter{ .builder = self });
    if (!gop.found_existing) {
        self.strtab_string_bytes.appendSliceAssumeCapacity(bytes);
        self.strtab_string_indices.appendAssumeCapacity(@intCast(self.strtab_string_bytes.items.len));
    }
    return StrtabString.fromIndex(gop.index);
}

pub fn strtabStringIfExists(self: *const Builder, bytes: []const u8) ?StrtabString {
    return StrtabString.fromIndex(
        self.strtab_string_map.getIndexAdapted(bytes, StrtabString.Adapter{ .builder = self }) orelse return null,
    );
}

pub fn strtabStringFmt(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) Allocator.Error!StrtabString {
    try self.strtab_string_map.ensureUnusedCapacity(self.gpa, 1);
    try self.strtab_string_bytes.ensureUnusedCapacity(self.gpa, @intCast(std.fmt.count(fmt_str, fmt_args)));
    try self.strtab_string_indices.ensureUnusedCapacity(self.gpa, 1);
    return self.strtabStringFmtAssumeCapacity(fmt_str, fmt_args);
}

pub fn strtabStringFmtAssumeCapacity(self: *Builder, comptime fmt_str: []const u8, fmt_args: anytype) StrtabString {
    self.strtab_string_bytes.writer(undefined).print(fmt_str, fmt_args) catch unreachable;
    return self.trailingStrtabStringAssumeCapacity();
}

pub fn trailingStrtabString(self: *Builder) Allocator.Error!StrtabString {
    try self.strtab_string_indices.ensureUnusedCapacity(self.gpa, 1);
    try self.strtab_string_map.ensureUnusedCapacity(self.gpa, 1);
    return self.trailingStrtabStringAssumeCapacity();
}

pub fn trailingStrtabStringAssumeCapacity(self: *Builder) StrtabString {
    const start = self.strtab_string_indices.getLast();
    const bytes: []const u8 = self.strtab_string_bytes.items[start..];
    const gop = self.strtab_string_map.getOrPutAssumeCapacityAdapted(bytes, StrtabString.Adapter{ .builder = self });
    if (gop.found_existing) {
        self.strtab_string_bytes.shrinkRetainingCapacity(start);
    } else {
        self.strtab_string_indices.appendAssumeCapacity(@intCast(self.strtab_string_bytes.items.len));
    }
    return StrtabString.fromIndex(gop.index);
}

pub const Global = struct {
    linkage: Linkage = .external,
    preemption: Preemption = .dso_preemptable,
    visibility: Visibility = .default,
    dll_storage_class: DllStorageClass = .default,
    unnamed_addr: UnnamedAddr = .default,
    addr_space: AddrSpace = .default,
    externally_initialized: ExternallyInitialized = .default,
    type: Type,
    partition: String = .none,
    dbg: Metadata = .none,
    kind: union(enum) {
        alias: Alias.Index,
        variable: Variable.Index,
        function: Function.Index,
        replaced: Global.Index,
    },

    pub const Index = enum(u32) {
        none = std.math.maxInt(u32),
        _,

        pub fn unwrap(self: Index, builder: *const Builder) Index {
            var cur = self;
            while (true) {
                const replacement = cur.getReplacement(builder);
                if (replacement == .none) return cur;
                cur = replacement;
            }
        }

        pub fn eql(self: Index, other: Index, builder: *const Builder) bool {
            return self.unwrap(builder) == other.unwrap(builder);
        }

        pub fn ptr(self: Index, builder: *Builder) *Global {
            return &builder.globals.values()[@intFromEnum(self.unwrap(builder))];
        }

        pub fn ptrConst(self: Index, builder: *const Builder) *const Global {
            return &builder.globals.values()[@intFromEnum(self.unwrap(builder))];
        }

        pub fn name(self: Index, builder: *const Builder) StrtabString {
            return builder.globals.keys()[@intFromEnum(self.unwrap(builder))];
        }

        pub fn strtab(self: Index, builder: *const Builder) struct {
            offset: u32,
            size: u32,
        } {
            const name_index = self.name(builder).toIndex() orelse return .{
                .offset = 0,
                .size = 0,
            };

            return .{
                .offset = builder.strtab_string_indices.items[name_index],
                .size = builder.strtab_string_indices.items[name_index + 1] -
                    builder.strtab_string_indices.items[name_index],
            };
        }

        pub fn typeOf(self: Index, builder: *const Builder) Type {
            return self.ptrConst(builder).type;
        }

        pub fn toConst(self: Index) Constant {
            return @enumFromInt(@intFromEnum(Constant.first_global) + @intFromEnum(self));
        }

        pub fn setLinkage(self: Index, linkage: Linkage, builder: *Builder) void {
            self.ptr(builder).linkage = linkage;
            self.updateDsoLocal(builder);
        }

        pub fn setVisibility(self: Index, visibility: Visibility, builder: *Builder) void {
            self.ptr(builder).visibility = visibility;
            self.updateDsoLocal(builder);
        }

        pub fn setDllStorageClass(self: Index, class: DllStorageClass, builder: *Builder) void {
            self.ptr(builder).dll_storage_class = class;
        }

        pub fn setUnnamedAddr(self: Index, unnamed_addr: UnnamedAddr, builder: *Builder) void {
            self.ptr(builder).unnamed_addr = unnamed_addr;
        }

        pub fn setDebugMetadata(self: Index, dbg: Metadata, builder: *Builder) void {
            self.ptr(builder).dbg = dbg;
        }

        const FormatData = struct {
            global: Index,
            builder: *const Builder,
        };
        fn format(
            data: FormatData,
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            try writer.print("@{}", .{
                data.global.unwrap(data.builder).name(data.builder).fmt(data.builder),
            });
        }
        pub fn fmt(self: Index, builder: *const Builder) std.fmt.Formatter(format) {
            return .{ .data = .{ .global = self, .builder = builder } };
        }

        pub fn rename(self: Index, new_name: StrtabString, builder: *Builder) Allocator.Error!void {
            try builder.ensureUnusedGlobalCapacity(new_name);
            self.renameAssumeCapacity(new_name, builder);
        }

        pub fn takeName(self: Index, other: Index, builder: *Builder) Allocator.Error!void {
            try builder.ensureUnusedGlobalCapacity(.empty);
            self.takeNameAssumeCapacity(other, builder);
        }

        pub fn replace(self: Index, other: Index, builder: *Builder) Allocator.Error!void {
            try builder.ensureUnusedGlobalCapacity(.empty);
            self.replaceAssumeCapacity(other, builder);
        }

        pub fn delete(self: Index, builder: *Builder) void {
            self.ptr(builder).kind = .{ .replaced = .none };
        }

        fn updateDsoLocal(self: Index, builder: *Builder) void {
            const self_ptr = self.ptr(builder);
            switch (self_ptr.linkage) {
                .private, .internal => {
                    self_ptr.visibility = .default;
                    self_ptr.dll_storage_class = .default;
                    self_ptr.preemption = .implicit_dso_local;
                },
                .extern_weak => if (self_ptr.preemption == .implicit_dso_local) {
                    self_ptr.preemption = .dso_local;
                },
                else => switch (self_ptr.visibility) {
                    .default => if (self_ptr.preemption == .implicit_dso_local) {
                        self_ptr.preemption = .dso_local;
                    },
                    else => self_ptr.preemption = .implicit_dso_local,
                },
            }
        }

        fn renameAssumeCapacity(self: Index, new_name: StrtabString, builder: *Builder) void {
            const old_name = self.name(builder);
            if (new_name == old_name) return;
            const index = @intFromEnum(self.unwrap(builder));
            _ = builder.addGlobalAssumeCapacity(new_name, builder.globals.values()[index]);
            builder.globals.swapRemoveAt(index);
            if (!old_name.isAnon()) return;
            builder.next_unnamed_global = @enumFromInt(@intFromEnum(builder.next_unnamed_global) - 1);
            if (builder.next_unnamed_global == old_name) return;
            builder.getGlobal(builder.next_unnamed_global).?.renameAssumeCapacity(old_name, builder);
        }

        fn takeNameAssumeCapacity(self: Index, other: Index, builder: *Builder) void {
            const other_name = other.name(builder);
            other.renameAssumeCapacity(.empty, builder);
            self.renameAssumeCapacity(other_name, builder);
        }

        fn replaceAssumeCapacity(self: Index, other: Index, builder: *Builder) void {
            if (self.eql(other, builder)) return;
            builder.next_replaced_global = @enumFromInt(@intFromEnum(builder.next_replaced_global) - 1);
            self.renameAssumeCapacity(builder.next_replaced_global, builder);
            self.ptr(builder).kind = .{ .replaced = other.unwrap(builder) };
        }

        fn getReplacement(self: Index, builder: *const Builder) Index {
            return switch (builder.globals.values()[@intFromEnum(self)].kind) {
                .replaced => |replacement| replacement,
                else => .none,
            };
        }
    };
};

pub const Alias = struct {
    global: Global.Index,
    thread_local: ThreadLocal = .default,
    aliasee: Constant = .no_init,

    pub const Index = enum(u32) {
        none = std.math.maxInt(u32),
        _,

        pub fn ptr(self: Index, builder: *Builder) *Alias {
            return &builder.aliases.items[@intFromEnum(self)];
        }

        pub fn ptrConst(self: Index, builder: *const Builder) *const Alias {
            return &builder.aliases.items[@intFromEnum(self)];
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

        pub fn getAliasee(self: Index, builder: *const Builder) Global.Index {
            const aliasee = self.ptrConst(builder).aliasee.getBase(builder);
            assert(aliasee != .none);
            return aliasee;
        }

        pub fn setAliasee(self: Index, aliasee: Constant, builder: *Builder) void {
            self.ptr(builder).aliasee = aliasee;
        }
    };
};

pub const Variable = struct {
    global: Global.Index,
    thread_local: ThreadLocal = .default,
    mutability: Mutability = .global,
    init: Constant = .no_init,
    section: String = .none,
    alignment: Alignment = .default,

    pub const Index = enum(u32) {
        none = std.math.maxInt(u32),
        _,

        pub fn ptr(self: Index, builder: *Builder) *Variable {
            return &builder.variables.items[@intFromEnum(self)];
        }

        pub fn ptrConst(self: Index, builder: *const Builder) *const Variable {
            return &builder.variables.items[@intFromEnum(self)];
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

        pub fn setDllStorageClass(self: Index, class: DllStorageClass, builder: *Builder) void {
            return self.ptrConst(builder).global.setDllStorageClass(class, builder);
        }

        pub fn setUnnamedAddr(self: Index, unnamed_addr: UnnamedAddr, builder: *Builder) void {
            return self.ptrConst(builder).global.setUnnamedAddr(unnamed_addr, builder);
        }

        pub fn setThreadLocal(self: Index, thread_local: ThreadLocal, builder: *Builder) void {
            self.ptr(builder).thread_local = thread_local;
        }

        pub fn setMutability(self: Index, mutability: Mutability, builder: *Builder) void {
            self.ptr(builder).mutability = mutability;
        }

        pub fn setInitializer(
            self: Index,
            initializer: Constant,
            builder: *Builder,
        ) Allocator.Error!void {
            if (initializer != .no_init) {
                const variable = self.ptrConst(builder);
                const global = variable.global.ptr(builder);
                const initializer_type = initializer.typeOf(builder);
                global.type = initializer_type;
            }
            self.ptr(builder).init = initializer;
        }

        pub fn setSection(self: Index, section: String, builder: *Builder) void {
            self.ptr(builder).section = section;
        }

        pub fn setAlignment(self: Index, alignment: Alignment, builder: *Builder) void {
            self.ptr(builder).alignment = alignment;
        }

        pub fn getAlignment(self: Index, builder: *Builder) Alignment {
            return self.ptr(builder).alignment;
        }

        pub fn setGlobalVariableExpression(self: Index, expression: Metadata, builder: *Builder) void {
            self.ptrConst(builder).global.setDebugMetadata(expression, builder);
        }
    };
};

pub const Intrinsic = enum {
    // Variable Argument Handling
    va_start,
    va_end,
    va_copy,

    // Code Generator
    returnaddress,
    addressofreturnaddress,
    sponentry,
    frameaddress,
    prefetch,
    @"thread.pointer",

    // Standard C/C++ Library
    abs,
    smax,
    smin,
    umax,
    umin,
    memcpy,
    @"memcpy.inline",
    memmove,
    memset,
    @"memset.inline",
    sqrt,
    powi,
    sin,
    cos,
    pow,
    exp,
    exp10,
    exp2,
    ldexp,
    frexp,
    log,
    log10,
    log2,
    fma,
    fabs,
    minnum,
    maxnum,
    minimum,
    maximum,
    copysign,
    floor,
    ceil,
    trunc,
    rint,
    nearbyint,
    round,
    roundeven,
    lround,
    llround,
    lrint,
    llrint,

    // Bit Manipulation
    bitreverse,
    bswap,
    ctpop,
    ctlz,
    cttz,
    fshl,
    fshr,

    // Arithmetic with Overflow
    @"sadd.with.overflow",
    @"uadd.with.overflow",
    @"ssub.with.overflow",
    @"usub.with.overflow",
    @"smul.with.overflow",
    @"umul.with.overflow",

    // Saturation Arithmetic
    @"sadd.sat",
    @"uadd.sat",
    @"ssub.sat",
    @"usub.sat",
    @"sshl.sat",
    @"ushl.sat",

    // Fixed Point Arithmetic
    @"smul.fix",
    @"umul.fix",
    @"smul.fix.sat",
    @"umul.fix.sat",
    @"sdiv.fix",
    @"udiv.fix",
    @"sdiv.fix.sat",
    @"udiv.fix.sat",

    // Specialised Arithmetic
    canonicalize,
    fmuladd,

    // Vector Reduction
    @"vector.reduce.add",
    @"vector.reduce.fadd",
    @"vector.reduce.mul",
    @"vector.reduce.fmul",
    @"vector.reduce.and",
    @"vector.reduce.or",
    @"vector.reduce.xor",
    @"vector.reduce.smax",
    @"vector.reduce.smin",
    @"vector.reduce.umax",
    @"vector.reduce.umin",
    @"vector.reduce.fmax",
    @"vector.reduce.fmin",
    @"vector.reduce.fmaximum",
    @"vector.reduce.fminimum",
    @"vector.insert",
    @"vector.extract",

    // Floating-Point Test
    @"is.fpclass",

    // General
    @"var.annotation",
    @"ptr.annotation",
    annotation,
    @"codeview.annotation",
    trap,
    debugtrap,
    ubsantrap,
    stackprotector,
    stackguard,
    objectsize,
    expect,
    @"expect.with.probability",
    assume,
    @"ssa.copy",
    @"type.test",
    @"type.checked.load",
    @"type.checked.load.relative",
    @"arithmetic.fence",
    donothing,
    @"load.relative",
    sideeffect,
    @"is.constant",
    ptrmask,
    @"threadlocal.address",
    vscale,

    // Debug
    @"dbg.declare",
    @"dbg.value",

    // AMDGPU
    @"amdgcn.workitem.id.x",
    @"amdgcn.workitem.id.y",
    @"amdgcn.workitem.id.z",
    @"amdgcn.workgroup.id.x",
    @"amdgcn.workgroup.id.y",
    @"amdgcn.workgroup.id.z",
    @"amdgcn.dispatch.ptr",

    // NVPTX
    @"nvvm.read.ptx.sreg.tid.x",
    @"nvvm.read.ptx.sreg.tid.y",
    @"nvvm.read.ptx.sreg.tid.z",
    @"nvvm.read.ptx.sreg.ntid.x",
    @"nvvm.read.ptx.sreg.ntid.y",
    @"nvvm.read.ptx.sreg.ntid.z",
    @"nvvm.read.ptx.sreg.ctaid.x",
    @"nvvm.read.ptx.sreg.ctaid.y",
    @"nvvm.read.ptx.sreg.ctaid.z",

    // WebAssembly
    @"wasm.memory.size",
    @"wasm.memory.grow",

    const Signature = struct {
        ret_len: u8,
        params: []const Parameter,
        attrs: []const Attribute = &.{},

        const Parameter = struct {
            kind: Kind,
            attrs: []const Attribute = &.{},

            const Kind = union(enum) {
                type: Type,
                overloaded,
                matches: u8,
                matches_scalar: u8,
                matches_changed_scalar: struct {
                    index: u8,
                    scalar: Type,
                },
            };
        };
    };

    const signatures = std.enums.EnumArray(Intrinsic, Signature).init(.{
        .va_start = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },
        .va_end = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },
        .va_copy = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },

        .returnaddress = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .addressofreturnaddress = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .sponentry = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .frameaddress = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .prefetch = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .nocapture, .readonly } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.readwrite) } },
        },
        .@"thread.pointer" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .abs = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .smax = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .smin = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .umax = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .umin = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .memcpy = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .@"noalias", .nocapture, .writeonly } },
                .{ .kind = .overloaded, .attrs = &.{ .@"noalias", .nocapture, .readonly } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nounwind, .willreturn, .{ .memory = .{ .argmem = .readwrite } } },
        },
        .@"memcpy.inline" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .@"noalias", .nocapture, .writeonly } },
                .{ .kind = .overloaded, .attrs = &.{ .@"noalias", .nocapture, .readonly } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nounwind, .willreturn, .{ .memory = .{ .argmem = .readwrite } } },
        },
        .memmove = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .nocapture, .writeonly } },
                .{ .kind = .overloaded, .attrs = &.{ .nocapture, .readonly } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nounwind, .willreturn, .{ .memory = .{ .argmem = .readwrite } } },
        },
        .memset = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .nocapture, .writeonly } },
                .{ .kind = .{ .type = .i8 } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nounwind, .willreturn, .{ .memory = .{ .argmem = .write } } },
        },
        .@"memset.inline" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded, .attrs = &.{ .nocapture, .writeonly } },
                .{ .kind = .{ .type = .i8 } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nounwind, .willreturn, .{ .memory = .{ .argmem = .write } } },
        },
        .sqrt = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .powi = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .sin = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .cos = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .pow = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .exp = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .exp2 = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .exp10 = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .ldexp = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .frexp = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .log = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .log10 = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .log2 = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .fma = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .fabs = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .minnum = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .maxnum = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .minimum = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .maximum = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .copysign = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .floor = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .ceil = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .trunc = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .rint = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .nearbyint = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .round = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .roundeven = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .lround = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .llround = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .lrint = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .llrint = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .bitreverse = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .bswap = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .ctpop = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .ctlz = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .cttz = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .fshl = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .fshr = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"sadd.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"uadd.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"ssub.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"usub.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"smul.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"umul.with.overflow" = .{
            .ret_len = 2,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 0, .scalar = .i1 } } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"sadd.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"uadd.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"ssub.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"usub.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"sshl.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"ushl.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"smul.fix" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"umul.fix" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"smul.fix.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"umul.fix.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"sdiv.fix" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"udiv.fix" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"sdiv.fix.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"udiv.fix.sat" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .canonicalize = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .fmuladd = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .{ .matches = 0 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"vector.reduce.add" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fadd" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 2 } },
                .{ .kind = .{ .matches_scalar = 2 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.mul" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fmul" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 2 } },
                .{ .kind = .{ .matches_scalar = 2 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.and" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.or" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.xor" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.smax" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.smin" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.umax" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.umin" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fmax" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fmin" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fmaximum" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.reduce.fminimum" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_scalar = 1 } },
                .{ .kind = .overloaded },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.insert" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i64 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },
        .@"vector.extract" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i64 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"is.fpclass" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .matches_changed_scalar = .{ .index = 1, .scalar = .i1 } } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i32 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .speculatable, .willreturn, .{ .memory = Attribute.Memory.all(.none) } },
        },

        .@"var.annotation" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 1 } },
                .{ .kind = .{ .type = .i32 } },
                .{ .kind = .{ .matches = 1 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .readwrite } } },
        },
        .@"ptr.annotation" = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 2 } },
                .{ .kind = .{ .type = .i32 } },
                .{ .kind = .{ .matches = 2 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .readwrite } } },
        },
        .annotation = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 0 } },
                .{ .kind = .overloaded },
                .{ .kind = .{ .matches = 2 } },
                .{ .kind = .{ .type = .i32 } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .readwrite } } },
        },
        .@"codeview.annotation" = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .metadata } },
            },
            .attrs = &.{ .nocallback, .noduplicate, .nofree, .nosync, .nounwind, .willreturn, .{ .memory = .{ .inaccessiblemem = .readwrite } } },
        },
        .trap = .{
            .ret_len = 0,
            .params = &.{},
            .attrs = &.{ .cold, .noreturn, .nounwind, .{ .memory = .{ .inaccessiblemem = .write } } },
        },
        .debugtrap = .{
            .ret_len = 0,
            .params = &.{},
            .attrs = &.{.nounwind},
        },
        .ubsantrap = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .i8 }, .attrs = &.{.immarg} },
            },
            .attrs = &.{ .cold, .noreturn, .nounwind },
        },
        .stackprotector = .{
            .ret_len = 0,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
                .{ .kind = .{ .type = .ptr } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },
        .stackguard = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .{ .type = .ptr } },
            },
            .attrs = &.{ .nocallback, .nofree, .nosync, .nounwind, .willreturn },
        },
        .objectsize = .{
            .ret_len = 1,
            .params = &.{
                .{ .kind = .overloaded },
                .{ .kind = .overloaded },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
                .{ .kind = .{ .type = .i1 }, .attrs = &.{.immarg} },
                .{ .kind```
