```
    .default_value_ptr = null,
            .is_comptime = false,
            .alignment = 0,
        };
    }

    return @Type(.{
        .@"struct" = .{
            .is_tuple = true,
            .layout = .auto,
            .decls = &.{},
            .fields = &tuple_fields,
        },
    });
}

const TupleTester = struct {
    fn assertTypeEqual(comptime Expected: type, comptime Actual: type) void {
        if (Expected != Actual)
            @compileError("Expected type " ++ @typeName(Expected) ++ ", but got type " ++ @typeName(Actual));
    }

    fn assertTuple(comptime expected: anytype, comptime Actual: type) void {
        const info = @typeInfo(Actual);
        if (info != .@"struct")
            @compileError("Expected struct type");
        if (!info.@"struct".is_tuple)
            @compileError("Struct type must be a tuple type");

        const fields_list = std.meta.fields(Actual);
        if (expected.len != fields_list.len)
            @compileError("Argument count mismatch");

        inline for (fields_list, 0..) |fld, i| {
            if (expected[i] != fld.type) {
                @compileError("Field " ++ fld.name ++ " expected to be type " ++ @typeName(expected[i]) ++ ", but was type " ++ @typeName(fld.type));
            }
        }
    }
};

test ArgsTuple {
    TupleTester.assertTuple(.{}, ArgsTuple(fn () void));
    TupleTester.assertTuple(.{u32}, ArgsTuple(fn (a: u32) []const u8));
    TupleTester.assertTuple(.{ u32, f16 }, ArgsTuple(fn (a: u32, b: f16) noreturn));
    TupleTester.assertTuple(.{ u32, f16, []const u8, void }, ArgsTuple(fn (a: u32, b: f16, c: []const u8, void) noreturn));
    TupleTester.assertTuple(.{u32}, ArgsTuple(fn (comptime a: u32) []const u8));
}

test Tuple {
    TupleTester.assertTuple(.{}, Tuple(&[_]type{}));
    TupleTester.assertTuple(.{u32}, Tuple(&[_]type{u32}));
    TupleTester.assertTuple(.{ u32, f16 }, Tuple(&[_]type{ u32, f16 }));
    TupleTester.assertTuple(.{ u32, f16, []const u8, void }, Tuple(&[_]type{ u32, f16, []const u8, void }));
}

test "Tuple deduplication" {
    const T1 = std.meta.Tuple(&.{ u32, f32, i8 });
    const T2 = std.meta.Tuple(&.{ u32, f32, i8 });
    const T3 = std.meta.Tuple(&.{ u32, f32, i7 });

    if (T1 != T2) {
        @compileError("std.meta.Tuple doesn't deduplicate tuple types.");
    }
    if (T1 == T3) {
        @compileError("std.meta.Tuple fails to generate different types.");
    }
}

test "ArgsTuple forwarding" {
    const T1 = std.meta.Tuple(&.{ u32, f32, i8 });
    const T2 = std.meta.ArgsTuple(fn (u32, f32, i8) void);
    const T3 = std.meta.ArgsTuple(fn (u32, f32, i8) callconv(.c) noreturn);

    if (T1 != T2) {
        @compileError("std.meta.ArgsTuple produces different types than std.meta.Tuple");
    }
    if (T1 != T3) {
        @compileError("std.meta.ArgsTuple produces different types for the same argument lists.");
    }
}

/// Returns whether `error_union` contains an error.
pub fn isError(error_union: anytype) bool {
    return if (error_union) |_| false else |_| true;
}

test isError {
    try std.testing.expect(isError(math.divTrunc(u8, 5, 0)));
    try std.testing.expect(!isError(math.divTrunc(u8, 5, 5)));
}

/// Returns true if a type has a namespace and the namespace contains `name`;
/// `false` otherwise. Result is always comptime-known.
pub inline fn hasFn(comptime T: type, comptime name: []const u8) bool {
    switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => {},
        else => return false,
    }
    if (!@hasDecl(T, name))
        return false;

    return @typeInfo(@TypeOf(@field(T, name))) == .@"fn";
}

test hasFn {
    const S1 = struct {
        pub fn foo() void {}
    };

    try std.testing.expect(hasFn(S1, "foo"));
    try std.testing.expect(!hasFn(S1, "bar"));
    try std.testing.expect(!hasFn(*S1, "foo"));

    const S2 = struct {
        foo: fn () void,
    };

    try std.testing.expect(!hasFn(S2, "foo"));
}

/// Returns true if a type has a `name` method; `false` otherwise.
/// Result is always comptime-known.
pub inline fn hasMethod(comptime T: type, comptime name: []const u8) bool {
    return switch (@typeInfo(T)) {
        .pointer => |P| switch (P.size) {
            .one => hasFn(P.child, name),
            .many, .slice, .c => false,
        },
        else => hasFn(T, name),
    };
}

test hasMethod {
    try std.testing.expect(!hasMethod(u32, "foo"));
    try std.testing.expect(!hasMethod([]u32, "len"));
    try std.testing.expect(!hasMethod(struct { u32, u64 }, "len"));

    const S1 = struct {
        pub fn foo() void {}
    };

    try std.testing.expect(hasMethod(S1, "foo"));
    try std.testing.expect(hasMethod(*S1, "foo"));

    try std.testing.expect(!hasMethod(S1, "bar"));
    try std.testing.expect(!hasMethod(*[1]S1, "foo"));
    try std.testing.expect(!hasMethod(*[10]S1, "foo"));
    try std.testing.expect(!hasMethod([]S1, "foo"));

    const S2 = struct {
        foo: fn () void,
    };

    try std.testing.expect(!hasMethod(S2, "foo"));

    const U = union {
        pub fn foo() void {}
    };

    try std.testing.expect(hasMethod(U, "foo"));
    try std.testing.expect(hasMethod(*U, "foo"));
    try std.testing.expect(!hasMethod(U, "bar"));
}

/// True if every value of the type `T` has a unique bit pattern representing it.
/// In other words, `T` has no unused bits and no padding.
/// Result is always comptime-known.
pub inline fn hasUniqueRepresentation(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        else => false, // TODO can we know if it's true for some of these types ?

        .@"anyframe",
        .@"enum",
        .error_set,
        .@"fn",
        => true,

        .bool => false,

        .int => |info| @sizeOf(T) * 8 == info.bits,

        .pointer => |info| info.size != .slice,

        .optional => |info| switch (@typeInfo(info.child)) {
            .pointer => |ptr| !ptr.is_allowzero and switch (ptr.size) {
                .slice, .c => false,
                .one, .many => true,
            },
            else => false,
        },

        .array => |info| hasUniqueRepresentation(info.child),

        .@"struct" => |info| {
            if (info.layout == .@"packed") return @sizeOf(T) * 8 == @bitSizeOf(T);

            var sum_size = @as(usize, 0);

            inline for (info.fields) |field| {
                if (field.is_comptime) continue;
                if (!hasUniqueRepresentation(field.type)) return false;
                sum_size += @sizeOf(field.type);
            }

            return @sizeOf(T) == sum_size;
        },

        .vector => |info| hasUniqueRepresentation(info.child) and
            @sizeOf(T) == @sizeOf(info.child) * info.len,
    };
}

test hasUniqueRepresentation {
    const TestStruct1 = struct {
        a: u32,
        b: u32,
    };

    try testing.expect(hasUniqueRepresentation(TestStruct1));

    const TestStruct2 = struct {
        a: u32,
        b: u16,
    };

    try testing.expect(!hasUniqueRepresentation(TestStruct2));

    const TestStruct3 = struct {
        a: u32,
        b: u32,
    };

    try testing.expect(hasUniqueRepresentation(TestStruct3));

    const TestStruct4 = struct { a: []const u8 };

    try testing.expect(!hasUniqueRepresentation(TestStruct4));

    const TestStruct5 = struct { a: TestStruct4 };

    try testing.expect(!hasUniqueRepresentation(TestStruct5));

    const TestStruct6 = packed struct(u8) {
        @"0": bool,
        @"1": bool,
        @"2": bool,
        @"3": bool,
        @"4": bool,
        @"5": bool,
        @"6": bool,
        @"7": bool,
    };

    try testing.expect(hasUniqueRepresentation(TestStruct6));

    const TestUnion1 = packed union {
        a: u32,
        b: u16,
    };

    try testing.expect(!hasUniqueRepresentation(TestUnion1));

    const TestUnion2 = extern union {
        a: u32,
        b: u16,
    };

    try testing.expect(!hasUniqueRepresentation(TestUnion2));

    const TestUnion3 = union {
        a: u32,
        b: u16,
    };

    try testing.expect(!hasUniqueRepresentation(TestUnion3));

    const TestUnion4 = union(enum) {
        a: u32,
        b: u16,
    };

    try testing.expect(!hasUniqueRepresentation(TestUnion4));

    inline for ([_]type{ i0, u8, i16, u32, i64 }) |T| {
        try testing.expect(hasUniqueRepresentation(T));
    }
    inline for ([_]type{ i1, u9, i17, u33, i24 }) |T| {
        try testing.expect(!hasUniqueRepresentation(T));
    }

    try testing.expect(hasUniqueRepresentation(*u8));
    try testing.expect(hasUniqueRepresentation(*const u8));
    try testing.expect(hasUniqueRepresentation(?*u8));
    try testing.expect(hasUniqueRepresentation(?*const u8));

    try testing.expect(!hasUniqueRepresentation([]u8));
    try testing.expect(!hasUniqueRepresentation([]const u8));
    try testing.expect(!hasUniqueRepresentation(?[]u8));
    try testing.expect(!hasUniqueRepresentation(?[]const u8));

    try testing.expect(hasUniqueRepresentation(@Vector(std.simd.suggestVectorLength(u8) orelse 1, u8)));
    try testing.expect(@sizeOf(@Vector(3, u8)) == 3 or !hasUniqueRepresentation(@Vector(3, u8)));

    const StructWithComptimeFields = struct {
        comptime should_be_ignored: u64 = 42,
        comptime should_also_be_ignored: [*:0]const u8 = "hope you're having a good day :)",
        field: u32,
    };

    try testing.expect(hasUniqueRepresentation(StructWithComptimeFields));
}
const std = @import("../std.zig");
const meta = std.meta;
const testing = std.testing;
const mem = std.mem;
const assert = std.debug.assert;
const Type = std.builtin.Type;

/// This is useful for saving memory when allocating an object that has many
/// optional components. The optional objects are allocated sequentially in
/// memory, and a single integer is used to represent each optional object
/// and whether it is present based on each corresponding bit.
pub fn TrailerFlags(comptime Fields: type) type {
    return struct {
        bits: Int,

        pub const Int = meta.Int(.unsigned, bit_count);
        pub const bit_count = @typeInfo(Fields).@"struct".fields.len;

        pub const FieldEnum = std.meta.FieldEnum(Fields);

        pub const ActiveFields = std.enums.EnumFieldStruct(FieldEnum, bool, false);
        pub const FieldValues = blk: {
            var fields: [bit_count]Type.StructField = undefined;
            for (@typeInfo(Fields).@"struct".fields, 0..) |struct_field, i| {
                fields[i] = Type.StructField{
                    .name = struct_field.name,
                    .type = ?struct_field.type,
                    .default_value_ptr = &@as(?struct_field.type, null),
                    .is_comptime = false,
                    .alignment = @alignOf(?struct_field.type),
                };
            }
            break :blk @Type(.{
                .@"struct" = .{
                    .layout = .auto,
                    .fields = &fields,
                    .decls = &.{},
                    .is_tuple = false,
                },
            });
        };

        pub const Self = @This();

        pub fn has(self: Self, comptime field: FieldEnum) bool {
            const field_index = @intFromEnum(field);
            return (self.bits & (1 << field_index)) != 0;
        }

        pub fn get(self: Self, p: [*]align(@alignOf(Fields)) const u8, comptime field: FieldEnum) ?Field(field) {
            if (!self.has(field))
                return null;
            return self.ptrConst(p, field).*;
        }

        pub fn setFlag(self: *Self, comptime field: FieldEnum) void {
            const field_index = @intFromEnum(field);
            self.bits |= 1 << field_index;
        }

        /// `fields` is a boolean struct where each active field is set to `true`
        pub fn init(fields: ActiveFields) Self {
            var self: Self = .{ .bits = 0 };
            inline for (@typeInfo(Fields).@"struct".fields, 0..) |field, i| {
                if (@field(fields, field.name))
                    self.bits |= 1 << i;
            }
            return self;
        }

        /// `fields` is a struct with each field set to an optional value
        pub fn setMany(self: Self, p: [*]align(@alignOf(Fields)) u8, fields: FieldValues) void {
            inline for (@typeInfo(Fields).@"struct".fields, 0..) |field, i| {
                if (@field(fields, field.name)) |value|
                    self.set(p, @as(FieldEnum, @enumFromInt(i)), value);
            }
        }

        pub fn set(
            self: Self,
            p: [*]align(@alignOf(Fields)) u8,
            comptime field: FieldEnum,
            value: Field(field),
        ) void {
            self.ptr(p, field).* = value;
        }

        pub fn ptr(self: Self, p: [*]align(@alignOf(Fields)) u8, comptime field: FieldEnum) *Field(field) {
            if (@sizeOf(Field(field)) == 0)
                return undefined;
            const off = self.offset(field);
            return @ptrCast(@alignCast(p + off));
        }

        pub fn ptrConst(self: Self, p: [*]align(@alignOf(Fields)) const u8, comptime field: FieldEnum) *const Field(field) {
            if (@sizeOf(Field(field)) == 0)
                return undefined;
            const off = self.offset(field);
            return @ptrCast(@alignCast(p + off));
        }

        pub fn offset(self: Self, comptime field: FieldEnum) usize {
            var off: usize = 0;
            inline for (@typeInfo(Fields).@"struct".fields, 0..) |field_info, i| {
                const active = (self.bits & (1 << i)) != 0;
                if (i == @intFromEnum(field)) {
                    assert(active);
                    return mem.alignForward(usize, off, @alignOf(field_info.type));
                } else if (active) {
                    off = mem.alignForward(usize, off, @alignOf(field_info.type));
                    off += @sizeOf(field_info.type);
                }
            }
        }

        pub fn Field(comptime field: FieldEnum) type {
            return @typeInfo(Fields).@"struct".fields[@intFromEnum(field)].type;
        }

        pub fn sizeInBytes(self: Self) usize {
            var off: usize = 0;
            inline for (@typeInfo(Fields).@"struct".fields, 0..) |field, i| {
                if (@sizeOf(field.type) == 0)
                    continue;
                if ((self.bits & (1 << i)) != 0) {
                    off = mem.alignForward(usize, off, @alignOf(field.type));
                    off += @sizeOf(field.type);
                }
            }
            return off;
        }
    };
}

test TrailerFlags {
    const Flags = TrailerFlags(struct {
        a: i32,
        b: bool,
        c: u64,
    });
    try testing.expectEqual(u2, meta.Tag(Flags.FieldEnum));

    var flags = Flags.init(.{
        .b = true,
        .c = true,
    });
    const slice = try testing.allocator.alignedAlloc(u8, .@"8", flags.sizeInBytes());
    defer testing.allocator.free(slice);

    flags.set(slice.ptr, .b, false);
    flags.set(slice.ptr, .c, 12345678);

    try testing.expect(flags.get(slice.ptr, .a) == null);
    try testing.expect(!flags.get(slice.ptr, .b).?);
    try testing.expect(flags.get(slice.ptr, .c).? == 12345678);

    flags.setMany(slice.ptr, .{
        .b = true,
        .c = 5678,
    });

    try testing.expect(flags.get(slice.ptr, .a) == null);
    try testing.expect(flags.get(slice.ptr, .b).?);
    try testing.expect(flags.get(slice.ptr, .c).? == 5678);
}
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const meta = std.meta;
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

/// A MultiArrayList stores a list of a struct or tagged union type.
/// Instead of storing a single list of items, MultiArrayList
/// stores separate lists for each field of the struct or
/// lists of tags and bare unions.
/// This allows for memory savings if the struct or union has padding,
/// and also improves cache usage if only some fields or just tags
/// are needed for a computation.  The primary API for accessing fields is
/// the `slice()` function, which computes the start pointers
/// for the array of each field.  From the slice you can call
/// `.items(.<field_name>)` to obtain a slice of field values.
/// For unions you can call `.items(.tags)` or `.items(.data)`.
pub fn MultiArrayList(comptime T: type) type {
    return struct {
        bytes: [*]align(@alignOf(T)) u8 = undefined,
        len: usize = 0,
        capacity: usize = 0,

        pub const empty: Self = .{
            .bytes = undefined,
            .len = 0,
            .capacity = 0,
        };

        const Elem = switch (@typeInfo(T)) {
            .@"struct" => T,
            .@"union" => |u| struct {
                pub const Bare = @Type(.{ .@"union" = .{
                    .layout = u.layout,
                    .tag_type = null,
                    .fields = u.fields,
                    .decls = &.{},
                } });
                pub const Tag =
                    u.tag_type orelse @compileError("MultiArrayList does not support untagged unions");
                tags: Tag,
                data: Bare,

                pub fn fromT(outer: T) @This() {
                    const tag = meta.activeTag(outer);
                    return .{
                        .tags = tag,
                        .data = switch (tag) {
                            inline else => |t| @unionInit(Bare, @tagName(t), @field(outer, @tagName(t))),
                        },
                    };
                }
                pub fn toT(tag: Tag, bare: Bare) T {
                    return switch (tag) {
                        inline else => |t| @unionInit(T, @tagName(t), @field(bare, @tagName(t))),
                    };
                }
            },
            else => @compileError("MultiArrayList only supports structs and tagged unions"),
        };

        pub const Field = meta.FieldEnum(Elem);

        /// A MultiArrayList.Slice contains cached start pointers for each field in the list.
        /// These pointers are not normally stored to reduce the size of the list in memory.
        /// If you are accessing multiple fields, call slice() first to compute the pointers,
        /// and then get the field arrays from the slice.
        pub const Slice = struct {
            /// This array is indexed by the field index which can be obtained
            /// by using @intFromEnum() on the Field enum
            ptrs: [fields.len][*]u8,
            len: usize,
            capacity: usize,

            pub const empty: Slice = .{
                .ptrs = undefined,
                .len = 0,
                .capacity = 0,
            };

            pub fn items(self: Slice, comptime field: Field) []FieldType(field) {
                const F = FieldType(field);
                if (self.capacity == 0) {
                    return &[_]F{};
                }
                const byte_ptr = self.ptrs[@intFromEnum(field)];
                const casted_ptr: [*]F = if (@sizeOf(F) == 0)
                    undefined
                else
                    @ptrCast(@alignCast(byte_ptr));
                return casted_ptr[0..self.len];
            }

            pub fn set(self: *Slice, index: usize, elem: T) void {
                const e = switch (@typeInfo(T)) {
                    .@"struct" => elem,
                    .@"union" => Elem.fromT(elem),
                    else => unreachable,
                };
                inline for (fields, 0..) |field_info, i| {
                    self.items(@as(Field, @enumFromInt(i)))[index] = @field(e, field_info.name);
                }
            }

            pub fn get(self: Slice, index: usize) T {
                var result: Elem = undefined;
                inline for (fields, 0..) |field_info, i| {
                    @field(result, field_info.name) = self.items(@as(Field, @enumFromInt(i)))[index];
                }
                return switch (@typeInfo(T)) {
                    .@"struct" => result,
                    .@"union" => Elem.toT(result.tags, result.data),
                    else => unreachable,
                };
            }

            pub fn toMultiArrayList(self: Slice) Self {
                if (self.ptrs.len == 0 or self.capacity == 0) {
                    return .{};
                }
                const unaligned_ptr = self.ptrs[sizes.fields[0]];
                const aligned_ptr: [*]align(@alignOf(Elem)) u8 = @alignCast(unaligned_ptr);
                return .{
                    .bytes = aligned_ptr,
                    .len = self.len,
                    .capacity = self.capacity,
                };
            }

            pub fn deinit(self: *Slice, gpa: Allocator) void {
                var other = self.toMultiArrayList();
                other.deinit(gpa);
                self.* = undefined;
            }

            /// This function is used in the debugger pretty formatters in tools/ to fetch the
            /// child field order and entry type to facilitate fancy debug printing for this type.
            fn dbHelper(self: *Slice, child: *Elem, field: *Field, entry: *Entry) void {
                _ = self;
                _ = child;
                _ = field;
                _ = entry;
            }
        };

        const Self = @This();

        const fields = meta.fields(Elem);
        /// `sizes.bytes` is an array of @sizeOf each T field. Sorted by alignment, descending.
        /// `sizes.fields` is an array mapping from `sizes.bytes` array index to field index.
        const sizes = blk: {
            const Data = struct {
                size: usize,
                size_index: usize,
                alignment: usize,
            };
            var data: [fields.len]Data = undefined;
            for (fields, 0..) |field_info, i| {
                data[i] = .{
                    .size = @sizeOf(field_info.type),
                    .size_index = i,
                    .alignment = if (@sizeOf(field_info.type) == 0) 1 else field_info.alignment,
                };
            }
            const Sort = struct {
                fn lessThan(context: void, lhs: Data, rhs: Data) bool {
                    _ = context;
                    return lhs.alignment > rhs.alignment;
                }
            };
            @setEvalBranchQuota(3 * fields.len * std.math.log2(fields.len));
            mem.sort(Data, &data, {}, Sort.lessThan);
            var sizes_bytes: [fields.len]usize = undefined;
            var field_indexes: [fields.len]usize = undefined;
            for (data, 0..) |elem, i| {
                sizes_bytes[i] = elem.size;
                field_indexes[i] = elem.size_index;
            }
            break :blk .{
                .bytes = sizes_bytes,
                .fields = field_indexes,
            };
        };

        /// Release all allocated memory.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.allocatedBytes());
            self.* = undefined;
        }

        /// The caller owns the returned memory. Empties this MultiArrayList.
        pub fn toOwnedSlice(self: *Self) Slice {
            const result = self.slice();
            self.* = .{};
            return result;
        }

        /// Compute pointers to the start of each field of the array.
        /// If you need to access multiple fields, calling this may
        /// be more efficient than calling `items()` multiple times.
        pub fn slice(self: Self) Slice {
            var result: Slice = .{
                .ptrs = undefined,
                .len = self.len,
                .capacity = self.capacity,
            };
            var ptr: [*]u8 = self.bytes;
            for (sizes.bytes, sizes.fields) |field_size, i| {
                result.ptrs[i] = ptr;
                ptr += field_size * self.capacity;
            }
            return result;
        }

        /// Get the slice of values for a specified field.
        /// If you need multiple fields, consider calling slice()
        /// instead.
        pub fn items(self: Self, comptime field: Field) []FieldType(field) {
            return self.slice().items(field);
        }

        /// Overwrite one array element with new data.
        pub fn set(self: *Self, index: usize, elem: T) void {
            var slices = self.slice();
            slices.set(index, elem);
        }

        /// Obtain all the data for one array element.
        pub fn get(self: Self, index: usize) T {
            return self.slice().get(index);
        }

        /// Extend the list by 1 element. Allocates more memory as necessary.
        pub fn append(self: *Self, gpa: Allocator, elem: T) !void {
            try self.ensureUnusedCapacity(gpa, 1);
            self.appendAssumeCapacity(elem);
        }

        /// Extend the list by 1 element, but asserting `self.capacity`
        /// is sufficient to hold an additional item.
        pub fn appendAssumeCapacity(self: *Self, elem: T) void {
            assert(self.len < self.capacity);
            self.len += 1;
            self.set(self.len - 1, elem);
        }

        /// Extend the list by 1 element, returning the newly reserved
        /// index with uninitialized data.
        /// Allocates more memory as necesasry.
        pub fn addOne(self: *Self, gpa: Allocator) Allocator.Error!usize {
            try self.ensureUnusedCapacity(gpa, 1);
            return self.addOneAssumeCapacity();
        }

        /// Extend the list by 1 element, asserting `self.capacity`
        /// is sufficient to hold an additional item.  Returns the
        /// newly reserved index with uninitialized data.
        pub fn addOneAssumeCapacity(self: *Self) usize {
            assert(self.len < self.capacity);
            const index = self.len;
            self.len += 1;
            return index;
        }

        /// Remove and return the last element from the list, or return `null` if list is empty.
        /// Invalidates pointers to fields of the removed element.
        pub fn pop(self: *Self) ?T {
            if (self.len == 0) return null;
            const val = self.get(self.len - 1);
            self.len -= 1;
            return val;
        }

        /// Inserts an item into an ordered list.  Shifts all elements
        /// after and including the specified index back by one and
        /// sets the given index to the specified element.  May reallocate
        /// and invalidate iterators.
        pub fn insert(self: *Self, gpa: Allocator, index: usize, elem: T) !void {
            try self.ensureUnusedCapacity(gpa, 1);
            self.insertAssumeCapacity(index, elem);
        }

        /// Inserts an item into an ordered list which has room for it.
        /// Shifts all elements after and including the specified index
        /// back by one and sets the given index to the specified element.
        /// Will not reallocate the array, does not invalidate iterators.
        pub fn insertAssumeCapacity(self: *Self, index: usize, elem: T) void {
            assert(self.len < self.capacity);
            assert(index <= self.len);
            self.len += 1;
            const entry = switch (@typeInfo(T)) {
                .@"struct" => elem,
                .@"union" => Elem.fromT(elem),
                else => unreachable,
            };
            const slices = self.slice();
            inline for (fields, 0..) |field_info, field_index| {
                const field_slice = slices.items(@as(Field, @enumFromInt(field_index)));
                var i: usize = self.len - 1;
                while (i > index) : (i -= 1) {
                    field_slice[i] = field_slice[i - 1];
                }
                field_slice[index] = @field(entry, field_info.name);
            }
        }

        /// Remove the specified item from the list, swapping the last
        /// item in the list into its position.  Fast, but does not
        /// retain list ordering.
        pub fn swapRemove(self: *Self, index: usize) void {
            const slices = self.slice();
            inline for (fields, 0..) |_, i| {
                const field_slice = slices.items(@as(Field, @enumFromInt(i)));
                field_slice[index] = field_slice[self.len - 1];
                field_slice[self.len - 1] = undefined;
            }
            self.len -= 1;
        }

        /// Remove the specified item from the list, shifting items
        /// after it to preserve order.
        pub fn orderedRemove(self: *Self, index: usize) void {
            const slices = self.slice();
            inline for (fields, 0..) |_, field_index| {
                const field_slice = slices.items(@as(Field, @enumFromInt(field_index)));
                var i = index;
                while (i < self.len - 1) : (i += 1) {
                    field_slice[i] = field_slice[i + 1];
                }
                field_slice[i] = undefined;
            }
            self.len -= 1;
        }

        /// Adjust the list's length to `new_len`.
        /// Does not initialize added items, if any.
        pub fn resize(self: *Self, gpa: Allocator, new_len: usize) !void {
            try self.ensureTotalCapacity(gpa, new_len);
            self.len = new_len;
        }

        /// Attempt to reduce allocated capacity to `new_len`.
        /// If `new_len` is greater than zero, this may fail to reduce the capacity,
        /// but the data remains intact and the length is updated to new_len.
        pub fn shrinkAndFree(self: *Self, gpa: Allocator, new_len: usize) void {
            if (new_len == 0) return clearAndFree(self, gpa);

            assert(new_len <= self.capacity);
            assert(new_len <= self.len);

            const other_bytes = gpa.alignedAlloc(u8, .of(Elem), capacityInBytes(new_len)) catch {
                const self_slice = self.slice();
                inline for (fields, 0..) |field_info, i| {
                    if (@sizeOf(field_info.type) != 0) {
                        const field = @as(Field, @enumFromInt(i));
                        const dest_slice = self_slice.items(field)[new_len..];
                        // We use memset here for more efficient codegen in safety-checked,
                        // valgrind-enabled builds. Otherwise the valgrind client request
                        // will be repeated for every element.
                        @memset(dest_slice, undefined);
                    }
                }
                self.len = new_len;
                return;
            };
            var other = Self{
                .bytes = other_bytes.ptr,
                .capacity = new_len,
                .len = new_len,
            };
            self.len = new_len;
            const self_slice = self.slice();
            const other_slice = other.slice();
            inline for (fields, 0..) |field_info, i| {
                if (@sizeOf(field_info.type) != 0) {
                    const field = @as(Field, @enumFromInt(i));
                    @memcpy(other_slice.items(field), self_slice.items(field));
                }
            }
            gpa.free(self.allocatedBytes());
            self.* = other;
        }

        pub fn clearAndFree(self: *Self, gpa: Allocator) void {
            gpa.free(self.allocatedBytes());
            self.* = .{};
        }

        /// Reduce length to `new_len`.
        /// Invalidates pointers to elements `items[new_len..]`.
        /// Keeps capacity the same.
        pub fn shrinkRetainingCapacity(self: *Self, new_len: usize) void {
            self.len = new_len;
        }

        /// Invalidates all element pointers.
        pub fn clearRetainingCapacity(self: *Self) void {
            self.len = 0;
        }

        /// Modify the array so that it can hold at least `new_capacity` items.
        /// Implements super-linear growth to achieve amortized O(1) append operations.
        /// Invalidates element pointers if additional memory is needed.
        pub fn ensureTotalCapacity(self: *Self, gpa: Allocator, new_capacity: usize) Allocator.Error!void {
            if (self.capacity >= new_capacity) return;
            return self.setCapacity(gpa, growCapacity(self.capacity, new_capacity));
        }

        const init_capacity = init: {
            var max = 1;
            for (fields) |field| max = @as(comptime_int, @max(max, @sizeOf(field.type)));
            break :init @as(comptime_int, @max(1, std.atomic.cache_line / max));
        };

        /// Called when memory growth is necessary. Returns a capacity larger than
        /// minimum that grows super-linearly.
        fn growCapacity(current: usize, minimum: usize) usize {
            var new = current;
            while (true) {
                new +|= new / 2 + init_capacity;
                if (new >= minimum)
                    return new;
            }
        }

        /// Modify the array so that it can hold at least `additional_count` **more** items.
        /// Invalidates pointers if additional memory is needed.
        pub fn ensureUnusedCapacity(self: *Self, gpa: Allocator, additional_count: usize) !void {
            return self.ensureTotalCapacity(gpa, self.len + additional_count);
        }

        /// Modify the array so that it can hold exactly `new_capacity` items.
        /// Invalidates pointers if additional memory is needed.
        /// `new_capacity` must be greater or equal to `len`.
        pub fn setCapacity(self: *Self, gpa: Allocator, new_capacity: usize) !void {
            assert(new_capacity >= self.len);
            const new_bytes = try gpa.alignedAlloc(u8, .of(Elem), capacityInBytes(new_capacity));
            if (self.len == 0) {
                gpa.free(self.allocatedBytes());
                self.bytes = new_bytes.ptr;
                self.capacity = new_capacity;
                return;
            }
            var other = Self{
                .bytes = new_bytes.ptr,
                .capacity = new_capacity,
                .len = self.len,
            };
            const self_slice = self.slice();
            const other_slice = other.slice();
            inline for (fields, 0..) |field_info, i| {
                if (@sizeOf(field_info.type) != 0) {
                    const field = @as(Field, @enumFromInt(i));
                    @memcpy(other_slice.items(field), self_slice.items(field));
                }
            }
            gpa.free(self.allocatedBytes());
            self.* = other;
        }

        /// Create a copy of this list with a new backing store,
        /// using the specified allocator.
        pub fn clone(self: Self, gpa: Allocator) !Self {
            var result = Self{};
            errdefer result.deinit(gpa);
            try result.ensureTotalCapacity(gpa, self.len);
            result.len = self.len;
            const self_slice = self.slice();
            const result_slice = result.slice();
            inline for (fields, 0..) |field_info, i| {
                if (@sizeOf(field_info.type) != 0) {
                    const field = @as(Field, @enumFromInt(i));
                    @memcpy(result_slice.items(field), self_slice.items(field));
                }
            }
            return result;
        }

        /// `ctx` has the following method:
        /// `fn lessThan(ctx: @TypeOf(ctx), a_index: usize, b_index: usize) bool`
        fn sortInternal(self: Self, a: usize, b: usize, ctx: anytype, comptime mode: std.sort.Mode) void {
            const sort_context: struct {
                sub_ctx: @TypeOf(ctx),
                slice: Slice,

                pub fn swap(sc: @This(), a_index: usize, b_index: usize) void {
                    inline for (fields, 0..) |field_info, i| {
                        if (@sizeOf(field_info.type) != 0) {
                            const field: Field = @enumFromInt(i);
                            const ptr = sc.slice.items(field);
                            mem.swap(field_info.type, &ptr[a_index], &ptr[b_index]);
                        }
                    }
                }

                pub fn lessThan(sc: @This(), a_index: usize, b_index: usize) bool {
                    return sc.sub_ctx.lessThan(a_index, b_index);
                }
            } = .{
                .sub_ctx = ctx,
                .slice = self.slice(),
            };

            switch (mode) {
                .stable => mem.sortContext(a, b, sort_context),
                .unstable => mem.sortUnstableContext(a, b, sort_context),
            }
        }

        /// This function guarantees a stable sort, i.e the relative order of equal elements is preserved during sorting.
        /// Read more about stable sorting here: https://en.wikipedia.org/wiki/Sorting_algorithm#Stability
        /// If this guarantee does not matter, `sortUnstable` might be a faster alternative.
        /// `ctx` has the following method:
        /// `fn lessThan(ctx: @TypeOf(ctx), a_index: usize, b_index: usize) bool`
        pub fn sort(self: Self, ctx: anytype) void {
            self.sortInternal(0, self.len, ctx, .stable);
        }

        /// Sorts only the subsection of items between indices `a` and `b` (excluding `b`)
        /// This function guarantees a stable sort, i.e the relative order of equal elements is preserved during sorting.
        /// Read more about stable sorting here: https://en.wikipedia.org/wiki/Sorting_algorithm#Stability
        /// If this guarantee does not matter, `sortSpanUnstable` might be a faster alternative.
        /// `ctx` has the following method:
        /// `fn lessThan(ctx: @TypeOf(ctx), a_index: usize, b_index: usize) bool`
        pub fn sortSpan(self: Self, a: usize, b: usize, ctx: anytype) void {
            self.sortInternal(a, b, ctx, .stable);
        }

        /// This function does NOT guarantee a stable sort, i.e the relative order of equal elements may change during sorting.
        /// Due to the weaker guarantees of this function, this may be faster than the stable `sort` method.
        /// Read more about stable sorting here: https://en.wikipedia.org/wiki/Sorting_algorithm#Stability
        /// `ctx` has the following method:
        /// `fn lessThan(ctx: @TypeOf(ctx), a_index: usize, b_index: usize) bool`
        pub fn sortUnstable(self: Self, ctx: anytype) void {
            self.sortInternal(0, self.len, ctx, .unstable);
        }

        /// Sorts only the subsection of items between indices `a` and `b` (excluding `b`)
        /// This function does NOT guarantee a stable sort, i.e the relative order of equal elements may change during sorting.
        /// Due to the weaker guarantees of this function, this may be faster than the stable `sortSpan` method.
        /// Read more about stable sorting here: https://en.wikipedia.org/wiki/Sorting_algorithm#Stability
        /// `ctx` has the following method:
        /// `fn lessThan(ctx: @TypeOf(ctx), a_index: usize, b_index: usize) bool`
        pub fn sortSpanUnstable(self: Self, a: usize, b: usize, ctx: anytype) void {
            self.sortInternal(a, b, ctx, .unstable);
        }

        pub fn capacityInBytes(capacity: usize) usize {
            comptime var elem_bytes: usize = 0;
            inline for (sizes.bytes) |size| elem_bytes += size;
            return elem_bytes * capacity;
        }

        fn allocatedBytes(self: Self) []align(@alignOf(Elem)) u8 {
            return self.bytes[0..capacityInBytes(self.capacity)];
        }

        fn FieldType(comptime field: Field) type {
            return @FieldType(Elem, @tagName(field));
        }

        const Entry = entry: {
            var entry_fields: [fields.len]std.builtin.Type.StructField = undefined;
            for (&entry_fields, sizes.fields) |*entry_field, i| entry_field.* = .{
                .name = fields[i].name ++ "_ptr",
                .type = *fields[i].type,
                .default_value_ptr = null,
                .is_comptime = fields[i].is_comptime,
                .alignment = fields[i].alignment,
            };
            break :entry @Type(.{ .@"struct" = .{
                .layout = .@"extern",
                .fields = &entry_fields,
                .decls = &.{},
                .is_tuple = false,
            } });
        };
        /// This function is used in the debugger pretty formatters in tools/ to fetch the
        /// child field order and entry type to facilitate fancy debug printing for this type.
        fn dbHelper(self: *Self, child: *Elem, field: *Field, entry: *Entry) void {
            _ = self;
            _ = child;
            _ = field;
            _ = entry;
        }

        comptime {
            if (builtin.zig_backend == .stage2_llvm and !builtin.strip_debug_info) {
                _ = &dbHelper;
                _ = &Slice.dbHelper;
            }
        }
    };
}

test "basic usage" {
    const ally = testing.allocator;

    const Foo = struct {
        a: u32,
        b: []const u8,
        c: u8,
    };

    var list = MultiArrayList(Foo){};
    defer list.deinit(ally);

    try testing.expectEqual(@as(usize, 0), list.items(.a).len);

    try list.ensureTotalCapacity(ally, 2);

    list.appendAssumeCapacity(.{
        .a = 1,
        .b = "foobar",
        .c = 'a',
    });

    list.appendAssumeCapacity(.{
        .a = 2,
        .b = "zigzag",
        .c = 'b',
    });

    try testing.expectEqualSlices(u32, list.items(.a), &[_]u32{ 1, 2 });
    try testing.expectEqualSlices(u8, list.items(.c), &[_]u8{ 'a', 'b' });

    try testing.expectEqual(@as(usize, 2), list.items(.b).len);
    try testing.expectEqualStrings("foobar", list.items(.b)[0]);
    try testing.expectEqualStrings("zigzag", list.items(.b)[1]);

    try list.append(ally, .{
        .a = 3,
        .b = "fizzbuzz",
        .c = 'c',
    });

    try testing.expectEqualSlices(u32, list.items(.a), &[_]u32{ 1, 2, 3 });
    try testing.expectEqualSlices(u8, list.items(.c), &[_]u8{ 'a', 'b', 'c' });

    try testing.expectEqual(@as(usize, 3), list.items(.b).len);
    try testing.expectEqualStrings("foobar", list.items(.b)[0]);
    try testing.expectEqualStrings("zigzag", list.items(.b)[1]);
    try testing.expectEqualStrings("fizzbuzz", list.items(.b)[2]);

    // Add 6 more things to force a capacity increase.
    var i: usize = 0;
    while (i < 6) : (i += 1) {
        try list.append(ally, .{
            .a = @as(u32, @intCast(4 + i)),
            .b = "whatever",
            .c = @as(u8, @intCast('d' + i)),
        });
    }

    try testing.expectEqualSlices(
        u32,
        &[_]u32{ 1, 2, 3, 4, 5, 6, 7, 8, 9 },
        list.items(.a),
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i' },
        list.items(.c),
    );

    list.shrinkAndFree(ally, 3);

    try testing.expectEqualSlices(u32, list.items(.a), &[_]u32{ 1, 2, 3 });
    try testing.expectEqualSlices(u8, list.items(.c), &[_]u8{ 'a', 'b', 'c' });

    try testing.expectEqual(@as(usize, 3), list.items(.b).len);
    try testing.expectEqualStrings("foobar", list.items(.b)[0]);
    try testing.expectEqualStrings("zigzag", list.items(.b)[1]);
    try testing.expectEqualStrings("fizzbuzz", list.items(.b)[2]);

    list.set(try list.addOne(ally), .{
        .a = 4,
        .b = "xnopyt",
        .c = 'd',
    });
    try testing.expectEqualStrings("xnopyt", list.pop().?.b);
    try testing.expectEqual(@as(?u8, 'c'), if (list.pop()) |elem| elem.c else null);
    try testing.expectEqual(@as(u32, 2), list.pop().?.a);
    try testing.expectEqual(@as(u8, 'a'), list.pop().?.c);
    try testing.expectEqual(@as(?Foo, null), list.pop());

    list.clearRetainingCapacity();
    try testing.expectEqual(0, list.len);
    try testing.expect(list.capacity > 0);

    list.clearAndFree(ally);
    try testing.expectEqual(0, list.len);
    try testing.expectEqual(0, list.capacity);
}

// This was observed to fail on aarch64 with LLVM 11, when the capacityInBytes
// function used the @reduce code path.
test "regression test for @reduce bug" {
    const ally = testing.allocator;
    var list = MultiArrayList(struct {
        tag: std.zig.Token.Tag,
        start: u32,
    }){};
    defer list.deinit(ally);

    try list.ensureTotalCapacity(ally, 20);

    try list.append(ally, .{ .tag = .keyword_const, .start = 0 });
    try list.append(ally, .{ .tag = .identifier, .start = 6 });
    try list.append(ally, .{ .tag = .equal, .start = 10 });
    try list.append(ally, .{ .tag = .builtin, .start = 12 });
    try list.append(ally, .{ .tag = .l_paren, .start = 19 });
    try list.append(ally, .{ .tag = .string_literal, .start = 20 });
    try list.append(ally, .{ .tag = .r_paren, .start = 25 });
    try list.append(ally, .{ .tag = .semicolon, .start = 26 });
    try list.append(ally, .{ .tag = .keyword_pub, .start = 29 });
    try list.append(ally, .{ .tag = .keyword_fn, .start = 33 });
    try list.append(ally, .{ .tag = .identifier, .start = 36 });
    try list.append(ally, .{ .tag = .l_paren, .start = 40 });
    try list.append(ally, .{ .tag = .r_paren, .start = 41 });
    try list.append(ally, .{ .tag = .identifier, .start = 43 });
    try list.append(ally, .{ .tag = .bang, .start = 51 });
    try list.append(ally, .{ .tag = .identifier, .start = 52 });
    try list.append(ally, .{ .tag = .l_brace, .start = 57 });
    try list.append(ally, .{ .tag = .identifier, .start = 63 });
    try list.append(ally, .{ .tag = .period, .start = 66 });
    try list.append(ally, .{ .tag = .identifier, .start = 67 });
    try list.append(ally, .{ .tag = .period, .start = 70 });
    try list.append(ally, .{ .tag = .identifier, .start = 71 });
    try list.append(ally, .{ .tag = .l_paren, .start = 75 });
    try list.append(ally, .{ .tag = .string_literal, .start = 76 });
    try list.append(ally, .{ .tag = .comma, .start = 113 });
    try list.append(ally, .{ .tag = .period, .start = 115 });
    try list.append(ally, .{ .tag = .l_brace, .start = 116 });
    try list.append(ally, .{ .tag = .r_brace, .start = 117 });
    try list.append(ally, .{ .tag = .r_paren, .start = 118 });
    try list.append(ally, .{ .tag = .semicolon, .start = 119 });
    try list.append(ally, .{ .tag = .r_brace, .start = 121 });
    try list.append(ally, .{ .tag = .eof, .start = 123 });

    const tags = list.items(.tag);
    try testing.expectEqual(tags[1], .identifier);
    try testing.expectEqual(tags[2], .equal);
    try testing.expectEqual(tags[3], .builtin);
    try testing.expectEqual(tags[4], .l_paren);
    try testing.expectEqual(tags[5], .string_literal);
    try testing.expectEqual(tags[6], .r_paren);
    try testing.expectEqual(tags[7], .semicolon);
    try testing.expectEqual(tags[8], .keyword_pub);
    try testing.expectEqual(tags[9], .keyword_fn);
    try testing.expectEqual(tags[10], .identifier);
    try testing.expectEqual(tags[11], .l_paren);
    try testing.expectEqual(tags[12], .r_paren);
    try testing.expectEqual(tags[13], .identifier);
    try testing.expectEqual(tags[14], .bang);
    try testing.expectEqual(tags[15], .identifier);
    try testing.expectEqual(tags[16], .l_brace);
    try testing.expectEqual(tags[17], .identifier);
    try testing.expectEqual(tags[18], .period);
    try testing.expectEqual(tags[19], .identifier);
    try testing.expectEqual(tags[20], .period);
    try testing.expectEqual(tags[21], .identifier);
    try testing.expectEqual(tags[22], .l_paren);
    try testing.expectEqual(tags[23], .string_literal);
    try testing.expectEqual(tags[24], .comma);
    try testing.expectEqual(tags[25], .period);
    try testing.expectEqual(tags[26], .l_brace);
    try testing.expectEqual(tags[27], .r_brace);
    try testing.expectEqual(tags[28], .r_paren);
    try testing.expectEqual(tags[29], .semicolon);
    try testing.expectEqual(tags[30], .r_brace);
    try testing.expectEqual(tags[31], .eof);
}

test "ensure capacity on empty list" {
    const ally = testing.allocator;

    const Foo = struct {
        a: u32,
        b: u8,
    };

    var list = MultiArrayList(Foo){};
    defer list.deinit(ally);

    try list.ensureTotalCapacity(ally, 2);
    list.appendAssumeCapacity(.{ .a = 1, .b = 2 });
    list.appendAssumeCapacity(.{ .a = 3, .b = 4 });

    try testing.expectEqualSlices(u32, &[_]u32{ 1, 3 }, list.items(.a));
    try testing.expectEqualSlices(u8, &[_]u8{ 2, 4 }, list.items(.b));

    list.len = 0;
    list.appendAssumeCapacity(.{ .a = 5, .b = 6 });
    list.appendAssumeCapacity(.{ .a = 7, .b = 8 });

    try testing.expectEqualSlices(u32, &[_]u32{ 5, 7 }, list.items(.a));
    try testing.expectEqualSlices(u8, &[_]u8{ 6, 8 }, list.items(.b));

    list.len = 0;
    try list.ensureTotalCapacity(ally, 16);

    list.appendAssumeCapacity(.{ .a = 9, .b = 10 });
    list.appendAssumeCapacity(.{ .a = 11, .b = 12 });

    try testing.expectEqualSlices(u32, &[_]u32{ 9, 11 }, list.items(.a));
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 12 }, list.items(.b));
}

test "insert elements" {
    const ally = testing.allocator;

    const Foo = struct {
        a: u8,
        b: u32,
    };

    var list = MultiArrayList(Foo){};
    defer list.deinit(ally);

    try list.insert(ally, 0, .{ .a = 1, .b = 2 });
    try list.ensureUnusedCapacity(ally, 1);
    list.insertAssumeCapacity(1, .{ .a = 2, .b = 3 });

    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2 }, list.items(.a));
    try testing.expectEqualSlices(u32, &[_]u32{ 2, 3 }, list.items(.b));
}

test "union" {
    const ally = testing.allocator;

    const Foo = union(enum) {
        a: u32,
        b: []const u8,
    };

    var list = MultiArrayList(Foo){};
    defer list.deinit(ally);

    try testing.expectEqual(@as(usize, 0), list.items(.tags).len);

    try list.ensureTotalCapacity(ally, 3);

    list.appendAssumeCapacity(.{ .a = 1 });
    list.appendAssumeCapacity(.{ .b = "zigzag" });

    try testing.expectEqualSlices(meta.Tag(Foo), list.items(.tags), &.{ .a, .b });
    try testing.expectEqual(@as(usize, 2), list.items(.tags).len);

    list.appendAssumeCapacity(.{ .b = "foobar" });
    try testing.expectEqualStrings("zigzag", list.items(.data)[1].b);
    try testing.expectEqualStrings("foobar", list.items(.data)[2].b);

    // Add 6 more things to force a capacity increase.
    for (0..6) |i| {
        try list.append(ally, .{ .a = @as(u32, @intCast(4 + i)) });
    }

    try testing.expectEqualSlices(
        meta.Tag(Foo),
        &.{ .a, .b, .b, .a, .a, .a, .a, .a, .a },
        list.items(.tags),
    );
    try testing.expectEqual(Foo{ .a = 1 }, list.get(0));
    try testing.expectEqual(Foo{ .b = "zigzag" }, list.get(1));
    try testing.expectEqual(Foo{ .b = "foobar" }, list.get(2));
    try testing.expectEqual(Foo{ .a = 4 }, list.get(3));
    try testing.expectEqual(Foo{ .a = 5 }, list.get(4));
    try testing.expectEqual(Foo{ .a = 6 }, list.get(5));
    try testing.expectEqual(Foo{ .a = 7 }, list.get(6));
    try testing.expectEqual(Foo{ .a = 8 }, list.get(7));
    try testing.expectEqual(Foo{ .a = 9 }, list.get(8));

    list.shrinkAndFree(ally, 3);

    try testing.expectEqual(@as(usize, 3), list.items(.tags).len);
    try testing.expectEqualSlices(meta.Tag(Foo), list.items(.tags), &.{ .a, .b, .b });

    try testing.expectEqual(Foo{ .a = 1 }, list.get(0));
    try testing.expectEqual(Foo{ .b = "zigzag" }, list.get(1));
    try testing.expectEqual(Foo{ .b = "foobar" }, list.get(2));
}

test "sorting a span" {
    var list: MultiArrayList(struct { score: u32, chr: u8 }) = .{};
    defer list.deinit(testing.allocator);

    try list.ensureTotalCapacity(testing.allocator, 42);
    for (
        // zig fmt: off
        [42]u8{ 'b', 'a', 'c', 'a', 'b', 'c', 'b', 'c', 'b', 'a', 'b', 'a', 'b', 'c', 'b', 'a', 'a', 'c', 'c', 'a', 'c', 'b', 'a', 'c', 'a', 'b', 'b', 'c', 'c', 'b', 'a', 'b', 'a', 'b', 'c', 'b', 'a', 'a', 'c', 'c', 'a', 'c' },
        [42]u32{ 1,   1,   1,   2,   2,   2,   3,   3,   4,   3,   5,   4,   6,   4,   7,   5,   6,   5,   6,   7,   7,   8,   8,   8,   9,   9,  10,   9,  10,  11,  10,  12,  11,  13,  11,  14,  12,  13,  12,  13,  14,  14 },
        // zig fmt: on
    ) |chr, score| {
        list.appendAssumeCapacity(.{ .chr = chr, .score = score });
    }

    const sliced = list.slice();
    list.sortSpan(6, 21, struct {
        chars: []const u8,

        fn lessThan(ctx: @This(), a: usize, b: usize) bool {
            return ctx.chars[a] < ctx.chars[b];
        }
    }{ .chars = sliced.items(.chr) });

    var i: u32 = undefined;
    var j: u32 = 6;
    var c: u8 = 'a';

    while (j < 21) {
        i = j;
        j += 5;
        var n: u32 = 3;
        for (sliced.items(.chr)[i..j], sliced.items(.score)[i..j]) |chr, score| {
            try testing.expectEqual(score, n);
            try testing.expectEqual(chr, c);
            n += 1;
        }
        c += 1;
    }
}

test "0 sized struct field" {
    const ally = testing.allocator;

    const Foo = struct {
        a: u0,
        b: f32,
    };

    var list = MultiArrayList(Foo){};
    defer list.deinit(ally);

    try testing.expectEqualSlices(u0, &[_]u0{}, list.items(.a));
    try testing.expectEqualSlices(f32, &[_]f32{}, list.items(.b));

    try list.append(ally, .{ .a = 0, .b = 42.0 });
    try testing.expectEqualSlices(u0, &[_]u0{0}, list.items(.a));
    try testing.expectEqualSlices(f32, &[_]f32{42.0}, list.items(.b));

    try list.insert(ally, 0, .{ .a = 0, .b = -1.0 });
    try testing.expectEqualSlices(u0, &[_]u0{ 0, 0 }, list.items(.a));
    try testing.expectEqualSlices(f32, &[_]f32{ -1.0, 42.0 }, list.items(.b));

    list.swapRemove(list.len - 1);
    try testing.expectEqualSlices(u0, &[_]u0{0}, list.items(.a));
    try testing.expectEqualSlices(f32, &[_]f32{-1.0}, list.items(.b));
}

test "0 sized struct" {
    const ally = testing.allocator;

    const Foo = struct {
        a: u0,
    };

    var list = MultiArrayList(Foo){};
    defer list.deinit(ally);

    try testing.expectEqualSlices(u0, &[_]u0{}, list.items(.a));

    try list.append(ally, .{ .a = 0 });
    try testing.expectEqualSlices(u0, &[_]u0{0}, list.items(.a));

    try list.insert(ally, 0, .{ .a = 0 });
    try testing.expectEqualSlices(u0, &[_]u0{ 0, 0 }, list.items(.a));

    list.swapRemove(list.len - 1);
    try testing.expectEqualSlices(u0, &[_]u0{0}, list.items(.a));
}

test "struct with many fields" {
    const ManyFields = struct {
        fn Type(count: comptime_int) type {
            var fields: [count]std.builtin.Type.StructField = undefined;
            for (0..count) |i| {
                fields[i] = .{
                    .name = std.fmt.comptimePrint("a{}", .{i}),
                    .type = u32,
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = @alignOf(u32),
                };
            }
            const info: std.builtin.Type = .{ .@"struct" = .{
                .layout = .auto,
                .fields = &fields,
                .decls = &.{},
                .is_tuple = false,
            } };
            return @Type(info);
        }

        fn doTest(ally: std.mem.Allocator, count: comptime_int) !void {
            var list: MultiArrayList(Type(count)) = .empty;
            defer list.deinit(ally);

            try list.resize(ally, 1);
            list.items(.a0)[0] = 42;
        }
    };

    try ManyFields.doTest(testing.allocator, 25);
    try ManyFields.doTest(testing.allocator, 50);
    try ManyFields.doTest(testing.allocator, 100);
    try ManyFields.doTest(testing.allocator, 200);
}
//! Cross-platform networking abstractions.

const std = @import("std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const net = @This();
const mem = std.mem;
const posix = std.posix;
const fs = std.fs;
const io = std.io;
const native_endian = builtin.target.cpu.arch.endian();
const native_os = builtin.os.tag;
const windows = std.os.windows;

// Windows 10 added support for unix sockets in build 17063, redstone 4 is the
// first release to support them.
pub const has_unix_sockets = switch (native_os) {
    .windows => builtin.os.version_range.windows.isAtLeast(.win10_rs4) orelse false,
    else => true,
};

pub const IPParseError = error{
    Overflow,
    InvalidEnd,
    InvalidCharacter,
    Incomplete,
};

pub const IPv4ParseError = IPParseError || error{NonCanonical};

pub const IPv6ParseError = IPParseError || error{InvalidIpv4Mapping};
pub const IPv6InterfaceError = posix.SocketError || posix.IoCtl_SIOCGIFINDEX_Error || error{NameTooLong};
pub const IPv6ResolveError = IPv6ParseError || IPv6InterfaceError;

pub const Address = extern union {
    any: posix.sockaddr,
    in: Ip4Address,
    in6: Ip6Address,
    un: if (has_unix_sockets) posix.sockaddr.un else void,

    /// Parse the given IP address string into an Address value.
    /// It is recommended to use `resolveIp` instead, to handle
    /// IPv6 link-local unix addresses.
    pub fn parseIp(name: []const u8, port: u16) !Address {
        if (parseIp4(name, port)) |ip4| return ip4 else |err| switch (err) {
            error.Overflow,
            error.InvalidEnd,
            error.InvalidCharacter,
            error.Incomplete,
            error.NonCanonical,
            => {},
        }

        if (parseIp6(name, port)) |ip6| return ip6 else |err| switch (err) {
            error.Overflow,
            error.InvalidEnd,
            error.InvalidCharacter,
            error.Incomplete,
            error.InvalidIpv4Mapping,
            => {},
        }

        return error.InvalidIPAddressFormat;
    }

    pub fn resolveIp(name: []const u8, port: u16) !Address {
        if (parseIp4(name, port)) |ip4| return ip4 else |err| switch (err) {
            error.Overflow,
            error.InvalidEnd,
            error.InvalidCharacter,
            error.Incomplete,
            error.NonCanonical,
            => {},
        }

        if (resolveIp6(name, port)) |ip6| return ip6 else |err| switch (err) {
            error.Overflow,
            error.InvalidEnd,
            error.InvalidCharacter,
            error.Incomplete,
            error.InvalidIpv4Mapping,
            => {},
            else => return err,
        }

        return error.InvalidIPAddressFormat;
    }

    pub fn parseExpectingFamily(name: []const u8, family: posix.sa_family_t, port: u16) !Address {
        switch (family) {
            posix.AF.INET => return parseIp4(name, port),
            posix.AF.INET6 => return parseIp6(name, port),
            posix.AF.UNSPEC => return parseIp(name, port),
            else => unreachable,
        }
    }

    pub fn parseIp6(buf: []const u8, port: u16) IPv6ParseError!Address {
        return .{ .in6 = try Ip6Address.parse(buf, port) };
    }

    pub fn resolveIp6(buf: []const u8, port: u16) IPv6ResolveError!Address {
        return .{ .in6 = try Ip6Address.resolve(buf, port) };
    }

    pub fn parseIp4(buf: []const u8, port: u16) IPv4ParseError!Address {
        return .{ .in = try Ip4Address.parse(buf, port) };
    }

    pub fn initIp4(addr: [4]u8, port: u16) Address {
        return .{ .in = Ip4Address.init(addr, port) };
    }

    pub fn initIp6(addr: [16]u8, port: u16, flowinfo: u32, scope_id: u32) Address {
        return .{ .in6 = Ip6Address.init(addr, port, flowinfo, scope_id) };
    }

    pub fn initUnix(path: []const u8) !Address {
        var sock_addr = posix.sockaddr.un{
            .family = posix.AF.UNIX,
            .path = undefined,
        };

        // Add 1 to ensure a terminating 0 is present in the path array for maximum portability.
        if (path.len + 1 > sock_addr.path.len) return error.NameTooLong;

        @memset(&sock_addr.path, 0);
        @memcpy(sock_addr.path[0..path.len], path);

        return .{ .un = sock_addr };
    }

    /// Returns the port in native endian.
    /// Asserts that the address is ip4 or ip6.
    pub fn getPort(self: Address) u16 {
        return switch (self.any.family) {
            posix.AF.INET => self.in.getPort(),
            posix.AF.INET6 => self.in6.getPort(),
            else => unreachable,
        };
    }

    /// `port` is native-endian.
    /// Asserts that the address is ip4 or ip6.
    pub fn setPort(self: *Address, port: u16) void {
        switch (self.any.family) {
            posix.AF.INET => self.in.setPort(port),
            posix.AF.INET6 => self.in6.setPort(port),
            else => unreachable,
        }
    }

    /// Asserts that `addr` is an IP address.
    /// This function will read past the end of the pointer, with a size depending
    /// on the address family.
    pub fn initPosix(addr: *align(4) const posix.sockaddr) Address {
        switch (addr.family) {
            posix.AF.INET => return Address{ .in = Ip4Address{ .sa = @as(*const posix.sockaddr.in, @ptrCast(addr)).* } },
            posix.AF.INET6 => return Address{ .in6 = Ip6Address{ .sa = @as(*const posix.sockaddr.in6, @ptrCast(addr)).* } },
            else => unreachable,
        }
    }

    pub fn format(
        self: Address,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
        switch (self.any.family) {
            posix.AF.INET => try self.in.format(fmt, options, out_stream),
            posix.AF.INET6 => try self.in6.format(fmt, options, out_stream),
            posix.AF.UNIX => {
                if (!has_unix_sockets) {
                    unreachable;
                }

                try std.fmt.format(out_stream, "{s}", .{std.mem.sliceTo(&self.un.path, 0)});
            },
            else => unreachable,
        }
    }

    pub fn eql(a: Address, b: Address) bool {
        const a_bytes = @as([*]const u8, @ptrCast(&a.any))[0..a.getOsSockLen()];
        const b_bytes = @as([*]const u8, @ptrCast(&b.any))[0..b.getOsSockLen()];
        return mem.eql(u8, a_bytes, b_bytes);
    }

    pub fn getOsSockLen(self: Address) posix.socklen_t {
        switch (self.any.family) {
            posix.AF.INET => return self.in.getOsSockLen(),
            posix.AF.INET6 => return self.in6.getOsSockLen(),
            posix.AF.UNIX => {
                if (!has_unix_sockets) {
                    unreachable;
                }

                // Using the full length of the structure here is more portable than returning
                // the number of bytes actually used by the currently stored path.
                // This also is correct regardless if we are passing a socket address to the kernel
                // (e.g. in bind, connect, sendto) since we ensure the path is 0 terminated in
                // initUnix() or if we are receiving a socket address from the kernel and must
                // provide the full buffer size (e.g. getsockname, getpeername, recvfrom, accept).
                //
                // To access the path, std.mem.sliceTo(&address.un.path, 0) should be used.
                return @as(posix.socklen_t, @intCast(@sizeOf(posix.sockaddr.un)));
            },

            else => unreachable,
        }
    }

    pub const ListenError = posix.SocketError || posix.BindError || posix.ListenError ||
        posix.SetSockOptError || posix.GetSockNameError;

    pub const ListenOptions = struct {
        /// How many connections the kernel will accept on the application's behalf.
        /// If more than this many connections pool in the kernel, clients will start
        /// seeing "Connection refused".
        kernel_backlog: u31 = 128,
        /// Sets SO_REUSEADDR and SO_REUSEPORT on POSIX.
        /// Sets SO_REUSEADDR on Windows, which is roughly equivalent.
        reuse_address: bool = false,
        /// Deprecated. Does the same thing as reuse_address.
        reuse_port: bool = false,
        force_nonblocking: bool = false,
    };

    /// The returned `Server` has an open `stream`.
    pub fn listen(address: Address, options: ListenOptions) ListenError!Server {
        const nonblock: u32 = if (options.force_nonblocking) posix.SOCK.NONBLOCK else 0;
        const sock_flags = posix.SOCK.STREAM | posix.SOCK.CLOEXEC | nonblock;
        const proto: u32 = if (address.any.family == posix.AF.UNIX) 0 else posix.IPPROTO.TCP;

        const sockfd = try posix.socket(address.any.family, sock_flags, proto);
        var s: Server = .{
            .listen_address = undefined,
            .stream = .{ .handle = sockfd },
        };
        errdefer s.stream.close();

        if (options.reuse_address or options.reuse_port) {
            try posix.setsockopt(
                sockfd,
                posix.SOL.SOCKET,
                posix.SO.REUSEADDR,
                &mem.toBytes(@as(c_int, 1)),
            );
            if (@hasDecl(posix.SO, "REUSEPORT") and address.any.family != posix.AF.UNIX) {
                try posix.setsockopt(
                    sockfd,
                    posix.SOL.SOCKET,
                    posix.SO.REUSEPORT,
                    &mem.toBytes(@as(c_int, 1)),
                );
            }
        }

        var socklen = address.getOsSockLen();
        try posix.bind(sockfd, &address.any, socklen);
        try posix.listen(sockfd, options.kernel_backlog);
        try posix.getsockname(sockfd, &s.listen_address.any, &socklen);
        return s;
    }
};

pub const Ip4Address = extern struct {
    sa: posix.sockaddr.in,

    pub fn parse(buf: []const u8, port: u16) IPv4ParseError!Ip4Address {
        var result: Ip4Address = .{
            .sa = .{
                .port = mem.nativeToBig(u16, port),
                .addr = undefined,
            },
        };
        const out_ptr = mem.asBytes(&result.sa.addr);

        var x: u8 = 0;
        var index: u8 = 0;
        var saw_any_digits = false;
        var has_zero_prefix = false;
        for (buf) |c| {
            if (c == '.') {
                if (!saw_any_digits) {
                    return error.InvalidCharacter;
                }
                if (index == 3) {
                    return error.InvalidEnd;
                }
                out_ptr[index] = x;
                index += 1;
                x = 0;
                saw_any_digits = false;
                has_zero_prefix = false;
            } else if (c >= '0' and c <= '9') {
                if (c == '0' and !saw_any_digits) {
                    has_zero_prefix = true;
                } else if (has_zero_prefix) {
                    return error.NonCanonical;
                }
                saw_any_digits = true;
                x = try std.math.mul(u8, x, 10);
                x = try std.math.add(u8, x, c - '0');
            } else {
                return error.InvalidCharacter;
            }
        }
        if (index == 3 and saw_any_digits) {
            out_ptr[index] = x;
            return result;
        }

        return error.Incomplete;
    }

    pub fn resolveIp(name: []const u8, port: u16) !Ip4Address {
        if (parse(name, port)) |ip4| return ip4 else |err| switch (err) {
            error.Overflow,
            error.InvalidEnd,
            error.InvalidCharacter,
            error.Incomplete,
            error.NonCanonical,
            => {},
        }
        return error.InvalidIPAddressFormat;
    }

    pub fn init(addr: [4]u8, port: u16) Ip4Address {
        return Ip4Address{
            .sa = posix.sockaddr.in{
                .port = mem.nativeToBig(u16, port),
                .addr = @as(*align(1) const u32, @ptrCast(&addr)).*,
            },
        };
    }

    /// Returns the port in native endian.
    /// Asserts that the address is ip4 or ip6.
    pub fn getPort(self: Ip4Address) u16 {
        return mem.bigToNative(u16, self.sa.port);
    }

    /// `port` is native-endian.
    /// Asserts that the address is ip4 or ip6.
    pub fn setPort(self: *Ip4Address, port: u16) void {
        self.sa.port = mem.nativeToBig(u16, port);
    }

    pub fn format(
        self: Ip4Address,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
        _ = options;
        const bytes = @as(*const [4]u8, @ptrCast(&self.sa.addr));
        try std.fmt.format(out_stream, "{}.{}.{}.{}:{}", .{
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            self.getPort(),
        });
    }

    pub fn getOsSockLen(self: Ip4Address) posix.socklen_t {
        _ = self;
        return @sizeOf(posix.sockaddr.in);
    }
};

pub const Ip6Address = extern struct {
    sa: posix.sockaddr.in6,

    /// Parse a given IPv6 address string into an Address.
    /// Assumes the Scope ID of the address is fully numeric.
    /// For non-numeric addresses, see `resolveIp6`.
    pub fn parse(buf: []const u8, port: u16) IPv6ParseError!Ip6Address {
        var result = Ip6Address{
            .sa = posix.sockaddr.in6{
                .scope_id = 0,
                .port = mem.nativeToBig(u16, port),
                .flowinfo = 0,
                .addr = undefined,
            },
        };
        var ip_slice: *[16]u8 = result.sa.addr[0..];

        var tail: [16]u8 = undefined;

        var x: u16 = 0;
        var saw_any_digits = false;
        var index: u8 = 0;
        var scope_id = false;
        var abbrv = false;
        for (buf, 0..) |c, i| {
            if (scope_id) {
                if (c >= '0' and c <= '9') {
                    const digit = c - '0';
                    {
                        const ov = @mulWithOverflow(result.sa.scope_id, 10);
                        if (ov[1] != 0) return error.Overflow;
                        result.sa.scope_id = ov[0];
                    }
                    {
                        const ov = @addWithOverflow(result.sa.scope_id, digit);
                        if (ov[1] != 0) return error.Overflow;
                        result.sa.scope_id = ov[0];
                    }
                } else {
                    return error.InvalidCharacter;
                }
            } else if (c == ':') {
                if (!saw_any_digits) {
                    if (abbrv) return error.InvalidCharacter; // ':::'
                    if (i != 0) abbrv = true;
                    @memset(ip_slice[index..], 0);
                    ip_slice = tail[0..];
                    index = 0;
                    continue;
                }
                if (index == 14) {
                    return error.InvalidEnd;
                }
                ip_slice[index] = @as(u8, @truncate(x >> 8));
                index += 1;
                ip_slice[index] = @as(u8, @truncate(x));
                index += 1;

                x = 0;
                saw_any_digits = false;
            } else if (c == '%') {
                if (!saw_any_digits) {
                    return error.InvalidCharacter;
                }
                scope_id = true;
                saw_any_digits = false;
            } else if (c == '.') {
                if (!abbrv or ip_slice[0] != 0xff or ip_slice[1] != 0xff) {
                    // must start with '::ffff:'
                    return error.InvalidIpv4Mapping;
                }
                const start_index = mem.lastIndexOfScalar(u8, buf[0..i], ':').? + 1;
                const addr = (Ip4Address.parse(buf[start_index..], 0) catch {
                    return error.InvalidIpv4Mapping;
                }).sa.addr;
                ip_slice = result.sa.addr[0..];
                ip_slice[10] = 0xff;
                ip_slice[11] = 0xff;

                const ptr = mem.sliceAsBytes(@as(*const [1]u32, &addr)[0..]);

                ip_slice[12] = ptr[0];
                ip_slice[13] = ptr[1];
                ip_slice[14] = ptr[2];
                ip_slice[15] = ptr[3];
                return result;
            } else {
                const digit = try std.fmt.charToDigit(c, 16);
                {
                    const ov = @mulWithOverflow(x, 16);
                    if (ov[1] != 0) return error.Overflow;
                    x = ov[0];
                }
                {
                    const ov = @addWithOverflow(x, digit);
                    if (ov[1] != 0) return error.Overflow;
                    x = ov[0];
                }
                saw_any_digits = true;
            }
        }

        if (!saw_any_digits and !abbrv) {
            return error.Incomplete;
        }
        if (!abbrv and index < 14) {
            return error.Incomplete;
        }

        if (index == 14) {
            ip_slice[14] = @as(u8, @truncate(x >> 8));
            ip_slice[15] = @as(u8, @truncate(x));
            return result;
        } else {
            ip_slice[index] = @as(u8, @truncate(x >> 8));
            index += 1;
            ip_slice[index] = @as(u8, @truncate(x));
            index += 1;
            @memcpy(result.sa.addr[16 - index ..][0..index], ip_slice[0..index]);
            return result;
        }
    }

    pub fn resolve(buf: []const u8, port: u16) IPv6ResolveError!Ip6Address {
        // TODO: Unify the implementations of resolveIp6 and parseIp6.
        var result = Ip6Address{
            .sa = posix.sockaddr.in6{
                .scope_id = 0,
                .port = mem.nativeToBig(u16, port),
                .flowinfo = 0,
                .addr = undefined,
            },
        };
        var ip_slice: *[16]u8 = result.sa.addr[0..];

        var tail: [16]u8 = undefined;

        var x: u16 = 0;
        var saw_any_digits = false;
        var index: u8 = 0;
        var abbrv = false;

        var scope_id = false;
        var scope_id_value: [posix.IFNAMESIZE - 1]u8 = undefined;
        var scope_id_index: usize = 0;

        for (buf, 0..) |c, i| {
            if (scope_id) {
                // Handling of percent-encoding should be for an URI library.
                if ((c >= '0' and c <= '9') or
                    (c >= 'A' and c <= 'Z') or
                    (c >= 'a' and c <= 'z') or
                    (c == '-') or (c == '.') or (c == '_') or (c == '~'))
                {
                    if (scope_id_index >= scope_id_value.len) {
                        return error.Overflow;
                    }

                    scope_id_value[scope_id_index] = c;
                    scope_id_index += 1;
                } else {
                    return error.InvalidCharacter;
                }
            } else if (c == ':') {
                if (!saw_any_digits) {
                    if (abbrv) return error.InvalidCharacter; // ':::'
                    if (i != 0) abbrv = true;
                    @memset(ip_slice[index..], 0);
                    ip_slice = tail[0..];
                    index = 0;
                    continue;
                }
                if (index == 14) {
                    return error.InvalidEnd;
                }
                ip_slice[index] = @as(u8, @truncate(x >> 8));
                index += 1;
                ip_slice[index] = @as(u8, @truncate(x));
                index += 1;

                x = 0;
                saw_any_digits = false;
            } else if (c == '%') {
                if (!saw_any_digits) {
                    return error.InvalidCharacter;
                }
                scope_id = true;
                saw_any_digits = false;
            } else if (c == '.') {
                if (!abbrv or ip_slice[0] != 0xff or ip_slice[1] != 0xff) {
                    // must start with '::ffff:'
                    return error.InvalidIpv4Mapping;
                }
                const start_index = mem.lastIndexOfScalar(u8, buf[0..i], ':').? + 1;
                const addr = (Ip4Address.parse(buf[start_index..], 0) catch {
                    return error.InvalidIpv4Mapping;
                }).sa.addr;
                ip_slice = result.sa.addr[0..];
                ip_slice[10] = 0xff;
                ip_slice[11] = 0xff;

                const ptr = mem.sliceAsBytes(@as(*const [1]u32, &addr)[0..]);

                ip_slice[12] = ptr[0];
                ip_slice[13] = ptr[1];
                ip_slice[14] = ptr[2];
                ip_slice[15] = ptr[3];
                return result;
            } else {
                const digit = try std.fmt.charToDigit(c, 16);
                {
                    const ov = @mulWithOverflow(x, 16);
                    if (ov[1] != 0) return error.Overflow;
                    x = ov[0];
                }
                {
                    const ov = @addWithOverflow(x, digit);
                    if (ov[1] != 0) return error.Overflow;
                    x = ov[0];
                }
                saw_any_digits = true;
            }
        }

        if (!saw_any_digits and !abbrv) {
            return error.Incomplete;
        }

        if (scope_id and scope_id_index == 0) {
            return error.Incomplete;
        }

        var resolved_scope_id: u32 = 0;
        if (scope_id_index > 0) {
            const scope_id_str = scope_id_value[0..scope_id_index];
            resolved_scope_id = std.fmt.parseInt(u32, scope_id_str, 10) catch |err| blk: {
                if (err != error.InvalidCharacter) return err;
                break :blk try if_nametoindex(scope_id_str);
            };
        }

        result.sa.scope_id = resolved_scope_id;

        if (index == 14) {
            ip_slice[14] = @as(u8, @truncate(x >> 8));
            ip_slice[15] = @as(u8, @truncate(x));
            return result;
        } else {
            ip_slice[index] = @as(u8, @truncate(x >> 8));
            index += 1;
            ip_slice[index] = @as(u8, @truncate(x));
            index += 1;
            @memcpy(result.sa.addr[16 - index ..][0..index], ip_slice[0..index]);
            return result;
        }
    }

    pub fn init(addr: [16]u8, port: u16, flowinfo: u32, scope_id: u32) Ip6Address {
        return Ip6Address{
            .sa = posix.sockaddr.in6{
                .addr = addr,
                .port = mem.nativeToBig(u16, port),
                .flowinfo = flowinfo,
                .scope_id = scope_id,
            },
        };
    }

    /// Returns the port in native endian.
    /// Asserts that the address is ip4 or ip6.
    pub fn getPort(self: Ip6Address) u16 {
        return mem.bigToNative(u16, self.sa.port);
    }

    /// `port` is native-endian.
    /// Asserts that the address is ip4 or ip6.
    pub fn setPort(self: *Ip6Address, port: u16) void {
        self.sa.port = mem.nativeToBig(u16, port);
    }

    pub fn format(
        self: Ip6Address,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        out_stream: anytype,
    ) !void {
        if (fmt.len != 0) std.fmt.invalidFmtError(fmt, self);
        _ = options;
        const port = mem.bigToNative(u16, self.sa.port);
        if (mem.eql(u8, self.sa.addr[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
            try std.fmt.format(out_stream, "[::ffff:{}.{}.{}.{}]:{}", .{
                self.sa.addr[12],
                self.sa.addr[13],
                self.sa.addr[14],
                self.sa.addr[15],
                port,
            });
            return;
        }
        const big_endian_parts = @as(*align(1) const [8]u16, @ptrCast(&self.sa.addr));
        const native_endian_parts = switch (native_endian) {
            .big => big_endian_parts.*,
            .little => blk: {
                var buf: [8]u16 = undefined;
                for (big_endian_parts, 0..) |part, i| {
                    buf[i] = mem.bigToNative(u16, part);
                }
                break :blk buf;
            },
        };

        // Find the longest zero run
        var longest_start: usize = 8;
        var longest_len: usize = 0;
        var current_start: usize = 0;
        var current_len: usize = 0;

        for (native_endian_parts, 0..) |part, i| {
            if (part == 0) {
                if (current_len == 0) {
                    current_start = i;
                }
                current_len += 1;
                if (current_len > longest_len) {
                    longest_start = current_start;
                    longest_len = current_len;
                }
            } else {
                current_len = 0;
            }
        }

        // Only compress if the longest zero run is 2 or more
        if (longest_len < 2) {
            longest_start = 8;
            longest_len = 0;
        }

        try out_stream.writeAll("[");
        var i: usize = 0;
        var abbrv = false;
        while (i < native_endian_parts.len) : (i += 1) {
            if (i == longest_start) {
                // Emit "::" for the longest zero run
                if (!abbrv) {
                    try out_stream.writeAll(if (i == 0) "::" else ":");
                    abbrv = true;
                }
                i += longest_len - 1; // Skip the compressed range
                continue;
            }
            if (abbrv) {
                abbrv = false;
            }
            try std.fmt.format(out_stream, "{x}", .{native_endian_parts[i]});
            if (i != native_endian_parts.len - 1) {
                try out_stream.writeAll(":");
            }
        }
        try std.fmt.format(out_stream, "]:{}", .{port});
    }

    pub fn getOsSockLen(self: Ip6Address) posix.socklen_t {
        _ = self;
        return @sizeOf(posix.sockaddr.in6);
    }
};

pub fn connectUnixSocket(path: []const u8) !Stream {
    const opt_non_block = 0;
    const sockfd = try posix.socket(
        posix.AF.UNIX,
        posix.SOCK.STREAM | posix.SOCK.CLOEXEC | opt_non_block,
        0,
    );
    errdefer Stream.close(.{ .handle = sockfd });

    var addr = try std.net.Address.initUnix(path);
    try posix.connect(sockfd, &addr.any, addr.getOsSockLen());

    return .{ .handle = sockfd };
}

fn if_nametoindex(name: []const u8) IPv6InterfaceError!u32 {
    if (native_os == .linux) {
        var ifr: posix.ifreq = undefined;
        const sockfd = try posix.socket(posix.AF.UNIX, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
        defer Stream.close(.{ .handle = sockfd });

        @memcpy(ifr.ifrn.name[0..name.len], name);
        ifr.ifrn.name[name.len] = 0;

        // TODO investigate if this needs to be integrated with evented I/O.
        try posix.ioctl_SIOCGIFINDEX(sockfd, &ifr);

        return @bitCast(ifr.ifru.ivalue);
    }

    if (native_os.isDarwin()) {
        if (name.len >= posix.IFNAMESIZE)
            return error.NameTooLong;

        var if_name: [posix.IFNAMESIZE:0]u8 = undefined;
        @memcpy(if_name[0..name.len], name);
        if_name[name.len] = 0;
        const if_slice = if_name[0..name.len :0];
        const index = std.c.if_nametoindex(if_slice);
        if (index == 0)
            return error.InterfaceNotFound;
        return @as(u32, @bitCast(index));
    }

    if (native_os == .windows) {
        if (name.len >= posix.IFNAMESIZE)
            return error.NameTooLong;

        var interface_name: [posix.IFNAMESIZE:0]u8 = undefined;
        @memcpy(interface_name[0..name.len], name);
        interface_name[name.len] = 0;
        const index = std.os.windows.ws2_32.if_nametoindex(@as([*:0]const u8, &interface_name));
        if (index == 0)
            return error.InterfaceNotFound;
        return index;
    }

    @compileError("std.net.if_nametoindex unimplemented for this OS");
}

pub const AddressList = struct {
    arena: std.heap.ArenaAllocator,
    addrs: []Address,
    canon_name: ?[]u8,

    pub fn deinit(self: *AddressList) void {
        // Here we copy the arena allocator into stack memory, because
        // otherwise it would destroy itself while it was still working.
        var arena = self.arena;
        arena.deinit();
        // self is destroyed
    }
};

pub const TcpConnectToHostError = GetAddressListError || TcpConnectToAddressError;

/// All memory allocated with `allocator` will be freed before this function returns.
pub fn tcpConnectToHost(allocator: mem.Allocator, name: []const u8, port: u16) TcpConnectToHostError!Stream {
    const list = try getAddressList(allocator, name, port);
    defer list.deinit();

    if (list.addrs.len == 0) return error.UnknownHostName;

    for (list.addrs) |addr| {
        return tcpConnectToAddress(addr) catch |err| switch (err) {
            error.ConnectionRefused => {
                continue;
            },
            else => return err,
        };
    }
    return posix.ConnectError.ConnectionRefused;
}

pub const TcpConnectToAddressError = posix.SocketError || posix.ConnectError;

pub fn tcpConnectToAddress(address: Address) TcpConnectToAddressError!Stream {
    const nonblock = 0;
    const sock_flags = posix.SOCK.STREAM | nonblock |
        (if (native_os == .windows) 0 else posix.SOCK.CLOEXEC);
    const sockfd = try posix.socket(address.any.family, sock_flags, posix.IPPROTO.TCP);
    errdefer Stream.close(.{ .handle = sockfd });

    try posix.connect(sockfd, &address.any, address.getOsSockLen());

    return Stream{ .handle = sockfd };
}

const GetAddressListError = std.mem.Allocator.Error || std.fs.File.OpenError || std.fs.File.ReadError || posix.SocketError || posix.BindError || posix.SetSockOptError || error{
    // TODO: break this up into error sets from the various underlying functions

    TemporaryNameServerFailure,
    NameServerFailure,
    AddressFamilyNotSupported,
    UnknownHostName,
    ServiceUnavailable,
    Unexpected,

    HostLacksNetworkAddresses,

    InvalidCharacter,
    InvalidEnd,
    NonCanonical,
    Overflow,
    Incomplete,
    InvalidIpv4Mapping,
    InvalidIPAddressFormat,

    InterfaceNotFound,
    FileSystem,
};

/// Call `AddressList.deinit` on the result.
pub fn getAddressList(allocator: mem.Allocator, name: []const u8, port: u16) GetAddressListError!*AddressList {
    const result = blk: {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        const result = try arena.allocator().create(AddressList);
        result.* = AddressList{
            .arena = arena,
            .addrs = undefined,
            .canon_name = null,
        };
        break :blk result;
    };
    const arena = result.arena.allocator();
    errdefer result.deinit();

    if (native_os == .windows) {
        const name_c = try allocator.dupeZ(u8, name);
        defer allocator.free(name_c);

        const port_c = try std.fmt.allocPrintZ(allocator, "{}", .{port});
        defer allocator.free(port_c);

        const ws2_32 = windows.ws2_32;
        const hints: posix.addrinfo = .{
            .flags = .{ .NUMERICSERV = true },
            .family = posix.AF.UNSPEC,
            .socktype = posix.SOCK.STREAM,
            .protocol = posix.IPPROTO.TCP,
            .canonname = null,
            .addr = null,
            .addrlen = 0,
            .next = null,
        };
        var res: ?*posix.addrinfo = null;
        var first = true;
        while (true) {
            const rc = ws2_32.getaddrinfo(name_c.ptr, port_c.ptr, &hints, &res);
            switch (@as(windows.ws2_32.WinsockError, @enumFromInt(@as(u16, @intCast(rc))))) {
                @as(windows.ws2_32.WinsockError, @enumFromInt(0)) => break,
                .WSATRY_AGAIN => return error.TemporaryNameServerFailure,
                .WSANO_RECOVERY => return error.NameServerFailure,
                .WSAEAFNOSUPPORT => return error.AddressFamilyNotSupported,
                .WSA_NOT_ENOUGH_MEMORY => return error.OutOfMemory,
                .WSAHOST_NOT_FOUND => return error.UnknownHostName,
                .WSATYPE_NOT_FOUND => return error.ServiceUnavailable,
                .WSAEINVAL => unreachable,
                .WSAESOCKTNOSUPPORT => unreachable,
                .WSANOTINITIALISED => {
                    if (!first) return error.Unexpected;
                    first = false;
                    try windows.callWSAStartup();
                    continue;
                },
                else => |err| return windows.unexpectedWSAError(err),
            }
        }
        defer ws2_32.freeaddrinfo(res);

        const addr_count = blk: {
            var count: usize = 0;
            var it = res;
            while (it) |info| : (it = info.next) {
                if (info.addr != null) {
                    count += 1;
                }
            }
            break :blk count;
        };
        result.addrs = try arena.alloc(Address, addr_count);

        var it = res;
        var i: usize = 0;
        while (it) |info| : (it = info.next) {
            const addr = info.addr orelse continue;
            result.addrs[i] = Address.initPosix(@alignCast(addr));

            if (info.canonname) |n| {
                if (result.canon_name == null) {
                    result.canon_name = try arena.dupe(u8, mem.sliceTo(n, 0));
                }
            }
            i += 1;
        }

        return result;
    }

    if (builtin.link_libc) {
        const name_c = try allocator.dupeZ(u8, name);
        defer allocator.free(name_c);

        const port_c = try std.fmt.allocPrintZ(allocator, "{}", .{port});
        defer allocator.free(port_c);

        const hints: posix.addrinfo = .{
            .flags = .{ .NUMERICSERV = true },
            .family = posix.AF.UNSPEC,
            .socktype = posix.SOCK.STREAM,
            .protocol = posix.IPPROTO.TCP,
            .canonname = null,
            .addr = null,
            .addrlen = 0,
            .next = null,
        };
        var res: ?*posix.addrinfo = null;
        switch (posix.system.getaddrinfo(name_c.ptr, port_c.ptr, &hints, &res)) {
            @as(posix.system.EAI, @enumFromInt(0)) => {},
            .ADDRFAMILY => return error.HostLacksNetworkAddresses,
            .AGAIN => return error.TemporaryNameServerFailure,
            .BADFLAGS => unreachable, // Invalid hints
            .FAIL => return error.NameServerFailure,
            .FAMILY => return error.AddressFamilyNotSupported,
            .MEMORY => return error.OutOfMemory,
            .NODATA => return error.HostLacksNetworkAddresses,
            .NONAME => return error.UnknownHostName,
            .SERVICE => return error.ServiceUnavailable,
            .SOCKTYPE => unreachable, // Invalid socket type requested in hints
            .SYSTEM => switch (posix.errno(-1)) {
                else => |e| return posix.unexpectedErrno(e),
            },
            else => unreachable,
        }
        defer if (res) |some| posix.system.freeaddrinfo(some);

        const addr_count = blk: {
            var count: usize = 0;
            var it = res;
            while (it) |info| : (it = info.next) {
                if (info.addr != null) {
                    count += 1;
                }
            }
            break :blk count;
        };
        result.addrs = try arena.alloc(Address, addr_count);

        var it = res;
        var i: usize = 0;
        while (it) |info| : (it = info.next) {
            const addr = info.addr orelse continue;
            result.addrs[i] = Address.initPosix(@alignCast(addr));

            if (info.canonname) |n| {
                if (result.canon_name == null) {
                    result.canon_name = try arena.dupe(u8, mem.sliceTo(n, 0));
                }
            }
            i += 1;
        }

        return result;
    }

    if (native_os == .linux) {
        const family = posix.AF.UNSPEC;
        var lookup_addrs = std.ArrayList(LookupAddr).init(allocator);
        defer lookup_addrs.deinit();

        var canon = std.ArrayList(u8).init(arena);
        defer canon.deinit();

        try linuxLookupName(&lookup_addrs, &canon, name, family, .{ .NUMERICSERV = true }, port);

        result.addrs = try arena.alloc(Address, lookup_addrs.items.len);
        if (canon.items.len != 0) {
            result.canon_name = try canon.toOwnedSlice();
        }

        for (lookup_addrs.items, 0..) |lookup_addr, i| {
            result.addrs[i] = lookup_addr.addr;
            assert(result.addrs[i].getPort() == port);
        }

        return result;
    }
    @compileError("std.net.getAddressList unimplemented for this OS");
}

const LookupAddr = struct {
    addr: Address,
    sortkey: i32 = 0,
};

const DAS_USABLE = 0x40000000;
const DAS_MATCHINGSCOPE = 0x20000000;
const DAS_MATCHINGLABEL = 0x10000000;
const DAS_PREC_SHIFT = 20;
const DAS_SCOPE_SHIFT = 16;
const DAS_PREFIX_SHIFT = 8;
const DAS_ORDER_SHIFT = 0;

fn linuxLookupName(
    addrs: *std.ArrayList(LookupAddr),
    canon: *std.ArrayList(u8),
    opt_name: ?[]const u8,
    family: posix.sa_family_t,
    flags: posix.AI,
    port: u16,
) !void {
    if (opt_name) |name| {
        // reject empty name and check len so it fits into temp bufs
        canon.items.len = 0;
        try canon.appendSlice(name);
        if (Address.parseExpectingFamily(name, family, port)) |addr| {
            try addrs.append(LookupAddr{ .addr = addr });
        } else |name_err| if (flags.NUMERICHOST) {
            return name_err;
        } else {
            try linuxLookupNameFromHosts(addrs, canon, name, family, port);
            if (addrs.items.len == 0) {
                // RFC 6761 Section 6.3.3
                // Name resolution APIs and libraries SHOULD recognize localhost
                // names as special and SHOULD always return the IP loopback address
                // for address queries and negative responses for all other query
                // types.

                // Check for equal to "localhost(.)" or ends in ".localhost(.)"
                const localhost = if (name[name.len - 1] == '.') "localhost." else "localhost";
                if (mem.endsWith(u8, name, localhost) and (name.len == localhost.len or name[name.len - localhost.len] == '.')) {
                    try addrs.append(LookupAddr{ .addr = .{ .in = Ip4Address.parse("127.0.0.1", port) catch unreachable } });
                    try addrs.append(LookupAddr{ .addr = .{ .in6 = Ip6Address.parse("::1", port) catch unreachable } });
                    return;
                }

                try linuxLookupNameFromDnsSearch(addrs, canon, name, family, port);
            }
        }
    } else {
        try canon.resize(0);
        try linuxLookupNameFromNull(addrs, family, flags, port);
    }
    if (addrs.items.len == 0) return error.UnknownHostName;

    // No further processing is needed if there are fewer than 2
    // results or if there are only IPv4 results.
    if (addrs.items.len == 1 or family == posix.AF.INET) return;
    const all_ip4 = for (addrs.items) |addr| {
        if (addr.addr.any.family != posix.AF.INET) break false;
    } else true;
    if (all_ip4) return;

    // The following implements a subset of RFC 3484/6724 destination
    // address selection by generating a single 31-bit sort key for
    // each address. Rules 3, 4, and 7 are omitted for having
    // excessive runtime and code size cost and dubious benefit.
    // So far the label/precedence table cannot be customized.
    // This implementation is ported from musl libc.
    // A more idiomatic "ziggy" implementation would be welcome.
    for (addrs.items, 0..) |*addr, i| {
        var key: i32 = 0;
        var sa6: posix.sockaddr.in6 = undefined;
        @memset(@as([*]u8, @ptrCast(&sa6))[0..@sizeOf(posix.sockaddr.in6)], 0);
        var da6 = posix.sockaddr.in6{
            .family = posix.AF.INET6,
            .scope_id = addr.addr.in6.sa.scope_id,
            .port = 65535,
            .flowinfo = 0,
            .addr = [1]u8{0} ** 16,
        };
        var sa4: posix.sockaddr.in = undefined;
        @memset(@as([*]u8, @ptrCast(&sa4))[0..@sizeOf(posix.sockaddr.in)], 0);
        var da4 = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = 65535,
            .addr = 0,
            .zero = [1]u8{0} ** 8,
        };
        var sa: *align(4) posix.sockaddr = undefined;
        var da: *align(4) posix.sockaddr = undefined;
        var salen: posix.socklen_t = undefined;
        var dalen: posix.socklen_t = undefined;
        if (addr.addr.any.family == posix.AF.INET6) {
            da6.addr = addr.addr.in6.sa.addr;
            da = @ptrCast(&da6);
            dalen = @sizeOf(posix.sockaddr.in6);
            sa = @ptrCast(&sa6);
            salen = @sizeOf(posix.sockaddr.in6);
        } else {
            sa6.addr[0..12].* = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff".*;
            da6.addr[0..12].* = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff".*;
            mem.writeInt(u32, da6.addr[12..], addr.addr.in.sa.addr, native_endian);
            da4.addr = addr.addr.in.sa.addr;
            da = @ptrCast(&da4);
            dalen = @sizeOf(posix.sockaddr.in);
            sa = @ptrCast(&sa4);
            salen = @sizeOf(posix.sockaddr.in);
        }
        const dpolicy = policyOf(da6.addr);
        const dscope: i32 = scopeOf(da6.addr);
        const dlabel = dpolicy.label;
        const dprec: i32 = dpolicy.prec;
        const MAXADDRS = 3;
        var prefixlen: i32 = 0;
        const sock_flags = posix.SOCK.DGRAM | posix.SOCK.CLOEXEC;
        if (posix.socket(addr.addr.any.family, sock_flags, posix.IPPROTO.UDP)) |fd| syscalls: {
            defer Stream.close(.{ .handle = fd });
            posix.connect(fd, da, dalen) catch break :syscalls;
            key |= DAS_USABLE;
            posix.getsockname(fd, sa, &salen) catch break :syscalls;
            if (addr.addr.any.family == posix.AF.INET) {
                mem.writeInt(u32, sa6.addr[12..16], sa4.addr, native_endian);
            }
            if (dscope == @as(i32, scopeOf(sa6.addr))) key |= DAS_MATCHINGSCOPE;
            if (dlabel == labelOf(sa6.addr)) key |= DAS_MATCHINGLABEL;
            prefixlen = prefixMatch(sa6.addr, da6.addr);
        } else |_| {}
        key |= dprec << DAS_PREC_SHIFT;
        key |= (15 - dscope) << DAS_SCOPE_SHIFT;
        key |= prefixlen << DAS_PREFIX_SHIFT;
        key |= (MAXADDRS - @as(i32, @intCast(i))) << DAS_ORDER_SHIFT;
        addr.sortkey = key;
    }
    mem.sort(LookupAddr, addrs.items, {}, addrCmpLessThan);
}

const Policy = struct {
    addr: [16]u8,
    len: u8,
    mask: u8,
    prec: u8,
    label: u8,
};

const defined_policies = [_]Policy{
    Policy{
        .addr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01".*,
        .len = 15,
        .mask = 0xff,
        .prec = 50,
        .label = 0,
    },
    Policy{
        .addr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00".*,
        .len = 11,
        .mask = 0xff,
        .prec = 35,
        .label = 4,
    },
    Policy{
        .addr = "\x20\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".*,
        .len = 1,
        .mask = 0xff,
        .prec = 30,
        .label = 2,
    },
    Policy{
        .addr = "\x20\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".*,
        .len = 3,
        .mask = 0xff,
        .prec = 5,
        .label = 5,
    },
    Policy{
        .addr = "\xfc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".*,
        .len = 0,
        .mask = 0xfe,
        .prec = 3,
        .label = 13,
    },
    //  These are deprecated and/or returned to the address
    //  pool, so despite the RFC, treating them as special
    //  is probably wrong.
    // { "", 11, 0xff, 1, 3 },
    // { "\xfe\xc0", 1, 0xc0, 1, 11 },
    // { "\x3f\xfe", 1, 0xff, 1, 12 },
    // Last rule must match all addresses to stop loop.
    Policy{
        .addr = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".*,
        .len = 0,
        .mask = 0,
        .prec = 40,
        .label = 1,
    },
};

fn policyOf(a: [16]u8) *const Policy {
    for (&defined_policies) |*policy| {
        if (!mem.eql(u8, a[0..policy.len], policy.addr[0..policy.len])) continue;
        if ((a[policy.len] & policy.mask) != policy.addr[policy.len]) continue;
        return policy;
    }
    unreachable;
}

fn scopeOf(a: [16]u8) u```
