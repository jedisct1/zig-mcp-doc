```
 Data which can be indexed by
/// @intCast(usize, @intFromEnum(enum_value)).
/// If the enum is non-exhaustive, the resulting array will only be large enough
/// to hold all explicit fields.
/// If the enum contains any fields with values that cannot be represented
/// by usize, a compile error is issued.  The max_unused_slots parameter limits
/// the total number of items which have no matching enum key (holes in the enum
/// numbering).  So for example, if an enum has values 1, 2, 5, and 6, max_unused_slots
/// must be at least 3, to allow unused slots 0, 3, and 4.
/// The init_values parameter must be a struct with field names that match the enum values.
/// If the enum has multiple fields with the same value, the name of the first one must
/// be used.
pub fn directEnumArray(
    comptime E: type,
    comptime Data: type,
    comptime max_unused_slots: comptime_int,
    init_values: EnumFieldStruct(E, Data, null),
) [directEnumArrayLen(E, max_unused_slots)]Data {
    return directEnumArrayDefault(E, Data, null, max_unused_slots, init_values);
}

test directEnumArray {
    const E = enum(i4) { a = 4, b = 6, c = 2 };
    var runtime_false: bool = false;
    _ = &runtime_false;
    const array = directEnumArray(E, bool, 4, .{
        .a = true,
        .b = runtime_false,
        .c = true,
    });

    try testing.expectEqual([7]bool, @TypeOf(array));
    try testing.expectEqual(true, array[4]);
    try testing.expectEqual(false, array[6]);
    try testing.expectEqual(true, array[2]);
}

/// Initializes an array of Data which can be indexed by
/// @intCast(usize, @intFromEnum(enum_value)).  The enum must be exhaustive.
/// If the enum contains any fields with values that cannot be represented
/// by usize, a compile error is issued.  The max_unused_slots parameter limits
/// the total number of items which have no matching enum key (holes in the enum
/// numbering).  So for example, if an enum has values 1, 2, 5, and 6, max_unused_slots
/// must be at least 3, to allow unused slots 0, 3, and 4.
/// The init_values parameter must be a struct with field names that match the enum values.
/// If the enum has multiple fields with the same value, the name of the first one must
/// be used.
pub fn directEnumArrayDefault(
    comptime E: type,
    comptime Data: type,
    comptime default: ?Data,
    comptime max_unused_slots: comptime_int,
    init_values: EnumFieldStruct(E, Data, default),
) [directEnumArrayLen(E, max_unused_slots)]Data {
    const len = comptime directEnumArrayLen(E, max_unused_slots);
    var result: [len]Data = if (default) |d| [_]Data{d} ** len else undefined;
    inline for (@typeInfo(@TypeOf(init_values)).@"struct".fields) |f| {
        const enum_value = @field(E, f.name);
        const index = @as(usize, @intCast(@intFromEnum(enum_value)));
        result[index] = @field(init_values, f.name);
    }
    return result;
}

test directEnumArrayDefault {
    const E = enum(i4) { a = 4, b = 6, c = 2 };
    var runtime_false: bool = false;
    _ = &runtime_false;
    const array = directEnumArrayDefault(E, bool, false, 4, .{
        .a = true,
        .b = runtime_false,
    });

    try testing.expectEqual([7]bool, @TypeOf(array));
    try testing.expectEqual(true, array[4]);
    try testing.expectEqual(false, array[6]);
    try testing.expectEqual(false, array[2]);
}

test "directEnumArrayDefault slice" {
    const E = enum(i4) { a = 4, b = 6, c = 2 };
    var runtime_b = "b";
    _ = &runtime_b;
    const array = directEnumArrayDefault(E, []const u8, "default", 4, .{
        .a = "a",
        .b = runtime_b,
    });

    try testing.expectEqual([7][]const u8, @TypeOf(array));
    try testing.expectEqualSlices(u8, "a", array[4]);
    try testing.expectEqualSlices(u8, "b", array[6]);
    try testing.expectEqualSlices(u8, "default", array[2]);
}

/// Deprecated: Use @field(E, @tagName(tag)) or @field(E, string)
pub fn nameCast(comptime E: type, comptime value: anytype) E {
    return comptime blk: {
        const V = @TypeOf(value);
        if (V == E) break :blk value;
        const name: ?[]const u8 = switch (@typeInfo(V)) {
            .enum_literal, .@"enum" => @tagName(value),
            .pointer => value,
            else => null,
        };
        if (name) |n| {
            if (@hasField(E, n)) {
                break :blk @field(E, n);
            }
            @compileError("Enum " ++ @typeName(E) ++ " has no field named " ++ n);
        }
        @compileError("Cannot cast from " ++ @typeName(@TypeOf(value)) ++ " to " ++ @typeName(E));
    };
}

test nameCast {
    const A = enum(u1) { a = 0, b = 1 };
    const B = enum(u1) { a = 1, b = 0 };
    try testing.expectEqual(A.a, nameCast(A, .a));
    try testing.expectEqual(A.a, nameCast(A, A.a));
    try testing.expectEqual(A.a, nameCast(A, B.a));
    try testing.expectEqual(A.a, nameCast(A, "a"));
    try testing.expectEqual(A.a, nameCast(A, @as(*const [1]u8, "a")));
    try testing.expectEqual(A.a, nameCast(A, @as([:0]const u8, "a")));
    try testing.expectEqual(A.a, nameCast(A, @as([]const u8, "a")));

    try testing.expectEqual(B.a, nameCast(B, .a));
    try testing.expectEqual(B.a, nameCast(B, A.a));
    try testing.expectEqual(B.a, nameCast(B, B.a));
    try testing.expectEqual(B.a, nameCast(B, "a"));

    try testing.expectEqual(B.b, nameCast(B, .b));
    try testing.expectEqual(B.b, nameCast(B, A.b));
    try testing.expectEqual(B.b, nameCast(B, B.b));
    try testing.expectEqual(B.b, nameCast(B, "b"));
}

/// A set of enum elements, backed by a bitfield.  If the enum
/// is exhaustive but not dense, a mapping will be constructed from enum values
/// to dense indices.  This type does no dynamic allocation and
/// can be copied by value.
pub fn EnumSet(comptime E: type) type {
    return struct {
        const Self = @This();

        /// The indexing rules for converting between keys and indices.
        pub const Indexer = EnumIndexer(E);
        /// The element type for this set.
        pub const Key = Indexer.Key;

        const BitSet = std.StaticBitSet(Indexer.count);

        /// The maximum number of items in this set.
        pub const len = Indexer.count;

        bits: BitSet = BitSet.initEmpty(),

        /// Initializes the set using a struct of bools
        pub fn init(init_values: EnumFieldStruct(E, bool, false)) Self {
            @setEvalBranchQuota(2 * @typeInfo(E).@"enum".fields.len);
            var result: Self = .{};
            if (@typeInfo(E).@"enum".is_exhaustive) {
                inline for (0..Self.len) |i| {
                    const key = comptime Indexer.keyForIndex(i);
                    const tag = @tagName(key);
                    if (@field(init_values, tag)) {
                        result.bits.set(i);
                    }
                }
            } else {
                inline for (std.meta.fields(E)) |field| {
                    const key = @field(E, field.name);
                    if (@field(init_values, field.name)) {
                        const i = comptime Indexer.indexOf(key);
                        result.bits.set(i);
                    }
                }
            }
            return result;
        }

        /// Returns a set containing no keys.
        pub fn initEmpty() Self {
            return .{ .bits = BitSet.initEmpty() };
        }

        /// Returns a set containing all possible keys.
        pub fn initFull() Self {
            return .{ .bits = BitSet.initFull() };
        }

        /// Returns a set containing multiple keys.
        pub fn initMany(keys: []const Key) Self {
            var set = initEmpty();
            for (keys) |key| set.insert(key);
            return set;
        }

        /// Returns a set containing a single key.
        pub fn initOne(key: Key) Self {
            return initMany(&[_]Key{key});
        }

        /// Returns the number of keys in the set.
        pub fn count(self: Self) usize {
            return self.bits.count();
        }

        /// Checks if a key is in the set.
        pub fn contains(self: Self, key: Key) bool {
            return self.bits.isSet(Indexer.indexOf(key));
        }

        /// Puts a key in the set.
        pub fn insert(self: *Self, key: Key) void {
            self.bits.set(Indexer.indexOf(key));
        }

        /// Removes a key from the set.
        pub fn remove(self: *Self, key: Key) void {
            self.bits.unset(Indexer.indexOf(key));
        }

        /// Changes the presence of a key in the set to match the passed bool.
        pub fn setPresent(self: *Self, key: Key, present: bool) void {
            self.bits.setValue(Indexer.indexOf(key), present);
        }

        /// Toggles the presence of a key in the set.  If the key is in
        /// the set, removes it.  Otherwise adds it.
        pub fn toggle(self: *Self, key: Key) void {
            self.bits.toggle(Indexer.indexOf(key));
        }

        /// Toggles the presence of all keys in the passed set.
        pub fn toggleSet(self: *Self, other: Self) void {
            self.bits.toggleSet(other.bits);
        }

        /// Toggles all possible keys in the set.
        pub fn toggleAll(self: *Self) void {
            self.bits.toggleAll();
        }

        /// Adds all keys in the passed set to this set.
        pub fn setUnion(self: *Self, other: Self) void {
            self.bits.setUnion(other.bits);
        }

        /// Removes all keys which are not in the passed set.
        pub fn setIntersection(self: *Self, other: Self) void {
            self.bits.setIntersection(other.bits);
        }

        /// Returns true iff both sets have the same keys.
        pub fn eql(self: Self, other: Self) bool {
            return self.bits.eql(other.bits);
        }

        /// Returns true iff all the keys in this set are
        /// in the other set. The other set may have keys
        /// not found in this set.
        pub fn subsetOf(self: Self, other: Self) bool {
            return self.bits.subsetOf(other.bits);
        }

        /// Returns true iff this set contains all the keys
        /// in the other set. This set may have keys not
        /// found in the other set.
        pub fn supersetOf(self: Self, other: Self) bool {
            return self.bits.supersetOf(other.bits);
        }

        /// Returns a set with all the keys not in this set.
        pub fn complement(self: Self) Self {
            return .{ .bits = self.bits.complement() };
        }

        /// Returns a set with keys that are in either this
        /// set or the other set.
        pub fn unionWith(self: Self, other: Self) Self {
            return .{ .bits = self.bits.unionWith(other.bits) };
        }

        /// Returns a set with keys that are in both this
        /// set and the other set.
        pub fn intersectWith(self: Self, other: Self) Self {
            return .{ .bits = self.bits.intersectWith(other.bits) };
        }

        /// Returns a set with keys that are in either this
        /// set or the other set, but not both.
        pub fn xorWith(self: Self, other: Self) Self {
            return .{ .bits = self.bits.xorWith(other.bits) };
        }

        /// Returns a set with keys that are in this set
        /// except for keys in the other set.
        pub fn differenceWith(self: Self, other: Self) Self {
            return .{ .bits = self.bits.differenceWith(other.bits) };
        }

        /// Returns an iterator over this set, which iterates in
        /// index order.  Modifications to the set during iteration
        /// may or may not be observed by the iterator, but will
        /// not invalidate it.
        pub fn iterator(self: *const Self) Iterator {
            return .{ .inner = self.bits.iterator(.{}) };
        }

        pub const Iterator = struct {
            inner: BitSet.Iterator(.{}),

            pub fn next(self: *Iterator) ?Key {
                return if (self.inner.next()) |index|
                    Indexer.keyForIndex(index)
                else
                    null;
            }
        };
    };
}

/// A map keyed by an enum, backed by a bitfield and a dense array.
/// If the enum is exhaustive but not dense, a mapping will be constructed from
/// enum values to dense indices.  This type does no dynamic
/// allocation and can be copied by value.
pub fn EnumMap(comptime E: type, comptime V: type) type {
    return struct {
        const Self = @This();

        /// The index mapping for this map
        pub const Indexer = EnumIndexer(E);
        /// The key type used to index this map
        pub const Key = Indexer.Key;
        /// The value type stored in this map
        pub const Value = V;
        /// The number of possible keys in the map
        pub const len = Indexer.count;

        const BitSet = std.StaticBitSet(Indexer.count);

        /// Bits determining whether items are in the map
        bits: BitSet = BitSet.initEmpty(),
        /// Values of items in the map.  If the associated
        /// bit is zero, the value is undefined.
        values: [Indexer.count]Value = undefined,

        /// Initializes the map using a sparse struct of optionals
        pub fn init(init_values: EnumFieldStruct(E, ?Value, @as(?Value, null))) Self {
            @setEvalBranchQuota(2 * @typeInfo(E).@"enum".fields.len);
            var result: Self = .{};
            if (@typeInfo(E).@"enum".is_exhaustive) {
                inline for (0..Self.len) |i| {
                    const key = comptime Indexer.keyForIndex(i);
                    const tag = @tagName(key);
                    if (@field(init_values, tag)) |*v| {
                        result.bits.set(i);
                        result.values[i] = v.*;
                    }
                }
            } else {
                inline for (std.meta.fields(E)) |field| {
                    const key = @field(E, field.name);
                    if (@field(init_values, field.name)) |*v| {
                        const i = comptime Indexer.indexOf(key);
                        result.bits.set(i);
                        result.values[i] = v.*;
                    }
                }
            }
            return result;
        }

        /// Initializes a full mapping with all keys set to value.
        /// Consider using EnumArray instead if the map will remain full.
        pub fn initFull(value: Value) Self {
            var result: Self = .{
                .bits = Self.BitSet.initFull(),
                .values = undefined,
            };
            @memset(&result.values, value);
            return result;
        }

        /// Initializes a full mapping with supplied values.
        /// Consider using EnumArray instead if the map will remain full.
        pub fn initFullWith(init_values: EnumFieldStruct(E, Value, null)) Self {
            return initFullWithDefault(null, init_values);
        }

        /// Initializes a full mapping with a provided default.
        /// Consider using EnumArray instead if the map will remain full.
        pub fn initFullWithDefault(comptime default: ?Value, init_values: EnumFieldStruct(E, Value, default)) Self {
            @setEvalBranchQuota(2 * @typeInfo(E).@"enum".fields.len);
            var result: Self = .{
                .bits = Self.BitSet.initFull(),
                .values = undefined,
            };
            inline for (0..Self.len) |i| {
                const key = comptime Indexer.keyForIndex(i);
                const tag = @tagName(key);
                result.values[i] = @field(init_values, tag);
            }
            return result;
        }

        /// The number of items in the map.
        pub fn count(self: Self) usize {
            return self.bits.count();
        }

        /// Checks if the map contains an item.
        pub fn contains(self: Self, key: Key) bool {
            return self.bits.isSet(Indexer.indexOf(key));
        }

        /// Gets the value associated with a key.
        /// If the key is not in the map, returns null.
        pub fn get(self: Self, key: Key) ?Value {
            const index = Indexer.indexOf(key);
            return if (self.bits.isSet(index)) self.values[index] else null;
        }

        /// Gets the value associated with a key, which must
        /// exist in the map.
        pub fn getAssertContains(self: Self, key: Key) Value {
            const index = Indexer.indexOf(key);
            assert(self.bits.isSet(index));
            return self.values[index];
        }

        /// Gets the address of the value associated with a key.
        /// If the key is not in the map, returns null.
        pub fn getPtr(self: *Self, key: Key) ?*Value {
            const index = Indexer.indexOf(key);
            return if (self.bits.isSet(index)) &self.values[index] else null;
        }

        /// Gets the address of the const value associated with a key.
        /// If the key is not in the map, returns null.
        pub fn getPtrConst(self: *const Self, key: Key) ?*const Value {
            const index = Indexer.indexOf(key);
            return if (self.bits.isSet(index)) &self.values[index] else null;
        }

        /// Gets the address of the value associated with a key.
        /// The key must be present in the map.
        pub fn getPtrAssertContains(self: *Self, key: Key) *Value {
            const index = Indexer.indexOf(key);
            assert(self.bits.isSet(index));
            return &self.values[index];
        }

        /// Gets the address of the const value associated with a key.
        /// The key must be present in the map.
        pub fn getPtrConstAssertContains(self: *const Self, key: Key) *const Value {
            const index = Indexer.indexOf(key);
            assert(self.bits.isSet(index));
            return &self.values[index];
        }

        /// Adds the key to the map with the supplied value.
        /// If the key is already in the map, overwrites the value.
        pub fn put(self: *Self, key: Key, value: Value) void {
            const index = Indexer.indexOf(key);
            self.bits.set(index);
            self.values[index] = value;
        }

        /// Adds the key to the map with an undefined value.
        /// If the key is already in the map, the value becomes undefined.
        /// A pointer to the value is returned, which should be
        /// used to initialize the value.
        pub fn putUninitialized(self: *Self, key: Key) *Value {
            const index = Indexer.indexOf(key);
            self.bits.set(index);
            self.values[index] = undefined;
            return &self.values[index];
        }

        /// Sets the value associated with the key in the map,
        /// and returns the old value.  If the key was not in
        /// the map, returns null.
        pub fn fetchPut(self: *Self, key: Key, value: Value) ?Value {
            const index = Indexer.indexOf(key);
            const result: ?Value = if (self.bits.isSet(index)) self.values[index] else null;
            self.bits.set(index);
            self.values[index] = value;
            return result;
        }

        /// Removes a key from the map.  If the key was not in the map,
        /// does nothing.
        pub fn remove(self: *Self, key: Key) void {
            const index = Indexer.indexOf(key);
            self.bits.unset(index);
            self.values[index] = undefined;
        }

        /// Removes a key from the map, and returns the old value.
        /// If the key was not in the map, returns null.
        pub fn fetchRemove(self: *Self, key: Key) ?Value {
            const index = Indexer.indexOf(key);
            const result: ?Value = if (self.bits.isSet(index)) self.values[index] else null;
            self.bits.unset(index);
            self.values[index] = undefined;
            return result;
        }

        /// Returns an iterator over the map, which visits items in index order.
        /// Modifications to the underlying map may or may not be observed by
        /// the iterator, but will not invalidate it.
        pub fn iterator(self: *Self) Iterator {
            return .{
                .inner = self.bits.iterator(.{}),
                .values = &self.values,
            };
        }

        /// An entry in the map.
        pub const Entry = struct {
            /// The key associated with this entry.
            /// Modifying this key will not change the map.
            key: Key,

            /// A pointer to the value in the map associated
            /// with this key.  Modifications through this
            /// pointer will modify the underlying data.
            value: *Value,
        };

        pub const Iterator = struct {
            inner: BitSet.Iterator(.{}),
            values: *[Indexer.count]Value,

            pub fn next(self: *Iterator) ?Entry {
                return if (self.inner.next()) |index|
                    Entry{
                        .key = Indexer.keyForIndex(index),
                        .value = &self.values[index],
                    }
                else
                    null;
            }
        };
    };
}

test EnumMap {
    const Ball = enum { red, green, blue };

    const some = EnumMap(Ball, u8).init(.{
        .green = 0xff,
        .blue = 0x80,
    });
    try testing.expectEqual(2, some.count());
    try testing.expectEqual(null, some.get(.red));
    try testing.expectEqual(0xff, some.get(.green));
    try testing.expectEqual(0x80, some.get(.blue));
}

/// A multiset of enum elements up to a count of usize. Backed
/// by an EnumArray. This type does no dynamic allocation and can
/// be copied by value.
pub fn EnumMultiset(comptime E: type) type {
    return BoundedEnumMultiset(E, usize);
}

/// A multiset of enum elements up to CountSize. Backed by an
/// EnumArray. This type does no dynamic allocation and can be
/// copied by value.
pub fn BoundedEnumMultiset(comptime E: type, comptime CountSize: type) type {
    return struct {
        const Self = @This();

        counts: EnumArray(E, CountSize),

        /// Initializes the multiset using a struct of counts.
        pub fn init(init_counts: EnumFieldStruct(E, CountSize, 0)) Self {
            @setEvalBranchQuota(2 * @typeInfo(E).@"enum".fields.len);
            var self = initWithCount(0);
            inline for (@typeInfo(E).@"enum".fields) |field| {
                const c = @field(init_counts, field.name);
                const key = @as(E, @enumFromInt(field.value));
                self.counts.set(key, c);
            }
            return self;
        }

        /// Initializes the multiset with a count of zero.
        pub fn initEmpty() Self {
            return initWithCount(0);
        }

        /// Initializes the multiset with all keys at the
        /// same count.
        pub fn initWithCount(comptime c: CountSize) Self {
            return .{
                .counts = EnumArray(E, CountSize).initDefault(c, .{}),
            };
        }

        /// Returns the total number of key counts in the multiset.
        pub fn count(self: Self) usize {
            var sum: usize = 0;
            for (self.counts.values) |c| {
                sum += c;
            }
            return sum;
        }

        /// Checks if at least one key in multiset.
        pub fn contains(self: Self, key: E) bool {
            return self.counts.get(key) > 0;
        }

        /// Removes all instance of a key from multiset. Same as
        /// setCount(key, 0).
        pub fn removeAll(self: *Self, key: E) void {
            return self.counts.set(key, 0);
        }

        /// Increases the key count by given amount. Caller asserts
        /// operation will not overflow.
        pub fn addAssertSafe(self: *Self, key: E, c: CountSize) void {
            self.counts.getPtr(key).* += c;
        }

        /// Increases the key count by given amount.
        pub fn add(self: *Self, key: E, c: CountSize) error{Overflow}!void {
            self.counts.set(key, try std.math.add(CountSize, self.counts.get(key), c));
        }

        /// Decreases the key count by given amount. If amount is
        /// greater than the number of keys in multset, then key count
        /// will be set to zero.
        pub fn remove(self: *Self, key: E, c: CountSize) void {
            self.counts.getPtr(key).* -= @min(self.getCount(key), c);
        }

        /// Returns the count for a key.
        pub fn getCount(self: Self, key: E) CountSize {
            return self.counts.get(key);
        }

        /// Set the count for a key.
        pub fn setCount(self: *Self, key: E, c: CountSize) void {
            self.counts.set(key, c);
        }

        /// Increases the all key counts by given multiset. Caller
        /// asserts operation will not overflow any key.
        pub fn addSetAssertSafe(self: *Self, other: Self) void {
            inline for (@typeInfo(E).@"enum".fields) |field| {
                const key = @as(E, @enumFromInt(field.value));
                self.addAssertSafe(key, other.getCount(key));
            }
        }

        /// Increases the all key counts by given multiset.
        pub fn addSet(self: *Self, other: Self) error{Overflow}!void {
            inline for (@typeInfo(E).@"enum".fields) |field| {
                const key = @as(E, @enumFromInt(field.value));
                try self.add(key, other.getCount(key));
            }
        }

        /// Decreases the all key counts by given multiset. If
        /// the given multiset has more key counts than this,
        /// then that key will have a key count of zero.
        pub fn removeSet(self: *Self, other: Self) void {
            inline for (@typeInfo(E).@"enum".fields) |field| {
                const key = @as(E, @enumFromInt(field.value));
                self.remove(key, other.getCount(key));
            }
        }

        /// Returns true iff all key counts are the same as
        /// given multiset.
        pub fn eql(self: Self, other: Self) bool {
            inline for (@typeInfo(E).@"enum".fields) |field| {
                const key = @as(E, @enumFromInt(field.value));
                if (self.getCount(key) != other.getCount(key)) {
                    return false;
                }
            }
            return true;
        }

        /// Returns true iff all key counts less than or
        /// equal to the given multiset.
        pub fn subsetOf(self: Self, other: Self) bool {
            inline for (@typeInfo(E).@"enum".fields) |field| {
                const key = @as(E, @enumFromInt(field.value));
                if (self.getCount(key) > other.getCount(key)) {
                    return false;
                }
            }
            return true;
        }

        /// Returns true iff all key counts greater than or
        /// equal to the given multiset.
        pub fn supersetOf(self: Self, other: Self) bool {
            inline for (@typeInfo(E).@"enum".fields) |field| {
                const key = @as(E, @enumFromInt(field.value));
                if (self.getCount(key) < other.getCount(key)) {
                    return false;
                }
            }
            return true;
        }

        /// Returns a multiset with the total key count of this
        /// multiset and the other multiset. Caller asserts
        /// operation will not overflow any key.
        pub fn plusAssertSafe(self: Self, other: Self) Self {
            var result = self;
            result.addSetAssertSafe(other);
            return result;
        }

        /// Returns a multiset with the total key count of this
        /// multiset and the other multiset.
        pub fn plus(self: Self, other: Self) error{Overflow}!Self {
            var result = self;
            try result.addSet(other);
            return result;
        }

        /// Returns a multiset with the key count of this
        /// multiset minus the corresponding key count in the
        /// other multiset. If the other multiset contains
        /// more key count than this set, that key will have
        /// a count of zero.
        pub fn minus(self: Self, other: Self) Self {
            var result = self;
            result.removeSet(other);
            return result;
        }

        pub const Entry = EnumArray(E, CountSize).Entry;
        pub const Iterator = EnumArray(E, CountSize).Iterator;

        /// Returns an iterator over this multiset. Keys with zero
        /// counts are included. Modifications to the set during
        /// iteration may or may not be observed by the iterator,
        /// but will not invalidate it.
        pub fn iterator(self: *Self) Iterator {
            return self.counts.iterator();
        }
    };
}

test EnumMultiset {
    const Ball = enum { red, green, blue };

    const empty = EnumMultiset(Ball).initEmpty();
    const r0_g1_b2 = EnumMultiset(Ball).init(.{
        .red = 0,
        .green = 1,
        .blue = 2,
    });
    const ten_of_each = EnumMultiset(Ball).initWithCount(10);

    try testing.expectEqual(empty.count(), 0);
    try testing.expectEqual(r0_g1_b2.count(), 3);
    try testing.expectEqual(ten_of_each.count(), 30);

    try testing.expect(!empty.contains(.red));
    try testing.expect(!empty.contains(.green));
    try testing.expect(!empty.contains(.blue));

    try testing.expect(!r0_g1_b2.contains(.red));
    try testing.expect(r0_g1_b2.contains(.green));
    try testing.expect(r0_g1_b2.contains(.blue));

    try testing.expect(ten_of_each.contains(.red));
    try testing.expect(ten_of_each.contains(.green));
    try testing.expect(ten_of_each.contains(.blue));

    {
        var copy = ten_of_each;
        copy.removeAll(.red);
        try testing.expect(!copy.contains(.red));

        // removeAll second time does nothing
        copy.removeAll(.red);
        try testing.expect(!copy.contains(.red));
    }

    {
        var copy = ten_of_each;
        copy.addAssertSafe(.red, 6);
        try testing.expectEqual(copy.getCount(.red), 16);
    }

    {
        var copy = ten_of_each;
        try copy.add(.red, 6);
        try testing.expectEqual(copy.getCount(.red), 16);

        try testing.expectError(error.Overflow, copy.add(.red, std.math.maxInt(usize)));
    }

    {
        var copy = ten_of_each;
        copy.remove(.red, 4);
        try testing.expectEqual(copy.getCount(.red), 6);

        // subtracting more it contains does not underflow
        copy.remove(.green, 14);
        try testing.expectEqual(copy.getCount(.green), 0);
    }

    try testing.expectEqual(empty.getCount(.green), 0);
    try testing.expectEqual(r0_g1_b2.getCount(.green), 1);
    try testing.expectEqual(ten_of_each.getCount(.green), 10);

    {
        var copy = empty;
        copy.setCount(.red, 6);
        try testing.expectEqual(copy.getCount(.red), 6);
    }

    {
        var copy = r0_g1_b2;
        copy.addSetAssertSafe(ten_of_each);
        try testing.expectEqual(copy.getCount(.red), 10);
        try testing.expectEqual(copy.getCount(.green), 11);
        try testing.expectEqual(copy.getCount(.blue), 12);
    }

    {
        var copy = r0_g1_b2;
        try copy.addSet(ten_of_each);
        try testing.expectEqual(copy.getCount(.red), 10);
        try testing.expectEqual(copy.getCount(.green), 11);
        try testing.expectEqual(copy.getCount(.blue), 12);

        const full = EnumMultiset(Ball).initWithCount(std.math.maxInt(usize));
        try testing.expectError(error.Overflow, copy.addSet(full));
    }

    {
        var copy = ten_of_each;
        copy.removeSet(r0_g1_b2);
        try testing.expectEqual(copy.getCount(.red), 10);
        try testing.expectEqual(copy.getCount(.green), 9);
        try testing.expectEqual(copy.getCount(.blue), 8);

        copy.removeSet(ten_of_each);
        try testing.expectEqual(copy.getCount(.red), 0);
        try testing.expectEqual(copy.getCount(.green), 0);
        try testing.expectEqual(copy.getCount(.blue), 0);
    }

    try testing.expect(empty.eql(empty));
    try testing.expect(r0_g1_b2.eql(r0_g1_b2));
    try testing.expect(ten_of_each.eql(ten_of_each));
    try testing.expect(!empty.eql(r0_g1_b2));
    try testing.expect(!r0_g1_b2.eql(ten_of_each));
    try testing.expect(!ten_of_each.eql(empty));

    try testing.expect(empty.subsetOf(empty));
    try testing.expect(r0_g1_b2.subsetOf(r0_g1_b2));
    try testing.expect(empty.subsetOf(r0_g1_b2));
    try testing.expect(r0_g1_b2.subsetOf(ten_of_each));
    try testing.expect(!ten_of_each.subsetOf(r0_g1_b2));
    try testing.expect(!r0_g1_b2.subsetOf(empty));

    try testing.expect(empty.supersetOf(empty));
    try testing.expect(r0_g1_b2.supersetOf(r0_g1_b2));
    try testing.expect(r0_g1_b2.supersetOf(empty));
    try testing.expect(ten_of_each.supersetOf(r0_g1_b2));
    try testing.expect(!r0_g1_b2.supersetOf(ten_of_each));
    try testing.expect(!empty.supersetOf(r0_g1_b2));

    {
        // with multisets it could be the case where two
        // multisets are neither subset nor superset of each
        // other.

        const r10 = EnumMultiset(Ball).init(.{
            .red = 10,
        });
        const b10 = EnumMultiset(Ball).init(.{
            .blue = 10,
        });

        try testing.expect(!r10.subsetOf(b10));
        try testing.expect(!b10.subsetOf(r10));
        try testing.expect(!r10.supersetOf(b10));
        try testing.expect(!b10.supersetOf(r10));
    }

    {
        const result = r0_g1_b2.plusAssertSafe(ten_of_each);
        try testing.expectEqual(result.getCount(.red), 10);
        try testing.expectEqual(result.getCount(.green), 11);
        try testing.expectEqual(result.getCount(.blue), 12);
    }

    {
        const result = try r0_g1_b2.plus(ten_of_each);
        try testing.expectEqual(result.getCount(.red), 10);
        try testing.expectEqual(result.getCount(.green), 11);
        try testing.expectEqual(result.getCount(.blue), 12);

        const full = EnumMultiset(Ball).initWithCount(std.math.maxInt(usize));
        try testing.expectError(error.Overflow, result.plus(full));
    }

    {
        const result = ten_of_each.minus(r0_g1_b2);
        try testing.expectEqual(result.getCount(.red), 10);
        try testing.expectEqual(result.getCount(.green), 9);
        try testing.expectEqual(result.getCount(.blue), 8);
    }

    {
        const result = ten_of_each.minus(r0_g1_b2).minus(ten_of_each);
        try testing.expectEqual(result.getCount(.red), 0);
        try testing.expectEqual(result.getCount(.green), 0);
        try testing.expectEqual(result.getCount(.blue), 0);
    }

    {
        var copy = empty;
        var it = copy.iterator();
        var entry = it.next().?;
        try testing.expectEqual(entry.key, .red);
        try testing.expectEqual(entry.value.*, 0);
        entry = it.next().?;
        try testing.expectEqual(entry.key, .green);
        try testing.expectEqual(entry.value.*, 0);
        entry = it.next().?;
        try testing.expectEqual(entry.key, .blue);
        try testing.expectEqual(entry.value.*, 0);
        try testing.expectEqual(it.next(), null);
    }

    {
        var copy = r0_g1_b2;
        var it = copy.iterator();
        var entry = it.next().?;
        try testing.expectEqual(entry.key, .red);
        try testing.expectEqual(entry.value.*, 0);
        entry = it.next().?;
        try testing.expectEqual(entry.key, .green);
        try testing.expectEqual(entry.value.*, 1);
        entry = it.next().?;
        try testing.expectEqual(entry.key, .blue);
        try testing.expectEqual(entry.value.*, 2);
        try testing.expectEqual(it.next(), null);
    }
}

/// An array keyed by an enum, backed by a dense array.
/// If the enum is not dense, a mapping will be constructed from
/// enum values to dense indices.  This type does no dynamic
/// allocation and can be copied by value.
pub fn EnumArray(comptime E: type, comptime V: type) type {
    return struct {
        const Self = @This();

        /// The index mapping for this map
        pub const Indexer = EnumIndexer(E);
        /// The key type used to index this map
        pub const Key = Indexer.Key;
        /// The value type stored in this map
        pub const Value = V;
        /// The number of possible keys in the map
        pub const len = Indexer.count;

        values: [Indexer.count]Value,

        pub fn init(init_values: EnumFieldStruct(E, Value, null)) Self {
            return initDefault(null, init_values);
        }

        /// Initializes values in the enum array, with the specified default.
        pub fn initDefault(comptime default: ?Value, init_values: EnumFieldStruct(E, Value, default)) Self {
            @setEvalBranchQuota(2 * @typeInfo(E).@"enum".fields.len);
            var result: Self = .{ .values = undefined };
            inline for (0..Self.len) |i| {
                const key = comptime Indexer.keyForIndex(i);
                const tag = @tagName(key);
                result.values[i] = @field(init_values, tag);
            }
            return result;
        }

        pub fn initUndefined() Self {
            return Self{ .values = undefined };
        }

        pub fn initFill(v: Value) Self {
            var self: Self = undefined;
            @memset(&self.values, v);
            return self;
        }

        /// Returns the value in the array associated with a key.
        pub fn get(self: Self, key: Key) Value {
            return self.values[Indexer.indexOf(key)];
        }

        /// Returns a pointer to the slot in the array associated with a key.
        pub fn getPtr(self: *Self, key: Key) *Value {
            return &self.values[Indexer.indexOf(key)];
        }

        /// Returns a const pointer to the slot in the array associated with a key.
        pub fn getPtrConst(self: *const Self, key: Key) *const Value {
            return &self.values[Indexer.indexOf(key)];
        }

        /// Sets the value in the slot associated with a key.
        pub fn set(self: *Self, key: Key, value: Value) void {
            self.values[Indexer.indexOf(key)] = value;
        }

        /// Iterates over the items in the array, in index order.
        pub fn iterator(self: *Self) Iterator {
            return .{
                .values = &self.values,
            };
        }

        /// An entry in the array.
        pub const Entry = struct {
            /// The key associated with this entry.
            /// Modifying this key will not change the array.
            key: Key,

            /// A pointer to the value in the array associated
            /// with this key.  Modifications through this
            /// pointer will modify the underlying data.
            value: *Value,
        };

        pub const Iterator = struct {
            index: usize = 0,
            values: *[Indexer.count]Value,

            pub fn next(self: *Iterator) ?Entry {
                const index = self.index;
                if (index < Indexer.count) {
                    self.index += 1;
                    return Entry{
                        .key = Indexer.keyForIndex(index),
                        .value = &self.values[index],
                    };
                }
                return null;
            }
        };
    };
}

test "pure EnumSet fns" {
    const Suit = enum { spades, hearts, clubs, diamonds };

    const empty = EnumSet(Suit).initEmpty();
    const full = EnumSet(Suit).initFull();
    const black = EnumSet(Suit).initMany(&[_]Suit{ .spades, .clubs });
    const red = EnumSet(Suit).initMany(&[_]Suit{ .hearts, .diamonds });

    try testing.expect(empty.eql(empty));
    try testing.expect(full.eql(full));
    try testing.expect(!empty.eql(full));
    try testing.expect(!full.eql(empty));
    try testing.expect(!empty.eql(black));
    try testing.expect(!full.eql(red));
    try testing.expect(!red.eql(empty));
    try testing.expect(!black.eql(full));

    try testing.expect(empty.subsetOf(empty));
    try testing.expect(empty.subsetOf(full));
    try testing.expect(full.subsetOf(full));
    try testing.expect(!black.subsetOf(red));
    try testing.expect(!red.subsetOf(black));

    try testing.expect(full.supersetOf(full));
    try testing.expect(full.supersetOf(empty));
    try testing.expect(empty.supersetOf(empty));
    try testing.expect(!black.supersetOf(red));
    try testing.expect(!red.supersetOf(black));

    try testing.expect(empty.complement().eql(full));
    try testing.expect(full.complement().eql(empty));
    try testing.expect(black.complement().eql(red));
    try testing.expect(red.complement().eql(black));

    try testing.expect(empty.unionWith(empty).eql(empty));
    try testing.expect(empty.unionWith(full).eql(full));
    try testing.expect(full.unionWith(full).eql(full));
    try testing.expect(full.unionWith(empty).eql(full));
    try testing.expect(black.unionWith(red).eql(full));
    try testing.expect(red.unionWith(black).eql(full));

    try testing.expect(empty.intersectWith(empty).eql(empty));
    try testing.expect(empty.intersectWith(full).eql(empty));
    try testing.expect(full.intersectWith(full).eql(full));
    try testing.expect(full.intersectWith(empty).eql(empty));
    try testing.expect(black.intersectWith(red).eql(empty));
    try testing.expect(red.intersectWith(black).eql(empty));

    try testing.expect(empty.xorWith(empty).eql(empty));
    try testing.expect(empty.xorWith(full).eql(full));
    try testing.expect(full.xorWith(full).eql(empty));
    try testing.expect(full.xorWith(empty).eql(full));
    try testing.expect(black.xorWith(red).eql(full));
    try testing.expect(red.xorWith(black).eql(full));

    try testing.expect(empty.differenceWith(empty).eql(empty));
    try testing.expect(empty.differenceWith(full).eql(empty));
    try testing.expect(full.differenceWith(full).eql(empty));
    try testing.expect(full.differenceWith(empty).eql(full));
    try testing.expect(full.differenceWith(red).eql(black));
    try testing.expect(full.differenceWith(black).eql(red));
}

test "EnumSet empty" {
    const E = enum {};
    const empty = EnumSet(E).initEmpty();
    const full = EnumSet(E).initFull();

    try std.testing.expect(empty.eql(full));
    try std.testing.expect(empty.complement().eql(full));
    try std.testing.expect(empty.complement().eql(full.complement()));
    try std.testing.expect(empty.eql(full.complement()));
}

test "EnumSet const iterator" {
    const Direction = enum { up, down, left, right };
    const diag_move = init: {
        var move = EnumSet(Direction).initEmpty();
        move.insert(.right);
        move.insert(.up);
        break :init move;
    };

    var result = EnumSet(Direction).initEmpty();
    var it = diag_move.iterator();
    while (it.next()) |dir| {
        result.insert(dir);
    }

    try testing.expect(result.eql(diag_move));
}

test "EnumSet non-exhaustive" {
    const BitIndices = enum(u4) {
        a = 0,
        b = 1,
        c = 4,
        _,
    };
    const BitField = EnumSet(BitIndices);

    var flags = BitField.init(.{ .a = true, .b = true });
    flags.insert(.c);
    flags.remove(.a);
    try testing.expect(!flags.contains(.a));
    try testing.expect(flags.contains(.b));
    try testing.expect(flags.contains(.c));
}

pub fn EnumIndexer(comptime E: type) type {
    // Assumes that the enum fields are sorted in ascending order (optimistic).
    // Unsorted enums may require the user to manually increase the quota.
    @setEvalBranchQuota(3 * @typeInfo(E).@"enum".fields.len + eval_branch_quota_cushion);

    if (!@typeInfo(E).@"enum".is_exhaustive) {
        const BackingInt = @typeInfo(E).@"enum".tag_type;
        if (@bitSizeOf(BackingInt) > @bitSizeOf(usize))
            @compileError("Cannot create an enum indexer for a given non-exhaustive enum, tag_type is larger than usize.");

        return struct {
            pub const Key: type = E;

            const backing_int_sign = @typeInfo(BackingInt).int.signedness;
            const min_value = std.math.minInt(BackingInt);
            const max_value = std.math.maxInt(BackingInt);

            const RangeType = std.meta.Int(.unsigned, @bitSizeOf(BackingInt));
            pub const count: comptime_int = std.math.maxInt(RangeType) + 1;

            pub fn indexOf(e: E) usize {
                if (backing_int_sign == .unsigned)
                    return @intFromEnum(e);

                return if (@intFromEnum(e) < 0)
                    @intCast(@intFromEnum(e) - min_value)
                else
                    @as(RangeType, -min_value) + @as(RangeType, @intCast(@intFromEnum(e)));
            }
            pub fn keyForIndex(i: usize) E {
                if (backing_int_sign == .unsigned)
                    return @enumFromInt(i);

                return @enumFromInt(@as(std.meta.Int(.signed, @bitSizeOf(RangeType) + 1), @intCast(i)) + min_value);
            }
        };
    }

    const const_fields = @typeInfo(E).@"enum".fields;
    var fields = const_fields[0..const_fields.len].*;
    const fields_len = fields.len;

    if (fields_len == 0) {
        return struct {
            pub const Key = E;
            pub const count: comptime_int = 0;
            pub fn indexOf(e: E) usize {
                _ = e;
                unreachable;
            }
            pub fn keyForIndex(i: usize) E {
                _ = i;
                unreachable;
            }
        };
    }

    const min = fields[0].value;
    const max = fields[fields.len - 1].value;

    const SortContext = struct {
        fields: []EnumField,

        pub fn lessThan(comptime ctx: @This(), comptime a: usize, comptime b: usize) bool {
            return ctx.fields[a].value < ctx.fields[b].value;
        }

        pub fn swap(comptime ctx: @This(), comptime a: usize, comptime b: usize) void {
            return std.mem.swap(EnumField, &ctx.fields[a], &ctx.fields[b]);
        }
    };
    std.sort.insertionContext(0, fields_len, SortContext{ .fields = &fields });

    if (max - min == fields.len - 1) {
        return struct {
            pub const Key = E;
            pub const count: comptime_int = fields_len;
            pub fn indexOf(e: E) usize {
                return @as(usize, @intCast(@intFromEnum(e) - min));
            }
            pub fn keyForIndex(i: usize) E {
                // TODO fix addition semantics.  This calculation
                // gives up some safety to avoid artificially limiting
                // the range of signed enum values to max_isize.
                const enum_value = if (min < 0) @as(isize, @bitCast(i)) +% min else i + min;
                return @as(E, @enumFromInt(@as(@typeInfo(E).@"enum".tag_type, @intCast(enum_value))));
            }
        };
    }

    const keys = valuesFromFields(E, &fields);

    return struct {
        pub const Key = E;
        pub const count: comptime_int = fields_len;
        pub fn indexOf(e: E) usize {
            for (keys, 0..) |k, i| {
                if (k == e) return i;
            }
            unreachable;
        }
        pub fn keyForIndex(i: usize) E {
            return keys[i];
        }
    };
}

test "EnumIndexer non-exhaustive" {
    const backing_ints = [_]type{
        i1,
        i2,
        i3,
        i4,
        i8,
        i16,
        std.meta.Int(.signed, @bitSizeOf(isize) - 1),
        isize,
        u1,
        u2,
        u3,
        u4,
        u16,
        std.meta.Int(.unsigned, @bitSizeOf(usize) - 1),
        usize,
    };
    inline for (backing_ints) |BackingInt| {
        const E = enum(BackingInt) {
            number_zero_tag = 0,
            _,
        };
        const Indexer = EnumIndexer(E);

        const min_tag: E = @enumFromInt(std.math.minInt(BackingInt));
        const max_tag: E = @enumFromInt(std.math.maxInt(BackingInt));

        const RangedType = std.meta.Int(.unsigned, @bitSizeOf(BackingInt));
        const max_index: comptime_int = std.math.maxInt(RangedType);
        const number_zero_tag_index: usize = switch (@typeInfo(BackingInt).int.signedness) {
            .unsigned => 0,
            .signed => std.math.divCeil(comptime_int, max_index, 2) catch unreachable,
        };

        try testing.expectEqual(E, Indexer.Key);
        try testing.expectEqual(max_index + 1, Indexer.count);

        try testing.expectEqual(@as(usize, 0), Indexer.indexOf(min_tag));
        try testing.expectEqual(number_zero_tag_index, Indexer.indexOf(E.number_zero_tag));
        try testing.expectEqual(@as(usize, max_index), Indexer.indexOf(max_tag));

        try testing.expectEqual(min_tag, Indexer.keyForIndex(0));
        try testing.expectEqual(E.number_zero_tag, Indexer.keyForIndex(number_zero_tag_index));
        try testing.expectEqual(max_tag, Indexer.keyForIndex(max_index));
    }
}

test "EnumIndexer dense zeroed" {
    const E = enum(u2) { b = 1, a = 0, c = 2 };
    const Indexer = EnumIndexer(E);
    try testing.expectEqual(E, Indexer.Key);
    try testing.expectEqual(3, Indexer.count);

    try testing.expectEqual(@as(usize, 0), Indexer.indexOf(.a));
    try testing.expectEqual(@as(usize, 1), Indexer.indexOf(.b));
    try testing.expectEqual(@as(usize, 2), Indexer.indexOf(.c));

    try testing.expectEqual(E.a, Indexer.keyForIndex(0));
    try testing.expectEqual(E.b, Indexer.keyForIndex(1));
    try testing.expectEqual(E.c, Indexer.keyForIndex(2));
}

test "EnumIndexer dense positive" {
    const E = enum(u4) { c = 6, a = 4, b = 5 };
    const Indexer = EnumIndexer(E);
    try testing.expectEqual(E, Indexer.Key);
    try testing.expectEqual(3, Indexer.count);

    try testing.expectEqual(@as(usize, 0), Indexer.indexOf(.a));
    try testing.expectEqual(@as(usize, 1), Indexer.indexOf(.b));
    try testing.expectEqual(@as(usize, 2), Indexer.indexOf(.c));

    try testing.expectEqual(E.a, Indexer.keyForIndex(0));
    try testing.expectEqual(E.b, Indexer.keyForIndex(1));
    try testing.expectEqual(E.c, Indexer.keyForIndex(2));
}

test "EnumIndexer dense negative" {
    const E = enum(i4) { a = -6, c = -4, b = -5 };
    const Indexer = EnumIndexer(E);
    try testing.expectEqual(E, Indexer.Key);
    try testing.expectEqual(3, Indexer.count);

    try testing.expectEqual(@as(usize, 0), Indexer.indexOf(.a));
    try testing.expectEqual(@as(usize, 1), Indexer.indexOf(.b));
    try testing.expectEqual(@as(usize, 2), Indexer.indexOf(.c));

    try testing.expectEqual(E.a, Indexer.keyForIndex(0));
    try testing.expectEqual(E.b, Indexer.keyForIndex(1));
    try testing.expectEqual(E.c, Indexer.keyForIndex(2));
}

test "EnumIndexer sparse" {
    const E = enum(i4) { a = -2, c = 6, b = 4 };
    const Indexer = EnumIndexer(E);
    try testing.expectEqual(E, Indexer.Key);
    try testing.expectEqual(3, Indexer.count);

    try testing.expectEqual(@as(usize, 0), Indexer.indexOf(.a));
    try testing.expectEqual(@as(usize, 1), Indexer.indexOf(.b));
    try testing.expectEqual(@as(usize, 2), Indexer.indexOf(.c));

    try testing.expectEqual(E.a, Indexer.keyForIndex(0));
    try testing.expectEqual(E.b, Indexer.keyForIndex(1));
    try testing.expectEqual(E.c, Indexer.keyForIndex(2));
}

test "EnumIndexer empty" {
    const E = enum {};
    const Indexer = EnumIndexer(E);
    try testing.expectEqual(E, Indexer.Key);
    try testing.expectEqual(0, Indexer.count);
}

test values {
    const E = enum {
        X,
        Y,
        Z,
        const A = 1;
    };
    try testing.expectEqualSlices(E, &.{ .X, .Y, .Z }, values(E));
}
// FIFO of fixed size items
// Usually used for e.g. byte buffers

const std = @import("std");
const math = std.math;
const mem = std.mem;
const Allocator = mem.Allocator;
const assert = std.debug.assert;
const testing = std.testing;

pub const LinearFifoBufferType = union(enum) {
    /// The buffer is internal to the fifo; it is of the specified size.
    Static: usize,

    /// The buffer is passed as a slice to the initialiser.
    Slice,

    /// The buffer is managed dynamically using a `mem.Allocator`.
    Dynamic,
};

pub fn LinearFifo(
    comptime T: type,
    comptime buffer_type: LinearFifoBufferType,
) type {
    const autoalign = false;

    const powers_of_two = switch (buffer_type) {
        .Static => std.math.isPowerOfTwo(buffer_type.Static),
        .Slice => false, // Any size slice could be passed in
        .Dynamic => true, // This could be configurable in future
    };

    return struct {
        allocator: if (buffer_type == .Dynamic) Allocator else void,
        buf: if (buffer_type == .Static) [buffer_type.Static]T else []T,
        head: usize,
        count: usize,

        const Self = @This();
        pub const Reader = std.io.Reader(*Self, error{}, readFn);
        pub const Writer = std.io.Writer(*Self, error{OutOfMemory}, appendWrite);

        // Type of Self argument for slice operations.
        // If buffer is inline (Static) then we need to ensure we haven't
        // returned a slice into a copy on the stack
        const SliceSelfArg = if (buffer_type == .Static) *Self else Self;

        pub const init = switch (buffer_type) {
            .Static => initStatic,
            .Slice => initSlice,
            .Dynamic => initDynamic,
        };

        fn initStatic() Self {
            comptime assert(buffer_type == .Static);
            return .{
                .allocator = {},
                .buf = undefined,
                .head = 0,
                .count = 0,
            };
        }

        fn initSlice(buf: []T) Self {
            comptime assert(buffer_type == .Slice);
            return .{
                .allocator = {},
                .buf = buf,
                .head = 0,
                .count = 0,
            };
        }

        fn initDynamic(allocator: Allocator) Self {
            comptime assert(buffer_type == .Dynamic);
            return .{
                .allocator = allocator,
                .buf = &.{},
                .head = 0,
                .count = 0,
            };
        }

        pub fn deinit(self: Self) void {
            if (buffer_type == .Dynamic) self.allocator.free(self.buf);
        }

        pub fn realign(self: *Self) void {
            if (self.buf.len - self.head >= self.count) {
                mem.copyForwards(T, self.buf[0..self.count], self.buf[self.head..][0..self.count]);
                self.head = 0;
            } else {
                var tmp: [4096 / 2 / @sizeOf(T)]T = undefined;

                while (self.head != 0) {
                    const n = @min(self.head, tmp.len);
                    const m = self.buf.len - n;
                    @memcpy(tmp[0..n], self.buf[0..n]);
                    mem.copyForwards(T, self.buf[0..m], self.buf[n..][0..m]);
                    @memcpy(self.buf[m..][0..n], tmp[0..n]);
                    self.head -= n;
                }
            }
            { // set unused area to undefined
                const unused = mem.sliceAsBytes(self.buf[self.count..]);
                @memset(unused, undefined);
            }
        }

        /// Reduce allocated capacity to `size`.
        pub fn shrink(self: *Self, size: usize) void {
            assert(size >= self.count);
            if (buffer_type == .Dynamic) {
                self.realign();
                self.buf = self.allocator.realloc(self.buf, size) catch |e| switch (e) {
                    error.OutOfMemory => return, // no problem, capacity is still correct then.
                };
            }
        }

        /// Ensure that the buffer can fit at least `size` items
        pub fn ensureTotalCapacity(self: *Self, size: usize) !void {
            if (self.buf.len >= size) return;
            if (buffer_type == .Dynamic) {
                self.realign();
                const new_size = if (powers_of_two) math.ceilPowerOfTwo(usize, size) catch return error.OutOfMemory else size;
                self.buf = try self.allocator.realloc(self.buf, new_size);
            } else {
                return error.OutOfMemory;
            }
        }

        /// Makes sure at least `size` items are unused
        pub fn ensureUnusedCapacity(self: *Self, size: usize) error{OutOfMemory}!void {
            if (self.writableLength() >= size) return;

            return try self.ensureTotalCapacity(math.add(usize, self.count, size) catch return error.OutOfMemory);
        }

        /// Returns number of items currently in fifo
        pub fn readableLength(self: Self) usize {
            return self.count;
        }

        /// Returns a writable slice from the 'read' end of the fifo
        fn readableSliceMut(self: SliceSelfArg, offset: usize) []T {
            if (offset > self.count) return &[_]T{};

            var start = self.head + offset;
            if (start >= self.buf.len) {
                start -= self.buf.len;
                return self.buf[start .. start + (self.count - offset)];
            } else {
                const end = @min(self.head + self.count, self.buf.len);
                return self.buf[start..end];
            }
        }

        /// Returns a readable slice from `offset`
        pub fn readableSlice(self: SliceSelfArg, offset: usize) []const T {
            return self.readableSliceMut(offset);
        }

        pub fn readableSliceOfLen(self: *Self, len: usize) []const T {
            assert(len <= self.count);
            const buf = self.readableSlice(0);
            if (buf.len >= len) {
                return buf[0..len];
            } else {
                self.realign();
                return self.readableSlice(0)[0..len];
            }
        }

        /// Discard first `count` items in the fifo
        pub fn discard(self: *Self, count: usize) void {
            assert(count <= self.count);
            { // set old range to undefined. Note: may be wrapped around
                const slice = self.readableSliceMut(0);
                if (slice.len >= count) {
                    const unused = mem.sliceAsBytes(slice[0..count]);
                    @memset(unused, undefined);
                } else {
                    const unused = mem.sliceAsBytes(slice[0..]);
                    @memset(unused, undefined);
                    const unused2 = mem.sliceAsBytes(self.readableSliceMut(slice.len)[0 .. count - slice.len]);
                    @memset(unused2, undefined);
                }
            }
            if (autoalign and self.count == count) {
                self.head = 0;
                self.count = 0;
            } else {
                var head = self.head + count;
                if (powers_of_two) {
                    // Note it is safe to do a wrapping subtract as
                    // bitwise & with all 1s is a noop
                    head &= self.buf.len -% 1;
                } else {
                    head %= self.buf.len;
                }
                self.head = head;
                self.count -= count;
            }
        }

        /// Read the next item from the fifo
        pub fn readItem(self: *Self) ?T {
            if (self.count == 0) return null;

            const c = self.buf[self.head];
            self.discard(1);
            return c;
        }

        /// Read data from the fifo into `dst`, returns number of items copied.
        pub fn read(self: *Self, dst: []T) usize {
            var dst_left = dst;

            while (dst_left.len > 0) {
                const slice = self.readableSlice(0);
                if (slice.len == 0) break;
                const n = @min(slice.len, dst_left.len);
                @memcpy(dst_left[0..n], slice[0..n]);
                self.discard(n);
                dst_left = dst_left[n..];
            }

            return dst.len - dst_left.len;
        }

        /// Same as `read` except it returns an error union
        /// The purpose of this function existing is to match `std.io.Reader` API.
        fn readFn(self: *Self, dest: []u8) error{}!usize {
            return self.read(dest);
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        /// Returns number of items available in fifo
        pub fn writableLength(self: Self) usize {
            return self.buf.len - self.count;
        }

        /// Returns the first section of writable buffer.
        /// Note that this may be of length 0
        pub fn writableSlice(self: SliceSelfArg, offset: usize) []T {
            if (offset > self.buf.len) return &[_]T{};

            const tail = self.head + offset + self.count;
            if (tail < self.buf.len) {
                return self.buf[tail..];
            } else {
                return self.buf[tail - self.buf.len ..][0 .. self.writableLength() - offset];
            }
        }

        /// Returns a writable buffer of at least `size` items, allocating memory as needed.
        /// Use `fifo.update` once you've written data to it.
        pub fn writableWithSize(self: *Self, size: usize) ![]T {
            try self.ensureUnusedCapacity(size);

            // try to avoid realigning buffer
            var slice = self.writableSlice(0);
            if (slice.len < size) {
                self.realign();
                slice = self.writableSlice(0);
            }
            return slice;
        }

        /// Update the tail location of the buffer (usually follows use of writable/writableWithSize)
        pub fn update(self: *Self, count: usize) void {
            assert(self.count + count <= self.buf.len);
            self.count += count;
        }

        /// Appends the data in `src` to the fifo.
        /// You must have ensured there is enough space.
        pub fn writeAssumeCapacity(self: *Self, src: []const T) void {
            assert(self.writableLength() >= src.len);

            var src_left = src;
            while (src_left.len > 0) {
                const writable_slice = self.writableSlice(0);
                assert(writable_slice.len != 0);
                const n = @min(writable_slice.len, src_left.len);
                @memcpy(writable_slice[0..n], src_left[0..n]);
                self.update(n);
                src_left = src_left[n..];
            }
        }

        /// Write a single item to the fifo
        pub fn writeItem(self: *Self, item: T) !void {
            try self.ensureUnusedCapacity(1);
            return self.writeItemAssumeCapacity(item);
        }

        pub fn writeItemAssumeCapacity(self: *Self, item: T) void {
            var tail = self.head + self.count;
            if (powers_of_two) {
                tail &= self.buf.len - 1;
            } else {
                tail %= self.buf.len;
            }
            self.buf[tail] = item;
            self.update(1);
        }

        /// Appends the data in `src` to the fifo.
        /// Allocates more memory as necessary
        pub fn write(self: *Self, src: []const T) !void {
            try self.ensureUnusedCapacity(src.len);

            return self.writeAssumeCapacity(src);
        }

        /// Same as `write` except it returns the number of bytes written, which is always the same
        /// as `bytes.len`. The purpose of this function existing is to match `std.io.Writer` API.
        fn appendWrite(self: *Self, bytes: []const u8) error{OutOfMemory}!usize {
            try self.write(bytes);
            return bytes.len;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        /// Make `count` items available before the current read location
        fn rewind(self: *Self, count: usize) void {
            assert(self.writableLength() >= count);

            var head = self.head + (self.buf.len - count);
            if (powers_of_two) {
                head &= self.buf.len - 1;
            } else {
                head %= self.buf.len;
            }
            self.head = head;
            self.count += count;
        }

        /// Place data back into the read stream
        pub fn unget(self: *Self, src: []const T) !void {
            try self.ensureUnusedCapacity(src.len);

            self.rewind(src.len);

            const slice = self.readableSliceMut(0);
            if (src.len < slice.len) {
                @memcpy(slice[0..src.len], src);
            } else {
                @memcpy(slice, src[0..slice.len]);
                const slice2 = self.readableSliceMut(slice.len);
                @memcpy(slice2[0 .. src.len - slice.len], src[slice.len..]);
            }
        }

        /// Returns the item at `offset`.
        /// Asserts offset is within bounds.
        pub fn peekItem(self: Self, offset: usize) T {
            assert(offset < self.count);

            var index = self.head + offset;
            if (powers_of_two) {
                index &= self.buf.len - 1;
            } else {
                index %= self.buf.len;
            }
            return self.buf[index];
        }

        /// Pump data from a reader into a writer.
        /// Stops when reader returns 0 bytes (EOF).
        /// Buffer size must be set before calling; a buffer length of 0 is invalid.
        pub fn pump(self: *Self, src_reader: anytype, dest_writer: anytype) !void {
            assert(self.buf.len > 0);
            while (true) {
                if (self.writableLength() > 0) {
                    const n = try src_reader.read(self.writableSlice(0));
                    if (n == 0) break; // EOF
                    self.update(n);
                }
                self.discard(try dest_writer.write(self.readableSlice(0)));
            }
            // flush remaining data
            while (self.readableLength() > 0) {
                self.discard(try dest_writer.write(self.readableSlice(0)));
            }
        }

        pub fn toOwnedSlice(self: *Self) Allocator.Error![]T {
            if (self.head != 0) self.realign();
            assert(self.head == 0);
            assert(self.count <= self.buf.len);
            const allocator = self.allocator;
            if (allocator.resize(self.buf, self.count)) {
                const result = self.buf[0..self.count];
                self.* = Self.init(allocator);
                return result;
            }
            const new_memory = try allocator.dupe(T, self.buf[0..self.count]);
            allocator.free(self.buf);
            self.* = Self.init(allocator);
            return new_memory;
        }
    };
}

test "LinearFifo(u8, .Dynamic) discard(0) from empty buffer should not error on overflow" {
    var fifo = LinearFifo(u8, .Dynamic).init(testing.allocator);
    defer fifo.deinit();

    // If overflow is not explicitly allowed this will crash in debug / safe mode
    fifo.discard(0);
}

test "LinearFifo(u8, .Dynamic)" {
    var fifo = LinearFifo(u8, .Dynamic).init(testing.allocator);
    defer fifo.deinit();

    try fifo.write("HELLO");
    try testing.expectEqual(@as(usize, 5), fifo.readableLength());
    try testing.expectEqualSlices(u8, "HELLO", fifo.readableSlice(0));

    {
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            try fifo.write(&[_]u8{fifo.peekItem(i)});
        }
        try testing.expectEqual(@as(usize, 10), fifo.readableLength());
        try testing.expectEqualSlices(u8, "HELLOHELLO", fifo.readableSlice(0));
    }

    {
        try testing.expectEqual(@as(u8, 'H'), fifo.readItem().?);
        try testing.expectEqual(@as(u8, 'E'), fifo.readItem().?);
        try testing.expectEqual(@as(u8, 'L'), fifo.readItem().?);
        try testing.expectEqual(@as(u8, 'L'), fifo.readItem().?);
        try testing.expectEqual(@as(u8, 'O'), fifo.readItem().?);
    }
    try testing.expectEqual(@as(usize, 5), fifo.readableLength());

    { // Writes that wrap around
        try testing.expectEqual(@as(usize, 11), fifo.writableLength());
        try testing.expectEqual(@as(usize, 6), fifo.writableSlice(0).len);
        fifo.writeAssumeCapacity("6<chars<11");
        try testing.expectEqualSlices(u8, "HELLO6<char", fifo.readableSlice(0));
        try testing.expectEqualSlices(u8, "s<11", fifo.readableSlice(11));
        try testing.expectEqualSlices(u8, "11", fifo.readableSlice(13));
        try testing.expectEqualSlices(u8, "", fifo.readableSlice(15));
        fifo.discard(11);
        try testing.expectEqualSlices(u8, "s<11", fifo.readableSlice(0));
        fifo.discard(4);
        try testing.expectEqual(@as(usize, 0), fifo.readableLength());
    }

    {
        const buf = try fifo.writableWithSize(12);
        try testing.expectEqual(@as(usize, 12), buf.len);
        var i: u8 = 0;
        while (i < 10) : (i += 1) {
            buf[i] = i + 'a';
        }
        fifo.update(10);
        try testing.expectEqualSlices(u8, "abcdefghij", fifo.readableSlice(0));
    }

    {
        try fifo.unget("prependedstring");
        var result: [30]u8 = undefined;
        try testing.expectEqualSlices(u8, "prependedstringabcdefghij", result[0..fifo.read(&result)]);
        try fifo.unget("b");
        try fifo.unget("a");
        try testing.expectEqualSlices(u8, "ab", result[0..fifo.read(&result)]);
    }

    fifo.shrink(0);

    {
        try fifo.writer().print("{s}, {s}!", .{ "Hello", "World" });
        var result: [30]u8 = undefined;
        try testing.expectEqualSlices(u8, "Hello, World!", result[0..fifo.read(&result)]);
        try testing.expectEqual(@as(usize, 0), fifo.readableLength());
    }

    {
        try fifo.writer().writeAll("This is a test");
        var result: [30]u8 = undefined;
        try testing.expectEqualSlices(u8, "This", (try fifo.reader().readUntilDelimiterOrEof(&result, ' ')).?);
        try testing.expectEqualSlices(u8, "is", (try fifo.reader().readUntilDelimiterOrEof(&result, ' ')).?);
        try testing.expectEqualSlices(u8, "a", (try fifo.reader().readUntilDelimiterOrEof(&result, ' ')).?);
        try testing.expectEqualSlices(u8, "test", (try fifo.reader().readUntilDelimiterOrEof(&result, ' ')).?);
    }

    {
        try fifo.ensureTotalCapacity(1);
        var in_fbs = std.io.fixedBufferStream("pump test");
        var out_buf: [50]u8 = undefined;
        var out_fbs = std.io.fixedBufferStream(&out_buf);
        try fifo.pump(in_fbs.reader(), out_fbs.writer());
        try testing.expectEqualSlices(u8, in_fbs.buffer, out_fbs.getWritten());
    }
}

test LinearFifo {
    inline for ([_]type{ u1, u8, u16, u64 }) |T| {
        inline for ([_]LinearFifoBufferType{ LinearFifoBufferType{ .Static = 32 }, .Slice, .Dynamic }) |bt| {
            const FifoType = LinearFifo(T, bt);
            var buf: if (bt == .Slice) [32]T else void = undefined;
            var fifo = switch (bt) {
                .Static => FifoType.init(),
                .Slice => FifoType.init(buf[0..]),
                .Dynamic => FifoType.init(testing.allocator),
            };
            defer fifo.deinit();

            try fifo.write(&[_]T{ 0, 1, 1, 0, 1 });
            try testing.expectEqual(@as(usize, 5), fifo.readableLength());

            {
                try testing.expectEqual(@as(T, 0), fifo.readItem().?);
                try testing.expectEqual(@as(T, 1), fifo.readItem().?);
                try testing.expectEqual(@as(T, 1), fifo.readItem().?);
                try testing.expectEqual(@as(T, 0), fifo.readItem().?);
                try testing.expectEqual(@as(T, 1), fifo.readItem().?);
                try testing.expectEqual(@as(usize, 0), fifo.readableLength());
            }

            {
                try fifo.writeItem(1);
                try fifo.writeItem(1);
                try fifo.writeItem(1);
                try testing.expectEqual(@as(usize, 3), fifo.readableLength());
            }

            {
                var readBuf: [3]T = undefined;
                const n = fifo.read(&readBuf);
                try testing.expectEqual(@as(usize, 3), n); // NOTE: It should be the number of items.
            }
        }
    }
}
//! String formatting and parsing.

const std = @import("std.zig");
const builtin = @import("builtin");

const io = std.io;
const math = std.math;
const assert = std.debug.assert;
const mem = std.mem;
const unicode = std.unicode;
const meta = std.meta;
const lossyCast = math.lossyCast;
const expectFmt = std.testing.expectFmt;
const testing = std.testing;

pub const default_max_depth = 3;

pub const Alignment = enum {
    left,
    center,
    right,
};

const default_alignment = .right;
const default_fill_char = ' ';

pub const FormatOptions = struct {
    precision: ?usize = null,
    width: ?usize = null,
    alignment: Alignment = default_alignment,
    fill: u21 = default_fill_char,
};

/// Renders fmt string with args, calling `writer` with slices of bytes.
/// If `writer` returns an error, the error is returned from `format` and
/// `writer` is not called again.
///
/// The format string must be comptime-known and may contain placeholders following
/// this format:
/// `{[argument][specifier]:[fill][alignment][width].[precision]}`
///
/// Above, each word including its surrounding [ and ] is a parameter which you have to replace with something:
///
/// - *argument* is either the numeric index or the field name of the argument that should be inserted
///   - when using a field name, you are required to enclose the field name (an identifier) in square
///     brackets, e.g. {[score]...} as opposed to the numeric index form which can be written e.g. {2...}
/// - *specifier* is a type-dependent formatting option that determines how a type should formatted (see below)
/// - *fill* is a single unicode codepoint which is used to pad the formatted text
/// - *alignment* is one of the three bytes '<', '^', or '>' to make the text left-, center-, or right-aligned, respectively
/// - *width* is the total width of the field in unicode codepoints
/// - *precision* specifies how many decimals a formatted number should have
///
/// Note that most of the parameters are optional and may be omitted. Also you can leave out separators like `:` and `.` when
/// all parameters after the separator are omitted.
/// Only exception is the *fill* parameter. If a non-zero *fill* character is required at the same time as *width* is specified,
/// one has to specify *alignment* as well, as otherwise the digit following `:` is interpreted as *width*, not *fill*.
///
/// The *specifier* has several options for types:
/// - `x` and `X`: output numeric value in hexadecimal notation
/// - `s`:
///   - for pointer-to-many and C pointers of u8, print as a C-string using zero-termination
///   - for slices of u8, print the entire slice as a string without zero-termination
/// - `e`: output floating point value in scientific notation
/// - `d`: output numeric value in decimal notation
/// - `b`: output integer value in binary notation
/// - `o`: output integer value in octal notation
/// - `c`: output integer as an ASCII character. Integer type must have 8 bits at max.
/// - `u`: output integer as an UTF-8 sequence. Integer type must have 21 bits at max.
/// - `?`: output optional value as either the unwrapped value, or `null`; may be followed by a format specifier for the underlying value.
/// - `!`: output error union value as either the unwrapped value, or the formatted error value; may be followed by a format specifier for the underlying value.
/// - `*`: output the address of the value instead of the value itself.
/// - `any`: output a value of any type using its default format.
///
/// If a formatted user type contains a function of the type
/// ```
/// pub fn format(value: ?, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void
/// ```
/// with `?` being the type formatted, this function will be called instead of the default implementation.
/// This allows user types to be formatted in a logical manner instead of dumping all fields of the type.
///
/// A user type may be a `struct`, `vector`, `union` or `enum` type.
///
/// To print literal curly braces, escape them by writing them twice, e.g. `{{` or `}}`.
pub fn format(
    writer: anytype,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const ArgsType = @TypeOf(args);
    const args_type_info = @typeInfo(ArgsType);
    if (args_type_info != .@"struct") {
        @compileError("expected tuple or struct argument, found " ++ @typeName(ArgsType));
    }

    const fields_info = args_type_info.@"struct".fields;
    if (fields_info.len > max_format_args) {
        @compileError("32 arguments max are supported per format call");
    }

    @setEvalBranchQuota(2000000);
    comptime var arg_state: ArgState = .{ .args_len = fields_info.len };
    comptime var i = 0;
    comptime var literal: []const u8 = "";
    inline while (true) {
        const start_index = i;

        inline while (i < fmt.len) : (i += 1) {
            switch (fmt[i]) {
                '{', '}' => break,
                else => {},
            }
        }

        comptime var end_index = i;
        comptime var unescape_brace = false;

        // Handle {{ and }}, those are un-escaped as single braces
        if (i + 1 < fmt.len and fmt[i + 1] == fmt[i]) {
            unescape_brace = true;
            // Make the first brace part of the literal...
            end_index += 1;
            // ...and skip both
            i += 2;
        }

        literal = literal ++ fmt[start_index..end_index];

        // We've already skipped the other brace, restart the loop
        if (unescape_brace) continue;

        // Write out the literal
        if (literal.len != 0) {
            try writer.writeAll(literal);
            literal = "";
        }

        if (i >= fmt.len) break;

        if (fmt[i] == '}') {
            @compileError("missing opening {");
        }

        // Get past the {
        comptime assert(fmt[i] == '{');
        i += 1;

        const fmt_begin = i;
        // Find the closing brace
        inline while (i < fmt.len and fmt[i] != '}') : (i += 1) {}
        const fmt_end = i;

        if (i >= fmt.len) {
            @compileError("missing closing }");
        }

        // Get past the }
        comptime assert(fmt[i] == '}');
        i += 1;

        const placeholder = comptime Placeholder.parse(fmt[fmt_begin..fmt_end].*);
        const arg_pos = comptime switch (placeholder.arg) {
            .none => null,
            .number => |pos| pos,
            .named => |arg_name| meta.fieldIndex(ArgsType, arg_name) orelse
                @compileError("no argument with name '" ++ arg_name ++ "'"),
        };

        const width = switch (placeholder.width) {
            .none => null,
            .number => |v| v,
            .named => |arg_name| blk: {
                const arg_i = comptime meta.fieldIndex(ArgsType, arg_name) orelse
                    @compileError("no argument with name '" ++ arg_name ++ "'");
                _ = comptime arg_state.nextArg(arg_i) orelse @compileError("too few arguments");
                break :blk @field(args, arg_name);
            },
        };

        const precision = switch (placeholder.precision) {
            .none => null,
            .number => |v| v,
            .named => |arg_name| blk: {
                const arg_i = comptime meta.fieldIndex(ArgsType, arg_name) orelse
                    @compileError("no argument with name '" ++ arg_name ++ "'");
                _ = comptime arg_state.nextArg(arg_i) orelse @compileError("too few arguments");
                break :blk @field(args, arg_name);
            },
        };

        const arg_to_print = comptime arg_state.nextArg(arg_pos) orelse
            @compileError("too few arguments");

        try formatType(
            @field(args, fields_info[arg_to_print].name),
            placeholder.specifier_arg,
            FormatOptions{
                .fill = placeholder.fill,
                .alignment = placeholder.alignment,
                .width = width,
                .precision = precision,
            },
            writer,
            std.options.fmt_max_depth,
        );
    }

    if (comptime arg_state.hasUnusedArgs()) {
        const missing_count = arg_state.args_len - @popCount(arg_state.used_args);
        switch (missing_count) {
            0 => unreachable,
            1 => @compileError("unused argument in '" ++ fmt ++ "'"),
            else => @compileError(comptimePrint("{d}", .{missing_count}) ++ " unused arguments in '" ++ fmt ++ "'"),
        }
    }
}

fn cacheString(str: anytype) []const u8 {
    return &str;
}

pub const Placeholder = struct {
    specifier_arg: []const u8,
    fill: u21,
    alignment: Alignment,
    arg: Specifier,
    width: Specifier,
    precision: Specifier,

    pub fn parse(comptime str: anytype) Placeholder {
        const view = std.unicode.Utf8View.initComptime(&str);
        comptime var parser = Parser{
            .iter = view.iterator(),
        };

        // Parse the positional argument number
        const arg = comptime parser.specifier() catch |err|
            @compileError(@errorName(err));

        // Parse the format specifier
        const specifier_arg = comptime parser.until(':');

        // Skip the colon, if present
        if (comptime parser.char()) |ch| {
            if (ch != ':') {
                @compileError("expected : or }, found '" ++ unicode.utf8EncodeComptime(ch) ++ "'");
            }
        }

        // Parse the fill character, if present.
        // When the width field is also specified, the fill character must
        // be followed by an alignment specifier, unless it's '0' (zero)
        // (in which case it's handled as part of the width specifier)
        var fill: ?u21 = comptime if (parser.peek(1)) |ch|
            switch (ch) {
                '<', '^', '>' => parser.char(),
                else => null,
            }
        else
            null;

        // Parse the alignment parameter
        const alignment: ?Alignment = comptime if (parser.peek(0)) |ch| init: {
            switch (ch) {
                '<', '^', '>' => {
                    // consume the character
                    break :init switch (parser.char().?) {
                        '<' => .left,
                        '^' => .center,
                        else => .right,
                    };
                },
                else => break :init null,
            }
        } else null;

        // When none of the fill character and the alignment specifier have
        // been provided, check whether the width starts with a zero.
        if (fill == null and alignment == null) {
            fill = comptime if (parser.peek(0) == '0') '0' else null;
        }

        // Parse the width parameter
        const width = comptime parser.specifier() catch |err|
            @compileError(@errorName(err));

        // Skip the dot, if present
        if (comptime parser.char()) |ch| {
            if (ch != '.') {
                @compileError("expected . or }, found '" ++ unicode.utf8EncodeComptime(ch) ++ "'");
            }
        }

        // Parse the precision parameter
        const precision = comptime parser.specifier() catch |err|
            @compileError(@errorName(err));

        if (comptime parser.char()) |ch| {
            @compileError("extraneous trailing character '" ++ unicode.utf8EncodeComptime(ch) ++ "'");
        }

        return Placeholder{
            .specifier_arg = cacheString(specifier_arg[0..specifier_arg.len].*),
            .fill = fill orelse default_fill_char,
            .alignment = alignment orelse default_alignment,
            .arg = arg,
            .width = width,
            .precision = precision,
        };
    }
};

pub const Specifier = union(enum) {
    none,
    number: usize,
    named: []const u8,
};

/// A stream based parser for format strings.
///
/// Allows to implement formatters compatible with std.fmt without replicating
/// the standard library behavior.
pub const Parser = struct {
    iter: std.unicode.Utf8Iterator,

    // Returns a decimal number or null if the current character is not a
    // digit
    pub fn number(self: *@This()) ?usize {
        var r: ?usize = null;

        while (self.peek(0)) |code_point| {
            switch (code_point) {
                '0'...'9' => {
                    if (r == null) r = 0;
                    r.? *= 10;
                    r.? += code_point - '0';
                },
                else => break,
            }
            _ = self.iter.nextCodepoint();
        }

        return r;
    }

    // Returns a substring of the input starting from the current position
    // and ending where `ch` is found or until the end if not found
    pub fn until(self: *@This(), ch: u21) []const u8 {
        const start = self.iter.i;
        while (self.peek(0)) |code_point| {
            if (code_point == ch)
                break;
            _ = self.iter.nextCodepoint();
        }
        return self.iter.bytes[start..self.iter.i];
    }

    // Returns the character pointed to by the iterator if available, or
    // null otherwise
    pub fn char(self: *@This()) ?u21 {
        if (self.iter.nextCodepoint()) |code_point| {
            return code_point;
        }
        return null;
    }

    // Returns true if the iterator points to an existing character and
    // false otherwise
    pub fn maybe(self: *@This(), val: u21) bool {
        if (self.peek(0) == val) {
            _ = self.iter.nextCodepoint();
            return true;
        }
        return false;
    }

    // Returns a decimal number or null if the current character is not a
    // digit
    pub fn specifier(self: *@This()) !Specifier {
        if (self.maybe('[')) {
            const arg_name = self.until(']');

            if (!self.maybe(']'))
                return @field(anyerror, "Expected closing ]");

            return Specifier{ .named = arg_name };
        }
        if (self.number()) |i|
            return Specifier{ .number = i };

        return Specifier{ .none = {} };
    }

    // Returns the n-th next character or null if that's past the end
    pub fn peek(self: *@This(), n: usize) ?u21 {
        const original_i = self.iter.i;
        defer self.iter.i = original_i;

        var i: usize = 0;
        var code_point: ?u21 = null;
        while (i <= n) : (i += 1) {
            code_point = self.iter.nextCodepoint();
            if (code_point == null) return null;
        }
        return code_point;
    }
};

pub const ArgSetType = u32;
const max_format_args = @typeInfo(ArgSetType).int.bits;

pub const ArgState = struct {
    next_arg: usize = 0,
    used_args: ArgSetType = 0,
    args_len: usize,

    pub fn hasUnusedArgs(self: *@This()) bool {
        return @popCount(self.used_args) != self.args_len;
    }

    pub fn nextArg(self: *@This(), arg_index: ?usize) ?usize {
        const next_index = arg_index orelse init: {
            const arg = self.next_arg;
            self.next_arg += 1;
            break :init arg;
        };

        if (next_index >= self.args_len) {
            return null;
        }

        // Mark this argument as used
        self.used_args |= @as(ArgSetType, 1) << @as(u5, @intCast(next_index));
        return next_index;
    }
};

pub fn formatAddress(value: anytype, options: FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
    _ = options;
    const T = @TypeOf(value);

    switch (@typeInfo(T)) {
        .pointer => |info| {
            try writer.writeAll(@typeName(info.child) ++ "@");
            if (info.size == .slice)
                try formatInt(@intFromPtr(value.ptr), 16, .lower, FormatOptions{}, writer)
            else
                try formatInt(@intFromPtr(value), 16, .lower, FormatOptions{}, writer);
            return;
        },
        .optional => |info| {
            if (@typeInfo(info.child) == .pointer) {
                try writer.writeAll(@typeName(info.child) ++ "@");
                try formatInt(@intFromPtr(value), 16, .lower, FormatOptions{}, writer);
                return;
            }
        },
        else => {},
    }

    @compileError("cannot format non-pointer type " ++ @typeName(T) ++ " with * specifier");
}

// This ANY const is a workaround for: https://github.com/ziglang/zig/issues/7948
const ANY = "any";

pub fn defaultSpec(comptime T: type) [:0]const u8 {
    switch (@typeInfo(T)) {
        .array, .vector => return ANY,
        .pointer => |ptr_info| switch (ptr_info.size) {
            .one => switch (@typeInfo(ptr_info.child)) {
                .array => return ANY,
                else => {},
            },
            .many, .c => return "*",
            .slice => return ANY,
        },
        .optional => |info| return "?" ++ defaultSpec(info.child),
        .error_union => |info| return "!" ++ defaultSpec(info.payload),
        else => {},
    }
    return "";
}

fn stripOptionalOrErrorUnionSpec(comptime fmt: []const u8) []const u8 {
    return if (std.mem.eql(u8, fmt[1..], ANY))
        ANY
    else
        fmt[1..];
}

pub fn invalidFmtError(comptime fmt: []const u8, value: anytype) void {
    @compileError("invalid format string '" ++ fmt ++ "' for type '" ++ @typeName(@TypeOf(value)) ++ "'");
}

pub fn formatType(
    value: anytype,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
    max_depth: usize,
) @TypeOf(writer).Error!void {
    const T = @TypeOf(value);
    const actual_fmt = comptime if (std.mem.eql(u8, fmt, ANY))
        defaultSpec(T)
    else if (fmt.len != 0 and (fmt[0] == '?' or fmt[0] == '!')) switch (@typeInfo(T)) {
        .optional, .error_union => fmt,
        else => stripOptionalOrErrorUnionSpec(fmt),
    } else fmt;

    if (comptime std.mem.eql(u8, actual_fmt, "*")) {
        return formatAddress(value, options, writer);
    }

    if (std.meta.hasMethod(T, "format")) {
        return try value.format(actual_fmt, options, writer);
    }

    switch (@typeInfo(T)) {
        .comptime_int, .int, .comptime_float, .float => {
            return formatValue(value, actual_fmt, options, writer);
        },
        .void => {
            if (actual_fmt.len != 0) invalidFmtError(fmt, value);
            return formatBuf("void", options, writer);
        },
        .bool => {
            if (actual_fmt.len != 0) invalidFmtError(fmt, value);
            return formatBuf(if (value) "true" else "false", options, writer);
        },
        .optional => {
            if (actual_fmt.len == 0 or actual_fmt[0] != '?')
                @compileError("cannot format optional without a specifier (i.e. {?} or {any})");
            const remaining_fmt = comptime stripOptionalOrErrorUnionSpec(actual_fmt);
            if (value) |payload| {
                return formatType(payload, remaining_fmt, options, writer, max_depth);
            } else {
                return formatBuf("null", options, writer);
            }
        },
        .error_union => {
            if (actual_fmt.len == 0 or actual_fmt[0] != '!')
                @compileError("cannot format error union without a specifier (i.e. {!} or {any})");
            const remaining_fmt = comptime stripOptionalOrErrorUnionSpec(actual_fmt);
            if (value) |payload| {
                return formatType(payload, remaining_fmt, options, writer, max_depth);
            } else |err| {
                return formatType(err, "", options, writer, max_depth);
            }
        },
        .error_set => {
            if (actual_fmt.len != 0) invalidFmtError(fmt, value);
            try writer.writeAll("error.");
            return writer.writeAll(@errorName(value));
        },
        .@"enum" => |enumInfo| {
            try writer.writeAll(@typeName(T));
            if (enumInfo.is_exhaustive) {
                if (actual_fmt.len != 0) invalidFmtError(fmt, value);
                try writer.writeAll(".");
                try writer.writeAll(@tagName(value));
                return;
            }

            // Use @tagName only if value is one of known fields
            @setEvalBranchQuota(3 * enumInfo.fields.len);
            inline for (enumInfo.fields) |enumField| {
                if (@intFromEnum(value) == enumField.value) {
                    try writer.writeAll(".");
                    try writer.writeAll(@tagName(value));
                    return;
                }
            }

            try writer.writeAll("(");
            try formatType(@intFromEnum(value), actual_fmt, options, writer, max_depth);
            try writer.writeAll(")");
        },
        .@"union" => |info| {
            if (actual_fmt.len != 0) invalidFmtError(fmt, value);
            try writer.writeAll(@typeName(T));
            if (max_depth == 0) {
                return writer.writeAll("{ ... }");
            }
            if (info.tag_type) |UnionTagType| {
                try writer.writeAll("{ .");
                try writer.writeAll(@tagName(@as(UnionTagType, value)));
                try writer.writeAll(" = ");
                inline for (info.fields) |u_field| {
                    if (value == @field(UnionTagType, u_field.name)) {
                        try formatType(@field(value, u_field.name), ANY, options, writer, max_depth - 1);
                    }
                }
                try writer.writeAll(" }");
            } else {
                try format(writer, "@{x}", .{@intFromPtr(&value)});
            }
        },
        .@"struct" => |info| {
            if (actual_fmt.len != 0) invalidFmtError(fmt, value);
            if (info.is_tuple) {
                // Skip the type and field names when formatting tuples.
                if (max_depth == 0) {
                    return writer.writeAll("{ ... }");
                }
                try writer.writeAll("{");
                inline for (info.fields, 0..) |f, i| {
                    if (i == 0) {
                        try writer.writeAll(" ");
                    } else {
                        try writer.writeAll(", ");
                    }
                    try formatType(@field(value, f.name), ANY, options, writer, max_depth - 1);
                }
                return writer.writeAll(" }");
            }
            try writer.writeAll(@typeName(T));
            if (max_depth == 0) {
                return writer.writeAll("{ ... }");
            }
            try writer.writeAll("{");
            inline for (info.fields, 0..) |f, i| {
                if (i == 0) {
                    try writer.writeAll(" .");
                } else {
                    try writer.writeAll(", .");
                }
                try writer.writeAll(f.name);
                try writer.writeAll(" = ");
                try formatType(@field(value, f.name), ANY, options, writer, max_depth - 1);
            }
            try writer.writeAll(" }");
        },
        .pointer => |ptr_info| switch (ptr_info.size) {
            .one => switch (@typeInfo(ptr_info.child)) {
                .array, .@"enum", .@"union", .@"struct" => {
                    return formatType(value.*, actual_fmt, options, writer, max_depth);
                },
                else => return format(writer, "{s}@{x}", .{ @typeName(ptr_info.child), @intFromPtr(value) }),
            },
            .many, .c => {
                if (actual_fmt.len == 0)
                    @compileError("cannot format pointer without a specifier (i.e. {s} or {*})");
                if (ptr_info.sentinel() != null) {
                    return formatType(mem.span(value), actual_fmt, options, writer, max_depth);
                }
                if (actual_fmt[0] == 's' and ptr_info.child == u8) {
                    return formatBuf(mem.span(value), options, writer);
                }
                invalidFmtError(fmt, value);
            },
            .slice => {
                if (actual_fmt.len == 0)
                    @compileError("cannot format slice without a specifier (i.e. {s} or {any})");
                if (max_depth == 0) {
                    return writer.writeAll("{ ... }");
                }
                if (actual_fmt[0] == 's' and ptr_info.child == u8) {
                    return formatBuf(value, options, writer);
                }
                try writer.writeAll("{ ");
                for (value, 0..) |elem, i| {
                    try formatType(elem, actual_fmt, options, writer, max_depth - 1);
                    if (i != value.len - 1) {
                        try writer.writeAll(", ");
                    }
                }
                try writer.writeAll(" }");
            },
        },
        .array => |info| {
            if (actual_fmt.len == 0)
                @compileError("cannot format array without a specifier (i.e. {s} or {any})");
            if (max_depth == 0) {
                return writer.writeAll("{ ... }");
            }
            if (actual_fmt[0] == 's' and info.child == u8) {
                return formatBuf(&value, options, writer);
            }
            try writer.writeAll("{ ");
            for (value, 0..) |elem, i| {
                try formatType(elem, actual_fmt, options, writer, max_depth - 1);
                if (i < value.len - 1) {
                    try writer.writeAll(", ");
                }
            }
            try writer.writeAll(" }");
        },
        .vector => |info| {
            if (max_depth == 0) {
                return writer.writeAll("{ ... }");
            }
            try writer.writeAll("{ ");
            var i: usize = 0;
            while (i < info.len) : (i += 1) {
                try formatType(value[i], actual_fmt, options, writer, max_depth - 1);
                if (i < info.len - 1) {
                    try writer.writeAll(", ");
                }
            }
            try writer.writeAll(" }");
        },
        .@"fn" => @compileError("unable to format function body type, use '*const " ++ @typeName(T) ++ "' for a function pointer type"),
        .type => {
            if (actual_fmt.len != 0) invalidFmtError(fmt, value);
            return formatBuf(@typeName(value), options, writer);
        },
        .enum_literal => {
            if (actual_fmt.len != 0) invalidFmtError(fmt, value);
            const buffer = [_]u8{'.'} ++ @tagName(value);
            return formatBuf(buffer, options, writer);
        },
        .null => {
            if (actual_fmt.len != 0) invalidFmtError(fmt, value);
            return formatBuf("null", options, writer);
        },
        else => @compileError("unable to format type '" ++ @typeName(T) ++ "'"),
    }
}

fn formatValue(
    value: anytype,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .float, .comptime_float => return formatFloatValue(value, fmt, options, writer),
        .int, .comptime_int => return formatIntValue(value, fmt, options, writer),
        .bool => return formatBuf(if (value) "true" else "false", options, writer),
        else => comptime unreachable,
    }
}

pub fn formatIntValue(
    value: anytype,
    comptime fmt: []const u8,
    options: FormatOptions,
    writer: anytype,
) !void {
    comptime var base = 10;
    comptime var case: Case = .lower;

    const int_value = if (@TypeOf(value) == comptime_int) blk: {
        const Int = math.IntFittingRange(value, value);
        break :blk @as(Int, value);
    } else value;

    if (fmt.len == 0 or comptime std.mem.eql(u8, fmt, "d")) {
        base = 10;
        case = .lower;
    } else if (comptime std.mem.eql(u8, fmt, "c")) {
        if (@typeInfo(@TypeOf(int_value)).int.bits <= 8) {
            return formatAsciiChar(@as(u8, int_value), options, writer);
        } else {
            @compileError("cannot print integer that is larger than 8 bits as an ASCII character");
        }
    } else if (comptime std.mem.eql(u8, fmt, "u")) {
        if (@typeInfo(@TypeOf(int_value)).int.bits <= 21) {
            return formatUnicodeCodepoint(@as(u21, int_value), options, writer);
        } else {
            @compileError("cannot print integer that is larger than 21 bits as an UTF-8 sequence");
 ```
