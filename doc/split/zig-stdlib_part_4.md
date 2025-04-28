```
.boolMask(MaskInt, true) << start_bit)) |
                    (std.math.boolMask(MaskInt, value) << start_bit);
                bulk_mask_index = start_mask_index + 1;
            } else {
                bulk_mask_index = start_mask_index;
            }

            while (bulk_mask_index < end_mask_index) : (bulk_mask_index += 1) {
                self.masks[bulk_mask_index] = std.math.boolMask(MaskInt, value);
            }

            if (end_bit > 0) {
                self.masks[end_mask_index] =
                    (self.masks[end_mask_index] & (std.math.boolMask(MaskInt, true) << end_bit)) |
                    (std.math.boolMask(MaskInt, value) >> ((@bitSizeOf(MaskInt) - 1) - (end_bit - 1)));
            }
        }
    }

    /// Removes a specific bit from the bit set
    pub fn unset(self: *Self, index: usize) void {
        assert(index < self.bit_length);
        self.masks[maskIndex(index)] &= ~maskBit(index);
    }

    /// Set all bits to 0.
    pub fn unsetAll(self: *Self) void {
        const masks_len = numMasks(self.bit_length);
        @memset(self.masks[0..masks_len], 0);
    }

    /// Set all bits to 1.
    pub fn setAll(self: *Self) void {
        const masks_len = numMasks(self.bit_length);
        @memset(self.masks[0..masks_len], std.math.maxInt(MaskInt));
    }

    /// Flips a specific bit in the bit set
    pub fn toggle(self: *Self, index: usize) void {
        assert(index < self.bit_length);
        self.masks[maskIndex(index)] ^= maskBit(index);
    }

    /// Flips all bits in this bit set which are present
    /// in the toggles bit set.  Both sets must have the
    /// same bit_length.
    pub fn toggleSet(self: *Self, toggles: Self) void {
        assert(toggles.bit_length == self.bit_length);
        const num_masks = numMasks(self.bit_length);
        for (self.masks[0..num_masks], 0..) |*mask, i| {
            mask.* ^= toggles.masks[i];
        }
    }

    /// Flips every bit in the bit set.
    pub fn toggleAll(self: *Self) void {
        const bit_length = self.bit_length;
        // avoid underflow if bit_length is zero
        if (bit_length == 0) return;

        const num_masks = numMasks(self.bit_length);
        for (self.masks[0..num_masks]) |*mask| {
            mask.* = ~mask.*;
        }

        const padding_bits = num_masks * @bitSizeOf(MaskInt) - bit_length;
        const last_item_mask = (~@as(MaskInt, 0)) >> @as(ShiftInt, @intCast(padding_bits));
        self.masks[num_masks - 1] &= last_item_mask;
    }

    /// Performs a union of two bit sets, and stores the
    /// result in the first one.  Bits in the result are
    /// set if the corresponding bits were set in either input.
    /// The two sets must both be the same bit_length.
    pub fn setUnion(self: *Self, other: Self) void {
        assert(other.bit_length == self.bit_length);
        const num_masks = numMasks(self.bit_length);
        for (self.masks[0..num_masks], 0..) |*mask, i| {
            mask.* |= other.masks[i];
        }
    }

    /// Performs an intersection of two bit sets, and stores
    /// the result in the first one.  Bits in the result are
    /// set if the corresponding bits were set in both inputs.
    /// The two sets must both be the same bit_length.
    pub fn setIntersection(self: *Self, other: Self) void {
        assert(other.bit_length == self.bit_length);
        const num_masks = numMasks(self.bit_length);
        for (self.masks[0..num_masks], 0..) |*mask, i| {
            mask.* &= other.masks[i];
        }
    }

    /// Finds the index of the first set bit.
    /// If no bits are set, returns null.
    pub fn findFirstSet(self: Self) ?usize {
        var offset: usize = 0;
        var mask = self.masks;
        while (offset < self.bit_length) {
            if (mask[0] != 0) break;
            mask += 1;
            offset += @bitSizeOf(MaskInt);
        } else return null;
        return offset + @ctz(mask[0]);
    }

    /// Finds the index of the last set bit.
    /// If no bits are set, returns null.
    pub fn findLastSet(self: Self) ?usize {
        if (self.bit_length == 0) return null;
        const bs = @bitSizeOf(MaskInt);
        var len = self.bit_length / bs;
        if (self.bit_length % bs != 0) len += 1;
        var offset: usize = len * bs;
        var idx: usize = len - 1;
        while (self.masks[idx] == 0) : (idx -= 1) {
            offset -= bs;
            if (idx == 0) return null;
        }
        offset -= @clz(self.masks[idx]);
        offset -= 1;
        return offset;
    }

    /// Finds the index of the first set bit, and unsets it.
    /// If no bits are set, returns null.
    pub fn toggleFirstSet(self: *Self) ?usize {
        var offset: usize = 0;
        var mask = self.masks;
        while (offset < self.bit_length) {
            if (mask[0] != 0) break;
            mask += 1;
            offset += @bitSizeOf(MaskInt);
        } else return null;
        const index = @ctz(mask[0]);
        mask[0] &= (mask[0] - 1);
        return offset + index;
    }

    /// Returns true iff every corresponding bit in both
    /// bit sets are the same.
    pub fn eql(self: Self, other: Self) bool {
        if (self.bit_length != other.bit_length) {
            return false;
        }
        const num_masks = numMasks(self.bit_length);
        var i: usize = 0;
        return while (i < num_masks) : (i += 1) {
            if (self.masks[i] != other.masks[i]) {
                break false;
            }
        } else true;
    }

    /// Returns true iff the first bit set is the subset
    /// of the second one.
    pub fn subsetOf(self: Self, other: Self) bool {
        if (self.bit_length != other.bit_length) {
            return false;
        }
        const num_masks = numMasks(self.bit_length);
        var i: usize = 0;
        return while (i < num_masks) : (i += 1) {
            if (self.masks[i] & other.masks[i] != self.masks[i]) {
                break false;
            }
        } else true;
    }

    /// Returns true iff the first bit set is the superset
    /// of the second one.
    pub fn supersetOf(self: Self, other: Self) bool {
        if (self.bit_length != other.bit_length) {
            return false;
        }
        const num_masks = numMasks(self.bit_length);
        var i: usize = 0;
        return while (i < num_masks) : (i += 1) {
            if (self.masks[i] & other.masks[i] != other.masks[i]) {
                break false;
            }
        } else true;
    }

    /// Iterates through the items in the set, according to the options.
    /// The default options (.{}) will iterate indices of set bits in
    /// ascending order.  Modifications to the underlying bit set may
    /// or may not be observed by the iterator.  Resizing the underlying
    /// bit set invalidates the iterator.
    pub fn iterator(self: *const Self, comptime options: IteratorOptions) Iterator(options) {
        const num_masks = numMasks(self.bit_length);
        const padding_bits = num_masks * @bitSizeOf(MaskInt) - self.bit_length;
        const last_item_mask = (~@as(MaskInt, 0)) >> @as(ShiftInt, @intCast(padding_bits));
        return Iterator(options).init(self.masks[0..num_masks], last_item_mask);
    }

    pub fn Iterator(comptime options: IteratorOptions) type {
        return BitSetIterator(MaskInt, options);
    }

    fn maskBit(index: usize) MaskInt {
        return @as(MaskInt, 1) << @as(ShiftInt, @truncate(index));
    }
    fn maskIndex(index: usize) usize {
        return index >> @bitSizeOf(ShiftInt);
    }
    fn boolMaskBit(index: usize, value: bool) MaskInt {
        return @as(MaskInt, @intFromBool(value)) << @as(ShiftInt, @intCast(index));
    }
    fn numMasks(bit_length: usize) usize {
        return (bit_length + (@bitSizeOf(MaskInt) - 1)) / @bitSizeOf(MaskInt);
    }
};

/// A bit set with runtime-known size, backed by an allocated slice
/// of usize.  Thin wrapper around DynamicBitSetUnmanaged which keeps
/// track of the allocator instance.
pub const DynamicBitSet = struct {
    const Self = @This();

    /// The integer type used to represent a mask in this bit set
    pub const MaskInt = usize;

    /// The integer type used to shift a mask in this bit set
    pub const ShiftInt = std.math.Log2Int(MaskInt);

    allocator: Allocator,
    unmanaged: DynamicBitSetUnmanaged = .{},

    /// Creates a bit set with no elements present.
    pub fn initEmpty(allocator: Allocator, bit_length: usize) !Self {
        return Self{
            .unmanaged = try DynamicBitSetUnmanaged.initEmpty(allocator, bit_length),
            .allocator = allocator,
        };
    }

    /// Creates a bit set with all elements present.
    pub fn initFull(allocator: Allocator, bit_length: usize) !Self {
        return Self{
            .unmanaged = try DynamicBitSetUnmanaged.initFull(allocator, bit_length),
            .allocator = allocator,
        };
    }

    /// Resizes to a new length.  If the new length is larger
    /// than the old length, fills any added bits with `fill`.
    pub fn resize(self: *@This(), new_len: usize, fill: bool) !void {
        try self.unmanaged.resize(self.allocator, new_len, fill);
    }

    /// Deinitializes the array and releases its memory.
    /// The passed allocator must be the same one used for
    /// init* or resize in the past.
    pub fn deinit(self: *Self) void {
        self.unmanaged.deinit(self.allocator);
    }

    /// Creates a duplicate of this bit set, using the new allocator.
    pub fn clone(self: *const Self, new_allocator: Allocator) !Self {
        return Self{
            .unmanaged = try self.unmanaged.clone(new_allocator),
            .allocator = new_allocator,
        };
    }

    /// Returns the number of bits in this bit set
    pub inline fn capacity(self: Self) usize {
        return self.unmanaged.capacity();
    }

    /// Returns true if the bit at the specified index
    /// is present in the set, false otherwise.
    pub fn isSet(self: Self, index: usize) bool {
        return self.unmanaged.isSet(index);
    }

    /// Returns the total number of set bits in this bit set.
    pub fn count(self: Self) usize {
        return self.unmanaged.count();
    }

    /// Changes the value of the specified bit of the bit
    /// set to match the passed boolean.
    pub fn setValue(self: *Self, index: usize, value: bool) void {
        self.unmanaged.setValue(index, value);
    }

    /// Adds a specific bit to the bit set
    pub fn set(self: *Self, index: usize) void {
        self.unmanaged.set(index);
    }

    /// Changes the value of all bits in the specified range to
    /// match the passed boolean.
    pub fn setRangeValue(self: *Self, range: Range, value: bool) void {
        self.unmanaged.setRangeValue(range, value);
    }

    /// Removes a specific bit from the bit set
    pub fn unset(self: *Self, index: usize) void {
        self.unmanaged.unset(index);
    }

    /// Flips a specific bit in the bit set
    pub fn toggle(self: *Self, index: usize) void {
        self.unmanaged.toggle(index);
    }

    /// Flips all bits in this bit set which are present
    /// in the toggles bit set.  Both sets must have the
    /// same bit_length.
    pub fn toggleSet(self: *Self, toggles: Self) void {
        self.unmanaged.toggleSet(toggles.unmanaged);
    }

    /// Flips every bit in the bit set.
    pub fn toggleAll(self: *Self) void {
        self.unmanaged.toggleAll();
    }

    /// Performs a union of two bit sets, and stores the
    /// result in the first one.  Bits in the result are
    /// set if the corresponding bits were set in either input.
    /// The two sets must both be the same bit_length.
    pub fn setUnion(self: *Self, other: Self) void {
        self.unmanaged.setUnion(other.unmanaged);
    }

    /// Performs an intersection of two bit sets, and stores
    /// the result in the first one.  Bits in the result are
    /// set if the corresponding bits were set in both inputs.
    /// The two sets must both be the same bit_length.
    pub fn setIntersection(self: *Self, other: Self) void {
        self.unmanaged.setIntersection(other.unmanaged);
    }

    /// Finds the index of the first set bit.
    /// If no bits are set, returns null.
    pub fn findFirstSet(self: Self) ?usize {
        return self.unmanaged.findFirstSet();
    }

    /// Finds the index of the last set bit.
    /// If no bits are set, returns null.
    pub fn findLastSet(self: Self) ?usize {
        return self.unmanaged.findLastSet();
    }

    /// Finds the index of the first set bit, and unsets it.
    /// If no bits are set, returns null.
    pub fn toggleFirstSet(self: *Self) ?usize {
        return self.unmanaged.toggleFirstSet();
    }

    /// Returns true iff every corresponding bit in both
    /// bit sets are the same.
    pub fn eql(self: Self, other: Self) bool {
        return self.unmanaged.eql(other.unmanaged);
    }

    /// Iterates through the items in the set, according to the options.
    /// The default options (.{}) will iterate indices of set bits in
    /// ascending order.  Modifications to the underlying bit set may
    /// or may not be observed by the iterator.  Resizing the underlying
    /// bit set invalidates the iterator.
    pub fn iterator(self: *const Self, comptime options: IteratorOptions) Iterator(options) {
        return self.unmanaged.iterator(options);
    }

    pub const Iterator = DynamicBitSetUnmanaged.Iterator;
};

/// Options for configuring an iterator over a bit set
pub const IteratorOptions = struct {
    /// determines which bits should be visited
    kind: Type = .set,
    /// determines the order in which bit indices should be visited
    direction: Direction = .forward,

    pub const Type = enum {
        /// visit indexes of set bits
        set,
        /// visit indexes of unset bits
        unset,
    };

    pub const Direction = enum {
        /// visit indices in ascending order
        forward,
        /// visit indices in descending order.
        /// Note that this may be slightly more expensive than forward iteration.
        reverse,
    };
};

// The iterator is reusable between several bit set types
fn BitSetIterator(comptime MaskInt: type, comptime options: IteratorOptions) type {
    const ShiftInt = std.math.Log2Int(MaskInt);
    const kind = options.kind;
    const direction = options.direction;
    return struct {
        const Self = @This();

        // all bits which have not yet been iterated over
        bits_remain: MaskInt,
        // all words which have not yet been iterated over
        words_remain: []const MaskInt,
        // the offset of the current word
        bit_offset: usize,
        // the mask of the last word
        last_word_mask: MaskInt,

        fn init(masks: []const MaskInt, last_word_mask: MaskInt) Self {
            if (masks.len == 0) {
                return Self{
                    .bits_remain = 0,
                    .words_remain = &[_]MaskInt{},
                    .last_word_mask = last_word_mask,
                    .bit_offset = 0,
                };
            } else {
                var result = Self{
                    .bits_remain = 0,
                    .words_remain = masks,
                    .last_word_mask = last_word_mask,
                    .bit_offset = if (direction == .forward) 0 else (masks.len - 1) * @bitSizeOf(MaskInt),
                };
                result.nextWord(true);
                return result;
            }
        }

        /// Returns the index of the next unvisited set bit
        /// in the bit set, in ascending order.
        pub fn next(self: *Self) ?usize {
            while (self.bits_remain == 0) {
                if (self.words_remain.len == 0) return null;
                self.nextWord(false);
                switch (direction) {
                    .forward => self.bit_offset += @bitSizeOf(MaskInt),
                    .reverse => self.bit_offset -= @bitSizeOf(MaskInt),
                }
            }

            switch (direction) {
                .forward => {
                    const next_index = @ctz(self.bits_remain) + self.bit_offset;
                    self.bits_remain &= self.bits_remain - 1;
                    return next_index;
                },
                .reverse => {
                    const leading_zeroes = @clz(self.bits_remain);
                    const top_bit = (@bitSizeOf(MaskInt) - 1) - leading_zeroes;
                    const no_top_bit_mask = (@as(MaskInt, 1) << @as(ShiftInt, @intCast(top_bit))) - 1;
                    self.bits_remain &= no_top_bit_mask;
                    return top_bit + self.bit_offset;
                },
            }
        }

        // Load the next word.  Don't call this if there
        // isn't a next word.  If the next word is the
        // last word, mask off the padding bits so we
        // don't visit them.
        inline fn nextWord(self: *Self, comptime is_first_word: bool) void {
            var word = switch (direction) {
                .forward => self.words_remain[0],
                .reverse => self.words_remain[self.words_remain.len - 1],
            };
            switch (kind) {
                .set => {},
                .unset => {
                    word = ~word;
                    if ((direction == .reverse and is_first_word) or
                        (direction == .forward and self.words_remain.len == 1))
                    {
                        word &= self.last_word_mask;
                    }
                },
            }
            switch (direction) {
                .forward => self.words_remain = self.words_remain[1..],
                .reverse => self.words_remain.len -= 1,
            }
            self.bits_remain = word;
        }
    };
}

/// A range of indices within a bitset.
pub const Range = struct {
    /// The index of the first bit of interest.
    start: usize,
    /// The index immediately after the last bit of interest.
    end: usize,
};

// ---------------- Tests -----------------

const testing = std.testing;

fn testEql(empty: anytype, full: anytype, len: usize) !void {
    try testing.expect(empty.eql(empty));
    try testing.expect(full.eql(full));
    switch (len) {
        0 => {
            try testing.expect(empty.eql(full));
            try testing.expect(full.eql(empty));
        },
        else => {
            try testing.expect(!empty.eql(full));
            try testing.expect(!full.eql(empty));
        },
    }
}

fn testSubsetOf(empty: anytype, full: anytype, even: anytype, odd: anytype, len: usize) !void {
    try testing.expect(empty.subsetOf(empty));
    try testing.expect(empty.subsetOf(full));
    try testing.expect(full.subsetOf(full));
    switch (len) {
        0 => {
            try testing.expect(even.subsetOf(odd));
            try testing.expect(odd.subsetOf(even));
        },
        1 => {
            try testing.expect(!even.subsetOf(odd));
            try testing.expect(odd.subsetOf(even));
        },
        else => {
            try testing.expect(!even.subsetOf(odd));
            try testing.expect(!odd.subsetOf(even));
        },
    }
}

fn testSupersetOf(empty: anytype, full: anytype, even: anytype, odd: anytype, len: usize) !void {
    try testing.expect(full.supersetOf(full));
    try testing.expect(full.supersetOf(empty));
    try testing.expect(empty.supersetOf(empty));
    switch (len) {
        0 => {
            try testing.expect(even.supersetOf(odd));
            try testing.expect(odd.supersetOf(even));
        },
        1 => {
            try testing.expect(even.supersetOf(odd));
            try testing.expect(!odd.supersetOf(even));
        },
        else => {
            try testing.expect(!even.supersetOf(odd));
            try testing.expect(!odd.supersetOf(even));
        },
    }
}

fn testBitSet(a: anytype, b: anytype, len: usize) !void {
    try testing.expectEqual(len, a.capacity());
    try testing.expectEqual(len, b.capacity());

    {
        var i: usize = 0;
        while (i < len) : (i += 1) {
            a.setValue(i, i & 1 == 0);
            b.setValue(i, i & 2 == 0);
        }
    }

    try testing.expectEqual((len + 1) / 2, a.count());
    try testing.expectEqual((len + 3) / 4 + (len + 2) / 4, b.count());

    {
        var iter = a.iterator(.{});
        var i: usize = 0;
        while (i < len) : (i += 2) {
            try testing.expectEqual(@as(?usize, i), iter.next());
        }
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(?usize, null), iter.next());
    }
    a.toggleAll();
    {
        var iter = a.iterator(.{});
        var i: usize = 1;
        while (i < len) : (i += 2) {
            try testing.expectEqual(@as(?usize, i), iter.next());
        }
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(?usize, null), iter.next());
    }

    {
        var iter = b.iterator(.{ .kind = .unset });
        var i: usize = 2;
        while (i < len) : (i += 4) {
            try testing.expectEqual(@as(?usize, i), iter.next());
            if (i + 1 < len) {
                try testing.expectEqual(@as(?usize, i + 1), iter.next());
            }
        }
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(?usize, null), iter.next());
    }

    {
        var i: usize = 0;
        while (i < len) : (i += 1) {
            try testing.expectEqual(i & 1 != 0, a.isSet(i));
            try testing.expectEqual(i & 2 == 0, b.isSet(i));
        }
    }

    a.setUnion(b.*);
    {
        var i: usize = 0;
        while (i < len) : (i += 1) {
            try testing.expectEqual(i & 1 != 0 or i & 2 == 0, a.isSet(i));
            try testing.expectEqual(i & 2 == 0, b.isSet(i));
        }

        i = len;
        var set = a.iterator(.{ .direction = .reverse });
        var unset = a.iterator(.{ .kind = .unset, .direction = .reverse });
        while (i > 0) {
            i -= 1;
            if (i & 1 != 0 or i & 2 == 0) {
                try testing.expectEqual(@as(?usize, i), set.next());
            } else {
                try testing.expectEqual(@as(?usize, i), unset.next());
            }
        }
        try testing.expectEqual(@as(?usize, null), set.next());
        try testing.expectEqual(@as(?usize, null), set.next());
        try testing.expectEqual(@as(?usize, null), set.next());
        try testing.expectEqual(@as(?usize, null), unset.next());
        try testing.expectEqual(@as(?usize, null), unset.next());
        try testing.expectEqual(@as(?usize, null), unset.next());
    }

    a.toggleSet(b.*);
    {
        try testing.expectEqual(len / 4, a.count());

        var i: usize = 0;
        while (i < len) : (i += 1) {
            try testing.expectEqual(i & 1 != 0 and i & 2 != 0, a.isSet(i));
            try testing.expectEqual(i & 2 == 0, b.isSet(i));
            if (i & 1 == 0) {
                a.set(i);
            } else {
                a.unset(i);
            }
        }
    }

    a.setIntersection(b.*);
    {
        try testing.expectEqual((len + 3) / 4, a.count());

        var i: usize = 0;
        while (i < len) : (i += 1) {
            try testing.expectEqual(i & 1 == 0 and i & 2 == 0, a.isSet(i));
            try testing.expectEqual(i & 2 == 0, b.isSet(i));
        }
    }

    a.toggleSet(a.*);
    {
        var iter = a.iterator(.{});
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(usize, 0), a.count());
    }
    {
        var iter = a.iterator(.{ .direction = .reverse });
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(?usize, null), iter.next());
        try testing.expectEqual(@as(usize, 0), a.count());
    }

    const test_bits = [_]usize{
        0,  1,  2,   3,   4,   5,    6, 7, 9, 10, 11, 22, 31, 32, 63, 64,
        66, 95, 127, 160, 192, 1000,
    };
    for (test_bits) |i| {
        if (i < a.capacity()) {
            a.set(i);
        }
    }

    for (test_bits) |i| {
        if (i < a.capacity()) {
            try testing.expectEqual(@as(?usize, i), a.findFirstSet());
            try testing.expectEqual(@as(?usize, i), a.toggleFirstSet());
        }
    }
    try testing.expectEqual(@as(?usize, null), a.findFirstSet());
    try testing.expectEqual(@as(?usize, null), a.findLastSet());
    try testing.expectEqual(@as(?usize, null), a.toggleFirstSet());
    try testing.expectEqual(@as(?usize, null), a.findFirstSet());
    try testing.expectEqual(@as(?usize, null), a.findLastSet());
    try testing.expectEqual(@as(?usize, null), a.toggleFirstSet());
    try testing.expectEqual(@as(usize, 0), a.count());

    a.setRangeValue(.{ .start = 0, .end = len }, false);
    try testing.expectEqual(@as(usize, 0), a.count());

    a.setRangeValue(.{ .start = 0, .end = len }, true);
    try testing.expectEqual(len, a.count());

    a.setRangeValue(.{ .start = 0, .end = len }, false);
    a.setRangeValue(.{ .start = 0, .end = 0 }, true);
    try testing.expectEqual(@as(usize, 0), a.count());

    a.setRangeValue(.{ .start = len, .end = len }, true);
    try testing.expectEqual(@as(usize, 0), a.count());

    if (len >= 1) {
        a.setRangeValue(.{ .start = 0, .end = len }, false);
        a.setRangeValue(.{ .start = 0, .end = 1 }, true);
        try testing.expectEqual(@as(usize, 1), a.count());
        try testing.expect(a.isSet(0));

        a.setRangeValue(.{ .start = 0, .end = len }, false);
        a.setRangeValue(.{ .start = 0, .end = len - 1 }, true);
        try testing.expectEqual(len - 1, a.count());
        try testing.expect(!a.isSet(len - 1));

        a.setRangeValue(.{ .start = 0, .end = len }, false);
        a.setRangeValue(.{ .start = 1, .end = len }, true);
        try testing.expectEqual(@as(usize, len - 1), a.count());
        try testing.expect(!a.isSet(0));

        a.setRangeValue(.{ .start = 0, .end = len }, false);
        a.setRangeValue(.{ .start = len - 1, .end = len }, true);
        try testing.expectEqual(@as(usize, 1), a.count());
        try testing.expect(a.isSet(len - 1));

        if (len >= 4) {
            a.setRangeValue(.{ .start = 0, .end = len }, false);
            a.setRangeValue(.{ .start = 1, .end = len - 2 }, true);
            try testing.expectEqual(@as(usize, len - 3), a.count());
            try testing.expect(!a.isSet(0));
            try testing.expect(a.isSet(1));
            try testing.expect(a.isSet(len - 3));
            try testing.expect(!a.isSet(len - 2));
            try testing.expect(!a.isSet(len - 1));
        }
    }
}

fn fillEven(set: anytype, len: usize) void {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        set.setValue(i, i & 1 == 0);
    }
}

fn fillOdd(set: anytype, len: usize) void {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        set.setValue(i, i & 1 == 1);
    }
}

fn testPureBitSet(comptime Set: type) !void {
    const empty = Set.initEmpty();
    const full = Set.initFull();

    const even = even: {
        var bit_set = Set.initEmpty();
        fillEven(&bit_set, Set.bit_length);
        break :even bit_set;
    };

    const odd = odd: {
        var bit_set = Set.initEmpty();
        fillOdd(&bit_set, Set.bit_length);
        break :odd bit_set;
    };

    try testSubsetOf(empty, full, even, odd, Set.bit_length);
    try testSupersetOf(empty, full, even, odd, Set.bit_length);

    try testing.expect(empty.complement().eql(full));
    try testing.expect(full.complement().eql(empty));
    try testing.expect(even.complement().eql(odd));
    try testing.expect(odd.complement().eql(even));

    try testing.expect(empty.unionWith(empty).eql(empty));
    try testing.expect(empty.unionWith(full).eql(full));
    try testing.expect(full.unionWith(full).eql(full));
    try testing.expect(full.unionWith(empty).eql(full));
    try testing.expect(even.unionWith(odd).eql(full));
    try testing.expect(odd.unionWith(even).eql(full));

    try testing.expect(empty.intersectWith(empty).eql(empty));
    try testing.expect(empty.intersectWith(full).eql(empty));
    try testing.expect(full.intersectWith(full).eql(full));
    try testing.expect(full.intersectWith(empty).eql(empty));
    try testing.expect(even.intersectWith(odd).eql(empty));
    try testing.expect(odd.intersectWith(even).eql(empty));

    try testing.expect(empty.xorWith(empty).eql(empty));
    try testing.expect(empty.xorWith(full).eql(full));
    try testing.expect(full.xorWith(full).eql(empty));
    try testing.expect(full.xorWith(empty).eql(full));
    try testing.expect(even.xorWith(odd).eql(full));
    try testing.expect(odd.xorWith(even).eql(full));

    try testing.expect(empty.differenceWith(empty).eql(empty));
    try testing.expect(empty.differenceWith(full).eql(empty));
    try testing.expect(full.differenceWith(full).eql(empty));
    try testing.expect(full.differenceWith(empty).eql(full));
    try testing.expect(full.differenceWith(odd).eql(even));
    try testing.expect(full.differenceWith(even).eql(odd));
}

fn testStaticBitSet(comptime Set: type) !void {
    var a = Set.initEmpty();
    var b = Set.initFull();
    try testing.expectEqual(@as(usize, 0), a.count());
    try testing.expectEqual(@as(usize, Set.bit_length), b.count());

    try testEql(a, b, Set.bit_length);
    try testBitSet(&a, &b, Set.bit_length);

    try testPureBitSet(Set);
}

test IntegerBitSet {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    try testStaticBitSet(IntegerBitSet(0));
    try testStaticBitSet(IntegerBitSet(1));
    try testStaticBitSet(IntegerBitSet(2));
    try testStaticBitSet(IntegerBitSet(5));
    try testStaticBitSet(IntegerBitSet(8));
    try testStaticBitSet(IntegerBitSet(32));
    try testStaticBitSet(IntegerBitSet(64));
    try testStaticBitSet(IntegerBitSet(127));
}

test ArrayBitSet {
    inline for (.{ 0, 1, 2, 31, 32, 33, 63, 64, 65, 254, 500, 3000 }) |size| {
        try testStaticBitSet(ArrayBitSet(u8, size));
        try testStaticBitSet(ArrayBitSet(u16, size));
        try testStaticBitSet(ArrayBitSet(u32, size));
        try testStaticBitSet(ArrayBitSet(u64, size));
        try testStaticBitSet(ArrayBitSet(u128, size));
    }
}

test DynamicBitSetUnmanaged {
    const allocator = std.testing.allocator;
    var a = try DynamicBitSetUnmanaged.initEmpty(allocator, 300);
    try testing.expectEqual(@as(usize, 0), a.count());
    a.deinit(allocator);

    a = try DynamicBitSetUnmanaged.initEmpty(allocator, 0);
    defer a.deinit(allocator);
    for ([_]usize{ 1, 2, 31, 32, 33, 0, 65, 64, 63, 500, 254, 3000 }) |size| {
        const old_len = a.capacity();

        var empty = try a.clone(allocator);
        defer empty.deinit(allocator);
        try testing.expectEqual(old_len, empty.capacity());
        var i: usize = 0;
        while (i < old_len) : (i += 1) {
            try testing.expectEqual(a.isSet(i), empty.isSet(i));
        }

        a.toggleSet(a); // zero a
        empty.toggleSet(empty);

        try a.resize(allocator, size, true);
        try empty.resize(allocator, size, false);

        if (size > old_len) {
            try testing.expectEqual(size - old_len, a.count());
        } else {
            try testing.expectEqual(@as(usize, 0), a.count());
        }
        try testing.expectEqual(@as(usize, 0), empty.count());

        var full = try DynamicBitSetUnmanaged.initFull(allocator, size);
        defer full.deinit(allocator);
        try testing.expectEqual(@as(usize, size), full.count());

        try testEql(empty, full, size);
        {
            var even = try DynamicBitSetUnmanaged.initEmpty(allocator, size);
            defer even.deinit(allocator);
            fillEven(&even, size);

            var odd = try DynamicBitSetUnmanaged.initEmpty(allocator, size);
            defer odd.deinit(allocator);
            fillOdd(&odd, size);

            try testSubsetOf(empty, full, even, odd, size);
            try testSupersetOf(empty, full, even, odd, size);
        }
        try testBitSet(&a, &full, size);
    }
}

test DynamicBitSet {
    const allocator = std.testing.allocator;
    var a = try DynamicBitSet.initEmpty(allocator, 300);
    try testing.expectEqual(@as(usize, 0), a.count());
    a.deinit();

    a = try DynamicBitSet.initEmpty(allocator, 0);
    defer a.deinit();
    for ([_]usize{ 1, 2, 31, 32, 33, 0, 65, 64, 63, 500, 254, 3000 }) |size| {
        const old_len = a.capacity();

        var tmp = try a.clone(allocator);
        defer tmp.deinit();
        try testing.expectEqual(old_len, tmp.capacity());
        var i: usize = 0;
        while (i < old_len) : (i += 1) {
            try testing.expectEqual(a.isSet(i), tmp.isSet(i));
        }

        a.toggleSet(a); // zero a
        tmp.toggleSet(tmp); // zero tmp

        try a.resize(size, true);
        try tmp.resize(size, false);

        if (size > old_len) {
            try testing.expectEqual(size - old_len, a.count());
        } else {
            try testing.expectEqual(@as(usize, 0), a.count());
        }
        try testing.expectEqual(@as(usize, 0), tmp.count());

        var b = try DynamicBitSet.initFull(allocator, size);
        defer b.deinit();
        try testing.expectEqual(@as(usize, size), b.count());

        try testEql(tmp, b, size);
        try testBitSet(&a, &b, size);
    }
}

test StaticBitSet {
    try testing.expectEqual(IntegerBitSet(0), StaticBitSet(0));
    try testing.expectEqual(IntegerBitSet(5), StaticBitSet(5));
    try testing.expectEqual(IntegerBitSet(@bitSizeOf(usize)), StaticBitSet(@bitSizeOf(usize)));
    try testing.expectEqual(ArrayBitSet(usize, @bitSizeOf(usize) + 1), StaticBitSet(@bitSizeOf(usize) + 1));
    try testing.expectEqual(ArrayBitSet(usize, 500), StaticBitSet(500));
}
//! Effectively a stack of u1 values implemented using ArrayList(u8).

const BitStack = @This();

const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

bytes: std.ArrayList(u8),
bit_len: usize = 0,

pub fn init(allocator: Allocator) @This() {
    return .{
        .bytes = std.ArrayList(u8).init(allocator),
    };
}

pub fn deinit(self: *@This()) void {
    self.bytes.deinit();
    self.* = undefined;
}

pub fn ensureTotalCapacity(self: *@This(), bit_capacity: usize) Allocator.Error!void {
    const byte_capacity = (bit_capacity + 7) >> 3;
    try self.bytes.ensureTotalCapacity(byte_capacity);
}

pub fn push(self: *@This(), b: u1) Allocator.Error!void {
    const byte_index = self.bit_len >> 3;
    if (self.bytes.items.len <= byte_index) {
        try self.bytes.append(0);
    }

    pushWithStateAssumeCapacity(self.bytes.items, &self.bit_len, b);
}

pub fn peek(self: *const @This()) u1 {
    return peekWithState(self.bytes.items, self.bit_len);
}

pub fn pop(self: *@This()) u1 {
    return popWithState(self.bytes.items, &self.bit_len);
}

/// Standalone function for working with a fixed-size buffer.
pub fn pushWithStateAssumeCapacity(buf: []u8, bit_len: *usize, b: u1) void {
    const byte_index = bit_len.* >> 3;
    const bit_index = @as(u3, @intCast(bit_len.* & 7));

    buf[byte_index] &= ~(@as(u8, 1) << bit_index);
    buf[byte_index] |= @as(u8, b) << bit_index;

    bit_len.* += 1;
}

/// Standalone function for working with a fixed-size buffer.
pub fn peekWithState(buf: []const u8, bit_len: usize) u1 {
    const byte_index = (bit_len - 1) >> 3;
    const bit_index = @as(u3, @intCast((bit_len - 1) & 7));
    return @as(u1, @intCast((buf[byte_index] >> bit_index) & 1));
}

/// Standalone function for working with a fixed-size buffer.
pub fn popWithState(buf: []const u8, bit_len: *usize) u1 {
    const b = peekWithState(buf, bit_len.*);
    bit_len.* -= 1;
    return b;
}

const testing = std.testing;
test BitStack {
    var stack = BitStack.init(testing.allocator);
    defer stack.deinit();

    try stack.push(1);
    try stack.push(0);
    try stack.push(0);
    try stack.push(1);

    try testing.expectEqual(@as(u1, 1), stack.peek());
    try testing.expectEqual(@as(u1, 1), stack.pop());
    try testing.expectEqual(@as(u1, 0), stack.peek());
    try testing.expectEqual(@as(u1, 0), stack.pop());
    try testing.expectEqual(@as(u1, 0), stack.pop());
    try testing.expectEqual(@as(u1, 1), stack.pop());
}
const std = @import("std.zig");
const assert = std.debug.assert;
const mem = std.mem;
const testing = std.testing;
const Alignment = std.mem.Alignment;

/// A structure with an array and a length, that can be used as a slice.
///
/// Useful to pass around small arrays whose exact size is only known at
/// runtime, but whose maximum size is known at comptime, without requiring
/// an `Allocator`.
///
/// ```zig
/// var actual_size = 32;
/// var a = try BoundedArray(u8, 64).init(actual_size);
/// var slice = a.slice(); // a slice of the 64-byte array
/// var a_clone = a; // creates a copy - the structure doesn't use any internal pointers
/// ```
pub fn BoundedArray(comptime T: type, comptime buffer_capacity: usize) type {
    return BoundedArrayAligned(T, .of(T), buffer_capacity);
}

/// A structure with an array, length and alignment, that can be used as a
/// slice.
///
/// Useful to pass around small explicitly-aligned arrays whose exact size is
/// only known at runtime, but whose maximum size is known at comptime, without
/// requiring an `Allocator`.
/// ```zig
//  var a = try BoundedArrayAligned(u8, 16, 2).init(0);
//  try a.append(255);
//  try a.append(255);
//  const b = @ptrCast(*const [1]u16, a.constSlice().ptr);
//  try testing.expectEqual(@as(u16, 65535), b[0]);
/// ```
pub fn BoundedArrayAligned(
    comptime T: type,
    comptime alignment: Alignment,
    comptime buffer_capacity: usize,
) type {
    return struct {
        const Self = @This();
        buffer: [buffer_capacity]T align(alignment.toByteUnits()) = undefined,
        len: usize = 0,

        /// Set the actual length of the slice.
        /// Returns error.Overflow if it exceeds the length of the backing array.
        pub fn init(len: usize) error{Overflow}!Self {
            if (len > buffer_capacity) return error.Overflow;
            return Self{ .len = len };
        }

        /// View the internal array as a slice whose size was previously set.
        pub fn slice(self: anytype) switch (@TypeOf(&self.buffer)) {
            *align(alignment.toByteUnits()) [buffer_capacity]T => []align(alignment.toByteUnits()) T,
            *align(alignment.toByteUnits()) const [buffer_capacity]T => []align(alignment.toByteUnits()) const T,
            else => unreachable,
        } {
            return self.buffer[0..self.len];
        }

        /// View the internal array as a constant slice whose size was previously set.
        pub fn constSlice(self: *const Self) []align(alignment.toByteUnits()) const T {
            return self.slice();
        }

        /// Adjust the slice's length to `len`.
        /// Does not initialize added items if any.
        pub fn resize(self: *Self, len: usize) error{Overflow}!void {
            if (len > buffer_capacity) return error.Overflow;
            self.len = len;
        }

        /// Remove all elements from the slice.
        pub fn clear(self: *Self) void {
            self.len = 0;
        }

        /// Copy the content of an existing slice.
        pub fn fromSlice(m: []const T) error{Overflow}!Self {
            var list = try init(m.len);
            @memcpy(list.slice(), m);
            return list;
        }

        /// Return the element at index `i` of the slice.
        pub fn get(self: Self, i: usize) T {
            return self.constSlice()[i];
        }

        /// Set the value of the element at index `i` of the slice.
        pub fn set(self: *Self, i: usize, item: T) void {
            self.slice()[i] = item;
        }

        /// Return the maximum length of a slice.
        pub fn capacity(self: Self) usize {
            return self.buffer.len;
        }

        /// Check that the slice can hold at least `additional_count` items.
        pub fn ensureUnusedCapacity(self: Self, additional_count: usize) error{Overflow}!void {
            if (self.len + additional_count > buffer_capacity) {
                return error.Overflow;
            }
        }

        /// Increase length by 1, returning a pointer to the new item.
        pub fn addOne(self: *Self) error{Overflow}!*T {
            try self.ensureUnusedCapacity(1);
            return self.addOneAssumeCapacity();
        }

        /// Increase length by 1, returning pointer to the new item.
        /// Asserts that there is space for the new item.
        pub fn addOneAssumeCapacity(self: *Self) *T {
            assert(self.len < buffer_capacity);
            self.len += 1;
            return &self.slice()[self.len - 1];
        }

        /// Resize the slice, adding `n` new elements, which have `undefined` values.
        /// The return value is a pointer to the array of uninitialized elements.
        pub fn addManyAsArray(self: *Self, comptime n: usize) error{Overflow}!*align(alignment.toByteUnits()) [n]T {
            const prev_len = self.len;
            try self.resize(self.len + n);
            return self.slice()[prev_len..][0..n];
        }

        /// Resize the slice, adding `n` new elements, which have `undefined` values.
        /// The return value is a slice pointing to the uninitialized elements.
        pub fn addManyAsSlice(self: *Self, n: usize) error{Overflow}![]align(alignment.toByteUnits()) T {
            const prev_len = self.len;
            try self.resize(self.len + n);
            return self.slice()[prev_len..][0..n];
        }

        /// Remove and return the last element from the slice, or return `null` if the slice is empty.
        pub fn pop(self: *Self) ?T {
            if (self.len == 0) return null;
            const item = self.get(self.len - 1);
            self.len -= 1;
            return item;
        }

        /// Return a slice of only the extra capacity after items.
        /// This can be useful for writing directly into it.
        /// Note that such an operation must be followed up with a
        /// call to `resize()`
        pub fn unusedCapacitySlice(self: *Self) []align(alignment.toByteUnits()) T {
            return self.buffer[self.len..];
        }

        /// Insert `item` at index `i` by moving `slice[n .. slice.len]` to make room.
        /// This operation is O(N).
        pub fn insert(
            self: *Self,
            i: usize,
            item: T,
        ) error{Overflow}!void {
            if (i > self.len) {
                return error.Overflow;
            }
            _ = try self.addOne();
            var s = self.slice();
            mem.copyBackwards(T, s[i + 1 .. s.len], s[i .. s.len - 1]);
            self.buffer[i] = item;
        }

        /// Insert slice `items` at index `i` by moving `slice[i .. slice.len]` to make room.
        /// This operation is O(N).
        pub fn insertSlice(self: *Self, i: usize, items: []const T) error{Overflow}!void {
            try self.ensureUnusedCapacity(items.len);
            self.len += items.len;
            mem.copyBackwards(T, self.slice()[i + items.len .. self.len], self.constSlice()[i .. self.len - items.len]);
            @memcpy(self.slice()[i..][0..items.len], items);
        }

        /// Replace range of elements `slice[start..][0..len]` with `new_items`.
        /// Grows slice if `len < new_items.len`.
        /// Shrinks slice if `len > new_items.len`.
        pub fn replaceRange(
            self: *Self,
            start: usize,
            len: usize,
            new_items: []const T,
        ) error{Overflow}!void {
            const after_range = start + len;
            var range = self.slice()[start..after_range];

            if (range.len == new_items.len) {
                @memcpy(range[0..new_items.len], new_items);
            } else if (range.len < new_items.len) {
                const first = new_items[0..range.len];
                const rest = new_items[range.len..];
                @memcpy(range[0..first.len], first);
                try self.insertSlice(after_range, rest);
            } else {
                @memcpy(range[0..new_items.len], new_items);
                const after_subrange = start + new_items.len;
                for (self.constSlice()[after_range..], 0..) |item, i| {
                    self.slice()[after_subrange..][i] = item;
                }
                self.len -= len - new_items.len;
            }
        }

        /// Extend the slice by 1 element.
        pub fn append(self: *Self, item: T) error{Overflow}!void {
            const new_item_ptr = try self.addOne();
            new_item_ptr.* = item;
        }

        /// Extend the slice by 1 element, asserting the capacity is already
        /// enough to store the new item.
        pub fn appendAssumeCapacity(self: *Self, item: T) void {
            const new_item_ptr = self.addOneAssumeCapacity();
            new_item_ptr.* = item;
        }

        /// Remove the element at index `i`, shift elements after index
        /// `i` forward, and return the removed element.
        /// Asserts the slice has at least one item.
        /// This operation is O(N).
        pub fn orderedRemove(self: *Self, i: usize) T {
            const newlen = self.len - 1;
            if (newlen == i) return self.pop().?;
            const old_item = self.get(i);
            for (self.slice()[i..newlen], 0..) |*b, j| b.* = self.get(i + 1 + j);
            self.set(newlen, undefined);
            self.len = newlen;
            return old_item;
        }

        /// Remove the element at the specified index and return it.
        /// The empty slot is filled from the end of the slice.
        /// This operation is O(1).
        pub fn swapRemove(self: *Self, i: usize) T {
            if (self.len - 1 == i) return self.pop().?;
            const old_item = self.get(i);
            self.set(i, self.pop().?);
            return old_item;
        }

        /// Append the slice of items to the slice.
        pub fn appendSlice(self: *Self, items: []const T) error{Overflow}!void {
            try self.ensureUnusedCapacity(items.len);
            self.appendSliceAssumeCapacity(items);
        }

        /// Append the slice of items to the slice, asserting the capacity is already
        /// enough to store the new items.
        pub fn appendSliceAssumeCapacity(self: *Self, items: []const T) void {
            const old_len = self.len;
            self.len += items.len;
            @memcpy(self.slice()[old_len..][0..items.len], items);
        }

        /// Append a value to the slice `n` times.
        /// Allocates more memory as necessary.
        pub fn appendNTimes(self: *Self, value: T, n: usize) error{Overflow}!void {
            const old_len = self.len;
            try self.resize(old_len + n);
            @memset(self.slice()[old_len..self.len], value);
        }

        /// Append a value to the slice `n` times.
        /// Asserts the capacity is enough.
        pub fn appendNTimesAssumeCapacity(self: *Self, value: T, n: usize) void {
            const old_len = self.len;
            self.len += n;
            assert(self.len <= buffer_capacity);
            @memset(self.slice()[old_len..self.len], value);
        }

        pub const Writer = if (T != u8)
            @compileError("The Writer interface is only defined for BoundedArray(u8, ...) " ++
                "but the given type is BoundedArray(" ++ @typeName(T) ++ ", ...)")
        else
            std.io.Writer(*Self, error{Overflow}, appendWrite);

        /// Initializes a writer which will write into the array.
        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        /// Same as `appendSlice` except it returns the number of bytes written, which is always the same
        /// as `m.len`. The purpose of this function existing is to match `std.io.Writer` API.
        fn appendWrite(self: *Self, m: []const u8) error{Overflow}!usize {
            try self.appendSlice(m);
            return m.len;
        }
    };
}

test BoundedArray {
    var a = try BoundedArray(u8, 64).init(32);

    try testing.expectEqual(a.capacity(), 64);
    try testing.expectEqual(a.slice().len, 32);
    try testing.expectEqual(a.constSlice().len, 32);

    try a.resize(48);
    try testing.expectEqual(a.len, 48);

    const x = [_]u8{1} ** 10;
    a = try BoundedArray(u8, 64).fromSlice(&x);
    try testing.expectEqualSlices(u8, &x, a.constSlice());

    var a2 = a;
    try testing.expectEqualSlices(u8, a.constSlice(), a2.constSlice());
    a2.set(0, 0);
    try testing.expect(a.get(0) != a2.get(0));

    try testing.expectError(error.Overflow, a.resize(100));
    try testing.expectError(error.Overflow, BoundedArray(u8, x.len - 1).fromSlice(&x));

    try a.resize(0);
    try a.ensureUnusedCapacity(a.capacity());
    (try a.addOne()).* = 0;
    try a.ensureUnusedCapacity(a.capacity() - 1);
    try testing.expectEqual(a.len, 1);

    const uninitialized = try a.addManyAsArray(4);
    try testing.expectEqual(uninitialized.len, 4);
    try testing.expectEqual(a.len, 5);

    try a.append(0xff);
    try testing.expectEqual(a.len, 6);
    try testing.expectEqual(a.pop(), 0xff);

    a.appendAssumeCapacity(0xff);
    try testing.expectEqual(a.len, 6);
    try testing.expectEqual(a.pop(), 0xff);

    try a.resize(1);
    try testing.expectEqual(a.pop(), 0);
    try testing.expectEqual(a.pop(), null);
    var unused = a.unusedCapacitySlice();
    @memset(unused[0..8], 2);
    unused[8] = 3;
    unused[9] = 4;
    try testing.expectEqual(unused.len, a.capacity());
    try a.resize(10);

    try a.insert(5, 0xaa);
    try testing.expectEqual(a.len, 11);
    try testing.expectEqual(a.get(5), 0xaa);
    try testing.expectEqual(a.get(9), 3);
    try testing.expectEqual(a.get(10), 4);

    try a.insert(11, 0xbb);
    try testing.expectEqual(a.len, 12);
    try testing.expectEqual(a.pop(), 0xbb);

    try a.appendSlice(&x);
    try testing.expectEqual(a.len, 11 + x.len);

    try a.appendNTimes(0xbb, 5);
    try testing.expectEqual(a.len, 11 + x.len + 5);
    try testing.expectEqual(a.pop(), 0xbb);

    a.appendNTimesAssumeCapacity(0xcc, 5);
    try testing.expectEqual(a.len, 11 + x.len + 5 - 1 + 5);
    try testing.expectEqual(a.pop(), 0xcc);

    try testing.expectEqual(a.len, 29);
    try a.replaceRange(1, 20, &x);
    try testing.expectEqual(a.len, 29 + x.len - 20);

    try a.insertSlice(0, &x);
    try testing.expectEqual(a.len, 29 + x.len - 20 + x.len);

    try a.replaceRange(1, 5, &x);
    try testing.expectEqual(a.len, 29 + x.len - 20 + x.len + x.len - 5);

    try a.append(10);
    try testing.expectEqual(a.pop(), 10);

    try a.append(20);
    const removed = a.orderedRemove(5);
    try testing.expectEqual(removed, 1);
    try testing.expectEqual(a.len, 34);

    a.set(0, 0xdd);
    a.set(a.len - 1, 0xee);
    const swapped = a.swapRemove(0);
    try testing.expectEqual(swapped, 0xdd);
    try testing.expectEqual(a.get(0), 0xee);

    const added_slice = try a.addManyAsSlice(3);
    try testing.expectEqual(added_slice.len, 3);
    try testing.expectEqual(a.len, 36);

    while (a.pop()) |_| {}
    const w = a.writer();
    const s = "hello, this is a test string";
    try w.writeAll(s);
    try testing.expectEqualStrings(s, a.constSlice());
}

test "BoundedArrayAligned" {
    var a = try BoundedArrayAligned(u8, .@"16", 4).init(0);
    try a.append(0);
    try a.append(0);
    try a.append(255);
    try a.append(255);

    const b = @as(*const [2]u16, @ptrCast(a.constSlice().ptr));
    try testing.expectEqual(@as(u16, 0), b[0]);
    try testing.expectEqual(@as(u16, 65535), b[1]);
}
const std = @import("std.zig");
const StringHashMap = std.StringHashMap;
const mem = std.mem;
const Allocator = mem.Allocator;
const testing = std.testing;

/// BufMap copies keys and values before they go into the map and
/// frees them when they get removed.
pub const BufMap = struct {
    hash_map: BufMapHashMap,

    const BufMapHashMap = StringHashMap([]const u8);

    /// Create a BufMap backed by a specific allocator.
    /// That allocator will be used for both backing allocations
    /// and string deduplication.
    pub fn init(allocator: Allocator) BufMap {
        return .{ .hash_map = BufMapHashMap.init(allocator) };
    }

    /// Free the backing storage of the map, as well as all
    /// of the stored keys and values.
    pub fn deinit(self: *BufMap) void {
        var it = self.hash_map.iterator();
        while (it.next()) |entry| {
            self.free(entry.key_ptr.*);
            self.free(entry.value_ptr.*);
        }

        self.hash_map.deinit();
    }

    /// Same as `put` but the key and value become owned by the BufMap rather
    /// than being copied.
    /// If `putMove` fails, the ownership of key and value does not transfer.
    pub fn putMove(self: *BufMap, key: []u8, value: []u8) !void {
        const get_or_put = try self.hash_map.getOrPut(key);
        if (get_or_put.found_existing) {
            self.free(get_or_put.key_ptr.*);
            self.free(get_or_put.value_ptr.*);
            get_or_put.key_ptr.* = key;
        }
        get_or_put.value_ptr.* = value;
    }

    /// `key` and `value` are copied into the BufMap.
    pub fn put(self: *BufMap, key: []const u8, value: []const u8) !void {
        const value_copy = try self.copy(value);
        errdefer self.free(value_copy);
        const get_or_put = try self.hash_map.getOrPut(key);
        if (get_or_put.found_existing) {
            self.free(get_or_put.value_ptr.*);
        } else {
            get_or_put.key_ptr.* = self.copy(key) catch |err| {
                _ = self.hash_map.remove(key);
                return err;
            };
        }
        get_or_put.value_ptr.* = value_copy;
    }

    /// Find the address of the value associated with a key.
    /// The returned pointer is invalidated if the map resizes.
    pub fn getPtr(self: BufMap, key: []const u8) ?*[]const u8 {
        return self.hash_map.getPtr(key);
    }

    /// Return the map's copy of the value associated with
    /// a key.  The returned string is invalidated if this
    /// key is removed from the map.
    pub fn get(self: BufMap, key: []const u8) ?[]const u8 {
        return self.hash_map.get(key);
    }

    /// Removes the item from the map and frees its value.
    /// This invalidates the value returned by get() for this key.
    pub fn remove(self: *BufMap, key: []const u8) void {
        const kv = self.hash_map.fetchRemove(key) orelse return;
        self.free(kv.key);
        self.free(kv.value);
    }

    /// Returns the number of KV pairs stored in the map.
    pub fn count(self: BufMap) BufMapHashMap.Size {
        return self.hash_map.count();
    }

    /// Returns an iterator over entries in the map.
    pub fn iterator(self: *const BufMap) BufMapHashMap.Iterator {
        return self.hash_map.iterator();
    }

    fn free(self: BufMap, value: []const u8) void {
        self.hash_map.allocator.free(value);
    }

    fn copy(self: BufMap, value: []const u8) ![]u8 {
        return self.hash_map.allocator.dupe(u8, value);
    }
};

test "BufMap" {
    const allocator = std.testing.allocator;
    var bufmap = BufMap.init(allocator);
    defer bufmap.deinit();

    try bufmap.put("x", "1");
    try testing.expect(mem.eql(u8, bufmap.get("x").?, "1"));
    try testing.expect(1 == bufmap.count());

    try bufmap.put("x", "2");
    try testing.expect(mem.eql(u8, bufmap.get("x").?, "2"));
    try testing.expect(1 == bufmap.count());

    try bufmap.put("x", "3");
    try testing.expect(mem.eql(u8, bufmap.get("x").?, "3"));
    try testing.expect(1 == bufmap.count());

    bufmap.remove("x");
    try testing.expect(0 == bufmap.count());

    try bufmap.putMove(try allocator.dupe(u8, "k"), try allocator.dupe(u8, "v1"));
    try bufmap.putMove(try allocator.dupe(u8, "k"), try allocator.dupe(u8, "v2"));
}
const std = @import("std.zig");
const StringHashMap = std.StringHashMap;
const mem = @import("mem.zig");
const Allocator = mem.Allocator;
const testing = std.testing;

/// A BufSet is a set of strings.  The BufSet duplicates
/// strings internally, and never takes ownership of strings
/// which are passed to it.
pub const BufSet = struct {
    hash_map: BufSetHashMap,

    const BufSetHashMap = StringHashMap(void);
    pub const Iterator = BufSetHashMap.KeyIterator;

    /// Create a BufSet using an allocator.  The allocator will
    /// be used internally for both backing allocations and
    /// string duplication.
    pub fn init(a: Allocator) BufSet {
        return .{ .hash_map = BufSetHashMap.init(a) };
    }

    /// Free a BufSet along with all stored keys.
    pub fn deinit(self: *BufSet) void {
        var it = self.hash_map.keyIterator();
        while (it.next()) |key_ptr| {
            self.free(key_ptr.*);
        }
        self.hash_map.deinit();
        self.* = undefined;
    }

    /// Insert an item into the BufSet.  The item will be
    /// copied, so the caller may delete or reuse the
    /// passed string immediately.
    pub fn insert(self: *BufSet, value: []const u8) !void {
        const gop = try self.hash_map.getOrPut(value);
        if (!gop.found_existing) {
            gop.key_ptr.* = self.copy(value) catch |err| {
                _ = self.hash_map.remove(value);
                return err;
            };
        }
    }

    /// Check if the set contains an item matching the passed string
    pub fn contains(self: BufSet, value: []const u8) bool {
        return self.hash_map.contains(value);
    }

    /// Remove an item from the set.
    pub fn remove(self: *BufSet, value: []const u8) void {
        const kv = self.hash_map.fetchRemove(value) orelse return;
        self.free(kv.key);
    }

    /// Returns the number of items stored in the set
    pub fn count(self: *const BufSet) usize {
        return self.hash_map.count();
    }

    /// Returns an iterator over the items stored in the set.
    /// Iteration order is arbitrary.
    pub fn iterator(self: *const BufSet) Iterator {
        return self.hash_map.keyIterator();
    }

    /// Get the allocator used by this set
    pub fn allocator(self: *const BufSet) Allocator {
        return self.hash_map.allocator;
    }

    /// Creates a copy of this BufSet, using a specified allocator.
    pub fn cloneWithAllocator(
        self: *const BufSet,
        new_allocator: Allocator,
    ) Allocator.Error!BufSet {
        const cloned_hashmap = try self.hash_map.cloneWithAllocator(new_allocator);
        const cloned = BufSet{ .hash_map = cloned_hashmap };
        var it = cloned.hash_map.keyIterator();
        while (it.next()) |key_ptr| {
            key_ptr.* = try cloned.copy(key_ptr.*);
        }

        return cloned;
    }

    /// Creates a copy of this BufSet, using the same allocator.
    pub fn clone(self: *const BufSet) Allocator.Error!BufSet {
        return self.cloneWithAllocator(self.allocator());
    }

    test clone {
        var original = BufSet.init(testing.allocator);
        defer original.deinit();
        try original.insert("x");

        var cloned = try original.clone();
        defer cloned.deinit();
        cloned.remove("x");
        try testing.expect(original.count() == 1);
        try testing.expect(cloned.count() == 0);

        try testing.expectError(
            error.OutOfMemory,
            original.cloneWithAllocator(testing.failing_allocator),
        );
    }

    fn free(self: *const BufSet, value: []const u8) void {
        self.hash_map.allocator.free(value);
    }

    fn copy(self: *const BufSet, value: []const u8) ![]const u8 {
        const result = try self.hash_map.allocator.alloc(u8, value.len);
        @memcpy(result, value);
        return result;
    }
};

test BufSet {
    var bufset = BufSet.init(std.testing.allocator);
    defer bufset.deinit();

    try bufset.insert("x");
    try testing.expect(bufset.count() == 1);
    bufset.remove("x");
    try testing.expect(bufset.count() == 0);

    try bufset.insert("x");
    try bufset.insert("y");
    try bufset.insert("z");
}

test "clone with arena" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var buf = BufSet.init(allocator);
    defer buf.deinit();
    try buf.insert("member1");
    try buf.insert("member2");

    _ = try buf.cloneWithAllocator(arena.allocator());
}
const std = @import("std.zig");
const builtin = @import("builtin");
const io = std.io;
const fs = std.fs;
const mem = std.mem;
const debug = std.debug;
const panic = std.debug.panic;
const assert = debug.assert;
const log = std.log;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;
const Allocator = mem.Allocator;
const Target = std.Target;
const process = std.process;
const EnvMap = std.process.EnvMap;
const File = fs.File;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Build = @This();

pub const Cache = @import("Build/Cache.zig");
pub const Step = @import("Build/Step.zig");
pub const Module = @import("Build/Module.zig");
pub const Watch = @import("Build/Watch.zig");
pub const Fuzz = @import("Build/Fuzz.zig");

/// Shared state among all Build instances.
graph: *Graph,
install_tls: TopLevelStep,
uninstall_tls: TopLevelStep,
allocator: Allocator,
user_input_options: UserInputOptionsMap,
available_options_map: AvailableOptionsMap,
available_options_list: ArrayList(AvailableOption),
verbose: bool,
verbose_link: bool,
verbose_cc: bool,
verbose_air: bool,
verbose_llvm_ir: ?[]const u8,
verbose_llvm_bc: ?[]const u8,
verbose_cimport: bool,
verbose_llvm_cpu_features: bool,
reference_trace: ?u32 = null,
invalid_user_input: bool,
default_step: *Step,
top_level_steps: std.StringArrayHashMapUnmanaged(*TopLevelStep),
install_prefix: []const u8,
dest_dir: ?[]const u8,
lib_dir: []const u8,
exe_dir: []const u8,
h_dir: []const u8,
install_path: []const u8,
sysroot: ?[]const u8 = null,
search_prefixes: std.ArrayListUnmanaged([]const u8),
libc_file: ?[]const u8 = null,
/// Path to the directory containing build.zig.
build_root: Cache.Directory,
cache_root: Cache.Directory,
pkg_config_pkg_list: ?(PkgConfigError![]const PkgConfigPkg) = null,
args: ?[]const []const u8 = null,
debug_log_scopes: []const []const u8 = &.{},
debug_compile_errors: bool = false,
debug_pkg_config: bool = false,
/// Number of stack frames captured when a `StackTrace` is recorded for debug purposes,
/// in particular at `Step` creation.
/// Set to 0 to disable stack collection.
debug_stack_frames_count: u8 = 8,

/// Experimental. Use system Darling installation to run cross compiled macOS build artifacts.
enable_darling: bool = false,
/// Use system QEMU installation to run cross compiled foreign architecture build artifacts.
enable_qemu: bool = false,
/// Darwin. Use Rosetta to run x86_64 macOS build artifacts on arm64 macOS.
enable_rosetta: bool = false,
/// Use system Wasmtime installation to run cross compiled wasm/wasi build artifacts.
enable_wasmtime: bool = false,
/// Use system Wine installation to run cross compiled Windows build artifacts.
enable_wine: bool = false,
/// After following the steps in https://github.com/ziglang/zig/wiki/Updating-libc#glibc,
/// this will be the directory $glibc-build-dir/install/glibcs
/// Given the example of the aarch64 target, this is the directory
/// that contains the path `aarch64-linux-gnu/lib/ld-linux-aarch64.so.1`.
glibc_runtimes_dir: ?[]const u8 = null,

dep_prefix: []const u8 = "",

modules: std.StringArrayHashMap(*Module),

named_writefiles: std.StringArrayHashMap(*Step.WriteFile),
named_lazy_paths: std.StringArrayHashMap(LazyPath),
/// The hash of this instance's package. `""` means that this is the root package.
pkg_hash: []const u8,
/// A mapping from dependency names to package hashes.
available_deps: AvailableDeps,

release_mode: ReleaseMode,

build_id: ?std.zig.BuildId = null,

pub const ReleaseMode = enum {
    off,
    any,
    fast,
    safe,
    small,
};

/// Shared state among all Build instances.
/// Settings that are here rather than in Build are not configurable per-package.
pub const Graph = struct {
    arena: Allocator,
    system_library_options: std.StringArrayHashMapUnmanaged(SystemLibraryMode) = .empty,
    system_package_mode: bool = false,
    debug_compiler_runtime_libs: bool = false,
    cache: Cache,
    zig_exe: [:0]const u8,
    env_map: EnvMap,
    global_cache_root: Cache.Directory,
    zig_lib_directory: Cache.Directory,
    needed_lazy_dependencies: std.StringArrayHashMapUnmanaged(void) = .empty,
    /// Information about the native target. Computed before build() is invoked.
    host: ResolvedTarget,
    incremental: ?bool = null,
    random_seed: u32 = 0,
    dependency_cache: InitializedDepMap = .empty,
    allow_so_scripts: ?bool = null,
};

const AvailableDeps = []const struct { []const u8, []const u8 };

const SystemLibraryMode = enum {
    /// User asked for the library to be disabled.
    /// The build runner has not confirmed whether the setting is recognized yet.
    user_disabled,
    /// User asked for the library to be enabled.
    /// The build runner has not confirmed whether the setting is recognized yet.
    user_enabled,
    /// The build runner has confirmed that this setting is recognized.
    /// System integration with this library has been resolved to off.
    declared_disabled,
    /// The build runner has confirmed that this setting is recognized.
    /// System integration with this library has been resolved to on.
    declared_enabled,
};

const InitializedDepMap = std.HashMapUnmanaged(InitializedDepKey, *Dependency, InitializedDepContext, std.hash_map.default_max_load_percentage);
const InitializedDepKey = struct {
    build_root_string: []const u8,
    user_input_options: UserInputOptionsMap,
};

const InitializedDepContext = struct {
    allocator: Allocator,

    pub fn hash(ctx: @This(), k: InitializedDepKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(k.build_root_string);
        hashUserInputOptionsMap(ctx.allocator, k.user_input_options, &hasher);
        return hasher.final();
    }

    pub fn eql(_: @This(), lhs: InitializedDepKey, rhs: InitializedDepKey) bool {
        if (!std.mem.eql(u8, lhs.build_root_string, rhs.build_root_string))
            return false;

        if (lhs.user_input_options.count() != rhs.user_input_options.count())
            return false;

        var it = lhs.user_input_options.iterator();
        while (it.next()) |lhs_entry| {
            const rhs_value = rhs.user_input_options.get(lhs_entry.key_ptr.*) orelse return false;
            if (!userValuesAreSame(lhs_entry.value_ptr.*.value, rhs_value.value))
                return false;
        }

        return true;
    }
};

pub const RunError = error{
    ReadFailure,
    ExitCodeFailure,
    ProcessTerminated,
    ExecNotSupported,
} || std.process.Child.SpawnError;

pub const PkgConfigError = error{
    PkgConfigCrashed,
    PkgConfigFailed,
    PkgConfigNotInstalled,
    PkgConfigInvalidOutput,
};

pub const PkgConfigPkg = struct {
    name: []const u8,
    desc: []const u8,
};

const UserInputOptionsMap = StringHashMap(UserInputOption);
const AvailableOptionsMap = StringHashMap(AvailableOption);

const AvailableOption = struct {
    name: []const u8,
    type_id: TypeId,
    description: []const u8,
    /// If the `type_id` is `enum` or `enum_list` this provides the list of enum options
    enum_options: ?[]const []const u8,
};

const UserInputOption = struct {
    name: []const u8,
    value: UserValue,
    used: bool,
};

const UserValue = union(enum) {
    flag: void,
    scalar: []const u8,
    list: ArrayList([]const u8),
    map: StringHashMap(*const UserValue),
    lazy_path: LazyPath,
    lazy_path_list: ArrayList(LazyPath),
};

const TypeId = enum {
    bool,
    int,
    float,
    @"enum",
    enum_list,
    string,
    list,
    build_id,
    lazy_path,
    lazy_path_list,
};

const TopLevelStep = struct {
    pub const base_id: Step.Id = .top_level;

    step: Step,
    description: []const u8,
};

pub const DirList = struct {
    lib_dir: ?[]const u8 = null,
    exe_dir: ?[]const u8 = null,
    include_dir: ?[]const u8 = null,
};

pub fn create(
    graph: *Graph,
    build_root: Cache.Directory,
    cache_root: Cache.Directory,
    available_deps: AvailableDeps,
) error{OutOfMemory}!*Build {
    const arena = graph.arena;

    const b = try arena.create(Build);
    b.* = .{
        .graph = graph,
        .build_root = build_root,
        .cache_root = cache_root,
        .verbose = false,
        .verbose_link = false,
        .verbose_cc = false,
        .verbose_air = false,
        .verbose_llvm_ir = null,
        .verbose_llvm_bc = null,
        .verbose_cimport = false,
        .verbose_llvm_cpu_features = false,
        .invalid_user_input = false,
        .allocator = arena,
        .user_input_options = UserInputOptionsMap.init(arena),
        .available_options_map = AvailableOptionsMap.init(arena),
        .available_options_list = ArrayList(AvailableOption).init(arena),
        .top_level_steps = .{},
        .default_step = undefined,
        .search_prefixes = .{},
        .install_prefix = undefined,
        .lib_dir = undefined,
        .exe_dir = undefined,
        .h_dir = undefined,
        .dest_dir = graph.env_map.get("DESTDIR"),
        .install_tls = .{
            .step = Step.init(.{
                .id = TopLevelStep.base_id,
                .name = "install",
                .owner = b,
            }),
            .description = "Copy build artifacts to prefix path",
        },
        .uninstall_tls = .{
            .step = Step.init(.{
                .id = TopLevelStep.base_id,
                .name = "uninstall",
                .owner = b,
                .makeFn = makeUninstall,
            }),
            .description = "Remove build artifacts from prefix path",
        },
        .install_path = undefined,
        .args = null,
        .modules = .init(arena),
        .named_writefiles = .init(arena),
        .named_lazy_paths = .init(arena),
        .pkg_hash = "",
        .available_deps = available_deps,
        .release_mode = .off,
    };
    try b.top_level_steps.put(arena, b.install_tls.step.name, &b.install_tls);
    try b.top_level_steps.put(arena, b.uninstall_tls.step.name, &b.uninstall_tls);
    b.default_step = &b.install_tls.step;
    return b;
}

fn createChild(
    parent: *Build,
    dep_name: []const u8,
    build_root: Cache.Directory,
    pkg_hash: []const u8,
    pkg_deps: AvailableDeps,
    user_input_options: UserInputOptionsMap,
) error{OutOfMemory}!*Build {
    const child = try createChildOnly(parent, dep_name, build_root, pkg_hash, pkg_deps, user_input_options);
    try determineAndApplyInstallPrefix(child);
    return child;
}

fn createChildOnly(
    parent: *Build,
    dep_name: []const u8,
    build_root: Cache.Directory,
    pkg_hash: []const u8,
    pkg_deps: AvailableDeps,
    user_input_options: UserInputOptionsMap,
) error{OutOfMemory}!*Build {
    const allocator = parent.allocator;
    const child = try allocator.create(Build);
    child.* = .{
        .graph = parent.graph,
        .allocator = allocator,
        .install_tls = .{
            .step = Step.init(.{
                .id = TopLevelStep.base_id,
                .name = "install",
                .owner = child,
            }),
            .description = "Copy build artifacts to prefix path",
        },
        .uninstall_tls = .{
            .step = Step.init(.{
                .id = TopLevelStep.base_id,
                .name = "uninstall",
                .owner = child,
                .makeFn = makeUninstall,
            }),
            .description = "Remove build artifacts from prefix path",
        },
        .user_input_options = user_input_options,
        .available_options_map = AvailableOptionsMap.init(allocator),
        .available_options_list = ArrayList(AvailableOption).init(allocator),
        .verbose = parent.verbose,
        .verbose_link = parent.verbose_link,
        .verbose_cc = parent.verbose_cc,
        .verbose_air = parent.verbose_air,
        .verbose_llvm_ir = parent.verbose_llvm_ir,
        .verbose_llvm_bc = parent.verbose_llvm_bc,
        .verbose_cimport = parent.verbose_cimport,
        .verbose_llvm_cpu_features = parent.verbose_llvm_cpu_features,
        .reference_trace = parent.reference_trace,
        .invalid_user_input = false,
        .default_step = undefined,
        .top_level_steps = .{},
        .install_prefix = undefined,
        .dest_dir = parent.dest_dir,
        .lib_dir = parent.lib_dir,
        .exe_dir = parent.exe_dir,
        .h_dir = parent.h_dir,
        .install_path = parent.install_path,
        .sysroot = parent.sysroot,
        .search_prefixes = parent.search_prefixes,
        .libc_file = parent.libc_file,
        .build_root = build_root,
        .cache_root = parent.cache_root,
        .debug_log_scopes = parent.debug_log_scopes,
        .debug_compile_errors = parent.debug_compile_errors,
        .debug_pkg_config = parent.debug_pkg_config,
        .enable_darling = parent.enable_darling,
        .enable_qemu = parent.enable_qemu,
        .enable_rosetta = parent.enable_rosetta,
        .enable_wasmtime = parent.enable_wasmtime,
        .enable_wine = parent.enable_wine,
        .glibc_runtimes_dir = parent.glibc_runtimes_dir,
        .dep_prefix = parent.fmt("{s}{s}.", .{ parent.dep_prefix, dep_name }),
        .modules = .init(allocator),
        .named_writefiles = .init(allocator),
        .named_lazy_paths = .init(allocator),
        .pkg_hash = pkg_hash,
        .available_deps = pkg_deps,
        .release_mode = parent.release_mode,
    };
    try child.top_level_steps.put(allocator, child.install_tls.step.name, &child.install_tls);
    try child.top_level_steps.put(allocator, child.uninstall_tls.step.name, &child.uninstall_tls);
    child.default_step = &child.install_tls.step;
    return child;
}

fn userInputOptionsFromArgs(allocator: Allocator, args: anytype) UserInputOptionsMap {
    var user_input_options = UserInputOptionsMap.init(allocator);
    inline for (@typeInfo(@TypeOf(args)).@"struct".fields) |field| {
        const v = @field(args, field.name);
        const T = @TypeOf(v);
        switch (T) {
            Target.Query => {
                user_input_options.put(field.name, .{
                    .name = field.name,
                    .value = .{ .scalar = v.zigTriple(allocator) catch @panic("OOM") },
                    .used = false,
                }) catch @panic("OOM");
                user_input_options.put("cpu", .{
                    .name = "cpu",
                    .value = .{ .scalar = v.serializeCpuAlloc(allocator) catch @panic("OOM") },
                    .used = false,
                }) catch @panic("OOM");
            },
            ResolvedTarget => {
                user_input_options.put(field.name, .{
                    .name = field.name,
                    .value = .{ .scalar = v.query.zigTriple(allocator) catch @panic("OOM") },
                    .used = false,
                }) catch @panic("OOM");
                user_input_options.put("cpu", .{
                    .name = "cpu",
                    .value = .{ .scalar = v.query.serializeCpuAlloc(allocator) catch @panic("OOM") },
                    .used = false,
                }) catch @panic("OOM");
            },
            LazyPath => {
                user_input_options.put(field.name, .{
                    .name = field.name,
                    .value = .{ .lazy_path = v.dupeInner(allocator) },
                    .used = false,
                }) catch @panic("OOM");
            },
            []const LazyPath => {
                var list = ArrayList(LazyPath).initCapacity(allocator, v.len) catch @panic("OOM");
                for (v) |lp| list.appendAssumeCapacity(lp.dupeInner(allocator));
                user_input_options.put(field.name, .{
                    .name = field.name,
                    .value = .{ .lazy_path_list = list },
                    .used = false,
                }) catch @panic("OOM");
            },
            []const u8 => {
                user_input_options.put(field.name, .{
                    .name = field.name,
                    .value = .{ .scalar = v },
                    .used = false,
                }) catch @panic("OOM");
            },
            []const []const u8 => {
                var list = ArrayList([]const u8).initCapacity(allocator, v.len) catch @panic("OOM");
                list.appendSliceAssumeCapacity(v);

                user_input_options.put(field.name, .{
                    .name = field.name,
                    .value = .{ .list = list },
                    .used = false,
                }) catch @panic("OOM");
            },
            else => switch (@typeInfo(T)) {
                .bool => {
                    user_input_options.put(field.name, .{
                        .name = field.name,
                        .value = .{ .scalar = if (v) "true" else "false" },
                        .used = false,
                    }) catch @panic("OOM");
                },
                .@"enum", .enum_literal => {
                    user_input_options.put(field.name, .{
                        .name = field.name,
                        .value = .{ .scalar = @tagName(v) },
                        .used = false,
                    }) catch @panic("OOM");
                },
                .comptime_int, .int => {
                    user_input_options.put(field.name, .{
                        .name = field.name,
                        .value = .{ .scalar = std.fmt.allocPrint(allocator, "{d}", .{v}) catch @panic("OOM") },
                        .used = false,
                    }) catch @panic("OOM");
                },
                .comptime_float, .float => {
                    user_input_options.put(field.name, .{
                        .name = field.name,
                        .value = .{ .scalar = std.fmt.allocPrint(allocator, "{e}", .{v}) catch @panic("OOM") },
                        .used = false,
                    }) catch @panic("OOM");
                },
                else => @compileError("option '" ++ field.name ++ "' has unsupported type: " ++ @typeName(T)),
            },
        }
    }

    return user_input_options;
}

const OrderedUserValue = union(enum) {
    flag: void,
    scalar: []const u8,
    list: ArrayList([]const u8),
    map: ArrayList(Pair),
    lazy_path: LazyPath,
    lazy_path_list: ArrayList(LazyPath),

    const Pair = struct {
        name: []const u8,
        value: OrderedUserValue,
        fn lessThan(_: void, lhs: Pair, rhs: Pair) bool {
            return std.ascii.lessThanIgnoreCase(lhs.name, rhs.name);
        }
    };

    fn hash(val: OrderedUserValue, hasher: *std.hash.Wyhash) void {
        hasher.update(&std.mem.toBytes(std.meta.activeTag(val)));
        switch (val) {
            .flag => {},
            .scalar => |scalar| hasher.update(scalar),
            // lists are already ordered
            .list => |list| for (list.items) |list_entry|
                hasher.update(list_entry),
            .map => |map| for (map.items) |map_entry| {
                hasher.update(map_entry.name);
                map_entry.value.hash(hasher);
            },
            .lazy_path => |lp| hashLazyPath(lp, hasher),
            .lazy_path_list => |lp_list| for (lp_list.items) |lp| {
                hashLazyPath(lp, hasher);
            },
        }
    }

    fn hashLazyPath(lp: LazyPath, hasher: *std.hash.Wyhash) void {
        switch (lp) {
            .src_path => |sp| {
                hasher.update(sp.owner.pkg_hash);
                hasher.update(sp.sub_path);
            },
            .generated => |gen| {
                hasher.update(gen.file.step.owner.pkg_hash);
                hasher.update(std.mem.asBytes(&gen.up));
                hasher.update(gen.sub_path);
            },
            .cwd_relative => |rel_path| {
                hasher.update(rel_path);
            },
            .dependency => |dep| {
                hasher.update(dep.dependency.builder.pkg_hash);
                hasher.update(dep.sub_path);
            },
        }
    }

    fn mapFromUnordered(allocator: Allocator, unordered: std.StringHashMap(*const UserValue)) ArrayList(Pair) {
        var ordered = ArrayList(Pair).init(allocator);
        var it = unordered.iterator();
        while (it.next()) |entry| {
            ordered.append(.{
                .name = entry.key_ptr.*,
                .value = OrderedUserValue.fromUnordered(allocator, entry.value_ptr.*.*),
            }) catch @panic("OOM");
        }

        std.mem.sortUnstable(Pair, ordered.items, {}, Pair.lessThan);
        return ordered;
    }

    fn fromUnordered(allocator: Allocator, unordered: UserValue) OrderedUserValue {
        return switch (unordered) {
            .flag => .{ .flag = {} },
            .scalar => |scalar| .{ .scalar = scalar },
            .list => |list| .{ .list = list },
            .map => |map| .{ .map = OrderedUserValue.mapFromUnordered(allocator, map) },
            .lazy_path => |lp| .{ .lazy_path = lp },
            .lazy_path_list => |list| .{ .lazy_path_list = list },
        };
    }
};

const OrderedUserInputOption = struct {
    name: []const u8,
    value: OrderedUserValue,
    used: bool,

    fn hash(opt: OrderedUserInputOption, hasher: *std.hash.Wyhash) void {
        hasher.update(opt.name);
        opt.value.hash(hasher);
    }

    fn fromUnordered(allocator: Allocator, user_input_option: UserInputOption) OrderedUserInputOption {
        return OrderedUserInputOption{
            .name = user_input_option.name,
            .used = user_input_option.used,
            .value = OrderedUserValue.fromUnordered(allocator, user_input_option.value),
        };
    }

    fn lessThan(_: void, lhs: OrderedUserInputOption, rhs: OrderedUserInputOption) bool {
        return std.ascii.lessThanIgnoreCase(lhs.name, rhs.name);
    }
};

// The hash should be consistent with the same values given a different order.
// This function takes a user input map, orders it, then hashes the contents.
fn hashUserInputOptionsMap(allocator: Allocator, user_input_options: UserInputOptionsMap, hasher: *std.hash.Wyhash) void {
    var ordered = ArrayList(OrderedUserInputOption).init(allocator);
    var it = user_input_options.iterator();
    while (it.next()) |entry|
        ordered.append(OrderedUserInputOption.fromUnordered(allocator, entry.value_ptr.*)) catch @panic("OOM");

    std.mem.sortUnstable(OrderedUserInputOption, ordered.items, {}, OrderedUserInputOption.lessThan);

    // juice it
    for (ordered.items) |user_option|
        user_option.hash(hasher);
}

fn determineAndApplyInstallPrefix(b: *Build) error{OutOfMemory}!void {
    // Create an installation directory local to this package. This will be used when
    // dependant packages require a standard prefix, such as include directories for C headers.
    var hash = b.graph.cache.hash;
    // Random bytes to make unique. Refresh this with new random bytes when
    // implementation is modified in a non-backwards-compatible way.
    hash.add(@as(u32, 0xd8cb0055));
    hash.addBytes(b.dep_prefix);

    var wyhash = std.hash.Wyhash.init(0);
    hashUserInputOptionsMap(b.allocator, b.user_input_options, &wyhash);
    hash.add(wyhash.final());

    const digest = hash.final();
    const install_prefix = try b.cache_root.join(b.allocator, &.{ "i", &digest });
    b.resolveInstallPrefix(install_prefix, .{});
}

/// This function is intended to be called by lib/build_runner.zig, not a build.zig file.
pub fn resolveInstallPrefix(b: *Build, install_prefix: ?[]const u8, dir_list: DirList) void {
    if (b.dest_dir) |dest_dir| {
        b.install_prefix = install_prefix orelse "/usr";
        b.install_path = b.pathJoin(&.{ dest_dir, b.install_prefix });
    } else {
        b.install_prefix = install_prefix orelse
            (b.build_root.join(b.allocator, &.{"zig-out"}) catch @panic("unhandled error"));
        b.install_path = b.install_prefix;
    }

    var lib_list = [_][]const u8{ b.install_path, "lib" };
    var exe_list = [_][]const u8{ b.install_path, "bin" };
    var h_list = [_][]const u8{ b.install_path, "include" };

    if (dir_list.lib_dir) |dir| {
        if (fs.path.isAbsolute(dir)) lib_list[0] = b.dest_dir orelse "";
        lib_list[1] = dir;
    }

    if (dir_list.exe_dir) |dir| {
        if (fs.path.isAbsolute(dir)) exe_list[0] = b.dest_dir orelse "";
        exe_list[1] = dir;
    }

    if (dir_list.include_dir) |dir| {
        if (fs.path.isAbsolute(dir)) h_list[0] = b.dest_dir orelse "";
        h_list[1] = dir;
    }

    b.lib_dir = b.pathJoin(&lib_list);
    b.exe_dir = b.pathJoin(&exe_list);
    b.h_dir = b.pathJoin(&h_list);
}

/// Create a set of key-value pairs that can be converted into a Zig source
/// file and then inserted into a Zig compilation's module table for importing.
/// In other words, this provides a way to expose build.zig values to Zig
/// source code with `@import`.
/// Related: `Module.addOptions`.
pub fn addOptions(b: *Build) *Step.Options {
    return Step.Options.create(b);
}

pub const ExecutableOptions = struct {
    name: []const u8,
    version: ?std.SemanticVersion = null,
    linkage: ?std.builtin.LinkMode = null,
    max_rss: usize = 0,
    use_llvm: ?bool = null,
    use_lld: ?bool = null,
    zig_lib_dir: ?LazyPath = null,
    /// Embed a `.manifest` file in the compilation if the object format supports it.
    /// https://learn.microsoft.com/en-us/windows/win32/sbscs/manifest-files-reference
    /// Manifest files must have the extension `.manifest`.
    /// Can be set regardless of target. The `.manifest` file will be ignored
    /// if the target object format does not support embedded manifests.
    win32_manifest: ?LazyPath = null,

    /// Prefer populating this field (using e.g. `createModule`) instead of populating
    /// the following fields (`root_source_file` etc). In a future release, those fields
    /// will be removed, and this field will become non-optional.
    root_module: ?*Module = null,

    /// Deprecated; prefer populating `root_module`.
    root_source_file: ?LazyPath = null,
    /// Deprecated; prefer populating `root_module`.
    target: ?ResolvedTarget = null,
    /// Deprecated; prefer populating `root_module`.
    optimize: std.builtin.OptimizeMode = .Debug,
    /// Deprecated; prefer populating `root_module`.
    code_model: std.builtin.CodeModel = .default,
    /// Deprecated; prefer populating `root_module`.
    link_libc: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    single_threaded: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    pic: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    strip: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    unwind_tables: ?std.builtin.UnwindTables = null,
    /// Deprecated; prefer populating `root_module`.
    omit_frame_pointer: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    sanitize_thread: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    error_tracing: ?bool = null,
};

pub fn addExecutable(b: *Build, options: ExecutableOptions) *Step.Compile {
    if (options.root_module != null and options.target != null) {
        @panic("`root_module` and `target` cannot both be populated");
    }
    return .create(b, .{
        .name = options.name,
        .root_module = options.root_module orelse b.createModule(.{
            .root_source_file = options.root_source_file,
            .target = options.target orelse @panic("`root_module` and `target` cannot both be null"),
            .optimize = options.optimize,
            .link_libc = options.link_libc,
            .single_threaded = options.single_threaded,
            .pic = options.pic,
            .strip = options.strip,
            .unwind_tables = options.unwind_tables,
            .omit_frame_pointer = options.omit_frame_pointer,
            .sanitize_thread = options.sanitize_thread,
            .error_tracing = options.error_tracing,
            .code_model = options.code_model,
        }),
        .version = options.version,
        .kind = .exe,
        .linkage = options.linkage,
        .max_rss = options.max_rss,
        .use_llvm = options.use_llvm,
        .use_lld = options.use_lld,
        .zig_lib_dir = options.zig_lib_dir,
        .win32_manifest = options.win32_manifest,
    });
}

pub const ObjectOptions = struct {
    name: []const u8,
    max_rss: usize = 0,
    use_llvm: ?bool = null,
    use_lld: ?bool = null,
    zig_lib_dir: ?LazyPath = null,

    /// Prefer populating this field (using e.g. `createModule`) instead of populating
    /// the following fields (`root_source_file` etc). In a future release, those fields
    /// will be removed, and this field will become non-optional.
    root_module: ?*Module = null,

    /// Deprecated; prefer populating `root_module`.
    root_source_file: ?LazyPath = null,
    /// Deprecated; prefer populating `root_module`.
    target: ?ResolvedTarget = null,
    /// Deprecated; prefer populating `root_module`.
    optimize: std.builtin.OptimizeMode = .Debug,
    /// Deprecated; prefer populating `root_module`.
    code_model: std.builtin.CodeModel = .default,
    /// Deprecated; prefer populating `root_module`.
    link_libc: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    single_threaded: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    pic: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    strip: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    unwind_tables: ?std.builtin.UnwindTables = null,
    /// Deprecated; prefer populating `root_module`.
    omit_frame_pointer: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    sanitize_thread: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    error_tracing: ?bool = null,
};

pub fn addObject(b: *Build, options: ObjectOptions) *Step.Compile {
    if (options.root_module != null and options.target != null) {
        @panic("`root_module` and `target` cannot both be populated");
    }
    return .create(b, .{
        .name = options.name,
        .root_module = options.root_module orelse b.createModule(.{
            .root_source_file = options.root_source_file,
            .target = options.target orelse @panic("`root_module` and `target` cannot both be null"),
            .optimize = options.optimize,
            .link_libc = options.link_libc,
            .single_threaded = options.single_threaded,
            .pic = options.pic,
            .strip = options.strip,
            .unwind_tables = options.unwind_tables,
            .omit_frame_pointer = options.omit_frame_pointer,
            .sanitize_thread = options.sanitize_thread,
            .error_tracing = options.error_tracing,
            .code_model = options.code_model,
        }),
        .kind = .obj,
        .max_rss = options.max_rss,
        .use_llvm = options.use_llvm,
        .use_lld = options.use_lld,
        .zig_lib_dir = options.zig_lib_dir,
    });
}

pub const SharedLibraryOptions = struct {
    name: []const u8,
    version: ?std.SemanticVersion = null,
    max_rss: usize = 0,
    use_llvm: ?bool = null,
    use_lld: ?bool = null,
    zig_lib_dir: ?LazyPath = null,
    /// Embed a `.manifest` file in the compilation if the object format supports it.
    /// https://learn.microsoft.com/en-us/windows/win32/sbscs/manifest-files-reference
    /// Manifest files must have the extension `.manifest`.
    /// Can be set regardless of target. The `.manifest` file will be ignored
    /// if the target object format does not support embedded manifests.
    win32_manifest: ?LazyPath = null,

    /// Prefer populating this field (using e.g. `createModule`) instead of populating
    /// the following fields (`root_source_file` etc). In a future release, those fields
    /// will be removed, and this field will become non-optional.
    root_module: ?*Module = null,

    /// Deprecated; prefer populating `root_module`.
    root_source_file: ?LazyPath = null,
    /// Deprecated; prefer populating `root_module`.
    target: ?ResolvedTarget = null,
    /// Deprecated; prefer populating `root_module`.
    optimize: std.builtin.OptimizeMode = .Debug,
    /// Deprecated; prefer populating `root_module`.
    code_model: std.builtin.CodeModel = .default,
    /// Deprecated; prefer populating `root_module`.
    link_libc: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    single_threaded: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    pic: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    strip: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    unwind_tables: ?std.builtin.UnwindTables = null,
    /// Deprecated; prefer populating `root_module`.
    omit_frame_pointer: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    sanitize_thread: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    error_tracing: ?bool = null,
};

/// Deprecated: use `b.addLibrary(.{ ..., .linkage = .dynamic })` instead.
pub fn addSharedLibrary(b: *Build, options: SharedLibraryOptions) *Step.Compile {
    if (options.root_module != null and options.target != null) {
        @panic("`root_module` and `target` cannot both be populated");
    }
    return .create(b, .{
        .name = options.name,
        .root_module = options.root_module orelse b.createModule(.{
            .target = options.target orelse @panic("`root_module` and `target` cannot both be null"),
            .optimize = options.optimize,
            .root_source_file = options.root_source_file,
            .link_libc = options.link_libc,
            .single_threaded = options.single_threaded,
            .pic = options.pic,
            .strip = options.strip,
            .unwind_tables = options.unwind_tables,
            .omit_frame_pointer = options.omit_frame_pointer,
            .sanitize_thread = options.sanitize_thread,
            .error_tracing = options.error_tracing,
            .code_model = options.code_model,
        }),
        .kind = .lib,
        .linkage = .dynamic,
        .version = options.version,
        .max_rss = options.max_rss,
        .use_llvm = options.use_llvm,
        .use_lld = options.use_lld,
        .zig_lib_dir = options.zig_lib_dir,
        .win32_manifest = options.win32_manifest,
    });
}

pub const StaticLibraryOptions = struct {
    name: []const u8,
    version: ?std.SemanticVersion = null,
    max_rss: usize = 0,
    use_llvm: ?bool = null,
    use_lld: ?bool = null,
    zig_lib_dir: ?LazyPath = null,

    /// Prefer populating this field (using e.g. `createModule`) instead of populating
    /// the following fields (`root_source_file` etc). In a future release, those fields
    /// will be removed, and this field will become non-optional.
    root_module: ?*Module = null,

    /// Deprecated; prefer populating `root_module`.
    root_source_file: ?LazyPath = null,
    /// Deprecated; prefer populating `root_module`.
    target: ?ResolvedTarget = null,
    /// Deprecated; prefer populating `root_module`.
    optimize: std.builtin.OptimizeMode = .Debug,
    /// Deprecated; prefer populating `root_module`.
    code_model: std.builtin.CodeModel = .default,
    /// Deprecated; prefer populating `root_module`.
    link_libc: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    single_threaded: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    pic: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    strip: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    unwind_tables: ?std.builtin.UnwindTables = null,
    /// Deprecated; prefer populating `root_module`.
    omit_frame_pointer: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    sanitize_thread: ?bool = null,
    /// Deprecated; prefer populating `root_module`.
    error_tracing: ?bool = null,
};

/// Deprecated: use `b.addLibrary(.{ ..., .linkage = .static })` instead.
pub fn addStaticLibrary(b: *Build, options: StaticLibraryOptions) *Step.Compile {
    if (options.root_module != null and options.target != null) {
        @panic("`root_module` and `target` cannot both be populated");
    }
    return .create(b, .{
        .name = options.name,
        .root_module = options.root_module orelse b.createModule(.{
            .target = options.target orelse @panic("`root_module` and `target` cannot both be null"),
            .optimize = options.optimize,
            .root_source_file = options.root_source_file,
            .link_libc = options.link_libc,
            .single_threaded = options.single_threaded,
            .pic = options.pic,
            .strip = options.strip,
            .unwind_tables = options.unwind_tables,
            .omit_frame_pointer = options.omit_frame_pointer,
            .sanitize_thread = options.sanitize_thread,
            .error_tracing = options.error_tracing,
            .code_model = options.code_model,
        }),
        .kind = .lib,
        .linkage = .static,
        .version = options.version,
        .max_rss = options.max_rss,
        .use_llvm = options.use_llvm,
        .use_lld = options.use_lld,
        .zig_lib_dir = options.zig_lib_dir,
    });
}

pub const LibraryOptions = struct {
    linkage: std.builtin.LinkMode = .static,
    name: []const u8,
    root_module: *Module,
    version: ?std.SemanticVersion = null,
    max_rss: usize = 0,
    use_llvm: ?bool = null,
    use_lld: ?bool = null,
    zig_lib_dir: ?LazyPath = null,
    /// Embed a `.manifest` file in the compilation if the object format supports it.
    /// https://learn.microsoft.com/en-us/windows/win32/sbscs/manifest-files-reference
    /// Manifest files must have the extension `.manifest`.
    /// Can be set regardless of target. The `.manifest` file will be ignored
    /// if the target object format does not support embedded manifests.
    win32_manifest: ?LazyPath = null,
};

pub fn addLibrary(b: *Build, options: LibraryOptions) *Step.Compile {
    return .create(b, .{
        .name = options.name,
        .root_module = options.root_module,
        .kind = .lib,
        .linkage = options.linkage,
        .version = options.version,
        .max_rss = options.max_rss,
        .use_llvm = options.use_llvm,
        .use_lld = options.use_lld,
        .zig_lib_dir = options.zig_lib_dir,
        .win32_manifest = options.win32_manifest,
    });
}

pub const TestOptions = struct {
    name: []const u8 = "test",
    max_rss: usize = 0,
    /// Deprecated; use `.filters = &.{filter}` instead of `.filter = filter`.
    filter: ?[]const u8 = null,
    filters: []const []const u8 = &.{},
    test_runner: ?Step.Compile.TestRunner = null,
    use_llvm: ?bool = null,
    use_lld: ?bool = null,
    zig_lib_dir: ?LazyPath = null,
    /// Emits an object file instead of a test binary.
    /// The object must be linked separately.
    /// Usually used in conjunction with a custom `test_runner`.
 ```
