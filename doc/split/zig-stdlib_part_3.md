```
a = testing.allocator;
    {
        var orig_list = ArrayList(u8).init(a);
        defer orig_list.deinit();
        try orig_list.appendSlice("foobar");

        const sentinel_slice = try orig_list.toOwnedSliceSentinel(0);
        var list = ArrayList(u8).fromOwnedSliceSentinel(a, 0, sentinel_slice);
        defer list.deinit();
        try testing.expectEqualStrings(list.items, "foobar");
    }
    {
        var list = ArrayList(u8).init(a);
        defer list.deinit();
        try list.appendSlice("foobar");

        const sentinel_slice = try list.toOwnedSliceSentinel(0);
        var unmanaged = ArrayListUnmanaged(u8).fromOwnedSliceSentinel(0, sentinel_slice);
        defer unmanaged.deinit(a);
        try testing.expectEqualStrings(unmanaged.items, "foobar");
    }
}

test "toOwnedSliceSentinel" {
    const a = testing.allocator;
    {
        var list = ArrayList(u8).init(a);
        defer list.deinit();

        try list.appendSlice("foobar");

        const result = try list.toOwnedSliceSentinel(0);
        defer a.free(result);
        try testing.expectEqualStrings(result, mem.sliceTo(result.ptr, 0));
    }
    {
        var list: ArrayListUnmanaged(u8) = .empty;
        defer list.deinit(a);

        try list.appendSlice(a, "foobar");

        const result = try list.toOwnedSliceSentinel(a, 0);
        defer a.free(result);
        try testing.expectEqualStrings(result, mem.sliceTo(result.ptr, 0));
    }
}

test "accepts unaligned slices" {
    const a = testing.allocator;
    {
        var list = std.ArrayListAligned(u8, .@"8").init(a);
        defer list.deinit();

        try list.appendSlice(&.{ 0, 1, 2, 3 });
        try list.insertSlice(2, &.{ 4, 5, 6, 7 });
        try list.replaceRange(1, 3, &.{ 8, 9 });

        try testing.expectEqualSlices(u8, list.items, &.{ 0, 8, 9, 6, 7, 2, 3 });
    }
    {
        var list: std.ArrayListAlignedUnmanaged(u8, .@"8") = .empty;
        defer list.deinit(a);

        try list.appendSlice(a, &.{ 0, 1, 2, 3 });
        try list.insertSlice(a, 2, &.{ 4, 5, 6, 7 });
        try list.replaceRange(a, 1, 3, &.{ 8, 9 });

        try testing.expectEqualSlices(u8, list.items, &.{ 0, 8, 9, 6, 7, 2, 3 });
    }
}

test "ArrayList(u0)" {
    // An ArrayList on zero-sized types should not need to allocate
    const a = testing.failing_allocator;

    var list = ArrayList(u0).init(a);
    defer list.deinit();

    try list.append(0);
    try list.append(0);
    try list.append(0);
    try testing.expectEqual(list.items.len, 3);

    var count: usize = 0;
    for (list.items) |x| {
        try testing.expectEqual(x, 0);
        count += 1;
    }
    try testing.expectEqual(count, 3);
}

test "ArrayList(?u32).pop()" {
    const a = testing.allocator;

    var list = ArrayList(?u32).init(a);
    defer list.deinit();

    try list.append(null);
    try list.append(1);
    try list.append(2);
    try testing.expectEqual(list.items.len, 3);

    try testing.expect(list.pop().? == @as(u32, 2));
    try testing.expect(list.pop().? == @as(u32, 1));
    try testing.expect(list.pop().? == null);
    try testing.expect(list.pop() == null);
}

test "ArrayList(u32).getLast()" {
    const a = testing.allocator;

    var list = ArrayList(u32).init(a);
    defer list.deinit();

    try list.append(2);
    const const_list = list;
    try testing.expectEqual(const_list.getLast(), 2);
}

test "ArrayList(u32).getLastOrNull()" {
    const a = testing.allocator;

    var list = ArrayList(u32).init(a);
    defer list.deinit();

    try testing.expectEqual(list.getLastOrNull(), null);

    try list.append(2);
    const const_list = list;
    try testing.expectEqual(const_list.getLastOrNull().?, 2);
}

test "return OutOfMemory when capacity would exceed maximum usize integer value" {
    const a = testing.allocator;
    const new_item: u32 = 42;
    const items = &.{ 42, 43 };

    {
        var list: ArrayListUnmanaged(u32) = .{
            .items = undefined,
            .capacity = math.maxInt(usize) - 1,
        };
        list.items.len = math.maxInt(usize) - 1;

        try testing.expectError(error.OutOfMemory, list.appendSlice(a, items));
        try testing.expectError(error.OutOfMemory, list.appendNTimes(a, new_item, 2));
        try testing.expectError(error.OutOfMemory, list.appendUnalignedSlice(a, &.{ new_item, new_item }));
        try testing.expectError(error.OutOfMemory, list.addManyAt(a, 0, 2));
        try testing.expectError(error.OutOfMemory, list.addManyAsArray(a, 2));
        try testing.expectError(error.OutOfMemory, list.addManyAsSlice(a, 2));
        try testing.expectError(error.OutOfMemory, list.insertSlice(a, 0, items));
        try testing.expectError(error.OutOfMemory, list.ensureUnusedCapacity(a, 2));
    }

    {
        var list: ArrayList(u32) = .{
            .items = undefined,
            .capacity = math.maxInt(usize) - 1,
            .allocator = a,
        };
        list.items.len = math.maxInt(usize) - 1;

        try testing.expectError(error.OutOfMemory, list.appendSlice(items));
        try testing.expectError(error.OutOfMemory, list.appendNTimes(new_item, 2));
        try testing.expectError(error.OutOfMemory, list.appendUnalignedSlice(&.{ new_item, new_item }));
        try testing.expectError(error.OutOfMemory, list.addManyAt(0, 2));
        try testing.expectError(error.OutOfMemory, list.addManyAsArray(2));
        try testing.expectError(error.OutOfMemory, list.addManyAsSlice(2));
        try testing.expectError(error.OutOfMemory, list.insertSlice(0, items));
        try testing.expectError(error.OutOfMemory, list.ensureUnusedCapacity(2));
    }
}
//! The 7-bit [ASCII](https://en.wikipedia.org/wiki/ASCII) character encoding standard.
//!
//! This is not to be confused with the 8-bit [extended ASCII](https://en.wikipedia.org/wiki/Extended_ASCII) character encoding.
//!
//! Even though this module concerns itself with 7-bit ASCII,
//! functions use `u8` as the type instead of `u7` for convenience and compatibility.
//! Characters outside of the 7-bit range are gracefully handled (e.g. by returning `false`).
//!
//! See also: https://en.wikipedia.org/wiki/ASCII#Character_set

const std = @import("std");

/// The C0 control codes of the ASCII encoding.
///
/// See also: https://en.wikipedia.org/wiki/C0_and_C1_control_codes and `isControl`
pub const control_code = struct {
    /// Null.
    pub const nul = 0x00;
    /// Start of Heading.
    pub const soh = 0x01;
    /// Start of Text.
    pub const stx = 0x02;
    /// End of Text.
    pub const etx = 0x03;
    /// End of Transmission.
    pub const eot = 0x04;
    /// Enquiry.
    pub const enq = 0x05;
    /// Acknowledge.
    pub const ack = 0x06;
    /// Bell, Alert.
    pub const bel = 0x07;
    /// Backspace.
    pub const bs = 0x08;
    /// Horizontal Tab, Tab ('\t').
    pub const ht = 0x09;
    /// Line Feed, Newline ('\n').
    pub const lf = 0x0A;
    /// Vertical Tab.
    pub const vt = 0x0B;
    /// Form Feed.
    pub const ff = 0x0C;
    /// Carriage Return ('\r').
    pub const cr = 0x0D;
    /// Shift Out.
    pub const so = 0x0E;
    /// Shift In.
    pub const si = 0x0F;
    /// Data Link Escape.
    pub const dle = 0x10;
    /// Device Control One (XON).
    pub const dc1 = 0x11;
    /// Device Control Two.
    pub const dc2 = 0x12;
    /// Device Control Three (XOFF).
    pub const dc3 = 0x13;
    /// Device Control Four.
    pub const dc4 = 0x14;
    /// Negative Acknowledge.
    pub const nak = 0x15;
    /// Synchronous Idle.
    pub const syn = 0x16;
    /// End of Transmission Block
    pub const etb = 0x17;
    /// Cancel.
    pub const can = 0x18;
    /// End of Medium.
    pub const em = 0x19;
    /// Substitute.
    pub const sub = 0x1A;
    /// Escape.
    pub const esc = 0x1B;
    /// File Separator.
    pub const fs = 0x1C;
    /// Group Separator.
    pub const gs = 0x1D;
    /// Record Separator.
    pub const rs = 0x1E;
    /// Unit Separator.
    pub const us = 0x1F;

    /// Delete.
    pub const del = 0x7F;

    /// An alias to `dc1`.
    pub const xon = dc1;
    /// An alias to `dc3`.
    pub const xoff = dc3;
};

/// Returns whether the character is alphanumeric: A-Z, a-z, or 0-9.
pub fn isAlphanumeric(c: u8) bool {
    return switch (c) {
        '0'...'9', 'A'...'Z', 'a'...'z' => true,
        else => false,
    };
}

/// Returns whether the character is alphabetic: A-Z or a-z.
pub fn isAlphabetic(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z' => true,
        else => false,
    };
}

/// Returns whether the character is a control character.
///
/// See also: `control_code`
pub fn isControl(c: u8) bool {
    return c <= control_code.us or c == control_code.del;
}

/// Returns whether the character is a digit.
pub fn isDigit(c: u8) bool {
    return switch (c) {
        '0'...'9' => true,
        else => false,
    };
}

/// Returns whether the character is a lowercase letter.
pub fn isLower(c: u8) bool {
    return switch (c) {
        'a'...'z' => true,
        else => false,
    };
}

/// Returns whether the character is printable and has some graphical representation,
/// including the space character.
pub fn isPrint(c: u8) bool {
    return isAscii(c) and !isControl(c);
}

/// Returns whether this character is included in `whitespace`.
pub fn isWhitespace(c: u8) bool {
    return switch (c) {
        ' ', '\t'...'\r' => true,
        else => false,
    };
}

/// Whitespace for general use.
/// This may be used with e.g. `std.mem.trim` to trim whitespace.
///
/// See also: `isWhitespace`
pub const whitespace = [_]u8{ ' ', '\t', '\n', '\r', control_code.vt, control_code.ff };

test whitespace {
    for (whitespace) |char| try std.testing.expect(isWhitespace(char));

    var i: u8 = 0;
    while (isAscii(i)) : (i += 1) {
        if (isWhitespace(i)) try std.testing.expect(std.mem.indexOfScalar(u8, &whitespace, i) != null);
    }
}

/// Returns whether the character is an uppercase letter.
pub fn isUpper(c: u8) bool {
    return switch (c) {
        'A'...'Z' => true,
        else => false,
    };
}

/// Returns whether the character is a hexadecimal digit: A-F, a-f, or 0-9.
pub fn isHex(c: u8) bool {
    return switch (c) {
        '0'...'9', 'A'...'F', 'a'...'f' => true,
        else => false,
    };
}

/// Returns whether the character is a 7-bit ASCII character.
pub fn isAscii(c: u8) bool {
    return c < 128;
}

/// Deprecated: use `isAscii`
pub const isASCII = isAscii;

/// Uppercases the character and returns it as-is if already uppercase or not a letter.
pub fn toUpper(c: u8) u8 {
    const mask = @as(u8, @intFromBool(isLower(c))) << 5;
    return c ^ mask;
}

/// Lowercases the character and returns it as-is if already lowercase or not a letter.
pub fn toLower(c: u8) u8 {
    const mask = @as(u8, @intFromBool(isUpper(c))) << 5;
    return c | mask;
}

test "ASCII character classes" {
    const testing = std.testing;

    try testing.expect(!isControl('a'));
    try testing.expect(!isControl('z'));
    try testing.expect(!isControl(' '));
    try testing.expect(isControl(control_code.nul));
    try testing.expect(isControl(control_code.ff));
    try testing.expect(isControl(control_code.us));
    try testing.expect(isControl(control_code.del));
    try testing.expect(!isControl(0x80));
    try testing.expect(!isControl(0xff));

    try testing.expect('C' == toUpper('c'));
    try testing.expect(':' == toUpper(':'));
    try testing.expect('\xab' == toUpper('\xab'));
    try testing.expect(!isUpper('z'));
    try testing.expect(!isUpper(0x80));
    try testing.expect(!isUpper(0xff));

    try testing.expect('c' == toLower('C'));
    try testing.expect(':' == toLower(':'));
    try testing.expect('\xab' == toLower('\xab'));
    try testing.expect(!isLower('Z'));
    try testing.expect(!isLower(0x80));
    try testing.expect(!isLower(0xff));

    try testing.expect(isAlphanumeric('Z'));
    try testing.expect(isAlphanumeric('z'));
    try testing.expect(isAlphanumeric('5'));
    try testing.expect(isAlphanumeric('a'));
    try testing.expect(!isAlphanumeric('!'));
    try testing.expect(!isAlphanumeric(0x80));
    try testing.expect(!isAlphanumeric(0xff));

    try testing.expect(!isAlphabetic('5'));
    try testing.expect(isAlphabetic('c'));
    try testing.expect(!isAlphabetic('@'));
    try testing.expect(isAlphabetic('Z'));
    try testing.expect(!isAlphabetic(0x80));
    try testing.expect(!isAlphabetic(0xff));

    try testing.expect(isWhitespace(' '));
    try testing.expect(isWhitespace('\t'));
    try testing.expect(isWhitespace('\r'));
    try testing.expect(isWhitespace('\n'));
    try testing.expect(isWhitespace(control_code.ff));
    try testing.expect(!isWhitespace('.'));
    try testing.expect(!isWhitespace(control_code.us));
    try testing.expect(!isWhitespace(0x80));
    try testing.expect(!isWhitespace(0xff));

    try testing.expect(!isHex('g'));
    try testing.expect(isHex('b'));
    try testing.expect(isHex('F'));
    try testing.expect(isHex('9'));
    try testing.expect(!isHex(0x80));
    try testing.expect(!isHex(0xff));

    try testing.expect(!isDigit('~'));
    try testing.expect(isDigit('0'));
    try testing.expect(isDigit('9'));
    try testing.expect(!isDigit(0x80));
    try testing.expect(!isDigit(0xff));

    try testing.expect(isPrint(' '));
    try testing.expect(isPrint('@'));
    try testing.expect(isPrint('~'));
    try testing.expect(!isPrint(control_code.esc));
    try testing.expect(!isPrint(0x80));
    try testing.expect(!isPrint(0xff));
}

/// Writes a lower case copy of `ascii_string` to `output`.
/// Asserts `output.len >= ascii_string.len`.
pub fn lowerString(output: []u8, ascii_string: []const u8) []u8 {
    std.debug.assert(output.len >= ascii_string.len);
    for (ascii_string, 0..) |c, i| {
        output[i] = toLower(c);
    }
    return output[0..ascii_string.len];
}

test lowerString {
    var buf: [1024]u8 = undefined;
    const result = lowerString(&buf, "aBcDeFgHiJkLmNOPqrst0234+💩!");
    try std.testing.expectEqualStrings("abcdefghijklmnopqrst0234+💩!", result);
}

/// Allocates a lower case copy of `ascii_string`.
/// Caller owns returned string and must free with `allocator`.
pub fn allocLowerString(allocator: std.mem.Allocator, ascii_string: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, ascii_string.len);
    return lowerString(result, ascii_string);
}

test allocLowerString {
    const result = try allocLowerString(std.testing.allocator, "aBcDeFgHiJkLmNOPqrst0234+💩!");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("abcdefghijklmnopqrst0234+💩!", result);
}

/// Writes an upper case copy of `ascii_string` to `output`.
/// Asserts `output.len >= ascii_string.len`.
pub fn upperString(output: []u8, ascii_string: []const u8) []u8 {
    std.debug.assert(output.len >= ascii_string.len);
    for (ascii_string, 0..) |c, i| {
        output[i] = toUpper(c);
    }
    return output[0..ascii_string.len];
}

test upperString {
    var buf: [1024]u8 = undefined;
    const result = upperString(&buf, "aBcDeFgHiJkLmNOPqrst0234+💩!");
    try std.testing.expectEqualStrings("ABCDEFGHIJKLMNOPQRST0234+💩!", result);
}

/// Allocates an upper case copy of `ascii_string`.
/// Caller owns returned string and must free with `allocator`.
pub fn allocUpperString(allocator: std.mem.Allocator, ascii_string: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, ascii_string.len);
    return upperString(result, ascii_string);
}

test allocUpperString {
    const result = try allocUpperString(std.testing.allocator, "aBcDeFgHiJkLmNOPqrst0234+💩!");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("ABCDEFGHIJKLMNOPQRST0234+💩!", result);
}

/// Compares strings `a` and `b` case-insensitively and returns whether they are equal.
pub fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |a_c, i| {
        if (toLower(a_c) != toLower(b[i])) return false;
    }
    return true;
}

test eqlIgnoreCase {
    try std.testing.expect(eqlIgnoreCase("HEl💩Lo!", "hel💩lo!"));
    try std.testing.expect(!eqlIgnoreCase("hElLo!", "hello! "));
    try std.testing.expect(!eqlIgnoreCase("hElLo!", "helro!"));
}

pub fn startsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return if (needle.len > haystack.len) false else eqlIgnoreCase(haystack[0..needle.len], needle);
}

test startsWithIgnoreCase {
    try std.testing.expect(startsWithIgnoreCase("boB", "Bo"));
    try std.testing.expect(!startsWithIgnoreCase("Needle in hAyStAcK", "haystack"));
}

pub fn endsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    return if (needle.len > haystack.len) false else eqlIgnoreCase(haystack[haystack.len - needle.len ..], needle);
}

test endsWithIgnoreCase {
    try std.testing.expect(endsWithIgnoreCase("Needle in HaYsTaCk", "haystack"));
    try std.testing.expect(!endsWithIgnoreCase("BoB", "Bo"));
}

/// Finds `needle` in `haystack`, ignoring case, starting at index 0.
pub fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    return indexOfIgnoreCasePos(haystack, 0, needle);
}

/// Finds `needle` in `haystack`, ignoring case, starting at `start_index`.
/// Uses Boyer-Moore-Horspool algorithm on large inputs; `indexOfIgnoreCasePosLinear` on small inputs.
pub fn indexOfIgnoreCasePos(haystack: []const u8, start_index: usize, needle: []const u8) ?usize {
    if (needle.len > haystack.len) return null;
    if (needle.len == 0) return start_index;

    if (haystack.len < 52 or needle.len <= 4)
        return indexOfIgnoreCasePosLinear(haystack, start_index, needle);

    var skip_table: [256]usize = undefined;
    boyerMooreHorspoolPreprocessIgnoreCase(needle, skip_table[0..]);

    var i: usize = start_index;
    while (i <= haystack.len - needle.len) {
        if (eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
        i += skip_table[toLower(haystack[i + needle.len - 1])];
    }

    return null;
}

/// Consider using `indexOfIgnoreCasePos` instead of this, which will automatically use a
/// more sophisticated algorithm on larger inputs.
pub fn indexOfIgnoreCasePosLinear(haystack: []const u8, start_index: usize, needle: []const u8) ?usize {
    var i: usize = start_index;
    const end = haystack.len - needle.len;
    while (i <= end) : (i += 1) {
        if (eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

fn boyerMooreHorspoolPreprocessIgnoreCase(pattern: []const u8, table: *[256]usize) void {
    for (table) |*c| {
        c.* = pattern.len;
    }

    var i: usize = 0;
    // The last item is intentionally ignored and the skip size will be pattern.len.
    // This is the standard way Boyer-Moore-Horspool is implemented.
    while (i < pattern.len - 1) : (i += 1) {
        table[toLower(pattern[i])] = pattern.len - 1 - i;
    }
}

test indexOfIgnoreCase {
    try std.testing.expect(indexOfIgnoreCase("one Two Three Four", "foUr").? == 14);
    try std.testing.expect(indexOfIgnoreCase("one two three FouR", "gOur") == null);
    try std.testing.expect(indexOfIgnoreCase("foO", "Foo").? == 0);
    try std.testing.expect(indexOfIgnoreCase("foo", "fool") == null);
    try std.testing.expect(indexOfIgnoreCase("FOO foo", "fOo").? == 0);

    try std.testing.expect(indexOfIgnoreCase("one two three four five six seven eight nine ten eleven", "ThReE fOUr").? == 8);
    try std.testing.expect(indexOfIgnoreCase("one two three four five six seven eight nine ten eleven", "Two tWo") == null);
}

/// Returns the lexicographical order of two slices. O(n).
pub fn orderIgnoreCase(lhs: []const u8, rhs: []const u8) std.math.Order {
    const n = @min(lhs.len, rhs.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        switch (std.math.order(toLower(lhs[i]), toLower(rhs[i]))) {
            .eq => continue,
            .lt => return .lt,
            .gt => return .gt,
        }
    }
    return std.math.order(lhs.len, rhs.len);
}

/// Returns whether the lexicographical order of `lhs` is lower than `rhs`.
pub fn lessThanIgnoreCase(lhs: []const u8, rhs: []const u8) bool {
    return orderIgnoreCase(lhs, rhs) == .lt;
}
/// This is a thin wrapper around a primitive value to prevent accidental data races.
pub fn Value(comptime T: type) type {
    return extern struct {
        /// Care must be taken to avoid data races when interacting with this field directly.
        raw: T,

        const Self = @This();

        pub fn init(value: T) Self {
            return .{ .raw = value };
        }

        pub const fence = @compileError("@fence is deprecated, use other atomics to establish ordering");

        pub inline fn load(self: *const Self, comptime order: AtomicOrder) T {
            return @atomicLoad(T, &self.raw, order);
        }

        pub inline fn store(self: *Self, value: T, comptime order: AtomicOrder) void {
            @atomicStore(T, &self.raw, value, order);
        }

        pub inline fn swap(self: *Self, operand: T, comptime order: AtomicOrder) T {
            return @atomicRmw(T, &self.raw, .Xchg, operand, order);
        }

        pub inline fn cmpxchgWeak(
            self: *Self,
            expected_value: T,
            new_value: T,
            comptime success_order: AtomicOrder,
            comptime fail_order: AtomicOrder,
        ) ?T {
            return @cmpxchgWeak(T, &self.raw, expected_value, new_value, success_order, fail_order);
        }

        pub inline fn cmpxchgStrong(
            self: *Self,
            expected_value: T,
            new_value: T,
            comptime success_order: AtomicOrder,
            comptime fail_order: AtomicOrder,
        ) ?T {
            return @cmpxchgStrong(T, &self.raw, expected_value, new_value, success_order, fail_order);
        }

        pub inline fn fetchAdd(self: *Self, operand: T, comptime order: AtomicOrder) T {
            return @atomicRmw(T, &self.raw, .Add, operand, order);
        }

        pub inline fn fetchSub(self: *Self, operand: T, comptime order: AtomicOrder) T {
            return @atomicRmw(T, &self.raw, .Sub, operand, order);
        }

        pub inline fn fetchMin(self: *Self, operand: T, comptime order: AtomicOrder) T {
            return @atomicRmw(T, &self.raw, .Min, operand, order);
        }

        pub inline fn fetchMax(self: *Self, operand: T, comptime order: AtomicOrder) T {
            return @atomicRmw(T, &self.raw, .Max, operand, order);
        }

        pub inline fn fetchAnd(self: *Self, operand: T, comptime order: AtomicOrder) T {
            return @atomicRmw(T, &self.raw, .And, operand, order);
        }

        pub inline fn fetchNand(self: *Self, operand: T, comptime order: AtomicOrder) T {
            return @atomicRmw(T, &self.raw, .Nand, operand, order);
        }

        pub inline fn fetchXor(self: *Self, operand: T, comptime order: AtomicOrder) T {
            return @atomicRmw(T, &self.raw, .Xor, operand, order);
        }

        pub inline fn fetchOr(self: *Self, operand: T, comptime order: AtomicOrder) T {
            return @atomicRmw(T, &self.raw, .Or, operand, order);
        }

        pub inline fn rmw(
            self: *Self,
            comptime op: std.builtin.AtomicRmwOp,
            operand: T,
            comptime order: AtomicOrder,
        ) T {
            return @atomicRmw(T, &self.raw, op, operand, order);
        }

        const Bit = std.math.Log2Int(T);

        /// Marked `inline` so that if `bit` is comptime-known, the instruction
        /// can be lowered to a more efficient machine code instruction if
        /// possible.
        pub inline fn bitSet(self: *Self, bit: Bit, comptime order: AtomicOrder) u1 {
            const mask = @as(T, 1) << bit;
            const value = self.fetchOr(mask, order);
            return @intFromBool(value & mask != 0);
        }

        /// Marked `inline` so that if `bit` is comptime-known, the instruction
        /// can be lowered to a more efficient machine code instruction if
        /// possible.
        pub inline fn bitReset(self: *Self, bit: Bit, comptime order: AtomicOrder) u1 {
            const mask = @as(T, 1) << bit;
            const value = self.fetchAnd(~mask, order);
            return @intFromBool(value & mask != 0);
        }

        /// Marked `inline` so that if `bit` is comptime-known, the instruction
        /// can be lowered to a more efficient machine code instruction if
        /// possible.
        pub inline fn bitToggle(self: *Self, bit: Bit, comptime order: AtomicOrder) u1 {
            const mask = @as(T, 1) << bit;
            const value = self.fetchXor(mask, order);
            return @intFromBool(value & mask != 0);
        }
    };
}

test Value {
    const RefCount = struct {
        count: Value(usize),
        dropFn: *const fn (*RefCount) void,

        const RefCount = @This();

        fn ref(rc: *RefCount) void {
            // no synchronization necessary; just updating a counter.
            _ = rc.count.fetchAdd(1, .monotonic);
        }

        fn unref(rc: *RefCount) void {
            // release ensures code before unref() happens-before the
            // count is decremented as dropFn could be called by then.
            if (rc.count.fetchSub(1, .release) == 1) {
                // seeing 1 in the counter means that other unref()s have happened,
                // but it doesn't mean that uses before each unref() are visible.
                // The load acquires the release-sequence created by previous unref()s
                // in order to ensure visibility of uses before dropping.
                _ = rc.count.load(.acquire);
                (rc.dropFn)(rc);
            }
        }

        fn noop(rc: *RefCount) void {
            _ = rc;
        }
    };

    var ref_count: RefCount = .{
        .count = Value(usize).init(0),
        .dropFn = RefCount.noop,
    };
    ref_count.ref();
    ref_count.unref();
}

test "Value.swap" {
    var x = Value(usize).init(5);
    try testing.expectEqual(@as(usize, 5), x.swap(10, .seq_cst));
    try testing.expectEqual(@as(usize, 10), x.load(.seq_cst));

    const E = enum(usize) { a, b, c };
    var y = Value(E).init(.c);
    try testing.expectEqual(E.c, y.swap(.a, .seq_cst));
    try testing.expectEqual(E.a, y.load(.seq_cst));

    var z = Value(f32).init(5.0);
    try testing.expectEqual(@as(f32, 5.0), z.swap(10.0, .seq_cst));
    try testing.expectEqual(@as(f32, 10.0), z.load(.seq_cst));

    var a = Value(bool).init(false);
    try testing.expectEqual(false, a.swap(true, .seq_cst));
    try testing.expectEqual(true, a.load(.seq_cst));

    var b = Value(?*u8).init(null);
    try testing.expectEqual(@as(?*u8, null), b.swap(@as(?*u8, @ptrFromInt(@alignOf(u8))), .seq_cst));
    try testing.expectEqual(@as(?*u8, @ptrFromInt(@alignOf(u8))), b.load(.seq_cst));
}

test "Value.store" {
    var x = Value(usize).init(5);
    x.store(10, .seq_cst);
    try testing.expectEqual(@as(usize, 10), x.load(.seq_cst));
}

test "Value.cmpxchgWeak" {
    var x = Value(usize).init(0);

    try testing.expectEqual(@as(?usize, 0), x.cmpxchgWeak(1, 0, .seq_cst, .seq_cst));
    try testing.expectEqual(@as(usize, 0), x.load(.seq_cst));

    while (x.cmpxchgWeak(0, 1, .seq_cst, .seq_cst)) |_| {}
    try testing.expectEqual(@as(usize, 1), x.load(.seq_cst));

    while (x.cmpxchgWeak(1, 0, .seq_cst, .seq_cst)) |_| {}
    try testing.expectEqual(@as(usize, 0), x.load(.seq_cst));
}

test "Value.cmpxchgStrong" {
    var x = Value(usize).init(0);
    try testing.expectEqual(@as(?usize, 0), x.cmpxchgStrong(1, 0, .seq_cst, .seq_cst));
    try testing.expectEqual(@as(usize, 0), x.load(.seq_cst));
    try testing.expectEqual(@as(?usize, null), x.cmpxchgStrong(0, 1, .seq_cst, .seq_cst));
    try testing.expectEqual(@as(usize, 1), x.load(.seq_cst));
    try testing.expectEqual(@as(?usize, null), x.cmpxchgStrong(1, 0, .seq_cst, .seq_cst));
    try testing.expectEqual(@as(usize, 0), x.load(.seq_cst));
}

test "Value.fetchAdd" {
    var x = Value(usize).init(5);
    try testing.expectEqual(@as(usize, 5), x.fetchAdd(5, .seq_cst));
    try testing.expectEqual(@as(usize, 10), x.load(.seq_cst));
    try testing.expectEqual(@as(usize, 10), x.fetchAdd(std.math.maxInt(usize), .seq_cst));
    try testing.expectEqual(@as(usize, 9), x.load(.seq_cst));
}

test "Value.fetchSub" {
    var x = Value(usize).init(5);
    try testing.expectEqual(@as(usize, 5), x.fetchSub(5, .seq_cst));
    try testing.expectEqual(@as(usize, 0), x.load(.seq_cst));
    try testing.expectEqual(@as(usize, 0), x.fetchSub(1, .seq_cst));
    try testing.expectEqual(@as(usize, std.math.maxInt(usize)), x.load(.seq_cst));
}

test "Value.fetchMin" {
    var x = Value(usize).init(5);
    try testing.expectEqual(@as(usize, 5), x.fetchMin(0, .seq_cst));
    try testing.expectEqual(@as(usize, 0), x.load(.seq_cst));
    try testing.expectEqual(@as(usize, 0), x.fetchMin(10, .seq_cst));
    try testing.expectEqual(@as(usize, 0), x.load(.seq_cst));
}

test "Value.fetchMax" {
    var x = Value(usize).init(5);
    try testing.expectEqual(@as(usize, 5), x.fetchMax(10, .seq_cst));
    try testing.expectEqual(@as(usize, 10), x.load(.seq_cst));
    try testing.expectEqual(@as(usize, 10), x.fetchMax(5, .seq_cst));
    try testing.expectEqual(@as(usize, 10), x.load(.seq_cst));
}

test "Value.fetchAnd" {
    var x = Value(usize).init(0b11);
    try testing.expectEqual(@as(usize, 0b11), x.fetchAnd(0b10, .seq_cst));
    try testing.expectEqual(@as(usize, 0b10), x.load(.seq_cst));
    try testing.expectEqual(@as(usize, 0b10), x.fetchAnd(0b00, .seq_cst));
    try testing.expectEqual(@as(usize, 0b00), x.load(.seq_cst));
}

test "Value.fetchNand" {
    var x = Value(usize).init(0b11);
    try testing.expectEqual(@as(usize, 0b11), x.fetchNand(0b10, .seq_cst));
    try testing.expectEqual(~@as(usize, 0b10), x.load(.seq_cst));
    try testing.expectEqual(~@as(usize, 0b10), x.fetchNand(0b00, .seq_cst));
    try testing.expectEqual(~@as(usize, 0b00), x.load(.seq_cst));
}

test "Value.fetchOr" {
    var x = Value(usize).init(0b11);
    try testing.expectEqual(@as(usize, 0b11), x.fetchOr(0b100, .seq_cst));
    try testing.expectEqual(@as(usize, 0b111), x.load(.seq_cst));
    try testing.expectEqual(@as(usize, 0b111), x.fetchOr(0b010, .seq_cst));
    try testing.expectEqual(@as(usize, 0b111), x.load(.seq_cst));
}

test "Value.fetchXor" {
    var x = Value(usize).init(0b11);
    try testing.expectEqual(@as(usize, 0b11), x.fetchXor(0b10, .seq_cst));
    try testing.expectEqual(@as(usize, 0b01), x.load(.seq_cst));
    try testing.expectEqual(@as(usize, 0b01), x.fetchXor(0b01, .seq_cst));
    try testing.expectEqual(@as(usize, 0b00), x.load(.seq_cst));
}

test "Value.bitSet" {
    var x = Value(usize).init(0);

    for (0..@bitSizeOf(usize)) |bit_index| {
        const bit = @as(std.math.Log2Int(usize), @intCast(bit_index));
        const mask = @as(usize, 1) << bit;

        // setting the bit should change the bit
        try testing.expect(x.load(.seq_cst) & mask == 0);
        try testing.expectEqual(@as(u1, 0), x.bitSet(bit, .seq_cst));
        try testing.expect(x.load(.seq_cst) & mask != 0);

        // setting it again shouldn't change the bit
        try testing.expectEqual(@as(u1, 1), x.bitSet(bit, .seq_cst));
        try testing.expect(x.load(.seq_cst) & mask != 0);

        // all the previous bits should have not changed (still be set)
        for (0..bit_index) |prev_bit_index| {
            const prev_bit = @as(std.math.Log2Int(usize), @intCast(prev_bit_index));
            const prev_mask = @as(usize, 1) << prev_bit;
            try testing.expect(x.load(.seq_cst) & prev_mask != 0);
        }
    }
}

test "Value.bitReset" {
    var x = Value(usize).init(0);

    for (0..@bitSizeOf(usize)) |bit_index| {
        const bit = @as(std.math.Log2Int(usize), @intCast(bit_index));
        const mask = @as(usize, 1) << bit;
        x.raw |= mask;

        // unsetting the bit should change the bit
        try testing.expect(x.load(.seq_cst) & mask != 0);
        try testing.expectEqual(@as(u1, 1), x.bitReset(bit, .seq_cst));
        try testing.expect(x.load(.seq_cst) & mask == 0);

        // unsetting it again shouldn't change the bit
        try testing.expectEqual(@as(u1, 0), x.bitReset(bit, .seq_cst));
        try testing.expect(x.load(.seq_cst) & mask == 0);

        // all the previous bits should have not changed (still be reset)
        for (0..bit_index) |prev_bit_index| {
            const prev_bit = @as(std.math.Log2Int(usize), @intCast(prev_bit_index));
            const prev_mask = @as(usize, 1) << prev_bit;
            try testing.expect(x.load(.seq_cst) & prev_mask == 0);
        }
    }
}

test "Value.bitToggle" {
    var x = Value(usize).init(0);

    for (0..@bitSizeOf(usize)) |bit_index| {
        const bit = @as(std.math.Log2Int(usize), @intCast(bit_index));
        const mask = @as(usize, 1) << bit;

        // toggling the bit should change the bit
        try testing.expect(x.load(.seq_cst) & mask == 0);
        try testing.expectEqual(@as(u1, 0), x.bitToggle(bit, .seq_cst));
        try testing.expect(x.load(.seq_cst) & mask != 0);

        // toggling it again *should* change the bit
        try testing.expectEqual(@as(u1, 1), x.bitToggle(bit, .seq_cst));
        try testing.expect(x.load(.seq_cst) & mask == 0);

        // all the previous bits should have not changed (still be toggled back)
        for (0..bit_index) |prev_bit_index| {
            const prev_bit = @as(std.math.Log2Int(usize), @intCast(prev_bit_index));
            const prev_mask = @as(usize, 1) << prev_bit;
            try testing.expect(x.load(.seq_cst) & prev_mask == 0);
        }
    }
}

/// Signals to the processor that the caller is inside a busy-wait spin-loop.
pub inline fn spinLoopHint() void {
    switch (builtin.target.cpu.arch) {
        // No-op instruction that can hint to save (or share with a hardware-thread)
        // pipelining/power resources
        // https://software.intel.com/content/www/us/en/develop/articles/benefitting-power-and-performance-sleep-loops.html
        .x86,
        .x86_64,
        => asm volatile ("pause"),

        // No-op instruction that serves as a hardware-thread resource yield hint.
        // https://stackoverflow.com/a/7588941
        .powerpc,
        .powerpcle,
        .powerpc64,
        .powerpc64le,
        => asm volatile ("or 27, 27, 27"),

        // `isb` appears more reliable for releasing execution resources than `yield`
        // on common aarch64 CPUs.
        // https://bugs.java.com/bugdatabase/view_bug.do?bug_id=8258604
        // https://bugs.mysql.com/bug.php?id=100664
        .aarch64,
        .aarch64_be,
        => asm volatile ("isb"),

        // `yield` was introduced in v6k but is also available on v6m.
        // https://www.keil.com/support/man/docs/armasm/armasm_dom1361289926796.htm
        .arm,
        .armeb,
        .thumb,
        .thumbeb,
        => {
            const can_yield = comptime std.Target.arm.featureSetHasAny(builtin.target.cpu.features, .{
                .has_v6k, .has_v6m,
            });
            if (can_yield) {
                asm volatile ("yield");
            }
        },

        // The 8-bit immediate specifies the amount of cycles to pause for. We can't really be too
        // opinionated here.
        .hexagon,
        => asm volatile ("pause(#1)"),

        .riscv32,
        .riscv64,
        => if (comptime std.Target.riscv.featureSetHas(builtin.target.cpu.features, .zihintpause)) {
            asm volatile ("pause");
        },

        else => {},
    }
}

test spinLoopHint {
    for (0..10) |_| {
        spinLoopHint();
    }
}

pub fn cacheLineForCpu(cpu: std.Target.Cpu) u16 {
    return switch (cpu.arch) {
        // x86_64: Starting from Intel's Sandy Bridge, the spatial prefetcher pulls in pairs of 64-byte cache lines at a time.
        // - https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-optimization-manual.pdf
        // - https://github.com/facebook/folly/blob/1b5288e6eea6df074758f877c849b6e73bbb9fbb/folly/lang/Align.h#L107
        //
        // aarch64: Some big.LITTLE ARM archs have "big" cores with 128-byte cache lines:
        // - https://www.mono-project.com/news/2016/09/12/arm64-icache/
        // - https://cpufun.substack.com/p/more-m1-fun-hardware-information
        //
        // - https://github.com/torvalds/linux/blob/3a7e02c040b130b5545e4b115aada7bacd80a2b6/arch/arc/Kconfig#L212
        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_ppc64x.go#L9
        .x86_64,
        .aarch64,
        .aarch64_be,
        .arc,
        .powerpc64,
        .powerpc64le,
        => 128,

        // https://github.com/llvm/llvm-project/blob/e379094328e49731a606304f7e3559d4f1fa96f9/clang/lib/Basic/Targets/Hexagon.h#L145-L151
        .hexagon,
        => if (std.Target.hexagon.featureSetHas(cpu.features, .v73)) 64 else 32,

        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_arm.go#L7
        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_mips.go#L7
        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_mipsle.go#L7
        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_mips64x.go#L9
        // - https://github.com/torvalds/linux/blob/3a7e02c040b130b5545e4b115aada7bacd80a2b6/arch/sparc/include/asm/cache.h#L14
        .arm,
        .armeb,
        .thumb,
        .thumbeb,
        .mips,
        .mipsel,
        .mips64,
        .mips64el,
        .sparc,
        .sparc64,
        => 32,

        // - https://github.com/torvalds/linux/blob/3a7e02c040b130b5545e4b115aada7bacd80a2b6/arch/m68k/include/asm/cache.h#L10
        .m68k,
        => 16,

        // - https://www.ti.com/lit/pdf/slaa498
        .msp430,
        => 8,

        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_s390x.go#L7
        // - https://sxauroratsubasa.sakura.ne.jp/documents/guide/pdfs/Aurora_ISA_guide.pdf
        .s390x,
        .ve,
        => 256,

        // Other x86 and WASM platforms have 64-byte cache lines.
        // The rest of the architectures are assumed to be similar.
        // - https://github.com/golang/go/blob/dda2991c2ea0c5914714469c4defc2562a907230/src/internal/cpu/cpu_x86.go#L9
        // - https://github.com/golang/go/blob/0a9321ad7f8c91e1b0c7184731257df923977eb9/src/internal/cpu/cpu_loong64.go#L11
        // - https://github.com/golang/go/blob/3dd58676054223962cd915bb0934d1f9f489d4d2/src/internal/cpu/cpu_wasm.go#L7
        // - https://github.com/golang/go/blob/19e923182e590ae6568c2c714f20f32512aeb3e3/src/internal/cpu/cpu_riscv64.go#L7
        // - https://github.com/torvalds/linux/blob/3a7e02c040b130b5545e4b115aada7bacd80a2b6/arch/xtensa/variants/csp/include/variant/core.h#L209
        // - https://github.com/torvalds/linux/blob/3a7e02c040b130b5545e4b115aada7bacd80a2b6/arch/csky/Kconfig#L183
        // - https://www.xmos.com/download/The-XMOS-XS3-Architecture.pdf
        else => 64,
    };
}

/// The estimated size of the CPU's cache line when atomically updating memory.
/// Add this much padding or align to this boundary to avoid atomically-updated
/// memory from forcing cache invalidations on near, but non-atomic, memory.
///
/// https://en.wikipedia.org/wiki/False_sharing
/// https://github.com/golang/go/search?q=CacheLinePadSize
pub const cache_line: comptime_int = cacheLineForCpu(builtin.cpu);

test "current CPU has a cache line size" {
    _ = cache_line;
}

const std = @import("std.zig");
const builtin = @import("builtin");
const AtomicOrder = std.builtin.AtomicOrder;
const testing = std.testing;
//! Base64 encoding/decoding as specified by
//! [RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648).

const std = @import("std.zig");
const assert = std.debug.assert;
const builtin = @import("builtin");
const testing = std.testing;
const mem = std.mem;
const window = mem.window;

pub const Error = error{
    InvalidCharacter,
    InvalidPadding,
    NoSpaceLeft,
};

const decoderWithIgnoreProto = *const fn (ignore: []const u8) Base64DecoderWithIgnore;

/// Base64 codecs
pub const Codecs = struct {
    alphabet_chars: [64]u8,
    pad_char: ?u8,
    decoderWithIgnore: decoderWithIgnoreProto,
    Encoder: Base64Encoder,
    Decoder: Base64Decoder,
};

/// The Base64 alphabet defined in
/// [RFC 4648 section 4](https://datatracker.ietf.org/doc/html/rfc4648#section-4).
pub const standard_alphabet_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".*;
fn standardBase64DecoderWithIgnore(ignore: []const u8) Base64DecoderWithIgnore {
    return Base64DecoderWithIgnore.init(standard_alphabet_chars, '=', ignore);
}

/// Standard Base64 codecs, with padding, as defined in
/// [RFC 4648 section 4](https://datatracker.ietf.org/doc/html/rfc4648#section-4).
pub const standard = Codecs{
    .alphabet_chars = standard_alphabet_chars,
    .pad_char = '=',
    .decoderWithIgnore = standardBase64DecoderWithIgnore,
    .Encoder = Base64Encoder.init(standard_alphabet_chars, '='),
    .Decoder = Base64Decoder.init(standard_alphabet_chars, '='),
};

/// Standard Base64 codecs, without padding, as defined in
/// [RFC 4648 section 3.2](https://datatracker.ietf.org/doc/html/rfc4648#section-3.2).
pub const standard_no_pad = Codecs{
    .alphabet_chars = standard_alphabet_chars,
    .pad_char = null,
    .decoderWithIgnore = standardBase64DecoderWithIgnore,
    .Encoder = Base64Encoder.init(standard_alphabet_chars, null),
    .Decoder = Base64Decoder.init(standard_alphabet_chars, null),
};

/// The URL-safe Base64 alphabet defined in
/// [RFC 4648 section 5](https://datatracker.ietf.org/doc/html/rfc4648#section-5).
pub const url_safe_alphabet_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".*;
fn urlSafeBase64DecoderWithIgnore(ignore: []const u8) Base64DecoderWithIgnore {
    return Base64DecoderWithIgnore.init(url_safe_alphabet_chars, null, ignore);
}

/// URL-safe Base64 codecs, with padding, as defined in
/// [RFC 4648 section 5](https://datatracker.ietf.org/doc/html/rfc4648#section-5).
pub const url_safe = Codecs{
    .alphabet_chars = url_safe_alphabet_chars,
    .pad_char = '=',
    .decoderWithIgnore = urlSafeBase64DecoderWithIgnore,
    .Encoder = Base64Encoder.init(url_safe_alphabet_chars, '='),
    .Decoder = Base64Decoder.init(url_safe_alphabet_chars, '='),
};

/// URL-safe Base64 codecs, without padding, as defined in
/// [RFC 4648 section 3.2](https://datatracker.ietf.org/doc/html/rfc4648#section-3.2).
pub const url_safe_no_pad = Codecs{
    .alphabet_chars = url_safe_alphabet_chars,
    .pad_char = null,
    .decoderWithIgnore = urlSafeBase64DecoderWithIgnore,
    .Encoder = Base64Encoder.init(url_safe_alphabet_chars, null),
    .Decoder = Base64Decoder.init(url_safe_alphabet_chars, null),
};

pub const Base64Encoder = struct {
    alphabet_chars: [64]u8,
    pad_char: ?u8,

    /// A bunch of assertions, then simply pass the data right through.
    pub fn init(alphabet_chars: [64]u8, pad_char: ?u8) Base64Encoder {
        assert(alphabet_chars.len == 64);
        var char_in_alphabet = [_]bool{false} ** 256;
        for (alphabet_chars) |c| {
            assert(!char_in_alphabet[c]);
            assert(pad_char == null or c != pad_char.?);
            char_in_alphabet[c] = true;
        }
        return Base64Encoder{
            .alphabet_chars = alphabet_chars,
            .pad_char = pad_char,
        };
    }

    /// Compute the encoded length
    pub fn calcSize(encoder: *const Base64Encoder, source_len: usize) usize {
        if (encoder.pad_char != null) {
            return @divTrunc(source_len + 2, 3) * 4;
        } else {
            const leftover = source_len % 3;
            return @divTrunc(source_len, 3) * 4 + @divTrunc(leftover * 4 + 2, 3);
        }
    }

    // dest must be compatible with std.io.Writer's writeAll interface
    pub fn encodeWriter(encoder: *const Base64Encoder, dest: anytype, source: []const u8) !void {
        var chunker = window(u8, source, 3, 3);
        while (chunker.next()) |chunk| {
            var temp: [5]u8 = undefined;
            const s = encoder.encode(&temp, chunk);
            try dest.writeAll(s);
        }
    }

    // destWriter must be compatible with std.io.Writer's writeAll interface
    // sourceReader must be compatible with std.io.Reader's read interface
    pub fn encodeFromReaderToWriter(encoder: *const Base64Encoder, destWriter: anytype, sourceReader: anytype) !void {
        while (true) {
            var tempSource: [3]u8 = undefined;
            const bytesRead = try sourceReader.read(&tempSource);
            if (bytesRead == 0) {
                break;
            }

            var temp: [5]u8 = undefined;
            const s = encoder.encode(&temp, tempSource[0..bytesRead]);
            try destWriter.writeAll(s);
        }
    }

    /// dest.len must at least be what you get from ::calcSize.
    pub fn encode(encoder: *const Base64Encoder, dest: []u8, source: []const u8) []const u8 {
        const out_len = encoder.calcSize(source.len);
        assert(dest.len >= out_len);

        var idx: usize = 0;
        var out_idx: usize = 0;
        while (idx + 15 < source.len) : (idx += 12) {
            const bits = std.mem.readInt(u128, source[idx..][0..16], .big);
            inline for (0..16) |i| {
                dest[out_idx + i] = encoder.alphabet_chars[@truncate((bits >> (122 - i * 6)) & 0x3f)];
            }
            out_idx += 16;
        }
        while (idx + 3 < source.len) : (idx += 3) {
            const bits = std.mem.readInt(u32, source[idx..][0..4], .big);
            dest[out_idx] = encoder.alphabet_chars[(bits >> 26) & 0x3f];
            dest[out_idx + 1] = encoder.alphabet_chars[(bits >> 20) & 0x3f];
            dest[out_idx + 2] = encoder.alphabet_chars[(bits >> 14) & 0x3f];
            dest[out_idx + 3] = encoder.alphabet_chars[(bits >> 8) & 0x3f];
            out_idx += 4;
        }
        if (idx + 2 < source.len) {
            dest[out_idx] = encoder.alphabet_chars[source[idx] >> 2];
            dest[out_idx + 1] = encoder.alphabet_chars[((source[idx] & 0x3) << 4) | (source[idx + 1] >> 4)];
            dest[out_idx + 2] = encoder.alphabet_chars[(source[idx + 1] & 0xf) << 2 | (source[idx + 2] >> 6)];
            dest[out_idx + 3] = encoder.alphabet_chars[source[idx + 2] & 0x3f];
            out_idx += 4;
        } else if (idx + 1 < source.len) {
            dest[out_idx] = encoder.alphabet_chars[source[idx] >> 2];
            dest[out_idx + 1] = encoder.alphabet_chars[((source[idx] & 0x3) << 4) | (source[idx + 1] >> 4)];
            dest[out_idx + 2] = encoder.alphabet_chars[(source[idx + 1] & 0xf) << 2];
            out_idx += 3;
        } else if (idx < source.len) {
            dest[out_idx] = encoder.alphabet_chars[source[idx] >> 2];
            dest[out_idx + 1] = encoder.alphabet_chars[(source[idx] & 0x3) << 4];
            out_idx += 2;
        }
        if (encoder.pad_char) |pad_char| {
            for (dest[out_idx..out_len]) |*pad| {
                pad.* = pad_char;
            }
        }
        return dest[0..out_len];
    }
};

pub const Base64Decoder = struct {
    const invalid_char: u8 = 0xff;
    const invalid_char_tst: u32 = 0xff000000;

    /// e.g. 'A' => 0.
    /// `invalid_char` for any value not in the 64 alphabet chars.
    char_to_index: [256]u8,
    fast_char_to_index: [4][256]u32,
    pad_char: ?u8,

    pub fn init(alphabet_chars: [64]u8, pad_char: ?u8) Base64Decoder {
        var result = Base64Decoder{
            .char_to_index = [_]u8{invalid_char} ** 256,
            .fast_char_to_index = .{[_]u32{invalid_char_tst} ** 256} ** 4,
            .pad_char = pad_char,
        };

        var char_in_alphabet = [_]bool{false} ** 256;
        for (alphabet_chars, 0..) |c, i| {
            assert(!char_in_alphabet[c]);
            assert(pad_char == null or c != pad_char.?);

            const ci = @as(u32, @intCast(i));
            result.fast_char_to_index[0][c] = ci << 2;
            result.fast_char_to_index[1][c] = (ci >> 4) | ((ci & 0x0f) << 12);
            result.fast_char_to_index[2][c] = ((ci & 0x3) << 22) | ((ci & 0x3c) << 6);
            result.fast_char_to_index[3][c] = ci << 16;

            result.char_to_index[c] = @as(u8, @intCast(i));
            char_in_alphabet[c] = true;
        }
        return result;
    }

    /// Return the maximum possible decoded size for a given input length - The actual length may be less if the input includes padding.
    /// `InvalidPadding` is returned if the input length is not valid.
    pub fn calcSizeUpperBound(decoder: *const Base64Decoder, source_len: usize) Error!usize {
        var result = source_len / 4 * 3;
        const leftover = source_len % 4;
        if (decoder.pad_char != null) {
            if (leftover % 4 != 0) return error.InvalidPadding;
        } else {
            if (leftover % 4 == 1) return error.InvalidPadding;
            result += leftover * 3 / 4;
        }
        return result;
    }

    /// Return the exact decoded size for a slice.
    /// `InvalidPadding` is returned if the input length is not valid.
    pub fn calcSizeForSlice(decoder: *const Base64Decoder, source: []const u8) Error!usize {
        const source_len = source.len;
        var result = try decoder.calcSizeUpperBound(source_len);
        if (decoder.pad_char) |pad_char| {
            if (source_len >= 1 and source[source_len - 1] == pad_char) result -= 1;
            if (source_len >= 2 and source[source_len - 2] == pad_char) result -= 1;
        }
        return result;
    }

    /// dest.len must be what you get from ::calcSize.
    /// Invalid characters result in `error.InvalidCharacter`.
    /// Invalid padding results in `error.InvalidPadding`.
    pub fn decode(decoder: *const Base64Decoder, dest: []u8, source: []const u8) Error!void {
        if (decoder.pad_char != null and source.len % 4 != 0) return error.InvalidPadding;
        var dest_idx: usize = 0;
        var fast_src_idx: usize = 0;
        var acc: u12 = 0;
        var acc_len: u4 = 0;
        var leftover_idx: ?usize = null;
        while (fast_src_idx + 16 < source.len and dest_idx + 15 < dest.len) : ({
            fast_src_idx += 16;
            dest_idx += 12;
        }) {
            var bits: u128 = 0;
            inline for (0..4) |i| {
                var new_bits: u128 = decoder.fast_char_to_index[0][source[fast_src_idx + i * 4]];
                new_bits |= decoder.fast_char_to_index[1][source[fast_src_idx + 1 + i * 4]];
                new_bits |= decoder.fast_char_to_index[2][source[fast_src_idx + 2 + i * 4]];
                new_bits |= decoder.fast_char_to_index[3][source[fast_src_idx + 3 + i * 4]];
                if ((new_bits & invalid_char_tst) != 0) return error.InvalidCharacter;
                bits |= (new_bits << (24 * i));
            }
            std.mem.writeInt(u128, dest[dest_idx..][0..16], bits, .little);
        }
        while (fast_src_idx + 4 < source.len and dest_idx + 3 < dest.len) : ({
            fast_src_idx += 4;
            dest_idx += 3;
        }) {
            var bits = decoder.fast_char_to_index[0][source[fast_src_idx]];
            bits |= decoder.fast_char_to_index[1][source[fast_src_idx + 1]];
            bits |= decoder.fast_char_to_index[2][source[fast_src_idx + 2]];
            bits |= decoder.fast_char_to_index[3][source[fast_src_idx + 3]];
            if ((bits & invalid_char_tst) != 0) return error.InvalidCharacter;
            std.mem.writeInt(u32, dest[dest_idx..][0..4], bits, .little);
        }
        const remaining = source[fast_src_idx..];
        for (remaining, fast_src_idx..) |c, src_idx| {
            const d = decoder.char_to_index[c];
            if (d == invalid_char) {
                if (decoder.pad_char == null or c != decoder.pad_char.?) return error.InvalidCharacter;
                leftover_idx = src_idx;
                break;
            }
            acc = (acc << 6) + d;
            acc_len += 6;
            if (acc_len >= 8) {
                acc_len -= 8;
                dest[dest_idx] = @as(u8, @truncate(acc >> acc_len));
                dest_idx += 1;
            }
        }
        if (acc_len > 4 or (acc & (@as(u12, 1) << acc_len) - 1) != 0) {
            return error.InvalidPadding;
        }
        if (leftover_idx == null) return;
        const leftover = source[leftover_idx.?..];
        if (decoder.pad_char) |pad_char| {
            const padding_len = acc_len / 2;
            var padding_chars: usize = 0;
            for (leftover) |c| {
                if (c != pad_char) {
                    return if (c == Base64Decoder.invalid_char) error.InvalidCharacter else error.InvalidPadding;
                }
                padding_chars += 1;
            }
            if (padding_chars != padding_len) return error.InvalidPadding;
        }
    }
};

pub const Base64DecoderWithIgnore = struct {
    decoder: Base64Decoder,
    char_is_ignored: [256]bool,

    pub fn init(alphabet_chars: [64]u8, pad_char: ?u8, ignore_chars: []const u8) Base64DecoderWithIgnore {
        var result = Base64DecoderWithIgnore{
            .decoder = Base64Decoder.init(alphabet_chars, pad_char),
            .char_is_ignored = [_]bool{false} ** 256,
        };
        for (ignore_chars) |c| {
            assert(result.decoder.char_to_index[c] == Base64Decoder.invalid_char);
            assert(!result.char_is_ignored[c]);
            assert(result.decoder.pad_char != c);
            result.char_is_ignored[c] = true;
        }
        return result;
    }

    /// Return the maximum possible decoded size for a given input length - The actual length may be less if the input includes padding.
    /// `InvalidPadding` is returned if the input length is not valid.
    pub fn calcSizeUpperBound(decoder_with_ignore: *const Base64DecoderWithIgnore, source_len: usize) Error!usize {
        var result = source_len / 4 * 3;
        if (decoder_with_ignore.decoder.pad_char == null) {
            const leftover = source_len % 4;
            result += leftover * 3 / 4;
        }
        return result;
    }

    /// Invalid characters that are not ignored result in error.InvalidCharacter.
    /// Invalid padding results in error.InvalidPadding.
    /// Decoding more data than can fit in dest results in error.NoSpaceLeft. See also ::calcSizeUpperBound.
    /// Returns the number of bytes written to dest.
    pub fn decode(decoder_with_ignore: *const Base64DecoderWithIgnore, dest: []u8, source: []const u8) Error!usize {
        const decoder = &decoder_with_ignore.decoder;
        var acc: u12 = 0;
        var acc_len: u4 = 0;
        var dest_idx: usize = 0;
        var leftover_idx: ?usize = null;
        for (source, 0..) |c, src_idx| {
            if (decoder_with_ignore.char_is_ignored[c]) continue;
            const d = decoder.char_to_index[c];
            if (d == Base64Decoder.invalid_char) {
                if (decoder.pad_char == null or c != decoder.pad_char.?) return error.InvalidCharacter;
                leftover_idx = src_idx;
                break;
            }
            acc = (acc << 6) + d;
            acc_len += 6;
            if (acc_len >= 8) {
                if (dest_idx == dest.len) return error.NoSpaceLeft;
                acc_len -= 8;
                dest[dest_idx] = @as(u8, @truncate(acc >> acc_len));
                dest_idx += 1;
            }
        }
        if (acc_len > 4 or (acc & (@as(u12, 1) << acc_len) - 1) != 0) {
            return error.InvalidPadding;
        }
        const padding_len = acc_len / 2;
        if (leftover_idx == null) {
            if (decoder.pad_char != null and padding_len != 0) return error.InvalidPadding;
            return dest_idx;
        }
        const leftover = source[leftover_idx.?..];
        if (decoder.pad_char) |pad_char| {
            var padding_chars: usize = 0;
            for (leftover) |c| {
                if (decoder_with_ignore.char_is_ignored[c]) continue;
                if (c != pad_char) {
                    return if (c == Base64Decoder.invalid_char) error.InvalidCharacter else error.InvalidPadding;
                }
                padding_chars += 1;
            }
            if (padding_chars != padding_len) return error.InvalidPadding;
        }
        return dest_idx;
    }
};

test "base64" {
    @setEvalBranchQuota(8000);
    try testBase64();
    try comptime testAllApis(standard, "comptime", "Y29tcHRpbWU=");
}

test "base64 padding dest overflow" {
    const input = "foo";

    var expect: [128]u8 = undefined;
    @memset(&expect, 0);
    _ = url_safe.Encoder.encode(expect[0..url_safe.Encoder.calcSize(input.len)], input);

    var got: [128]u8 = undefined;
    @memset(&got, 0);
    _ = url_safe.Encoder.encode(&got, input);

    try std.testing.expectEqualSlices(u8, &expect, &got);
}

test "base64 url_safe_no_pad" {
    @setEvalBranchQuota(8000);
    try testBase64UrlSafeNoPad();
    try comptime testAllApis(url_safe_no_pad, "comptime", "Y29tcHRpbWU");
}

fn testBase64() !void {
    const codecs = standard;

    try testAllApis(codecs, "", "");
    try testAllApis(codecs, "f", "Zg==");
    try testAllApis(codecs, "fo", "Zm8=");
    try testAllApis(codecs, "foo", "Zm9v");
    try testAllApis(codecs, "foob", "Zm9vYg==");
    try testAllApis(codecs, "fooba", "Zm9vYmE=");
    try testAllApis(codecs, "foobar", "Zm9vYmFy");
    try testAllApis(codecs, "foobarfoobarfoo", "Zm9vYmFyZm9vYmFyZm9v");
    try testAllApis(codecs, "foobarfoobarfoob", "Zm9vYmFyZm9vYmFyZm9vYg==");
    try testAllApis(codecs, "foobarfoobarfooba", "Zm9vYmFyZm9vYmFyZm9vYmE=");
    try testAllApis(codecs, "foobarfoobarfoobar", "Zm9vYmFyZm9vYmFyZm9vYmFy");

    try testDecodeIgnoreSpace(codecs, "", " ");
    try testDecodeIgnoreSpace(codecs, "f", "Z g= =");
    try testDecodeIgnoreSpace(codecs, "fo", "    Zm8=");
    try testDecodeIgnoreSpace(codecs, "foo", "Zm9v    ");
    try testDecodeIgnoreSpace(codecs, "foob", "Zm9vYg = = ");
    try testDecodeIgnoreSpace(codecs, "fooba", "Zm9v YmE=");
    try testDecodeIgnoreSpace(codecs, "foobar", " Z m 9 v Y m F y ");

    // test getting some api errors
    try testError(codecs, "A", error.InvalidPadding);
    try testError(codecs, "AA", error.InvalidPadding);
    try testError(codecs, "AAA", error.InvalidPadding);
    try testError(codecs, "A..A", error.InvalidCharacter);
    try testError(codecs, "AA=A", error.InvalidPadding);
    try testError(codecs, "AA/=", error.InvalidPadding);
    try testError(codecs, "A/==", error.InvalidPadding);
    try testError(codecs, "A===", error.InvalidPadding);
    try testError(codecs, "====", error.InvalidPadding);
    try testError(codecs, "Zm9vYmFyZm9vYmFyA..A", error.InvalidCharacter);
    try testError(codecs, "Zm9vYmFyZm9vYmFyAA=A", error.InvalidPadding);
    try testError(codecs, "Zm9vYmFyZm9vYmFyAA/=", error.InvalidPadding);
    try testError(codecs, "Zm9vYmFyZm9vYmFyA/==", error.InvalidPadding);
    try testError(codecs, "Zm9vYmFyZm9vYmFyA===", error.InvalidPadding);
    try testError(codecs, "A..AZm9vYmFyZm9vYmFy", error.InvalidCharacter);
    try testError(codecs, "Zm9vYmFyZm9vAA=A", error.InvalidPadding);
    try testError(codecs, "Zm9vYmFyZm9vAA/=", error.InvalidPadding);
    try testError(codecs, "Zm9vYmFyZm9vA/==", error.InvalidPadding);
    try testError(codecs, "Zm9vYmFyZm9vA===", error.InvalidPadding);

    try testNoSpaceLeftError(codecs, "AA==");
    try testNoSpaceLeftError(codecs, "AAA=");
    try testNoSpaceLeftError(codecs, "AAAA");
    try testNoSpaceLeftError(codecs, "AAAAAA==");

    try testFourBytesDestNoSpaceLeftError(codecs, "AAAAAAAAAAAAAAAA");
}

fn testBase64UrlSafeNoPad() !void {
    const codecs = url_safe_no_pad;

    try testAllApis(codecs, "", "");
    try testAllApis(codecs, "f", "Zg");
    try testAllApis(codecs, "fo", "Zm8");
    try testAllApis(codecs, "foo", "Zm9v");
    try testAllApis(codecs, "foob", "Zm9vYg");
    try testAllApis(codecs, "fooba", "Zm9vYmE");
    try testAllApis(codecs, "foobar", "Zm9vYmFy");
    try testAllApis(codecs, "foobarfoobarfoobar", "Zm9vYmFyZm9vYmFyZm9vYmFy");

    try testDecodeIgnoreSpace(codecs, "", " ");
    try testDecodeIgnoreSpace(codecs, "f", "Z g ");
    try testDecodeIgnoreSpace(codecs, "fo", "    Zm8");
    try testDecodeIgnoreSpace(codecs, "foo", "Zm9v    ");
    try testDecodeIgnoreSpace(codecs, "foob", "Zm9vYg   ");
    try testDecodeIgnoreSpace(codecs, "fooba", "Zm9v YmE");
    try testDecodeIgnoreSpace(codecs, "foobar", " Z m 9 v Y m F y ");

    // test getting some api errors
    try testError(codecs, "A", error.InvalidPadding);
    try testError(codecs, "AAA=", error.InvalidCharacter);
    try testError(codecs, "A..A", error.InvalidCharacter);
    try testError(codecs, "AA=A", error.InvalidCharacter);
    try testError(codecs, "AA/=", error.InvalidCharacter);
    try testError(codecs, "A/==", error.InvalidCharacter);
    try testError(codecs, "A===", error.InvalidCharacter);
    try testError(codecs, "====", error.InvalidCharacter);
    try testError(codecs, "Zm9vYmFyZm9vYmFyA..A", error.InvalidCharacter);
    try testError(codecs, "A..AZm9vYmFyZm9vYmFy", error.InvalidCharacter);

    try testNoSpaceLeftError(codecs, "AA");
    try testNoSpaceLeftError(codecs, "AAA");
    try testNoSpaceLeftError(codecs, "AAAA");
    try testNoSpaceLeftError(codecs, "AAAAAA");

    try testFourBytesDestNoSpaceLeftError(codecs, "AAAAAAAAAAAAAAAA");
}

fn testAllApis(codecs: Codecs, expected_decoded: []const u8, expected_encoded: []const u8) !void {
    // Base64Encoder
    {
        // raw encode
        var buffer: [0x100]u8 = undefined;
        const encoded = codecs.Encoder.encode(&buffer, expected_decoded);
        try testing.expectEqualSlices(u8, expected_encoded, encoded);

        // stream encode
        var list = try std.BoundedArray(u8, 0x100).init(0);
        try codecs.Encoder.encodeWriter(list.writer(), expected_decoded);
        try testing.expectEqualSlices(u8, expected_encoded, list.slice());

        // reader to writer encode
        var stream = std.io.fixedBufferStream(expected_decoded);
        list = try std.BoundedArray(u8, 0x100).init(0);
        try codecs.Encoder.encodeFromReaderToWriter(list.writer(), stream.reader());
        try testing.expectEqualSlices(u8, expected_encoded, list.slice());
    }

    // Base64Decoder
    {
        var buffer: [0x100]u8 = undefined;
        const decoded = buffer[0..try codecs.Decoder.calcSizeForSlice(expected_encoded)];
        try codecs.Decoder.decode(decoded, expected_encoded);
        try testing.expectEqualSlices(u8, expected_decoded, decoded);
    }

    // Base64DecoderWithIgnore
    {
        const decoder_ignore_nothing = codecs.decoderWithIgnore("");
        var buffer: [0x100]u8 = undefined;
        const decoded = buffer[0..try decoder_ignore_nothing.calcSizeUpperBound(expected_encoded.len)];
        const written = try decoder_ignore_nothing.decode(decoded, expected_encoded);
        try testing.expect(written <= decoded.len);
        try testing.expectEqualSlices(u8, expected_decoded, decoded[0..written]);
    }
}

fn testDecodeIgnoreSpace(codecs: Codecs, expected_decoded: []const u8, encoded: []const u8) !void {
    const decoder_ignore_space = codecs.decoderWithIgnore(" ");
    var buffer: [0x100]u8 = undefined;
    const decoded = buffer[0..try decoder_ignore_space.calcSizeUpperBound(encoded.len)];
    const written = try decoder_ignore_space.decode(decoded, encoded);
    try testing.expectEqualSlices(u8, expected_decoded, decoded[0..written]);
}

fn testError(codecs: Codecs, encoded: []const u8, expected_err: anyerror) !void {
    const decoder_ignore_space = codecs.decoderWithIgnore(" ");
    var buffer: [0x100]u8 = undefined;
    if (codecs.Decoder.calcSizeForSlice(encoded)) |decoded_size| {
        const decoded = buffer[0..decoded_size];
        if (codecs.Decoder.decode(decoded, encoded)) |_| {
            return error.ExpectedError;
        } else |err| if (err != expected_err) return err;
    } else |err| if (err != expected_err) return err;

    if (decoder_ignore_space.decode(buffer[0..], encoded)) |_| {
        return error.ExpectedError;
    } else |err| if (err != expected_err) return err;
}

fn testNoSpaceLeftError(codecs: Codecs, encoded: []const u8) !void {
    const decoder_ignore_space = codecs.decoderWithIgnore(" ");
    var buffer: [0x100]u8 = undefined;
    const decoded = buffer[0 .. (try codecs.Decoder.calcSizeForSlice(encoded)) - 1];
    if (decoder_ignore_space.decode(decoded, encoded)) |_| {
        return error.ExpectedError;
    } else |err| if (err != error.NoSpaceLeft) return err;
}

fn testFourBytesDestNoSpaceLeftError(codecs: Codecs, encoded: []const u8) !void {
    const decoder_ignore_space = codecs.decoderWithIgnore(" ");
    var buffer: [0x100]u8 = undefined;
    const decoded = buffer[0..4];
    if (decoder_ignore_space.decode(decoded, encoded)) |_| {
        return error.ExpectedError;
    } else |err| if (err != error.NoSpaceLeft) return err;
}
//! This file defines several variants of bit sets.  A bit set
//! is a densely stored set of integers with a known maximum,
//! in which each integer gets a single bit.  Bit sets have very
//! fast presence checks, update operations, and union and intersection
//! operations.  However, if the number of possible items is very
//! large and the number of actual items in a given set is usually
//! small, they may be less memory efficient than an array set.
//!
//! There are five variants defined here:
//!
//! IntegerBitSet:
//!   A bit set with static size, which is backed by a single integer.
//!   This set is good for sets with a small size, but may generate
//!   inefficient code for larger sets, especially in debug mode.
//!
//! ArrayBitSet:
//!   A bit set with static size, which is backed by an array of usize.
//!   This set is good for sets with a larger size, but may use
//!   more bytes than necessary if your set is small.
//!
//! StaticBitSet:
//!   Picks either IntegerBitSet or ArrayBitSet depending on the requested
//!   size.  The interfaces of these two types match exactly, except for fields.
//!
//! DynamicBitSet:
//!   A bit set with runtime-known size, backed by an allocated slice
//!   of usize.
//!
//! DynamicBitSetUnmanaged:
//!   A variant of DynamicBitSet which does not store a pointer to its
//!   allocator, in order to save space.

const std = @import("std.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

/// Returns the optimal static bit set type for the specified number
/// of elements: either `IntegerBitSet` or `ArrayBitSet`,
/// both of which fulfill the same interface.
/// The returned type will perform no allocations,
/// can be copied by value, and does not require deinitialization.
pub fn StaticBitSet(comptime size: usize) type {
    if (size <= @bitSizeOf(usize)) {
        return IntegerBitSet(size);
    } else {
        return ArrayBitSet(usize, size);
    }
}

/// A bit set with static size, which is backed by a single integer.
/// This set is good for sets with a small size, but may generate
/// inefficient code for larger sets, especially in debug mode.
pub fn IntegerBitSet(comptime size: u16) type {
    return packed struct {
        const Self = @This();

        // TODO: Make this a comptime field once those are fixed
        /// The number of items in this bit set
        pub const bit_length: usize = size;

        /// The integer type used to represent a mask in this bit set
        pub const MaskInt = std.meta.Int(.unsigned, size);

        /// The integer type used to shift a mask in this bit set
        pub const ShiftInt = std.math.Log2Int(MaskInt);

        /// The bit mask, as a single integer
        mask: MaskInt,

        /// Creates a bit set with no elements present.
        pub fn initEmpty() Self {
            return .{ .mask = 0 };
        }

        /// Creates a bit set with all elements present.
        pub fn initFull() Self {
            return .{ .mask = ~@as(MaskInt, 0) };
        }

        /// Returns the number of bits in this bit set
        pub inline fn capacity(self: Self) usize {
            _ = self;
            return bit_length;
        }

        /// Returns true if the bit at the specified index
        /// is present in the set, false otherwise.
        pub fn isSet(self: Self, index: usize) bool {
            assert(index < bit_length);
            return (self.mask & maskBit(index)) != 0;
        }

        /// Returns the total number of set bits in this bit set.
        pub fn count(self: Self) usize {
            return @popCount(self.mask);
        }

        /// Changes the value of the specified bit of the bit
        /// set to match the passed boolean.
        pub fn setValue(self: *Self, index: usize, value: bool) void {
            assert(index < bit_length);
            if (MaskInt == u0) return;
            const bit = maskBit(index);
            const new_bit = bit & std.math.boolMask(MaskInt, value);
            self.mask = (self.mask & ~bit) | new_bit;
        }

        /// Adds a specific bit to the bit set
        pub fn set(self: *Self, index: usize) void {
            assert(index < bit_length);
            self.mask |= maskBit(index);
        }

        /// Changes the value of all bits in the specified range to
        /// match the passed boolean.
        pub fn setRangeValue(self: *Self, range: Range, value: bool) void {
            assert(range.end <= bit_length);
            assert(range.start <= range.end);
            if (range.start == range.end) return;
            if (MaskInt == u0) return;

            const start_bit = @as(ShiftInt, @intCast(range.start));

            var mask = std.math.boolMask(MaskInt, true) << start_bit;
            if (range.end != bit_length) {
                const end_bit = @as(ShiftInt, @intCast(range.end));
                mask &= std.math.boolMask(MaskInt, true) >> @as(ShiftInt, @truncate(@as(usize, @bitSizeOf(MaskInt)) - @as(usize, end_bit)));
            }
            self.mask &= ~mask;

            mask = std.math.boolMask(MaskInt, value) << start_bit;
            if (range.end != bit_length) {
                const end_bit = @as(ShiftInt, @intCast(range.end));
                mask &= std.math.boolMask(MaskInt, value) >> @as(ShiftInt, @truncate(@as(usize, @bitSizeOf(MaskInt)) - @as(usize, end_bit)));
            }
            self.mask |= mask;
        }

        /// Removes a specific bit from the bit set
        pub fn unset(self: *Self, index: usize) void {
            assert(index < bit_length);
            // Workaround for #7953
            if (MaskInt == u0) return;
            self.mask &= ~maskBit(index);
        }

        /// Flips a specific bit in the bit set
        pub fn toggle(self: *Self, index: usize) void {
            assert(index < bit_length);
            self.mask ^= maskBit(index);
        }

        /// Flips all bits in this bit set which are present
        /// in the toggles bit set.
        pub fn toggleSet(self: *Self, toggles: Self) void {
            self.mask ^= toggles.mask;
        }

        /// Flips every bit in the bit set.
        pub fn toggleAll(self: *Self) void {
            self.mask = ~self.mask;
        }

        /// Performs a union of two bit sets, and stores the
        /// result in the first one.  Bits in the result are
        /// set if the corresponding bits were set in either input.
        pub fn setUnion(self: *Self, other: Self) void {
            self.mask |= other.mask;
        }

        /// Performs an intersection of two bit sets, and stores
        /// the result in the first one.  Bits in the result are
        /// set if the corresponding bits were set in both inputs.
        pub fn setIntersection(self: *Self, other: Self) void {
            self.mask &= other.mask;
        }

        /// Finds the index of the first set bit.
        /// If no bits are set, returns null.
        pub fn findFirstSet(self: Self) ?usize {
            const mask = self.mask;
            if (mask == 0) return null;
            return @ctz(mask);
        }

        /// Finds the index of the last set bit.
        /// If no bits are set, returns null.
        pub fn findLastSet(self: Self) ?usize {
            const mask = self.mask;
            if (mask == 0) return null;
            return bit_length - @clz(mask) - 1;
        }

        /// Finds the index of the first set bit, and unsets it.
        /// If no bits are set, returns null.
        pub fn toggleFirstSet(self: *Self) ?usize {
            const mask = self.mask;
            if (mask == 0) return null;
            const index = @ctz(mask);
            self.mask = mask & (mask - 1);
            return index;
        }

        /// Returns true iff every corresponding bit in both
        /// bit sets are the same.
        pub fn eql(self: Self, other: Self) bool {
            return bit_length == 0 or self.mask == other.mask;
        }

        /// Returns true iff the first bit set is the subset
        /// of the second one.
        pub fn subsetOf(self: Self, other: Self) bool {
            return self.intersectWith(other).eql(self);
        }

        /// Returns true iff the first bit set is the superset
        /// of the second one.
        pub fn supersetOf(self: Self, other: Self) bool {
            return other.subsetOf(self);
        }

        /// Returns the complement bit sets. Bits in the result
        /// are set if the corresponding bits were not set.
        pub fn complement(self: Self) Self {
            var result = self;
            result.toggleAll();
            return result;
        }

        /// Returns the union of two bit sets. Bits in the
        /// result are set if the corresponding bits were set
        /// in either input.
        pub fn unionWith(self: Self, other: Self) Self {
            var result = self;
            result.setUnion(other);
            return result;
        }

        /// Returns the intersection of two bit sets. Bits in
        /// the result are set if the corresponding bits were
        /// set in both inputs.
        pub fn intersectWith(self: Self, other: Self) Self {
            var result = self;
            result.setIntersection(other);
            return result;
        }

        /// Returns the xor of two bit sets. Bits in the
        /// result are set if the corresponding bits were
        /// not the same in both inputs.
        pub fn xorWith(self: Self, other: Self) Self {
            var result = self;
            result.toggleSet(other);
            return result;
        }

        /// Returns the difference of two bit sets. Bits in
        /// the result are set if set in the first but not
        /// set in the second set.
        pub fn differenceWith(self: Self, other: Self) Self {
            var result = self;
            result.setIntersection(other.complement());
            return result;
        }

        /// Iterates through the items in the set, according to the options.
        /// The default options (.{}) will iterate indices of set bits in
        /// ascending order.  Modifications to the underlying bit set may
        /// or may not be observed by the iterator.
        pub fn iterator(self: *const Self, comptime options: IteratorOptions) Iterator(options) {
            return .{
                .bits_remain = switch (options.kind) {
                    .set => self.mask,
                    .unset => ~self.mask,
                },
            };
        }

        pub fn Iterator(comptime options: IteratorOptions) type {
            return SingleWordIterator(options.direction);
        }

        fn SingleWordIterator(comptime direction: IteratorOptions.Direction) type {
            return struct {
                const IterSelf = @This();
                // all bits which have not yet been iterated over
                bits_remain: MaskInt,

                /// Returns the index of the next unvisited set bit
                /// in the bit set, in ascending order.
                pub fn next(self: *IterSelf) ?usize {
                    if (self.bits_remain == 0) return null;

                    switch (direction) {
                        .forward => {
                            const next_index = @ctz(self.bits_remain);
                            self.bits_remain &= self.bits_remain - 1;
                            return next_index;
                        },
                        .reverse => {
                            const leading_zeroes = @clz(self.bits_remain);
                            const top_bit = (@bitSizeOf(MaskInt) - 1) - leading_zeroes;
                            self.bits_remain &= (@as(MaskInt, 1) << @as(ShiftInt, @intCast(top_bit))) - 1;
                            return top_bit;
                        },
                    }
                }
            };
        }

        fn maskBit(index: usize) MaskInt {
            if (MaskInt == u0) return 0;
            return @as(MaskInt, 1) << @as(ShiftInt, @intCast(index));
        }
        fn boolMaskBit(index: usize, value: bool) MaskInt {
            if (MaskInt == u0) return 0;
            return @as(MaskInt, @intFromBool(value)) << @as(ShiftInt, @intCast(index));
        }
    };
}

/// A bit set with static size, which is backed by an array of usize.
/// This set is good for sets with a larger size, but may use
/// more bytes than necessary if your set is small.
pub fn ArrayBitSet(comptime MaskIntType: type, comptime size: usize) type {
    const mask_info: std.builtin.Type = @typeInfo(MaskIntType);

    // Make sure the mask int is indeed an int
    if (mask_info != .int) @compileError("ArrayBitSet can only operate on integer masks, but was passed " ++ @typeName(MaskIntType));

    // It must also be unsigned.
    if (mask_info.int.signedness != .unsigned) @compileError("ArrayBitSet requires an unsigned integer mask type, but was passed " ++ @typeName(MaskIntType));

    // And it must not be empty.
    if (MaskIntType == u0)
        @compileError("ArrayBitSet requires a sized integer for its mask int.  u0 does not work.");

    const byte_size = std.mem.byte_size_in_bits;

    // We use shift and truncate to decompose indices into mask indices and bit indices.
    // This operation requires that the mask has an exact power of two number of bits.
    if (!std.math.isPowerOfTwo(@bitSizeOf(MaskIntType))) {
        var desired_bits = std.math.ceilPowerOfTwoAssert(usize, @bitSizeOf(MaskIntType));
        if (desired_bits < byte_size) desired_bits = byte_size;
        const FixedMaskType = std.meta.Int(.unsigned, desired_bits);
        @compileError("ArrayBitSet was passed integer type " ++ @typeName(MaskIntType) ++
            ", which is not a power of two.  Please round this up to a power of two integer size (i.e. " ++ @typeName(FixedMaskType) ++ ").");
    }

    // Make sure the integer has no padding bits.
    // Those would be wasteful here and are probably a mistake by the user.
    // This case may be hit with small powers of two, like u4.
    if (@bitSizeOf(MaskIntType) != @sizeOf(MaskIntType) * byte_size) {
        var desired_bits = @sizeOf(MaskIntType) * byte_size;
        desired_bits = std.math.ceilPowerOfTwoAssert(usize, desired_bits);
        const FixedMaskType = std.meta.Int(.unsigned, desired_bits);
        @compileError("ArrayBitSet was passed integer type " ++ @typeName(MaskIntType) ++
            ", which contains padding bits.  Please round this up to an unpadded integer size (i.e. " ++ @typeName(FixedMaskType) ++ ").");
    }

    return extern struct {
        const Self = @This();

        // TODO: Make this a comptime field once those are fixed
        /// The number of items in this bit set
        pub const bit_length: usize = size;

        /// The integer type used to represent a mask in this bit set
        pub const MaskInt = MaskIntType;

        /// The integer type used to shift a mask in this bit set
        pub const ShiftInt = std.math.Log2Int(MaskInt);

        // bits in one mask
        const mask_len = @bitSizeOf(MaskInt);
        // total number of masks
        const num_masks = (size + mask_len - 1) / mask_len;
        // padding bits in the last mask (may be 0)
        const last_pad_bits = mask_len * num_masks - size;
        // Mask of valid bits in the last mask.
        // All functions will ensure that the invalid
        // bits in the last mask are zero.
        pub const last_item_mask = ~@as(MaskInt, 0) >> last_pad_bits;

        /// The bit masks, ordered with lower indices first.
        /// Padding bits at the end are undefined.
        masks: [num_masks]MaskInt,

        /// Creates a bit set with no elements present.
        pub fn initEmpty() Self {
            return .{ .masks = [_]MaskInt{0} ** num_masks };
        }

        /// Creates a bit set with all elements present.
        pub fn initFull() Self {
            if (num_masks == 0) {
                return .{ .masks = .{} };
            } else {
                return .{ .masks = [_]MaskInt{~@as(MaskInt, 0)} ** (num_masks - 1) ++ [_]MaskInt{last_item_mask} };
            }
        }

        /// Returns the number of bits in this bit set
        pub inline fn capacity(self: Self) usize {
            _ = self;
            return bit_length;
        }

        /// Returns true if the bit at the specified index
        /// is present in the set, false otherwise.
        pub fn isSet(self: Self, index: usize) bool {
            assert(index < bit_length);
            if (num_masks == 0) return false; // doesn't compile in this case
            return (self.masks[maskIndex(index)] & maskBit(index)) != 0;
        }

        /// Returns the total number of set bits in this bit set.
        pub fn count(self: Self) usize {
            var total: usize = 0;
            for (self.masks) |mask| {
                total += @popCount(mask);
            }
            return total;
        }

        /// Changes the value of the specified bit of the bit
        /// set to match the passed boolean.
        pub fn setValue(self: *Self, index: usize, value: bool) void {
            assert(index < bit_length);
            if (num_masks == 0) return; // doesn't compile in this case
            const bit = maskBit(index);
            const mask_index = maskIndex(index);
            const new_bit = bit & std.math.boolMask(MaskInt, value);
            self.masks[mask_index] = (self.masks[mask_index] & ~bit) | new_bit;
        }

        /// Adds a specific bit to the bit set
        pub fn set(self: *Self, index: usize) void {
            assert(index < bit_length);
            if (num_masks == 0) return; // doesn't compile in this case
            self.masks[maskIndex(index)] |= maskBit(index);
        }

        /// Changes the value of all bits in the specified range to
        /// match the passed boolean.
        pub fn setRangeValue(self: *Self, range: Range, value: bool) void {
            assert(range.end <= bit_length);
            assert(range.start <= range.end);
            if (range.start == range.end) return;
            if (num_masks == 0) return;

            const start_mask_index = maskIndex(range.start);
            const start_bit = @as(ShiftInt, @truncate(range.start));

            const end_mask_index = maskIndex(range.end);
            const end_bit = @as(ShiftInt, @truncate(range.end));

            if (start_mask_index == end_mask_index) {
                var mask1 = std.math.boolMask(MaskInt, true) << start_bit;
                var mask2 = std.math.boolMask(MaskInt, true) >> (mask_len - 1) - (end_bit - 1);
                self.masks[start_mask_index] &= ~(mask1 & mask2);

                mask1 = std.math.boolMask(MaskInt, value) << start_bit;
                mask2 = std.math.boolMask(MaskInt, value) >> (mask_len - 1) - (end_bit - 1);
                self.masks[start_mask_index] |= mask1 & mask2;
            } else {
                var bulk_mask_index: usize = undefined;
                if (start_bit > 0) {
                    self.masks[start_mask_index] =
                        (self.masks[start_mask_index] & ~(std.math.boolMask(MaskInt, true) << start_bit)) |
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
            assert(index < bit_length);
            if (num_masks == 0) return; // doesn't compile in this case
            self.masks[maskIndex(index)] &= ~maskBit(index);
        }

        /// Flips a specific bit in the bit set
        pub fn toggle(self: *Self, index: usize) void {
            assert(index < bit_length);
            if (num_masks == 0) return; // doesn't compile in this case
            self.masks[maskIndex(index)] ^= maskBit(index);
        }

        /// Flips all bits in this bit set which are present
        /// in the toggles bit set.
        pub fn toggleSet(self: *Self, toggles: Self) void {
            for (&self.masks, 0..) |*mask, i| {
                mask.* ^= toggles.masks[i];
            }
        }

        /// Flips every bit in the bit set.
        pub fn toggleAll(self: *Self) void {
            for (&self.masks) |*mask| {
                mask.* = ~mask.*;
            }

            // Zero the padding bits
            if (num_masks > 0) {
                self.masks[num_masks - 1] &= last_item_mask;
            }
        }

        /// Performs a union of two bit sets, and stores the
        /// result in the first one.  Bits in the result are
        /// set if the corresponding bits were set in either input.
        pub fn setUnion(self: *Self, other: Self) void {
            for (&self.masks, 0..) |*mask, i| {
                mask.* |= other.masks[i];
            }
        }

        /// Performs an intersection of two bit sets, and stores
        /// the result in the first one.  Bits in the result are
        /// set if the corresponding bits were set in both inputs.
        pub fn setIntersection(self: *Self, other: Self) void {
            for (&self.masks, 0..) |*mask, i| {
                mask.* &= other.masks[i];
            }
        }

        /// Finds the index of the first set bit.
        /// If no bits are set, returns null.
        pub fn findFirstSet(self: Self) ?usize {
            var offset: usize = 0;
            const mask = for (self.masks) |mask| {
                if (mask != 0) break mask;
                offset += @bitSizeOf(MaskInt);
            } else return null;
            return offset + @ctz(mask);
        }

        /// Finds the index of the last set bit.
        /// If no bits are set, returns null.
        pub fn findLastSet(self: Self) ?usize {
            if (bit_length == 0) return null;
            const bs = @bitSizeOf(MaskInt);
            var len = bit_length / bs;
            if (bit_length % bs != 0) len += 1;
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
            const mask = for (&self.masks) |*mask| {
                if (mask.* != 0) break mask;
                offset += @bitSizeOf(MaskInt);
            } else return null;
            const index = @ctz(mask.*);
            mask.* &= (mask.* - 1);
            return offset + index;
        }

        /// Returns true iff every corresponding bit in both
        /// bit sets are the same.
        pub fn eql(self: Self, other: Self) bool {
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
            return self.intersectWith(other).eql(self);
        }

        /// Returns true iff the first bit set is the superset
        /// of the second one.
        pub fn supersetOf(self: Self, other: Self) bool {
            return other.subsetOf(self);
        }

        /// Returns the complement bit sets. Bits in the result
        /// are set if the corresponding bits were not set.
        pub fn complement(self: Self) Self {
            var result = self;
            result.toggleAll();
            return result;
        }

        /// Returns the union of two bit sets. Bits in the
        /// result are set if the corresponding bits were set
        /// in either input.
        pub fn unionWith(self: Self, other: Self) Self {
            var result = self;
            result.setUnion(other);
            return result;
        }

        /// Returns the intersection of two bit sets. Bits in
        /// the result are set if the corresponding bits were
        /// set in both inputs.
        pub fn intersectWith(self: Self, other: Self) Self {
            var result = self;
            result.setIntersection(other);
            return result;
        }

        /// Returns the xor of two bit sets. Bits in the
        /// result are set if the corresponding bits were
        /// not the same in both inputs.
        pub fn xorWith(self: Self, other: Self) Self {
            var result = self;
            result.toggleSet(other);
            return result;
        }

        /// Returns the difference of two bit sets. Bits in
        /// the result are set if set in the first but not
        /// set in the second set.
        pub fn differenceWith(self: Self, other: Self) Self {
            var result = self;
            result.setIntersection(other.complement());
            return result;
        }

        /// Iterates through the items in the set, according to the options.
        /// The default options (.{}) will iterate indices of set bits in
        /// ascending order.  Modifications to the underlying bit set may
        /// or may not be observed by the iterator.
        pub fn iterator(self: *const Self, comptime options: IteratorOptions) Iterator(options) {
            return Iterator(options).init(&self.masks, last_item_mask);
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
    };
}

/// A bit set with runtime-known size, backed by an allocated slice
/// of usize.  The allocator must be tracked externally by the user.
pub const DynamicBitSetUnmanaged = struct {
    const Self = @This();

    /// The integer type used to represent a mask in this bit set
    pub const MaskInt = usize;

    /// The integer type used to shift a mask in this bit set
    pub const ShiftInt = std.math.Log2Int(MaskInt);

    /// The number of valid items in this bit set
    bit_length: usize = 0,

    /// The bit masks, ordered with lower indices first.
    /// Padding bits at the end must be zeroed.
    masks: [*]MaskInt = empty_masks_ptr,
    // This pointer is one usize after the actual allocation.
    // That slot holds the size of the true allocation, which
    // is needed by Zig's allocator interface in case a shrink
    // fails.

    // Don't modify this value.  Ideally it would go in const data so
    // modifications would cause a bus error, but the only way
    // to discard a const qualifier is through intFromPtr, which
    // cannot currently round trip at comptime.
    var empty_masks_data = [_]MaskInt{ 0, undefined };
    const empty_masks_ptr = empty_masks_data[1..2];

    /// Creates a bit set with no elements present.
    /// If bit_length is not zero, deinit must eventually be called.
    pub fn initEmpty(allocator: Allocator, bit_length: usize) !Self {
        var self = Self{};
        try self.resize(allocator, bit_length, false);
        return self;
    }

    /// Creates a bit set with all elements present.
    /// If bit_length is not zero, deinit must eventually be called.
    pub fn initFull(allocator: Allocator, bit_length: usize) !Self {
        var self = Self{};
        try self.resize(allocator, bit_length, true);
        return self;
    }

    /// Resizes to a new bit_length.  If the new length is larger
    /// than the old length, fills any added bits with `fill`.
    /// If new_len is not zero, deinit must eventually be called.
    pub fn resize(self: *@This(), allocator: Allocator, new_len: usize, fill: bool) !void {
        const old_len = self.bit_length;

        const old_masks = numMasks(old_len);
        const new_masks = numMasks(new_len);

        const old_allocation = (self.masks - 1)[0..(self.masks - 1)[0]];

        if (new_masks == 0) {
            assert(new_len == 0);
            allocator.free(old_allocation);
            self.masks = empty_masks_ptr;
            self.bit_length = 0;
            return;
        }

        if (old_allocation.len != new_masks + 1) realloc: {
            // If realloc fails, it may mean one of two things.
            // If we are growing, it means we are out of memory.
            // If we are shrinking, it means the allocator doesn't
            // want to move the allocation.  This means we need to
            // hold on to the extra 8 bytes required to be able to free
            // this allocation properly.
            const new_allocation = allocator.realloc(old_allocation, new_masks + 1) catch |err| {
                if (new_masks + 1 > old_allocation.len) return err;
                break :realloc;
            };

            new_allocation[0] = new_allocation.len;
            self.masks = new_allocation.ptr + 1;
        }

        // If we increased in size, we need to set any new bits
        // to the fill value.
        if (new_len > old_len) {
            // set the padding bits in the old last item to 1
            if (fill and old_masks > 0) {
                const old_padding_bits = old_masks * @bitSizeOf(MaskInt) - old_len;
                const old_mask = (~@as(MaskInt, 0)) >> @as(ShiftInt, @intCast(old_padding_bits));
                self.masks[old_masks - 1] |= ~old_mask;
            }

            // fill in any new masks
            if (new_masks > old_masks) {
                const fill_value = std.math.boolMask(MaskInt, fill);
                @memset(self.masks[old_masks..new_masks], fill_value);
            }
        }

        // Zero out the padding bits
        if (new_len > 0) {
            const padding_bits = new_masks * @bitSizeOf(MaskInt) - new_len;
            const last_item_mask = (~@as(MaskInt, 0)) >> @as(ShiftInt, @intCast(padding_bits));
            self.masks[new_masks - 1] &= last_item_mask;
        }

        // And finally, save the new length.
        self.bit_length = new_len;
    }

    /// Deinitializes the array and releases its memory.
    /// The passed allocator must be the same one used for
    /// init* or resize in the past.
    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.resize(allocator, 0, false) catch unreachable;
    }

    /// Creates a duplicate of this bit set, using the new allocator.
    pub fn clone(self: *const Self, new_allocator: Allocator) !Self {
        const num_masks = numMasks(self.bit_length);
        var copy = Self{};
        try copy.resize(new_allocator, self.bit_length, false);
        @memcpy(copy.masks[0..num_masks], self.masks[0..num_masks]);
        return copy;
    }

    /// Returns the number of bits in this bit set
    pub inline fn capacity(self: Self) usize {
        return self.bit_length;
    }

    /// Returns true if the bit at the specified index
    /// is present in the set, false otherwise.
    pub fn isSet(self: Self, index: usize) bool {
        assert(index < self.bit_length);
        return (self.masks[maskIndex(index)] & maskBit(index)) != 0;
    }

    /// Returns the total number of set bits in this bit set.
    pub fn count(self: Self) usize {
        const num_masks = (self.bit_length + (@bitSizeOf(MaskInt) - 1)) / @bitSizeOf(MaskInt);
        var total: usize = 0;
        for (self.masks[0..num_masks]) |mask| {
            // Note: This is where we depend on padding bits being zero
            total += @popCount(mask);
        }
        return total;
    }

    /// Changes the value of the specified bit of the bit
    /// set to match the passed boolean.
    pub fn setValue(self: *Self, index: usize, value: bool) void {
        assert(index < self.bit_length);
        const bit = maskBit(index);
        const mask_index = maskIndex(index);
        const new_bit = bit & std.math.boolMask(MaskInt, value);
        self.masks[mask_index] = (self.masks[mask_index] & ~bit) | new_bit;
    }

    /// Adds a specific bit to the bit set
    pub fn set(self: *Self, index: usize) void {
        assert(index < self.bit_length);
        self.masks[maskIndex(index)] |= maskBit(index);
    }

    /// Changes the value of all bits in the specified range to
    /// match the passed boolean.
    pub fn setRangeValue(self: *Self, range: Range, value: bool) void {
        assert(range.end <= self.bit_length);
        assert(range.start <= range.end);
        if (range.start == range.end) return;

        const start_mask_index = maskIndex(range.start);
        const start_bit = @as(ShiftInt, @truncate(range.start));

        const end_mask_index = maskIndex(range.end);
        const end_bit = @as(ShiftInt, @truncate(range.end));

        if (start_mask_index == end_mask_index) {
            var mask1 = std.math.boolMask(MaskInt, true) << start_bit;
            var mask2 = std.math.boolMask(MaskInt, true) >> (@bitSizeOf(MaskInt) - 1) - (end_bit - 1);
            self.masks[start_mask_index] &= ~(mask1 & mask2);

            mask1 = std.math.boolMask(MaskInt, value) << start_bit;
            mask2 = std.math.boolMask(MaskInt, value) >> (@bitSizeOf(MaskInt) - 1) - (end_bit - 1);
            self.masks[start_mask_index] |= mask1 & mask2;
        } else {
            var bulk_mask_index: usize = undefined;
            if (start_bit > 0) {
                self.masks[start_mask_index] =
                    (self.masks[start_mask_index] & ~(std.math```
