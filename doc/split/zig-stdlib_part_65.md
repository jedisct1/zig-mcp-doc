```
                  else => @compileError("invalid type given to fixedBufferStream"),
                },
                else => @compileError("invalid type given to fixedBufferStream"),
            }
            new_ptr_info.size = .slice;
            return @Type(.{ .pointer = new_ptr_info });
        },
        else => @compileError("invalid type given to fixedBufferStream"),
    }
}

test "output" {
    var buf: [255]u8 = undefined;
    var fbs = fixedBufferStream(&buf);
    const stream = fbs.writer();

    try stream.print("{s}{s}!", .{ "Hello", "World" });
    try testing.expectEqualSlices(u8, "HelloWorld!", fbs.getWritten());
}

test "output at comptime" {
    comptime {
        var buf: [255]u8 = undefined;
        var fbs = fixedBufferStream(&buf);
        const stream = fbs.writer();

        try stream.print("{s}{s}!", .{ "Hello", "World" });
        try testing.expectEqualSlices(u8, "HelloWorld!", fbs.getWritten());
    }
}

test "output 2" {
    var buffer: [10]u8 = undefined;
    var fbs = fixedBufferStream(&buffer);

    try fbs.writer().writeAll("Hello");
    try testing.expect(mem.eql(u8, fbs.getWritten(), "Hello"));

    try fbs.writer().writeAll("world");
    try testing.expect(mem.eql(u8, fbs.getWritten(), "Helloworld"));

    try testing.expectError(error.NoSpaceLeft, fbs.writer().writeAll("!"));
    try testing.expect(mem.eql(u8, fbs.getWritten(), "Helloworld"));

    fbs.reset();
    try testing.expect(fbs.getWritten().len == 0);

    try testing.expectError(error.NoSpaceLeft, fbs.writer().writeAll("Hello world!"));
    try testing.expect(mem.eql(u8, fbs.getWritten(), "Hello worl"));

    try fbs.seekTo((try fbs.getEndPos()) + 1);
    try testing.expectError(error.NoSpaceLeft, fbs.writer().writeAll("H"));
}

test "input" {
    const bytes = [_]u8{ 1, 2, 3, 4, 5, 6, 7 };
    var fbs = fixedBufferStream(&bytes);

    var dest: [4]u8 = undefined;

    var read = try fbs.reader().read(&dest);
    try testing.expect(read == 4);
    try testing.expect(mem.eql(u8, dest[0..4], bytes[0..4]));

    read = try fbs.reader().read(&dest);
    try testing.expect(read == 3);
    try testing.expect(mem.eql(u8, dest[0..3], bytes[4..7]));

    read = try fbs.reader().read(&dest);
    try testing.expect(read == 0);

    try fbs.seekTo((try fbs.getEndPos()) + 1);
    read = try fbs.reader().read(&dest);
    try testing.expect(read == 0);
}
const std = @import("../std.zig");
const io = std.io;
const assert = std.debug.assert;
const testing = std.testing;

pub fn LimitedReader(comptime ReaderType: type) type {
    return struct {
        inner_reader: ReaderType,
        bytes_left: u64,

        pub const Error = ReaderType.Error;
        pub const Reader = io.Reader(*Self, Error, read);

        const Self = @This();

        pub fn read(self: *Self, dest: []u8) Error!usize {
            const max_read = @min(self.bytes_left, dest.len);
            const n = try self.inner_reader.read(dest[0..max_read]);
            self.bytes_left -= n;
            return n;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

/// Returns an initialised `LimitedReader`.
/// `bytes_left` is a `u64` to be able to take 64 bit file offsets
pub fn limitedReader(inner_reader: anytype, bytes_left: u64) LimitedReader(@TypeOf(inner_reader)) {
    return .{ .inner_reader = inner_reader, .bytes_left = bytes_left };
}

test "basic usage" {
    const data = "hello world";
    var fbs = std.io.fixedBufferStream(data);
    var early_stream = limitedReader(fbs.reader(), 3);

    var buf: [5]u8 = undefined;
    try testing.expectEqual(@as(usize, 3), try early_stream.reader().read(&buf));
    try testing.expectEqualSlices(u8, data[0..3], buf[0..3]);
    try testing.expectEqual(@as(usize, 0), try early_stream.reader().read(&buf));
    try testing.expectError(error.EndOfStream, early_stream.reader().skipBytes(10, .{}));
}
const std = @import("../std.zig");
const io = std.io;

/// Takes a tuple of streams, and constructs a new stream that writes to all of them
pub fn MultiWriter(comptime Writers: type) type {
    comptime var ErrSet = error{};
    inline for (@typeInfo(Writers).@"struct".fields) |field| {
        const StreamType = field.type;
        ErrSet = ErrSet || StreamType.Error;
    }

    return struct {
        const Self = @This();

        streams: Writers,

        pub const Error = ErrSet;
        pub const Writer = io.Writer(*Self, Error, write);

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            inline for (self.streams) |stream|
                try stream.writeAll(bytes);
            return bytes.len;
        }
    };
}

pub fn multiWriter(streams: anytype) MultiWriter(@TypeOf(streams)) {
    return .{ .streams = streams };
}

const testing = std.testing;

test "MultiWriter" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var f = try tmp.dir.createFile("t.txt", .{});

    var buf1: [255]u8 = undefined;
    var fbs1 = io.fixedBufferStream(&buf1);
    var buf2: [255]u8 = undefined;
    var stream = multiWriter(.{ fbs1.writer(), f.writer() });

    try stream.writer().print("HI", .{});
    f.close();

    try testing.expectEqualSlices(u8, "HI", fbs1.getWritten());
    try testing.expectEqualSlices(u8, "HI", try tmp.dir.readFile("t.txt", &buf2));
}
context: *const anyopaque,
readFn: *const fn (context: *const anyopaque, buffer: []u8) anyerror!usize,

pub const Error = anyerror;

/// Returns the number of bytes read. It may be less than buffer.len.
/// If the number of bytes read is 0, it means end of stream.
/// End of stream is not an error condition.
pub fn read(self: Self, buffer: []u8) anyerror!usize {
    return self.readFn(self.context, buffer);
}

/// Returns the number of bytes read. If the number read is smaller than `buffer.len`, it
/// means the stream reached the end. Reaching the end of a stream is not an error
/// condition.
pub fn readAll(self: Self, buffer: []u8) anyerror!usize {
    return readAtLeast(self, buffer, buffer.len);
}

/// Returns the number of bytes read, calling the underlying read
/// function the minimal number of times until the buffer has at least
/// `len` bytes filled. If the number read is less than `len` it means
/// the stream reached the end. Reaching the end of the stream is not
/// an error condition.
pub fn readAtLeast(self: Self, buffer: []u8, len: usize) anyerror!usize {
    assert(len <= buffer.len);
    var index: usize = 0;
    while (index < len) {
        const amt = try self.read(buffer[index..]);
        if (amt == 0) break;
        index += amt;
    }
    return index;
}

/// If the number read would be smaller than `buf.len`, `error.EndOfStream` is returned instead.
pub fn readNoEof(self: Self, buf: []u8) anyerror!void {
    const amt_read = try self.readAll(buf);
    if (amt_read < buf.len) return error.EndOfStream;
}

/// Appends to the `std.ArrayList` contents by reading from the stream
/// until end of stream is found.
/// If the number of bytes appended would exceed `max_append_size`,
/// `error.StreamTooLong` is returned
/// and the `std.ArrayList` has exactly `max_append_size` bytes appended.
pub fn readAllArrayList(
    self: Self,
    array_list: *std.ArrayList(u8),
    max_append_size: usize,
) anyerror!void {
    return self.readAllArrayListAligned(null, array_list, max_append_size);
}

pub fn readAllArrayListAligned(
    self: Self,
    comptime alignment: ?Alignment,
    array_list: *std.ArrayListAligned(u8, alignment),
    max_append_size: usize,
) anyerror!void {
    try array_list.ensureTotalCapacity(@min(max_append_size, 4096));
    const original_len = array_list.items.len;
    var start_index: usize = original_len;
    while (true) {
        array_list.expandToCapacity();
        const dest_slice = array_list.items[start_index..];
        const bytes_read = try self.readAll(dest_slice);
        start_index += bytes_read;

        if (start_index - original_len > max_append_size) {
            array_list.shrinkAndFree(original_len + max_append_size);
            return error.StreamTooLong;
        }

        if (bytes_read != dest_slice.len) {
            array_list.shrinkAndFree(start_index);
            return;
        }

        // This will trigger ArrayList to expand superlinearly at whatever its growth rate is.
        try array_list.ensureTotalCapacity(start_index + 1);
    }
}

/// Allocates enough memory to hold all the contents of the stream. If the allocated
/// memory would be greater than `max_size`, returns `error.StreamTooLong`.
/// Caller owns returned memory.
/// If this function returns an error, the contents from the stream read so far are lost.
pub fn readAllAlloc(self: Self, allocator: mem.Allocator, max_size: usize) anyerror![]u8 {
    var array_list = std.ArrayList(u8).init(allocator);
    defer array_list.deinit();
    try self.readAllArrayList(&array_list, max_size);
    return try array_list.toOwnedSlice();
}

/// Deprecated: use `streamUntilDelimiter` with ArrayList's writer instead.
/// Replaces the `std.ArrayList` contents by reading from the stream until `delimiter` is found.
/// Does not include the delimiter in the result.
/// If the `std.ArrayList` length would exceed `max_size`, `error.StreamTooLong` is returned and the
/// `std.ArrayList` is populated with `max_size` bytes from the stream.
pub fn readUntilDelimiterArrayList(
    self: Self,
    array_list: *std.ArrayList(u8),
    delimiter: u8,
    max_size: usize,
) anyerror!void {
    array_list.shrinkRetainingCapacity(0);
    try self.streamUntilDelimiter(array_list.writer(), delimiter, max_size);
}

/// Deprecated: use `streamUntilDelimiter` with ArrayList's writer instead.
/// Allocates enough memory to read until `delimiter`. If the allocated
/// memory would be greater than `max_size`, returns `error.StreamTooLong`.
/// Caller owns returned memory.
/// If this function returns an error, the contents from the stream read so far are lost.
pub fn readUntilDelimiterAlloc(
    self: Self,
    allocator: mem.Allocator,
    delimiter: u8,
    max_size: usize,
) anyerror![]u8 {
    var array_list = std.ArrayList(u8).init(allocator);
    defer array_list.deinit();
    try self.streamUntilDelimiter(array_list.writer(), delimiter, max_size);
    return try array_list.toOwnedSlice();
}

/// Deprecated: use `streamUntilDelimiter` with FixedBufferStream's writer instead.
/// Reads from the stream until specified byte is found. If the buffer is not
/// large enough to hold the entire contents, `error.StreamTooLong` is returned.
/// If end-of-stream is found, `error.EndOfStream` is returned.
/// Returns a slice of the stream data, with ptr equal to `buf.ptr`. The
/// delimiter byte is written to the output buffer but is not included
/// in the returned slice.
pub fn readUntilDelimiter(self: Self, buf: []u8, delimiter: u8) anyerror![]u8 {
    var fbs = std.io.fixedBufferStream(buf);
    try self.streamUntilDelimiter(fbs.writer(), delimiter, fbs.buffer.len);
    const output = fbs.getWritten();
    buf[output.len] = delimiter; // emulating old behaviour
    return output;
}

/// Deprecated: use `streamUntilDelimiter` with ArrayList's (or any other's) writer instead.
/// Allocates enough memory to read until `delimiter` or end-of-stream.
/// If the allocated memory would be greater than `max_size`, returns
/// `error.StreamTooLong`. If end-of-stream is found, returns the rest
/// of the stream. If this function is called again after that, returns
/// null.
/// Caller owns returned memory.
/// If this function returns an error, the contents from the stream read so far are lost.
pub fn readUntilDelimiterOrEofAlloc(
    self: Self,
    allocator: mem.Allocator,
    delimiter: u8,
    max_size: usize,
) anyerror!?[]u8 {
    var array_list = std.ArrayList(u8).init(allocator);
    defer array_list.deinit();
    self.streamUntilDelimiter(array_list.writer(), delimiter, max_size) catch |err| switch (err) {
        error.EndOfStream => if (array_list.items.len == 0) {
            return null;
        },
        else => |e| return e,
    };
    return try array_list.toOwnedSlice();
}

/// Deprecated: use `streamUntilDelimiter` with FixedBufferStream's writer instead.
/// Reads from the stream until specified byte is found. If the buffer is not
/// large enough to hold the entire contents, `error.StreamTooLong` is returned.
/// If end-of-stream is found, returns the rest of the stream. If this
/// function is called again after that, returns null.
/// Returns a slice of the stream data, with ptr equal to `buf.ptr`. The
/// delimiter byte is written to the output buffer but is not included
/// in the returned slice.
pub fn readUntilDelimiterOrEof(self: Self, buf: []u8, delimiter: u8) anyerror!?[]u8 {
    var fbs = std.io.fixedBufferStream(buf);
    self.streamUntilDelimiter(fbs.writer(), delimiter, fbs.buffer.len) catch |err| switch (err) {
        error.EndOfStream => if (fbs.getWritten().len == 0) {
            return null;
        },

        else => |e| return e,
    };
    const output = fbs.getWritten();
    buf[output.len] = delimiter; // emulating old behaviour
    return output;
}

/// Appends to the `writer` contents by reading from the stream until `delimiter` is found.
/// Does not write the delimiter itself.
/// If `optional_max_size` is not null and amount of written bytes exceeds `optional_max_size`,
/// returns `error.StreamTooLong` and finishes appending.
/// If `optional_max_size` is null, appending is unbounded.
pub fn streamUntilDelimiter(
    self: Self,
    writer: anytype,
    delimiter: u8,
    optional_max_size: ?usize,
) anyerror!void {
    if (optional_max_size) |max_size| {
        for (0..max_size) |_| {
            const byte: u8 = try self.readByte();
            if (byte == delimiter) return;
            try writer.writeByte(byte);
        }
        return error.StreamTooLong;
    } else {
        while (true) {
            const byte: u8 = try self.readByte();
            if (byte == delimiter) return;
            try writer.writeByte(byte);
        }
        // Can not throw `error.StreamTooLong` since there are no boundary.
    }
}

/// Reads from the stream until specified byte is found, discarding all data,
/// including the delimiter.
/// If end-of-stream is found, this function succeeds.
pub fn skipUntilDelimiterOrEof(self: Self, delimiter: u8) anyerror!void {
    while (true) {
        const byte = self.readByte() catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        if (byte == delimiter) return;
    }
}

/// Reads 1 byte from the stream or returns `error.EndOfStream`.
pub fn readByte(self: Self) anyerror!u8 {
    var result: [1]u8 = undefined;
    const amt_read = try self.read(result[0..]);
    if (amt_read < 1) return error.EndOfStream;
    return result[0];
}

/// Same as `readByte` except the returned byte is signed.
pub fn readByteSigned(self: Self) anyerror!i8 {
    return @as(i8, @bitCast(try self.readByte()));
}

/// Reads exactly `num_bytes` bytes and returns as an array.
/// `num_bytes` must be comptime-known
pub fn readBytesNoEof(self: Self, comptime num_bytes: usize) anyerror![num_bytes]u8 {
    var bytes: [num_bytes]u8 = undefined;
    try self.readNoEof(&bytes);
    return bytes;
}

/// Reads bytes until `bounded.len` is equal to `num_bytes`,
/// or the stream ends.
///
/// * it is assumed that `num_bytes` will not exceed `bounded.capacity()`
pub fn readIntoBoundedBytes(
    self: Self,
    comptime num_bytes: usize,
    bounded: *std.BoundedArray(u8, num_bytes),
) anyerror!void {
    while (bounded.len < num_bytes) {
        // get at most the number of bytes free in the bounded array
        const bytes_read = try self.read(bounded.unusedCapacitySlice());
        if (bytes_read == 0) return;

        // bytes_read will never be larger than @TypeOf(bounded.len)
        // due to `self.read` being bounded by `bounded.unusedCapacitySlice()`
        bounded.len += @as(@TypeOf(bounded.len), @intCast(bytes_read));
    }
}

/// Reads at most `num_bytes` and returns as a bounded array.
pub fn readBoundedBytes(self: Self, comptime num_bytes: usize) anyerror!std.BoundedArray(u8, num_bytes) {
    var result = std.BoundedArray(u8, num_bytes){};
    try self.readIntoBoundedBytes(num_bytes, &result);
    return result;
}

pub inline fn readInt(self: Self, comptime T: type, endian: std.builtin.Endian) anyerror!T {
    const bytes = try self.readBytesNoEof(@divExact(@typeInfo(T).int.bits, 8));
    return mem.readInt(T, &bytes, endian);
}

pub fn readVarInt(
    self: Self,
    comptime ReturnType: type,
    endian: std.builtin.Endian,
    size: usize,
) anyerror!ReturnType {
    assert(size <= @sizeOf(ReturnType));
    var bytes_buf: [@sizeOf(ReturnType)]u8 = undefined;
    const bytes = bytes_buf[0..size];
    try self.readNoEof(bytes);
    return mem.readVarInt(ReturnType, bytes, endian);
}

/// Optional parameters for `skipBytes`
pub const SkipBytesOptions = struct {
    buf_size: usize = 512,
};

// `num_bytes` is a `u64` to match `off_t`
/// Reads `num_bytes` bytes from the stream and discards them
pub fn skipBytes(self: Self, num_bytes: u64, comptime options: SkipBytesOptions) anyerror!void {
    var buf: [options.buf_size]u8 = undefined;
    var remaining = num_bytes;

    while (remaining > 0) {
        const amt = @min(remaining, options.buf_size);
        try self.readNoEof(buf[0..amt]);
        remaining -= amt;
    }
}

/// Reads `slice.len` bytes from the stream and returns if they are the same as the passed slice
pub fn isBytes(self: Self, slice: []const u8) anyerror!bool {
    var i: usize = 0;
    var matches = true;
    while (i < slice.len) : (i += 1) {
        if (slice[i] != try self.readByte()) {
            matches = false;
        }
    }
    return matches;
}

pub fn readStruct(self: Self, comptime T: type) anyerror!T {
    // Only extern and packed structs have defined in-memory layout.
    comptime assert(@typeInfo(T).@"struct".layout != .auto);
    var res: [1]T = undefined;
    try self.readNoEof(mem.sliceAsBytes(res[0..]));
    return res[0];
}

pub fn readStructEndian(self: Self, comptime T: type, endian: std.builtin.Endian) anyerror!T {
    var res = try self.readStruct(T);
    if (native_endian != endian) {
        mem.byteSwapAllFields(T, &res);
    }
    return res;
}

/// Reads an integer with the same size as the given enum's tag type. If the integer matches
/// an enum tag, casts the integer to the enum tag and returns it. Otherwise, returns an `error.InvalidValue`.
/// TODO optimization taking advantage of most fields being in order
pub fn readEnum(self: Self, comptime Enum: type, endian: std.builtin.Endian) anyerror!Enum {
    const E = error{
        /// An integer was read, but it did not match any of the tags in the supplied enum.
        InvalidValue,
    };
    const type_info = @typeInfo(Enum).@"enum";
    const tag = try self.readInt(type_info.tag_type, endian);

    inline for (std.meta.fields(Enum)) |field| {
        if (tag == field.value) {
            return @field(Enum, field.name);
        }
    }

    return E.InvalidValue;
}

/// Reads the stream until the end, ignoring all the data.
/// Returns the number of bytes discarded.
pub fn discard(self: Self) anyerror!u64 {
    var trash: [4096]u8 = undefined;
    var index: u64 = 0;
    while (true) {
        const n = try self.read(&trash);
        if (n == 0) return index;
        index += n;
    }
}

const std = @import("../std.zig");
const Self = @This();
const math = std.math;
const assert = std.debug.assert;
const mem = std.mem;
const testing = std.testing;
const native_endian = @import("builtin").target.cpu.arch.endian();
const Alignment = std.mem.Alignment;

test {
    _ = @import("Reader/test.zig");
}
const builtin = @import("builtin");
const std = @import("../../std.zig");
const testing = std.testing;

test "Reader" {
    var buf = "a\x02".*;
    var fis = std.io.fixedBufferStream(&buf);
    const reader = fis.reader();
    try testing.expect((try reader.readByte()) == 'a');
    try testing.expect((try reader.readEnum(enum(u8) {
        a = 0,
        b = 99,
        c = 2,
        d = 3,
    }, builtin.cpu.arch.endian())) == .c);
    try testing.expectError(error.EndOfStream, reader.readByte());
}

test "isBytes" {
    var fis = std.io.fixedBufferStream("foobar");
    const reader = fis.reader();
    try testing.expectEqual(true, try reader.isBytes("foo"));
    try testing.expectEqual(false, try reader.isBytes("qux"));
}

test "skipBytes" {
    var fis = std.io.fixedBufferStream("foobar");
    const reader = fis.reader();
    try reader.skipBytes(3, .{});
    try testing.expect(try reader.isBytes("bar"));
    try reader.skipBytes(0, .{});
    try testing.expectError(error.EndOfStream, reader.skipBytes(1, .{}));
}

test "readUntilDelimiterArrayList returns ArrayLists with bytes read until the delimiter, then EndOfStream" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).init(a);
    defer list.deinit();

    var fis = std.io.fixedBufferStream("0000\n1234\n");
    const reader = fis.reader();

    try reader.readUntilDelimiterArrayList(&list, '\n', 5);
    try std.testing.expectEqualStrings("0000", list.items);
    try reader.readUntilDelimiterArrayList(&list, '\n', 5);
    try std.testing.expectEqualStrings("1234", list.items);
    try std.testing.expectError(error.EndOfStream, reader.readUntilDelimiterArrayList(&list, '\n', 5));
}

test "readUntilDelimiterArrayList returns an empty ArrayList" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).init(a);
    defer list.deinit();

    var fis = std.io.fixedBufferStream("\n");
    const reader = fis.reader();

    try reader.readUntilDelimiterArrayList(&list, '\n', 5);
    try std.testing.expectEqualStrings("", list.items);
}

test "readUntilDelimiterArrayList returns StreamTooLong, then an ArrayList with bytes read until the delimiter" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).init(a);
    defer list.deinit();

    var fis = std.io.fixedBufferStream("1234567\n");
    const reader = fis.reader();

    try std.testing.expectError(error.StreamTooLong, reader.readUntilDelimiterArrayList(&list, '\n', 5));
    try std.testing.expectEqualStrings("12345", list.items);
    try reader.readUntilDelimiterArrayList(&list, '\n', 5);
    try std.testing.expectEqualStrings("67", list.items);
}

test "readUntilDelimiterArrayList returns EndOfStream" {
    const a = std.testing.allocator;
    var list = std.ArrayList(u8).init(a);
    defer list.deinit();

    var fis = std.io.fixedBufferStream("1234");
    const reader = fis.reader();

    try std.testing.expectError(error.EndOfStream, reader.readUntilDelimiterArrayList(&list, '\n', 5));
    try std.testing.expectEqualStrings("1234", list.items);
}

test "readUntilDelimiterAlloc returns ArrayLists with bytes read until the delimiter, then EndOfStream" {
    const a = std.testing.allocator;

    var fis = std.io.fixedBufferStream("0000\n1234\n");
    const reader = fis.reader();

    {
        const result = try reader.readUntilDelimiterAlloc(a, '\n', 5);
        defer a.free(result);
        try std.testing.expectEqualStrings("0000", result);
    }

    {
        const result = try reader.readUntilDelimiterAlloc(a, '\n', 5);
        defer a.free(result);
        try std.testing.expectEqualStrings("1234", result);
    }

    try std.testing.expectError(error.EndOfStream, reader.readUntilDelimiterAlloc(a, '\n', 5));
}

test "readUntilDelimiterAlloc returns an empty ArrayList" {
    const a = std.testing.allocator;

    var fis = std.io.fixedBufferStream("\n");
    const reader = fis.reader();

    {
        const result = try reader.readUntilDelimiterAlloc(a, '\n', 5);
        defer a.free(result);
        try std.testing.expectEqualStrings("", result);
    }
}

test "readUntilDelimiterAlloc returns StreamTooLong, then an ArrayList with bytes read until the delimiter" {
    const a = std.testing.allocator;

    var fis = std.io.fixedBufferStream("1234567\n");
    const reader = fis.reader();

    try std.testing.expectError(error.StreamTooLong, reader.readUntilDelimiterAlloc(a, '\n', 5));

    const result = try reader.readUntilDelimiterAlloc(a, '\n', 5);
    defer a.free(result);
    try std.testing.expectEqualStrings("67", result);
}

test "readUntilDelimiterAlloc returns EndOfStream" {
    const a = std.testing.allocator;

    var fis = std.io.fixedBufferStream("1234");
    const reader = fis.reader();

    try std.testing.expectError(error.EndOfStream, reader.readUntilDelimiterAlloc(a, '\n', 5));
}

test "readUntilDelimiter returns bytes read until the delimiter" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("0000\n1234\n");
    const reader = fis.reader();
    try std.testing.expectEqualStrings("0000", try reader.readUntilDelimiter(&buf, '\n'));
    try std.testing.expectEqualStrings("1234", try reader.readUntilDelimiter(&buf, '\n'));
}

test "readUntilDelimiter returns an empty string" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("\n");
    const reader = fis.reader();
    try std.testing.expectEqualStrings("", try reader.readUntilDelimiter(&buf, '\n'));
}

test "readUntilDelimiter returns StreamTooLong, then an empty string" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("12345\n");
    const reader = fis.reader();
    try std.testing.expectError(error.StreamTooLong, reader.readUntilDelimiter(&buf, '\n'));
    try std.testing.expectEqualStrings("", try reader.readUntilDelimiter(&buf, '\n'));
}

test "readUntilDelimiter returns StreamTooLong, then bytes read until the delimiter" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("1234567\n");
    const reader = fis.reader();
    try std.testing.expectError(error.StreamTooLong, reader.readUntilDelimiter(&buf, '\n'));
    try std.testing.expectEqualStrings("67", try reader.readUntilDelimiter(&buf, '\n'));
}

test "readUntilDelimiter returns EndOfStream" {
    {
        var buf: [5]u8 = undefined;
        var fis = std.io.fixedBufferStream("");
        const reader = fis.reader();
        try std.testing.expectError(error.EndOfStream, reader.readUntilDelimiter(&buf, '\n'));
    }
    {
        var buf: [5]u8 = undefined;
        var fis = std.io.fixedBufferStream("1234");
        const reader = fis.reader();
        try std.testing.expectError(error.EndOfStream, reader.readUntilDelimiter(&buf, '\n'));
    }
}

test "readUntilDelimiter returns bytes read until delimiter, then EndOfStream" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("1234\n");
    const reader = fis.reader();
    try std.testing.expectEqualStrings("1234", try reader.readUntilDelimiter(&buf, '\n'));
    try std.testing.expectError(error.EndOfStream, reader.readUntilDelimiter(&buf, '\n'));
}

test "readUntilDelimiter returns StreamTooLong, then EndOfStream" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("12345");
    const reader = fis.reader();
    try std.testing.expectError(error.StreamTooLong, reader.readUntilDelimiter(&buf, '\n'));
    try std.testing.expectError(error.EndOfStream, reader.readUntilDelimiter(&buf, '\n'));
}

test "readUntilDelimiter writes all bytes read to the output buffer" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("0000\n12345");
    const reader = fis.reader();
    _ = try reader.readUntilDelimiter(&buf, '\n');
    try std.testing.expectEqualStrings("0000\n", &buf);
    try std.testing.expectError(error.StreamTooLong, reader.readUntilDelimiter(&buf, '\n'));
    try std.testing.expectEqualStrings("12345", &buf);
}

test "readUntilDelimiterOrEofAlloc returns ArrayLists with bytes read until the delimiter, then EndOfStream" {
    const a = std.testing.allocator;

    var fis = std.io.fixedBufferStream("0000\n1234\n");
    const reader = fis.reader();

    {
        const result = (try reader.readUntilDelimiterOrEofAlloc(a, '\n', 5)).?;
        defer a.free(result);
        try std.testing.expectEqualStrings("0000", result);
    }

    {
        const result = (try reader.readUntilDelimiterOrEofAlloc(a, '\n', 5)).?;
        defer a.free(result);
        try std.testing.expectEqualStrings("1234", result);
    }

    try std.testing.expect((try reader.readUntilDelimiterOrEofAlloc(a, '\n', 5)) == null);
}

test "readUntilDelimiterOrEofAlloc returns an empty ArrayList" {
    const a = std.testing.allocator;

    var fis = std.io.fixedBufferStream("\n");
    const reader = fis.reader();

    {
        const result = (try reader.readUntilDelimiterOrEofAlloc(a, '\n', 5)).?;
        defer a.free(result);
        try std.testing.expectEqualStrings("", result);
    }
}

test "readUntilDelimiterOrEofAlloc returns StreamTooLong, then an ArrayList with bytes read until the delimiter" {
    const a = std.testing.allocator;

    var fis = std.io.fixedBufferStream("1234567\n");
    const reader = fis.reader();

    try std.testing.expectError(error.StreamTooLong, reader.readUntilDelimiterOrEofAlloc(a, '\n', 5));

    const result = (try reader.readUntilDelimiterOrEofAlloc(a, '\n', 5)).?;
    defer a.free(result);
    try std.testing.expectEqualStrings("67", result);
}

test "readUntilDelimiterOrEof returns bytes read until the delimiter" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("0000\n1234\n");
    const reader = fis.reader();
    try std.testing.expectEqualStrings("0000", (try reader.readUntilDelimiterOrEof(&buf, '\n')).?);
    try std.testing.expectEqualStrings("1234", (try reader.readUntilDelimiterOrEof(&buf, '\n')).?);
}

test "readUntilDelimiterOrEof returns an empty string" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("\n");
    const reader = fis.reader();
    try std.testing.expectEqualStrings("", (try reader.readUntilDelimiterOrEof(&buf, '\n')).?);
}

test "readUntilDelimiterOrEof returns StreamTooLong, then an empty string" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("12345\n");
    const reader = fis.reader();
    try std.testing.expectError(error.StreamTooLong, reader.readUntilDelimiterOrEof(&buf, '\n'));
    try std.testing.expectEqualStrings("", (try reader.readUntilDelimiterOrEof(&buf, '\n')).?);
}

test "readUntilDelimiterOrEof returns StreamTooLong, then bytes read until the delimiter" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("1234567\n");
    const reader = fis.reader();
    try std.testing.expectError(error.StreamTooLong, reader.readUntilDelimiterOrEof(&buf, '\n'));
    try std.testing.expectEqualStrings("67", (try reader.readUntilDelimiterOrEof(&buf, '\n')).?);
}

test "readUntilDelimiterOrEof returns null" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("");
    const reader = fis.reader();
    try std.testing.expect((try reader.readUntilDelimiterOrEof(&buf, '\n')) == null);
}

test "readUntilDelimiterOrEof returns bytes read until delimiter, then null" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("1234\n");
    const reader = fis.reader();
    try std.testing.expectEqualStrings("1234", (try reader.readUntilDelimiterOrEof(&buf, '\n')).?);
    try std.testing.expect((try reader.readUntilDelimiterOrEof(&buf, '\n')) == null);
}

test "readUntilDelimiterOrEof returns bytes read until end-of-stream" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("1234");
    const reader = fis.reader();
    try std.testing.expectEqualStrings("1234", (try reader.readUntilDelimiterOrEof(&buf, '\n')).?);
}

test "readUntilDelimiterOrEof returns StreamTooLong, then bytes read until end-of-stream" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("1234567");
    const reader = fis.reader();
    try std.testing.expectError(error.StreamTooLong, reader.readUntilDelimiterOrEof(&buf, '\n'));
    try std.testing.expectEqualStrings("67", (try reader.readUntilDelimiterOrEof(&buf, '\n')).?);
}

test "readUntilDelimiterOrEof writes all bytes read to the output buffer" {
    var buf: [5]u8 = undefined;
    var fis = std.io.fixedBufferStream("0000\n12345");
    const reader = fis.reader();
    _ = try reader.readUntilDelimiterOrEof(&buf, '\n');
    try std.testing.expectEqualStrings("0000\n", &buf);
    try std.testing.expectError(error.StreamTooLong, reader.readUntilDelimiterOrEof(&buf, '\n'));
    try std.testing.expectEqualStrings("12345", &buf);
}

test "streamUntilDelimiter writes all bytes without delimiter to the output" {
    const input_string = "some_string_with_delimiter!";
    var input_fbs = std.io.fixedBufferStream(input_string);
    const reader = input_fbs.reader();

    var output: [input_string.len]u8 = undefined;
    var output_fbs = std.io.fixedBufferStream(&output);
    const writer = output_fbs.writer();

    try reader.streamUntilDelimiter(writer, '!', input_fbs.buffer.len);
    try std.testing.expectEqualStrings("some_string_with_delimiter", output_fbs.getWritten());
    try std.testing.expectError(error.EndOfStream, reader.streamUntilDelimiter(writer, '!', input_fbs.buffer.len));

    input_fbs.reset();
    output_fbs.reset();

    try std.testing.expectError(error.StreamTooLong, reader.streamUntilDelimiter(writer, '!', 5));
}

test "readBoundedBytes correctly reads into a new bounded array" {
    const test_string = "abcdefg";
    var fis = std.io.fixedBufferStream(test_string);
    const reader = fis.reader();

    var array = try reader.readBoundedBytes(10000);
    try testing.expectEqualStrings(array.slice(), test_string);
}

test "readIntoBoundedBytes correctly reads into a provided bounded array" {
    const test_string = "abcdefg";
    var fis = std.io.fixedBufferStream(test_string);
    const reader = fis.reader();

    var bounded_array = std.BoundedArray(u8, 10000){};

    // compile time error if the size is not the same at the provided `bounded.capacity()`
    try reader.readIntoBoundedBytes(10000, &bounded_array);
    try testing.expectEqualStrings(bounded_array.slice(), test_string);
}
const std = @import("../std.zig");

pub fn SeekableStream(
    comptime Context: type,
    comptime SeekErrorType: type,
    comptime GetSeekPosErrorType: type,
    comptime seekToFn: fn (context: Context, pos: u64) SeekErrorType!void,
    comptime seekByFn: fn (context: Context, pos: i64) SeekErrorType!void,
    comptime getPosFn: fn (context: Context) GetSeekPosErrorType!u64,
    comptime getEndPosFn: fn (context: Context) GetSeekPosErrorType!u64,
) type {
    return struct {
        context: Context,

        const Self = @This();
        pub const SeekError = SeekErrorType;
        pub const GetSeekPosError = GetSeekPosErrorType;

        pub fn seekTo(self: Self, pos: u64) SeekError!void {
            return seekToFn(self.context, pos);
        }

        pub fn seekBy(self: Self, amt: i64) SeekError!void {
            return seekByFn(self.context, amt);
        }

        pub fn getEndPos(self: Self) GetSeekPosError!u64 {
            return getEndPosFn(self.context);
        }

        pub fn getPos(self: Self) GetSeekPosError!u64 {
            return getPosFn(self.context);
        }
    };
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const io = std.io;

/// Provides `io.Reader`, `io.Writer`, and `io.SeekableStream` for in-memory buffers as
/// well as files.
/// For memory sources, if the supplied byte buffer is const, then `io.Writer` is not available.
/// The error set of the stream functions is the error set of the corresponding file functions.
pub const StreamSource = union(enum) {
    // TODO: expose UEFI files to std.os in a way that allows this to be true
    const has_file = (builtin.os.tag != .freestanding and builtin.os.tag != .uefi);

    /// The stream access is redirected to this buffer.
    buffer: io.FixedBufferStream([]u8),

    /// The stream access is redirected to this buffer.
    /// Writing to the source will always yield `error.AccessDenied`.
    const_buffer: io.FixedBufferStream([]const u8),

    /// The stream access is redirected to this file.
    /// On freestanding, this must never be initialized!
    file: if (has_file) std.fs.File else void,

    pub const ReadError = io.FixedBufferStream([]u8).ReadError || (if (has_file) std.fs.File.ReadError else error{});
    pub const WriteError = error{AccessDenied} || io.FixedBufferStream([]u8).WriteError || (if (has_file) std.fs.File.WriteError else error{});
    pub const SeekError = io.FixedBufferStream([]u8).SeekError || (if (has_file) std.fs.File.SeekError else error{});
    pub const GetSeekPosError = io.FixedBufferStream([]u8).GetSeekPosError || (if (has_file) std.fs.File.GetSeekPosError else error{});

    pub const Reader = io.Reader(*StreamSource, ReadError, read);
    pub const Writer = io.Writer(*StreamSource, WriteError, write);
    pub const SeekableStream = io.SeekableStream(
        *StreamSource,
        SeekError,
        GetSeekPosError,
        seekTo,
        seekBy,
        getPos,
        getEndPos,
    );

    pub fn read(self: *StreamSource, dest: []u8) ReadError!usize {
        switch (self.*) {
            .buffer => |*x| return x.read(dest),
            .const_buffer => |*x| return x.read(dest),
            .file => |x| if (!has_file) unreachable else return x.read(dest),
        }
    }

    pub fn write(self: *StreamSource, bytes: []const u8) WriteError!usize {
        switch (self.*) {
            .buffer => |*x| return x.write(bytes),
            .const_buffer => return error.AccessDenied,
            .file => |x| if (!has_file) unreachable else return x.write(bytes),
        }
    }

    pub fn seekTo(self: *StreamSource, pos: u64) SeekError!void {
        switch (self.*) {
            .buffer => |*x| return x.seekTo(pos),
            .const_buffer => |*x| return x.seekTo(pos),
            .file => |x| if (!has_file) unreachable else return x.seekTo(pos),
        }
    }

    pub fn seekBy(self: *StreamSource, amt: i64) SeekError!void {
        switch (self.*) {
            .buffer => |*x| return x.seekBy(amt),
            .const_buffer => |*x| return x.seekBy(amt),
            .file => |x| if (!has_file) unreachable else return x.seekBy(amt),
        }
    }

    pub fn getEndPos(self: *StreamSource) GetSeekPosError!u64 {
        switch (self.*) {
            .buffer => |*x| return x.getEndPos(),
            .const_buffer => |*x| return x.getEndPos(),
            .file => |x| if (!has_file) unreachable else return x.getEndPos(),
        }
    }

    pub fn getPos(self: *StreamSource) GetSeekPosError!u64 {
        switch (self.*) {
            .buffer => |*x| return x.getPos(),
            .const_buffer => |*x| return x.getPos(),
            .file => |x| if (!has_file) unreachable else return x.getPos(),
        }
    }

    pub fn reader(self: *StreamSource) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: *StreamSource) Writer {
        return .{ .context = self };
    }

    pub fn seekableStream(self: *StreamSource) SeekableStream {
        return .{ .context = self };
    }
};

test "refs" {
    std.testing.refAllDecls(StreamSource);
}

test "mutable buffer" {
    var buffer: [64]u8 = undefined;
    var source = StreamSource{ .buffer = std.io.fixedBufferStream(&buffer) };

    var writer = source.writer();

    try writer.writeAll("Hello, World!");

    try std.testing.expectEqualStrings("Hello, World!", source.buffer.getWritten());
}

test "const buffer" {
    const buffer: [64]u8 = "Hello, World!".* ++ ([1]u8{0xAA} ** 51);
    var source = StreamSource{ .const_buffer = std.io.fixedBufferStream(&buffer) };

    var reader = source.reader();

    var dst_buffer: [13]u8 = undefined;
    try reader.readNoEof(&dst_buffer);

    try std.testing.expectEqualStrings("Hello, World!", &dst_buffer);
}
const std = @import("std");
const io = std.io;
const DefaultPrng = std.Random.DefaultPrng;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const mem = std.mem;
const fs = std.fs;
const File = std.fs.File;
const native_endian = @import("builtin").target.cpu.arch.endian();

const tmpDir = std.testing.tmpDir;

test "write a file, read it, then delete it" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    var data: [1024]u8 = undefined;
    var prng = DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    random.bytes(data[0..]);
    const tmp_file_name = "temp_test_file.txt";
    {
        var file = try tmp.dir.createFile(tmp_file_name, .{});
        defer file.close();

        var buf_stream = io.bufferedWriter(file.writer());
        const st = buf_stream.writer();
        try st.print("begin", .{});
        try st.writeAll(data[0..]);
        try st.print("end", .{});
        try buf_stream.flush();
    }

    {
        // Make sure the exclusive flag is honored.
        try expectError(File.OpenError.PathAlreadyExists, tmp.dir.createFile(tmp_file_name, .{ .exclusive = true }));
    }

    {
        var file = try tmp.dir.openFile(tmp_file_name, .{});
        defer file.close();

        const file_size = try file.getEndPos();
        const expected_file_size: u64 = "begin".len + data.len + "end".len;
        try expectEqual(expected_file_size, file_size);

        var buf_stream = io.bufferedReader(file.reader());
        const st = buf_stream.reader();
        const contents = try st.readAllAlloc(std.testing.allocator, 2 * 1024);
        defer std.testing.allocator.free(contents);

        try expect(mem.eql(u8, contents[0.."begin".len], "begin"));
        try expect(mem.eql(u8, contents["begin".len .. contents.len - "end".len], &data));
        try expect(mem.eql(u8, contents[contents.len - "end".len ..], "end"));
    }
    try tmp.dir.deleteFile(tmp_file_name);
}

test "BitStreams with File Stream" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "temp_test_file.txt";
    {
        var file = try tmp.dir.createFile(tmp_file_name, .{});
        defer file.close();

        var bit_stream = io.bitWriter(native_endian, file.writer());

        try bit_stream.writeBits(@as(u2, 1), 1);
        try bit_stream.writeBits(@as(u5, 2), 2);
        try bit_stream.writeBits(@as(u128, 3), 3);
        try bit_stream.writeBits(@as(u8, 4), 4);
        try bit_stream.writeBits(@as(u9, 5), 5);
        try bit_stream.writeBits(@as(u1, 1), 1);
        try bit_stream.flushBits();
    }
    {
        var file = try tmp.dir.openFile(tmp_file_name, .{});
        defer file.close();

        var bit_stream = io.bitReader(native_endian, file.reader());

        var out_bits: u16 = undefined;

        try expect(1 == try bit_stream.readBits(u2, 1, &out_bits));
        try expect(out_bits == 1);
        try expect(2 == try bit_stream.readBits(u5, 2, &out_bits));
        try expect(out_bits == 2);
        try expect(3 == try bit_stream.readBits(u128, 3, &out_bits));
        try expect(out_bits == 3);
        try expect(4 == try bit_stream.readBits(u8, 4, &out_bits));
        try expect(out_bits == 4);
        try expect(5 == try bit_stream.readBits(u9, 5, &out_bits));
        try expect(out_bits == 5);
        try expect(1 == try bit_stream.readBits(u1, 1, &out_bits));
        try expect(out_bits == 1);

        try expectError(error.EndOfStream, bit_stream.readBitsNoEof(u1, 1));
    }
    try tmp.dir.deleteFile(tmp_file_name);
}

test "File seek ops" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "temp_test_file.txt";
    var file = try tmp.dir.createFile(tmp_file_name, .{});
    defer file.close();

    try file.writeAll(&([_]u8{0x55} ** 8192));

    // Seek to the end
    try file.seekFromEnd(0);
    try expect((try file.getPos()) == try file.getEndPos());
    // Negative delta
    try file.seekBy(-4096);
    try expect((try file.getPos()) == 4096);
    // Positive delta
    try file.seekBy(10);
    try expect((try file.getPos()) == 4106);
    // Absolute position
    try file.seekTo(1234);
    try expect((try file.getPos()) == 1234);
}

test "setEndPos" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "temp_test_file.txt";
    var file = try tmp.dir.createFile(tmp_file_name, .{});
    defer file.close();

    // Verify that the file size changes and the file offset is not moved
    try std.testing.expect((try file.getEndPos()) == 0);
    try std.testing.expect((try file.getPos()) == 0);
    try file.setEndPos(8192);
    try std.testing.expect((try file.getEndPos()) == 8192);
    try std.testing.expect((try file.getPos()) == 0);
    try file.seekTo(100);
    try file.setEndPos(4096);
    try std.testing.expect((try file.getEndPos()) == 4096);
    try std.testing.expect((try file.getPos()) == 100);
    try file.setEndPos(0);
    try std.testing.expect((try file.getEndPos()) == 0);
    try std.testing.expect((try file.getPos()) == 100);
}

test "updateTimes" {
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "just_a_temporary_file.txt";
    var file = try tmp.dir.createFile(tmp_file_name, .{ .read = true });
    defer file.close();

    const stat_old = try file.stat();
    // Set atime and mtime to 5s before
    try file.updateTimes(
        stat_old.atime - 5 * std.time.ns_per_s,
        stat_old.mtime - 5 * std.time.ns_per_s,
    );
    const stat_new = try file.stat();
    try expect(stat_new.atime < stat_old.atime);
    try expect(stat_new.mtime < stat_old.mtime);
}

test "GenericReader methods can return error.EndOfStream" {
    // https://github.com/ziglang/zig/issues/17733
    var fbs = std.io.fixedBufferStream("");
    try std.testing.expectError(
        error.EndOfStream,
        fbs.reader().readEnum(enum(u8) { a, b }, .little),
    );
    try std.testing.expectError(
        error.EndOfStream,
        fbs.reader().isBytes("foo"),
    );
}
const std = @import("std");
const builtin = @import("builtin");
const File = std.fs.File;
const process = std.process;
const windows = std.os.windows;
const native_os = builtin.os.tag;

/// Detect suitable TTY configuration options for the given file (commonly stdout/stderr).
/// This includes feature checks for ANSI escape codes and the Windows console API, as well as
/// respecting the `NO_COLOR` and `CLICOLOR_FORCE` environment variables to override the default.
/// Will attempt to enable ANSI escape code support if necessary/possible.
pub fn detectConfig(file: File) Config {
    const force_color: ?bool = if (builtin.os.tag == .wasi)
        null // wasi does not support environment variables
    else if (process.hasNonEmptyEnvVarConstant("NO_COLOR"))
        false
    else if (process.hasNonEmptyEnvVarConstant("CLICOLOR_FORCE"))
        true
    else
        null;

    if (force_color == false) return .no_color;

    if (file.getOrEnableAnsiEscapeSupport()) return .escape_codes;

    if (native_os == .windows and file.isTty()) {
        var info: windows.CONSOLE_SCREEN_BUFFER_INFO = undefined;
        if (windows.kernel32.GetConsoleScreenBufferInfo(file.handle, &info) == windows.FALSE) {
            return if (force_color == true) .escape_codes else .no_color;
        }
        return .{ .windows_api = .{
            .handle = file.handle,
            .reset_attributes = info.wAttributes,
        } };
    }

    return if (force_color == true) .escape_codes else .no_color;
}

pub const Color = enum {
    black,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    bright_black,
    bright_red,
    bright_green,
    bright_yellow,
    bright_blue,
    bright_magenta,
    bright_cyan,
    bright_white,
    dim,
    bold,
    reset,
};

/// Provides simple functionality for manipulating the terminal in some way,
/// such as coloring text, etc.
pub const Config = union(enum) {
    no_color,
    escape_codes,
    windows_api: if (native_os == .windows) WindowsContext else void,

    pub const WindowsContext = struct {
        handle: File.Handle,
        reset_attributes: u16,
    };

    pub fn setColor(
        conf: Config,
        writer: anytype,
        color: Color,
    ) (@typeInfo(@TypeOf(writer.writeAll(""))).error_union.error_set ||
        windows.SetConsoleTextAttributeError)!void {
        nosuspend switch (conf) {
            .no_color => return,
            .escape_codes => {
                const color_string = switch (color) {
                    .black => "\x1b[30m",
                    .red => "\x1b[31m",
                    .green => "\x1b[32m",
                    .yellow => "\x1b[33m",
                    .blue => "\x1b[34m",
                    .magenta => "\x1b[35m",
                    .cyan => "\x1b[36m",
                    .white => "\x1b[37m",
                    .bright_black => "\x1b[90m",
                    .bright_red => "\x1b[91m",
                    .bright_green => "\x1b[92m",
                    .bright_yellow => "\x1b[93m",
                    .bright_blue => "\x1b[94m",
                    .bright_magenta => "\x1b[95m",
                    .bright_cyan => "\x1b[96m",
                    .bright_white => "\x1b[97m",
                    .bold => "\x1b[1m",
                    .dim => "\x1b[2m",
                    .reset => "\x1b[0m",
                };
                try writer.writeAll(color_string);
            },
            .windows_api => |ctx| if (native_os == .windows) {
                const attributes = switch (color) {
                    .black => 0,
                    .red => windows.FOREGROUND_RED,
                    .green => windows.FOREGROUND_GREEN,
                    .yellow => windows.FOREGROUND_RED | windows.FOREGROUND_GREEN,
                    .blue => windows.FOREGROUND_BLUE,
                    .magenta => windows.FOREGROUND_RED | windows.FOREGROUND_BLUE,
                    .cyan => windows.FOREGROUND_GREEN | windows.FOREGROUND_BLUE,
                    .white => windows.FOREGROUND_RED | windows.FOREGROUND_GREEN | windows.FOREGROUND_BLUE,
                    .bright_black => windows.FOREGROUND_INTENSITY,
                    .bright_red => windows.FOREGROUND_RED | windows.FOREGROUND_INTENSITY,
                    .bright_green => windows.FOREGROUND_GREEN | windows.FOREGROUND_INTENSITY,
                    .bright_yellow => windows.FOREGROUND_RED | windows.FOREGROUND_GREEN | windows.FOREGROUND_INTENSITY,
                    .bright_blue => windows.FOREGROUND_BLUE | windows.FOREGROUND_INTENSITY,
                    .bright_magenta => windows.FOREGROUND_RED | windows.FOREGROUND_BLUE | windows.FOREGROUND_INTENSITY,
                    .bright_cyan => windows.FOREGROUND_GREEN | windows.FOREGROUND_BLUE | windows.FOREGROUND_INTENSITY,
                    .bright_white, .bold => windows.FOREGROUND_RED | windows.FOREGROUND_GREEN | windows.FOREGROUND_BLUE | windows.FOREGROUND_INTENSITY,
                    // "dim" is not supported using basic character attributes, but let's still make it do *something*.
                    // This matches the old behavior of TTY.Color before the bright variants were added.
                    .dim => windows.FOREGROUND_INTENSITY,
                    .reset => ctx.reset_attributes,
                };
                try windows.SetConsoleTextAttribute(ctx.handle, attributes);
            } else {
                unreachable;
            },
        };
    }
};
const std = @import("../std.zig");
const assert = std.debug.assert;
const mem = std.mem;
const native_endian = @import("builtin").target.cpu.arch.endian();

context: *const anyopaque,
writeFn: *const fn (context: *const anyopaque, bytes: []const u8) anyerror!usize,

const Self = @This();
pub const Error = anyerror;

pub fn write(self: Self, bytes: []const u8) anyerror!usize {
    return self.writeFn(self.context, bytes);
}

pub fn writeAll(self: Self, bytes: []const u8) anyerror!void {
    var index: usize = 0;
    while (index != bytes.len) {
        index += try self.write(bytes[index..]);
    }
}

pub fn print(self: Self, comptime format: []const u8, args: anytype) anyerror!void {
    return std.fmt.format(self, format, args);
}

pub fn writeByte(self: Self, byte: u8) anyerror!void {
    const array = [1]u8{byte};
    return self.writeAll(&array);
}

pub fn writeByteNTimes(self: Self, byte: u8, n: usize) anyerror!void {
    var bytes: [256]u8 = undefined;
    @memset(bytes[0..], byte);

    var remaining: usize = n;
    while (remaining > 0) {
        const to_write = @min(remaining, bytes.len);
        try self.writeAll(bytes[0..to_write]);
        remaining -= to_write;
    }
}

pub fn writeBytesNTimes(self: Self, bytes: []const u8, n: usize) anyerror!void {
    var i: usize = 0;
    while (i < n) : (i += 1) {
        try self.writeAll(bytes);
    }
}

pub inline fn writeInt(self: Self, comptime T: type, value: T, endian: std.builtin.Endian) anyerror!void {
    var bytes: [@divExact(@typeInfo(T).int.bits, 8)]u8 = undefined;
    mem.writeInt(std.math.ByteAlignedInt(@TypeOf(value)), &bytes, value, endian);
    return self.writeAll(&bytes);
}

pub fn writeStruct(self: Self, value: anytype) anyerror!void {
    // Only extern and packed structs have defined in-memory layout.
    comptime assert(@typeInfo(@TypeOf(value)).@"struct".layout != .auto);
    return self.writeAll(mem.asBytes(&value));
}

pub fn writeStructEndian(self: Self, value: anytype, endian: std.builtin.Endian) anyerror!void {
    // TODO: make sure this value is not a reference type
    if (native_endian == endian) {
        return self.writeStruct(value);
    } else {
        var copy = value;
        mem.byteSwapAllFields(@TypeOf(value), &copy);
        return self.writeStruct(copy);
    }
}

pub fn writeFile(self: Self, file: std.fs.File) anyerror!void {
    // TODO: figure out how to adjust std lib abstractions so that this ends up
    // doing sendfile or maybe even copy_file_range under the right conditions.
    var buf: [4000]u8 = undefined;
    while (true) {
        const n = try file.readAll(&buf);
        try self.writeAll(buf[0..n]);
        if (n < buf.len) return;
    }
}
//! JSON parsing and stringification conforming to RFC 8259. https://datatracker.ietf.org/doc/html/rfc8259
//!
//! The low-level `Scanner` API produces `Token`s from an input slice or successive slices of inputs,
//! The `Reader` API connects a `std.io.Reader` to a `Scanner`.
//!
//! The high-level `parseFromSlice` and `parseFromTokenSource` deserialize a JSON document into a Zig type.
//! Parse into a dynamically-typed `Value` to load any JSON value for runtime inspection.
//!
//! The low-level `writeStream` emits syntax-conformant JSON tokens to a `std.io.Writer`.
//! The high-level `stringify` serializes a Zig or `Value` type into JSON.

const builtin = @import("builtin");
const testing = @import("std").testing;
const ArrayList = @import("std").ArrayList;

test Scanner {
    var scanner = Scanner.initCompleteInput(testing.allocator, "{\"foo\": 123}\n");
    defer scanner.deinit();
    try testing.expectEqual(Token.object_begin, try scanner.next());
    try testing.expectEqualSlices(u8, "foo", (try scanner.next()).string);
    try testing.expectEqualSlices(u8, "123", (try scanner.next()).number);
    try testing.expectEqual(Token.object_end, try scanner.next());
    try testing.expectEqual(Token.end_of_document, try scanner.next());
}

test parseFromSlice {
    var parsed_str = try parseFromSlice([]const u8, testing.allocator, "\"a\\u0020b\"", .{});
    defer parsed_str.deinit();
    try testing.expectEqualSlices(u8, "a b", parsed_str.value);

    const T = struct { a: i32 = -1, b: [2]u8 };
    var parsed_struct = try parseFromSlice(T, testing.allocator, "{\"b\":\"xy\"}", .{});
    defer parsed_struct.deinit();
    try testing.expectEqual(@as(i32, -1), parsed_struct.value.a); // default value
    try testing.expectEqualSlices(u8, "xy", parsed_struct.value.b[0..]);
}

test Value {
    var parsed = try parseFromSlice(Value, testing.allocator, "{\"anything\": \"goes\"}", .{});
    defer parsed.deinit();
    try testing.expectEqualSlices(u8, "goes", parsed.value.object.get("anything").?.string);
}

test writeStream {
    var out = ArrayList(u8).init(testing.allocator);
    defer out.deinit();
    var write_stream = writeStream(out.writer(), .{ .whitespace = .indent_2 });
    defer write_stream.deinit();
    try write_stream.beginObject();
    try write_stream.objectField("foo");
    try write_stream.write(123);
    try write_stream.endObject();
    const expected =
        \\{
        \\  "foo": 123
        \\}
    ;
    try testing.expectEqualSlices(u8, expected, out.items);
}

test stringify {
    var out = ArrayList(u8).init(testing.allocator);
    defer out.deinit();

    const T = struct { a: i32, b: []const u8 };
    try stringify(T{ .a = 123, .b = "xy" }, .{}, out.writer());
    try testing.expectEqualSlices(u8, "{\"a\":123,\"b\":\"xy\"}", out.items);
}

pub const ObjectMap = @import("json/dynamic.zig").ObjectMap;
pub const Array = @import("json/dynamic.zig").Array;
pub const Value = @import("json/dynamic.zig").Value;

pub const ArrayHashMap = @import("json/hashmap.zig").ArrayHashMap;

pub const validate = @import("json/scanner.zig").validate;
pub const Error = @import("json/scanner.zig").Error;
pub const reader = @import("json/scanner.zig").reader;
pub const default_buffer_size = @import("json/scanner.zig").default_buffer_size;
pub const Token = @import("json/scanner.zig").Token;
pub const TokenType = @import("json/scanner.zig").TokenType;
pub const Diagnostics = @import("json/scanner.zig").Diagnostics;
pub const AllocWhen = @import("json/scanner.zig").AllocWhen;
pub const default_max_value_len = @import("json/scanner.zig").default_max_value_len;
pub const Reader = @import("json/scanner.zig").Reader;
pub const Scanner = @import("json/scanner.zig").Scanner;
pub const isNumberFormattedLikeAnInteger = @import("json/scanner.zig").isNumberFormattedLikeAnInteger;

pub const ParseOptions = @import("json/static.zig").ParseOptions;
pub const Parsed = @import("json/static.zig").Parsed;
pub const parseFromSlice = @import("json/static.zig").parseFromSlice;
pub const parseFromSliceLeaky = @import("json/static.zig").parseFromSliceLeaky;
pub const parseFromTokenSource = @import("json/static.zig").parseFromTokenSource;
pub const parseFromTokenSourceLeaky = @import("json/static.zig").parseFromTokenSourceLeaky;
pub const innerParse = @import("json/static.zig").innerParse;
pub const parseFromValue = @import("json/static.zig").parseFromValue;
pub const parseFromValueLeaky = @import("json/static.zig").parseFromValueLeaky;
pub const innerParseFromValue = @import("json/static.zig").innerParseFromValue;
pub const ParseError = @import("json/static.zig").ParseError;
pub const ParseFromValueError = @import("json/static.zig").ParseFromValueError;

pub const StringifyOptions = @import("json/stringify.zig").StringifyOptions;
pub const stringify = @import("json/stringify.zig").stringify;
pub const stringifyMaxDepth = @import("json/stringify.zig").stringifyMaxDepth;
pub const stringifyArbitraryDepth = @import("json/stringify.zig").stringifyArbitraryDepth;
pub const stringifyAlloc = @import("json/stringify.zig").stringifyAlloc;
pub const writeStream = @import("json/stringify.zig").writeStream;
pub const writeStreamMaxDepth = @import("json/stringify.zig").writeStreamMaxDepth;
pub const writeStreamArbitraryDepth = @import("json/stringify.zig").writeStreamArbitraryDepth;
pub const WriteStream = @import("json/stringify.zig").WriteStream;
pub const encodeJsonString = @import("json/stringify.zig").encodeJsonString;
pub const encodeJsonStringChars = @import("json/stringify.zig").encodeJsonStringChars;

pub const Formatter = @import("json/fmt.zig").Formatter;
pub const fmt = @import("json/fmt.zig").fmt;

test {
    _ = @import("json/test.zig");
    _ = @import("json/scanner.zig");
    _ = @import("json/dynamic.zig");
    _ = @import("json/hashmap.zig");
    _ = @import("json/static.zig");
    _ = @import("json/stringify.zig");
    _ = @import("json/JSONTestSuite_test.zig");
}
const std = @import("std");
const mem = std.mem;
const testing = std.testing;
const ArenaAllocator = std.heap.ArenaAllocator;
const Allocator = std.mem.Allocator;

const ObjectMap = @import("dynamic.zig").ObjectMap;
const Array = @import("dynamic.zig").Array;
const Value = @import("dynamic.zig").Value;

const parseFromSlice = @import("static.zig").parseFromSlice;
const parseFromSliceLeaky = @import("static.zig").parseFromSliceLeaky;
const parseFromTokenSource = @import("static.zig").parseFromTokenSource;
const parseFromValueLeaky = @import("static.zig").parseFromValueLeaky;
const ParseOptions = @import("static.zig").ParseOptions;

const jsonReader = @import("scanner.zig").reader;
const JsonReader = @import("scanner.zig").Reader;

test "json.parser.dynamic" {
    const s =
        \\{
        \\  "Image": {
        \\      "Width":  800,
        \\      "Height": 600,
        \\      "Title":  "View from 15th Floor",
        \\      "Thumbnail": {
        \\          "Url":    "http://www.example.com/image/481989943",
        \\          "Height": 125,
        \\          "Width":  100
        \\      },
        \\      "Animated" : false,
        \\      "IDs": [116, 943, 234, 38793],
        \\      "ArrayOfObject": [{"n": "m"}],
        \\      "double": 1.3412,
        \\      "LargeInt": 18446744073709551615
        \\    }
        \\}
    ;

    var parsed = try parseFromSlice(Value, testing.allocator, s, .{});
    defer parsed.deinit();

    var root = parsed.value;

    var image = root.object.get("Image").?;

    const width = image.object.get("Width").?;
    try testing.expect(width.integer == 800);

    const height = image.object.get("Height").?;
    try testing.expect(height.integer == 600);

    const title = image.object.get("Title").?;
    try testing.expect(mem.eql(u8, title.string, "View from 15th Floor"));

    const animated = image.object.get("Animated").?;
    try testing.expect(animated.bool == false);

    const array_of_object = image.object.get("ArrayOfObject").?;
    try testing.expect(array_of_object.array.items.len == 1);

    const obj0 = array_of_object.array.items[0].object.get("n").?;
    try testing.expect(mem.eql(u8, obj0.string, "m"));

    const double = image.object.get("double").?;
    try testing.expect(double.float == 1.3412);

    const large_int = image.object.get("LargeInt").?;
    try testing.expect(mem.eql(u8, large_int.number_string, "18446744073709551615"));
}

const writeStream = @import("./stringify.zig").writeStream;
test "write json then parse it" {
    var out_buffer: [1000]u8 = undefined;

    var fixed_buffer_stream = std.io.fixedBufferStream(&out_buffer);
    const out_stream = fixed_buffer_stream.writer();
    var jw = writeStream(out_stream, .{});
    defer jw.deinit();

    try jw.beginObject();

    try jw.objectField("f");
    try jw.write(false);

    try jw.objectField("t");
    try jw.write(true);

    try jw.objectField("int");
    try jw.write(1234);

    try jw.objectField("array");
    try jw.beginArray();
    try jw.write(null);
    try jw.write(12.34);
    try jw.endArray();

    try jw.objectField("str");
    try jw.write("hello");

    try jw.endObject();

    fixed_buffer_stream = std.io.fixedBufferStream(fixed_buffer_stream.getWritten());
    var json_reader = jsonReader(testing.allocator, fixed_buffer_stream.reader());
    defer json_reader.deinit();
    var parsed = try parseFromTokenSource(Value, testing.allocator, &json_reader, .{});
    defer parsed.deinit();

    try testing.expect(parsed.value.object.get("f").?.bool == false);
    try testing.expect(parsed.value.object.get("t").?.bool == true);
    try testing.expect(parsed.value.object.get("int").?.integer == 1234);
    try testing.expect(parsed.value.object.get("array").?.array.items[0].null == {});
    try testing.expect(parsed.value.object.get("array").?.array.items[1].float == 12.34);
    try testing.expect(mem.eql(u8, parsed.value.object.get("str").?.string, "hello"));
}

fn testParse(allocator: std.mem.Allocator, json_str: []const u8) !Value {
    return parseFromSliceLeaky(Value, allocator, json_str, .{});
}

test "parsing empty string gives appropriate error" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    try testing.expectError(error.UnexpectedEndOfInput, testParse(arena_allocator.allocator(), ""));
}

test "Value.array allocator should still be usable after parsing" {
    var parsed = try parseFromSlice(Value, std.testing.allocator, "[]", .{});
    defer parsed.deinit();

    // Allocation should succeed
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try parsed.value.array.append(Value{ .integer = 100 });
    }
    try testing.expectEqual(parsed.value.array.items.len, 100);
}

test "integer after float has proper type" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const parsed = try testParse(arena_allocator.allocator(),
        \\{
        \\  "float": 3.14,
        \\  "ints": [1, 2, 3]
        \\}
    );
    try std.testing.expect(parsed.object.get("ints").?.array.items[0] == .integer);
}

test "ParseOptions.parse_numbers prevents parsing when false" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const parsed = try parseFromSliceLeaky(Value, arena_allocator.allocator(),
        \\{
        \\  "float": 3.14,
        \\  "int": 3
        \\}
    , .{ .parse_numbers = false });
    try std.testing.expect(parsed.object.get("float").? == .number_string);
    try std.testing.expect(parsed.object.get("int").? == .number_string);
}

test "escaped characters" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const input =
        \\{
        \\  "backslash": "\\",
        \\  "forwardslash": "\/",
        \\  "newline": "\n",
        \\  "carriagereturn": "\r",
        \\  "tab": "\t",
        \\  "formfeed": "\f",
        \\  "backspace": "\b",
        \\  "doublequote": "\"",
        \\  "unicode": "\u0105",
        \\  "surrogatepair": "\ud83d\ude02"
        \\}
    ;

    const obj = (try testParse(arena_allocator.allocator(), input)).object;

    try testing.expectEqualSlices(u8, obj.get("backslash").?.string, "\\");
    try testing.expectEqualSlices(u8, obj.get("forwardslash").?.string, "/");
    try testing.expectEqualSlices(u8, obj.get("newline").?.string, "\n");
    try testing.expectEqualSlices(u8, obj.get("carriagereturn").?.string, "\r");
    try testing.expectEqualSlices(u8, obj.get("tab").?.string, "\t");
    try testing.expectEqualSlices(u8, obj.get("formfeed").?.string, "\x0C");
    try testing.expectEqualSlices(u8, obj.get("backspace").?.string, "\x08");
    try testing.expectEqualSlices(u8, obj.get("doublequote").?.string, "\"");
    try testing.expectEqualSlices(u8, obj.get("unicode").?.string, "ą");
    try testing.expectEqualSlices(u8, obj.get("surrogatepair").?.string, "😂");
}

test "Value with duplicate fields" {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();

    const doc =
        \\{
        \\  "abc": 0,
        \\  "abc": 1
        \\}
    ;

    try testing.expectError(error.DuplicateField, parseFromSliceLeaky(std.json.Value, arena_allocator.allocator(), doc, .{
        .duplicate_field_behavior = .@"error",
    }));

    const first = try parseFromSliceLeaky(std.json.Value, arena_allocator.allocator(), doc, .{
        .duplicate_field_behavior = .use_first,
    });
    try testing.expectEqual(@as(usize, 1), first.object.count());
    try testing.expectEqual(@as(i64, 0), first.object.get("abc").?.integer);

    const last = try parseFromSliceLeaky(std.json.Value, arena_allocator.allocator(), doc, .{
        .duplicate_field_behavior = .use_last,
    });
    try testing.expectEqual(@as(usize, 1), last.object.count());
    try testing.expectEqual(@as(i64, 1), last.object.get("abc").?.integer);
}

test "Value.jsonStringify" {
    var vals = [_]Value{
        .{ .integer = 1 },
        .{ .integer = 2 },
        .{ .number_string = "3" },
    };
    var obj = ObjectMap.init(testing.allocator);
    defer obj.deinit();
    try obj.putNoClobber("a", .{ .string = "b" });
    const array = [_]Value{
        .null,
        .{ .bool = true },
        .{ .integer = 42 },
        .{ .number_string = "43" },
        .{ .float = 42 },
        .{ .string = "weeee" },
        .{ .array = Array.fromOwnedSlice(undefined, &vals) },
        .{ .object = obj },
    };
    var buffer: [0x1000]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);

    var jw = writeStream(fbs.writer(), .{ .whitespace = .indent_1 });
    defer jw.deinit();
    try jw.write(array);

    const expected =
        \\[
        \\ null,
        \\ true,
        \\ 42,
        \\ 43,
        \\ 4.2e1,
        \\ "weeee",
        \\ [
        \\  1,
        \\  2,
        \\  3
        \\ ],
        \\ {
        \\  "a": "b"
        \\ }
        \\]
    ;
    try testing.expectEqualSlices(u8, expected, fbs.getWritten());
}

test "parseFromValue(std.json.Value,...)" {
    const str =
        \\{
        \\  "int": 32,
        \\  "float": 3.2,
        \\  "str": "str",
        \\  "array": [3, 2],
        \\  "object": {}
        \\}
    ;

    const parsed_tree = try parseFromSlice(Value, testing.allocator, str, .{});
    defer parsed_tree.deinit();
    const tree = try parseFromValueLeaky(Value, parsed_tree.arena.allocator(), parsed_tree.value, .{});
    try testing.expect(std.meta.eql(parsed_tree.value, tree));
}

test "polymorphic parsing" {
    if (true) return error.SkipZigTest; // See https://github.com/ziglang/zig/issues/16108
    const doc =
        \\{ "type": "div",
        \\  "color": "blue",
        \\  "children": [
        \\    { "type": "button",
        \\      "caption": "OK" },
        \\    { "type": "button",
        \\      "caption": "Cancel" } ] }
    ;
    const Node = union(enum) {
        div: Div,
        button: Button,
        const Self = @This();
        const Div = struct {
            color: enum { red, blue },
            children: []Self,
        };
        const Button = struct {
            caption: []const u8,
        };

        pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: ParseOptions) !@This() {
            if (source != .object) return error.UnexpectedToken;
            const type_value = source.object.get("type") orelse return error.UnexpectedToken; // Missing "type" field.
            if (type_value != .string) return error.UnexpectedToken; // "type" expected to be string.
            const type_str = type_value.string;
            var child_options = options;
            child_options.ignore_unknown_fields = true;
            if (std.mem.eql(u8, type_str, "div")) return .{ .div = try parseFromValueLeaky(Div, allocator, source, child_options) };
            if (std.mem.eql(u8, type_str, "button")) return .{ .button = try parseFromValueLeaky(Button, allocator, source, child_options) };
            return error.UnexpectedToken; // unknown type.
        }
    };

    var arena = ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const dynamic_tree = try parseFromSliceLeaky(Value, arena.allocator(), doc, .{});
    const tree = try parseFromValueLeaky(Node, arena.allocator(), dynamic_tree, .{});

    try testing.expect(tree.div.color == .blue);
    try testing.expectEqualStrings("Cancel", tree.div.children[1].button.caption);
}

test "long object value" {
    const value = "01234567890123456789";
    const doc = "{\"key\":\"" ++ value ++ "\"}";
    var fbs = std.io.fixedBufferStream(doc);
    var reader = smallBufferJsonReader(testing.allocator, fbs.reader());
    defer reader.deinit();
    var parsed = try parseFromTokenSource(Value, testing.allocator, &reader, .{});
    defer parsed.deinit();

    try testing.expectEqualStrings(value, parsed.value.object.get("key").?.string);
}

test "ParseOptions.max_value_len" {
    var arena = ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const str = "\"0800fc577294c34e0b28ad2839435945\"";

    const value = try std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), str, .{ .max_value_len = 32 });

    try testing.expect(value == .string);
    try testing.expect(value.string.len == 32);

    try testing.expectError(error.ValueTooLong, std.json.parseFromSliceLeaky(std.json.Value, arena.allocator(), str, .{ .max_value_len = 31 }));
}

test "many object keys" {
    const doc =
        \\{
        \\  "k1": "v1",
        \\  "k2": "v2",
        \\  "k3": "v3",
        \\  "k4": "v4",
        \\  "k5": "v5"
        \\}
    ;
    var fbs = std.io.fixedBufferStream(doc);
    var reader = smallBufferJsonReader(testing.allocator, fbs.reader());
    defer reader.deinit();
    var parsed = try parseFromTokenSource(Value, testing.allocator, &reader, .{});
    defer parsed.deinit();

    try testing.expectEqualStrings("v1", parsed.value.object.get("k1").?.string);
    try testing.expectEqualStrings("v2", parsed.value.object.get("k2").?.string);
    try testing.expectEqualStrings("v3", parsed.value.object.get("k3").?.string);
    try testing.expectEqualStrings("v4", parsed.value.object.get("k4").?.string);
    try testing.expectEqualStrings("v5", parsed.value.object.get("k5").?.string);
}

test "negative zero" {
    const doc = "-0";
    var fbs = std.io.fixedBufferStream(doc);
    var reader = smallBufferJsonReader(testing.allocator, fbs.reader());
    defer reader.deinit();
    var parsed = try parseFromTokenSource(Value, testing.allocator, &reader, .{});
    defer parsed.deinit();

    try testing.expect(std.math.isNegativeZero(parsed.value.float));
}

fn smallBufferJsonReader(allocator: Allocator, io_reader: anytype) JsonReader(16, @TypeOf(io_reader)) {
    return JsonReader(16, @TypeOf(io_reader)).init(allocator, io_reader);
}
const std = @import("std");
const debug = std.debug;
const ArenaAllocator = std.heap.ArenaAllocator;
const ArrayList = std.ArrayList;
const StringArrayHashMap = std.StringArrayHashMap;
const Allocator = std.mem.Allocator;

const StringifyOptions = @import("./stringify.zig").StringifyOptions;
const stringify = @import("./stringify.zig").stringify;

const ParseOptions = @import("./static.zig").ParseOptions;
const ParseError = @import("./static.zig").ParseError;

const JsonScanner = @import("./scanner.zig").Scanner;
const AllocWhen = @import("./scanner.zig").AllocWhen;
const Token = @import("./scanner.zig").Token;
const isNumberFormattedLikeAnInteger = @import("./scanner.zig").isNumberFormattedLikeAnInteger;

pub const ObjectMap = StringArrayHashMap(Value);
pub const Array = ArrayList(Value);

/// Represents any JSON value, potentially containing other JSON values.
/// A .float value may be an approximation of the original value.
/// Arbitrary precision numbers can be represented by .number_string values.
/// See also `std.json.ParseOptions.parse_numbers`.
pub const Value = union(enum) {
    null,
    bool: bool,
    integer: i64,
    float: f64,
    number_string: []const u8,
    string: []const u8,
    array: Array,
    object: ObjectMap,

    pub fn parseFromNumberSlice(s: []const u8) Value {
        if (!isNumberFormattedLikeAnInteger(s)) {
            const f = std.fmt.parseFloat(f64, s) catch unreachable;
            if (std.math.isFinite(f)) {
                return Value{ .float = f };
            } else {
                return Value{ .number_string = s };
            }
        }
        if (std.fmt.parseInt(i64, s, 10)) |i| {
            return Value{ .integer = i };
        } else |e| {
            switch (e) {
                error.Overflow => return Value{ .number_string = s },
                error.InvalidCharacter => unreachable,
            }
        }
    }

    pub fn dump(self: Value) void {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();

        const stderr = std.io.getStdErr().writer();
        stringify(self, .{}, stderr) catch return;
    }

    pub fn jsonStringify(value: @This(), jws: anytype) !void {
        switch (value) {
            .null => try jws.write(null),
            .bool => |inner| try jws.write(inner),
            .integer => |inner| try jws.write(inner),
            .float => |inner| try jws.write(inner),
            .number_string => |inner| try jws.print("{s}", .{inner}),
            .string => |inner| try jws.write(inner),
            .array => |inner| try jws.write(inner.items),
            .object => |inner| {
                try jws.beginObject();
                var it = inner.iterator();
                while (it.next()) |entry| {
                    try jws.objectField(entry.key_ptr.*);
                    try jws.write(entry.value_ptr.*);
                }
                try jws.endObject();
            },
        }
    }

    pub fn jsonParse(allocator: Allocator, source: anytype, options: ParseOptions) ParseError(@TypeOf(source.*))!@This() {
        // The grammar of the stack is:
        //  (.array | .object .string)*
        var stack = Array.init(allocator);
        defer stack.deinit();

        while (true) {
            // Assert the stack grammar at the top of the stack.
            debug.assert(stack.items.len == 0 or
                stack.items[stack.items.len - 1] == .array or
                (stack.items[stack.items.len - 2] == .object and stack.items[stack.items.len - 1] == .string));

            switch (try source.nextAllocMax(allocator, .alloc_always, options.max_value_len.?)) {
                .allocated_string => |s| {
                    return try handleCompleteValue(&stack, allocator, source, Value{ .string = s }, options) orelse continue;
                },
                .allocated_number => |slice| {
                    if (options.parse_numbers) {
                        return try handleCompleteValue(&stack, allocator, source, Value.parseFromNumberSlice(slice), options) orelse continue;
                    } else {
                        return try handleCompleteValue(&stack, allocator, source, Value{ .number_string = slice }, options) orelse continue;
                    }
                },

                .null => return try handleCompleteValue(&stack, allocator, source, .null, options) orelse continue,
                .true => return try handleCompleteValue(&stack, allocator, source, Value{ .bool = true }, options) orelse continue,
                .false => return try handleCompleteValue(&stack, allocator, source, Value{ .bool = false }, options) orelse continue,

                .object_begin => {
                    switch (try source.nextAllocMax(allocator, .alloc_always, options.max_value_len.?)) {
                        .object_end => return try handleCompleteValue(&stack, allocator, source, Value{ .object = ObjectMap.init(allocator) }, options) orelse continue,
                        .allocated_string => |key| {
                            try stack.appendSlice(&[_]Value{
                                Value{ .object = ObjectMap.init(allocator) },
                                Value{ .string = key },
                            });
                        },
                        else => unreachable,
                    }
                },
                .array_begin => {
                    try stack.append(Value{ .array = Array.init(allocator) });
                },
                .array_end => return try handleCompleteValue(&stack, allocator, source, stack.pop().?, options) orelse continue,

                else => unreachable,
            }
        }
    }

    pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: ParseOptions) !@This() {
        _ = allocator;
        _ = options;
        return source;
    }
};

fn handleCompleteValue(stack: *Array, allocator: Allocator, source: anytype, value_: Value, options: ParseOptions) !?Value {
    if (stack.items.len == 0) return value_;
    var value = value_;
    while (true) {
        // Assert the stack grammar at the top of the stack.
        debug.assert(stack.items[stack.items.len - 1] == .array or
            (stack.items[stack.items.len - 2] == .object and stack.items[stack.items.len - 1] == .string));
        switch (stack.items[stack.items.len - 1]) {
            .string => |key| {
                // stack: [..., .object, .string]
                _ = stack.pop();

                // stack: [..., .object]
                var object = &stack.items[stack.items.len - 1].object;

                const gop = try object.getOrPut(key);
                if (gop.found_existing) {
                    switch (options.duplicate_field_behavior) {
                        .use_first => {},
                        .@"error" => return error.DuplicateField,
                        .use_last => {
                            gop.value_ptr.* = value;
                        },
                    }
                } else {
                    gop.value_ptr.* = value;
                }

                // This is an invalid state to leave the stack in,
                // so we have to process the next token before we return.
                switch (try source.nextAllocMax(allocator, .alloc_always, options.max_value_len.?)) {
                    .object_end => {
                        // This object is complete.
                        value = stack.pop().?;
                        // Effectively recurse now that we have a complete value.
                        if (stack.items.len == 0) return value;
                        continue;
                    },
                    .allocated_string => |next_key| {
                        // We've got another key.
                        try stack.append(Value{ .string = next_key });
                        // stack: [..., .object, .string]
                        return null;
                    },
                    else => unreachable,
                }
            },
            .array => |*array| {
                // stack: [..., .array]
                try array.append(value);
                return null;
            },
            else => unreachable,
        }
    }
}

test {
    _ = @import("dynamic_test.zig");
}
const std = @import("std");

const stringify = @import("stringify.zig").stringify;
const StringifyOptions = @import("stringify.zig").StringifyOptions;

/// Returns a formatter that formats the given value using stringify.
pub fn fmt(value: anytype, options: StringifyOptions) Formatter(@TypeOf(value)) {
    return Formatter(@TypeOf(value)){ .value = value, .options = options };
}

/// Formats the given value using stringify.
pub fn Formatter(comptime T: type) type {
    return struct {
        value: T,
        options: StringifyOptions,

        pub fn format(
            self: @This(),
            comptime fmt_spec: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt_spec;
            _ = options;
            try stringify(self.value, self.options, writer);
        }
    };
}

test fmt {
    const expectFmt = std.testing.expectFmt;
    try expectFmt("123", "{}", .{fmt(@as(u32, 123), .{})});
    try expectFmt(
        \\{"num":927,"msg":"hello","sub":{"mybool":true}}
    , "{}", .{fmt(struct {
        num: u32,
        msg: []const u8,
        sub: struct {
            mybool: bool,
        },
    }{
        .num = 927,
        .msg = "hello",
        .sub = .{ .mybool = true },
    }, .{})});
}
const std = @import("std");
const testing = std.testing;

const ArrayHashMap = @import("hashmap.zig").ArrayHashMap;

const parseFromSlice = @import("static.zig").parseFromSlice;
const parseFromSliceLeaky = @import("static.zig").parseFromSliceLeaky;
const parseFromTokenSource = @import("static.zig").parseFromTokenSource;
const parseFromValue = @import("static.zig").parseFromValue;
const stringifyAlloc = @import("stringify.zig").stringifyAlloc;
const Value = @import("dynamic.zig").Value;

const jsonReader = @import("./scanner.zig").reader;

const T = struct {
    i: i32,
    s: []const u8,
};

test "parse json hashmap" {
    const doc =
        \\{
        \\  "abc": {"i": 0, "s": "d"},
        \\  "xyz": {"i": 1, "s": "w"}
        \\}
    ;
    const parsed = try parseFromSlice(ArrayHashMap(T), testing.allocator, doc, .{});
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 2), parsed.value.map.count());
    try testing.expectEqualStrings("d", parsed.value.map.get("abc").?.s);
    try testing.expectEqual(@as(i32, 1), parsed.value.map.get("xyz").?.i);
}

test "parse json hashmap while streaming" {
    const doc =
        \\{
        \\  "abc": {"i": 0, "s": "d"},
        \\  "xyz": {"i": 1, "s": "w"}
        \\}
    ;
    var stream = std.io.fixedBufferStream(doc);
    var json_reader = jsonReader(testing.allocator, stream.reader());

    var parsed = try parseFromTokenSource(
        ArrayHashMap(T),
        testing.allocator,
        &json_reader,
        .{},
    );
    defer parsed.deinit();
    // Deinit our reader to invalidate its buffer
    json_reader.deinit();

    try testing.expectEqual(@as(usize, 2), parsed.value.map.count());
    try testing.expectEqualStrings("d", parsed.value.map.get("abc").?.s);
    try testing.expectEqual(@as(i32, 1), parsed.value.map.get("xyz").?.i);
}

test "parse json hashmap duplicate fields" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const doc =
        \\{
        \\  "abc": {"i": 0, "s": "d"},
        \\  "abc": {"i": 1, "s": "w"}
        \\}
    ;

    try testing.expectError(error.DuplicateField, parseFromSliceLeaky(ArrayHashMap(T), arena.allocator(), doc, .{
        .duplicate_field_behavior = .@"error",
    }));

    const first = try parseFromSliceLeaky(ArrayHashMap(T), arena.allocator(), doc, .{
        .duplicate_field_behavior = .use_first,
    });
    try testing.expectEqual(@as(usize, 1), first.map.count());
    try testing.expectEqual(@as(i32, 0), first.map.get("abc").?.i);

    const last = try parseFromSliceLeaky(ArrayHashMap(T), arena.allocator(), doc, .{
        .duplicate_field_behavior = .use_last,
    });
    try testing.expectEqual(@as(usize, 1), last.map.count());
    try testing.expectEqual(@as(i32, 1), last.map.get("abc").?.i);
}

test "stringify json hashmap" {
    var value = ArrayHashMap(T){};
    defer value.deinit(testing.allocator);
    {
        const doc = try stringifyAlloc(testing.allocator, value, .{});
        defer testing.allocator.free(doc);
        try testing.expectEqualStrings("{}", doc);
    }

    try value.map.put(testing.allocator, "abc", .{ .i = 0, .s = "d" });
    try value.map.put(testing.allocator, "xyz", .{ .i = 1, .s = "w" });

    {
        const doc = try stringifyAlloc(testing.allocator, value, .{});
        defer testing.allocator.free(doc);
        try testing.expectEqualStrings(
            \\{"abc":{"i":0,"s":"d"},"xyz":{"i":1,"s":"w"}}
        , doc);
    }

    try testing.expect(value.map.swapRemove("abc"));
    {
        const doc = try stringifyAlloc(testing.allocator, value, .{});
        defer testing.allocator.free(doc);
        try testing.expectEqualStrings(
            \\{"xyz":{"i":1,"s":"w"}}
        , doc);
    }

    try testing.expect(value.map.swapRemove("xyz"));
    {
        const doc = try stringifyAlloc(testing.allocator, value, .{});
        defer testing.allocator.free(doc);
        try testing.expectEqualStrings("{}", doc);
    }
}

test "stringify json hashmap whitespace" {
    var value = ArrayHashMap(T){};
    defer value.deinit(testing.allocator);
    try value.map.put(testing.allocator, "abc", .{ .i = 0, .s = "d" });
    try value.map.put(testing.allocator, "xyz", .{ .i = 1, .s = "w" });

    {
        const doc = try stringifyAlloc(testing.allocator, value, .{ .whitespace = .indent_2 });
        defer testing.allocator.free(doc);
        try testing.expectEqualStrings(
            \\{
            \\  "abc": {
            \\    "i": 0,
            \\    "s": "d"
            \\  },
            \\  "xyz": {
            \\    "i": 1,
            \\    "s": "w"
            \\  }
            \\}
        , doc);
    }
}

test "json parse from value hashmap" {
    const doc =
        \\{
        \\  "abc": {"i": 0, "s": "d"},
        \\  "xyz": {"i": 1, "s": "w"}
        \\}
    ;
    const parsed1 = try parseFromSlice(Value, testing.allocator, doc, .{});
    defer parsed1.deinit();

    const parsed2 = try parseFromValue(ArrayHashMap(T), testing.allocator, parsed1.value, .{});
    defer parsed2.deinit();

    try testing.expectEqualStrings("d", parsed2.value.map.get("abc").?.s);
}
const std = @import("std");
const Allocator = std.mem.Allocator;

const ParseOptions = @import("static.zig").ParseOptions;
const innerParse = @import("static.zig").innerParse;
const innerParseFromValue = @import("static.zig").innerParseFromValue;
const Value = @import("dynamic.zig").Value;

/// A thin wrapper around `std.StringArrayHashMapUnmanaged` that implements
/// `jsonParse`, `jsonParseFromValue`, and `jsonStringify`.
/// This is useful when your JSON schema has an object with arbitrary data keys
/// instead of comptime-known struct field names.
pub fn ArrayHashMap(comptime T: type) type {
    return struct {
        map: std.StringArrayHashMapUnmanaged(T) = .empty,

        pub fn deinit(self: *@This(), allocator: Allocator) void {
            self.map.deinit(allocator);
        }

        pub fn jsonParse(allocator: Allocator, source: anytype, options: ParseOptions) !@This() {
            var map: std.StringArrayHashMapUnmanaged(T) = .empty;
            errdefer map.deinit(allocator);

            if (.object_begin != try source.next()) return error.UnexpectedToken;
            while (true) {
                const token = try source.nextAlloc(allocator, options.allocate.?);
                switch (token) {
                    inline .string, .allocated_string => |k| {
                        const gop = try map.getOrPut(allocator, k);
                        if (gop.found_existing) {
                            switch (options.duplicate_field_behavior) {
                                .use_first => {
                                    // Parse and ignore the redundant value.
                                    // We don't want to skip the value, because we want type checking.
                                    _ = try innerParse(T, allocator, source, options);
                                    continue;
                                },
                                .@"error" => return error.DuplicateField,
                                .use_last => {},
                            }
                        }
                        gop.value_ptr.* = try innerParse(T, allocator, source, options);
                    },
                    .object_end => break,
                    else => unreachable,
                }
            }
            return .{ .map = map };
        }

        pub fn jsonParseFromValue(allocator: Allocator, source: Value, options: ParseOptions) !@This() {
            if (source != .object) return error.UnexpectedToken;

            var map: std.StringArrayHashMapUnmanaged(T) = .empty;
            errdefer map.deinit(allocator);

            var it = source.object.iterator();
            while (it.next()) |kv| {
                try map.put(allocator, kv.key_ptr.*, try innerParseFromValue(T, allocator, kv.value_ptr.*, options));
            }
            return .{ .map = map };
        }

        pub fn jsonStringify(self: @This(), jws: anytype) !void {
            try jws.beginObject();
            var it = self.map.iterator();
            while (it.next()) |kv| {
                try jws.objectField(kv.key_ptr.*);
                try jws.write(kv.value_ptr.*);
            }
            try jws.endObject();
        }
    };
}

test {
    _ = @import("hashmap_test.zig");
}
// This file was generated by _generate_JSONTestSuite.zig
// These test cases are sourced from: https://github.com/nst/JSONTestSuite
const ok = @import("./test.zig").ok;
const err = @import("./test.zig").err;
const any = @import("./test.zig").any;

test "i_number_double_huge_neg_exp.json" {
    try any("[123.456e-789]");
}
test "i_number_huge_exp.json" {
    try any("[0.4e00669999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999969999999006]");
}
test "i_number_neg_int_huge_exp.json" {
    try any("[-1e+9999]");
}
test "i_number_pos_double_huge_exp.json" {
    try any("[1.5e+9999]");
}
test "i_number_real_neg_overflow.json" {
    try any("[-123123e100000]");
}
test "i_number_real_pos_overflow.json" {
    try any("[123123e100000]");
}
test "i_number_real_underflow.json" {
    try any("[123e-10000000]");
}
test "i_number_too_big_neg_int.json" {
    try any("[-123123123123123123123123123123]");
}
test "i_number_too_big_pos_int.json" {
    try any("[100000000000000000000]");
}
test "i_number_very_big_negative_int.json" {
    try any("[-237462374673276894279832749832423479823246327846]");
}
test "i_object_key_lone_2nd_surrogate.json" {
    try any("{\"\\uDFAA\":0}");
}
test "i_string_1st_surrogate_but_2nd_missing.json" {
    try any("[\"\\uDADA\"]");
}
test "i_string_1st_valid_surrogate_2nd_invalid.json" {
    try any("[\"\\uD888\\u1234\"]");
}
test "i_string_UTF-16LE_with_BOM.json" {
    try any("\xff\xfe[\x00\"\x00\xe9\x00\"\x00]\x00");
}
test "i_string_UTF-8_invalid_sequence.json" {
    try any("[\"\xe6\x97\xa5\xd1\x88\xfa\"]");
}
test "i_string_UTF8_surrogate_U+D800.json" {
    try any("[\"\xed\xa0\x80\"]");
}
test "i_string_incomplete_surrogate_and_escape_valid.json" {
    try any("[\"\\uD800\\n\"]");
}
test "i_string_incomplete_surrogate_pair.json" {
    try any("[\"\\uDd1ea\"]");
}
test "i_string_incomplete_surrogates_escape_valid.json" {
    try any("[\"\\uD800\\uD800\\n\"]");
}
test "i_string_invalid_lonely_surrogate.json" {
    try any("[\"\\ud800\"]");
}
test "i_string_invalid_surrogate.json" {
    try any("[\"\\ud800abc\"]");
}
test "i_string_invalid_utf-8.json" {
    try any("[\"\xff\"]");
}
test "i_string_inverted_surrogates_U+1D11E.json" {
    try any("[\"\\uDd1e\\uD834\"]");
}
test "i_string_iso_latin_1.json" {
    try any("[\"\xe9\"]");
}
test "i_string_lone_second_surrogate.json" {
    try any("[\"\\uDFAA\"]");
}
test "i_string_lone_utf8_continuation_byte.json" {
    try any("[\"\x81\"]");
}
test "i_string_not_in_unicode_range.json" {
    try any("[\"\xf4\xbf\xbf\xbf\"]");
}
test "i_string_overlong_sequence_2_bytes.json" {
    try any("[\"\xc0\xaf\"]");
}
test "i_string_overlong_sequence_6_bytes.json" {
    try any("[\"\xfc\x83\xbf\xbf\xbf\xbf\"]");
}
test "i_string_overlong_sequence_6_bytes_null.json" {
    try any("[\"\xfc\x80\x80\x80\x80\x80\"]");
}
test "i_string_truncated-utf-8.json" {
    try any("[\"\xe0\xff\"]");
}
test "i_string_utf16BE_no_BOM.json" {
    try any("\x00[\x00\"\x00\xe9\x00\"\x00]");
}
test "i_string_utf16LE_no_BOM.json" {
    try any("[\x00\"\x00\xe9\x00\"\x00]\x00");
}
test "i_structure_500_nested_arrays.json" {
    try any("[" ** 500 ++ "]" ** 500);
}
test "i_structure_UTF-8_BOM_empty_object.json" {
    try any("\xef\xbb\xbf{}");
}
test "n_array_1_true_without_comma.json" {
    try err("[1 true]");
}
test "n_array_a_invalid_utf8.json" {
    try err("[a\xe5]");
}
test "n_array_colon_instead_of_comma.json" {
    try err("[\"\": 1]");
}
test "n_array_comma_after_close.json" {
    try err("[\"\"],");
}
test "n_array_comma_and_number.json" {
    try err("[,1]");
}
test "n_array_double_comma.json" {
    try err("[1,,2]");
}
test "n_array_double_extra_comma.json" {
    try err("[\"x\",,]");
}
test "n_array_extra_close.json" {
    try err("[\"x\"]]");
}
test "n_array_extra_comma.json" {
    try err("[\"\",]");
}
test "n_array_incomplete.json" {
    try err("[\"x\"");
}
test "n_array_incomplete_invalid_value.json" {
    try err("[x");
}
test "n_array_inner_array_no_comma.json" {
    try err("[3[4]]");
}
test "n_array_invalid_utf8.json" {
    try err("[\xff]");
}
test "n_array_items_separated_by_semicolon.json" {
    try err("[1:2]");
}
test "n_array_just_comma.json" {
    try err("[,]");
}
test "n_array_just_minus.json" {
    try err("[-]");
}
test "n_array_missing_value.json" {
    try err("[   , \"\"]");
}
test "n_array_newlines_unclosed.json" {
    try err("[\"a\",\n4\n,1,");
}
test "n_array_number_and_comma.json" {
    try err("[1,]");
}
test "n_array_number_and_several_commas.json" {
    try err("[1,,]");
}
test "n_array_spaces_vertical_tab_formfeed.json" {
    try err("[\"\x0ba\"\\f]");
}
test "n_array_star_inside.json" {
    try err("[*]");
}
test "n_array_unclosed.json" {
    try err("[\"\"");
}
test "n_array_unclosed_trailing_comma.json" {
    try err("[1,");
}
test "n_array_unclosed_with_new_lines.json" {
    try err("[1,\n1\n,1");
}
test "n_array_unclosed_with_object_inside.json" {
    try err("[{}");
}
test "n_incomplete_false.json" {
    try err("[fals]");
}
test "n_incomplete_null.json" {
    try err("[nul]");
}
test "n_incomplete_true.json" {
    try err("[tru]");
}
test "n_multidigit_number_then_00.json" {
    try err("123\x00");
}
test "n_number_++.json" {
    try err("[++1234]");
}
test "n_number_+1.json" {
    try err("[+1]");
}
test "n_number_+Inf.json" {
    try err("[+Inf]");
}
test "n_number_-01.json" {
    try err("[-01]");
}
test "n_number_-1.0..json" {
    try err("[-1.0.]");
}
test "n_number_-2..json" {
    try err("[-2.]");
}
test "n_number_-NaN.json" {
    try err("[-NaN]");
}
test "n_number_.-1.json" {
    try err("[.-1]");
}
test "n_number_.2e-3.json" {
    try err("[.2e-3]");
}
test "n_number_0.1.2.json" {
    try err("[0.1.2]");
}
test "n_number_0.3e+.json" {
    try err("[0.3e+]");
}
test "n_number_0.3e.json" {
    try err("[0.3e]");
}
test "n_number_0.e1.json" {
    try err("[0.e1]");
}
test "n_number_0_capital_E+.json" {
    try err("[0E+]");
}
test "n_number_0_capital_E.json" {
    try err("[0E]");
}
test "n_number_0e+.json" {
    try err("[0e+]");
}
test "n_number_0e.json" {
    try err("[0e]");
}
test "n_number_1.0e+.json" {
    try err("[1.0e+]");
}
test "n_number_1.0e-.json" {
    try err("[1.0e-]");
}
test "n_number_1.0e.json" {
    try err("[1.0e]");
}
test "n_number_1_000.json" {
    try err("[1 000.0]");
}
test "n_number_1eE2.json" {
    try err("[1eE2]");
}
test "n_number_2.e+3.json" {
    try err("[2.e+3]");
}
test "n_number_2.e-3.json" {
    try err("[2.e-3]");
}
test "n_number_2.e3.json" {
    try err("[2.e3]");
}
test "n_number_9.e+.json" {
    try err("[9.e+]");
}
test "n_number_Inf.json" {
    try err("[Inf]");
}
test "n_number_NaN.json" {
    try err("[NaN]");
}
test "n_number_U+FF11_fullwidth_digit_one.json" {
    try err("[\xef\xbc\x91]");
}
test "n_number_expression.json" {
    try err("[1+2]");
}
test "n_number_hex_1_digit.json" {
    try err("[0x1]");
}
test "n_number_hex_2_digits.json" {
    try err("[0x42]");
}
test "n_number_infinity.json" {
    try err("[Infinity]");
}
test "n_number_invalid+-.json" {
    try err("[0e+-1]");
}
test "n_number_invalid-negative-real.json" {
    try err("[-123.123foo]");
}
test "n_number_invalid-utf-8-in-bigger-int.json" {
    try err("[123\xe5]");
}
test "n_number_invalid-utf-8-in-exponent.json" {
    try err("[1e1\xe5]");
}
test "n_number_invalid-utf-8-in-int.json" {
    try err("[0\xe5]\n");
}
test "n_number_minus_infinity.json" {
    try err("[-Infinity]");
}
test "n_number_minus_sign_with_trailing_garbage.json" {
    try err("[-foo]");
}
test "n_number_minus_space_1.json" {
    try err("[- 1]");
}
test "n_number_neg_int_starting_with_zero.j```
