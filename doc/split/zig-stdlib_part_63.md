```
ool, &client.next_https_rescan_certs, false, .release);
        }
    }

    const conn = options.connection orelse
        try client.connect(valid_uri.host.?.raw, uriPort(valid_uri, protocol), protocol);

    var req: Request = .{
        .uri = valid_uri,
        .client = client,
        .connection = conn,
        .keep_alive = options.keep_alive,
        .method = method,
        .version = options.version,
        .transfer_encoding = .none,
        .redirect_behavior = options.redirect_behavior,
        .handle_continue = options.handle_continue,
        .response = .{
            .version = undefined,
            .status = undefined,
            .reason = undefined,
            .keep_alive = undefined,
            .parser = .init(server_header.buffer[server_header.end_index..]),
        },
        .headers = options.headers,
        .extra_headers = options.extra_headers,
        .privileged_headers = options.privileged_headers,
    };
    errdefer req.deinit();

    return req;
}

pub const FetchOptions = struct {
    server_header_buffer: ?[]u8 = null,
    redirect_behavior: ?Request.RedirectBehavior = null,

    /// If the server sends a body, it will be appended to this ArrayList.
    /// `max_append_size` provides an upper limit for how much they can grow.
    response_storage: ResponseStorage = .ignore,
    max_append_size: ?usize = null,

    location: Location,
    method: ?http.Method = null,
    payload: ?[]const u8 = null,
    raw_uri: bool = false,
    keep_alive: bool = true,

    /// Standard headers that have default, but overridable, behavior.
    headers: Request.Headers = .{},
    /// These headers are kept including when following a redirect to a
    /// different domain.
    /// Externally-owned; must outlive the Request.
    extra_headers: []const http.Header = &.{},
    /// These headers are stripped when following a redirect to a different
    /// domain.
    /// Externally-owned; must outlive the Request.
    privileged_headers: []const http.Header = &.{},

    pub const Location = union(enum) {
        url: []const u8,
        uri: Uri,
    };

    pub const ResponseStorage = union(enum) {
        ignore,
        /// Only the existing capacity will be used.
        static: *std.ArrayListUnmanaged(u8),
        dynamic: *std.ArrayList(u8),
    };
};

pub const FetchResult = struct {
    status: http.Status,
};

/// Perform a one-shot HTTP request with the provided options.
///
/// This function is threadsafe.
pub fn fetch(client: *Client, options: FetchOptions) !FetchResult {
    const uri = switch (options.location) {
        .url => |u| try Uri.parse(u),
        .uri => |u| u,
    };
    var server_header_buffer: [16 * 1024]u8 = undefined;

    const method: http.Method = options.method orelse
        if (options.payload != null) .POST else .GET;

    var req = try open(client, method, uri, .{
        .server_header_buffer = options.server_header_buffer orelse &server_header_buffer,
        .redirect_behavior = options.redirect_behavior orelse
            if (options.payload == null) @enumFromInt(3) else .unhandled,
        .headers = options.headers,
        .extra_headers = options.extra_headers,
        .privileged_headers = options.privileged_headers,
        .keep_alive = options.keep_alive,
    });
    defer req.deinit();

    if (options.payload) |payload| req.transfer_encoding = .{ .content_length = payload.len };

    try req.send();

    if (options.payload) |payload| try req.writeAll(payload);

    try req.finish();
    try req.wait();

    switch (options.response_storage) {
        .ignore => {
            // Take advantage of request internals to discard the response body
            // and make the connection available for another request.
            req.response.skip = true;
            assert(try req.transferRead(&.{}) == 0); // No buffer is necessary when skipping.
        },
        .dynamic => |list| {
            const max_append_size = options.max_append_size orelse 2 * 1024 * 1024;
            try req.reader().readAllArrayList(list, max_append_size);
        },
        .static => |list| {
            const buf = b: {
                const buf = list.unusedCapacitySlice();
                if (options.max_append_size) |len| {
                    if (len < buf.len) break :b buf[0..len];
                }
                break :b buf;
            };
            list.items.len += try req.reader().readAll(buf);
        },
    }

    return .{
        .status = req.response.status,
    };
}

test {
    _ = &initDefaultProxies;
}
bytes: []const u8,
index: usize,
is_trailer: bool,

pub fn init(bytes: []const u8) HeaderIterator {
    return .{
        .bytes = bytes,
        .index = std.mem.indexOfPosLinear(u8, bytes, 0, "\r\n").? + 2,
        .is_trailer = false,
    };
}

pub fn next(it: *HeaderIterator) ?std.http.Header {
    const end = std.mem.indexOfPosLinear(u8, it.bytes, it.index, "\r\n").?;
    if (it.index == end) { // found the trailer boundary (\r\n\r\n)
        if (it.is_trailer) return null;

        const next_end = std.mem.indexOfPosLinear(u8, it.bytes, end + 2, "\r\n") orelse
            return null;

        var kv_it = std.mem.splitScalar(u8, it.bytes[end + 2 .. next_end], ':');
        const name = kv_it.first();
        const value = kv_it.rest();

        it.is_trailer = true;
        it.index = next_end + 2;
        if (name.len == 0)
            return null;

        return .{
            .name = name,
            .value = std.mem.trim(u8, value, " \t"),
        };
    } else { // normal header
        var kv_it = std.mem.splitScalar(u8, it.bytes[it.index..end], ':');
        const name = kv_it.first();
        const value = kv_it.rest();

        it.index = end + 2;
        if (name.len == 0)
            return null;

        return .{
            .name = name,
            .value = std.mem.trim(u8, value, " \t"),
        };
    }
}

test next {
    var it = HeaderIterator.init("200 OK\r\na: b\r\nc:  \r\nd:e\r\n\r\nf: g\r\n\r\n");
    try std.testing.expect(!it.is_trailer);
    {
        const header = it.next().?;
        try std.testing.expect(!it.is_trailer);
        try std.testing.expectEqualStrings("a", header.name);
        try std.testing.expectEqualStrings("b", header.value);
    }
    {
        const header = it.next().?;
        try std.testing.expect(!it.is_trailer);
        try std.testing.expectEqualStrings("c", header.name);
        try std.testing.expectEqualStrings("", header.value);
    }
    {
        const header = it.next().?;
        try std.testing.expect(!it.is_trailer);
        try std.testing.expectEqualStrings("d", header.name);
        try std.testing.expectEqualStrings("e", header.value);
    }
    {
        const header = it.next().?;
        try std.testing.expect(it.is_trailer);
        try std.testing.expectEqualStrings("f", header.name);
        try std.testing.expectEqualStrings("g", header.value);
    }
    try std.testing.expectEqual(null, it.next());

    it = HeaderIterator.init("200 OK\r\n: ss\r\n\r\n");
    try std.testing.expect(!it.is_trailer);
    try std.testing.expectEqual(null, it.next());

    it = HeaderIterator.init("200 OK\r\na:b\r\n\r\n: ss\r\n\r\n");
    try std.testing.expect(!it.is_trailer);
    {
        const header = it.next().?;
        try std.testing.expect(!it.is_trailer);
        try std.testing.expectEqualStrings("a", header.name);
        try std.testing.expectEqualStrings("b", header.value);
    }
    try std.testing.expectEqual(null, it.next());
    try std.testing.expect(it.is_trailer);
}

const HeaderIterator = @This();
const std = @import("../std.zig");
const assert = std.debug.assert;
//! Finds the end of an HTTP head in a stream.

state: State = .start,

pub const State = enum {
    start,
    seen_n,
    seen_r,
    seen_rn,
    seen_rnr,
    finished,
};

/// Returns the number of bytes consumed by headers. This is always less
/// than or equal to `bytes.len`.
///
/// If the amount returned is less than `bytes.len`, the parser is in a
/// content state and the first byte of content is located at
/// `bytes[result]`.
pub fn feed(p: *HeadParser, bytes: []const u8) usize {
    const vector_len: comptime_int = @max(std.simd.suggestVectorLength(u8) orelse 1, 8);
    var index: usize = 0;

    while (true) {
        switch (p.state) {
            .finished => return index,
            .start => switch (bytes.len - index) {
                0 => return index,
                1 => {
                    switch (bytes[index]) {
                        '\r' => p.state = .seen_r,
                        '\n' => p.state = .seen_n,
                        else => {},
                    }

                    return index + 1;
                },
                2 => {
                    const b16 = int16(bytes[index..][0..2]);
                    const b8 = intShift(u8, b16);

                    switch (b8) {
                        '\r' => p.state = .seen_r,
                        '\n' => p.state = .seen_n,
                        else => {},
                    }

                    switch (b16) {
                        int16("\r\n") => p.state = .seen_rn,
                        int16("\n\n") => p.state = .finished,
                        else => {},
                    }

                    return index + 2;
                },
                3 => {
                    const b24 = int24(bytes[index..][0..3]);
                    const b16 = intShift(u16, b24);
                    const b8 = intShift(u8, b24);

                    switch (b8) {
                        '\r' => p.state = .seen_r,
                        '\n' => p.state = .seen_n,
                        else => {},
                    }

                    switch (b16) {
                        int16("\r\n") => p.state = .seen_rn,
                        int16("\n\n") => p.state = .finished,
                        else => {},
                    }

                    switch (b24) {
                        int24("\r\n\r") => p.state = .seen_rnr,
                        else => {},
                    }

                    return index + 3;
                },
                4...vector_len - 1 => {
                    const b32 = int32(bytes[index..][0..4]);
                    const b24 = intShift(u24, b32);
                    const b16 = intShift(u16, b32);
                    const b8 = intShift(u8, b32);

                    switch (b8) {
                        '\r' => p.state = .seen_r,
                        '\n' => p.state = .seen_n,
                        else => {},
                    }

                    switch (b16) {
                        int16("\r\n") => p.state = .seen_rn,
                        int16("\n\n") => p.state = .finished,
                        else => {},
                    }

                    switch (b24) {
                        int24("\r\n\r") => p.state = .seen_rnr,
                        else => {},
                    }

                    switch (b32) {
                        int32("\r\n\r\n") => p.state = .finished,
                        else => {},
                    }

                    index += 4;
                    continue;
                },
                else => {
                    const chunk = bytes[index..][0..vector_len];
                    const matches = if (use_vectors) matches: {
                        const Vector = @Vector(vector_len, u8);
                        // const BoolVector = @Vector(vector_len, bool);
                        const BitVector = @Vector(vector_len, u1);
                        const SizeVector = @Vector(vector_len, u8);

                        const v: Vector = chunk.*;
                        const matches_r: BitVector = @bitCast(v == @as(Vector, @splat('\r')));
                        const matches_n: BitVector = @bitCast(v == @as(Vector, @splat('\n')));
                        const matches_or: SizeVector = matches_r | matches_n;

                        break :matches @reduce(.Add, matches_or);
                    } else matches: {
                        var matches: u8 = 0;
                        for (chunk) |byte| switch (byte) {
                            '\r', '\n' => matches += 1,
                            else => {},
                        };
                        break :matches matches;
                    };
                    switch (matches) {
                        0 => {},
                        1 => switch (chunk[vector_len - 1]) {
                            '\r' => p.state = .seen_r,
                            '\n' => p.state = .seen_n,
                            else => {},
                        },
                        2 => {
                            const b16 = int16(chunk[vector_len - 2 ..][0..2]);
                            const b8 = intShift(u8, b16);

                            switch (b8) {
                                '\r' => p.state = .seen_r,
                                '\n' => p.state = .seen_n,
                                else => {},
                            }

                            switch (b16) {
                                int16("\r\n") => p.state = .seen_rn,
                                int16("\n\n") => p.state = .finished,
                                else => {},
                            }
                        },
                        3 => {
                            const b24 = int24(chunk[vector_len - 3 ..][0..3]);
                            const b16 = intShift(u16, b24);
                            const b8 = intShift(u8, b24);

                            switch (b8) {
                                '\r' => p.state = .seen_r,
                                '\n' => p.state = .seen_n,
                                else => {},
                            }

                            switch (b16) {
                                int16("\r\n") => p.state = .seen_rn,
                                int16("\n\n") => p.state = .finished,
                                else => {},
                            }

                            switch (b24) {
                                int24("\r\n\r") => p.state = .seen_rnr,
                                else => {},
                            }
                        },
                        4...vector_len => {
                            inline for (0..vector_len - 3) |i_usize| {
                                const i = @as(u32, @truncate(i_usize));

                                const b32 = int32(chunk[i..][0..4]);
                                const b16 = intShift(u16, b32);

                                if (b32 == int32("\r\n\r\n")) {
                                    p.state = .finished;
                                    return index + i + 4;
                                } else if (b16 == int16("\n\n")) {
                                    p.state = .finished;
                                    return index + i + 2;
                                }
                            }

                            const b24 = int24(chunk[vector_len - 3 ..][0..3]);
                            const b16 = intShift(u16, b24);
                            const b8 = intShift(u8, b24);

                            switch (b8) {
                                '\r' => p.state = .seen_r,
                                '\n' => p.state = .seen_n,
                                else => {},
                            }

                            switch (b16) {
                                int16("\r\n") => p.state = .seen_rn,
                                int16("\n\n") => p.state = .finished,
                                else => {},
                            }

                            switch (b24) {
                                int24("\r\n\r") => p.state = .seen_rnr,
                                else => {},
                            }
                        },
                        else => unreachable,
                    }

                    index += vector_len;
                    continue;
                },
            },
            .seen_n => switch (bytes.len - index) {
                0 => return index,
                else => {
                    switch (bytes[index]) {
                        '\n' => p.state = .finished,
                        else => p.state = .start,
                    }

                    index += 1;
                    continue;
                },
            },
            .seen_r => switch (bytes.len - index) {
                0 => return index,
                1 => {
                    switch (bytes[index]) {
                        '\n' => p.state = .seen_rn,
                        '\r' => p.state = .seen_r,
                        else => p.state = .start,
                    }

                    return index + 1;
                },
                2 => {
                    const b16 = int16(bytes[index..][0..2]);
                    const b8 = intShift(u8, b16);

                    switch (b8) {
                        '\r' => p.state = .seen_r,
                        '\n' => p.state = .seen_rn,
                        else => p.state = .start,
                    }

                    switch (b16) {
                        int16("\r\n") => p.state = .seen_rn,
                        int16("\n\r") => p.state = .seen_rnr,
                        int16("\n\n") => p.state = .finished,
                        else => {},
                    }

                    return index + 2;
                },
                else => {
                    const b24 = int24(bytes[index..][0..3]);
                    const b16 = intShift(u16, b24);
                    const b8 = intShift(u8, b24);

                    switch (b8) {
                        '\r' => p.state = .seen_r,
                        '\n' => p.state = .seen_n,
                        else => p.state = .start,
                    }

                    switch (b16) {
                        int16("\r\n") => p.state = .seen_rn,
                        int16("\n\n") => p.state = .finished,
                        else => {},
                    }

                    switch (b24) {
                        int24("\n\r\n") => p.state = .finished,
                        else => {},
                    }

                    index += 3;
                    continue;
                },
            },
            .seen_rn => switch (bytes.len - index) {
                0 => return index,
                1 => {
                    switch (bytes[index]) {
                        '\r' => p.state = .seen_rnr,
                        '\n' => p.state = .seen_n,
                        else => p.state = .start,
                    }

                    return index + 1;
                },
                else => {
                    const b16 = int16(bytes[index..][0..2]);
                    const b8 = intShift(u8, b16);

                    switch (b8) {
                        '\r' => p.state = .seen_rnr,
                        '\n' => p.state = .seen_n,
                        else => p.state = .start,
                    }

                    switch (b16) {
                        int16("\r\n") => p.state = .finished,
                        int16("\n\n") => p.state = .finished,
                        else => {},
                    }

                    index += 2;
                    continue;
                },
            },
            .seen_rnr => switch (bytes.len - index) {
                0 => return index,
                else => {
                    switch (bytes[index]) {
                        '\n' => p.state = .finished,
                        else => p.state = .start,
                    }

                    index += 1;
                    continue;
                },
            },
        }

        return index;
    }
}

inline fn int16(array: *const [2]u8) u16 {
    return @bitCast(array.*);
}

inline fn int24(array: *const [3]u8) u24 {
    return @bitCast(array.*);
}

inline fn int32(array: *const [4]u8) u32 {
    return @bitCast(array.*);
}

inline fn intShift(comptime T: type, x: anytype) T {
    switch (@import("builtin").cpu.arch.endian()) {
        .little => return @truncate(x >> (@bitSizeOf(@TypeOf(x)) - @bitSizeOf(T))),
        .big => return @truncate(x),
    }
}

const HeadParser = @This();
const std = @import("std");
const use_vectors = builtin.zig_backend != .stage2_x86_64;
const builtin = @import("builtin");

test feed {
    const data = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\nHello";

    for (0..36) |i| {
        var p: HeadParser = .{};
        try std.testing.expectEqual(i, p.feed(data[0..i]));
        try std.testing.expectEqual(35 - i, p.feed(data[i..]));
    }
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const testing = std.testing;
const mem = std.mem;

const assert = std.debug.assert;

pub const State = enum {
    invalid,

    // Begin header and trailer parsing states.

    start,
    seen_n,
    seen_r,
    seen_rn,
    seen_rnr,
    finished,

    // Begin transfer-encoding: chunked parsing states.

    chunk_head_size,
    chunk_head_ext,
    chunk_head_r,
    chunk_data,
    chunk_data_suffix,
    chunk_data_suffix_r,

    /// Returns true if the parser is in a content state (ie. not waiting for more headers).
    pub fn isContent(self: State) bool {
        return switch (self) {
            .invalid, .start, .seen_n, .seen_r, .seen_rn, .seen_rnr => false,
            .finished, .chunk_head_size, .chunk_head_ext, .chunk_head_r, .chunk_data, .chunk_data_suffix, .chunk_data_suffix_r => true,
        };
    }
};

pub const HeadersParser = struct {
    state: State = .start,
    /// A fixed buffer of len `max_header_bytes`.
    /// Pointers into this buffer are not stable until after a message is complete.
    header_bytes_buffer: []u8,
    header_bytes_len: u32,
    next_chunk_length: u64,
    /// `false`: headers. `true`: trailers.
    done: bool,

    /// Initializes the parser with a provided buffer `buf`.
    pub fn init(buf: []u8) HeadersParser {
        return .{
            .header_bytes_buffer = buf,
            .header_bytes_len = 0,
            .done = false,
            .next_chunk_length = 0,
        };
    }

    /// Reinitialize the parser.
    /// Asserts the parser is in the "done" state.
    pub fn reset(hp: *HeadersParser) void {
        assert(hp.done);
        hp.* = .{
            .state = .start,
            .header_bytes_buffer = hp.header_bytes_buffer,
            .header_bytes_len = 0,
            .done = false,
            .next_chunk_length = 0,
        };
    }

    pub fn get(hp: HeadersParser) []u8 {
        return hp.header_bytes_buffer[0..hp.header_bytes_len];
    }

    pub fn findHeadersEnd(r: *HeadersParser, bytes: []const u8) u32 {
        var hp: std.http.HeadParser = .{
            .state = switch (r.state) {
                .start => .start,
                .seen_n => .seen_n,
                .seen_r => .seen_r,
                .seen_rn => .seen_rn,
                .seen_rnr => .seen_rnr,
                .finished => .finished,
                else => unreachable,
            },
        };
        const result = hp.feed(bytes);
        r.state = switch (hp.state) {
            .start => .start,
            .seen_n => .seen_n,
            .seen_r => .seen_r,
            .seen_rn => .seen_rn,
            .seen_rnr => .seen_rnr,
            .finished => .finished,
        };
        return @intCast(result);
    }

    pub fn findChunkedLen(r: *HeadersParser, bytes: []const u8) u32 {
        var cp: std.http.ChunkParser = .{
            .state = switch (r.state) {
                .chunk_head_size => .head_size,
                .chunk_head_ext => .head_ext,
                .chunk_head_r => .head_r,
                .chunk_data => .data,
                .chunk_data_suffix => .data_suffix,
                .chunk_data_suffix_r => .data_suffix_r,
                .invalid => .invalid,
                else => unreachable,
            },
            .chunk_len = r.next_chunk_length,
        };
        const result = cp.feed(bytes);
        r.state = switch (cp.state) {
            .head_size => .chunk_head_size,
            .head_ext => .chunk_head_ext,
            .head_r => .chunk_head_r,
            .data => .chunk_data,
            .data_suffix => .chunk_data_suffix,
            .data_suffix_r => .chunk_data_suffix_r,
            .invalid => .invalid,
        };
        r.next_chunk_length = cp.chunk_len;
        return @intCast(result);
    }

    /// Returns whether or not the parser has finished parsing a complete
    /// message. A message is only complete after the entire body has been read
    /// and any trailing headers have been parsed.
    pub fn isComplete(r: *HeadersParser) bool {
        return r.done and r.state == .finished;
    }

    pub const CheckCompleteHeadError = error{HttpHeadersOversize};

    /// Pushes `in` into the parser. Returns the number of bytes consumed by
    /// the header. Any header bytes are appended to `header_bytes_buffer`.
    pub fn checkCompleteHead(hp: *HeadersParser, in: []const u8) CheckCompleteHeadError!u32 {
        if (hp.state.isContent()) return 0;

        const i = hp.findHeadersEnd(in);
        const data = in[0..i];
        if (hp.header_bytes_len + data.len > hp.header_bytes_buffer.len)
            return error.HttpHeadersOversize;

        @memcpy(hp.header_bytes_buffer[hp.header_bytes_len..][0..data.len], data);
        hp.header_bytes_len += @intCast(data.len);

        return i;
    }

    pub const ReadError = error{
        HttpChunkInvalid,
    };

    /// Reads the body of the message into `buffer`. Returns the number of
    /// bytes placed in the buffer.
    ///
    /// If `skip` is true, the buffer will be unused and the body will be skipped.
    ///
    /// See `std.http.Client.Connection for an example of `conn`.
    pub fn read(r: *HeadersParser, conn: anytype, buffer: []u8, skip: bool) !usize {
        assert(r.state.isContent());
        if (r.done) return 0;

        var out_index: usize = 0;
        while (true) {
            switch (r.state) {
                .invalid, .start, .seen_n, .seen_r, .seen_rn, .seen_rnr => unreachable,
                .finished => {
                    const data_avail = r.next_chunk_length;

                    if (skip) {
                        conn.fill() catch |err| switch (err) {
                            error.EndOfStream => {
                                r.done = true;
                                return 0;
                            },
                            else => |e| return e,
                        };

                        const nread = @min(conn.peek().len, data_avail);
                        conn.drop(@intCast(nread));
                        r.next_chunk_length -= nread;

                        if (r.next_chunk_length == 0 or nread == 0) r.done = true;

                        return out_index;
                    } else if (out_index < buffer.len) {
                        const out_avail = buffer.len - out_index;

                        const can_read = @as(usize, @intCast(@min(data_avail, out_avail)));
                        const nread = try conn.read(buffer[0..can_read]);
                        r.next_chunk_length -= nread;

                        if (r.next_chunk_length == 0 or nread == 0) r.done = true;

                        return nread;
                    } else {
                        return out_index;
                    }
                },
                .chunk_data_suffix, .chunk_data_suffix_r, .chunk_head_size, .chunk_head_ext, .chunk_head_r => {
                    conn.fill() catch |err| switch (err) {
                        error.EndOfStream => {
                            r.done = true;
                            return 0;
                        },
                        else => |e| return e,
                    };

                    const i = r.findChunkedLen(conn.peek());
                    conn.drop(@intCast(i));

                    switch (r.state) {
                        .invalid => return error.HttpChunkInvalid,
                        .chunk_data => if (r.next_chunk_length == 0) {
                            if (std.mem.eql(u8, conn.peek(), "\r\n")) {
                                r.state = .finished;
                                conn.drop(2);
                            } else {
                                // The trailer section is formatted identically
                                // to the header section.
                                r.state = .seen_rn;
                            }
                            r.done = true;

                            return out_index;
                        },
                        else => return out_index,
                    }

                    continue;
                },
                .chunk_data => {
                    const data_avail = r.next_chunk_length;
                    const out_avail = buffer.len - out_index;

                    if (skip) {
                        conn.fill() catch |err| switch (err) {
                            error.EndOfStream => {
                                r.done = true;
                                return 0;
                            },
                            else => |e| return e,
                        };

                        const nread = @min(conn.peek().len, data_avail);
                        conn.drop(@intCast(nread));
                        r.next_chunk_length -= nread;
                    } else if (out_avail > 0) {
                        const can_read: usize = @intCast(@min(data_avail, out_avail));
                        const nread = try conn.read(buffer[out_index..][0..can_read]);
                        r.next_chunk_length -= nread;
                        out_index += nread;
                    }

                    if (r.next_chunk_length == 0) {
                        r.state = .chunk_data_suffix;
                        continue;
                    }

                    return out_index;
                },
            }
        }
    }
};

inline fn int16(array: *const [2]u8) u16 {
    return @as(u16, @bitCast(array.*));
}

inline fn int24(array: *const [3]u8) u24 {
    return @as(u24, @bitCast(array.*));
}

inline fn int32(array: *const [4]u8) u32 {
    return @as(u32, @bitCast(array.*));
}

inline fn intShift(comptime T: type, x: anytype) T {
    switch (@import("builtin").cpu.arch.endian()) {
        .little => return @as(T, @truncate(x >> (@bitSizeOf(@TypeOf(x)) - @bitSizeOf(T)))),
        .big => return @as(T, @truncate(x)),
    }
}

/// A buffered (and peekable) Connection.
const MockBufferedConnection = struct {
    pub const buffer_size = 0x2000;

    conn: std.io.FixedBufferStream([]const u8),
    buf: [buffer_size]u8 = undefined,
    start: u16 = 0,
    end: u16 = 0,

    pub fn fill(conn: *MockBufferedConnection) ReadError!void {
        if (conn.end != conn.start) return;

        const nread = try conn.conn.read(conn.buf[0..]);
        if (nread == 0) return error.EndOfStream;
        conn.start = 0;
        conn.end = @as(u16, @truncate(nread));
    }

    pub fn peek(conn: *MockBufferedConnection) []const u8 {
        return conn.buf[conn.start..conn.end];
    }

    pub fn drop(conn: *MockBufferedConnection, num: u16) void {
        conn.start += num;
    }

    pub fn readAtLeast(conn: *MockBufferedConnection, buffer: []u8, len: usize) ReadError!usize {
        var out_index: u16 = 0;
        while (out_index < len) {
            const available = conn.end - conn.start;
            const left = buffer.len - out_index;

            if (available > 0) {
                const can_read = @as(u16, @truncate(@min(available, left)));

                @memcpy(buffer[out_index..][0..can_read], conn.buf[conn.start..][0..can_read]);
                out_index += can_read;
                conn.start += can_read;

                continue;
            }

            if (left > conn.buf.len) {
                // skip the buffer if the output is large enough
                return conn.conn.read(buffer[out_index..]);
            }

            try conn.fill();
        }

        return out_index;
    }

    pub fn read(conn: *MockBufferedConnection, buffer: []u8) ReadError!usize {
        return conn.readAtLeast(buffer, 1);
    }

    pub const ReadError = std.io.FixedBufferStream([]const u8).ReadError || error{EndOfStream};
    pub const Reader = std.io.Reader(*MockBufferedConnection, ReadError, read);

    pub fn reader(conn: *MockBufferedConnection) Reader {
        return Reader{ .context = conn };
    }

    pub fn writeAll(conn: *MockBufferedConnection, buffer: []const u8) WriteError!void {
        return conn.conn.writeAll(buffer);
    }

    pub fn write(conn: *MockBufferedConnection, buffer: []const u8) WriteError!usize {
        return conn.conn.write(buffer);
    }

    pub const WriteError = std.io.FixedBufferStream([]const u8).WriteError;
    pub const Writer = std.io.Writer(*MockBufferedConnection, WriteError, write);

    pub fn writer(conn: *MockBufferedConnection) Writer {
        return Writer{ .context = conn };
    }
};

test "HeadersParser.read length" {
    // mock BufferedConnection for read
    var headers_buf: [256]u8 = undefined;

    var r = HeadersParser.init(&headers_buf);
    const data = "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nHello";

    var conn: MockBufferedConnection = .{
        .conn = std.io.fixedBufferStream(data),
    };

    while (true) { // read headers
        try conn.fill();

        const nchecked = try r.checkCompleteHead(conn.peek());
        conn.drop(@intCast(nchecked));

        if (r.state.isContent()) break;
    }

    var buf: [8]u8 = undefined;

    r.next_chunk_length = 5;
    const len = try r.read(&conn, &buf, false);
    try std.testing.expectEqual(@as(usize, 5), len);
    try std.testing.expectEqualStrings("Hello", buf[0..len]);

    try std.testing.expectEqualStrings("GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n", r.get());
}

test "HeadersParser.read chunked" {
    // mock BufferedConnection for read

    var headers_buf: [256]u8 = undefined;
    var r = HeadersParser.init(&headers_buf);
    const data = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n2\r\nHe\r\n2\r\nll\r\n1\r\no\r\n0\r\n\r\n";

    var conn: MockBufferedConnection = .{
        .conn = std.io.fixedBufferStream(data),
    };

    while (true) { // read headers
        try conn.fill();

        const nchecked = try r.checkCompleteHead(conn.peek());
        conn.drop(@intCast(nchecked));

        if (r.state.isContent()) break;
    }
    var buf: [8]u8 = undefined;

    r.state = .chunk_head_size;
    const len = try r.read(&conn, &buf, false);
    try std.testing.expectEqual(@as(usize, 5), len);
    try std.testing.expectEqualStrings("Hello", buf[0..len]);

    try std.testing.expectEqualStrings("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", r.get());
}

test "HeadersParser.read chunked trailer" {
    // mock BufferedConnection for read

    var headers_buf: [256]u8 = undefined;
    var r = HeadersParser.init(&headers_buf);
    const data = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n2\r\nHe\r\n2\r\nll\r\n1\r\no\r\n0\r\nContent-Type: text/plain\r\n\r\n";

    var conn: MockBufferedConnection = .{
        .conn = std.io.fixedBufferStream(data),
    };

    while (true) { // read headers
        try conn.fill();

        const nchecked = try r.checkCompleteHead(conn.peek());
        conn.drop(@intCast(nchecked));

        if (r.state.isContent()) break;
    }
    var buf: [8]u8 = undefined;

    r.state = .chunk_head_size;
    const len = try r.read(&conn, &buf, false);
    try std.testing.expectEqual(@as(usize, 5), len);
    try std.testing.expectEqualStrings("Hello", buf[0..len]);

    while (true) { // read headers
        try conn.fill();

        const nchecked = try r.checkCompleteHead(conn.peek());
        conn.drop(@intCast(nchecked));

        if (r.state.isContent()) break;
    }

    try std.testing.expectEqualStrings("GET / HTTP/1.1\r\nHost: localhost\r\n\r\nContent-Type: text/plain\r\n\r\n", r.get());
}
//! Blocking HTTP server implementation.
//! Handles a single connection's lifecycle.

connection: net.Server.Connection,
/// Keeps track of whether the Server is ready to accept a new request on the
/// same connection, and makes invalid API usage cause assertion failures
/// rather than HTTP protocol violations.
state: State,
/// User-provided buffer that must outlive this Server.
/// Used to store the client's entire HTTP header.
read_buffer: []u8,
/// Amount of available data inside read_buffer.
read_buffer_len: usize,
/// Index into `read_buffer` of the first byte of the next HTTP request.
next_request_start: usize,

pub const State = enum {
    /// The connection is available to be used for the first time, or reused.
    ready,
    /// An error occurred in `receiveHead`.
    receiving_head,
    /// A Request object has been obtained and from there a Response can be
    /// opened.
    received_head,
    /// The client is uploading something to this Server.
    receiving_body,
    /// The connection is eligible for another HTTP request, however the client
    /// and server did not negotiate a persistent connection.
    closing,
};

/// Initialize an HTTP server that can respond to multiple requests on the same
/// connection.
/// The returned `Server` is ready for `receiveHead` to be called.
pub fn init(connection: net.Server.Connection, read_buffer: []u8) Server {
    return .{
        .connection = connection,
        .state = .ready,
        .read_buffer = read_buffer,
        .read_buffer_len = 0,
        .next_request_start = 0,
    };
}

pub const ReceiveHeadError = error{
    /// Client sent too many bytes of HTTP headers.
    /// The HTTP specification suggests to respond with a 431 status code
    /// before closing the connection.
    HttpHeadersOversize,
    /// Client sent headers that did not conform to the HTTP protocol.
    HttpHeadersInvalid,
    /// A low level I/O error occurred trying to read the headers.
    HttpHeadersUnreadable,
    /// Partial HTTP request was received but the connection was closed before
    /// fully receiving the headers.
    HttpRequestTruncated,
    /// The client sent 0 bytes of headers before closing the stream.
    /// In other words, a keep-alive connection was finally closed.
    HttpConnectionClosing,
};

/// The header bytes reference the read buffer that Server was initialized with
/// and remain alive until the next call to receiveHead.
pub fn receiveHead(s: *Server) ReceiveHeadError!Request {
    assert(s.state == .ready);
    s.state = .received_head;
    errdefer s.state = .receiving_head;

    // In case of a reused connection, move the next request's bytes to the
    // beginning of the buffer.
    if (s.next_request_start > 0) {
        if (s.read_buffer_len > s.next_request_start) {
            rebase(s, 0);
        } else {
            s.read_buffer_len = 0;
        }
    }

    var hp: http.HeadParser = .{};

    if (s.read_buffer_len > 0) {
        const bytes = s.read_buffer[0..s.read_buffer_len];
        const end = hp.feed(bytes);
        if (hp.state == .finished)
            return finishReceivingHead(s, end);
    }

    while (true) {
        const buf = s.read_buffer[s.read_buffer_len..];
        if (buf.len == 0)
            return error.HttpHeadersOversize;
        const read_n = s.connection.stream.read(buf) catch
            return error.HttpHeadersUnreadable;
        if (read_n == 0) {
            if (s.read_buffer_len > 0) {
                return error.HttpRequestTruncated;
            } else {
                return error.HttpConnectionClosing;
            }
        }
        s.read_buffer_len += read_n;
        const bytes = buf[0..read_n];
        const end = hp.feed(bytes);
        if (hp.state == .finished)
            return finishReceivingHead(s, s.read_buffer_len - bytes.len + end);
    }
}

fn finishReceivingHead(s: *Server, head_end: usize) ReceiveHeadError!Request {
    return .{
        .server = s,
        .head_end = head_end,
        .head = Request.Head.parse(s.read_buffer[0..head_end]) catch
            return error.HttpHeadersInvalid,
        .reader_state = undefined,
    };
}

pub const Request = struct {
    server: *Server,
    /// Index into Server's read_buffer.
    head_end: usize,
    head: Head,
    reader_state: union {
        remaining_content_length: u64,
        chunk_parser: http.ChunkParser,
    },

    pub const Compression = union(enum) {
        pub const DeflateDecompressor = std.compress.zlib.Decompressor(std.io.AnyReader);
        pub const GzipDecompressor = std.compress.gzip.Decompressor(std.io.AnyReader);
        pub const ZstdDecompressor = std.compress.zstd.Decompressor(std.io.AnyReader);

        deflate: DeflateDecompressor,
        gzip: GzipDecompressor,
        zstd: ZstdDecompressor,
        none: void,
    };

    pub const Head = struct {
        method: http.Method,
        target: []const u8,
        version: http.Version,
        expect: ?[]const u8,
        content_type: ?[]const u8,
        content_length: ?u64,
        transfer_encoding: http.TransferEncoding,
        transfer_compression: http.ContentEncoding,
        keep_alive: bool,
        compression: Compression,

        pub const ParseError = error{
            UnknownHttpMethod,
            HttpHeadersInvalid,
            HttpHeaderContinuationsUnsupported,
            HttpTransferEncodingUnsupported,
            HttpConnectionHeaderUnsupported,
            InvalidContentLength,
            CompressionUnsupported,
            MissingFinalNewline,
        };

        pub fn parse(bytes: []const u8) ParseError!Head {
            var it = mem.splitSequence(u8, bytes, "\r\n");

            const first_line = it.next().?;
            if (first_line.len < 10)
                return error.HttpHeadersInvalid;

            const method_end = mem.indexOfScalar(u8, first_line, ' ') orelse
                return error.HttpHeadersInvalid;
            if (method_end > 24) return error.HttpHeadersInvalid;

            const method_str = first_line[0..method_end];
            const method: http.Method = @enumFromInt(http.Method.parse(method_str));

            const version_start = mem.lastIndexOfScalar(u8, first_line, ' ') orelse
                return error.HttpHeadersInvalid;
            if (version_start == method_end) return error.HttpHeadersInvalid;

            const version_str = first_line[version_start + 1 ..];
            if (version_str.len != 8) return error.HttpHeadersInvalid;
            const version: http.Version = switch (int64(version_str[0..8])) {
                int64("HTTP/1.0") => .@"HTTP/1.0",
                int64("HTTP/1.1") => .@"HTTP/1.1",
                else => return error.HttpHeadersInvalid,
            };

            const target = first_line[method_end + 1 .. version_start];

            var head: Head = .{
                .method = method,
                .target = target,
                .version = version,
                .expect = null,
                .content_type = null,
                .content_length = null,
                .transfer_encoding = .none,
                .transfer_compression = .identity,
                .keep_alive = switch (version) {
                    .@"HTTP/1.0" => false,
                    .@"HTTP/1.1" => true,
                },
                .compression = .none,
            };

            while (it.next()) |line| {
                if (line.len == 0) return head;
                switch (line[0]) {
                    ' ', '\t' => return error.HttpHeaderContinuationsUnsupported,
                    else => {},
                }

                var line_it = mem.splitScalar(u8, line, ':');
                const header_name = line_it.next().?;
                const header_value = mem.trim(u8, line_it.rest(), " \t");
                if (header_name.len == 0) return error.HttpHeadersInvalid;

                if (std.ascii.eqlIgnoreCase(header_name, "connection")) {
                    head.keep_alive = !std.ascii.eqlIgnoreCase(header_value, "close");
                } else if (std.ascii.eqlIgnoreCase(header_name, "expect")) {
                    head.expect = header_value;
                } else if (std.ascii.eqlIgnoreCase(header_name, "content-type")) {
                    head.content_type = header_value;
                } else if (std.ascii.eqlIgnoreCase(header_name, "content-length")) {
                    if (head.content_length != null) return error.HttpHeadersInvalid;
                    head.content_length = std.fmt.parseInt(u64, header_value, 10) catch
                        return error.InvalidContentLength;
                } else if (std.ascii.eqlIgnoreCase(header_name, "content-encoding")) {
                    if (head.transfer_compression != .identity) return error.HttpHeadersInvalid;

                    const trimmed = mem.trim(u8, header_value, " ");

                    if (std.meta.stringToEnum(http.ContentEncoding, trimmed)) |ce| {
                        head.transfer_compression = ce;
                    } else {
                        return error.HttpTransferEncodingUnsupported;
                    }
                } else if (std.ascii.eqlIgnoreCase(header_name, "transfer-encoding")) {
                    // Transfer-Encoding: second, first
                    // Transfer-Encoding: deflate, chunked
                    var iter = mem.splitBackwardsScalar(u8, header_value, ',');

                    const first = iter.first();
                    const trimmed_first = mem.trim(u8, first, " ");

                    var next: ?[]const u8 = first;
                    if (std.meta.stringToEnum(http.TransferEncoding, trimmed_first)) |transfer| {
                        if (head.transfer_encoding != .none)
                            return error.HttpHeadersInvalid; // we already have a transfer encoding
                        head.transfer_encoding = transfer;

                        next = iter.next();
                    }

                    if (next) |second| {
                        const trimmed_second = mem.trim(u8, second, " ");

                        if (std.meta.stringToEnum(http.ContentEncoding, trimmed_second)) |transfer| {
                            if (head.transfer_compression != .identity)
                                return error.HttpHeadersInvalid; // double compression is not supported
                            head.transfer_compression = transfer;
                        } else {
                            return error.HttpTransferEncodingUnsupported;
                        }
                    }

                    if (iter.next()) |_| return error.HttpTransferEncodingUnsupported;
                }
            }
            return error.MissingFinalNewline;
        }

        test parse {
            const request_bytes = "GET /hi HTTP/1.0\r\n" ++
                "content-tYpe: text/plain\r\n" ++
                "content-Length:10\r\n" ++
                "expeCt:   100-continue \r\n" ++
                "TRansfer-encoding:\tdeflate, chunked \r\n" ++
                "connectioN:\t keep-alive \r\n\r\n";

            const req = try parse(request_bytes);

            try testing.expectEqual(.GET, req.method);
            try testing.expectEqual(.@"HTTP/1.0", req.version);
            try testing.expectEqualStrings("/hi", req.target);

            try testing.expectEqualStrings("text/plain", req.content_type.?);
            try testing.expectEqualStrings("100-continue", req.expect.?);

            try testing.expectEqual(true, req.keep_alive);
            try testing.expectEqual(10, req.content_length.?);
            try testing.expectEqual(.chunked, req.transfer_encoding);
            try testing.expectEqual(.deflate, req.transfer_compression);
        }

        inline fn int64(array: *const [8]u8) u64 {
            return @bitCast(array.*);
        }
    };

    pub fn iterateHeaders(r: *Request) http.HeaderIterator {
        return http.HeaderIterator.init(r.server.read_buffer[0..r.head_end]);
    }

    test iterateHeaders {
        const request_bytes = "GET /hi HTTP/1.0\r\n" ++
            "content-tYpe: text/plain\r\n" ++
            "content-Length:10\r\n" ++
            "expeCt:   100-continue \r\n" ++
            "TRansfer-encoding:\tdeflate, chunked \r\n" ++
            "connectioN:\t keep-alive \r\n\r\n";

        var read_buffer: [500]u8 = undefined;
        @memcpy(read_buffer[0..request_bytes.len], request_bytes);

        var server: Server = .{
            .connection = undefined,
            .state = .ready,
            .read_buffer = &read_buffer,
            .read_buffer_len = request_bytes.len,
            .next_request_start = 0,
        };

        var request: Request = .{
            .server = &server,
            .head_end = request_bytes.len,
            .head = undefined,
            .reader_state = undefined,
        };

        var it = request.iterateHeaders();
        {
            const header = it.next().?;
            try testing.expectEqualStrings("content-tYpe", header.name);
            try testing.expectEqualStrings("text/plain", header.value);
            try testing.expect(!it.is_trailer);
        }
        {
            const header = it.next().?;
            try testing.expectEqualStrings("content-Length", header.name);
            try testing.expectEqualStrings("10", header.value);
            try testing.expect(!it.is_trailer);
        }
        {
            const header = it.next().?;
            try testing.expectEqualStrings("expeCt", header.name);
            try testing.expectEqualStrings("100-continue", header.value);
            try testing.expect(!it.is_trailer);
        }
        {
            const header = it.next().?;
            try testing.expectEqualStrings("TRansfer-encoding", header.name);
            try testing.expectEqualStrings("deflate, chunked", header.value);
            try testing.expect(!it.is_trailer);
        }
        {
            const header = it.next().?;
            try testing.expectEqualStrings("connectioN", header.name);
            try testing.expectEqualStrings("keep-alive", header.value);
            try testing.expect(!it.is_trailer);
        }
        try testing.expectEqual(null, it.next());
    }

    pub const RespondOptions = struct {
        version: http.Version = .@"HTTP/1.1",
        status: http.Status = .ok,
        reason: ?[]const u8 = null,
        keep_alive: bool = true,
        extra_headers: []const http.Header = &.{},
        transfer_encoding: ?http.TransferEncoding = null,
    };

    /// Send an entire HTTP response to the client, including headers and body.
    ///
    /// Automatically handles HEAD requests by omitting the body.
    ///
    /// Unless `transfer_encoding` is specified, uses the "content-length"
    /// header.
    ///
    /// If the request contains a body and the connection is to be reused,
    /// discards the request body, leaving the Server in the `ready` state. If
    /// this discarding fails, the connection is marked as not to be reused and
    /// no error is surfaced.
    ///
    /// Asserts status is not `continue`.
    /// Asserts there are at most 25 extra_headers.
    /// Asserts that "\r\n" does not occur in any header name or value.
    pub fn respond(
        request: *Request,
        content: []const u8,
        options: RespondOptions,
    ) Response.WriteError!void {
        const max_extra_headers = 25;
        assert(options.status != .@"continue");
        assert(options.extra_headers.len <= max_extra_headers);
        if (std.debug.runtime_safety) {
            for (options.extra_headers) |header| {
                assert(header.name.len != 0);
                assert(std.mem.indexOfScalar(u8, header.name, ':') == null);
                assert(std.mem.indexOfPosLinear(u8, header.name, 0, "\r\n") == null);
                assert(std.mem.indexOfPosLinear(u8, header.value, 0, "\r\n") == null);
            }
        }

        const transfer_encoding_none = (options.transfer_encoding orelse .chunked) == .none;
        const server_keep_alive = !transfer_encoding_none and options.keep_alive;
        const keep_alive = request.discardBody(server_keep_alive);

        const phrase = options.reason orelse options.status.phrase() orelse "";

        var first_buffer: [500]u8 = undefined;
        var h = std.ArrayListUnmanaged(u8).initBuffer(&first_buffer);
        if (request.head.expect != null) {
            // reader() and hence discardBody() above sets expect to null if it
            // is handled. So the fact that it is not null here means unhandled.
            h.appendSliceAssumeCapacity("HTTP/1.1 417 Expectation Failed\r\n");
            if (!keep_alive) h.appendSliceAssumeCapacity("connection: close\r\n");
            h.appendSliceAssumeCapacity("content-length: 0\r\n\r\n");
            try request.server.connection.stream.writeAll(h.items);
            return;
        }
        h.fixedWriter().print("{s} {d} {s}\r\n", .{
            @tagName(options.version), @intFromEnum(options.status), phrase,
        }) catch unreachable;

        switch (options.version) {
            .@"HTTP/1.0" => if (keep_alive) h.appendSliceAssumeCapacity("connection: keep-alive\r\n"),
            .@"HTTP/1.1" => if (!keep_alive) h.appendSliceAssumeCapacity("connection: close\r\n"),
        }

        if (options.transfer_encoding) |transfer_encoding| switch (transfer_encoding) {
            .none => {},
            .chunked => h.appendSliceAssumeCapacity("transfer-encoding: chunked\r\n"),
        } else {
            h.fixedWriter().print("content-length: {d}\r\n", .{content.len}) catch unreachable;
        }

        var chunk_header_buffer: [18]u8 = undefined;
        var iovecs: [max_extra_headers * 4 + 3]std.posix.iovec_const = undefined;
        var iovecs_len: usize = 0;

        iovecs[iovecs_len] = .{
            .base = h.items.ptr,
            .len = h.items.len,
        };
        iovecs_len += 1;

        for (options.extra_headers) |header| {
            iovecs[iovecs_len] = .{
                .base = header.name.ptr,
                .len = header.name.len,
            };
            iovecs_len += 1;

            iovecs[iovecs_len] = .{
                .base = ": ",
                .len = 2,
            };
            iovecs_len += 1;

            if (header.value.len != 0) {
                iovecs[iovecs_len] = .{
                    .base = header.value.ptr,
                    .len = header.value.len,
                };
                iovecs_len += 1;
            }

            iovecs[iovecs_len] = .{
                .base = "\r\n",
                .len = 2,
            };
            iovecs_len += 1;
        }

        iovecs[iovecs_len] = .{
            .base = "\r\n",
            .len = 2,
        };
        iovecs_len += 1;

        if (request.head.method != .HEAD) {
            const is_chunked = (options.transfer_encoding orelse .none) == .chunked;
            if (is_chunked) {
                if (content.len > 0) {
                    const chunk_header = std.fmt.bufPrint(
                        &chunk_header_buffer,
                        "{x}\r\n",
                        .{content.len},
                    ) catch unreachable;

                    iovecs[iovecs_len] = .{
                        .base = chunk_header.ptr,
                        .len = chunk_header.len,
                    };
                    iovecs_len += 1;

                    iovecs[iovecs_len] = .{
                        .base = content.ptr,
                        .len = content.len,
                    };
                    iovecs_len += 1;

                    iovecs[iovecs_len] = .{
                        .base = "\r\n",
                        .len = 2,
                    };
                    iovecs_len += 1;
                }

                iovecs[iovecs_len] = .{
                    .base = "0\r\n\r\n",
                    .len = 5,
                };
                iovecs_len += 1;
            } else if (content.len > 0) {
                iovecs[iovecs_len] = .{
                    .base = content.ptr,
                    .len = content.len,
                };
                iovecs_len += 1;
            }
        }

        try request.server.connection.stream.writevAll(iovecs[0..iovecs_len]);
    }

    pub const RespondStreamingOptions = struct {
        /// An externally managed slice of memory used to batch bytes before
        /// sending. `respondStreaming` asserts this is large enough to store
        /// the full HTTP response head.
        ///
        /// Must outlive the returned Response.
        send_buffer: []u8,
        /// If provided, the response will use the content-length header;
        /// otherwise it will use transfer-encoding: chunked.
        content_length: ?u64 = null,
        /// Options that are shared with the `respond` method.
        respond_options: RespondOptions = .{},
    };

    /// The header is buffered but not sent until Response.flush is called.
    ///
    /// If the request contains a body and the connection is to be reused,
    /// discards the request body, leaving the Server in the `ready` state. If
    /// this discarding fails, the connection is marked as not to be reused and
    /// no error is surfaced.
    ///
    /// HEAD requests are handled transparently by setting a flag on the
    /// returned Response to omit the body. However it may be worth noticing
    /// that flag and skipping any expensive work that would otherwise need to
    /// be done to satisfy the request.
    ///
    /// Asserts `send_buffer` is large enough to store the entire response header.
    /// Asserts status is not `continue`.
    pub fn respondStreaming(request: *Request, options: RespondStreamingOptions) Response {
        const o = options.respond_options;
        assert(o.status != .@"continue");
        const transfer_encoding_none = (o.transfer_encoding orelse .chunked) == .none;
        const server_keep_alive = !transfer_encoding_none and o.keep_alive;
        const keep_alive = request.discardBody(server_keep_alive);
        const phrase = o.reason orelse o.status.phrase() orelse "";

        var h = std.ArrayListUnmanaged(u8).initBuffer(options.send_buffer);

        const elide_body = if (request.head.expect != null) eb: {
            // reader() and hence discardBody() above sets expect to null if it
            // is handled. So the fact that it is not null here means unhandled.
            h.appendSliceAssumeCapacity("HTTP/1.1 417 Expectation Failed\r\n");
            if (!keep_alive) h.appendSliceAssumeCapacity("connection: close\r\n");
            h.appendSliceAssumeCapacity("content-length: 0\r\n\r\n");
            break :eb true;
        } else eb: {
            h.fixedWriter().print("{s} {d} {s}\r\n", .{
                @tagName(o.version), @intFromEnum(o.status), phrase,
            }) catch unreachable;

            switch (o.version) {
                .@"HTTP/1.0" => if (keep_alive) h.appendSliceAssumeCapacity("connection: keep-alive\r\n"),
                .@"HTTP/1.1" => if (!keep_alive) h.appendSliceAssumeCapacity("connection: close\r\n"),
            }

            if (o.transfer_encoding) |transfer_encoding| switch (transfer_encoding) {
                .chunked => h.appendSliceAssumeCapacity("transfer-encoding: chunked\r\n"),
                .none => {},
            } else if (options.content_length) |len| {
                h.fixedWriter().print("content-length: {d}\r\n", .{len}) catch unreachable;
            } else {
                h.appendSliceAssumeCapacity("transfer-encoding: chunked\r\n");
            }

            for (o.extra_headers) |header| {
                assert(header.name.len != 0);
                h.appendSliceAssumeCapacity(header.name);
                h.appendSliceAssumeCapacity(": ");
                h.appendSliceAssumeCapacity(header.value);
                h.appendSliceAssumeCapacity("\r\n");
            }

            h.appendSliceAssumeCapacity("\r\n");
            break :eb request.head.method == .HEAD;
        };

        return .{
            .stream = request.server.connection.stream,
            .send_buffer = options.send_buffer,
            .send_buffer_start = 0,
            .send_buffer_end = h.items.len,
            .transfer_encoding = if (o.transfer_encoding) |te| switch (te) {
                .chunked => .chunked,
                .none => .none,
            } else if (options.content_length) |len| .{
                .content_length = len,
            } else .chunked,
            .elide_body = elide_body,
            .chunk_len = 0,
        };
    }

    pub const ReadError = net.Stream.ReadError || error{
        HttpChunkInvalid,
        HttpHeadersOversize,
    };

    fn read_cl(context: *const anyopaque, buffer: []u8) ReadError!usize {
        const request: *Request = @constCast(@alignCast(@ptrCast(context)));
        const s = request.server;

        const remaining_content_length = &request.reader_state.remaining_content_length;
        if (remaining_content_length.* == 0) {
            s.state = .ready;
            return 0;
        }
        assert(s.state == .receiving_body);
        const available = try fill(s, request.head_end);
        const len = @min(remaining_content_length.*, available.len, buffer.len);
        @memcpy(buffer[0..len], available[0..len]);
        remaining_content_length.* -= len;
        s.next_request_start += len;
        if (remaining_content_length.* == 0)
            s.state = .ready;
        return len;
    }

    fn fill(s: *Server, head_end: usize) ReadError![]u8 {
        const available = s.read_buffer[s.next_request_start..s.read_buffer_len];
        if (available.len > 0) return available;
        s.next_request_start = head_end;
        s.read_buffer_len = head_end + try s.connection.stream.read(s.read_buffer[head_end..]);
        return s.read_buffer[head_end..s.read_buffer_len];
    }

    fn read_chunked(context: *const anyopaque, buffer: []u8) ReadError!usize {
        const request: *Request = @constCast(@alignCast(@ptrCast(context)));
        const s = request.server;

        const cp = &request.reader_state.chunk_parser;
        const head_end = request.head_end;

        // Protect against returning 0 before the end of stream.
        var out_end: usize = 0;
        while (out_end == 0) {
            switch (cp.state) {
                .invalid => return 0,
                .data => {
                    assert(s.state == .receiving_body);
                    const available = try fill(s, head_end);
                    const len = @min(cp.chunk_len, available.len, buffer.len);
                    @memcpy(buffer[0..len], available[0..len]);
                    cp.chunk_len -= len;
                    if (cp.chunk_len == 0)
                        cp.state = .data_suffix;
                    out_end += len;
                    s.next_request_start += len;
                    continue;
                },
                else => {
                    assert(s.state == .receiving_body);
                    const available = try fill(s, head_end);
                    const n = cp.feed(available);
                    switch (cp.state) {
                        .invalid => return error.HttpChunkInvalid,
                        .data => {
                            if (cp.chunk_len == 0) {
                                // The next bytes in the stream are trailers,
                                // or \r\n to indicate end of chunked body.
                                //
                                // This function must append the trailers at
                                // head_end so that headers and trailers are
                                // together.
                                //
                                // Since returning 0 would indicate end of
                                // stream, this function must read all the
                                // trailers before returning.
                                if (s.next_request_start > head_end) rebase(s, head_end);
                                var hp: http.HeadParser = .{};
                                {
                                    const bytes = s.read_buffer[head_end..s.read_buffer_len];
                                    const end = hp.feed(bytes);
                                    if (hp.state == .finished) {
                                        cp.state = .invalid;
                                        s.state = .ready;
                                        s.next_request_start = s.read_buffer_len - bytes.len + end;
                                        return out_end;
                                    }
                                }
                                while (true) {
                                    const buf = s.read_buffer[s.read_buffer_len..];
                                    if (buf.len == 0)
                                        return error.HttpHeadersOversize;
                                    const read_n = try s.connection.stream.read(buf);
                                    s.read_buffer_len += read_n;
                                    const bytes = buf[0..read_n];
                                    const end = hp.feed(bytes);
                                    if (hp.state == .finished) {
                                        cp.state = .invalid;
                                        s.state = .ready;
                                        s.next_request_start = s.read_buffer_len - bytes.len + end;
                                        return out_end;
                                    }
                                }
                            }
                            const data = available[n..];
                            const len = @min(cp.chunk_len, data.len, buffer.len);
                            @memcpy(buffer[0..len], data[0..len]);
                            cp.chunk_len -= len;
                            if (cp.chunk_len == 0)
                                cp.state = .data_suffix;
                            out_end += len;
                            s.next_request_start += n + len;
                            continue;
                        },
                        else => continue,
                    }
                },
            }
        }
        return out_end;
    }

    pub const ReaderError = Response.WriteError || error{
        /// The client sent an expect HTTP header value other than
        /// "100-continue".
        HttpExpectationFailed,
    };

    /// In the case that the request contains "expect: 100-continue", this
    /// function writes the continuation header, which means it can fail with a
    /// write error. After sending the continuation header, it sets the
    /// request's expect field to `null`.
    ///
    /// Asserts that this function is only called once.
    pub fn reader(request: *Request) ReaderError!std.io.AnyReader {
        const s = request.server;
        assert(s.state == .received_head);
        s.state = .receiving_body;
        s.next_request_start = request.head_end;

        if (request.head.expect) |expect| {
            if (mem.eql(u8, expect, "100-continue")) {
                try request.server.connection.stream.writeAll("HTTP/1.1 100 Continue\r\n\r\n");
                request.head.expect = null;
            } else {
                return error.HttpExpectationFailed;
            }
        }

        switch (request.head.transfer_encoding) {
            .chunked => {
                request.reader_state = .{ .chunk_parser = http.ChunkParser.init };
                return .{
                    .readFn = read_chunked,
                    .context = request,
                };
            },
            .none => {
                request.reader_state = .{
                    .remaining_content_length = request.head.content_length orelse 0,
                };
                return .{
                    .readFn = read_cl,
                    .context = request,
                };
            },
        }
    }

    /// Returns whether the connection should remain persistent.
    /// If it would fail, it instead sets the Server state to `receiving_body`
    /// and returns false.
    fn discardBody(request: *Request, keep_alive: bool) bool {
        // Prepare to receive another request on the same connection.
        // There are two factors to consider:
        // * Any body the client sent must be discarded.
        // * The Server's read_buffer may already have some bytes in it from
        //   whatever came after the head, which may be the next HTTP request
        //   or the request body.
        // If the connection won't be kept alive, then none of this matters
        // because the connection will be severed after the response is sent.
        const s = request.server;
        if (keep_alive and request.head.keep_alive) switch (s.state) {
            .received_head => {
                const r = request.reader() catch return false;
                _ = r.discard() catch return false;
                assert(s.state == .ready);
                return true;
            },
            .receiving_body, .ready => return true,
            else => unreachable,
        };

        // Avoid clobbering the state in case a reading stream already exists.
        switch (s.state) {
            .received_head => s.state = .closing,
            else => {},
        }
        return false;
    }
};

pub const Response = struct {
    stream: net.Stream,
    send_buffer: []u8,
    /// Index of the first byte in `send_buffer`.
    /// This is 0 unless a short write happens in `write`.
    send_buffer_start: usize,
    /// Index of the last byte + 1 in `send_buffer`.
    send_buffer_end: usize,
    /// `null` means transfer-encoding: chunked.
    /// As a debugging utility, counts down to zero as bytes are written.
    transfer_encoding: TransferEncoding,
    elide_body: bool,
    /// Indicates how much of the end of the `send_buffer` corresponds to a
    /// chunk. This amount of data will be wrapped by an HTTP chunk header.
    chunk_len: usize,

    pub const TransferEncoding = union(enum) {
        /// End of connection signals the end of the stream.
        none,
        /// As a debugging utility, counts down to zero as bytes are written.
        content_length: u64,
        /// Each chunk is wrapped in a header and trailer.
        chunked,
    };

    pub const WriteError = net.Stream.WriteError;

    /// When using content-length, asserts that the amount of data sent matches
    /// the value sent in the header, then calls `flush`.
    /// Otherwise, transfer-encoding: chunked is being used, and it writes the
    /// end-of-stream message, then flushes the stream to the system.
    /// Respects the value of `elide_body` to omit all data after the headers.
    pub fn end(r: *Response) WriteError!void {
        switch (r.transfer_encoding) {
            .content_length => |len| {
                assert(len == 0); // Trips when end() called before all bytes written.
                try flush_cl(r);
            },
            .none => {
                try flush_cl(r);
            },
            .chunked => {
                try flush_chunked(r, &.{});
            },
        }
        r.* = undefined;
    }

    pub const EndChunkedOptions = struct {
        trailers: []const http.Header = &.{},
    };

    /// Asserts that the Response is using transfer-encoding: chunked.
    /// Writes the end-of-stream message and any optional trailers, then
    /// flushes the stream to the system.
    /// Respects the value of `elide_body` to omit all data after the headers.
    /// Asserts there are at most 25 trailers.
    pub fn endChunked(r: *Response, options: EndChunkedOptions) WriteError!void {
        assert(r.transfer_encoding == .chunked);
        try flush_chunked(r, options.trailers);
        r.* = undefined;
    }

    /// If using content-length, asserts that writing these bytes to the client
    /// would not exceed the content-length value sent in the HTTP header.
    /// May return 0, which does not indicate end of stream. The caller decides
    /// when the end of stream occurs by calling `end`.
    pub fn write(r: *Response, bytes: []const u8) WriteError!usize {
        switch (r.transfer_encoding) {
            .content_length, .none => return write_cl(r, bytes),
            .chunked => return write_chunked(r, bytes),
        }
    }

    fn write_cl(context: *const anyopaque, bytes: []const u8) WriteError!usize {
        const r: *Response = @constCast(@alignCast(@ptrCast(context)));

        var trash: u64 = std.math.maxInt(u64);
        const len = switch (r.transfer_encoding) {
            .content_length => |*len| len,
            else => &trash,
        };

        if (r.elide_body) {
            len.* -= bytes.len;
            return bytes.len;
        }

        if (bytes.len + r.send_buffer_end > r.send_buffer.len) {
            const send_buffer_len = r.send_buffer_end - r.send_buffer_start;
            var iovecs: [2]std.posix.iovec_const = .{
                .{
                    .base = r.send_buffer.ptr + r.send_buffer_start,
                    .len = send_buffer_len,
                },
                .{
                    .base = bytes.ptr,
                    .len = bytes.len,
                },
            };
            const n = try r.stream.writev(&iovecs);

            if (n >= send_buffer_len) {
                // It was enough to reset the buffer.
                r.send_buffer_start = 0;
                r.send_buffer_end = 0;
                const bytes_n = n - send_buffer_len;
                len.* -= bytes_n;
                return bytes_n;
            }

            // It didn't even make it through the existing buffer, let
            // alone the new bytes provided.
            r.send_buffer_start += n;
            return 0;
        }

        // All bytes can be stored in the remaining space of the buffer.
        @memcpy(r.send_buffer[r.send_buffer_end..][0..bytes.len], bytes);
        r.send_buffer_end += bytes.len;
        len.* -= bytes.len;
        return bytes.len;
    }

    fn write_chunked(context: *const anyopaque, bytes: []const u8) WriteError!usize {
        const r: *Response = @constCast(@alignCast(@ptrCast(context)));
        assert(r.transfer_encoding == .chunked);

        if (r.elide_body)
            return bytes.len;

        if (bytes.len + r.send_buffer_end > r.send_buffer.len) {
            const send_buffer_len = r.send_buffer_end - r.send_buffer_start;
            const chunk_len = r.chunk_len + bytes.len;
            var header_buf: [18]u8 = undefined;
            const chunk_header = std.fmt.bufPrint(&header_buf, "{x}\r\n", .{chunk_len}) catch unreachable;

            var iovecs: [5]std.posix.iovec_const = .{
                .{
                    .base = r.send_buffer.ptr + r.send_buffer_start,
                    .len = send_buffer_len - r.chunk_len,
                },
                .{
                    .base = chunk_header.ptr,
                    .len = chunk_header.len,
                },
                .{
                    .base = r.send_buffer.ptr + r.send_buffer_end - r.chunk_len,
                    .len = r.chunk_len,
                },
                .{
                    .base = bytes.ptr,
                    .len = bytes.len,
                },
                .{
                    .base = "\r\n",
                    .len = 2,
                },
            };
            // TODO make this writev instead of writevAll, which involves
            // complicating the logic of this function.
            try r.stream.writevAll(&iovecs);
            r.send_buffer_start = 0;
            r.send_buffer_end = 0;
            r.chunk_len = 0;
            return bytes.len;
        }

        // All bytes can be stored in the remaining space of the buffer.
        @memcpy(r.send_buffer[r.send_buffer_end..][0..bytes.len], bytes);
        r.send_buffer_end += bytes.len;
        r.chunk_len += bytes.len;
        return bytes.len;
    }

    /// If using content-length, asserts that writing these bytes to the client
    /// would not exceed the content-length value sent in the HTTP header.
    pub fn writeAll(r: *Response, bytes: []const u8) WriteError!void {
        var index: usize = 0;
        while (index < bytes.len) {
            index += try write(r, bytes[index..]);
        }
    }

    /// Sends all buffered data to the client.
    /// This is redundant after calling `end`.
    /// Respects the value of `elide_body` to omit all data after the headers.
    pub fn flush(r: *Response) WriteError!void {
        switch (r.transfer_encoding) {
            .none, .content_length => return flush_cl(r),
            .chunked => return flush_chunked(r, null),
        }
    }

    fn flush_cl(r: *Response) WriteError!void {
        try r.stream.writeAll(r.send_buffer[r.send_buffer_start..r.send_buffer_end]);
        r.send_buffer_start = 0;
        r.send_buffer_end = 0;
    }

    fn flush_chunked(r: *Response, end_trailers: ?[]const http.Header) WriteError!void {
        const max_trailers = 25;
        if (end_trailers) |trailers| assert(trailers.len <= max_trailers);
        assert(r.transfer_encoding == .chunked);

        const http_headers = r.send_buffer[r.send_buffer_start .. r.send_buffer_end - r.chunk_len];

        if (r.elide_body) {
            try r.stream.writeAll(http_headers);
            r.send_buffer_start = 0;
            r.send_buffer_end = 0;
            r.chunk_len = 0;
            return;
        }

        var header_buf: [18]u8 = undefined;
        const chunk_header = std.fmt.bufPrint(&header_buf, "{x}\r\n", .{r.chunk_len}) catch unreachable;

        var iovecs: [max_trailers * 4 + 5]std.posix.iovec_const = undefined;
        var iovecs_len: usize = 0;

        iovecs[iovecs_len] = .{
            .base = http_headers.ptr,
            .len = http_headers.len,
        };
        iovecs_len += 1;

        if (r.chunk_len > 0) {
            iovecs[iovecs_len] = .{
                .base = chunk_header.ptr,
                .len = chunk_header.len,
            };
            iovecs_len += 1;

            iovecs[iovecs_len] = .{
                .base = r.send_buffer.ptr + r.send_buffer_end - r.chunk_len,
                .len = r.chunk_len,
            };
            iovecs_len += 1;

            iovecs[iovecs_len] = .{
                .base = "\r\n",
                .len = 2,
            };
            iovecs_len += 1;
        }

        if (end_trailers) |trailers| {
            iovecs[iovecs_len] = .{
                .base = "0\r\n",
                .len = 3,
            };
            iovecs_len += 1;

            for (trailers) |trailer| {
                iovecs[iovecs_len] = .{
                    .base = trailer.name.ptr,
                    .len = trailer.name.len,
                };
                iovecs_len += 1;

                iovecs[iovecs_len] = .{
                    .base = ": ",
                    .len = 2,
                };
                iovecs_len += 1;

                if (trailer.value.len != 0) {
                    iovecs[iovecs_len] = .{
                        .base = trailer.value.ptr,
                        .len = trailer.value.len,
                    };
                    iovecs_len += 1;
                }

                iovecs[iovecs_len] = .{
                    .base = "\r\n",
                    .len = 2,
                };
                iovecs_len += 1;
            }

            iovecs[iovecs_len] = .{
                .base = "\r\n",
                .len = 2,
            };
            iovecs_len += 1;
        }

        try r.stream.writevAll(iovecs[0..iovecs_len]);
        r.send_buffer_start = 0;
        r.send_buffer_end = 0;
        r.chunk_len = 0;
    }

    pub fn writer(r: *Response) std.io.AnyWriter {
        return .{
            .writeFn = switch (r.transfer_encoding) {
                .none, .content_length => write_cl,
                .chunked => write_chunked,
            },
            .context = r,
        };
    }
};

fn rebase(s: *Server, index: usize) void {
    const leftover = s.read_buffer[s.next_request_start..s.read_buffer_len];
    const dest = s.read_buffer[index..][0..leftover.len];
    if (leftover.len <= s.next_request_start - index) {
        @memcpy(dest, leftover);
    } else {
        mem.copyBackwards(u8, dest, leftover);
    }
    s.read_buffer_len = index + leftover.len;
}

const std = @import("../std.zig");
const http = std.http;
const mem = std.mem;
const net = std.net;
const Uri = std.Uri;
const assert = std.debug.assert;
const testing = std.testing;

const Server = @This();
const builtin = @import("builtin");
const std = @import("std");
const http = std.http;
const mem = std.mem;
const native_endian = builtin.cpu.arch.endian();
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;
const expectError = std.testing.expectError;

test "trailers" {
    const test_server = try createTestServer(struct {
        fn run(net_server: *std.net.Server) anyerror!void {
            var header_buffer: [1024]u8 = undefined;
            var remaining: usize = 1;
            while (remaining != 0) : (remaining -= 1) {
                const conn = try net_server.accept();
                defer conn.stream.close();

                var server = http.Server.init(conn, &header_buffer);

                try expectEqual(.ready, server.state);
                var request = try server.receiveHead();
                try serve(&request);
                try expectEqual(.ready, server.state);
            }
        }

        fn serve(request: *http.Server.Request) !void {
            try expectEqualStrings(request.head.target, "/trailer");

            var send_buffer: [1024]u8 = undefined;
            var response = request.respondStreaming(.{
                .send_buffer = &send_buffer,
            });
            try response.writeAll("Hello, ");
            try response.flush();
            try response.writeAll("World!\n");
            try response.flush();
            try response.endChunked(.{
                .trailers = &.{
                    .{ .name = "X-Checksum", .value = "aaaa" },
                },
            });
        }
    });
    defer test_server.destroy();

    const gpa = std.testing.allocator;

    var client: http.Client = .{ .allocator = gpa };
    defer client.deinit();

    const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/trailer", .{
        test_server.port(),
    });
    defer gpa.free(location);
    const uri = try std.Uri.parse(location);

    {
        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.GET, uri, .{
            .server_header_buffer = &server_header_buffer,
        });
        defer req.deinit();

        try req.send();
        try req.wait();

        const body = try req.reader().readAllAlloc(gpa, 8192);
        defer gpa.free(body);

        try expectEqualStrings("Hello, World!\n", body);

        var it = req.response.iterateHeaders();
        {
            const header = it.next().?;
            try expect(!it.is_trailer);
            try expectEqualStrings("transfer-encoding", header.name);
            try expectEqualStrings("chunked", header.value);
        }
        {
            const header = it.next().?;
            try expect(it.is_trailer);
            try expectEqualStrings("X-Checksum", header.name);
            try expectEqualStrings("aaaa", header.value);
        }
        try expectEqual(null, it.next());
    }

    // connection has been kept alive
    try expect(client.connection_pool.free_len == 1);
}

test "HTTP server handles a chunked transfer coding request" {
    const test_server = try createTestServer(struct {
        fn run(net_server: *std.net.Server) !void {
            var header_buffer: [8192]u8 = undefined;
            const conn = try net_server.accept();
            defer conn.stream.close();

            var server = http.Server.init(conn, &header_buffer);
            var request = try server.receiveHead();

            try expect(request.head.transfer_encoding == .chunked);

            var buf: [128]u8 = undefined;
            const n = try (try request.reader()).readAll(&buf);
            try expect(mem.eql(u8, buf[0..n], "ABCD"));

            try request.respond("message from server!\n", .{
                .extra_headers = &.{
                    .{ .name = "content-type", .value = "text/plain" },
                },
                .keep_alive = false,
            });
        }
    });
    defer test_server.destroy();

    const request_bytes =
        "POST / HTTP/1.1\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "1\r\n" ++
        "A\r\n" ++
        "1\r\n" ++
        "B\r\n" ++
        "2\r\n" ++
        "CD\r\n" ++
        "0\r\n" ++
        "\r\n";

    const gpa = std.testing.allocator;
    const stream = try std.net.tcpConnectToHost(gpa, "127.0.0.1", test_server.port());
    defer stream.close();
    try stream.writeAll(request_bytes);

    const expected_response =
        "HTTP/1.1 200 OK\r\n" ++
        "connection: close\r\n" ++
        "content-length: 21\r\n" ++
        "content-type: text/plain\r\n" ++
        "\r\n" ++
        "message from server!\n";
    const response = try stream.reader().readAllAlloc(gpa, expected_response.len);
    defer gpa.free(response);
    try expectEqualStrings(expected_response, response);
}

test "echo content server" {
    const test_server = try createTestServer(struct {
        fn run(net_server: *std.net.Server) anyerror!void {
            var read_buffer: [1024]u8 = undefined;

            accept: while (true) {
                const conn = try net_server.accept();
                defer conn.stream.close();

                var http_server = http.Server.init(conn, &read_buffer);

                while (http_server.state == .ready) {
                    var request = http_server.receiveHead() catch |err| switch (err) {
                        error.HttpConnectionClosing => continue :accept,
                        else => |e| return e,
                    };
                    if (mem.eql(u8, request.head.target, "/end")) {
                        return request.respond("", .{ .keep_alive = false });
                    }
                    if (request.head.expect) |expect_header_value| {
                        if (mem.eql(u8, expect_header_value, "garbage")) {
                            try expectError(error.HttpExpectationFailed, request.reader());
                            try request.respond("", .{ .keep_alive = false });
                            continue;
                        }
                    }
                    handleRequest(&request) catch |err| {
                        // This message helps the person troubleshooting determine whether
                        // output comes from the server thread or the client thread.
                        std.debug.print("handleRequest failed with '{s}'\n", .{@errorName(err)});
                        return err;
                    };
                }
            }
        }

        fn handleRequest(request: *http.Server.Request) !void {
            //std.debug.print("server received {s} {s} {s}\n", .{
            //    @tagName(request.head.method),
            //    @tagName(request.head.version),
            //    request.head.target,
            //});

            const body = try (try request.reader()).readAllAlloc(std.testing.allocator, 8192);
            defer std.testing.allocator.free(body);

            try expect(mem.startsWith(u8, request.head.target, "/echo-content"));
            try expectEqualStrings("Hello, World!\n", body);
            try expectEqualStrings("text/plain", request.head.content_type.?);

            var send_buffer: [100]u8 = undefined;
            var response = request.respondStreaming(.{
                .send_buffer = &send_buffer,
                .content_length = switch (request.head.transfer_encoding) {
                    .chunked => null,
                    .none => len: {
                        try expectEqual(14, request.head.content_length.?);
                        break :len 14;
                    },
                },
            });

            try response.flush(); // Test an early flush to send the HTTP headers before the body.
            const w = response.writer();
            try w.writeAll("Hello, ");
            try w.writeAll("World!\n");
            try response.end();
            //std.debug.print("  server finished responding\n", .{});
        }
    });
    defer test_server.destroy();

    {
        var client: http.Client = .{ .allocator = std.testing.allocator };
        defer client.deinit();

        try echoTests(&client, test_server.port());
    }
}

test "Server.Request.respondStreaming non-chunked, unknown content-length" {
    if (builtin.os.tag == .windows) {
        // https://github.com/ziglang/zig/issues/21457
        return error.SkipZigTest;
    }

    // In this case, the response is expected to stream until the connection is
    // closed, indicating the end of the body.
    const test_server = try createTestServer(struct {
        fn run(net_server: *std.net.Server) anyerror!void {
            var header_buffer: [1000]u8 = undefined;
            var remaining: usize = 1;
            while (remaining != 0) : (remaining -= 1) {
                const conn = try net_server.accept();
                defer conn.stream.close();

                var server = http.Server.init(conn, &header_buffer);

                try expectEqual(.ready, server.state);
                var request = try server.receiveHead();
                try expectEqualStrings(request.head.target, "/foo");
                var send_buffer: [500]u8 = undefined;
                var response = request.respondStreaming(.{
                    .send_buffer = &send_buffer,
                    .respond_options = .{
                        .transfer_encoding = .none,
                    },
                });
                var total: usize = 0;
                for (0..500) |i| {
                    var buf: [30]u8 = undefined;
                    const line = try std.fmt.bufPrint(&buf, "{d}, ah ha ha!\n", .{i});
                    try response.writeAll(line);
                    total += line.len;
                }
                try expectEqual(7390, total);
                try response.end();
                try expectEqual(.closing, server.state);
            }
        }
    });
    defer test_server.destroy();

    const request_bytes = "GET /foo HTTP/1.1\r\n\r\n";
    const gpa = std.testing.allocator;
    const stream = try std.net.tcpConnectToHost(gpa, "127.0.0.1", test_server.port());
    defer stream.close();
    try stream.writeAll(request_bytes);

    const response = try stream.reader().readAllAlloc(gpa, 8192);
    defer gpa.free(response);

    var expected_response = std.ArrayList(u8).init(gpa);
    defer expected_response.deinit();

    try expected_response.appendSlice("HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n");

    {
        var total: usize = 0;
        for (0..500) |i| {
            var buf: [30]u8 = undefined;
            const line = try std.fmt.bufPrint(&buf, "{d}, ah ha ha!\n", .{i});
            try expected_response.appendSlice(line);
            total += line.len;
        }
        try expectEqual(7390, total);
    }

    try expectEqualStrings(expected_response.items, response);
}

test "receiving arbitrary http headers from the client" {
    const test_server = try createTestServer(struct {
        fn run(net_server: *std.net.Server) anyerror!void {
            var read_buffer: [666]u8 = undefined;
            var remaining: usize = 1;
            while (remaining != 0) : (remaining -= 1) {
                const conn = try net_server.accept();
                defer conn.stream.close();

                var server = http.Server.init(conn, &read_buffer);
                try expectEqual(.ready, server.state);
                var request = try server.receiveHead();
                try expectEqualStrings("/bar", request.head.target);
                var it = request.iterateHeaders();
                {
                    const header = it.next().?;
                    try expectEqualStrings("CoNneCtIoN", header.name);
                    try expectEqualStrings("close", header.value);
                    try expect(!it.is_trailer);
                }
                {
                    const header = it.next().?;
                    try expectEqualStrings("aoeu", header.name);
                    try expectEqualStrings("asdf", header.value);
                    try expect(!it.is_trailer);
                }
                try request.respond("", .{});
            }
        }
    });
    defer test_server.destroy();

    const request_bytes = "GET /bar HTTP/1.1\r\n" ++
        "CoNneCtIoN:close\r\n" ++
        "aoeu:  asdf \r\n" ++
        "\r\n";
    const gpa = std.testing.allocator;
    const stream = try std.net.tcpConnectToHost(gpa, "127.0.0.1", test_server.port());
    defer stream.close();
    try stream.writeAll(request_bytes);

    const response = try stream.reader().readAllAlloc(gpa, 8192);
    defer gpa.free(response);

    var expected_response = std.ArrayList(u8).init(gpa);
    defer expected_response.deinit();

    try expected_response.appendSlice("HTTP/1.1 200 OK\r\n");
    try expected_response.appendSlice("connection: close\r\n");
    try expected_response.appendSlice("content-length: 0\r\n\r\n");
    try expectEqualStrings(expected_response.items, response);
}

test "general client/server API coverage" {
    if (builtin.os.tag == .windows) {
        // This test was never passing on Windows.
        return error.SkipZigTest;
    }

    const global = struct {
        var handle_new_requests = true;
    };
    const test_server = try createTestServer(struct {
        fn run(net_server: *std.net.Server) anyerror!void {
            var client_header_buffer: [1024]u8 = undefined;
            outer: while (global.handle_new_requests) {
                var connection = try net_server.accept();
                defer connection.stream.close();

                var http_server = http.Server.init(connection, &client_header_buffer);

                while (http_server.state == .ready) {
                    var request = http_server.receiveHead() catch |err| switch (err) {
                        error.HttpConnectionClosing => continue :outer,
                        else => |e| return e,
                    };

                    try handleRequest(&request, net_server.listen_address.getPort());
                }
            }
        }

        fn handleRequest(request: *http.Server.Request, listen_port: u16) !void {
            const log = std.log.scoped(.server);

            log.info("{} {s} {s}", .{
                request.head.method,
                @tagName(request.head.version),
                request.head.target,
            });

            const gpa = std.testing.allocator;
            const body = try (try request.reader()).readAllAlloc(gpa, 8192);
            defer gpa.free(body);

            var send_buffer: [100]u8 = undefined;

            if (mem.startsWith(u8, request.head.target, "/get")) {
                var response = request.respondStreaming(.{
                    .send_buffer = &send_buffer,
                    .content_length = if (mem.indexOf(u8, request.head.target, "?chunked") == null)
                        14
                    else
                        null,
                    .respond_options = .{
                        .extra_headers = &.{
                            .{ .name = "content-type", .value = "text/plain" },
                        },
                    },
                });
                const w = response.writer();
                try w.writeAll("Hello, ");
                try w.writeAll("World!\n");
                try response.end();
                // Writing again would cause an assertion failure.
            } else if (mem.startsWith(u8, request.head.target, "/large")) {
                var response = request.respondStreaming(.{
                    .send_buffer = &send_buffer,
                    .content_length = 14 * 1024 + 14 * 10,
                });

                try response.flush(); // Test an early flush to send the HTTP headers before the body.

                const w = response.writer();

                var i: u32 = 0;
                while (i < 5) : (i += 1) {
                    try w.writeAll("Hello, World!\n");
                }

                try w.writeAll("Hello, World!\n" ** 1024);

                i = 0;
                while (i < 5) : (i += 1) {
                    try w.writeAll("Hello, World!\n");
                }

                try response.end();
            } else if (mem.eql(u8, request.head.target, "/redirect/1")) {
                var response = request.respondStreaming(.{
                    .send_buffer = &send_buffer,
                    .respond_options = .{
                        .status = .found,
                        .extra_headers = &.{
                            .{ .name = "location", .value = "../../get" },
                        },
                    },
                });

                const w = response.writer();
                try w.writeAll("Hello, ");
                try w.writeAll("Redirected!\n");
                try response.end();
            } else if (mem.eql(u8, request.head.target, "/redirect/2")) {
                try request.respond("Hello, Redirected!\n", .{
                    .status = .found,
                    .extra_headers = &.{
                        .{ .name = "location", .value = "/redirect/1" },
                    },
                });
            } else if (mem.eql(u8, request.head.target, "/redirect/3")) {
                const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/redirect/2", .{
                    listen_port,
                });
                defer gpa.free(location);

                try request.respond("Hello, Redirected!\n", .{
                    .status = .found,
                    .extra_headers = &.{
                        .{ .name = "location", .value = location },
                    },
                });
            } else if (mem.eql(u8, request.head.target, "/redirect/4")) {
                try request.respond("Hello, Redirected!\n", .{
                    .status = .found,
                    .extra_headers = &.{
                        .{ .name = "location", .value = "/redirect/3" },
                    },
                });
            } else if (mem.eql(u8, request.head.target, "/redirect/5")) {
                try request.respond("Hello, Redirected!\n", .{
                    .status = .found,
                    .extra_headers = &.{
                        .{ .name = "location", .value = "/%2525" },
                    },
                });
            } else if (mem.eql(u8, request.head.target, "/%2525")) {
                try request.respond("Encoded redirect successful!\n", .{});
            } else if (mem.eql(u8, request.head.target, "/redirect/invalid")) {
                const invalid_port = try getUnusedTcpPort();
                const location = try std.fmt.a```
