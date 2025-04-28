```
llocPrint(gpa, "http://127.0.0.1:{d}", .{invalid_port});
                defer gpa.free(location);

                try request.respond("", .{
                    .status = .found,
                    .extra_headers = &.{
                        .{ .name = "location", .value = location },
                    },
                });
            } else if (mem.eql(u8, request.head.target, "/empty")) {
                try request.respond("", .{
                    .extra_headers = &.{
                        .{ .name = "empty", .value = "" },
                    },
                });
            } else {
                try request.respond("", .{ .status = .not_found });
            }
        }

        fn getUnusedTcpPort() !u16 {
            const addr = try std.net.Address.parseIp("127.0.0.1", 0);
            var s = try addr.listen(.{});
            defer s.deinit();
            return s.listen_address.in.getPort();
        }
    });
    defer {
        global.handle_new_requests = false;
        test_server.destroy();
    }

    const log = std.log.scoped(.client);

    const gpa = std.testing.allocator;
    var client: http.Client = .{ .allocator = gpa };
    errdefer client.deinit();
    // defer client.deinit(); handled below

    const port = test_server.port();

    { // read content-length response
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/get", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
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
        try expectEqualStrings("text/plain", req.response.content_type.?);
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // read large content-length response
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/large", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.GET, uri, .{
            .server_header_buffer = &server_header_buffer,
        });
        defer req.deinit();

        try req.send();
        try req.wait();

        const body = try req.reader().readAllAlloc(gpa, 8192 * 1024);
        defer gpa.free(body);

        try expectEqual(@as(usize, 14 * 1024 + 14 * 10), body.len);
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // send head request and not read chunked
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/get", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.HEAD, uri, .{
            .server_header_buffer = &server_header_buffer,
        });
        defer req.deinit();

        try req.send();
        try req.wait();

        const body = try req.reader().readAllAlloc(gpa, 8192);
        defer gpa.free(body);

        try expectEqualStrings("", body);
        try expectEqualStrings("text/plain", req.response.content_type.?);
        try expectEqual(14, req.response.content_length.?);
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // read chunked response
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/get?chunked", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
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
        try expectEqualStrings("text/plain", req.response.content_type.?);
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // send head request and not read chunked
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/get?chunked", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.HEAD, uri, .{
            .server_header_buffer = &server_header_buffer,
        });
        defer req.deinit();

        try req.send();
        try req.wait();

        const body = try req.reader().readAllAlloc(gpa, 8192);
        defer gpa.free(body);

        try expectEqualStrings("", body);
        try expectEqualStrings("text/plain", req.response.content_type.?);
        try expect(req.response.transfer_encoding == .chunked);
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // read content-length response with connection close
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/get", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.GET, uri, .{
            .server_header_buffer = &server_header_buffer,
            .keep_alive = false,
        });
        defer req.deinit();

        try req.send();
        try req.wait();

        const body = try req.reader().readAllAlloc(gpa, 8192);
        defer gpa.free(body);

        try expectEqualStrings("Hello, World!\n", body);
        try expectEqualStrings("text/plain", req.response.content_type.?);
    }

    // connection has been closed
    try expect(client.connection_pool.free_len == 0);

    { // handle empty header field value
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/empty", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.GET, uri, .{
            .server_header_buffer = &server_header_buffer,
            .extra_headers = &.{
                .{ .name = "empty", .value = "" },
            },
        });
        defer req.deinit();

        try req.send();
        try req.wait();

        try std.testing.expectEqual(.ok, req.response.status);

        const body = try req.reader().readAllAlloc(gpa, 8192);
        defer gpa.free(body);

        try expectEqualStrings("", body);

        var it = req.response.iterateHeaders();
        {
            const header = it.next().?;
            try expect(!it.is_trailer);
            try expectEqualStrings("content-length", header.name);
            try expectEqualStrings("0", header.value);
        }
        {
            const header = it.next().?;
            try expect(!it.is_trailer);
            try expectEqualStrings("empty", header.name);
            try expectEqualStrings("", header.value);
        }
        try expectEqual(null, it.next());
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // relative redirect
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/redirect/1", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
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
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // redirect from root
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/redirect/2", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
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
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // absolute redirect
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/redirect/3", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
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
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // too many redirects
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/redirect/4", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.GET, uri, .{
            .server_header_buffer = &server_header_buffer,
        });
        defer req.deinit();

        try req.send();
        req.wait() catch |err| switch (err) {
            error.TooManyHttpRedirects => {},
            else => return err,
        };
    }

    { // redirect to encoded url
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/redirect/5", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.GET, uri, .{
            .server_header_buffer = &server_header_buffer,
        });
        defer req.deinit();

        try req.send();
        try req.wait();

        const body = try req.reader().readAllAlloc(gpa, 8192);
        defer gpa.free(body);

        try expectEqualStrings("Encoded redirect successful!\n", body);
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // check client without segfault by connection error after redirection
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/redirect/invalid", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        log.info("{s}", .{location});
        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.GET, uri, .{
            .server_header_buffer = &server_header_buffer,
        });
        defer req.deinit();

        try req.send();
        const result = req.wait();

        // a proxy without an upstream is likely to return a 5xx status.
        if (client.http_proxy == null) {
            try expectError(error.ConnectionRefused, result); // expects not segfault but the regular error
        }
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // issue 16282 *** This test leaves the client in an invalid state, it must be last ***
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/get", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        const total_connections = client.connection_pool.free_size + 64;
        var requests = try gpa.alloc(http.Client.Request, total_connections);
        defer gpa.free(requests);

        var header_bufs = std.ArrayList([]u8).init(gpa);
        defer header_bufs.deinit();
        defer for (header_bufs.items) |item| gpa.free(item);

        for (0..total_connections) |i| {
            const headers_buf = try gpa.alloc(u8, 1024);
            try header_bufs.append(headers_buf);
            var req = try client.open(.GET, uri, .{
                .server_header_buffer = headers_buf,
            });
            req.response.parser.done = true;
            req.connection.?.closing = false;
            requests[i] = req;
        }

        for (0..total_connections) |i| {
            requests[i].deinit();
        }

        // free connections should be full now
        try expect(client.connection_pool.free_len == client.connection_pool.free_size);
    }

    client.deinit();

    {
        global.handle_new_requests = false;

        const conn = try std.net.tcpConnectToAddress(test_server.net_server.listen_address);
        conn.close();
    }
}

test "Server streams both reading and writing" {
    const test_server = try createTestServer(struct {
        fn run(net_server: *std.net.Server) anyerror!void {
            var header_buffer: [1024]u8 = undefined;
            const conn = try net_server.accept();
            defer conn.stream.close();

            var server = http.Server.init(conn, &header_buffer);
            var request = try server.receiveHead();
            const reader = try request.reader();

            var send_buffer: [777]u8 = undefined;
            var response = request.respondStreaming(.{
                .send_buffer = &send_buffer,
                .respond_options = .{
                    .transfer_encoding = .none, // Causes keep_alive=false
                },
            });
            const writer = response.writer();

            while (true) {
                try response.flush();
                var buf: [100]u8 = undefined;
                const n = try reader.read(&buf);
                if (n == 0) break;
                const sub_buf = buf[0..n];
                for (sub_buf) |*b| b.* = std.ascii.toUpper(b.*);
                try writer.writeAll(sub_buf);
            }
            try response.end();
        }
    });
    defer test_server.destroy();

    var client: http.Client = .{ .allocator = std.testing.allocator };
    defer client.deinit();

    var server_header_buffer: [555]u8 = undefined;
    var req = try client.open(.POST, .{
        .scheme = "http",
        .host = .{ .raw = "127.0.0.1" },
        .port = test_server.port(),
        .path = .{ .percent_encoded = "/" },
    }, .{
        .server_header_buffer = &server_header_buffer,
    });
    defer req.deinit();

    req.transfer_encoding = .chunked;
    try req.send();
    try req.wait();

    try req.writeAll("one ");
    try req.writeAll("fish");

    try req.finish();

    const body = try req.reader().readAllAlloc(std.testing.allocator, 8192);
    defer std.testing.allocator.free(body);

    try expectEqualStrings("ONE FISH", body);
}

fn echoTests(client: *http.Client, port: u16) !void {
    const gpa = std.testing.allocator;
    var location_buffer: [100]u8 = undefined;

    { // send content-length request
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/echo-content", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.POST, uri, .{
            .server_header_buffer = &server_header_buffer,
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/plain" },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = 14 };

        try req.send();
        try req.writeAll("Hello, ");
        try req.writeAll("World!\n");
        try req.finish();

        try req.wait();

        const body = try req.reader().readAllAlloc(gpa, 8192);
        defer gpa.free(body);

        try expectEqualStrings("Hello, World!\n", body);
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // send chunked request
        const uri = try std.Uri.parse(try std.fmt.bufPrint(
            &location_buffer,
            "http://127.0.0.1:{d}/echo-content",
            .{port},
        ));

        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.POST, uri, .{
            .server_header_buffer = &server_header_buffer,
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/plain" },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .chunked;

        try req.send();
        try req.writeAll("Hello, ");
        try req.writeAll("World!\n");
        try req.finish();

        try req.wait();

        const body = try req.reader().readAllAlloc(gpa, 8192);
        defer gpa.free(body);

        try expectEqualStrings("Hello, World!\n", body);
    }

    // connection has been kept alive
    try expect(client.http_proxy != null or client.connection_pool.free_len == 1);

    { // Client.fetch()

        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/echo-content#fetch", .{port});
        defer gpa.free(location);

        var body = std.ArrayList(u8).init(gpa);
        defer body.deinit();

        const res = try client.fetch(.{
            .location = .{ .url = location },
            .method = .POST,
            .payload = "Hello, World!\n",
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/plain" },
            },
            .response_storage = .{ .dynamic = &body },
        });
        try expectEqual(.ok, res.status);
        try expectEqualStrings("Hello, World!\n", body.items);
    }

    { // expect: 100-continue
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/echo-content#expect-100", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.POST, uri, .{
            .server_header_buffer = &server_header_buffer,
            .extra_headers = &.{
                .{ .name = "expect", .value = "100-continue" },
                .{ .name = "content-type", .value = "text/plain" },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .chunked;

        try req.send();
        try req.writeAll("Hello, ");
        try req.writeAll("World!\n");
        try req.finish();

        try req.wait();
        try expectEqual(.ok, req.response.status);

        const body = try req.reader().readAllAlloc(gpa, 8192);
        defer gpa.free(body);

        try expectEqualStrings("Hello, World!\n", body);
    }

    { // expect: garbage
        const location = try std.fmt.allocPrint(gpa, "http://127.0.0.1:{d}/echo-content#expect-garbage", .{port});
        defer gpa.free(location);
        const uri = try std.Uri.parse(location);

        var server_header_buffer: [1024]u8 = undefined;
        var req = try client.open(.POST, uri, .{
            .server_header_buffer = &server_header_buffer,
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/plain" },
                .{ .name = "expect", .value = "garbage" },
            },
        });
        defer req.deinit();

        req.transfer_encoding = .chunked;

        try req.send();
        try req.wait();
        try expectEqual(.expectation_failed, req.response.status);
    }

    _ = try client.fetch(.{
        .location = .{
            .url = try std.fmt.bufPrint(&location_buffer, "http://127.0.0.1:{d}/end", .{port}),
        },
    });
}

const TestServer = struct {
    server_thread: std.Thread,
    net_server: std.net.Server,

    fn destroy(self: *@This()) void {
        self.server_thread.join();
        self.net_server.deinit();
        std.testing.allocator.destroy(self);
    }

    fn port(self: @This()) u16 {
        return self.net_server.listen_address.in.getPort();
    }
};

fn createTestServer(S: type) !*TestServer {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.zig_backend == .stage2_llvm and native_endian == .big) {
        // https://github.com/ziglang/zig/issues/13782
        return error.SkipZigTest;
    }

    const address = try std.net.Address.parseIp("127.0.0.1", 0);
    const test_server = try std.testing.allocator.create(TestServer);
    test_server.net_server = try address.listen(.{ .reuse_address = true });
    test_server.server_thread = try std.Thread.spawn(.{}, S.run, .{&test_server.net_server});
    return test_server;
}

test "redirect to different connection" {
    const test_server_new = try createTestServer(struct {
        fn run(net_server: *std.net.Server) anyerror!void {
            var header_buffer: [888]u8 = undefined;

            const conn = try net_server.accept();
            defer conn.stream.close();

            var server = http.Server.init(conn, &header_buffer);
            var request = try server.receiveHead();
            try expectEqualStrings(request.head.target, "/ok");
            try request.respond("good job, you pass", .{});
        }
    });
    defer test_server_new.destroy();

    const global = struct {
        var other_port: ?u16 = null;
    };
    global.other_port = test_server_new.port();

    const test_server_orig = try createTestServer(struct {
        fn run(net_server: *std.net.Server) anyerror!void {
            var header_buffer: [999]u8 = undefined;
            var send_buffer: [100]u8 = undefined;

            const conn = try net_server.accept();
            defer conn.stream.close();

            const new_loc = try std.fmt.bufPrint(&send_buffer, "http://127.0.0.1:{d}/ok", .{
                global.other_port.?,
            });

            var server = http.Server.init(conn, &header_buffer);
            var request = try server.receiveHead();
            try expectEqualStrings(request.head.target, "/help");
            try request.respond("", .{
                .status = .found,
                .extra_headers = &.{
                    .{ .name = "location", .value = new_loc },
                },
            });
        }
    });
    defer test_server_orig.destroy();

    const gpa = std.testing.allocator;

    var client: http.Client = .{ .allocator = gpa };
    defer client.deinit();

    var loc_buf: [100]u8 = undefined;
    const location = try std.fmt.bufPrint(&loc_buf, "http://127.0.0.1:{d}/help", .{
        test_server_orig.port(),
    });
    const uri = try std.Uri.parse(location);

    {
        var server_header_buffer: [666]u8 = undefined;
        var req = try client.open(.GET, uri, .{
            .server_header_buffer = &server_header_buffer,
        });
        defer req.deinit();

        try req.send();
        try req.wait();

        const body = try req.reader().readAllAlloc(gpa, 8192);
        defer gpa.free(body);

        try expectEqualStrings("good job, you pass", body);
    }
}
//! See https://tools.ietf.org/html/rfc6455

const builtin = @import("builtin");
const std = @import("std");
const WebSocket = @This();
const assert = std.debug.assert;
const native_endian = builtin.cpu.arch.endian();

key: []const u8,
request: *std.http.Server.Request,
recv_fifo: std.fifo.LinearFifo(u8, .Slice),
reader: std.io.AnyReader,
response: std.http.Server.Response,
/// Number of bytes that have been peeked but not discarded yet.
outstanding_len: usize,

pub const InitError = error{WebSocketUpgradeMissingKey} ||
    std.http.Server.Request.ReaderError;

pub fn init(
    ws: *WebSocket,
    request: *std.http.Server.Request,
    send_buffer: []u8,
    recv_buffer: []align(4) u8,
) InitError!bool {
    switch (request.head.version) {
        .@"HTTP/1.0" => return false,
        .@"HTTP/1.1" => if (request.head.method != .GET) return false,
    }

    var sec_websocket_key: ?[]const u8 = null;
    var upgrade_websocket: bool = false;
    var it = request.iterateHeaders();
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "sec-websocket-key")) {
            sec_websocket_key = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "upgrade")) {
            if (!std.ascii.eqlIgnoreCase(header.value, "websocket"))
                return false;
            upgrade_websocket = true;
        }
    }
    if (!upgrade_websocket)
        return false;

    const key = sec_websocket_key orelse return error.WebSocketUpgradeMissingKey;

    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(key);
    sha1.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
    sha1.final(&digest);
    var base64_digest: [28]u8 = undefined;
    assert(std.base64.standard.Encoder.encode(&base64_digest, &digest).len == base64_digest.len);

    request.head.content_length = std.math.maxInt(u64);

    ws.* = .{
        .key = key,
        .recv_fifo = std.fifo.LinearFifo(u8, .Slice).init(recv_buffer),
        .reader = try request.reader(),
        .response = request.respondStreaming(.{
            .send_buffer = send_buffer,
            .respond_options = .{
                .status = .switching_protocols,
                .extra_headers = &.{
                    .{ .name = "upgrade", .value = "websocket" },
                    .{ .name = "connection", .value = "upgrade" },
                    .{ .name = "sec-websocket-accept", .value = &base64_digest },
                },
                .transfer_encoding = .none,
            },
        }),
        .request = request,
        .outstanding_len = 0,
    };
    return true;
}

pub const Header0 = packed struct(u8) {
    opcode: Opcode,
    rsv3: u1 = 0,
    rsv2: u1 = 0,
    rsv1: u1 = 0,
    fin: bool,
};

pub const Header1 = packed struct(u8) {
    payload_len: enum(u7) {
        len16 = 126,
        len64 = 127,
        _,
    },
    mask: bool,
};

pub const Opcode = enum(u4) {
    continuation = 0,
    text = 1,
    binary = 2,
    connection_close = 8,
    ping = 9,
    /// "A Pong frame MAY be sent unsolicited. This serves as a unidirectional
    /// heartbeat. A response to an unsolicited Pong frame is not expected."
    pong = 10,
    _,
};

pub const ReadSmallTextMessageError = error{
    ConnectionClose,
    UnexpectedOpCode,
    MessageTooBig,
    MissingMaskBit,
} || RecvError;

pub const SmallMessage = struct {
    /// Can be text, binary, or ping.
    opcode: Opcode,
    data: []u8,
};

/// Reads the next message from the WebSocket stream, failing if the message does not fit
/// into `recv_buffer`.
pub fn readSmallMessage(ws: *WebSocket) ReadSmallTextMessageError!SmallMessage {
    while (true) {
        const header_bytes = (try recv(ws, 2))[0..2];
        const h0: Header0 = @bitCast(header_bytes[0]);
        const h1: Header1 = @bitCast(header_bytes[1]);

        switch (h0.opcode) {
            .text, .binary, .pong, .ping => {},
            .connection_close => return error.ConnectionClose,
            .continuation => return error.UnexpectedOpCode,
            _ => return error.UnexpectedOpCode,
        }

        if (!h0.fin) return error.MessageTooBig;
        if (!h1.mask) return error.MissingMaskBit;

        const len: usize = switch (h1.payload_len) {
            .len16 => try recvReadInt(ws, u16),
            .len64 => std.math.cast(usize, try recvReadInt(ws, u64)) orelse return error.MessageTooBig,
            else => @intFromEnum(h1.payload_len),
        };
        if (len > ws.recv_fifo.buf.len) return error.MessageTooBig;

        const mask: u32 = @bitCast((try recv(ws, 4))[0..4].*);
        const payload = try recv(ws, len);

        // Skip pongs.
        if (h0.opcode == .pong) continue;

        // The last item may contain a partial word of unused data.
        const floored_len = (payload.len / 4) * 4;
        const u32_payload: []align(1) u32 = @alignCast(std.mem.bytesAsSlice(u32, payload[0..floored_len]));
        for (u32_payload) |*elem| elem.* ^= mask;
        const mask_bytes = std.mem.asBytes(&mask)[0 .. payload.len - floored_len];
        for (payload[floored_len..], mask_bytes) |*leftover, m| leftover.* ^= m;

        return .{
            .opcode = h0.opcode,
            .data = payload,
        };
    }
}

const RecvError = std.http.Server.Request.ReadError || error{EndOfStream};

fn recv(ws: *WebSocket, len: usize) RecvError![]u8 {
    ws.recv_fifo.discard(ws.outstanding_len);
    assert(len <= ws.recv_fifo.buf.len);
    if (len > ws.recv_fifo.count) {
        const small_buf = ws.recv_fifo.writableSlice(0);
        const needed = len - ws.recv_fifo.count;
        const buf = if (small_buf.len >= needed) small_buf else b: {
            ws.recv_fifo.realign();
            break :b ws.recv_fifo.writableSlice(0);
        };
        const n = try @as(RecvError!usize, @errorCast(ws.reader.readAtLeast(buf, needed)));
        if (n < needed) return error.EndOfStream;
        ws.recv_fifo.update(n);
    }
    ws.outstanding_len = len;
    // TODO: improve the std lib API so this cast isn't necessary.
    return @constCast(ws.recv_fifo.readableSliceOfLen(len));
}

fn recvReadInt(ws: *WebSocket, comptime I: type) !I {
    const unswapped: I = @bitCast((try recv(ws, @sizeOf(I)))[0..@sizeOf(I)].*);
    return switch (native_endian) {
        .little => @byteSwap(unswapped),
        .big => unswapped,
    };
}

pub const WriteError = std.http.Server.Response.WriteError;

pub fn writeMessage(ws: *WebSocket, message: []const u8, opcode: Opcode) WriteError!void {
    const iovecs: [1]std.posix.iovec_const = .{
        .{ .base = message.ptr, .len = message.len },
    };
    return writeMessagev(ws, &iovecs, opcode);
}

pub fn writeMessagev(ws: *WebSocket, message: []const std.posix.iovec_const, opcode: Opcode) WriteError!void {
    const total_len = l: {
        var total_len: u64 = 0;
        for (message) |iovec| total_len += iovec.len;
        break :l total_len;
    };

    var header_buf: [2 + 8]u8 = undefined;
    header_buf[0] = @bitCast(@as(Header0, .{
        .opcode = opcode,
        .fin = true,
    }));
    const header = switch (total_len) {
        0...125 => blk: {
            header_buf[1] = @bitCast(@as(Header1, .{
                .payload_len = @enumFromInt(total_len),
                .mask = false,
            }));
            break :blk header_buf[0..2];
        },
        126...0xffff => blk: {
            header_buf[1] = @bitCast(@as(Header1, .{
                .payload_len = .len16,
                .mask = false,
            }));
            std.mem.writeInt(u16, header_buf[2..4], @intCast(total_len), .big);
            break :blk header_buf[0..4];
        },
        else => blk: {
            header_buf[1] = @bitCast(@as(Header1, .{
                .payload_len = .len64,
                .mask = false,
            }));
            std.mem.writeInt(u64, header_buf[2..10], total_len, .big);
            break :blk header_buf[0..10];
        },
    };

    const response = &ws.response;
    try response.writeAll(header);
    for (message) |iovec|
        try response.writeAll(iovec.base[0..iovec.len]);
    try response.flush();
}
const std = @import("std.zig");
const builtin = @import("builtin");
const root = @import("root");
const c = std.c;
const is_windows = builtin.os.tag == .windows;
const windows = std.os.windows;
const posix = std.posix;
const math = std.math;
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;
const meta = std.meta;
const File = std.fs.File;
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

fn getStdOutHandle() posix.fd_t {
    if (is_windows) {
        return windows.peb().ProcessParameters.hStdOutput;
    }

    if (@hasDecl(root, "os") and @hasDecl(root.os, "io") and @hasDecl(root.os.io, "getStdOutHandle")) {
        return root.os.io.getStdOutHandle();
    }

    return posix.STDOUT_FILENO;
}

pub fn getStdOut() File {
    return .{ .handle = getStdOutHandle() };
}

fn getStdErrHandle() posix.fd_t {
    if (is_windows) {
        return windows.peb().ProcessParameters.hStdError;
    }

    if (@hasDecl(root, "os") and @hasDecl(root.os, "io") and @hasDecl(root.os.io, "getStdErrHandle")) {
        return root.os.io.getStdErrHandle();
    }

    return posix.STDERR_FILENO;
}

pub fn getStdErr() File {
    return .{ .handle = getStdErrHandle() };
}

fn getStdInHandle() posix.fd_t {
    if (is_windows) {
        return windows.peb().ProcessParameters.hStdInput;
    }

    if (@hasDecl(root, "os") and @hasDecl(root.os, "io") and @hasDecl(root.os.io, "getStdInHandle")) {
        return root.os.io.getStdInHandle();
    }

    return posix.STDIN_FILENO;
}

pub fn getStdIn() File {
    return .{ .handle = getStdInHandle() };
}

pub fn GenericReader(
    comptime Context: type,
    comptime ReadError: type,
    /// Returns the number of bytes read. It may be less than buffer.len.
    /// If the number of bytes read is 0, it means end of stream.
    /// End of stream is not an error condition.
    comptime readFn: fn (context: Context, buffer: []u8) ReadError!usize,
) type {
    return struct {
        context: Context,

        pub const Error = ReadError;
        pub const NoEofError = ReadError || error{
            EndOfStream,
        };

        pub inline fn read(self: Self, buffer: []u8) Error!usize {
            return readFn(self.context, buffer);
        }

        pub inline fn readAll(self: Self, buffer: []u8) Error!usize {
            return @errorCast(self.any().readAll(buffer));
        }

        pub inline fn readAtLeast(self: Self, buffer: []u8, len: usize) Error!usize {
            return @errorCast(self.any().readAtLeast(buffer, len));
        }

        pub inline fn readNoEof(self: Self, buf: []u8) NoEofError!void {
            return @errorCast(self.any().readNoEof(buf));
        }

        pub inline fn readAllArrayList(
            self: Self,
            array_list: *std.ArrayList(u8),
            max_append_size: usize,
        ) (error{StreamTooLong} || Allocator.Error || Error)!void {
            return @errorCast(self.any().readAllArrayList(array_list, max_append_size));
        }

        pub inline fn readAllArrayListAligned(
            self: Self,
            comptime alignment: ?Alignment,
            array_list: *std.ArrayListAligned(u8, alignment),
            max_append_size: usize,
        ) (error{StreamTooLong} || Allocator.Error || Error)!void {
            return @errorCast(self.any().readAllArrayListAligned(
                alignment,
                array_list,
                max_append_size,
            ));
        }

        pub inline fn readAllAlloc(
            self: Self,
            allocator: Allocator,
            max_size: usize,
        ) (Error || Allocator.Error || error{StreamTooLong})![]u8 {
            return @errorCast(self.any().readAllAlloc(allocator, max_size));
        }

        pub inline fn readUntilDelimiterArrayList(
            self: Self,
            array_list: *std.ArrayList(u8),
            delimiter: u8,
            max_size: usize,
        ) (NoEofError || Allocator.Error || error{StreamTooLong})!void {
            return @errorCast(self.any().readUntilDelimiterArrayList(
                array_list,
                delimiter,
                max_size,
            ));
        }

        pub inline fn readUntilDelimiterAlloc(
            self: Self,
            allocator: Allocator,
            delimiter: u8,
            max_size: usize,
        ) (NoEofError || Allocator.Error || error{StreamTooLong})![]u8 {
            return @errorCast(self.any().readUntilDelimiterAlloc(
                allocator,
                delimiter,
                max_size,
            ));
        }

        pub inline fn readUntilDelimiter(
            self: Self,
            buf: []u8,
            delimiter: u8,
        ) (NoEofError || error{StreamTooLong})![]u8 {
            return @errorCast(self.any().readUntilDelimiter(buf, delimiter));
        }

        pub inline fn readUntilDelimiterOrEofAlloc(
            self: Self,
            allocator: Allocator,
            delimiter: u8,
            max_size: usize,
        ) (Error || Allocator.Error || error{StreamTooLong})!?[]u8 {
            return @errorCast(self.any().readUntilDelimiterOrEofAlloc(
                allocator,
                delimiter,
                max_size,
            ));
        }

        pub inline fn readUntilDelimiterOrEof(
            self: Self,
            buf: []u8,
            delimiter: u8,
        ) (Error || error{StreamTooLong})!?[]u8 {
            return @errorCast(self.any().readUntilDelimiterOrEof(buf, delimiter));
        }

        pub inline fn streamUntilDelimiter(
            self: Self,
            writer: anytype,
            delimiter: u8,
            optional_max_size: ?usize,
        ) (NoEofError || error{StreamTooLong} || @TypeOf(writer).Error)!void {
            return @errorCast(self.any().streamUntilDelimiter(
                writer,
                delimiter,
                optional_max_size,
            ));
        }

        pub inline fn skipUntilDelimiterOrEof(self: Self, delimiter: u8) Error!void {
            return @errorCast(self.any().skipUntilDelimiterOrEof(delimiter));
        }

        pub inline fn readByte(self: Self) NoEofError!u8 {
            return @errorCast(self.any().readByte());
        }

        pub inline fn readByteSigned(self: Self) NoEofError!i8 {
            return @errorCast(self.any().readByteSigned());
        }

        pub inline fn readBytesNoEof(
            self: Self,
            comptime num_bytes: usize,
        ) NoEofError![num_bytes]u8 {
            return @errorCast(self.any().readBytesNoEof(num_bytes));
        }

        pub inline fn readIntoBoundedBytes(
            self: Self,
            comptime num_bytes: usize,
            bounded: *std.BoundedArray(u8, num_bytes),
        ) Error!void {
            return @errorCast(self.any().readIntoBoundedBytes(num_bytes, bounded));
        }

        pub inline fn readBoundedBytes(
            self: Self,
            comptime num_bytes: usize,
        ) Error!std.BoundedArray(u8, num_bytes) {
            return @errorCast(self.any().readBoundedBytes(num_bytes));
        }

        pub inline fn readInt(self: Self, comptime T: type, endian: std.builtin.Endian) NoEofError!T {
            return @errorCast(self.any().readInt(T, endian));
        }

        pub inline fn readVarInt(
            self: Self,
            comptime ReturnType: type,
            endian: std.builtin.Endian,
            size: usize,
        ) NoEofError!ReturnType {
            return @errorCast(self.any().readVarInt(ReturnType, endian, size));
        }

        pub const SkipBytesOptions = AnyReader.SkipBytesOptions;

        pub inline fn skipBytes(
            self: Self,
            num_bytes: u64,
            comptime options: SkipBytesOptions,
        ) NoEofError!void {
            return @errorCast(self.any().skipBytes(num_bytes, options));
        }

        pub inline fn isBytes(self: Self, slice: []const u8) NoEofError!bool {
            return @errorCast(self.any().isBytes(slice));
        }

        pub inline fn readStruct(self: Self, comptime T: type) NoEofError!T {
            return @errorCast(self.any().readStruct(T));
        }

        pub inline fn readStructEndian(self: Self, comptime T: type, endian: std.builtin.Endian) NoEofError!T {
            return @errorCast(self.any().readStructEndian(T, endian));
        }

        pub const ReadEnumError = NoEofError || error{
            /// An integer was read, but it did not match any of the tags in the supplied enum.
            InvalidValue,
        };

        pub inline fn readEnum(
            self: Self,
            comptime Enum: type,
            endian: std.builtin.Endian,
        ) ReadEnumError!Enum {
            return @errorCast(self.any().readEnum(Enum, endian));
        }

        pub inline fn any(self: *const Self) AnyReader {
            return .{
                .context = @ptrCast(&self.context),
                .readFn = typeErasedReadFn,
            };
        }

        const Self = @This();

        fn typeErasedReadFn(context: *const anyopaque, buffer: []u8) anyerror!usize {
            const ptr: *const Context = @alignCast(@ptrCast(context));
            return readFn(ptr.*, buffer);
        }
    };
}

pub fn GenericWriter(
    comptime Context: type,
    comptime WriteError: type,
    comptime writeFn: fn (context: Context, bytes: []const u8) WriteError!usize,
) type {
    return struct {
        context: Context,

        const Self = @This();
        pub const Error = WriteError;

        pub inline fn write(self: Self, bytes: []const u8) Error!usize {
            return writeFn(self.context, bytes);
        }

        pub inline fn writeAll(self: Self, bytes: []const u8) Error!void {
            return @errorCast(self.any().writeAll(bytes));
        }

        pub inline fn print(self: Self, comptime format: []const u8, args: anytype) Error!void {
            return @errorCast(self.any().print(format, args));
        }

        pub inline fn writeByte(self: Self, byte: u8) Error!void {
            return @errorCast(self.any().writeByte(byte));
        }

        pub inline fn writeByteNTimes(self: Self, byte: u8, n: usize) Error!void {
            return @errorCast(self.any().writeByteNTimes(byte, n));
        }

        pub inline fn writeBytesNTimes(self: Self, bytes: []const u8, n: usize) Error!void {
            return @errorCast(self.any().writeBytesNTimes(bytes, n));
        }

        pub inline fn writeInt(self: Self, comptime T: type, value: T, endian: std.builtin.Endian) Error!void {
            return @errorCast(self.any().writeInt(T, value, endian));
        }

        pub inline fn writeStruct(self: Self, value: anytype) Error!void {
            return @errorCast(self.any().writeStruct(value));
        }

        pub inline fn writeStructEndian(self: Self, value: anytype, endian: std.builtin.Endian) Error!void {
            return @errorCast(self.any().writeStructEndian(value, endian));
        }

        pub inline fn any(self: *const Self) AnyWriter {
            return .{
                .context = @ptrCast(&self.context),
                .writeFn = typeErasedWriteFn,
            };
        }

        fn typeErasedWriteFn(context: *const anyopaque, bytes: []const u8) anyerror!usize {
            const ptr: *const Context = @alignCast(@ptrCast(context));
            return writeFn(ptr.*, bytes);
        }
    };
}

/// Deprecated; consider switching to `AnyReader` or use `GenericReader`
/// to use previous API.
pub const Reader = GenericReader;
/// Deprecated; consider switching to `AnyWriter` or use `GenericWriter`
/// to use previous API.
pub const Writer = GenericWriter;

pub const AnyReader = @import("io/Reader.zig");
pub const AnyWriter = @import("io/Writer.zig");

pub const SeekableStream = @import("io/seekable_stream.zig").SeekableStream;

pub const BufferedWriter = @import("io/buffered_writer.zig").BufferedWriter;
pub const bufferedWriter = @import("io/buffered_writer.zig").bufferedWriter;

pub const BufferedReader = @import("io/buffered_reader.zig").BufferedReader;
pub const bufferedReader = @import("io/buffered_reader.zig").bufferedReader;
pub const bufferedReaderSize = @import("io/buffered_reader.zig").bufferedReaderSize;

pub const FixedBufferStream = @import("io/fixed_buffer_stream.zig").FixedBufferStream;
pub const fixedBufferStream = @import("io/fixed_buffer_stream.zig").fixedBufferStream;

pub const CWriter = @import("io/c_writer.zig").CWriter;
pub const cWriter = @import("io/c_writer.zig").cWriter;

pub const LimitedReader = @import("io/limited_reader.zig").LimitedReader;
pub const limitedReader = @import("io/limited_reader.zig").limitedReader;

pub const CountingWriter = @import("io/counting_writer.zig").CountingWriter;
pub const countingWriter = @import("io/counting_writer.zig").countingWriter;
pub const CountingReader = @import("io/counting_reader.zig").CountingReader;
pub const countingReader = @import("io/counting_reader.zig").countingReader;

pub const MultiWriter = @import("io/multi_writer.zig").MultiWriter;
pub const multiWriter = @import("io/multi_writer.zig").multiWriter;

pub const BitReader = @import("io/bit_reader.zig").BitReader;
pub const bitReader = @import("io/bit_reader.zig").bitReader;

pub const BitWriter = @import("io/bit_writer.zig").BitWriter;
pub const bitWriter = @import("io/bit_writer.zig").bitWriter;

pub const ChangeDetectionStream = @import("io/change_detection_stream.zig").ChangeDetectionStream;
pub const changeDetectionStream = @import("io/change_detection_stream.zig").changeDetectionStream;

pub const FindByteWriter = @import("io/find_byte_writer.zig").FindByteWriter;
pub const findByteWriter = @import("io/find_byte_writer.zig").findByteWriter;

pub const BufferedAtomicFile = @import("io/buffered_atomic_file.zig").BufferedAtomicFile;

pub const StreamSource = @import("io/stream_source.zig").StreamSource;

pub const tty = @import("io/tty.zig");

/// A Writer that doesn't write to anything.
pub const null_writer: NullWriter = .{ .context = {} };

pub const NullWriter = Writer(void, error{}, dummyWrite);
fn dummyWrite(context: void, data: []const u8) error{}!usize {
    _ = context;
    return data.len;
}

test null_writer {
    null_writer.writeAll("yay" ** 10) catch |err| switch (err) {};
}

pub fn poll(
    allocator: Allocator,
    comptime StreamEnum: type,
    files: PollFiles(StreamEnum),
) Poller(StreamEnum) {
    const enum_fields = @typeInfo(StreamEnum).@"enum".fields;
    var result: Poller(StreamEnum) = undefined;

    if (is_windows) result.windows = .{
        .first_read_done = false,
        .overlapped = [1]windows.OVERLAPPED{
            mem.zeroes(windows.OVERLAPPED),
        } ** enum_fields.len,
        .small_bufs = undefined,
        .active = .{
            .count = 0,
            .handles_buf = undefined,
            .stream_map = undefined,
        },
    };

    inline for (0..enum_fields.len) |i| {
        result.fifos[i] = .{
            .allocator = allocator,
            .buf = &.{},
            .head = 0,
            .count = 0,
        };
        if (is_windows) {
            result.windows.active.handles_buf[i] = @field(files, enum_fields[i].name).handle;
        } else {
            result.poll_fds[i] = .{
                .fd = @field(files, enum_fields[i].name).handle,
                .events = posix.POLL.IN,
                .revents = undefined,
            };
        }
    }
    return result;
}

pub const PollFifo = std.fifo.LinearFifo(u8, .Dynamic);

pub fn Poller(comptime StreamEnum: type) type {
    return struct {
        const enum_fields = @typeInfo(StreamEnum).@"enum".fields;
        const PollFd = if (is_windows) void else posix.pollfd;

        fifos: [enum_fields.len]PollFifo,
        poll_fds: [enum_fields.len]PollFd,
        windows: if (is_windows) struct {
            first_read_done: bool,
            overlapped: [enum_fields.len]windows.OVERLAPPED,
            small_bufs: [enum_fields.len][128]u8,
            active: struct {
                count: math.IntFittingRange(0, enum_fields.len),
                handles_buf: [enum_fields.len]windows.HANDLE,
                stream_map: [enum_fields.len]StreamEnum,

                pub fn removeAt(self: *@This(), index: u32) void {
                    std.debug.assert(index < self.count);
                    for (index + 1..self.count) |i| {
                        self.handles_buf[i - 1] = self.handles_buf[i];
                        self.stream_map[i - 1] = self.stream_map[i];
                    }
                    self.count -= 1;
                }
            },
        } else void,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            if (is_windows) {
                // cancel any pending IO to prevent clobbering OVERLAPPED value
                for (self.windows.active.handles_buf[0..self.windows.active.count]) |h| {
                    _ = windows.kernel32.CancelIo(h);
                }
            }
            inline for (&self.fifos) |*q| q.deinit();
            self.* = undefined;
        }

        pub fn poll(self: *Self) !bool {
            if (is_windows) {
                return pollWindows(self, null);
            } else {
                return pollPosix(self, null);
            }
        }

        pub fn pollTimeout(self: *Self, nanoseconds: u64) !bool {
            if (is_windows) {
                return pollWindows(self, nanoseconds);
            } else {
                return pollPosix(self, nanoseconds);
            }
        }

        pub inline fn fifo(self: *Self, comptime which: StreamEnum) *PollFifo {
            return &self.fifos[@intFromEnum(which)];
        }

        fn pollWindows(self: *Self, nanoseconds: ?u64) !bool {
            const bump_amt = 512;

            if (!self.windows.first_read_done) {
                var already_read_data = false;
                for (0..enum_fields.len) |i| {
                    const handle = self.windows.active.handles_buf[i];
                    switch (try windowsAsyncReadToFifoAndQueueSmallRead(
                        handle,
                        &self.windows.overlapped[i],
                        &self.fifos[i],
                        &self.windows.small_bufs[i],
                        bump_amt,
                    )) {
                        .populated, .empty => |state| {
                            if (state == .populated) already_read_data = true;
                            self.windows.active.handles_buf[self.windows.active.count] = handle;
                            self.windows.active.stream_map[self.windows.active.count] = @as(StreamEnum, @enumFromInt(i));
                            self.windows.active.count += 1;
                        },
                        .closed => {}, // don't add to the wait_objects list
                        .closed_populated => {
                            // don't add to the wait_objects list, but we did already get data
                            already_read_data = true;
                        },
                    }
                }
                self.windows.first_read_done = true;
                if (already_read_data) return true;
            }

            while (true) {
                if (self.windows.active.count == 0) return false;

                const status = windows.kernel32.WaitForMultipleObjects(
                    self.windows.active.count,
                    &self.windows.active.handles_buf,
                    0,
                    if (nanoseconds) |ns|
                        @min(std.math.cast(u32, ns / std.time.ns_per_ms) orelse (windows.INFINITE - 1), windows.INFINITE - 1)
                    else
                        windows.INFINITE,
                );
                if (status == windows.WAIT_FAILED)
                    return windows.unexpectedError(windows.GetLastError());
                if (status == windows.WAIT_TIMEOUT)
                    return true;

                if (status < windows.WAIT_OBJECT_0 or status > windows.WAIT_OBJECT_0 + enum_fields.len - 1)
                    unreachable;

                const active_idx = status - windows.WAIT_OBJECT_0;

                const stream_idx = @intFromEnum(self.windows.active.stream_map[active_idx]);
                const handle = self.windows.active.handles_buf[active_idx];

                const overlapped = &self.windows.overlapped[stream_idx];
                const stream_fifo = &self.fifos[stream_idx];
                const small_buf = &self.windows.small_bufs[stream_idx];

                const num_bytes_read = switch (try windowsGetReadResult(handle, overlapped, false)) {
                    .success => |n| n,
                    .closed => {
                        self.windows.active.removeAt(active_idx);
                        continue;
                    },
                    .aborted => unreachable,
                };
                try stream_fifo.write(small_buf[0..num_bytes_read]);

                switch (try windowsAsyncReadToFifoAndQueueSmallRead(
                    handle,
                    overlapped,
                    stream_fifo,
                    small_buf,
                    bump_amt,
                )) {
                    .empty => {}, // irrelevant, we already got data from the small buffer
                    .populated => {},
                    .closed,
                    .closed_populated, // identical, since we already got data from the small buffer
                    => self.windows.active.removeAt(active_idx),
                }
                return true;
            }
        }

        fn pollPosix(self: *Self, nanoseconds: ?u64) !bool {
            // We ask for ensureUnusedCapacity with this much extra space. This
            // has more of an effect on small reads because once the reads
            // start to get larger the amount of space an ArrayList will
            // allocate grows exponentially.
            const bump_amt = 512;

            const err_mask = posix.POLL.ERR | posix.POLL.NVAL | posix.POLL.HUP;

            const events_len = try posix.poll(&self.poll_fds, if (nanoseconds) |ns|
                std.math.cast(i32, ns / std.time.ns_per_ms) orelse std.math.maxInt(i32)
            else
                -1);
            if (events_len == 0) {
                for (self.poll_fds) |poll_fd| {
                    if (poll_fd.fd != -1) return true;
                } else return false;
            }

            var keep_polling = false;
            inline for (&self.poll_fds, &self.fifos) |*poll_fd, *q| {
                // Try reading whatever is available before checking the error
                // conditions.
                // It's still possible to read after a POLL.HUP is received,
                // always check if there's some data waiting to be read first.
                if (poll_fd.revents & posix.POLL.IN != 0) {
                    const buf = try q.writableWithSize(bump_amt);
                    const amt = posix.read(poll_fd.fd, buf) catch |err| switch (err) {
                        error.BrokenPipe => 0, // Handle the same as EOF.
                        else => |e| return e,
                    };
                    q.update(amt);
                    if (amt == 0) {
                        // Remove the fd when the EOF condition is met.
                        poll_fd.fd = -1;
                    } else {
                        keep_polling = true;
                    }
                } else if (poll_fd.revents & err_mask != 0) {
                    // Exclude the fds that signaled an error.
                    poll_fd.fd = -1;
                } else if (poll_fd.fd != -1) {
                    keep_polling = true;
                }
            }
            return keep_polling;
        }
    };
}

/// The `ReadFile` docuementation states that `lpNumberOfBytesRead` does not have a meaningful
/// result when using overlapped I/O, but also that it cannot be `null` on Windows 7. For
/// compatibility, we point it to this dummy variables, which we never otherwise access.
/// See: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
var win_dummy_bytes_read: u32 = undefined;

/// Read as much data as possible from `handle` with `overlapped`, and write it to the FIFO. Before
/// returning, queue a read into `small_buf` so that `WaitForMultipleObjects` returns when more data
/// is available. `handle` must have no pending asynchronous operation.
fn windowsAsyncReadToFifoAndQueueSmallRead(
    handle: windows.HANDLE,
    overlapped: *windows.OVERLAPPED,
    fifo: *PollFifo,
    small_buf: *[128]u8,
    bump_amt: usize,
) !enum { empty, populated, closed_populated, closed } {
    var read_any_data = false;
    while (true) {
        const fifo_read_pending = while (true) {
            const buf = try fifo.writableWithSize(bump_amt);
            const buf_len = math.cast(u32, buf.len) orelse math.maxInt(u32);

            if (0 == windows.kernel32.ReadFile(
                handle,
                buf.ptr,
                buf_len,
                &win_dummy_bytes_read,
                overlapped,
            )) switch (windows.GetLastError()) {
                .IO_PENDING => break true,
                .BROKEN_PIPE => return if (read_any_data) .closed_populated else .closed,
                else => |err| return windows.unexpectedError(err),
            };

            const num_bytes_read = switch (try windowsGetReadResult(handle, overlapped, false)) {
                .success => |n| n,
                .closed => return if (read_any_data) .closed_populated else .closed,
                .aborted => unreachable,
            };

            read_any_data = true;
            fifo.update(num_bytes_read);

            if (num_bytes_read == buf_len) {
                // We filled the buffer, so there's probably more data available.
                continue;
            } else {
                // We didn't fill the buffer, so assume we're out of data.
                // There is no pending read.
                break false;
            }
        };

        if (fifo_read_pending) cancel_read: {
            // Cancel the pending read into the FIFO.
            _ = windows.kernel32.CancelIo(handle);

            // We have to wait for the handle to be signalled, i.e. for the cancellation to complete.
            switch (windows.kernel32.WaitForSingleObject(handle, windows.INFINITE)) {
                windows.WAIT_OBJECT_0 => {},
                windows.WAIT_FAILED => return windows.unexpectedError(windows.GetLastError()),
                else => unreachable,
            }

            // If it completed before we canceled, make sure to tell the FIFO!
            const num_bytes_read = switch (try windowsGetReadResult(handle, overlapped, true)) {
                .success => |n| n,
                .closed => return if (read_any_data) .closed_populated else .closed,
                .aborted => break :cancel_read,
            };
            read_any_data = true;
            fifo.update(num_bytes_read);
        }

        // Try to queue the 1-byte read.
        if (0 == windows.kernel32.ReadFile(
            handle,
            small_buf,
            small_buf.len,
            &win_dummy_bytes_read,
            overlapped,
        )) switch (windows.GetLastError()) {
            .IO_PENDING => {
                // 1-byte read pending as intended
                return if (read_any_data) .populated else .empty;
            },
            .BROKEN_PIPE => return if (read_any_data) .closed_populated else .closed,
            else => |err| return windows.unexpectedError(err),
        };

        // We got data back this time. Write it to the FIFO and run the main loop again.
        const num_bytes_read = switch (try windowsGetReadResult(handle, overlapped, false)) {
            .success => |n| n,
            .closed => return if (read_any_data) .closed_populated else .closed,
            .aborted => unreachable,
        };
        try fifo.write(small_buf[0..num_bytes_read]);
        read_any_data = true;
    }
}

/// Simple wrapper around `GetOverlappedResult` to determine the result of a `ReadFile` operation.
/// If `!allow_aborted`, then `aborted` is never returned (`OPERATION_ABORTED` is considered unexpected).
///
/// The `ReadFile` documentation states that the number of bytes read by an overlapped `ReadFile` must be determined using `GetOverlappedResult`, even if the
/// operation immediately returns data:
/// "Use NULL for [lpNumberOfBytesRead] if this is an asynchronous operation to avoid potentially
/// erroneous results."
/// "If `hFile` was opened with `FILE_FLAG_OVERLAPPED`, the following conditions are in effect: [...]
/// The lpNumberOfBytesRead parameter should be set to NULL. Use the GetOverlappedResult function to
/// get the actual number of bytes read."
/// See: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
fn windowsGetReadResult(
    handle: windows.HANDLE,
    overlapped: *windows.OVERLAPPED,
    allow_aborted: bool,
) !union(enum) {
    success: u32,
    closed,
    aborted,
} {
    var num_bytes_read: u32 = undefined;
    if (0 == windows.kernel32.GetOverlappedResult(
        handle,
        overlapped,
        &num_bytes_read,
        0,
    )) switch (windows.GetLastError()) {
        .BROKEN_PIPE => return .closed,
        .OPERATION_ABORTED => |err| if (allow_aborted) {
            return .aborted;
        } else {
            return windows.unexpectedError(err);
        },
        else => |err| return windows.unexpectedError(err),
    };
    return .{ .success = num_bytes_read };
}

/// Given an enum, returns a struct with fields of that enum, each field
/// representing an I/O stream for polling.
pub fn PollFiles(comptime StreamEnum: type) type {
    const enum_fields = @typeInfo(StreamEnum).@"enum".fields;
    var struct_fields: [enum_fields.len]std.builtin.Type.StructField = undefined;
    for (&struct_fields, enum_fields) |*struct_field, enum_field| {
        struct_field.* = .{
            .name = enum_field.name ++ "",
            .type = fs.File,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(fs.File),
        };
    }
    return @Type(.{ .@"struct" = .{
        .layout = .auto,
        .fields = &struct_fields,
        .decls = &.{},
        .is_tuple = false,
    } });
}

test {
    _ = AnyReader;
    _ = AnyWriter;
    _ = @import("io/bit_reader.zig");
    _ = @import("io/bit_writer.zig");
    _ = @import("io/buffered_atomic_file.zig");
    _ = @import("io/buffered_reader.zig");
    _ = @import("io/buffered_writer.zig");
    _ = @import("io/c_writer.zig");
    _ = @import("io/counting_writer.zig");
    _ = @import("io/counting_reader.zig");
    _ = @import("io/fixed_buffer_stream.zig");
    _ = @import("io/seekable_stream.zig");
    _ = @import("io/stream_source.zig");
    _ = @import("io/test.zig");
}
const std = @import("../std.zig");

//General note on endianess:
//Big endian is packed starting in the most significant part of the byte and subsequent
// bytes contain less significant bits. Thus we always take bits from the high
// end and place them below existing bits in our output.
//Little endian is packed starting in the least significant part of the byte and
// subsequent bytes contain more significant bits. Thus we always take bits from
// the low end and place them above existing bits in our output.
//Regardless of endianess, within any given byte the bits are always in most
// to least significant order.
//Also regardless of endianess, the buffer always aligns bits to the low end
// of the byte.

/// Creates a bit reader which allows for reading bits from an underlying standard reader
pub fn BitReader(comptime endian: std.builtin.Endian, comptime Reader: type) type {
    return struct {
        reader: Reader,
        bits: u8 = 0,
        count: u4 = 0,

        const low_bit_mask = [9]u8{
            0b00000000,
            0b00000001,
            0b00000011,
            0b00000111,
            0b00001111,
            0b00011111,
            0b00111111,
            0b01111111,
            0b11111111,
        };

        fn Bits(comptime T: type) type {
            return struct {
                T,
                u16,
            };
        }

        fn initBits(comptime T: type, out: anytype, num: u16) Bits(T) {
            const UT = std.meta.Int(.unsigned, @bitSizeOf(T));
            return .{
                @bitCast(@as(UT, @intCast(out))),
                num,
            };
        }

        /// Reads `bits` bits from the reader and returns a specified type
        ///  containing them in the least significant end, returning an error if the
        ///  specified number of bits could not be read.
        pub fn readBitsNoEof(self: *@This(), comptime T: type, num: u16) !T {
            const b, const c = try self.readBitsTuple(T, num);
            if (c < num) return error.EndOfStream;
            return b;
        }

        /// Reads `bits` bits from the reader and returns a specified type
        ///  containing them in the least significant end. The number of bits successfully
        ///  read is placed in `out_bits`, as reaching the end of the stream is not an error.
        pub fn readBits(self: *@This(), comptime T: type, num: u16, out_bits: *u16) !T {
            const b, const c = try self.readBitsTuple(T, num);
            out_bits.* = c;
            return b;
        }

        /// Reads `bits` bits from the reader and returns a tuple of the specified type
        ///  containing them in the least significant end, and the number of bits successfully
        ///  read. Reaching the end of the stream is not an error.
        pub fn readBitsTuple(self: *@This(), comptime T: type, num: u16) !Bits(T) {
            const UT = std.meta.Int(.unsigned, @bitSizeOf(T));
            const U = if (@bitSizeOf(T) < 8) u8 else UT; //it is a pain to work with <u8

            //dump any bits in our buffer first
            if (num <= self.count) return initBits(T, self.removeBits(@intCast(num)), num);

            var out_count: u16 = self.count;
            var out: U = self.removeBits(self.count);

            //grab all the full bytes we need and put their
            //bits where they belong
            const full_bytes_left = (num - out_count) / 8;

            for (0..full_bytes_left) |_| {
                const byte = self.reader.readByte() catch |err| switch (err) {
                    error.EndOfStream => return initBits(T, out, out_count),
                    else => |e| return e,
                };

                switch (endian) {
                    .big => {
                        if (U == u8) out = 0 else out <<= 8; //shifting u8 by 8 is illegal in Zig
                        out |= byte;
                    },
                    .little => {
                        const pos = @as(U, byte) << @intCast(out_count);
                        out |= pos;
                    },
                }
                out_count += 8;
            }

            const bits_left = num - out_count;
            const keep = 8 - bits_left;

            if (bits_left == 0) return initBits(T, out, out_count);

            const final_byte = self.reader.readByte() catch |err| switch (err) {
                error.EndOfStream => return initBits(T, out, out_count),
                else => |e| return e,
            };

            switch (endian) {
                .big => {
                    out <<= @intCast(bits_left);
                    out |= final_byte >> @intCast(keep);
                    self.bits = final_byte & low_bit_mask[keep];
                },
                .little => {
                    const pos = @as(U, final_byte & low_bit_mask[bits_left]) << @intCast(out_count);
                    out |= pos;
                    self.bits = final_byte >> @intCast(bits_left);
                },
            }

            self.count = @intCast(keep);
            return initBits(T, out, num);
        }

        //convenience function for removing bits from
        //the appropriate part of the buffer based on
        //endianess.
        fn removeBits(self: *@This(), num: u4) u8 {
            if (num == 8) {
                self.count = 0;
                return self.bits;
            }

            const keep = self.count - num;
            const bits = switch (endian) {
                .big => self.bits >> @intCast(keep),
                .little => self.bits & low_bit_mask[num],
            };
            switch (endian) {
                .big => self.bits &= low_bit_mask[keep],
                .little => self.bits >>= @intCast(num),
            }

            self.count = keep;
            return bits;
        }

        pub fn alignToByte(self: *@This()) void {
            self.bits = 0;
            self.count = 0;
        }
    };
}

pub fn bitReader(comptime endian: std.builtin.Endian, reader: anytype) BitReader(endian, @TypeOf(reader)) {
    return .{ .reader = reader };
}

///////////////////////////////

test "api coverage" {
    const mem_be = [_]u8{ 0b11001101, 0b00001011 };
    const mem_le = [_]u8{ 0b00011101, 0b10010101 };

    var mem_in_be = std.io.fixedBufferStream(&mem_be);
    var bit_stream_be = bitReader(.big, mem_in_be.reader());

    var out_bits: u16 = undefined;

    const expect = std.testing.expect;
    const expectError = std.testing.expectError;

    try expect(1 == try bit_stream_be.readBits(u2, 1, &out_bits));
    try expect(out_bits == 1);
    try expect(2 == try bit_stream_be.readBits(u5, 2, &out_bits));
    try expect(out_bits == 2);
    try expect(3 == try bit_stream_be.readBits(u128, 3, &out_bits));
    try expect(out_bits == 3);
    try expect(4 == try bit_stream_be.readBits(u8, 4, &out_bits));
    try expect(out_bits == 4);
    try expect(5 == try bit_stream_be.readBits(u9, 5, &out_bits));
    try expect(out_bits == 5);
    try expect(1 == try bit_stream_be.readBits(u1, 1, &out_bits));
    try expect(out_bits == 1);

    mem_in_be.pos = 0;
    bit_stream_be.count = 0;
    try expect(0b110011010000101 == try bit_stream_be.readBits(u15, 15, &out_bits));
    try expect(out_bits == 15);

    mem_in_be.pos = 0;
    bit_stream_be.count = 0;
    try expect(0b1100110100001011 == try bit_stream_be.readBits(u16, 16, &out_bits));
    try expect(out_bits == 16);

    _ = try bit_stream_be.readBits(u0, 0, &out_bits);

    try expect(0 == try bit_stream_be.readBits(u1, 1, &out_bits));
    try expect(out_bits == 0);
    try expectError(error.EndOfStream, bit_stream_be.readBitsNoEof(u1, 1));

    var mem_in_le = std.io.fixedBufferStream(&mem_le);
    var bit_stream_le = bitReader(.little, mem_in_le.reader());

    try expect(1 == try bit_stream_le.readBits(u2, 1, &out_bits));
    try expect(out_bits == 1);
    try expect(2 == try bit_stream_le.readBits(u5, 2, &out_bits));
    try expect(out_bits == 2);
    try expect(3 == try bit_stream_le.readBits(u128, 3, &out_bits));
    try expect(out_bits == 3);
    try expect(4 == try bit_stream_le.readBits(u8, 4, &out_bits));
    try expect(out_bits == 4);
    try expect(5 == try bit_stream_le.readBits(u9, 5, &out_bits));
    try expect(out_bits == 5);
    try expect(1 == try bit_stream_le.readBits(u1, 1, &out_bits));
    try expect(out_bits == 1);

    mem_in_le.pos = 0;
    bit_stream_le.count = 0;
    try expect(0b001010100011101 == try bit_stream_le.readBits(u15, 15, &out_bits));
    try expect(out_bits == 15);

    mem_in_le.pos = 0;
    bit_stream_le.count = 0;
    try expect(0b1001010100011101 == try bit_stream_le.readBits(u16, 16, &out_bits));
    try expect(out_bits == 16);

    _ = try bit_stream_le.readBits(u0, 0, &out_bits);

    try expect(0 == try bit_stream_le.readBits(u1, 1, &out_bits));
    try expect(out_bits == 0);
    try expectError(error.EndOfStream, bit_stream_le.readBitsNoEof(u1, 1));
}
const std = @import("../std.zig");

//General note on endianess:
//Big endian is packed starting in the most significant part of the byte and subsequent
// bytes contain less significant bits. Thus we write out bits from the high end
// of our input first.
//Little endian is packed starting in the least significant part of the byte and
// subsequent bytes contain more significant bits. Thus we write out bits from
// the low end of our input first.
//Regardless of endianess, within any given byte the bits are always in most
// to least significant order.
//Also regardless of endianess, the buffer always aligns bits to the low end
// of the byte.

/// Creates a bit writer which allows for writing bits to an underlying standard writer
pub fn BitWriter(comptime endian: std.builtin.Endian, comptime Writer: type) type {
    return struct {
        writer: Writer,
        bits: u8 = 0,
        count: u4 = 0,

        const low_bit_mask = [9]u8{
            0b00000000,
            0b00000001,
            0b00000011,
            0b00000111,
            0b00001111,
            0b00011111,
            0b00111111,
            0b01111111,
            0b11111111,
        };

        /// Write the specified number of bits to the writer from the least significant bits of
        ///  the specified value. Bits will only be written to the writer when there
        ///  are enough to fill a byte.
        pub fn writeBits(self: *@This(), value: anytype, num: u16) !void {
            const T = @TypeOf(value);
            const UT = std.meta.Int(.unsigned, @bitSizeOf(T));
            const U = if (@bitSizeOf(T) < 8) u8 else UT; //<u8 is a pain to work with

            var in: U = @as(UT, @bitCast(value));
            var in_count: u16 = num;

            if (self.count > 0) {
                //if we can't fill the buffer, add what we have
                const bits_free = 8 - self.count;
                if (num < bits_free) {
                    self.addBits(@truncate(in), @intCast(num));
                    return;
                }

                //finish filling the buffer and flush it
                if (num == bits_free) {
                    self.addBits(@truncate(in), @intCast(num));
                    return self.flushBits();
                }

                switch (endian) {
                    .big => {
                        const bits = in >> @intCast(in_count - bits_free);
                        self.addBits(@truncate(bits), bits_free);
                    },
                    .little => {
                        self.addBits(@truncate(in), bits_free);
                        in >>= @intCast(bits_free);
                    },
                }
                in_count -= bits_free;
                try self.flushBits();
            }

            //write full bytes while we can
            const full_bytes_left = in_count / 8;
            for (0..full_bytes_left) |_| {
                switch (endian) {
                    .big => {
                        const bits = in >> @intCast(in_count - 8);
                        try self.writer.writeByte(@truncate(bits));
                    },
                    .little => {
                        try self.writer.writeByte(@truncate(in));
                        if (U == u8) in = 0 else in >>= 8;
                    },
                }
                in_count -= 8;
            }

            //save the remaining bits in the buffer
            self.addBits(@truncate(in), @intCast(in_count));
        }

        //convenience funciton for adding bits to the buffer
        //in the appropriate position based on endianess
        fn addBits(self: *@This(), bits: u8, num: u4) void {
            if (num == 8) self.bits = bits else switch (endian) {
                .big => {
                    self.bits <<= @intCast(num);
                    self.bits |= bits & low_bit_mask[num];
                },
                .little => {
                    const pos = bits << @intCast(self.count);
                    self.bits |= pos;
                },
            }
            self.count += num;
        }

        /// Flush any remaining bits to the writer, filling
        /// unused bits with 0s.
        pub fn flushBits(self: *@This()) !void {
            if (self.count == 0) return;
            if (endian == .big) self.bits <<= @intCast(8 - self.count);
            try self.writer.writeByte(self.bits);
            self.bits = 0;
            self.count = 0;
        }
    };
}

pub fn bitWriter(comptime endian: std.builtin.Endian, writer: anytype) BitWriter(endian, @TypeOf(writer)) {
    return .{ .writer = writer };
}

///////////////////////////////

test "api coverage" {
    var mem_be = [_]u8{0} ** 2;
    var mem_le = [_]u8{0} ** 2;

    var mem_out_be = std.io.fixedBufferStream(&mem_be);
    var bit_stream_be = bitWriter(.big, mem_out_be.writer());

    const testing = std.testing;

    try bit_stream_be.writeBits(@as(u2, 1), 1);
    try bit_stream_be.writeBits(@as(u5, 2), 2);
    try bit_stream_be.writeBits(@as(u128, 3), 3);
    try bit_stream_be.writeBits(@as(u8, 4), 4);
    try bit_stream_be.writeBits(@as(u9, 5), 5);
    try bit_stream_be.writeBits(@as(u1, 1), 1);

    try testing.expect(mem_be[0] == 0b11001101 and mem_be[1] == 0b00001011);

    mem_out_be.pos = 0;

    try bit_stream_be.writeBits(@as(u15, 0b110011010000101), 15);
    try bit_stream_be.flushBits();
    try testing.expect(mem_be[0] == 0b11001101 and mem_be[1] == 0b00001010);

    mem_out_be.pos = 0;
    try bit_stream_be.writeBits(@as(u32, 0b110011010000101), 16);
    try testing.expect(mem_be[0] == 0b01100110 and mem_be[1] == 0b10000101);

    try bit_stream_be.writeBits(@as(u0, 0), 0);

    var mem_out_le = std.io.fixedBufferStream(&mem_le);
    var bit_stream_le = bitWriter(.little, mem_out_le.writer());

    try bit_stream_le.writeBits(@as(u2, 1), 1);
    try bit_stream_le.writeBits(@as(u5, 2), 2);
    try bit_stream_le.writeBits(@as(u128, 3), 3);
    try bit_stream_le.writeBits(@as(u8, 4), 4);
    try bit_stream_le.writeBits(@as(u9, 5), 5);
    try bit_stream_le.writeBits(@as(u1, 1), 1);

    try testing.expect(mem_le[0] == 0b00011101 and mem_le[1] == 0b10010101);

    mem_out_le.pos = 0;
    try bit_stream_le.writeBits(@as(u15, 0b110011010000101), 15);
    try bit_stream_le.flushBits();
    try testing.expect(mem_le[0] == 0b10000101 and mem_le[1] == 0b01100110);

    mem_out_le.pos = 0;
    try bit_stream_le.writeBits(@as(u32, 0b1100110100001011), 16);
    try testing.expect(mem_le[0] == 0b00001011 and mem_le[1] == 0b11001101);

    try bit_stream_le.writeBits(@as(u0, 0), 0);
}
const std = @import("../std.zig");
const mem = std.mem;
const fs = std.fs;
const File = std.fs.File;

pub const BufferedAtomicFile = struct {
    atomic_file: fs.AtomicFile,
    file_writer: File.Writer,
    buffered_writer: BufferedWriter,
    allocator: mem.Allocator,

    pub const buffer_size = 4096;
    pub const BufferedWriter = std.io.BufferedWriter(buffer_size, File.Writer);
    pub const Writer = std.io.Writer(*BufferedWriter, BufferedWriter.Error, BufferedWriter.write);

    /// TODO when https://github.com/ziglang/zig/issues/2761 is solved
    /// this API will not need an allocator
    pub fn create(
        allocator: mem.Allocator,
        dir: fs.Dir,
        dest_path: []const u8,
        atomic_file_options: fs.Dir.AtomicFileOptions,
    ) !*BufferedAtomicFile {
        var self = try allocator.create(BufferedAtomicFile);
        self.* = BufferedAtomicFile{
            .atomic_file = undefined,
            .file_writer = undefined,
            .buffered_writer = undefined,
            .allocator = allocator,
        };
        errdefer allocator.destroy(self);

        self.atomic_file = try dir.atomicFile(dest_path, atomic_file_options);
        errdefer self.atomic_file.deinit();

        self.file_writer = self.atomic_file.file.writer();
        self.buffered_writer = .{ .unbuffered_writer = self.file_writer };
        return self;
    }

    /// always call destroy, even after successful finish()
    pub fn destroy(self: *BufferedAtomicFile) void {
        self.atomic_file.deinit();
        self.allocator.destroy(self);
    }

    pub fn finish(self: *BufferedAtomicFile) !void {
        try self.buffered_writer.flush();
        try self.atomic_file.finish();
    }

    pub fn writer(self: *BufferedAtomicFile) Writer {
        return .{ .context = &self.buffered_writer };
    }
};
const std = @import("../std.zig");
const io = std.io;
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;

pub fn BufferedReader(comptime buffer_size: usize, comptime ReaderType: type) type {
    return struct {
        unbuffered_reader: ReaderType,
        buf: [buffer_size]u8 = undefined,
        start: usize = 0,
        end: usize = 0,

        pub const Error = ReaderType.Error;
        pub const Reader = io.Reader(*Self, Error, read);

        const Self = @This();

        pub fn read(self: *Self, dest: []u8) Error!usize {
            // First try reading from the already buffered data onto the destination.
            const current = self.buf[self.start..self.end];
            if (current.len != 0) {
                const to_transfer = @min(current.len, dest.len);
                @memcpy(dest[0..to_transfer], current[0..to_transfer]);
                self.start += to_transfer;
                return to_transfer;
            }

            // If dest is large, read from the unbuffered reader directly into the destination.
            if (dest.len >= buffer_size) {
                return self.unbuffered_reader.read(dest);
            }

            // If dest is small, read from the unbuffered reader into our own internal buffer,
            // and then transfer to destination.
            self.end = try self.unbuffered_reader.read(&self.buf);
            const to_transfer = @min(self.end, dest.len);
            @memcpy(dest[0..to_transfer], self.buf[0..to_transfer]);
            self.start = to_transfer;
            return to_transfer;
        }

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };
}

pub fn bufferedReader(reader: anytype) BufferedReader(4096, @TypeOf(reader)) {
    return .{ .unbuffered_reader = reader };
}

pub fn bufferedReaderSize(comptime size: usize, reader: anytype) BufferedReader(size, @TypeOf(reader)) {
    return .{ .unbuffered_reader = reader };
}

test "OneByte" {
    const OneByteReadReader = struct {
        str: []const u8,
        curr: usize,

        const Error = error{NoError};
        const Self = @This();
        const Reader = io.Reader(*Self, Error, read);

        fn init(str: []const u8) Self {
            return Self{
                .str = str,
                .curr = 0,
            };
        }

        fn read(self: *Self, dest: []u8) Error!usize {
            if (self.str.len <= self.curr or dest.len == 0)
                return 0;

            dest[0] = self.str[self.curr];
            self.curr += 1;
            return 1;
        }

        fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };

    const str = "This is a test";
    var one_byte_stream = OneByteReadReader.init(str);
    var buf_reader = bufferedReader(one_byte_stream.reader());
    const stream = buf_reader.reader();

    const res = try stream.readAllAlloc(testing.allocator, str.len + 1);
    defer testing.allocator.free(res);
    try testing.expectEqualSlices(u8, str, res);
}

fn smallBufferedReader(underlying_stream: anytype) BufferedReader(8, @TypeOf(underlying_stream)) {
    return .{ .unbuffered_reader = underlying_stream };
}
test "Block" {
    const BlockReader = struct {
        block: []const u8,
        reads_allowed: usize,
        curr_read: usize,

        const Error = error{NoError};
        const Self = @This();
        const Reader = io.Reader(*Self, Error, read);

        fn init(block: []const u8, reads_allowed: usize) Self {
            return Self{
                .block = block,
                .reads_allowed = reads_allowed,
                .curr_read = 0,
            };
        }

        fn read(self: *Self, dest: []u8) Error!usize {
            if (self.curr_read >= self.reads_allowed) return 0;
            @memcpy(dest[0..self.block.len], self.block);

            self.curr_read += 1;
            return self.block.len;
        }

        fn reader(self: *Self) Reader {
            return .{ .context = self };
        }
    };

    const block = "0123";

    // len out == block
    {
        var test_buf_reader: BufferedReader(4, BlockReader) = .{
            .unbuffered_reader = BlockReader.init(block, 2),
        };
        const reader = test_buf_reader.reader();
        var out_buf: [4]u8 = undefined;
        _ = try reader.readAll(&out_buf);
        try testing.expectEqualSlices(u8, &out_buf, block);
        _ = try reader.readAll(&out_buf);
        try testing.expectEqualSlices(u8, &out_buf, block);
        try testing.expectEqual(try reader.readAll(&out_buf), 0);
    }

    // len out < block
    {
        var test_buf_reader: BufferedReader(4, BlockReader) = .{
            .unbuffered_reader = BlockReader.init(block, 2),
        };
        const reader = test_buf_reader.reader();
        var out_buf: [3]u8 = undefined;
        _ = try reader.readAll(&out_buf);
        try testing.expectEqualSlices(u8, &out_buf, "012");
        _ = try reader.readAll(&out_buf);
        try testing.expectEqualSlices(u8, &out_buf, "301");
        const n = try reader.readAll(&out_buf);
        try testing.expectEqualSlices(u8, out_buf[0..n], "23");
        try testing.expectEqual(try reader.readAll(&out_buf), 0);
    }

    // len out > block
    {
        var test_buf_reader: BufferedReader(4, BlockReader) = .{
            .unbuffered_reader = BlockReader.init(block, 2),
        };
        const reader = test_buf_reader.reader();
        var out_buf: [5]u8 = undefined;
        _ = try reader.readAll(&out_buf);
        try testing.expectEqualSlices(u8, &out_buf, "01230");
        const n = try reader.readAll(&out_buf);
        try testing.expectEqualSlices(u8, out_buf[0..n], "123");
        try testing.expectEqual(try reader.readAll(&out_buf), 0);
    }

    // len out == 0
    {
        var test_buf_reader: BufferedReader(4, BlockReader) = .{
            .unbuffered_reader = BlockReader.init(block, 2),
        };
        const reader = test_buf_reader.reader();
        var out_buf: [0]u8 = undefined;
        _ = try reader.readAll(&out_buf);
        try testing.expectEqualSlices(u8, &out_buf, "");
    }

    // len bufreader buf > block
    {
        var test_buf_reader: BufferedReader(5, BlockReader) = .{
            .unbuffered_reader = BlockReader.init(block, 2),
        };
        const reader = test_buf_reader.reader();
        var out_buf: [4]u8 = undefined;
        _ = try reader.readAll(&out_buf);
        try testing.expectEqualSlices(u8, &out_buf, block);
        _ = try reader.readAll(&out_buf);
        try testing.expectEqualSlices(u8, &out_buf, block);
        try testing.expectEqual(try reader.readAll(&out_buf), 0);
    }
}
const std = @import("../std.zig");

const io = std.io;
const mem = std.mem;

pub fn BufferedWriter(comptime buffer_size: usize, comptime WriterType: type) type {
    return struct {
        unbuffered_writer: WriterType,
        buf: [buffer_size]u8 = undefined,
        end: usize = 0,

        pub const Error = WriterType.Error;
        pub const Writer = io.Writer(*Self, Error, write);

        const Self = @This();

        pub fn flush(self: *Self) !void {
            try self.unbuffered_writer.writeAll(self.buf[0..self.end]);
            self.end = 0;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            if (self.end + bytes.len > self.buf.len) {
                try self.flush();
                if (bytes.len > self.buf.len)
                    return self.unbuffered_writer.write(bytes);
            }

            const new_end = self.end + bytes.len;
            @memcpy(self.buf[self.end..new_end], bytes);
            self.end = new_end;
            return bytes.len;
        }
    };
}

pub fn bufferedWriter(underlying_stream: anytype) BufferedWriter(4096, @TypeOf(underlying_stream)) {
    return .{ .unbuffered_writer = underlying_stream };
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const io = std.io;
const testing = std.testing;

pub const CWriter = io.Writer(*std.c.FILE, std.fs.File.WriteError, cWriterWrite);

pub fn cWriter(c_file: *std.c.FILE) CWriter {
    return .{ .context = c_file };
}

fn cWriterWrite(c_file: *std.c.FILE, bytes: []const u8) std.fs.File.WriteError!usize {
    const amt_written = std.c.fwrite(bytes.ptr, 1, bytes.len, c_file);
    if (amt_written >= 0) return amt_written;
    switch (@as(std.c.E, @enumFromInt(std.c._errno().*))) {
        .SUCCESS => unreachable,
        .INVAL => unreachable,
        .FAULT => unreachable,
        .AGAIN => unreachable, // this is a blocking API
        .BADF => unreachable, // always a race condition
        .DESTADDRREQ => unreachable, // connect was never called
        .DQUOT => return error.DiskQuota,
        .FBIG => return error.FileTooBig,
        .IO => return error.InputOutput,
        .NOSPC => return error.NoSpaceLeft,
        .PERM => return error.PermissionDenied,
        .PIPE => return error.BrokenPipe,
        else => |err| return std.posix.unexpectedErrno(err),
    }
}

test cWriter {
    if (!builtin.link_libc or builtin.os.tag == .wasi) return error.SkipZigTest;

    const filename = "tmp_io_test_file.txt";
    const out_file = std.c.fopen(filename, "w") orelse return error.UnableToOpenTestFile;
    defer {
        _ = std.c.fclose(out_file);
        std.fs.cwd().deleteFileZ(filename) catch {};
    }

    const writer = cWriter(out_file);
    try writer.print("hi: {}\n", .{@as(i32, 123)});
}
const std = @import("../std.zig");
const io = std.io;
const mem = std.mem;
const assert = std.debug.assert;

/// Used to detect if the data written to a stream differs from a source buffer
pub fn ChangeDetectionStream(comptime WriterType: type) type {
    return struct {
        const Self = @This();
        pub const Error = WriterType.Error;
        pub const Writer = io.Writer(*Self, Error, write);

        anything_changed: bool,
        underlying_writer: WriterType,
        source_index: usize,
        source: []const u8,

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        fn write(self: *Self, bytes: []const u8) Error!usize {
            if (!self.anything_changed) {
                const end = self.source_index + bytes.len;
                if (end > self.source.len) {
                    self.anything_changed = true;
                } else {
                    const src_slice = self.source[self.source_index..end];
                    self.source_index += bytes.len;
                    if (!mem.eql(u8, bytes, src_slice)) {
                        self.anything_changed = true;
                    }
                }
            }

            return self.underlying_writer.write(bytes);
        }

        pub fn changeDetected(self: *Self) bool {
            return self.anything_changed or (self.source_index != self.source.len);
        }
    };
}

pub fn changeDetectionStream(
    source: []const u8,
    underlying_writer: anytype,
) ChangeDetectionStream(@TypeOf(underlying_writer)) {
    return ChangeDetectionStream(@TypeOf(underlying_writer)){
        .anything_changed = false,
        .underlying_writer = underlying_writer,
        .source_index = 0,
        .source = source,
    };
}
const std = @import("../std.zig");
const io = std.io;
const testing = std.testing;

/// A Reader that counts how many bytes has been read from it.
pub fn CountingReader(comptime ReaderType: anytype) type {
    return struct {
        child_reader: ReaderType,
        bytes_read: u64 = 0,

        pub const Error = ReaderType.Error;
        pub const Reader = io.Reader(*@This(), Error, read);

        pub fn read(self: *@This(), buf: []u8) Error!usize {
            const amt = try self.child_reader.read(buf);
            self.bytes_read += amt;
            return amt;
        }

        pub fn reader(self: *@This()) Reader {
            return .{ .context = self };
        }
    };
}

pub fn countingReader(reader: anytype) CountingReader(@TypeOf(reader)) {
    return .{ .child_reader = reader };
}

test CountingReader {
    const bytes = "yay" ** 100;
    var fbs = io.fixedBufferStream(bytes);

    var counting_stream = countingReader(fbs.reader());
    const stream = counting_stream.reader();

    //read and discard all bytes
    while (stream.readByte()) |_| {} else |err| {
        try testing.expect(err == error.EndOfStream);
    }

    try testing.expect(counting_stream.bytes_read == bytes.len);
}
const std = @import("../std.zig");
const io = std.io;
const testing = std.testing;

/// A Writer that counts how many bytes has been written to it.
pub fn CountingWriter(comptime WriterType: type) type {
    return struct {
        bytes_written: u64,
        child_stream: WriterType,

        pub const Error = WriterType.Error;
        pub const Writer = io.Writer(*Self, Error, write);

        const Self = @This();

        pub fn write(self: *Self, bytes: []const u8) Error!usize {
            const amt = try self.child_stream.write(bytes);
            self.bytes_written += amt;
            return amt;
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
    };
}

pub fn countingWriter(child_stream: anytype) CountingWriter(@TypeOf(child_stream)) {
    return .{ .bytes_written = 0, .child_stream = child_stream };
}

test CountingWriter {
    var counting_stream = countingWriter(std.io.null_writer);
    const stream = counting_stream.writer();

    const bytes = "yay" ** 100;
    stream.writeAll(bytes) catch unreachable;
    try testing.expect(counting_stream.bytes_written == bytes.len);
}
const std = @import("../std.zig");
const io = std.io;
const assert = std.debug.assert;

/// A Writer that returns whether the given character has been written to it.
/// The contents are not written to anything.
pub fn FindByteWriter(comptime UnderlyingWriter: type) type {
    return struct {
        const Self = @This();
        pub const Error = UnderlyingWriter.Error;
        pub const Writer = io.Writer(*Self, Error, write);

        underlying_writer: UnderlyingWriter,
        byte_found: bool,
        byte: u8,

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        fn write(self: *Self, bytes: []const u8) Error!usize {
            if (!self.byte_found) {
                self.byte_found = blk: {
                    for (bytes) |b|
                        if (b == self.byte) break :blk true;
                    break :blk false;
                };
            }
            return self.underlying_writer.write(bytes);
        }
    };
}

pub fn findByteWriter(byte: u8, underlying_writer: anytype) FindByteWriter(@TypeOf(underlying_writer)) {
    return FindByteWriter(@TypeOf(underlying_writer)){
        .underlying_writer = underlying_writer,
        .byte = byte,
        .byte_found = false,
    };
}
const std = @import("../std.zig");
const io = std.io;
const testing = std.testing;
const mem = std.mem;
const assert = std.debug.assert;

/// This turns a byte buffer into an `io.Writer`, `io.Reader`, or `io.SeekableStream`.
/// If the supplied byte buffer is const, then `io.Writer` is not available.
pub fn FixedBufferStream(comptime Buffer: type) type {
    return struct {
        /// `Buffer` is either a `[]u8` or `[]const u8`.
        buffer: Buffer,
        pos: usize,

        pub const ReadError = error{};
        pub const WriteError = error{NoSpaceLeft};
        pub const SeekError = error{};
        pub const GetSeekPosError = error{};

        pub const Reader = io.Reader(*Self, ReadError, read);
        pub const Writer = io.Writer(*Self, WriteError, write);

        pub const SeekableStream = io.SeekableStream(
            *Self,
            SeekError,
            GetSeekPosError,
            seekTo,
            seekBy,
            getPos,
            getEndPos,
        );

        const Self = @This();

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        pub fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        pub fn seekableStream(self: *Self) SeekableStream {
            return .{ .context = self };
        }

        pub fn read(self: *Self, dest: []u8) ReadError!usize {
            const size = @min(dest.len, self.buffer.len - self.pos);
            const end = self.pos + size;

            @memcpy(dest[0..size], self.buffer[self.pos..end]);
            self.pos = end;

            return size;
        }

        /// If the returned number of bytes written is less than requested, the
        /// buffer is full. Returns `error.NoSpaceLeft` when no bytes would be written.
        /// Note: `error.NoSpaceLeft` matches the corresponding error from
        /// `std.fs.File.WriteError`.
        pub fn write(self: *Self, bytes: []const u8) WriteError!usize {
            if (bytes.len == 0) return 0;
            if (self.pos >= self.buffer.len) return error.NoSpaceLeft;

            const n = @min(self.buffer.len - self.pos, bytes.len);
            @memcpy(self.buffer[self.pos..][0..n], bytes[0..n]);
            self.pos += n;

            if (n == 0) return error.NoSpaceLeft;

            return n;
        }

        pub fn seekTo(self: *Self, pos: u64) SeekError!void {
            self.pos = @min(std.math.lossyCast(usize, pos), self.buffer.len);
        }

        pub fn seekBy(self: *Self, amt: i64) SeekError!void {
            if (amt < 0) {
                const abs_amt = @abs(amt);
                const abs_amt_usize = std.math.cast(usize, abs_amt) orelse std.math.maxInt(usize);
                if (abs_amt_usize > self.pos) {
                    self.pos = 0;
                } else {
                    self.pos -= abs_amt_usize;
                }
            } else {
                const amt_usize = std.math.cast(usize, amt) orelse std.math.maxInt(usize);
                const new_pos = std.math.add(usize, self.pos, amt_usize) catch std.math.maxInt(usize);
                self.pos = @min(self.buffer.len, new_pos);
            }
        }

        pub fn getEndPos(self: *Self) GetSeekPosError!u64 {
            return self.buffer.len;
        }

        pub fn getPos(self: *Self) GetSeekPosError!u64 {
            return self.pos;
        }

        pub fn getWritten(self: Self) Buffer {
            return self.buffer[0..self.pos];
        }

        pub fn reset(self: *Self) void {
            self.pos = 0;
        }
    };
}

pub fn fixedBufferStream(buffer: anytype) FixedBufferStream(Slice(@TypeOf(buffer))) {
    return .{ .buffer = buffer, .pos = 0 };
}

fn Slice(comptime T: type) type {
    switch (@typeInfo(T)) {
        .pointer => |ptr_info| {
            var new_ptr_info = ptr_info;
            switch (ptr_info.size) {
                .slice => {},
                .one => switch (@typeInfo(ptr_info.child)) {
                    .array => |info| new_ptr_info.child = info.child,
  ```
