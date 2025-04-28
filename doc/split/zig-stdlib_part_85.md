```
ss.server, &([_]u8{'w'} ** buffer_len), 0);
        try testing.expectEqual(@as(u32, 1), try ring.submit());

        _ = try ring.copy_cqe();
    }

    // Final recv which should work

    // Deliberately put something we don't expect in the buffers
    @memset(mem.sliceAsBytes(&buffers), 1);

    {
        const sqe = try ring.recv(0xdfdfdfdf, socket_test_harness.client, .{ .buffer_selection = .{ .group_id = group_id, .len = buffer_len } }, 0);
        try testing.expectEqual(linux.IORING_OP.RECV, sqe.opcode);
        try testing.expectEqual(@as(i32, socket_test_harness.client), sqe.fd);
        try testing.expectEqual(@as(u64, 0), sqe.addr);
        try testing.expectEqual(@as(u32, buffer_len), sqe.len);
        try testing.expectEqual(@as(u16, group_id), sqe.buf_index);
        try testing.expectEqual(@as(u32, 0), sqe.rw_flags);
        try testing.expectEqual(@as(u32, linux.IOSQE_BUFFER_SELECT), sqe.flags);
        try testing.expectEqual(@as(u32, 1), try ring.submit());

        const cqe = try ring.copy_cqe();
        switch (cqe.err()) {
            .SUCCESS => {},
            else => |errno| std.debug.panic("unhandled errno: {}", .{errno}),
        }

        try testing.expect(cqe.flags & linux.IORING_CQE_F_BUFFER == linux.IORING_CQE_F_BUFFER);
        const used_buffer_id = cqe.flags >> 16;
        try testing.expectEqual(used_buffer_id, reprovided_buffer_id);
        try testing.expectEqual(@as(i32, buffer_len), cqe.res);
        try testing.expectEqual(@as(u64, 0xdfdfdfdf), cqe.user_data);
        const buffer = buffers[used_buffer_id][0..@as(usize, @intCast(cqe.res))];
        try testing.expectEqualSlices(u8, &([_]u8{'w'} ** buffer_len), buffer);
    }
}

/// Used for testing server/client interactions.
const SocketTestHarness = struct {
    listener: posix.socket_t,
    server: posix.socket_t,
    client: posix.socket_t,

    fn close(self: SocketTestHarness) void {
        posix.close(self.client);
        posix.close(self.listener);
    }
};

fn createSocketTestHarness(ring: *IoUring) !SocketTestHarness {
    // Create a TCP server socket
    var address = try net.Address.parseIp4("127.0.0.1", 0);
    const listener_socket = try createListenerSocket(&address);
    errdefer posix.close(listener_socket);

    // Submit 1 accept
    var accept_addr: posix.sockaddr = undefined;
    var accept_addr_len: posix.socklen_t = @sizeOf(@TypeOf(accept_addr));
    _ = try ring.accept(0xaaaaaaaa, listener_socket, &accept_addr, &accept_addr_len, 0);

    // Create a TCP client socket
    const client = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(client);
    _ = try ring.connect(0xcccccccc, client, &address.any, address.getOsSockLen());

    try testing.expectEqual(@as(u32, 2), try ring.submit());

    var cqe_accept = try ring.copy_cqe();
    if (cqe_accept.err() == .INVAL) return error.SkipZigTest;
    var cqe_connect = try ring.copy_cqe();
    if (cqe_connect.err() == .INVAL) return error.SkipZigTest;

    // The accept/connect CQEs may arrive in any order, the connect CQE will sometimes come first:
    if (cqe_accept.user_data == 0xcccccccc and cqe_connect.user_data == 0xaaaaaaaa) {
        const a = cqe_accept;
        const b = cqe_connect;
        cqe_accept = b;
        cqe_connect = a;
    }

    try testing.expectEqual(@as(u64, 0xaaaaaaaa), cqe_accept.user_data);
    if (cqe_accept.res <= 0) std.debug.print("\ncqe_accept.res={}\n", .{cqe_accept.res});
    try testing.expect(cqe_accept.res > 0);
    try testing.expectEqual(@as(u32, 0), cqe_accept.flags);
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xcccccccc,
        .res = 0,
        .flags = 0,
    }, cqe_connect);

    // All good

    return SocketTestHarness{
        .listener = listener_socket,
        .server = cqe_accept.res,
        .client = client,
    };
}

fn createListenerSocket(address: *net.Address) !posix.socket_t {
    const kernel_backlog = 1;
    const listener_socket = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(listener_socket);

    try posix.setsockopt(listener_socket, posix.SOL.SOCKET, posix.SO.REUSEADDR, &mem.toBytes(@as(c_int, 1)));
    try posix.bind(listener_socket, &address.any, address.getOsSockLen());
    try posix.listen(listener_socket, kernel_backlog);

    // set address to the OS-chosen IP/port.
    var slen: posix.socklen_t = address.getOsSockLen();
    try posix.getsockname(listener_socket, &address.any, &slen);

    return listener_socket;
}

test "accept multishot" {
    if (!is_linux) return error.SkipZigTest;

    var ring = IoUring.init(16, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    var address = try net.Address.parseIp4("127.0.0.1", 0);
    const listener_socket = try createListenerSocket(&address);
    defer posix.close(listener_socket);

    // submit multishot accept operation
    var addr: posix.sockaddr = undefined;
    var addr_len: posix.socklen_t = @sizeOf(@TypeOf(addr));
    const userdata: u64 = 0xaaaaaaaa;
    _ = try ring.accept_multishot(userdata, listener_socket, &addr, &addr_len, 0);
    try testing.expectEqual(@as(u32, 1), try ring.submit());

    var nr: usize = 4; // number of clients to connect
    while (nr > 0) : (nr -= 1) {
        // connect client
        const client = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
        errdefer posix.close(client);
        try posix.connect(client, &address.any, address.getOsSockLen());

        // test accept completion
        var cqe = try ring.copy_cqe();
        if (cqe.err() == .INVAL) return error.SkipZigTest;
        try testing.expect(cqe.res > 0);
        try testing.expect(cqe.user_data == userdata);
        try testing.expect(cqe.flags & linux.IORING_CQE_F_MORE > 0); // more flag is set

        posix.close(client);
    }
}

test "accept/connect/send_zc/recv" {
    try skipKernelLessThan(.{ .major = 6, .minor = 0, .patch = 0 });

    var ring = IoUring.init(16, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const socket_test_harness = try createSocketTestHarness(&ring);
    defer socket_test_harness.close();

    const buffer_send = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe };
    var buffer_recv = [_]u8{0} ** 10;

    // zero-copy send
    const sqe_send = try ring.send_zc(0xeeeeeeee, socket_test_harness.client, buffer_send[0..], 0, 0);
    sqe_send.flags |= linux.IOSQE_IO_LINK;
    _ = try ring.recv(0xffffffff, socket_test_harness.server, .{ .buffer = buffer_recv[0..] }, 0);
    try testing.expectEqual(@as(u32, 2), try ring.submit());

    var cqe_send = try ring.copy_cqe();
    // First completion of zero-copy send.
    // IORING_CQE_F_MORE, means that there
    // will be a second completion event / notification for the
    // request, with the user_data field set to the same value.
    // buffer_send must be keep alive until second cqe.
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xeeeeeeee,
        .res = buffer_send.len,
        .flags = linux.IORING_CQE_F_MORE,
    }, cqe_send);

    cqe_send, const cqe_recv = brk: {
        const cqe1 = try ring.copy_cqe();
        const cqe2 = try ring.copy_cqe();
        break :brk if (cqe1.user_data == 0xeeeeeeee) .{ cqe1, cqe2 } else .{ cqe2, cqe1 };
    };

    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xffffffff,
        .res = buffer_recv.len,
        .flags = cqe_recv.flags & linux.IORING_CQE_F_SOCK_NONEMPTY,
    }, cqe_recv);
    try testing.expectEqualSlices(u8, buffer_send[0..buffer_recv.len], buffer_recv[0..]);

    // Second completion of zero-copy send.
    // IORING_CQE_F_NOTIF in flags signals that kernel is done with send_buffer
    try testing.expectEqual(linux.io_uring_cqe{
        .user_data = 0xeeeeeeee,
        .res = 0,
        .flags = linux.IORING_CQE_F_NOTIF,
    }, cqe_send);
}

test "accept_direct" {
    try skipKernelLessThan(.{ .major = 5, .minor = 19, .patch = 0 });

    var ring = IoUring.init(1, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();
    var address = try net.Address.parseIp4("127.0.0.1", 0);

    // register direct file descriptors
    var registered_fds = [_]posix.fd_t{-1} ** 2;
    try ring.register_files(registered_fds[0..]);

    const listener_socket = try createListenerSocket(&address);
    defer posix.close(listener_socket);

    const accept_userdata: u64 = 0xaaaaaaaa;
    const read_userdata: u64 = 0xbbbbbbbb;
    const data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe };

    for (0..2) |_| {
        for (registered_fds, 0..) |_, i| {
            var buffer_recv = [_]u8{0} ** 16;
            const buffer_send: []const u8 = data[0 .. data.len - i]; // make it different at each loop

            // submit accept, will chose registered fd and return index in cqe
            _ = try ring.accept_direct(accept_userdata, listener_socket, null, null, 0);
            try testing.expectEqual(@as(u32, 1), try ring.submit());

            // connect
            const client = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
            try posix.connect(client, &address.any, address.getOsSockLen());
            defer posix.close(client);

            // accept completion
            const cqe_accept = try ring.copy_cqe();
            try testing.expectEqual(posix.E.SUCCESS, cqe_accept.err());
            const fd_index = cqe_accept.res;
            try testing.expect(fd_index < registered_fds.len);
            try testing.expect(cqe_accept.user_data == accept_userdata);

            // send data
            _ = try posix.send(client, buffer_send, 0);

            // Example of how to use registered fd:
            // Submit receive to fixed file returned by accept (fd_index).
            // Fd field is set to registered file index, returned by accept.
            // Flag linux.IOSQE_FIXED_FILE must be set.
            const recv_sqe = try ring.recv(read_userdata, fd_index, .{ .buffer = &buffer_recv }, 0);
            recv_sqe.flags |= linux.IOSQE_FIXED_FILE;
            try testing.expectEqual(@as(u32, 1), try ring.submit());

            // accept receive
            const recv_cqe = try ring.copy_cqe();
            try testing.expect(recv_cqe.user_data == read_userdata);
            try testing.expect(recv_cqe.res == buffer_send.len);
            try testing.expectEqualSlices(u8, buffer_send, buffer_recv[0..buffer_send.len]);
        }
        // no more available fds, accept will get NFILE error
        {
            // submit accept
            _ = try ring.accept_direct(accept_userdata, listener_socket, null, null, 0);
            try testing.expectEqual(@as(u32, 1), try ring.submit());
            // connect
            const client = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
            try posix.connect(client, &address.any, address.getOsSockLen());
            defer posix.close(client);
            // completion with error
            const cqe_accept = try ring.copy_cqe();
            try testing.expect(cqe_accept.user_data == accept_userdata);
            try testing.expectEqual(posix.E.NFILE, cqe_accept.err());
        }
        // return file descriptors to kernel
        try ring.register_files_update(0, registered_fds[0..]);
    }
    try ring.unregister_files();
}

test "accept_multishot_direct" {
    try skipKernelLessThan(.{ .major = 5, .minor = 19, .patch = 0 });

    var ring = IoUring.init(1, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    var address = try net.Address.parseIp4("127.0.0.1", 0);

    var registered_fds = [_]posix.fd_t{-1} ** 2;
    try ring.register_files(registered_fds[0..]);

    const listener_socket = try createListenerSocket(&address);
    defer posix.close(listener_socket);

    const accept_userdata: u64 = 0xaaaaaaaa;

    for (0..2) |_| {
        // submit multishot accept
        // Will chose registered fd and return index of the selected registered file in cqe.
        _ = try ring.accept_multishot_direct(accept_userdata, listener_socket, null, null, 0);
        try testing.expectEqual(@as(u32, 1), try ring.submit());

        for (registered_fds) |_| {
            // connect
            const client = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
            try posix.connect(client, &address.any, address.getOsSockLen());
            defer posix.close(client);

            // accept completion
            const cqe_accept = try ring.copy_cqe();
            const fd_index = cqe_accept.res;
            try testing.expect(fd_index < registered_fds.len);
            try testing.expect(cqe_accept.user_data == accept_userdata);
            try testing.expect(cqe_accept.flags & linux.IORING_CQE_F_MORE > 0); // has more is set
        }
        // No more available fds, accept will get NFILE error.
        // Multishot is terminated (more flag is not set).
        {
            // connect
            const client = try posix.socket(address.any.family, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
            try posix.connect(client, &address.any, address.getOsSockLen());
            defer posix.close(client);
            // completion with error
            const cqe_accept = try ring.copy_cqe();
            try testing.expect(cqe_accept.user_data == accept_userdata);
            try testing.expectEqual(posix.E.NFILE, cqe_accept.err());
            try testing.expect(cqe_accept.flags & linux.IORING_CQE_F_MORE == 0); // has more is not set
        }
        // return file descriptors to kernel
        try ring.register_files_update(0, registered_fds[0..]);
    }
    try ring.unregister_files();
}

test "socket" {
    try skipKernelLessThan(.{ .major = 5, .minor = 19, .patch = 0 });

    var ring = IoUring.init(1, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    // prepare, submit socket operation
    _ = try ring.socket(0, linux.AF.INET, posix.SOCK.STREAM, 0, 0);
    try testing.expectEqual(@as(u32, 1), try ring.submit());

    // test completion
    var cqe = try ring.copy_cqe();
    try testing.expectEqual(posix.E.SUCCESS, cqe.err());
    const fd: posix.fd_t = @intCast(cqe.res);
    try testing.expect(fd > 2);

    posix.close(fd);
}

test "socket_direct/socket_direct_alloc/close_direct" {
    try skipKernelLessThan(.{ .major = 5, .minor = 19, .patch = 0 });

    var ring = IoUring.init(2, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    var registered_fds = [_]posix.fd_t{-1} ** 3;
    try ring.register_files(registered_fds[0..]);

    // create socket in registered file descriptor at index 0 (last param)
    _ = try ring.socket_direct(0, linux.AF.INET, posix.SOCK.STREAM, 0, 0, 0);
    try testing.expectEqual(@as(u32, 1), try ring.submit());
    var cqe_socket = try ring.copy_cqe();
    try testing.expectEqual(posix.E.SUCCESS, cqe_socket.err());
    try testing.expect(cqe_socket.res == 0);

    // create socket in registered file descriptor at index 1 (last param)
    _ = try ring.socket_direct(0, linux.AF.INET, posix.SOCK.STREAM, 0, 0, 1);
    try testing.expectEqual(@as(u32, 1), try ring.submit());
    cqe_socket = try ring.copy_cqe();
    try testing.expectEqual(posix.E.SUCCESS, cqe_socket.err());
    try testing.expect(cqe_socket.res == 0); // res is 0 when index is specified

    // create socket in kernel chosen file descriptor index (_alloc version)
    // completion res has index from registered files
    _ = try ring.socket_direct_alloc(0, linux.AF.INET, posix.SOCK.STREAM, 0, 0);
    try testing.expectEqual(@as(u32, 1), try ring.submit());
    cqe_socket = try ring.copy_cqe();
    try testing.expectEqual(posix.E.SUCCESS, cqe_socket.err());
    try testing.expect(cqe_socket.res == 2); // returns registered file index

    // use sockets from registered_fds in connect operation
    var address = try net.Address.parseIp4("127.0.0.1", 0);
    const listener_socket = try createListenerSocket(&address);
    defer posix.close(listener_socket);
    const accept_userdata: u64 = 0xaaaaaaaa;
    const connect_userdata: u64 = 0xbbbbbbbb;
    const close_userdata: u64 = 0xcccccccc;
    for (registered_fds, 0..) |_, fd_index| {
        // prepare accept
        _ = try ring.accept(accept_userdata, listener_socket, null, null, 0);
        // prepare connect with fixed socket
        const connect_sqe = try ring.connect(connect_userdata, @intCast(fd_index), &address.any, address.getOsSockLen());
        connect_sqe.flags |= linux.IOSQE_FIXED_FILE; // fd is fixed file index
        // submit both
        try testing.expectEqual(@as(u32, 2), try ring.submit());
        // get completions
        var cqe_connect = try ring.copy_cqe();
        var cqe_accept = try ring.copy_cqe();
        // ignore order
        if (cqe_connect.user_data == accept_userdata and cqe_accept.user_data == connect_userdata) {
            const a = cqe_accept;
            const b = cqe_connect;
            cqe_accept = b;
            cqe_connect = a;
        }
        // test connect completion
        try testing.expect(cqe_connect.user_data == connect_userdata);
        try testing.expectEqual(posix.E.SUCCESS, cqe_connect.err());
        // test accept completion
        try testing.expect(cqe_accept.user_data == accept_userdata);
        try testing.expectEqual(posix.E.SUCCESS, cqe_accept.err());

        //  submit and test close_direct
        _ = try ring.close_direct(close_userdata, @intCast(fd_index));
        try testing.expectEqual(@as(u32, 1), try ring.submit());
        var cqe_close = try ring.copy_cqe();
        try testing.expect(cqe_close.user_data == close_userdata);
        try testing.expectEqual(posix.E.SUCCESS, cqe_close.err());
    }

    try ring.unregister_files();
}

test "openat_direct/close_direct" {
    try skipKernelLessThan(.{ .major = 5, .minor = 19, .patch = 0 });

    var ring = IoUring.init(2, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    var registered_fds = [_]posix.fd_t{-1} ** 3;
    try ring.register_files(registered_fds[0..]);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = "test_io_uring_close_direct";
    const flags: linux.O = .{ .ACCMODE = .RDWR, .CREAT = true };
    const mode: posix.mode_t = 0o666;
    const user_data: u64 = 0;

    // use registered file at index 0 (last param)
    _ = try ring.openat_direct(user_data, tmp.dir.fd, path, flags, mode, 0);
    try testing.expectEqual(@as(u32, 1), try ring.submit());
    var cqe = try ring.copy_cqe();
    try testing.expectEqual(posix.E.SUCCESS, cqe.err());
    try testing.expect(cqe.res == 0);

    // use registered file at index 1
    _ = try ring.openat_direct(user_data, tmp.dir.fd, path, flags, mode, 1);
    try testing.expectEqual(@as(u32, 1), try ring.submit());
    cqe = try ring.copy_cqe();
    try testing.expectEqual(posix.E.SUCCESS, cqe.err());
    try testing.expect(cqe.res == 0); // res is 0 when we specify index

    // let kernel choose registered file index
    _ = try ring.openat_direct(user_data, tmp.dir.fd, path, flags, mode, linux.IORING_FILE_INDEX_ALLOC);
    try testing.expectEqual(@as(u32, 1), try ring.submit());
    cqe = try ring.copy_cqe();
    try testing.expectEqual(posix.E.SUCCESS, cqe.err());
    try testing.expect(cqe.res == 2); // chosen index is in res

    // close all open file descriptors
    for (registered_fds, 0..) |_, fd_index| {
        _ = try ring.close_direct(user_data, @intCast(fd_index));
        try testing.expectEqual(@as(u32, 1), try ring.submit());
        var cqe_close = try ring.copy_cqe();
        try testing.expectEqual(posix.E.SUCCESS, cqe_close.err());
    }
    try ring.unregister_files();
}

test "waitid" {
    try skipKernelLessThan(.{ .major = 6, .minor = 7, .patch = 0 });

    var ring = IoUring.init(16, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const pid = try posix.fork();
    if (pid == 0) {
        posix.exit(7);
    }

    var siginfo: posix.siginfo_t = undefined;
    _ = try ring.waitid(0, .PID, pid, &siginfo, posix.W.EXITED, 0);

    try testing.expectEqual(1, try ring.submit());

    const cqe_waitid = try ring.copy_cqe();
    try testing.expectEqual(0, cqe_waitid.res);
    try testing.expectEqual(pid, siginfo.fields.common.first.piduid.pid);
    try testing.expectEqual(7, siginfo.fields.common.second.sigchld.status);
}

/// For use in tests. Returns SkipZigTest if kernel version is less than required.
inline fn skipKernelLessThan(required: std.SemanticVersion) !void {
    if (!is_linux) return error.SkipZigTest;

    var uts: linux.utsname = undefined;
    const res = linux.uname(&uts);
    switch (linux.E.init(res)) {
        .SUCCESS => {},
        else => |errno| return posix.unexpectedErrno(errno),
    }

    const release = mem.sliceTo(&uts.release, 0);
    // Strips potential extra, as kernel version might not be semver compliant, example "6.8.9-300.fc40.x86_64"
    const extra_index = std.mem.indexOfAny(u8, release, "-+");
    const stripped = release[0..(extra_index orelse release.len)];
    // Make sure the input don't rely on the extra we just stripped
    try testing.expect(required.pre == null and required.build == null);

    var current = try std.SemanticVersion.parse(stripped);
    current.pre = null; // don't check pre field
    if (required.order(current) == .gt) return error.SkipZigTest;
}

test BufferGroup {
    if (!is_linux) return error.SkipZigTest;

    // Init IoUring
    var ring = IoUring.init(16, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    // Init buffer group for ring
    const group_id: u16 = 1; // buffers group id
    const buffers_count: u16 = 1; // number of buffers in buffer group
    const buffer_size: usize = 128; // size of each buffer in group
    var buf_grp = BufferGroup.init(
        &ring,
        testing.allocator,
        group_id,
        buffer_size,
        buffers_count,
    ) catch |err| switch (err) {
        // kernel older than 5.19
        error.ArgumentsInvalid => return error.SkipZigTest,
        else => return err,
    };
    defer buf_grp.deinit(testing.allocator);

    // Create client/server fds
    const fds = try createSocketTestHarness(&ring);
    defer fds.close();
    const data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe };

    // Client sends data
    {
        _ = try ring.send(1, fds.client, data[0..], 0);
        const submitted = try ring.submit();
        try testing.expectEqual(1, submitted);
        const cqe_send = try ring.copy_cqe();
        if (cqe_send.err() == .INVAL) return error.SkipZigTest;
        try testing.expectEqual(linux.io_uring_cqe{ .user_data = 1, .res = data.len, .flags = 0 }, cqe_send);
    }

    // Server uses buffer group receive
    {
        // Submit recv operation, buffer will be chosen from buffer group
        _ = try buf_grp.recv(2, fds.server, 0);
        const submitted = try ring.submit();
        try testing.expectEqual(1, submitted);

        // ... when we have completion for recv operation
        const cqe = try ring.copy_cqe();
        try testing.expectEqual(2, cqe.user_data); // matches submitted user_data
        try testing.expect(cqe.res >= 0); // success
        try testing.expectEqual(posix.E.SUCCESS, cqe.err());
        try testing.expectEqual(data.len, @as(usize, @intCast(cqe.res))); // cqe.res holds received data len

        // Get buffer from pool
        const buf = try buf_grp.get(cqe);
        try testing.expectEqualSlices(u8, &data, buf);
        // Release buffer to the kernel when application is done with it
        try buf_grp.put(cqe);
    }
}

test "ring mapped buffers recv" {
    if (!is_linux) return error.SkipZigTest;

    var ring = IoUring.init(16, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    // init buffer group
    const group_id: u16 = 1; // buffers group id
    const buffers_count: u16 = 2; // number of buffers in buffer group
    const buffer_size: usize = 4; // size of each buffer in group
    var buf_grp = BufferGroup.init(
        &ring,
        testing.allocator,
        group_id,
        buffer_size,
        buffers_count,
    ) catch |err| switch (err) {
        // kernel older than 5.19
        error.ArgumentsInvalid => return error.SkipZigTest,
        else => return err,
    };
    defer buf_grp.deinit(testing.allocator);

    // create client/server fds
    const fds = try createSocketTestHarness(&ring);
    defer fds.close();

    // for random user_data in sqe/cqe
    var Rnd = std.Random.DefaultPrng.init(std.testing.random_seed);
    var rnd = Rnd.random();

    var round: usize = 4; // repeat send/recv cycle round times
    while (round > 0) : (round -= 1) {
        // client sends data
        const data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe };
        {
            const user_data = rnd.int(u64);
            _ = try ring.send(user_data, fds.client, data[0..], 0);
            try testing.expectEqual(@as(u32, 1), try ring.submit());
            const cqe_send = try ring.copy_cqe();
            if (cqe_send.err() == .INVAL) return error.SkipZigTest;
            try testing.expectEqual(linux.io_uring_cqe{ .user_data = user_data, .res = data.len, .flags = 0 }, cqe_send);
        }
        var pos: usize = 0;

        // read first chunk
        const cqe1 = try buf_grp_recv_submit_get_cqe(&ring, &buf_grp, fds.server, rnd.int(u64));
        var buf = try buf_grp.get(cqe1);
        try testing.expectEqualSlices(u8, data[pos..][0..buf.len], buf);
        pos += buf.len;
        // second chunk
        const cqe2 = try buf_grp_recv_submit_get_cqe(&ring, &buf_grp, fds.server, rnd.int(u64));
        buf = try buf_grp.get(cqe2);
        try testing.expectEqualSlices(u8, data[pos..][0..buf.len], buf);
        pos += buf.len;

        // both buffers provided to the kernel are used so we get error
        // 'no more buffers', until we put buffers to the kernel
        {
            const user_data = rnd.int(u64);
            _ = try buf_grp.recv(user_data, fds.server, 0);
            try testing.expectEqual(@as(u32, 1), try ring.submit());
            const cqe = try ring.copy_cqe();
            try testing.expectEqual(user_data, cqe.user_data);
            try testing.expect(cqe.res < 0); // fail
            try testing.expectEqual(posix.E.NOBUFS, cqe.err());
            try testing.expect(cqe.flags & linux.IORING_CQE_F_BUFFER == 0); // IORING_CQE_F_BUFFER flags is set on success only
            try testing.expectError(error.NoBufferSelected, cqe.buffer_id());
        }

        // put buffers back to the kernel
        try buf_grp.put(cqe1);
        try buf_grp.put(cqe2);

        // read remaining data
        while (pos < data.len) {
            const cqe = try buf_grp_recv_submit_get_cqe(&ring, &buf_grp, fds.server, rnd.int(u64));
            buf = try buf_grp.get(cqe);
            try testing.expectEqualSlices(u8, data[pos..][0..buf.len], buf);
            pos += buf.len;
            try buf_grp.put(cqe);
        }
    }
}

test "ring mapped buffers multishot recv" {
    if (!is_linux) return error.SkipZigTest;

    var ring = IoUring.init(16, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    // init buffer group
    const group_id: u16 = 1; // buffers group id
    const buffers_count: u16 = 2; // number of buffers in buffer group
    const buffer_size: usize = 4; // size of each buffer in group
    var buf_grp = BufferGroup.init(
        &ring,
        testing.allocator,
        group_id,
        buffer_size,
        buffers_count,
    ) catch |err| switch (err) {
        // kernel older than 5.19
        error.ArgumentsInvalid => return error.SkipZigTest,
        else => return err,
    };
    defer buf_grp.deinit(testing.allocator);

    // create client/server fds
    const fds = try createSocketTestHarness(&ring);
    defer fds.close();

    // for random user_data in sqe/cqe
    var Rnd = std.Random.DefaultPrng.init(std.testing.random_seed);
    var rnd = Rnd.random();

    var round: usize = 4; // repeat send/recv cycle round times
    while (round > 0) : (round -= 1) {
        // client sends data
        const data = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
        {
            const user_data = rnd.int(u64);
            _ = try ring.send(user_data, fds.client, data[0..], 0);
            try testing.expectEqual(@as(u32, 1), try ring.submit());
            const cqe_send = try ring.copy_cqe();
            if (cqe_send.err() == .INVAL) return error.SkipZigTest;
            try testing.expectEqual(linux.io_uring_cqe{ .user_data = user_data, .res = data.len, .flags = 0 }, cqe_send);
        }

        // start multishot recv
        var recv_user_data = rnd.int(u64);
        _ = try buf_grp.recv_multishot(recv_user_data, fds.server, 0);
        try testing.expectEqual(@as(u32, 1), try ring.submit()); // submit

        // server reads data into provided buffers
        // there are 2 buffers of size 4, so each read gets only chunk of data
        // we read four chunks of 4, 4, 4, 4 bytes each
        var chunk: []const u8 = data[0..buffer_size]; // first chunk
        const cqe1 = try expect_buf_grp_cqe(&ring, &buf_grp, recv_user_data, chunk);
        try testing.expect(cqe1.flags & linux.IORING_CQE_F_MORE > 0);

        chunk = data[buffer_size .. buffer_size * 2]; // second chunk
        const cqe2 = try expect_buf_grp_cqe(&ring, &buf_grp, recv_user_data, chunk);
        try testing.expect(cqe2.flags & linux.IORING_CQE_F_MORE > 0);

        // both buffers provided to the kernel are used so we get error
        // 'no more buffers', until we put buffers to the kernel
        {
            const cqe = try ring.copy_cqe();
            try testing.expectEqual(recv_user_data, cqe.user_data);
            try testing.expect(cqe.res < 0); // fail
            try testing.expectEqual(posix.E.NOBUFS, cqe.err());
            try testing.expect(cqe.flags & linux.IORING_CQE_F_BUFFER == 0); // IORING_CQE_F_BUFFER flags is set on success only
            // has more is not set
            // indicates that multishot is finished
            try testing.expect(cqe.flags & linux.IORING_CQE_F_MORE == 0);
            try testing.expectError(error.NoBufferSelected, cqe.buffer_id());
        }

        // put buffers back to the kernel
        try buf_grp.put(cqe1);
        try buf_grp.put(cqe2);

        // restart multishot
        recv_user_data = rnd.int(u64);
        _ = try buf_grp.recv_multishot(recv_user_data, fds.server, 0);
        try testing.expectEqual(@as(u32, 1), try ring.submit()); // submit

        chunk = data[buffer_size * 2 .. buffer_size * 3]; // third chunk
        const cqe3 = try expect_buf_grp_cqe(&ring, &buf_grp, recv_user_data, chunk);
        try testing.expect(cqe3.flags & linux.IORING_CQE_F_MORE > 0);
        try buf_grp.put(cqe3);

        chunk = data[buffer_size * 3 ..]; // last chunk
        const cqe4 = try expect_buf_grp_cqe(&ring, &buf_grp, recv_user_data, chunk);
        try testing.expect(cqe4.flags & linux.IORING_CQE_F_MORE > 0);
        try buf_grp.put(cqe4);

        // cancel pending multishot recv operation
        {
            const cancel_user_data = rnd.int(u64);
            _ = try ring.cancel(cancel_user_data, recv_user_data, 0);
            try testing.expectEqual(@as(u32, 1), try ring.submit());

            // expect completion of cancel operation and completion of recv operation
            var cqe_cancel = try ring.copy_cqe();
            if (cqe_cancel.err() == .INVAL) return error.SkipZigTest;
            var cqe_recv = try ring.copy_cqe();
            if (cqe_recv.err() == .INVAL) return error.SkipZigTest;

            // don't depend on order of completions
            if (cqe_cancel.user_data == recv_user_data and cqe_recv.user_data == cancel_user_data) {
                const a = cqe_cancel;
                const b = cqe_recv;
                cqe_cancel = b;
                cqe_recv = a;
            }

            // Note on different kernel results:
            // on older kernel (tested with v6.0.16, v6.1.57, v6.2.12, v6.4.16)
            //   cqe_cancel.err() == .NOENT
            //   cqe_recv.err() == .NOBUFS
            // on kernel (tested with v6.5.0, v6.5.7)
            //   cqe_cancel.err() == .SUCCESS
            //   cqe_recv.err() == .CANCELED
            // Upstream reference: https://github.com/axboe/liburing/issues/984

            // cancel operation is success (or NOENT on older kernels)
            try testing.expectEqual(cancel_user_data, cqe_cancel.user_data);
            try testing.expect(cqe_cancel.err() == .NOENT or cqe_cancel.err() == .SUCCESS);

            // recv operation is failed with err CANCELED (or NOBUFS on older kernels)
            try testing.expectEqual(recv_user_data, cqe_recv.user_data);
            try testing.expect(cqe_recv.res < 0);
            try testing.expect(cqe_recv.err() == .NOBUFS or cqe_recv.err() == .CANCELED);
            try testing.expect(cqe_recv.flags & linux.IORING_CQE_F_MORE == 0);
        }
    }
}

// Prepare, submit recv and get cqe using buffer group.
fn buf_grp_recv_submit_get_cqe(
    ring: *IoUring,
    buf_grp: *BufferGroup,
    fd: posix.fd_t,
    user_data: u64,
) !linux.io_uring_cqe {
    // prepare and submit recv
    const sqe = try buf_grp.recv(user_data, fd, 0);
    try testing.expect(sqe.flags & linux.IOSQE_BUFFER_SELECT == linux.IOSQE_BUFFER_SELECT);
    try testing.expect(sqe.buf_index == buf_grp.group_id);
    try testing.expectEqual(@as(u32, 1), try ring.submit()); // submit
    // get cqe, expect success
    const cqe = try ring.copy_cqe();
    try testing.expectEqual(user_data, cqe.user_data);
    try testing.expect(cqe.res >= 0); // success
    try testing.expectEqual(posix.E.SUCCESS, cqe.err());
    try testing.expect(cqe.flags & linux.IORING_CQE_F_BUFFER == linux.IORING_CQE_F_BUFFER); // IORING_CQE_F_BUFFER flag is set

    return cqe;
}

fn expect_buf_grp_cqe(
    ring: *IoUring,
    buf_grp: *BufferGroup,
    user_data: u64,
    expected: []const u8,
) !linux.io_uring_cqe {
    // get cqe
    const cqe = try ring.copy_cqe();
    try testing.expectEqual(user_data, cqe.user_data);
    try testing.expect(cqe.res >= 0); // success
    try testing.expect(cqe.flags & linux.IORING_CQE_F_BUFFER == linux.IORING_CQE_F_BUFFER); // IORING_CQE_F_BUFFER flag is set
    try testing.expectEqual(expected.len, @as(usize, @intCast(cqe.res)));
    try testing.expectEqual(posix.E.SUCCESS, cqe.err());

    // get buffer from pool
    const buffer_id = try cqe.buffer_id();
    const len = @as(usize, @intCast(cqe.res));
    const buf = buf_grp.get_by_id(buffer_id)[0..len];
    try testing.expectEqualSlices(u8, expected, buf);

    return cqe;
}

test "copy_cqes with wrapping sq.cqes buffer" {
    if (!is_linux) return error.SkipZigTest;

    var ring = IoUring.init(2, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    try testing.expectEqual(2, ring.sq.sqes.len);
    try testing.expectEqual(4, ring.cq.cqes.len);

    // submit 2 entries, receive 2 completions
    var cqes: [8]linux.io_uring_cqe = undefined;
    {
        for (0..2) |_| {
            const sqe = try ring.get_sqe();
            sqe.prep_timeout(&.{ .sec = 0, .nsec = 10000 }, 0, 0);
            try testing.expect(try ring.submit() == 1);
        }
        var cqe_count: u32 = 0;
        while (cqe_count < 2) {
            cqe_count += try ring.copy_cqes(&cqes, 2 - cqe_count);
        }
    }

    try testing.expectEqual(2, ring.cq.head.*);

    // sq.sqes len is 4, starting at position 2
    // every 4 entries submit wraps completion buffer
    // we are reading ring.cq.cqes at indexes 2,3,0,1
    for (1..1024) |i| {
        for (0..4) |_| {
            const sqe = try ring.get_sqe();
            sqe.prep_timeout(&.{ .sec = 0, .nsec = 10000 }, 0, 0);
            try testing.expect(try ring.submit() == 1);
        }
        var cqe_count: u32 = 0;
        while (cqe_count < 4) {
            cqe_count += try ring.copy_cqes(&cqes, 4 - cqe_count);
        }
        try testing.expectEqual(4, cqe_count);
        try testing.expectEqual(2 + 4 * i, ring.cq.head.*);
    }
}

test "bind/listen/connect" {
    var ring = IoUring.init(4, 0) catch |err| switch (err) {
        error.SystemOutdated => return error.SkipZigTest,
        error.PermissionDenied => return error.SkipZigTest,
        else => return err,
    };
    defer ring.deinit();

    const probe = ring.get_probe() catch return error.SkipZigTest;
    // LISTEN is higher required operation
    if (!probe.is_supported(.LISTEN)) return error.SkipZigTest;

    var addr = net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 0);
    const proto: u32 = if (addr.any.family == linux.AF.UNIX) 0 else linux.IPPROTO.TCP;

    const listen_fd = brk: {
        // Create socket
        _ = try ring.socket(1, addr.any.family, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, proto, 0);
        try testing.expectEqual(1, try ring.submit());
        var cqe = try ring.copy_cqe();
        try testing.expectEqual(1, cqe.user_data);
        try testing.expectEqual(posix.E.SUCCESS, cqe.err());
        const listen_fd: posix.fd_t = @intCast(cqe.res);
        try testing.expect(listen_fd > 2);

        // Prepare: set socket option * 2, bind, listen
        var optval: u32 = 1;
        (try ring.setsockopt(2, listen_fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, mem.asBytes(&optval))).link_next();
        (try ring.setsockopt(3, listen_fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, mem.asBytes(&optval))).link_next();
        (try ring.bind(4, listen_fd, &addr.any, addr.getOsSockLen(), 0)).link_next();
        _ = try ring.listen(5, listen_fd, 1, 0);
        // Submit 4 operations
        try testing.expectEqual(4, try ring.submit());
        // Expect all to succeed
        for (2..6) |user_data| {
            cqe = try ring.copy_cqe();
            try testing.expectEqual(user_data, cqe.user_data);
            try testing.expectEqual(posix.E.SUCCESS, cqe.err());
        }

        // Check that socket option is set
        optval = 0;
        _ = try ring.getsockopt(5, listen_fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, mem.asBytes(&optval));
        try testing.expectEqual(1, try ring.submit());
        cqe = try ring.copy_cqe();
        try testing.expectEqual(5, cqe.user_data);
        try testing.expectEqual(posix.E.SUCCESS, cqe.err());
        try testing.expectEqual(1, optval);

        // Read system assigned port into addr
        var addr_len: posix.socklen_t = addr.getOsSockLen();
        try posix.getsockname(listen_fd, &addr.any, &addr_len);

        break :brk listen_fd;
    };

    const connect_fd = brk: {
        // Create connect socket
        _ = try ring.socket(6, addr.any.family, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, proto, 0);
        try testing.expectEqual(1, try ring.submit());
        const cqe = try ring.copy_cqe();
        try testing.expectEqual(6, cqe.user_data);
        try testing.expectEqual(posix.E.SUCCESS, cqe.err());
        // Get connect socket fd
        const connect_fd: posix.fd_t = @intCast(cqe.res);
        try testing.expect(connect_fd > 2 and connect_fd != listen_fd);
        break :brk connect_fd;
    };

    // Prepare accept/connect operations
    _ = try ring.accept(7, listen_fd, null, null, 0);
    _ = try ring.connect(8, connect_fd, &addr.any, addr.getOsSockLen());
    try testing.expectEqual(2, try ring.submit());
    // Get listener accepted socket
    var accept_fd: posix.socket_t = 0;
    for (0..2) |_| {
        const cqe = try ring.copy_cqe();
        try testing.expectEqual(posix.E.SUCCESS, cqe.err());
        if (cqe.user_data == 7) {
            accept_fd = @intCast(cqe.res);
        } else {
            try testing.expectEqual(8, cqe.user_data);
        }
    }
    try testing.expect(accept_fd > 2 and accept_fd != listen_fd and accept_fd != connect_fd);

    // Communicate
    try testSendRecv(&ring, connect_fd, accept_fd);
    try testSendRecv(&ring, accept_fd, connect_fd);

    // Shutdown and close all sockets
    for ([_]posix.socket_t{ connect_fd, accept_fd, listen_fd }) |fd| {
        (try ring.shutdown(9, fd, posix.SHUT.RDWR)).link_next();
        _ = try ring.close(10, fd);
        try testing.expectEqual(2, try ring.submit());
        for (0..2) |i| {
            const cqe = try ring.copy_cqe();
            try testing.expectEqual(posix.E.SUCCESS, cqe.err());
            try testing.expectEqual(9 + i, cqe.user_data);
        }
    }
}

fn testSendRecv(ring: *IoUring, send_fd: posix.socket_t, recv_fd: posix.socket_t) !void {
    const buffer_send = "0123456789abcdf" ** 10;
    var buffer_recv: [buffer_send.len * 2]u8 = undefined;

    // 2 sends
    _ = try ring.send(1, send_fd, buffer_send, linux.MSG.WAITALL);
    _ = try ring.send(2, send_fd, buffer_send, linux.MSG.WAITALL);
    try testing.expectEqual(2, try ring.submit());
    for (0..2) |i| {
        const cqe = try ring.copy_cqe();
        try testing.expectEqual(1 + i, cqe.user_data);
        try testing.expectEqual(posix.E.SUCCESS, cqe.err());
        try testing.expectEqual(buffer_send.len, @as(usize, @intCast(cqe.res)));
    }

    // receive
    var recv_len: usize = 0;
    while (recv_len < buffer_send.len * 2) {
        _ = try ring.recv(3, recv_fd, .{ .buffer = buffer_recv[recv_len..] }, 0);
        try testing.expectEqual(1, try ring.submit());
        const cqe = try ring.copy_cqe();
        try testing.expectEqual(3, cqe.user_data);
        try testing.expectEqual(posix.E.SUCCESS, cqe.err());
        recv_len += @intCast(cqe.res);
    }

    // inspect recv buffer
    try testing.expectEqualSlices(u8, buffer_send, buffer_recv[0..buffer_send.len]);
    try testing.expectEqualSlices(u8, buffer_send, buffer_recv[buffer_send.len..]);
}
const builtin = @import("builtin");
const std = @import("../../std.zig");
const linux = std.os.linux;
const SYS = linux.SYS;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const uid_t = linux.uid_t;
const gid_t = linux.gid_t;
const stack_t = linux.stack_t;
const sigset_t = linux.sigset_t;
const sockaddr = linux.sockaddr;
const socklen_t = linux.socklen_t;
const timespec = linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile (
        \\ syscall 0
        : [ret] "={$r4}" (-> usize),
        : [number] "{$r11}" (@intFromEnum(number)),
        : "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8", "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile (
        \\ syscall 0
        : [ret] "={$r4}" (-> usize),
        : [number] "{$r11}" (@intFromEnum(number)),
          [arg1] "{$r4}" (arg1),
        : "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8", "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile (
        \\ syscall 0
        : [ret] "={$r4}" (-> usize),
        : [number] "{$r11}" (@intFromEnum(number)),
          [arg1] "{$r4}" (arg1),
          [arg2] "{$r5}" (arg2),
        : "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8", "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile (
        \\ syscall 0
        : [ret] "={$r4}" (-> usize),
        : [number] "{$r11}" (@intFromEnum(number)),
          [arg1] "{$r4}" (arg1),
          [arg2] "{$r5}" (arg2),
          [arg3] "{$r6}" (arg3),
        : "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8", "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile (
        \\ syscall 0
        : [ret] "={$r4}" (-> usize),
        : [number] "{$r11}" (@intFromEnum(number)),
          [arg1] "{$r4}" (arg1),
          [arg2] "{$r5}" (arg2),
          [arg3] "{$r6}" (arg3),
          [arg4] "{$r7}" (arg4),
        : "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8", "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile (
        \\ syscall 0
        : [ret] "={$r4}" (-> usize),
        : [number] "{$r11}" (@intFromEnum(number)),
          [arg1] "{$r4}" (arg1),
          [arg2] "{$r5}" (arg2),
          [arg3] "{$r6}" (arg3),
          [arg4] "{$r7}" (arg4),
          [arg5] "{$r8}" (arg5),
        : "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8", "memory"
    );
}

pub fn syscall6(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) usize {
    return asm volatile (
        \\ syscall 0
        : [ret] "={$r4}" (-> usize),
        : [number] "{$r11}" (@intFromEnum(number)),
          [arg1] "{$r4}" (arg1),
          [arg2] "{$r5}" (arg2),
          [arg3] "{$r6}" (arg3),
          [arg4] "{$r7}" (arg4),
          [arg5] "{$r8}" (arg5),
          [arg6] "{$r9}" (arg6),
        : "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8", "memory"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //           a0,    a1,    a2,  a3,   a4,  a5,   a6
    // sys_clone(flags, stack, ptid, ctid, tls)
    //              a0,    a1,   a2,   a3,  a4
    asm volatile (
        \\ bstrins.d $a1, $zero, 3, 0   # stack to 16 align
        \\
        \\ # Save function pointer and argument pointer on new thread stack
        \\ addi.d  $a1, $a1, -16
        \\ st.d    $a0, $a1, 0     # save function pointer
        \\ st.d    $a3, $a1, 8     # save argument pointer
        \\ or      $a0, $a2, $zero
        \\ or      $a2, $a4, $zero
        \\ or      $a3, $a6, $zero
        \\ or      $a4, $a5, $zero
        \\ ori     $a7, $zero, 220 # SYS_clone
        \\ syscall 0               # call clone
        \\
        \\ beqz    $a0, 1f         # whether child process
        \\ jirl    $zero, $ra, 0   # parent process return
        \\1:
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\ .cfi_undefined 1
    );
    asm volatile (
        \\ move    $fp, $zero
        \\ move    $ra, $zero
        \\
        \\ ld.d    $t8, $sp, 0     # function pointer
        \\ ld.d    $a0, $sp, 8     # argument pointer
        \\ jirl    $ra, $t8, 0     # call the user's function
        \\ ori     $a7, $zero, 93  # SYS_exit
        \\ syscall 0               # child process exit
    );
}

pub const restore = restore_rt;

pub fn restore_rt() callconv(.naked) noreturn {
    asm volatile (
        \\ or $a7, $zero, %[number]
        \\ syscall 0
        :
        : [number] "r" (@intFromEnum(SYS.rt_sigreturn)),
        : "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8", "memory"
    );
}

pub const msghdr = extern struct {
    name: ?*sockaddr,
    namelen: socklen_t,
    iov: [*]iovec,
    iovlen: i32,
    __pad1: i32 = 0,
    control: ?*anyopaque,
    controllen: socklen_t,
    __pad2: socklen_t = 0,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    iovlen: i32,
    __pad1: i32 = 0,
    control: ?*const anyopaque,
    controllen: socklen_t,
    __pad2: socklen_t = 0,
    flags: i32,
};

pub const blksize_t = i32;
pub const nlink_t = u32;
pub const time_t = i64;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u32;
pub const blkcnt_t = i64;

// The `stat` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    ino: ino_t,
    mode: mode_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    _pad1: u64,
    size: off_t,
    blksize: blksize_t,
    _pad2: i32,
    blocks: blkcnt_t,
    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    _pad3: [2]u32,

    pub fn atime(self: @This()) timespec {
        return self.atim;
    }

    pub fn mtime(self: @This()) timespec {
        return self.mtim;
    }

    pub fn ctime(self: @This()) timespec {
        return self.ctim;
    }
};

pub const timeval = extern struct {
    tv_sec: time_t,
    tv_usec: i64,
};

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;
    pub const GETLK = 5;
    pub const SETLK = 6;
    pub const SETLKW = 7;
    pub const SETOWN = 8;
    pub const GETOWN = 9;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const VDSO = struct {
    pub const CGT_SYM = "__vdso_clock_gettime";
    pub const CGT_VER = "LINUX_5.10";
};

pub const mcontext_t = extern struct {
    pc: u64,
    regs: [32]u64,
    flags: u32,
    extcontext: [0]u64 align(16),
};

pub const ucontext_t = extern struct {
    flags: c_ulong,
    link: ?*ucontext_t,
    stack: stack_t,
    sigmask: sigset_t,
    _pad: [1024 / 8 - @sizeOf(sigset_t)]u8,
    mcontext: mcontext_t,
};

pub const Elf_Symndx = u32;

/// TODO
pub const getcontext = {};
const builtin = @import("builtin");
const std = @import("../../std.zig");
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const linux = std.os.linux;
const SYS = linux.SYS;
const uid_t = std.os.linux.uid_t;
const gid_t = std.os.linux.uid_t;
const pid_t = std.os.linux.pid_t;
const sockaddr = linux.sockaddr;
const socklen_t = linux.socklen_t;
const timespec = std.os.linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile ("trap #0"
        : [ret] "={d0}" (-> usize),
        : [number] "{d0}" (@intFromEnum(number)),
        : "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile ("trap #0"
        : [ret] "={d0}" (-> usize),
        : [number] "{d0}" (@intFromEnum(number)),
          [arg1] "{d1}" (arg1),
        : "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile ("trap #0"
        : [ret] "={d0}" (-> usize),
        : [number] "{d0}" (@intFromEnum(number)),
          [arg1] "{d1}" (arg1),
          [arg2] "{d2}" (arg2),
        : "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile ("trap #0"
        : [ret] "={d0}" (-> usize),
        : [number] "{d0}" (@intFromEnum(number)),
          [arg1] "{d1}" (arg1),
          [arg2] "{d2}" (arg2),
          [arg3] "{d3}" (arg3),
        : "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile ("trap #0"
        : [ret] "={d0}" (-> usize),
        : [number] "{d0}" (@intFromEnum(number)),
          [arg1] "{d1}" (arg1),
          [arg2] "{d2}" (arg2),
          [arg3] "{d3}" (arg3),
          [arg4] "{d4}" (arg4),
        : "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile ("trap #0"
        : [ret] "={d0}" (-> usize),
        : [number] "{d0}" (@intFromEnum(number)),
          [arg1] "{d1}" (arg1),
          [arg2] "{d2}" (arg2),
          [arg3] "{d3}" (arg3),
          [arg4] "{d4}" (arg4),
          [arg5] "{d5}" (arg5),
        : "memory"
    );
}

pub fn syscall6(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) usize {
    return asm volatile ("trap #0"
        : [ret] "={d0}" (-> usize),
        : [number] "{d0}" (@intFromEnum(number)),
          [arg1] "{d1}" (arg1),
          [arg2] "{d2}" (arg2),
          [arg3] "{d3}" (arg3),
          [arg4] "{d4}" (arg4),
          [arg5] "{d5}" (arg5),
          [arg6] "{a0}" (arg6),
        : "memory"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //         +4,   +8,    +12,   +16, +20,  +24, +28
    //
    // syscall(SYS_clone, flags, stack, ptid, ctid, tls)
    //         d0,        d1,    d2,    d3,   d4,   d5
    asm volatile (
        \\ // Save callee-saved registers.
        \\ movem.l %%d2-%%d5, -(%%sp) // sp -= 16
        \\
        \\ // Save func and arg.
        \\ move.l 16+4(%%sp), %%a0
        \\ move.l 16+16(%%sp), %%a1
        \\
        \\ // d0 = syscall(d0, d1, d2, d3, d4, d5)
        \\ move.l #120, %%d0 // SYS_clone
        \\ move.l 16+12(%%sp), %%d1
        \\ move.l 16+8(%%sp), %%d2
        \\ move.l 16+20(%%sp), %%d3
        \\ move.l 16+28(%%sp), %%d4
        \\ move.l 16+24(%%sp), %%d5
        \\ and.l #-4, %%d2 // Align the child stack pointer.
        \\ trap #0
        \\
        \\ // Are we in the parent or child?
        \\ tst.l %%d0
        \\ beq 1f
        \\ // Parent:
        \\
        \\ // Restore callee-saved registers and return.
        \\ movem.l (%%sp)+, %%d2-%%d5 // sp += 16
        \\ rts
        \\
        \\ // Child:
        \\1:
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\ .cfi_undefined %%pc
    );
    asm volatile (
        \\ suba.l %%fp, %%fp
        \\
        \\ // d0 = func(a1)
        \\ move.l %%a1, -(%%sp)
        \\ jsr (%%a0)
        \\
        \\ // syscall(d0, d1)
        \\ move.l %%d0, %%d1
        \\ move.l #1, %%d0 // SYS_exit
        \\ trap #0
    );
}

pub const restore = restore_rt;

pub fn restore_rt() callconv(.naked) noreturn {
    asm volatile ("trap #0"
        :
        : [number] "{d0}" (@intFromEnum(SYS.rt_sigreturn)),
        : "memory"
    );
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;

    pub const SETOWN = 8;
    pub const GETOWN = 9;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const GETLK = 12;
    pub const SETLK = 13;
    pub const SETLKW = 14;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;
};

pub const blksize_t = i32;
pub const nlink_t = u32;
pub const time_t = i32;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u64;
pub const blkcnt_t = i64;

pub const timeval = extern struct {
    sec: time_t,
    usec: i32,
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    start: off_t,
    len: off_t,
    pid: pid_t,
};

// TODO: not 100% sure of padding for msghdr
pub const msghdr = extern struct {
    name: ?*sockaddr,
    namelen: socklen_t,
    iov: [*]iovec,
    iovlen: i32,
    control: ?*anyopaque,
    controllen: socklen_t,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    iovlen: i32,
    control: ?*const anyopaque,
    controllen: socklen_t,
    flags: i32,
};

pub const Stat = extern struct {
    dev: dev_t,
    __pad: i16,
    __ino_truncated: i32,
    mode: mode_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    __pad2: i16,
    size: off_t,
    blksize: blksize_t,
    blocks: blkcnt_t,
    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    ino: ino_t,

    pub fn atime(self: @This()) timespec {
        return self.atim;
    }

    pub fn mtime(self: @This()) timespec {
        return self.mtim;
    }

    pub fn ctime(self: @This()) timespec {
        return self.ctim;
    }
};

pub const Elf_Symndx = u32;

// No VDSO used as of glibc 112a0ae18b831bf31f44d81b82666980312511d6.
pub const VDSO = void;

/// TODO
pub const ucontext_t = void;

/// TODO
pub const getcontext = {};
const builtin = @import("builtin");
const std = @import("../../std.zig");
const maxInt = std.math.maxInt;
const linux = std.os.linux;
const SYS = linux.SYS;
const socklen_t = linux.socklen_t;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const uid_t = linux.uid_t;
const gid_t = linux.gid_t;
const pid_t = linux.pid_t;
const sockaddr = linux.sockaddr;
const timespec = linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ subu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
        : "$1", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall_pipe(fd: *[2]i32) usize {
    return asm volatile (
        \\ .set noat
        \\ .set noreorder
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ nop
        \\ b 2f
        \\ subu $2, $0, $2
        \\ 1:
        \\ sw $2, 0($4)
        \\ sw $3, 4($4)
        \\ 2:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(SYS.pipe)),
          [fd] "{$4}" (fd),
        : "$1", "$3", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ subu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
        : "$1", "$3", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ subu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
        : "$1", "$3", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ subu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
          [arg3] "{$6}" (arg3),
        : "$1", "$3", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ subu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
          [arg3] "{$6}" (arg3),
          [arg4] "{$7}" (arg4),
        : "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile (
        \\ .set noat
        \\ subu $sp, $sp, 24
        \\ sw %[arg5], 16($sp)
        \\ syscall
        \\ addu $sp, $sp, 24
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ subu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
          [arg3] "{$6}" (arg3),
          [arg4] "{$7}" (arg4),
          [arg5] "r" (arg5),
        : "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

// NOTE: The o32 calling convention requires the callee to reserve 16 bytes for
// the first four arguments even though they're passed in $a0-$a3.

pub fn syscall6(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) usize {
    return asm volatile (
        \\ .set noat
        \\ subu $sp, $sp, 24
        \\ sw %[arg5], 16($sp)
        \\ sw %[arg6], 20($sp)
        \\ syscall
        \\ addu $sp, $sp, 24
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ subu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
          [arg3] "{$6}" (arg3),
          [arg4] "{$7}" (arg4),
          [arg5] "r" (arg5),
          [arg6] "r" (arg6),
        : "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall7(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
    arg7: usize,
) usize {
    return asm volatile (
        \\ .set noat
        \\ subu $sp, $sp, 32
        \\ sw %[arg5], 16($sp)
        \\ sw %[arg6], 20($sp)
        \\ sw %[arg7], 24($sp)
        \\ syscall
        \\ addu $sp, $sp, 32
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ subu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
          [arg3] "{$6}" (arg3),
          [arg4] "{$7}" (arg4),
          [arg5] "r" (arg5),
          [arg6] "r" (arg6),
          [arg7] "r" (arg7),
        : "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //         3,    4,     5,     6,   7,    8,   9
    //
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
    //         2          4,     5,     6,    7,   8
    asm volatile (
        \\  # Save function pointer and argument pointer on new thread stack
        \\  and $5, $5, -8
        \\  subu $5, $5, 16
        \\  sw $4, 0($5)
        \\  sw $7, 4($5)
        \\  # Shuffle (fn,sp,fl,arg,ptid,tls,ctid) to (fl,sp,ptid,tls,ctid)
        \\  move $4, $6
        \\  lw $6, 16($sp)
        \\  lw $7, 20($sp)
        \\  lw $9, 24($sp)
        \\  subu $sp, $sp, 16
        \\  sw $9, 16($sp)
        \\  li $2, 4120 # SYS_clone
        \\  syscall
        \\  beq $7, $0, 1f
        \\  nop
        \\  addu $sp, $sp, 16
        \\  jr $ra
        \\  subu $2, $0, $2
        \\1:
        \\  beq $2, $0, 1f
        \\  nop
        \\  addu $sp, $sp, 16
        \\  jr $ra
        \\  nop
        \\1:
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\  .cfi_undefined $ra
    );
    asm volatile (
        \\  move $fp, $zero
        \\  move $ra, $zero
        \\
        \\  lw $25, 0($sp)
        \\  lw $4, 4($sp)
        \\  jalr $25
        \\  nop
        \\  move $4, $2
        \\  li $2, 4001 # SYS_exit
        \\  syscall
    );
}

pub fn restore() callconv(.naked) noreturn {
    asm volatile (
        \\ syscall
        :
        : [number] "{$2}" (@intFromEnum(SYS.sigreturn)),
        : "$1", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn restore_rt() callconv(.naked) noreturn {
    asm volatile (
        \\ syscall
        :
        : [number] "{$2}" (@intFromEnum(SYS.rt_sigreturn)),
        : "$1", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;

    pub const SETOWN = 24;
    pub const GETOWN = 23;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const GETLK = 33;
    pub const SETLK = 34;
    pub const SETLKW = 35;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const VDSO = struct {
    pub const CGT_SYM = "__vdso_clock_gettime";
    pub const CGT_VER = "LINUX_2.6";
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    __pad0: [4]u8,
    start: off_t,
    len: off_t,
    pid: pid_t,
    __unused: [4]u8,
};

pub const msghdr = extern struct {
    name: ?*sockaddr,
    namelen: socklen_t,
    iov: [*]iovec,
    iovlen: i32,
    control: ?*anyopaque,
    controllen: socklen_t,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    iovlen: i32,
    control: ?*const anyopaque,
    controllen: socklen_t,
    flags: i32,
};

pub const blksize_t = u32;
pub const nlink_t = u32;
pub const time_t = i32;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u64;
pub const blkcnt_t = i64;

// The `stat64` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    __pad0: [2]u32, // -1 because our dev_t is u64 (kernel dev_t is really u32).
    ino: ino_t,
    mode: mode_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    __pad1: [2]u32, // -1 because our dev_t is u64 (kernel dev_t is really u32).
    size: off_t,
    atim: i32,
    atim_nsec: u32,
    mtim: i32,
    mtim_nsec: u32,
    ctim: i32,
    ctim_nsec: u32,
    blksize: blksize_t,
    __pad3: u32,
    blocks: blkcnt_t,

    pub fn atime(self: @This()) timespec {
        return .{
            .sec = self.atim,
            .nsec = self.atim_nsec,
        };
    }

    pub fn mtime(self: @This()) timespec {
        return .{
            .sec = self.mtim,
            .nsec = self.mtim_nsec,
        };
    }

    pub fn ctime(self: @This()) timespec {
        return .{
            .sec = self.ctim,
            .nsec = self.ctim_nsec,
        };
    }
};

pub const timeval = extern struct {
    sec: isize,
    usec: isize,
};

pub const timezone = extern struct {
    minuteswest: i32,
    dsttime: i32,
};

pub const Elf_Symndx = u32;

/// TODO
pub const ucontext_t = void;

/// TODO
pub const getcontext = {};
const builtin = @import("builtin");
const std = @import("../../std.zig");
const maxInt = std.math.maxInt;
const linux = std.os.linux;
const SYS = linux.SYS;
const socklen_t = linux.socklen_t;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const uid_t = linux.uid_t;
const gid_t = linux.gid_t;
const pid_t = linux.pid_t;
const sockaddr = linux.sockaddr;
const timespec = linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ dsubu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
        : "$1", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall_pipe(fd: *[2]i32) usize {
    return asm volatile (
        \\ .set noat
        \\ .set noreorder
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ nop
        \\ b 2f
        \\ subu $2, $0, $2
        \\ 1:
        \\ sw $2, 0($4)
        \\ sw $3, 4($4)
        \\ 2:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(SYS.pipe)),
          [fd] "{$4}" (fd),
        : "$1", "$3", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ nop
        \\ dsubu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
        : "$1", "$3", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ dsubu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
        : "$1", "$3", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ dsubu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
          [arg3] "{$6}" (arg3),
        : "$1", "$3", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ dsubu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
          [arg3] "{$6}" (arg3),
          [arg4] "{$7}" (arg4),
        : "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ dsubu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
          [arg3] "{$6}" (arg3),
          [arg4] "{$7}" (arg4),
          [arg5] "{$8}" (arg5),
        : "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall6(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ dsubu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
          [arg3] "{$6}" (arg3),
          [arg4] "{$7}" (arg4),
          [arg5] "{$8}" (arg5),
          [arg6] "{$9}" (arg6),
        : "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn syscall7(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
    arg7: usize,
) usize {
    return asm volatile (
        \\ syscall
        \\ beq $7, $zero, 1f
        \\ blez $2, 1f
        \\ dsubu $2, $0, $2
        \\ 1:
        : [ret] "={$2}" (-> usize),
        : [number] "{$2}" (@intFromEnum(number)),
          [arg1] "{$4}" (arg1),
          [arg2] "{$5}" (arg2),
          [arg3] "{$6}" (arg3),
          [arg4] "{$7}" (arg4),
          [arg5] "{$8}" (arg5),
          [arg6] "{$9}" (arg6),
          [arg7] "{$10}" (arg7),
        : "$1", "$3", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //         3,    4,     5,     6,   7,    8,   9
    //
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
    //         2          4,     5,     6,    7,   8
    asm volatile (
        \\ # Save function pointer and argument pointer on new thread stack
        \\ and $5, $5, -16
        \\ dsubu $5, $5, 16
        \\ sd $4, 0($5)
        \\ sd $7, 8($5)
        \\ # Shuffle (fn,sp,fl,arg,ptid,tls,ctid) to (fl,sp,ptid,tls,ctid)
        \\ move $4, $6
        \\ move $6, $8
        \\ move $7, $9
        \\ move $8, $10
        \\ li $2, 5055 # SYS_clone
        \\ syscall
        \\ beq $7, $0, 1f
        \\ nop
        \\ jr $ra
        \\ dsubu $2, $0, $2
        \\1:
        \\ beq $2, $0, 1f
        \\ nop
        \\ jr $ra
        \\ nop
        \\1:
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\ .cfi_undefined $ra
    );
    asm volatile (
        \\ move $fp, $zero
        \\ move $ra, $zero
        \\
        \\ ld $25, 0($sp)
        \\ ld $4, 8($sp)
        \\ jalr $25
        \\ nop
        \\ move $4, $2
        \\ li $2, 5058 # SYS_exit
        \\ syscall
    );
}

pub fn restore() callconv(.naked) noreturn {
    asm volatile (
        \\ syscall
        :
        : [number] "{$2}" (@intFromEnum(SYS.rt_sigreturn)),
        : "$1", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub fn restore_rt() callconv(.naked) noreturn {
    asm volatile (
        \\ syscall
        :
        : [number] "{$2}" (@intFromEnum(SYS.rt_sigreturn)),
        : "$1", "$3", "$4", "$5", "$6", "$7", "$8", "$9", "$10", "$11", "$12", "$13", "$14", "$15", "$24", "$25", "hi", "lo", "memory"
    );
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;

    pub const SETOWN = 24;
    pub const GETOWN = 23;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const GETLK = 33;
    pub const SETLK = 34;
    pub const SETLKW = 35;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const VDSO = struct {
    pub const CGT_SYM = "__vdso_clock_gettime";
    pub const CGT_VER = "LINUX_2.6";
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    __pad0: [4]u8,
    start: off_t,
    len: off_t,
    pid: pid_t,
    __unused: [4]u8,
};

pub const msghdr = extern struct {
    name: ?*sockaddr,
    namelen: socklen_t,
    iov: [*]iovec,
    iovlen: i32,
    control: ?*anyopaque,
    controllen: socklen_t,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    iovlen: i32,
    control: ?*const anyopaque,
    controllen: socklen_t,
    flags: i32,
};

pub const blksize_t = u32;
pub const nlink_t = u32;
pub const time_t = i32;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u64;
pub const blkcnt_t = i64;

// The `stat` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    __pad0: [2]u32, // -1 because our dev_t is u64 (kernel dev_t is really u32).
    ino: ino_t,
    mode: mode_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    __pad1: [2]u32, // -1 because our dev_t is u64 (kernel dev_t is really u32).
    size: off_t,
    atim: u32,
    atim_nsec: u32,
    mtim: u32,
    mtim_nsec: u32,
    ctim: u32,
    ctim_nsec: u32,
    blksize: blksize_t,
    __pad3: u32,
    blocks: blkcnt_t,

    pub fn atime(self: @This()) timespec {
        return .{
            .sec = self.atim,
            .nsec = self.atim_nsec,
        };
    }

    pub fn mtime(self: @This()) timespec {
        return .{
            .sec = self.mtim,
            .nsec = self.mtim_nsec,
        };
    }

    pub fn ctime(self: @This()) timespec {
        return .{
            .sec = self.ctim,
            .nsec = self.ctim_nsec,
        };
    }
};

pub const timeval = extern struct {
    sec: isize,
    usec: isize,
};

pub const timezone = extern struct {
    minuteswest: i32,
    dsttime: i32,
};

pub const Elf_Symndx = u32;

/// TODO
pub const ucontext_t = void;

/// TODO
pub const getcontext = {};
const std = @import("std");
const builtin = @import("builtin");
const elf = std.elf;
const assert = std.debug.assert;

const R_AMD64_RELATIVE = 8;
const R_386_RELATIVE = 8;
const R_ARC_RELATIVE = 56;
const R_ARM_RELATIVE = 23;
const R_AARCH64_RELATIVE = 1027;
const R_CSKY_RELATIVE = 9;
const R_HEXAGON_RELATIVE = 35;
const R_LARCH_RELATIVE = 3;
const R_68K_RELATIVE = 22;
const R_MIPS_RELATIVE = 128;
const R_PPC_RELATIVE = 22;
const R_RISCV_RELATIVE = 3;
const R_390_RELATIVE = 12;
const R_SPARC_RELATIVE = 22;

const R_RELATIVE = switch (builtin.cpu.arch) {
    .x86 => R_386_RELATIVE,
    .x86_64 => R_AMD64_RELATIVE,
    .arc => R_ARC_RELATIVE,
    .arm, .armeb, .thumb, .thumbeb => R_ARM_RELATIVE,
    .aarch64, .aarch64_be => R_AARCH64_RELATIVE,
    .csky => R_CSKY_RELATIVE,
    .hexagon => R_HEXAGON_RELATIVE,
    .loongarch32, .loongarch64 => R_LARCH_RELATIVE,
    .m68k => R_68K_RELATIVE,
    .mips, .mipsel, .mips64, .mips64el => R_MIPS_RELATIVE,
    .powerpc, .powerpcle, .powerpc64, .powerpc64le => R_PPC_RELATIVE,
    .riscv32, .riscv64 => R_RISCV_RELATIVE,
    .s390x => R_390_RELATIVE,
    .sparc, .sparc64 => R_SPARC_RELATIVE,
    else => @compileError("Missing R_RELATIVE definition for this target"),
};

// Obtain a pointer to the _DYNAMIC array.
// We have to compute its address as a PC-relative quantity not to require a
// relocation that, at this point, is not yet applied.
inline fn getDynamicSymbol() [*]elf.Dyn {
    return switch (builtin.cpu.arch) {
        .x86 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ call 1f
            \\ 1: pop %[ret]
            \\ lea _DYNAMIC-1b(%[ret]), %[ret]
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        .x86_64 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ lea _DYNAMIC(%%rip), %[ret]
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        .arc => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ add %[ret], pcl, _DYNAMIC@pcl
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        // Work around the limited offset range of `ldr`
        .arm, .armeb, .thumb, .thumbeb => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ ldr %[ret], 1f
            \\ add %[ret], pc
            \\ b 2f
            \\ 1: .word _DYNAMIC-1b
            \\ 2:
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        // A simple `adr` is not enough as it has a limited offset range
        .aarch64, .aarch64_be => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ adrp %[ret], _DYNAMIC
            \\ add %[ret], %[ret], #:lo12:_DYNAMIC
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        // The CSKY ABI requires the gb register to point to the GOT. Additionally, the first
        // entry in the GOT is defined to hold the address of _DYNAMIC.
        .csky => asm volatile (
            \\ mov %[ret], gb
            \\ ldw %[ret], %[ret]
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        .hexagon => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ jump 1f
            \\ .word _DYNAMIC - .
            \\ 1:
            \\ r1 = pc
            \\ r1 = add(r1, #-4)
            \\ %[ret] = memw(r1)
            \\ %[ret] = add(r1, %[ret])
            : [ret] "=r" (-> [*]elf.Dyn),
            :
            : "r1"
        ),
        .loongarch32, .loongarch64 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ la.local %[ret], _DYNAMIC
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        // Note that the - 8 is needed because pc in the second lea instruction points into the
        // middle of that instruction. (The first lea is 6 bytes, the second is 4 bytes.)
        .m68k => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ lea _DYNAMIC - . - 8, %[ret]
            \\ lea (%[ret], %%pc), %[ret]
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        .mips, .mipsel => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ bal 1f
            \\ .gpword _DYNAMIC
            \\ 1:
            \\ lw %[ret], 0($ra)
            \\ addu %[ret], %[ret], $gp
            : [ret] "=r" (-> [*]elf.Dyn),
            :
            : "lr"
        ),
        .mips64, .mips64el => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ .balign 8
            \\ bal 1f
            \\ .gpdword _DYNAMIC
            \\ 1:
            \\ ld %[ret], 0($ra)
            \\ daddu %[ret], %[ret], $gp
            : [ret] "=r" (-> [*]elf.Dyn),
            :
            : "lr"
        ),
        .powerpc, .powerpcle => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ bl 1f
            \\ .long _DYNAMIC - .
            \\ 1:
            \\ mflr %[ret]
            \\ lwz 4, 0(%[ret])
            \\ add %[ret], 4, %[ret]
            : [ret] "=r" (-> [*]elf.Dyn),
            :
            : "lr", "r4"
        ),
        .powerpc64, .powerpc64le => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ bl 1f
            \\ .quad _DYNAMIC - .
            \\ 1:
            \\ mflr %[ret]
            \\ ld 4, 0(%[ret])
            \\ add %[ret], 4, %[ret]
            : [ret] "=r" (-> [*]elf.Dyn),
            :
            : "lr", "r4"
        ),
        .riscv32, .riscv64 => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ lla %[ret], _DYNAMIC
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        .s390x => asm volatile (
            \\ .weak _DYNAMIC
            \\ .hidden _DYNAMIC
            \\ larl %[ret], 1f
            \\ ag %[ret], 0(%[ret])
            \\ jg 2f
            \\ 1: .quad _DYNAMIC - .
            \\ 2:
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        // The compiler does not necessarily have any obligation to load the `l7` register (pointing
        // to the GOT), so do it ourselves just in case.
        .sparc, .sparc64 => asm volatile (
            \\ sethi %%hi(_GLOBAL_OFFSET_TABLE_ - 4), %%l7
            \\ call 1f
            \\ add %%l7, %%lo(_GLOBAL_OFFSET_TABLE_ + 4), %%l7
            \\ 1:
            \\ add %%l7, %%o7, %[ret]
            : [ret] "=r" (-> [*]elf.Dyn),
        ),
        else => {
            @compileError("PIE startup is not yet supported for this target!");
        },
    };
}

pub fn relocate(phdrs: []elf.Phdr) void {
    @setRuntimeSafety(false);
    @disableInstrumentation();

    const dynv = getDynamicSymbol();

    // Recover the delta applied by the loader by comparing the effective and
    // the theoretical load addresses for the `_DYNAMIC` symbol.
    const base_addr = base: {
        for (phdrs) |*phdr| {
            if (phdr.p_type != elf.PT_DYNAMIC) continue;
            break :base @intFromPtr(dynv) - phdr.p_vaddr;
        }
        // This is not supposed to happen for well-formed binaries.
        @trap();
    };

    var sorted_dynv: [elf.DT_NUM]elf.Addr = undefined;

    // Zero-initialized this way to prevent the compiler from turning this into
    // `memcpy` or `memset` calls (which can require relocations).
    for (&sorted_dynv) |*dyn| {
        const pdyn: *volatile elf.Addr = @ptrCast(dyn);
        pdyn.* = 0;
    }

    {
        // `dynv` has no defined order. Fix that.
        var i: usize = 0;
        while (dynv[i].d_tag != elf.DT_NULL) : (i += 1) {
            if (dynv[i].d_tag < elf.DT_NUM) sorted_dynv[@bitCast(dynv[i].d_tag)] = dynv[i].d_val;
        }
    }

    // Deal with the GOT relocations that MIPS uses first.
    if (builtin.cpu.arch.isMIPS()) {
        const count: elf.Addr = blk: {
            // This is an architecture-specific tag, so not part of `sorted_dynv`.
            var i: usize = 0;
            while (dynv[i].d_tag != elf.DT_NULL) : (i += 1) {
                if (dynv[i].d_tag == elf.DT_MIPS_LOCAL_GOTNO) break :blk dynv[i].d_val;
            }

            break :blk 0;
        };

        const got: [*]usize = @ptrFromInt(base_addr + sorted_dynv[elf.DT_PLTGOT]);

        for (0..count) |i| {
            got[i] += base_addr;
        }
    }

    // Apply normal relocations.

    const rel = sorted_dynv[elf.DT_REL];
    if (rel != 0) {
        const rels = @call(.always_inline, std.mem.bytesAsSlice, .{
            elf.Rel,
            @as([*]u8, @ptrFromInt(base_addr + rel))[0..sorted_dynv[elf.DT_RELSZ]],
        });
        for (rels) |r| {
            if (r.r_type() != R_RELATIVE) continue;
            @as(*usize, @ptrFromInt(base_addr + r.r_offset)).* += base_addr;
        }
    }

    const rela = sorted_dynv[elf.DT_RELA];
    if (rela != 0) {
        const relas = @call(.always_inline, std.mem.bytesAsSlice, .{
            elf.Rela,
            @as([*]u8, @ptrFromInt(base_addr + rela))[0..sorted_dynv[elf.DT_RELASZ]],
        });
        for (relas) |r| {
            if (r.r_type() != R_RELATIVE) continue;
            @as(*usize, @ptrFromInt(base_addr + r.r_offset)).* = base_addr + @as(usize, @bitCast(r.r_addend));
        }
    }

    const relr = sorted_dynv[elf.DT_RELR];
    if (relr != 0) {
        const relrs = @call(.always_inline, std.mem.bytesAsSlice, .{
            elf.Relr,
            @as([*]u8, @ptrFromInt(base_addr + relr))[0..sorted_dynv[elf.DT_RELRSZ]],
        });
        var current: [*]usize = undefined;
        for (relrs) |r| {
            if ((r & 1) == 0) {
                current = @ptrFromInt(base_addr + r);
                current[0] += base_addr;
                current += 1;
            } else {
                // Skip the first bit; there are 63 locations in the bitmap.
                var i: if (@sizeOf(usize) == 8) u6 else u5 = 1;
                while (i < @bitSizeOf(elf.Relr)) : (i += 1) {
                    if (((r >> i) & 1) != 0) current[i] += base_addr;
                }

                current += @bitSizeOf(elf.Relr) - 1;
            }
        }
    }
}
const builtin = @import("builtin");
const std = @import("../../std.zig");
const maxInt = std.math.maxInt;
const linux = std.os.linux;
const SYS = linux.SYS;
const socklen_t = linux.socklen_t;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const uid_t = linux.uid_t;
const gid_t = linux.gid_t;
const pid_t = linux.pid_t;
const stack_t = linux.stack_t;
const sigset_t = linux.sigset_t;
const sockaddr = linux.sockaddr;
const timespec = linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
        : "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
        : "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
          [arg2] "{r4}" (arg2),
        : "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
          [arg2] "{r4}" (arg2),
          [arg3] "{r5}" (arg3),
        : "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
          [arg2] "{r4}" (arg2),
          [arg3] "{r5}" (arg3),
          [arg4] "{r6}" (arg4),
        : "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
          [arg2] "{r4}" (arg2),
          [arg3] "{r5}" (arg3),
          [arg4] "{r6}" (arg4),
          [arg5] "{r7}" (arg5),
        : "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall6(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
          [arg2] "{r4}" (arg2),
          [arg3] "{r5}" (arg3),
          [arg4] "{r6}" (arg4),
          [arg5] "{r7}" (arg5),
          [arg6] "{r8}" (arg6),
        : "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //         3,    4,     5,     6,   7,    8,   9
    //
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
    //         0          3,     4,     5,    6,   7
    asm volatile (
        \\ # store non-volatile regs r29, r30 on stack in order to put our
        \\ # start func and its arg there
        \\ stwu 29, -16(1)
        \\ stw 30, 4(1)
        \\
        \\ # save r3 (func) into r29, and r6(arg) into r30
        \\ mr 29, 3
        \\ mr 30, 6
        \\
        \\ # create initial stack frame for new thread
        \\ clrrwi 4, 4, 4
        \\ li 0, 0
        \\ stwu 0, -16(4)
        \\
        \\ #move c into first arg
        \\ mr 3, 5
        \\ #mr 4, 4
        \\ mr 5, 7
        \\ mr 6, 8
        \\ mr 7, 9
        \\
        \\ # move syscall number into r0
        \\ li 0, 120 # SYS_clone
        \\
        \\ sc
        \\
        \\ # check for syscall error
        \\ bns+ 1f # jump to label 1 if no summary overflow.
        \\ #else
        \\ neg 3, 3 #negate the result (errno)
        \\ 1:
        \\ # compare sc result with 0
        \\ cmpwi cr7, 3, 0
        \\
        \\ # if not 0, restore stack and return
        \\ beq cr7, 2f
        \\ lwz 29, 0(1)
        \\ lwz 30, 4(1)
        \\ addi 1, 1, 16
        \\ blr
        \\
        \\ #else: we're the child
        \\ 2:
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\ .cfi_undefined lr
    );
    asm volatile (
        \\ li 31, 0
        \\ mtlr 0
        \\
        \\ #call funcptr: move arg (d) into r3
        \\ mr 3, 30
        \\ #move r29 (funcptr) into CTR reg
        \\ mtctr 29
        \\ # call CTR reg
        \\ bctrl
        \\ # mov SYS_exit into r0 (the exit param is already in r3)
        \\ li 0, 1
        \\ sc
    );
}

pub const restore = restore_rt;

pub fn restore_rt() callconv(.naked) noreturn {
    asm volatile (
        \\ sc
        :
        : [number] "{r0}" (@intFromEnum(SYS.rt_sigreturn)),
        : "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;

    pub const SETOWN = 8;
    pub const GETOWN = 9;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const GETLK = 12;
    pub const SETLK = 13;
    pub const SETLKW = 14;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;
};

pub const VDSO = struct {
    pub const CGT_SYM = "__kernel_clock_gettime";
    pub const CGT_VER = "LINUX_2.6.15";
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    start: off_t,
    len: off_t,
    pid: pid_t,
};

pub const msghdr = extern struct {
    name: ?*sockaddr,
    namelen: socklen_t,
    iov: [*]iovec,
    iovlen: usize,
    control: ?*anyopaque,
    controllen: socklen_t,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    iovlen: usize,
    control: ?*const anyopaque,
    controllen: socklen_t,
    flags: i32,
};

pub const blksize_t = i32;
pub const nlink_t = u32;
pub const time_t = isize;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u64;
pub const blkcnt_t = i64;

// The `stat` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    ino: ino_t,
    mode: mode_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    __rdev_padding: i16,
    size: off_t,
    blksize: blksize_t,
    blocks: blkcnt_t,
    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    __unused: [2]u32,

    pub fn atime(self: @This()) timespec {
        return self.atim;
    }

    pub fn mtime(self: @This()) timespec {
        return self.mtim;
    }

    pub fn ctime(self: @This()) timespec {
        return self.ctim;
    }
};

pub const timeval = extern struct {
    sec: time_t,
    usec: isize,
};

pub const timezone = extern struct {
    minuteswest: i32,
    dsttime: i32,
};

pub const greg_t = u32;
pub const gregset_t = [48]greg_t;
pub const fpregset_t = [33]f64;

pub const vrregset = extern struct {
    vrregs: [32][4]u32,
    vrsave: u32,
    _pad: [2]u32,
    vscr: u32,
};
pub const vrregset_t = vrregset;

pub const mcontext_t = extern struct {
    gp_regs: gregset_t,
    fp_regs: fpregset_t,
    v_regs: vrregset_t align(16),
};

pub const ucontext_t = extern struct {
    flags: u32,
    link: ?*ucontext_t,
    stack: stack_t,
    pad: [7]i32,
    regs: *mcontext_t,
    sigmask: sigset_t,
    pad2: [3]i32,
    mcontext: mcontext_t,
};

pub const Elf_Symndx = u32;

/// TODO
pub const getcontext = {};
const builtin = @import("builtin");
const std = @import("../../std.zig");
const maxInt = std.math.maxInt;
const linux = std.os.linux;
const SYS = linux.SYS;
const socklen_t = linux.socklen_t;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const uid_t = linux.uid_t;
const gid_t = linux.gid_t;
const pid_t = linux.pid_t;
const stack_t = linux.stack_t;
const sigset_t = linux.sigset_t;
const sockaddr = linux.sockaddr;
const timespec = linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
        : "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
        : "memory", "cr0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
          [arg2] "{r4}" (arg2),
        : "memory", "cr0", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
          [arg2] "{r4}" (arg2),
          [arg3] "{r5}" (arg3),
        : "memory", "cr0", "r6", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
          [arg2] "{r4}" (arg2),
          [arg3] "{r5}" (arg3),
          [arg4] "{r6}" (arg4),
        : "memory", "cr0", "r7", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile (
        \\ sc
        \\ bns+ 1f
        \\ neg 3, 3
        \\ 1:
        : [ret] "={r3}" (-> usize),
        : [number] "{r0}" (@intFromEnum(number)),
          [arg1] "{r3}" (arg1),
          [arg2] "{r4}" (arg2),
          [arg3] "{r5}" (arg3),
          [arg4] "{r6}" (arg4),
          [arg5] "{r7}" (arg5),
        : "memory", "cr0", "r8", "r9", "r10", "r11", "r12"
    );
}

pub fn syscall6(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3```
