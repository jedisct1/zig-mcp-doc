```
8 {
    if (IN6_IS_ADDR_MULTICAST(a)) return a[1] & 15;
    if (IN6_IS_ADDR_LINKLOCAL(a)) return 2;
    if (IN6_IS_ADDR_LOOPBACK(a)) return 2;
    if (IN6_IS_ADDR_SITELOCAL(a)) return 5;
    return 14;
}

fn prefixMatch(s: [16]u8, d: [16]u8) u8 {
    // TODO: This FIXME inherited from porting from musl libc.
    // I don't want this to go into zig std lib 1.0.0.

    // FIXME: The common prefix length should be limited to no greater
    // than the nominal length of the prefix portion of the source
    // address. However the definition of the source prefix length is
    // not clear and thus this limiting is not yet implemented.
    var i: u8 = 0;
    while (i < 128 and ((s[i / 8] ^ d[i / 8]) & (@as(u8, 128) >> @as(u3, @intCast(i % 8)))) == 0) : (i += 1) {}
    return i;
}

fn labelOf(a: [16]u8) u8 {
    return policyOf(a).label;
}

fn IN6_IS_ADDR_MULTICAST(a: [16]u8) bool {
    return a[0] == 0xff;
}

fn IN6_IS_ADDR_LINKLOCAL(a: [16]u8) bool {
    return a[0] == 0xfe and (a[1] & 0xc0) == 0x80;
}

fn IN6_IS_ADDR_LOOPBACK(a: [16]u8) bool {
    return a[0] == 0 and a[1] == 0 and
        a[2] == 0 and
        a[12] == 0 and a[13] == 0 and
        a[14] == 0 and a[15] == 1;
}

fn IN6_IS_ADDR_SITELOCAL(a: [16]u8) bool {
    return a[0] == 0xfe and (a[1] & 0xc0) == 0xc0;
}

// Parameters `b` and `a` swapped to make this descending.
fn addrCmpLessThan(context: void, b: LookupAddr, a: LookupAddr) bool {
    _ = context;
    return a.sortkey < b.sortkey;
}

fn linuxLookupNameFromNull(
    addrs: *std.ArrayList(LookupAddr),
    family: posix.sa_family_t,
    flags: posix.AI,
    port: u16,
) !void {
    if (flags.PASSIVE) {
        if (family != posix.AF.INET6) {
            (try addrs.addOne()).* = LookupAddr{
                .addr = Address.initIp4([1]u8{0} ** 4, port),
            };
        }
        if (family != posix.AF.INET) {
            (try addrs.addOne()).* = LookupAddr{
                .addr = Address.initIp6([1]u8{0} ** 16, port, 0, 0),
            };
        }
    } else {
        if (family != posix.AF.INET6) {
            (try addrs.addOne()).* = LookupAddr{
                .addr = Address.initIp4([4]u8{ 127, 0, 0, 1 }, port),
            };
        }
        if (family != posix.AF.INET) {
            (try addrs.addOne()).* = LookupAddr{
                .addr = Address.initIp6(([1]u8{0} ** 15) ++ [1]u8{1}, port, 0, 0),
            };
        }
    }
}

fn linuxLookupNameFromHosts(
    addrs: *std.ArrayList(LookupAddr),
    canon: *std.ArrayList(u8),
    name: []const u8,
    family: posix.sa_family_t,
    port: u16,
) !void {
    const file = fs.openFileAbsoluteZ("/etc/hosts", .{}) catch |err| switch (err) {
        error.FileNotFound,
        error.NotDir,
        error.AccessDenied,
        => return,
        else => |e| return e,
    };
    defer file.close();

    var buffered_reader = std.io.bufferedReader(file.reader());
    const reader = buffered_reader.reader();
    var line_buf: [512]u8 = undefined;
    while (reader.readUntilDelimiterOrEof(&line_buf, '\n') catch |err| switch (err) {
        error.StreamTooLong => blk: {
            // Skip to the delimiter in the reader, to fix parsing
            try reader.skipUntilDelimiterOrEof('\n');
            // Use the truncated line. A truncated comment or hostname will be handled correctly.
            break :blk &line_buf;
        },
        else => |e| return e,
    }) |line| {
        var split_it = mem.splitScalar(u8, line, '#');
        const no_comment_line = split_it.first();

        var line_it = mem.tokenizeAny(u8, no_comment_line, " \t");
        const ip_text = line_it.next() orelse continue;
        var first_name_text: ?[]const u8 = null;
        while (line_it.next()) |name_text| {
            if (first_name_text == null) first_name_text = name_text;
            if (mem.eql(u8, name_text, name)) {
                break;
            }
        } else continue;

        const addr = Address.parseExpectingFamily(ip_text, family, port) catch |err| switch (err) {
            error.Overflow,
            error.InvalidEnd,
            error.InvalidCharacter,
            error.Incomplete,
            error.InvalidIPAddressFormat,
            error.InvalidIpv4Mapping,
            error.NonCanonical,
            => continue,
        };
        try addrs.append(LookupAddr{ .addr = addr });

        // first name is canonical name
        const name_text = first_name_text.?;
        if (isValidHostName(name_text)) {
            canon.items.len = 0;
            try canon.appendSlice(name_text);
        }
    }
}

pub fn isValidHostName(hostname: []const u8) bool {
    if (hostname.len >= 254) return false;
    if (!std.unicode.utf8ValidateSlice(hostname)) return false;
    for (hostname) |byte| {
        if (!std.ascii.isAscii(byte) or byte == '.' or byte == '-' or std.ascii.isAlphanumeric(byte)) {
            continue;
        }
        return false;
    }
    return true;
}

fn linuxLookupNameFromDnsSearch(
    addrs: *std.ArrayList(LookupAddr),
    canon: *std.ArrayList(u8),
    name: []const u8,
    family: posix.sa_family_t,
    port: u16,
) !void {
    var rc: ResolvConf = undefined;
    try getResolvConf(addrs.allocator, &rc);
    defer rc.deinit();

    // Count dots, suppress search when >=ndots or name ends in
    // a dot, which is an explicit request for global scope.
    var dots: usize = 0;
    for (name) |byte| {
        if (byte == '.') dots += 1;
    }

    const search = if (dots >= rc.ndots or mem.endsWith(u8, name, "."))
        ""
    else
        rc.search.items;

    var canon_name = name;

    // Strip final dot for canon, fail if multiple trailing dots.
    if (mem.endsWith(u8, canon_name, ".")) canon_name.len -= 1;
    if (mem.endsWith(u8, canon_name, ".")) return error.UnknownHostName;

    // Name with search domain appended is setup in canon[]. This both
    // provides the desired default canonical name (if the requested
    // name is not a CNAME record) and serves as a buffer for passing
    // the full requested name to name_from_dns.
    try canon.resize(canon_name.len);
    @memcpy(canon.items, canon_name);
    try canon.append('.');

    var tok_it = mem.tokenizeAny(u8, search, " \t");
    while (tok_it.next()) |tok| {
        canon.shrinkRetainingCapacity(canon_name.len + 1);
        try canon.appendSlice(tok);
        try linuxLookupNameFromDns(addrs, canon, canon.items, family, rc, port);
        if (addrs.items.len != 0) return;
    }

    canon.shrinkRetainingCapacity(canon_name.len);
    return linuxLookupNameFromDns(addrs, canon, name, family, rc, port);
}

const dpc_ctx = struct {
    addrs: *std.ArrayList(LookupAddr),
    canon: *std.ArrayList(u8),
    port: u16,
};

fn linuxLookupNameFromDns(
    addrs: *std.ArrayList(LookupAddr),
    canon: *std.ArrayList(u8),
    name: []const u8,
    family: posix.sa_family_t,
    rc: ResolvConf,
    port: u16,
) !void {
    const ctx = dpc_ctx{
        .addrs = addrs,
        .canon = canon,
        .port = port,
    };
    const AfRr = struct {
        af: posix.sa_family_t,
        rr: u8,
    };
    const afrrs = [_]AfRr{
        AfRr{ .af = posix.AF.INET6, .rr = posix.RR.A },
        AfRr{ .af = posix.AF.INET, .rr = posix.RR.AAAA },
    };
    var qbuf: [2][280]u8 = undefined;
    var abuf: [2][512]u8 = undefined;
    var qp: [2][]const u8 = undefined;
    const apbuf = [2][]u8{ &abuf[0], &abuf[1] };
    var nq: usize = 0;

    for (afrrs) |afrr| {
        if (family != afrr.af) {
            const len = posix.res_mkquery(0, name, 1, afrr.rr, &[_]u8{}, null, &qbuf[nq]);
            qp[nq] = qbuf[nq][0..len];
            nq += 1;
        }
    }

    var ap = [2][]u8{ apbuf[0], apbuf[1] };
    ap[0].len = 0;
    ap[1].len = 0;

    try resMSendRc(qp[0..nq], ap[0..nq], apbuf[0..nq], rc);

    var i: usize = 0;
    while (i < nq) : (i += 1) {
        dnsParse(ap[i], ctx, dnsParseCallback) catch {};
    }

    if (addrs.items.len != 0) return;
    if (ap[0].len < 4 or (ap[0][3] & 15) == 2) return error.TemporaryNameServerFailure;
    if ((ap[0][3] & 15) == 0) return error.UnknownHostName;
    if ((ap[0][3] & 15) == 3) return;
    return error.NameServerFailure;
}

const ResolvConf = struct {
    attempts: u32,
    ndots: u32,
    timeout: u32,
    search: std.ArrayList(u8),
    ns: std.ArrayList(LookupAddr),

    fn deinit(rc: *ResolvConf) void {
        rc.ns.deinit();
        rc.search.deinit();
        rc.* = undefined;
    }
};

/// Ignores lines longer than 512 bytes.
/// TODO: https://github.com/ziglang/zig/issues/2765 and https://github.com/ziglang/zig/issues/2761
fn getResolvConf(allocator: mem.Allocator, rc: *ResolvConf) !void {
    rc.* = ResolvConf{
        .ns = std.ArrayList(LookupAddr).init(allocator),
        .search = std.ArrayList(u8).init(allocator),
        .ndots = 1,
        .timeout = 5,
        .attempts = 2,
    };
    errdefer rc.deinit();

    const file = fs.openFileAbsoluteZ("/etc/resolv.conf", .{}) catch |err| switch (err) {
        error.FileNotFound,
        error.NotDir,
        error.AccessDenied,
        => return linuxLookupNameFromNumericUnspec(&rc.ns, "127.0.0.1", 53),
        else => |e| return e,
    };
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    const stream = buf_reader.reader();
    var line_buf: [512]u8 = undefined;
    while (stream.readUntilDelimiterOrEof(&line_buf, '\n') catch |err| switch (err) {
        error.StreamTooLong => blk: {
            // Skip to the delimiter in the stream, to fix parsing
            try stream.skipUntilDelimiterOrEof('\n');
            // Give an empty line to the while loop, which will be skipped.
            break :blk line_buf[0..0];
        },
        else => |e| return e,
    }) |line| {
        const no_comment_line = no_comment_line: {
            var split = mem.splitScalar(u8, line, '#');
            break :no_comment_line split.first();
        };
        var line_it = mem.tokenizeAny(u8, no_comment_line, " \t");

        const token = line_it.next() orelse continue;
        if (mem.eql(u8, token, "options")) {
            while (line_it.next()) |sub_tok| {
                var colon_it = mem.splitScalar(u8, sub_tok, ':');
                const name = colon_it.first();
                const value_txt = colon_it.next() orelse continue;
                const value = std.fmt.parseInt(u8, value_txt, 10) catch |err| switch (err) {
                    // TODO https://github.com/ziglang/zig/issues/11812
                    error.Overflow => @as(u8, 255),
                    error.InvalidCharacter => continue,
                };
                if (mem.eql(u8, name, "ndots")) {
                    rc.ndots = @min(value, 15);
                } else if (mem.eql(u8, name, "attempts")) {
                    rc.attempts = @min(value, 10);
                } else if (mem.eql(u8, name, "timeout")) {
                    rc.timeout = @min(value, 60);
                }
            }
        } else if (mem.eql(u8, token, "nameserver")) {
            const ip_txt = line_it.next() orelse continue;
            try linuxLookupNameFromNumericUnspec(&rc.ns, ip_txt, 53);
        } else if (mem.eql(u8, token, "domain") or mem.eql(u8, token, "search")) {
            rc.search.items.len = 0;
            try rc.search.appendSlice(line_it.rest());
        }
    }

    if (rc.ns.items.len == 0) {
        return linuxLookupNameFromNumericUnspec(&rc.ns, "127.0.0.1", 53);
    }
}

fn linuxLookupNameFromNumericUnspec(
    addrs: *std.ArrayList(LookupAddr),
    name: []const u8,
    port: u16,
) !void {
    const addr = try Address.resolveIp(name, port);
    (try addrs.addOne()).* = LookupAddr{ .addr = addr };
}

fn resMSendRc(
    queries: []const []const u8,
    answers: [][]u8,
    answer_bufs: []const []u8,
    rc: ResolvConf,
) !void {
    const timeout = 1000 * rc.timeout;
    const attempts = rc.attempts;

    var sl: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    var family: posix.sa_family_t = posix.AF.INET;

    var ns_list = std.ArrayList(Address).init(rc.ns.allocator);
    defer ns_list.deinit();

    try ns_list.resize(rc.ns.items.len);
    const ns = ns_list.items;

    for (rc.ns.items, 0..) |iplit, i| {
        ns[i] = iplit.addr;
        assert(ns[i].getPort() == 53);
        if (iplit.addr.any.family != posix.AF.INET) {
            family = posix.AF.INET6;
        }
    }

    const flags = posix.SOCK.DGRAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK;
    const fd = posix.socket(family, flags, 0) catch |err| switch (err) {
        error.AddressFamilyNotSupported => blk: {
            // Handle case where system lacks IPv6 support
            if (family == posix.AF.INET6) {
                family = posix.AF.INET;
                break :blk try posix.socket(posix.AF.INET, flags, 0);
            }
            return err;
        },
        else => |e| return e,
    };
    defer Stream.close(.{ .handle = fd });

    // Past this point, there are no errors. Each individual query will
    // yield either no reply (indicated by zero length) or an answer
    // packet which is up to the caller to interpret.

    // Convert any IPv4 addresses in a mixed environment to v4-mapped
    if (family == posix.AF.INET6) {
        try posix.setsockopt(
            fd,
            posix.SOL.IPV6,
            std.os.linux.IPV6.V6ONLY,
            &mem.toBytes(@as(c_int, 0)),
        );
        for (0..ns.len) |i| {
            if (ns[i].any.family != posix.AF.INET) continue;
            mem.writeInt(u32, ns[i].in6.sa.addr[12..], ns[i].in.sa.addr, native_endian);
            ns[i].in6.sa.addr[0..12].* = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff".*;
            ns[i].any.family = posix.AF.INET6;
            ns[i].in6.sa.flowinfo = 0;
            ns[i].in6.sa.scope_id = 0;
        }
        sl = @sizeOf(posix.sockaddr.in6);
    }

    // Get local address and open/bind a socket
    var sa: Address = undefined;
    @memset(@as([*]u8, @ptrCast(&sa))[0..@sizeOf(Address)], 0);
    sa.any.family = family;
    try posix.bind(fd, &sa.any, sl);

    var pfd = [1]posix.pollfd{posix.pollfd{
        .fd = fd,
        .events = posix.POLL.IN,
        .revents = undefined,
    }};
    const retry_interval = timeout / attempts;
    var next: u32 = 0;
    var t2: u64 = @bitCast(std.time.milliTimestamp());
    const t0 = t2;
    var t1 = t2 - retry_interval;

    var servfail_retry: usize = undefined;

    outer: while (t2 - t0 < timeout) : (t2 = @as(u64, @bitCast(std.time.milliTimestamp()))) {
        if (t2 - t1 >= retry_interval) {
            // Query all configured nameservers in parallel
            var i: usize = 0;
            while (i < queries.len) : (i += 1) {
                if (answers[i].len == 0) {
                    var j: usize = 0;
                    while (j < ns.len) : (j += 1) {
                        _ = posix.sendto(fd, queries[i], posix.MSG.NOSIGNAL, &ns[j].any, sl) catch undefined;
                    }
                }
            }
            t1 = t2;
            servfail_retry = 2 * queries.len;
        }

        // Wait for a response, or until time to retry
        const clamped_timeout = @min(@as(u31, std.math.maxInt(u31)), t1 + retry_interval - t2);
        const nevents = posix.poll(&pfd, clamped_timeout) catch 0;
        if (nevents == 0) continue;

        while (true) {
            var sl_copy = sl;
            const rlen = posix.recvfrom(fd, answer_bufs[next], 0, &sa.any, &sl_copy) catch break;

            // Ignore non-identifiable packets
            if (rlen < 4) continue;

            // Ignore replies from addresses we didn't send to
            var j: usize = 0;
            while (j < ns.len and !ns[j].eql(sa)) : (j += 1) {}
            if (j == ns.len) continue;

            // Find which query this answer goes with, if any
            var i: usize = next;
            while (i < queries.len and (answer_bufs[next][0] != queries[i][0] or
                answer_bufs[next][1] != queries[i][1])) : (i += 1)
            {}

            if (i == queries.len) continue;
            if (answers[i].len != 0) continue;

            // Only accept positive or negative responses;
            // retry immediately on server failure, and ignore
            // all other codes such as refusal.
            switch (answer_bufs[next][3] & 15) {
                0, 3 => {},
                2 => if (servfail_retry != 0) {
                    servfail_retry -= 1;
                    _ = posix.sendto(fd, queries[i], posix.MSG.NOSIGNAL, &ns[j].any, sl) catch undefined;
                },
                else => continue,
            }

            // Store answer in the right slot, or update next
            // available temp slot if it's already in place.
            answers[i].len = rlen;
            if (i == next) {
                while (next < queries.len and answers[next].len != 0) : (next += 1) {}
            } else {
                @memcpy(answer_bufs[i][0..rlen], answer_bufs[next][0..rlen]);
            }

            if (next == queries.len) break :outer;
        }
    }
}

fn dnsParse(
    r: []const u8,
    ctx: anytype,
    comptime callback: anytype,
) !void {
    // This implementation is ported from musl libc.
    // A more idiomatic "ziggy" implementation would be welcome.
    if (r.len < 12) return error.InvalidDnsPacket;
    if ((r[3] & 15) != 0) return;
    var p = r.ptr + 12;
    var qdcount = r[4] * @as(usize, 256) + r[5];
    var ancount = r[6] * @as(usize, 256) + r[7];
    if (qdcount + ancount > 64) return error.InvalidDnsPacket;
    while (qdcount != 0) {
        qdcount -= 1;
        while (@intFromPtr(p) - @intFromPtr(r.ptr) < r.len and p[0] -% 1 < 127) p += 1;
        if (p[0] > 193 or (p[0] == 193 and p[1] > 254) or @intFromPtr(p) > @intFromPtr(r.ptr) + r.len - 6)
            return error.InvalidDnsPacket;
        p += @as(usize, 5) + @intFromBool(p[0] != 0);
    }
    while (ancount != 0) {
        ancount -= 1;
        while (@intFromPtr(p) - @intFromPtr(r.ptr) < r.len and p[0] -% 1 < 127) p += 1;
        if (p[0] > 193 or (p[0] == 193 and p[1] > 254) or @intFromPtr(p) > @intFromPtr(r.ptr) + r.len - 6)
            return error.InvalidDnsPacket;
        p += @as(usize, 1) + @intFromBool(p[0] != 0);
        const len = p[8] * @as(usize, 256) + p[9];
        if (@intFromPtr(p) + len > @intFromPtr(r.ptr) + r.len) return error.InvalidDnsPacket;
        try callback(ctx, p[1], p[10..][0..len], r);
        p += 10 + len;
    }
}

fn dnsParseCallback(ctx: dpc_ctx, rr: u8, data: []const u8, packet: []const u8) !void {
    switch (rr) {
        posix.RR.A => {
            if (data.len != 4) return error.InvalidDnsARecord;
            const new_addr = try ctx.addrs.addOne();
            new_addr.* = LookupAddr{
                .addr = Address.initIp4(data[0..4].*, ctx.port),
            };
        },
        posix.RR.AAAA => {
            if (data.len != 16) return error.InvalidDnsAAAARecord;
            const new_addr = try ctx.addrs.addOne();
            new_addr.* = LookupAddr{
                .addr = Address.initIp6(data[0..16].*, ctx.port, 0, 0),
            };
        },
        posix.RR.CNAME => {
            var tmp: [256]u8 = undefined;
            // Returns len of compressed name. strlen to get canon name.
            _ = try posix.dn_expand(packet, data, &tmp);
            const canon_name = mem.sliceTo(&tmp, 0);
            if (isValidHostName(canon_name)) {
                ctx.canon.items.len = 0;
                try ctx.canon.appendSlice(canon_name);
            }
        },
        else => return,
    }
}

pub const Stream = struct {
    /// Underlying platform-defined type which may or may not be
    /// interchangeable with a file system file descriptor.
    handle: posix.socket_t,

    pub fn close(s: Stream) void {
        switch (native_os) {
            .windows => windows.closesocket(s.handle) catch unreachable,
            else => posix.close(s.handle),
        }
    }

    pub const ReadError = posix.ReadError;
    pub const WriteError = posix.WriteError;

    pub const Reader = io.Reader(Stream, ReadError, read);
    pub const Writer = io.Writer(Stream, WriteError, write);

    pub fn reader(self: Stream) Reader {
        return .{ .context = self };
    }

    pub fn writer(self: Stream) Writer {
        return .{ .context = self };
    }

    pub fn read(self: Stream, buffer: []u8) ReadError!usize {
        if (native_os == .windows) {
            return windows.ReadFile(self.handle, buffer, null);
        }

        return posix.read(self.handle, buffer);
    }

    pub fn readv(s: Stream, iovecs: []const posix.iovec) ReadError!usize {
        if (native_os == .windows) {
            // TODO improve this to use ReadFileScatter
            if (iovecs.len == 0) return @as(usize, 0);
            const first = iovecs[0];
            return windows.ReadFile(s.handle, first.base[0..first.len], null);
        }

        return posix.readv(s.handle, iovecs);
    }

    /// Returns the number of bytes read. If the number read is smaller than
    /// `buffer.len`, it means the stream reached the end. Reaching the end of
    /// a stream is not an error condition.
    pub fn readAll(s: Stream, buffer: []u8) ReadError!usize {
        return readAtLeast(s, buffer, buffer.len);
    }

    /// Returns the number of bytes read, calling the underlying read function
    /// the minimal number of times until the buffer has at least `len` bytes
    /// filled. If the number read is less than `len` it means the stream
    /// reached the end. Reaching the end of the stream is not an error
    /// condition.
    pub fn readAtLeast(s: Stream, buffer: []u8, len: usize) ReadError!usize {
        assert(len <= buffer.len);
        var index: usize = 0;
        while (index < len) {
            const amt = try s.read(buffer[index..]);
            if (amt == 0) break;
            index += amt;
        }
        return index;
    }

    /// TODO in evented I/O mode, this implementation incorrectly uses the event loop's
    /// file system thread instead of non-blocking. It needs to be reworked to properly
    /// use non-blocking I/O.
    pub fn write(self: Stream, buffer: []const u8) WriteError!usize {
        if (native_os == .windows) {
            return windows.WriteFile(self.handle, buffer, null);
        }

        return posix.write(self.handle, buffer);
    }

    pub fn writeAll(self: Stream, bytes: []const u8) WriteError!void {
        var index: usize = 0;
        while (index < bytes.len) {
            index += try self.write(bytes[index..]);
        }
    }

    /// See https://github.com/ziglang/zig/issues/7699
    /// See equivalent function: `std.fs.File.writev`.
    pub fn writev(self: Stream, iovecs: []const posix.iovec_const) WriteError!usize {
        return posix.writev(self.handle, iovecs);
    }

    /// The `iovecs` parameter is mutable because this function needs to mutate the fields in
    /// order to handle partial writes from the underlying OS layer.
    /// See https://github.com/ziglang/zig/issues/7699
    /// See equivalent function: `std.fs.File.writevAll`.
    pub fn writevAll(self: Stream, iovecs: []posix.iovec_const) WriteError!void {
        if (iovecs.len == 0) return;

        var i: usize = 0;
        while (true) {
            var amt = try self.writev(iovecs[i..]);
            while (amt >= iovecs[i].len) {
                amt -= iovecs[i].len;
                i += 1;
                if (i >= iovecs.len) return;
            }
            iovecs[i].base += amt;
            iovecs[i].len -= amt;
        }
    }
};

pub const Server = struct {
    listen_address: Address,
    stream: std.net.Stream,

    pub const Connection = struct {
        stream: std.net.Stream,
        address: Address,
    };

    pub fn deinit(s: *Server) void {
        s.stream.close();
        s.* = undefined;
    }

    pub const AcceptError = posix.AcceptError;

    /// Blocks until a client connects to the server. The returned `Connection` has
    /// an open stream.
    pub fn accept(s: *Server) AcceptError!Connection {
        var accepted_addr: Address = undefined;
        var addr_len: posix.socklen_t = @sizeOf(Address);
        const fd = try posix.accept(s.stream.handle, &accepted_addr.any, &addr_len, posix.SOCK.CLOEXEC);
        return .{
            .stream = .{ .handle = fd },
            .address = accepted_addr,
        };
    }
};

test {
    if (builtin.os.tag != .wasi) {
        _ = Server;
        _ = Stream;
        _ = Address;
        _ = @import("net/test.zig");
    }
}
const std = @import("std");
const builtin = @import("builtin");
const net = std.net;
const mem = std.mem;
const testing = std.testing;

test "parse and render IP addresses at comptime" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;
    comptime {
        var ipAddrBuffer: [16]u8 = undefined;
        // Parses IPv6 at comptime
        const ipv6addr = net.Address.parseIp("::1", 0) catch unreachable;
        var ipv6 = std.fmt.bufPrint(ipAddrBuffer[0..], "{}", .{ipv6addr}) catch unreachable;
        try std.testing.expect(std.mem.eql(u8, "::1", ipv6[1 .. ipv6.len - 3]));

        // Parses IPv4 at comptime
        const ipv4addr = net.Address.parseIp("127.0.0.1", 0) catch unreachable;
        var ipv4 = std.fmt.bufPrint(ipAddrBuffer[0..], "{}", .{ipv4addr}) catch unreachable;
        try std.testing.expect(std.mem.eql(u8, "127.0.0.1", ipv4[0 .. ipv4.len - 2]));

        // Returns error for invalid IP addresses at comptime
        try testing.expectError(error.InvalidIPAddressFormat, net.Address.parseIp("::123.123.123.123", 0));
        try testing.expectError(error.InvalidIPAddressFormat, net.Address.parseIp("127.01.0.1", 0));
        try testing.expectError(error.InvalidIPAddressFormat, net.Address.resolveIp("::123.123.123.123", 0));
        try testing.expectError(error.InvalidIPAddressFormat, net.Address.resolveIp("127.01.0.1", 0));
    }
}

test "format IPv6 address with no zero runs" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const addr = try std.net.Address.parseIp6("2001:db8:1:2:3:4:5:6", 0);

    var buffer: [50]u8 = undefined;
    const result = std.fmt.bufPrint(buffer[0..], "{}", .{addr}) catch unreachable;

    try std.testing.expectEqualStrings("[2001:db8:1:2:3:4:5:6]:0", result);
}

test "parse IPv6 addresses and check compressed form" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const alloc = testing.allocator;

    // 1) Parse an IPv6 address that should compress to [2001:db8::1:0:0:2]:0
    const addr1 = try std.net.Address.parseIp6("2001:0db8:0000:0000:0001:0000:0000:0002", 0);

    // 2) Parse an IPv6 address that should compress to [2001:db8::1:2]:0
    const addr2 = try std.net.Address.parseIp6("2001:0db8:0000:0000:0000:0000:0001:0002", 0);

    // 3) Parse an IPv6 address that should compress to [2001:db8:1:0:1::2]:0
    const addr3 = try std.net.Address.parseIp6("2001:0db8:0001:0000:0001:0000:0000:0002", 0);

    // Print each address in Zig's default "[ipv6]:port" form.
    const printed1 = try std.fmt.allocPrint(alloc, "{any}", .{addr1});
    defer testing.allocator.free(printed1);
    const printed2 = try std.fmt.allocPrint(alloc, "{any}", .{addr2});
    defer testing.allocator.free(printed2);
    const printed3 = try std.fmt.allocPrint(alloc, "{any}", .{addr3});
    defer testing.allocator.free(printed3);

    // Check the exact compressed forms we expect.
    try std.testing.expectEqualStrings("[2001:db8::1:0:0:2]:0", printed1);
    try std.testing.expectEqualStrings("[2001:db8::1:2]:0", printed2);
    try std.testing.expectEqualStrings("[2001:db8:1:0:1::2]:0", printed3);
}

test "parse IPv6 address, check raw bytes" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const expected_raw: [16]u8 = .{
        0x20, 0x01, 0x0d, 0xb8, // 2001:db8
        0x00, 0x00, 0x00, 0x00, // :0000:0000
        0x00, 0x01, 0x00, 0x00, // :0001:0000
        0x00, 0x00, 0x00, 0x02, // :0000:0002
    };

    const addr = try std.net.Address.parseIp6("2001:db8:0000:0000:0001:0000:0000:0002", 0);

    const actual_raw = addr.in6.sa.addr[0..];
    try std.testing.expectEqualSlices(u8, expected_raw[0..], actual_raw);
}

test "parse and render IPv6 addresses" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    var buffer: [100]u8 = undefined;
    const ips = [_][]const u8{
        "FF01:0:0:0:0:0:0:FB",
        "FF01::Fb",
        "::1",
        "::",
        "1::",
        "2001:db8::",
        "::1234:5678",
        "2001:db8::1234:5678",
        "FF01::FB%1234",
        "::ffff:123.5.123.5",
    };
    const printed = [_][]const u8{
        "ff01::fb",
        "ff01::fb",
        "::1",
        "::",
        "1::",
        "2001:db8::",
        "::1234:5678",
        "2001:db8::1234:5678",
        "ff01::fb",
        "::ffff:123.5.123.5",
    };
    for (ips, 0..) |ip, i| {
        const addr = net.Address.parseIp6(ip, 0) catch unreachable;
        var newIp = std.fmt.bufPrint(buffer[0..], "{}", .{addr}) catch unreachable;
        try std.testing.expect(std.mem.eql(u8, printed[i], newIp[1 .. newIp.len - 3]));

        if (builtin.os.tag == .linux) {
            const addr_via_resolve = net.Address.resolveIp6(ip, 0) catch unreachable;
            var newResolvedIp = std.fmt.bufPrint(buffer[0..], "{}", .{addr_via_resolve}) catch unreachable;
            try std.testing.expect(std.mem.eql(u8, printed[i], newResolvedIp[1 .. newResolvedIp.len - 3]));
        }
    }

    try testing.expectError(error.InvalidCharacter, net.Address.parseIp6(":::", 0));
    try testing.expectError(error.Overflow, net.Address.parseIp6("FF001::FB", 0));
    try testing.expectError(error.InvalidCharacter, net.Address.parseIp6("FF01::Fb:zig", 0));
    try testing.expectError(error.InvalidEnd, net.Address.parseIp6("FF01:0:0:0:0:0:0:FB:", 0));
    try testing.expectError(error.Incomplete, net.Address.parseIp6("FF01:", 0));
    try testing.expectError(error.InvalidIpv4Mapping, net.Address.parseIp6("::123.123.123.123", 0));
    try testing.expectError(error.Incomplete, net.Address.parseIp6("1", 0));
    // TODO Make this test pass on other operating systems.
    if (builtin.os.tag == .linux or comptime builtin.os.tag.isDarwin() or builtin.os.tag == .windows) {
        try testing.expectError(error.Incomplete, net.Address.resolveIp6("ff01::fb%", 0));
        // Assumes IFNAMESIZE will always be a multiple of 2
        try testing.expectError(error.Overflow, net.Address.resolveIp6("ff01::fb%wlp3" ++ "s0" ** @divExact(std.posix.IFNAMESIZE - 4, 2), 0));
        try testing.expectError(error.Overflow, net.Address.resolveIp6("ff01::fb%12345678901234", 0));
    }
}

test "invalid but parseable IPv6 scope ids" {
    if (builtin.os.tag != .linux and comptime !builtin.os.tag.isDarwin() and builtin.os.tag != .windows) {
        // Currently, resolveIp6 with alphanumerical scope IDs only works on Linux.
        // TODO Make this test pass on other operating systems.
        return error.SkipZigTest;
    }

    try testing.expectError(error.InterfaceNotFound, net.Address.resolveIp6("ff01::fb%123s45678901234", 0));
}

test "parse and render IPv4 addresses" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    var buffer: [18]u8 = undefined;
    for ([_][]const u8{
        "0.0.0.0",
        "255.255.255.255",
        "1.2.3.4",
        "123.255.0.91",
        "127.0.0.1",
    }) |ip| {
        const addr = net.Address.parseIp4(ip, 0) catch unreachable;
        var newIp = std.fmt.bufPrint(buffer[0..], "{}", .{addr}) catch unreachable;
        try std.testing.expect(std.mem.eql(u8, ip, newIp[0 .. newIp.len - 2]));
    }

    try testing.expectError(error.Overflow, net.Address.parseIp4("256.0.0.1", 0));
    try testing.expectError(error.InvalidCharacter, net.Address.parseIp4("x.0.0.1", 0));
    try testing.expectError(error.InvalidEnd, net.Address.parseIp4("127.0.0.1.1", 0));
    try testing.expectError(error.Incomplete, net.Address.parseIp4("127.0.0.", 0));
    try testing.expectError(error.InvalidCharacter, net.Address.parseIp4("100..0.1", 0));
    try testing.expectError(error.NonCanonical, net.Address.parseIp4("127.01.0.1", 0));
}

test "parse and render UNIX addresses" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;
    if (!net.has_unix_sockets) return error.SkipZigTest;

    var buffer: [14]u8 = undefined;
    const addr = net.Address.initUnix("/tmp/testpath") catch unreachable;
    const fmt_addr = std.fmt.bufPrint(buffer[0..], "{}", .{addr}) catch unreachable;
    try std.testing.expectEqualSlices(u8, "/tmp/testpath", fmt_addr);

    const too_long = [_]u8{'a'} ** 200;
    try testing.expectError(error.NameTooLong, net.Address.initUnix(too_long[0..]));
}

test "resolve DNS" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    if (builtin.os.tag == .windows) {
        _ = try std.os.windows.WSAStartup(2, 2);
    }
    defer {
        if (builtin.os.tag == .windows) {
            std.os.windows.WSACleanup() catch unreachable;
        }
    }

    // Resolve localhost, this should not fail.
    {
        const localhost_v4 = try net.Address.parseIp("127.0.0.1", 80);
        const localhost_v6 = try net.Address.parseIp("::2", 80);

        const result = try net.getAddressList(testing.allocator, "localhost", 80);
        defer result.deinit();
        for (result.addrs) |addr| {
            if (addr.eql(localhost_v4) or addr.eql(localhost_v6)) break;
        } else @panic("unexpected address for localhost");
    }

    {
        // The tests are required to work even when there is no Internet connection,
        // so some of these errors we must accept and skip the test.
        const result = net.getAddressList(testing.allocator, "example.com", 80) catch |err| switch (err) {
            error.UnknownHostName => return error.SkipZigTest,
            error.TemporaryNameServerFailure => return error.SkipZigTest,
            else => return err,
        };
        result.deinit();
    }
}

test "listen on a port, send bytes, receive bytes" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    if (builtin.os.tag == .windows) {
        _ = try std.os.windows.WSAStartup(2, 2);
    }
    defer {
        if (builtin.os.tag == .windows) {
            std.os.windows.WSACleanup() catch unreachable;
        }
    }

    // Try only the IPv4 variant as some CI builders have no IPv6 localhost
    // configured.
    const localhost = try net.Address.parseIp("127.0.0.1", 0);

    var server = try localhost.listen(.{});
    defer server.deinit();

    const S = struct {
        fn clientFn(server_address: net.Address) !void {
            const socket = try net.tcpConnectToAddress(server_address);
            defer socket.close();

            _ = try socket.writer().writeAll("Hello world!");
        }
    };

    const t = try std.Thread.spawn(.{}, S.clientFn, .{server.listen_address});
    defer t.join();

    var client = try server.accept();
    defer client.stream.close();
    var buf: [16]u8 = undefined;
    const n = try client.stream.reader().read(&buf);

    try testing.expectEqual(@as(usize, 12), n);
    try testing.expectEqualSlices(u8, "Hello world!", buf[0..n]);
}

test "listen on an in use port" {
    if (builtin.os.tag != .linux and comptime !builtin.os.tag.isDarwin() and builtin.os.tag != .windows) {
        // TODO build abstractions for other operating systems
        return error.SkipZigTest;
    }

    const localhost = try net.Address.parseIp("127.0.0.1", 0);

    var server1 = try localhost.listen(.{ .reuse_port = true });
    defer server1.deinit();

    var server2 = try server1.listen_address.listen(.{ .reuse_port = true });
    defer server2.deinit();
}

fn testClientToHost(allocator: mem.Allocator, name: []const u8, port: u16) anyerror!void {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const connection = try net.tcpConnectToHost(allocator, name, port);
    defer connection.close();

    var buf: [100]u8 = undefined;
    const len = try connection.read(&buf);
    const msg = buf[0..len];
    try testing.expect(mem.eql(u8, msg, "hello from server\n"));
}

fn testClient(addr: net.Address) anyerror!void {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const socket_file = try net.tcpConnectToAddress(addr);
    defer socket_file.close();

    var buf: [100]u8 = undefined;
    const len = try socket_file.read(&buf);
    const msg = buf[0..len];
    try testing.expect(mem.eql(u8, msg, "hello from server\n"));
}

fn testServer(server: *net.Server) anyerror!void {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    var client = try server.accept();

    const stream = client.stream.writer();
    try stream.print("hello from server\n", .{});
}

test "listen on a unix socket, send bytes, receive bytes" {
    if (builtin.single_threaded) return error.SkipZigTest;
    if (!net.has_unix_sockets) return error.SkipZigTest;

    if (builtin.os.tag == .windows) {
        _ = try std.os.windows.WSAStartup(2, 2);
    }
    defer {
        if (builtin.os.tag == .windows) {
            std.os.windows.WSACleanup() catch unreachable;
        }
    }

    const socket_path = try generateFileName("socket.unix");
    defer testing.allocator.free(socket_path);

    const socket_addr = try net.Address.initUnix(socket_path);
    defer std.fs.cwd().deleteFile(socket_path) catch {};

    var server = try socket_addr.listen(.{});
    defer server.deinit();

    const S = struct {
        fn clientFn(path: []const u8) !void {
            const socket = try net.connectUnixSocket(path);
            defer socket.close();

            _ = try socket.writer().writeAll("Hello world!");
        }
    };

    const t = try std.Thread.spawn(.{}, S.clientFn, .{socket_path});
    defer t.join();

    var client = try server.accept();
    defer client.stream.close();
    var buf: [16]u8 = undefined;
    const n = try client.stream.reader().read(&buf);

    try testing.expectEqual(@as(usize, 12), n);
    try testing.expectEqualSlices(u8, "Hello world!", buf[0..n]);
}

test "listen on a unix socket with reuse_port option" {
    if (!net.has_unix_sockets) return error.SkipZigTest;
    // Windows doesn't implement reuse port option.
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const socket_path = try generateFileName("socket.unix");
    defer testing.allocator.free(socket_path);

    const socket_addr = try net.Address.initUnix(socket_path);
    defer std.fs.cwd().deleteFile(socket_path) catch {};

    var server = try socket_addr.listen(.{ .reuse_port = true });
    server.deinit();
}

fn generateFileName(base_name: []const u8) ![]const u8 {
    const random_bytes_count = 12;
    const sub_path_len = comptime std.fs.base64_encoder.calcSize(random_bytes_count);
    var random_bytes: [12]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    var sub_path: [sub_path_len]u8 = undefined;
    _ = std.fs.base64_encoder.encode(&sub_path, &random_bytes);
    return std.fmt.allocPrint(testing.allocator, "{s}-{s}", .{ sub_path[0..], base_name });
}

test "non-blocking tcp server" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;
    if (true) {
        // https://github.com/ziglang/zig/issues/18315
        return error.SkipZigTest;
    }

    const localhost = try net.Address.parseIp("127.0.0.1", 0);
    var server = localhost.listen(.{ .force_nonblocking = true });
    defer server.deinit();

    const accept_err = server.accept();
    try testing.expectError(error.WouldBlock, accept_err);

    const socket_file = try net.tcpConnectToAddress(server.listen_address);
    defer socket_file.close();

    var client = try server.accept();
    defer client.stream.close();
    const stream = client.stream.writer();
    try stream.print("hello from server\n", .{});

    var buf: [100]u8 = undefined;
    const len = try socket_file.read(&buf);
    const msg = buf[0..len];
    try testing.expect(mem.eql(u8, msg, "hello from server\n"));
}
const std = @import("std.zig");
const builtin = @import("builtin");
const testing = std.testing;

pub fn once(comptime f: fn () void) Once(f) {
    return Once(f){};
}

/// An object that executes the function `f` just once.
/// It is undefined behavior if `f` re-enters the same Once instance.
pub fn Once(comptime f: fn () void) type {
    return struct {
        done: bool = false,
        mutex: std.Thread.Mutex = std.Thread.Mutex{},

        /// Call the function `f`.
        /// If `call` is invoked multiple times `f` will be executed only the
        /// first time.
        /// The invocations are thread-safe.
        pub fn call(self: *@This()) void {
            if (@atomicLoad(bool, &self.done, .acquire))
                return;

            return self.callSlow();
        }

        fn callSlow(self: *@This()) void {
            @branchHint(.cold);

            self.mutex.lock();
            defer self.mutex.unlock();

            // The first thread to acquire the mutex gets to run the initializer
            if (!self.done) {
                f();
                @atomicStore(bool, &self.done, true, .release);
            }
        }
    };
}

var global_number: i32 = 0;
var global_once = once(incr);

fn incr() void {
    global_number += 1;
}

test "Once executes its function just once" {
    if (builtin.single_threaded) {
        global_once.call();
        global_once.call();
    } else {
        var threads: [10]std.Thread = undefined;
        var thread_count: usize = 0;
        defer for (threads[0..thread_count]) |handle| handle.join();

        for (&threads) |*handle| {
            handle.* = try std.Thread.spawn(.{}, struct {
                fn thread_fn(x: u8) void {
                    _ = x;
                    global_once.call();
                    if (global_number != 1) @panic("memory ordering bug");
                }
            }.thread_fn, .{0});
            thread_count += 1;
        }
    }

    try testing.expectEqual(@as(i32, 1), global_number);
}
//! This file contains thin wrappers around OS-specific APIs, with these
//! specific goals in mind:
//! * Convert "errno"-style error codes into Zig errors.
//! * When null-terminated byte buffers are required, provide APIs which accept
//!   slices as well as APIs which accept null-terminated byte buffers. Same goes
//!   for WTF-16LE encoding.
//! * Where operating systems share APIs, e.g. POSIX, these thin wrappers provide
//!   cross platform abstracting.
//! * When there exists a corresponding libc function and linking libc, the libc
//!   implementation is used. Exceptions are made for known buggy areas of libc.
//!   On Linux libc can be side-stepped by using `std.os.linux` directly.
//! * For Windows, this file represents the API that libc would provide for
//!   Windows. For thin wrappers around Windows-specific APIs, see `std.os.windows`.

const root = @import("root");
const std = @import("std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const elf = std.elf;
const fs = std.fs;
const dl = @import("dynamic_library.zig");
const max_path_bytes = std.fs.max_path_bytes;
const posix = std.posix;
const native_os = builtin.os.tag;

pub const linux = @import("os/linux.zig");
pub const plan9 = @import("os/plan9.zig");
pub const uefi = @import("os/uefi.zig");
pub const wasi = @import("os/wasi.zig");
pub const emscripten = @import("os/emscripten.zig");
pub const windows = @import("os/windows.zig");

test {
    _ = linux;
    if (native_os == .uefi) {
        _ = uefi;
    }
    _ = wasi;
    _ = windows;
}

/// See also `getenv`. Populated by startup code before main().
/// TODO this is a footgun because the value will be undefined when using `zig build-lib`.
/// https://github.com/ziglang/zig/issues/4524
pub var environ: [][*:0]u8 = undefined;

/// Populated by startup code before main().
/// Not available on WASI or Windows without libc. See `std.process.argsAlloc`
/// or `std.process.argsWithAllocator` for a cross-platform alternative.
pub var argv: [][*:0]u8 = if (builtin.link_libc) undefined else switch (native_os) {
    .windows => @compileError("argv isn't supported on Windows: use std.process.argsAlloc instead"),
    .wasi => @compileError("argv isn't supported on WASI: use std.process.argsAlloc instead"),
    else => undefined,
};

/// Call from Windows-specific code if you already have a WTF-16LE encoded, null terminated string.
/// Otherwise use `access` or `accessZ`.
pub fn accessW(path: [*:0]const u16) windows.GetFileAttributesError!void {
    const ret = try windows.GetFileAttributesW(path);
    if (ret != windows.INVALID_FILE_ATTRIBUTES) {
        return;
    }
    switch (windows.GetLastError()) {
        .FILE_NOT_FOUND => return error.FileNotFound,
        .PATH_NOT_FOUND => return error.FileNotFound,
        .ACCESS_DENIED => return error.AccessDenied,
        else => |err| return windows.unexpectedError(err),
    }
}

pub fn isGetFdPathSupportedOnTarget(os: std.Target.Os) bool {
    return switch (os.tag) {
        .windows,
        .macos,
        .ios,
        .watchos,
        .tvos,
        .visionos,
        .linux,
        .solaris,
        .illumos,
        .freebsd,
        .serenity,
        => true,

        .dragonfly => os.version_range.semver.max.order(.{ .major = 6, .minor = 0, .patch = 0 }) != .lt,
        .netbsd => os.version_range.semver.max.order(.{ .major = 10, .minor = 0, .patch = 0 }) != .lt,
        else => false,
    };
}

/// Return canonical path of handle `fd`.
///
/// This function is very host-specific and is not universally supported by all hosts.
/// For example, while it generally works on Linux, macOS, FreeBSD or Windows, it is
/// unsupported on WASI.
///
/// * On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// * On other platforms, the result is an opaque sequence of bytes with no particular encoding.
///
/// Calling this function is usually a bug.
pub fn getFdPath(fd: std.posix.fd_t, out_buffer: *[max_path_bytes]u8) std.posix.RealPathError![]u8 {
    if (!comptime isGetFdPathSupportedOnTarget(builtin.os)) {
        @compileError("querying for canonical path of a handle is unsupported on this host");
    }
    switch (native_os) {
        .windows => {
            var wide_buf: [windows.PATH_MAX_WIDE]u16 = undefined;
            const wide_slice = try windows.GetFinalPathNameByHandle(fd, .{}, wide_buf[0..]);

            const end_index = std.unicode.wtf16LeToWtf8(out_buffer, wide_slice);
            return out_buffer[0..end_index];
        },
        .macos, .ios, .watchos, .tvos, .visionos => {
            // On macOS, we can use F.GETPATH fcntl command to query the OS for
            // the path to the file descriptor.
            @memset(out_buffer[0..max_path_bytes], 0);
            switch (posix.errno(posix.system.fcntl(fd, posix.F.GETPATH, out_buffer))) {
                .SUCCESS => {},
                .BADF => return error.FileNotFound,
                .NOSPC => return error.NameTooLong,
                // TODO man pages for fcntl on macOS don't really tell you what
                // errno values to expect when command is F.GETPATH...
                else => |err| return posix.unexpectedErrno(err),
            }
            const len = mem.indexOfScalar(u8, out_buffer[0..], 0) orelse max_path_bytes;
            return out_buffer[0..len];
        },
        .linux, .serenity => {
            var procfs_buf: ["/proc/self/fd/-2147483648\x00".len]u8 = undefined;
            const proc_path = std.fmt.bufPrintZ(procfs_buf[0..], "/proc/self/fd/{d}", .{fd}) catch unreachable;

            const target = posix.readlinkZ(proc_path, out_buffer) catch |err| {
                switch (err) {
                    error.NotLink => unreachable,
                    error.BadPathName => unreachable,
                    error.InvalidUtf8 => unreachable, // WASI-only
                    error.InvalidWtf8 => unreachable, // Windows-only
                    error.UnsupportedReparsePointType => unreachable, // Windows-only
                    error.NetworkNotFound => unreachable, // Windows-only
                    else => |e| return e,
                }
            };
            return target;
        },
        .solaris, .illumos => {
            var procfs_buf: ["/proc/self/path/-2147483648\x00".len]u8 = undefined;
            const proc_path = std.fmt.bufPrintZ(procfs_buf[0..], "/proc/self/path/{d}", .{fd}) catch unreachable;

            const target = posix.readlinkZ(proc_path, out_buffer) catch |err| switch (err) {
                error.UnsupportedReparsePointType => unreachable,
                error.NotLink => unreachable,
                error.InvalidUtf8 => unreachable, // WASI-only
                else => |e| return e,
            };
            return target;
        },
        .freebsd => {
            var kfile: std.c.kinfo_file = undefined;
            kfile.structsize = std.c.KINFO_FILE_SIZE;
            switch (posix.errno(std.c.fcntl(fd, std.c.F.KINFO, @intFromPtr(&kfile)))) {
                .SUCCESS => {},
                .BADF => return error.FileNotFound,
                else => |err| return posix.unexpectedErrno(err),
            }
            const len = mem.indexOfScalar(u8, &kfile.path, 0) orelse max_path_bytes;
            if (len == 0) return error.NameTooLong;
            const result = out_buffer[0..len];
            @memcpy(result, kfile.path[0..len]);
            return result;
        },
        .dragonfly => {
            @memset(out_buffer[0..max_path_bytes], 0);
            switch (posix.errno(std.c.fcntl(fd, posix.F.GETPATH, out_buffer))) {
                .SUCCESS => {},
                .BADF => return error.FileNotFound,
                .RANGE => return error.NameTooLong,
                else => |err| return posix.unexpectedErrno(err),
            }
            const len = mem.indexOfScalar(u8, out_buffer[0..], 0) orelse max_path_bytes;
            return out_buffer[0..len];
        },
        .netbsd => {
            @memset(out_buffer[0..max_path_bytes], 0);
            switch (posix.errno(std.c.fcntl(fd, posix.F.GETPATH, out_buffer))) {
                .SUCCESS => {},
                .ACCES => return error.AccessDenied,
                .BADF => return error.FileNotFound,
                .NOENT => return error.FileNotFound,
                .NOMEM => return error.SystemResources,
                .RANGE => return error.NameTooLong,
                else => |err| return posix.unexpectedErrno(err),
            }
            const len = mem.indexOfScalar(u8, out_buffer[0..], 0) orelse max_path_bytes;
            return out_buffer[0..len];
        },
        else => unreachable, // made unreachable by isGetFdPathSupportedOnTarget above
    }
}

/// WASI-only. Same as `fstatat` but targeting WASI.
/// `pathname` should be encoded as valid UTF-8.
/// See also `fstatat`.
pub fn fstatat_wasi(dirfd: posix.fd_t, pathname: []const u8, flags: wasi.lookupflags_t) posix.FStatAtError!wasi.filestat_t {
    var stat: wasi.filestat_t = undefined;
    switch (wasi.path_filestat_get(dirfd, flags, pathname.ptr, pathname.len, &stat)) {
        .SUCCESS => return stat,
        .INVAL => unreachable,
        .BADF => unreachable, // Always a race condition.
        .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        .FAULT => unreachable,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOTDIR => return error.FileNotFound,
        .NOTCAPABLE => return error.AccessDenied,
        .ILSEQ => return error.InvalidUtf8,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub fn fstat_wasi(fd: posix.fd_t) posix.FStatError!wasi.filestat_t {
    var stat: wasi.filestat_t = undefined;
    switch (wasi.fd_filestat_get(fd, &stat)) {
        .SUCCESS => return stat,
        .INVAL => unreachable,
        .BADF => unreachable, // Always a race condition.
        .NOMEM => return error.SystemResources,
        .ACCES => return error.AccessDenied,
        .NOTCAPABLE => return error.AccessDenied,
        else => |err| return posix.unexpectedErrno(err),
    }
}
const std = @import("std");
const builtin = @import("builtin");
const wasi = std.os.wasi;
const linux = std.os.linux;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const c = std.c;

// TODO: go through this file and delete all the bits that are identical to linux because they can
// be merged in the std.c namespace.

pub const FILE = c.FILE;

var __stack_chk_guard: usize = 0;
fn __stack_chk_fail() callconv(.c) void {
    std.debug.print("stack smashing detected: terminated\n", .{});
    emscripten_force_exit(127);
}

comptime {
    if (builtin.os.tag == .emscripten) {
        if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
            // Emscripten does not provide these symbols, so we must export our own
            @export(&__stack_chk_guard, .{ .name = "__stack_chk_guard", .linkage = .strong });
            @export(&__stack_chk_fail, .{ .name = "__stack_chk_fail", .linkage = .strong });
        }
    }
}

pub const PF = linux.PF;
pub const AF = linux.AF;
pub const CLOCK = linux.CLOCK;

pub const CPU_SETSIZE = 128;
pub const cpu_set_t = [CPU_SETSIZE / @sizeOf(usize)]usize;
pub const cpu_count_t = std.meta.Int(.unsigned, std.math.log2(CPU_SETSIZE * 8));

pub fn CPU_COUNT(set: cpu_set_t) cpu_count_t {
    var sum: cpu_count_t = 0;
    for (set) |x| {
        sum += @popCount(x);
    }
    return sum;
}

pub const E = enum(u16) {
    SUCCESS = @intFromEnum(wasi.errno_t.SUCCESS),
    @"2BIG" = @intFromEnum(wasi.errno_t.@"2BIG"),
    ACCES = @intFromEnum(wasi.errno_t.ACCES),
    ADDRINUSE = @intFromEnum(wasi.errno_t.ADDRINUSE),
    ADDRNOTAVAIL = @intFromEnum(wasi.errno_t.ADDRNOTAVAIL),
    AFNOSUPPORT = @intFromEnum(wasi.errno_t.AFNOSUPPORT),
    /// This is also the error code used for `WOULDBLOCK`.
    AGAIN = @intFromEnum(wasi.errno_t.AGAIN),
    ALREADY = @intFromEnum(wasi.errno_t.ALREADY),
    BADF = @intFromEnum(wasi.errno_t.BADF),
    BADMSG = @intFromEnum(wasi.errno_t.BADMSG),
    BUSY = @intFromEnum(wasi.errno_t.BUSY),
    CANCELED = @intFromEnum(wasi.errno_t.CANCELED),
    CHILD = @intFromEnum(wasi.errno_t.CHILD),
    CONNABORTED = @intFromEnum(wasi.errno_t.CONNABORTED),
    CONNREFUSED = @intFromEnum(wasi.errno_t.CONNREFUSED),
    CONNRESET = @intFromEnum(wasi.errno_t.CONNRESET),
    DEADLK = @intFromEnum(wasi.errno_t.DEADLK),
    DESTADDRREQ = @intFromEnum(wasi.errno_t.DESTADDRREQ),
    DOM = @intFromEnum(wasi.errno_t.DOM),
    DQUOT = @intFromEnum(wasi.errno_t.DQUOT),
    EXIST = @intFromEnum(wasi.errno_t.EXIST),
    FAULT = @intFromEnum(wasi.errno_t.FAULT),
    FBIG = @intFromEnum(wasi.errno_t.FBIG),
    HOSTUNREACH = @intFromEnum(wasi.errno_t.HOSTUNREACH),
    IDRM = @intFromEnum(wasi.errno_t.IDRM),
    ILSEQ = @intFromEnum(wasi.errno_t.ILSEQ),
    INPROGRESS = @intFromEnum(wasi.errno_t.INPROGRESS),
    INTR = @intFromEnum(wasi.errno_t.INTR),
    INVAL = @intFromEnum(wasi.errno_t.INVAL),
    IO = @intFromEnum(wasi.errno_t.IO),
    ISCONN = @intFromEnum(wasi.errno_t.ISCONN),
    ISDIR = @intFromEnum(wasi.errno_t.ISDIR),
    LOOP = @intFromEnum(wasi.errno_t.LOOP),
    MFILE = @intFromEnum(wasi.errno_t.MFILE),
    MLINK = @intFromEnum(wasi.errno_t.MLINK),
    MSGSIZE = @intFromEnum(wasi.errno_t.MSGSIZE),
    MULTIHOP = @intFromEnum(wasi.errno_t.MULTIHOP),
    NAMETOOLONG = @intFromEnum(wasi.errno_t.NAMETOOLONG),
    NETDOWN = @intFromEnum(wasi.errno_t.NETDOWN),
    NETRESET = @intFromEnum(wasi.errno_t.NETRESET),
    NETUNREACH = @intFromEnum(wasi.errno_t.NETUNREACH),
    NFILE = @intFromEnum(wasi.errno_t.NFILE),
    NOBUFS = @intFromEnum(wasi.errno_t.NOBUFS),
    NODEV = @intFromEnum(wasi.errno_t.NODEV),
    NOENT = @intFromEnum(wasi.errno_t.NOENT),
    NOEXEC = @intFromEnum(wasi.errno_t.NOEXEC),
    NOLCK = @intFromEnum(wasi.errno_t.NOLCK),
    NOLINK = @intFromEnum(wasi.errno_t.NOLINK),
    NOMEM = @intFromEnum(wasi.errno_t.NOMEM),
    NOMSG = @intFromEnum(wasi.errno_t.NOMSG),
    NOPROTOOPT = @intFromEnum(wasi.errno_t.NOPROTOOPT),
    NOSPC = @intFromEnum(wasi.errno_t.NOSPC),
    NOSYS = @intFromEnum(wasi.errno_t.NOSYS),
    NOTCONN = @intFromEnum(wasi.errno_t.NOTCONN),
    NOTDIR = @intFromEnum(wasi.errno_t.NOTDIR),
    NOTEMPTY = @intFromEnum(wasi.errno_t.NOTEMPTY),
    NOTRECOVERABLE = @intFromEnum(wasi.errno_t.NOTRECOVERABLE),
    NOTSOCK = @intFromEnum(wasi.errno_t.NOTSOCK),
    /// This is also the code used for `NOTSUP`.
    OPNOTSUPP = @intFromEnum(wasi.errno_t.OPNOTSUPP),
    NOTTY = @intFromEnum(wasi.errno_t.NOTTY),
    NXIO = @intFromEnum(wasi.errno_t.NXIO),
    OVERFLOW = @intFromEnum(wasi.errno_t.OVERFLOW),
    OWNERDEAD = @intFromEnum(wasi.errno_t.OWNERDEAD),
    PERM = @intFromEnum(wasi.errno_t.PERM),
    PIPE = @intFromEnum(wasi.errno_t.PIPE),
    PROTO = @intFromEnum(wasi.errno_t.PROTO),
    PROTONOSUPPORT = @intFromEnum(wasi.errno_t.PROTONOSUPPORT),
    PROTOTYPE = @intFromEnum(wasi.errno_t.PROTOTYPE),
    RANGE = @intFromEnum(wasi.errno_t.RANGE),
    ROFS = @intFromEnum(wasi.errno_t.ROFS),
    SPIPE = @intFromEnum(wasi.errno_t.SPIPE),
    SRCH = @intFromEnum(wasi.errno_t.SRCH),
    STALE = @intFromEnum(wasi.errno_t.STALE),
    TIMEDOUT = @intFromEnum(wasi.errno_t.TIMEDOUT),
    TXTBSY = @intFromEnum(wasi.errno_t.TXTBSY),
    XDEV = @intFromEnum(wasi.errno_t.XDEV),
    NOTCAPABLE = @intFromEnum(wasi.errno_t.NOTCAPABLE),

    ENOSTR = 100,
    EBFONT = 101,
    EBADSLT = 102,
    EBADRQC = 103,
    ENOANO = 104,
    ENOTBLK = 105,
    ECHRNG = 106,
    EL3HLT = 107,
    EL3RST = 108,
    ELNRNG = 109,
    EUNATCH = 110,
    ENOCSI = 111,
    EL2HLT = 112,
    EBADE = 113,
    EBADR = 114,
    EXFULL = 115,
    ENODATA = 116,
    ETIME = 117,
    ENOSR = 118,
    ENONET = 119,
    ENOPKG = 120,
    EREMOTE = 121,
    EADV = 122,
    ESRMNT = 123,
    ECOMM = 124,
    EDOTDOT = 125,
    ENOTUNIQ = 126,
    EBADFD = 127,
    EREMCHG = 128,
    ELIBACC = 129,
    ELIBBAD = 130,
    ELIBSCN = 131,
    ELIBMAX = 132,
    ELIBEXEC = 133,
    ERESTART = 134,
    ESTRPIPE = 135,
    EUSERS = 136,
    ESOCKTNOSUPPORT = 137,
    EOPNOTSUPP = 138,
    EPFNOSUPPORT = 139,
    ESHUTDOWN = 140,
    ETOOMANYREFS = 141,
    EHOSTDOWN = 142,
    EUCLEAN = 143,
    ENOTNAM = 144,
    ENAVAIL = 145,
    EISNAM = 146,
    EREMOTEIO = 147,
    ENOMEDIUM = 148,
    EMEDIUMTYPE = 149,
    ENOKEY = 150,
    EKEYEXPIRED = 151,
    EKEYREVOKED = 152,
    EKEYREJECTED = 153,
    ERFKILL = 154,
    EHWPOISON = 155,
    EL2NSYNC = 156,
    _,
};

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

pub const FD_CLOEXEC = 1;

pub const F_OK = 0;
pub const X_OK = 1;
pub const W_OK = 2;
pub const R_OK = 4;

pub const W = struct {
    pub const NOHANG = 1;
    pub const UNTRACED = 2;
    pub const STOPPED = 2;
    pub const EXITED = 4;
    pub const CONTINUED = 8;
    pub const NOWAIT = 0x1000000;

    pub fn EXITSTATUS(s: u32) u8 {
        return @as(u8, @intCast((s & 0xff00) >> 8));
    }
    pub fn TERMSIG(s: u32) u32 {
        return s & 0x7f;
    }
    pub fn STOPSIG(s: u32) u32 {
        return EXITSTATUS(s);
    }
    pub fn IFEXITED(s: u32) bool {
        return TERMSIG(s) == 0;
    }
    pub fn IFSTOPPED(s: u32) bool {
        return @as(u16, @truncate(((s & 0xffff) *% 0x10001) >> 8)) > 0x7f00;
    }
    pub fn IFSIGNALED(s: u32) bool {
        return (s & 0xffff) -% 1 < 0xff;
    }
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    start: off_t,
    len: off_t,
    pid: pid_t,
};

pub const IFNAMESIZE = 16;

pub const NAME_MAX = 255;
pub const PATH_MAX = 4096;
pub const IOV_MAX = 1024;

pub const IPPORT_RESERVED = 1024;

pub const IPPROTO = linux.IPPROTO;

pub const LOCK = struct {
    pub const SH = 1;
    pub const EX = 2;
    pub const NB = 4;
    pub const UN = 8;
};

pub const MADV = struct {
    pub const NORMAL = 0;
    pub const RANDOM = 1;
    pub const SEQUENTIAL = 2;
    pub const WILLNEED = 3;
    pub const DONTNEED = 4;
    pub const FREE = 8;
    pub const REMOVE = 9;
    pub const DONTFORK = 10;
    pub const DOFORK = 11;
    pub const MERGEABLE = 12;
    pub const UNMERGEABLE = 13;
    pub const HUGEPAGE = 14;
    pub const NOHUGEPAGE = 15;
    pub const DONTDUMP = 16;
    pub const DODUMP = 17;
    pub const WIPEONFORK = 18;
    pub const KEEPONFORK = 19;
    pub const COLD = 20;
    pub const PAGEOUT = 21;
    pub const HWPOISON = 100;
    pub const SOFT_OFFLINE = 101;
};

pub const MSF = struct {
    pub const ASYNC = 1;
    pub const INVALIDATE = 2;
    pub const SYNC = 4;
};

pub const MSG = struct {
    pub const OOB = 0x0001;
    pub const PEEK = 0x0002;
    pub const DONTROUTE = 0x0004;
    pub const CTRUNC = 0x0008;
    pub const PROXY = 0x0010;
    pub const TRUNC = 0x0020;
    pub const DONTWAIT = 0x0040;
    pub const EOR = 0x0080;
    pub const WAITALL = 0x0100;
    pub const FIN = 0x0200;
    pub const SYN = 0x0400;
    pub const CONFIRM = 0x0800;
    pub const RST = 0x1000;
    pub const ERRQUEUE = 0x2000;
    pub const NOSIGNAL = 0x4000;
    pub const MORE = 0x8000;
    pub const WAITFORONE = 0x10000;
    pub const BATCH = 0x40000;
    pub const ZEROCOPY = 0x4000000;
    pub const FASTOPEN = 0x20000000;
    pub const CMSG_CLOEXEC = 0x40000000;
};

pub const POLL = struct {
    pub const IN = 0x001;
    pub const PRI = 0x002;
    pub const OUT = 0x004;
    pub const ERR = 0x008;
    pub const HUP = 0x010;
    pub const NVAL = 0x020;
    pub const RDNORM = 0x040;
    pub const RDBAND = 0x080;
};

pub const PROT = struct {
    pub const NONE = 0x0;
    pub const READ = 0x1;
    pub const WRITE = 0x2;
    pub const EXEC = 0x4;
    pub const GROWSDOWN = 0x01000000;
    pub const GROWSUP = 0x02000000;
};

pub const rlim_t = u64;

pub const RLIM = struct {
    pub const INFINITY = ~@as(rlim_t, 0);

    pub const SAVED_MAX = INFINITY;
    pub const SAVED_CUR = INFINITY;
};

pub const rlimit = c.rlimit;

pub const rlimit_resource = enum(c_int) {
    CPU,
    FSIZE,
    DATA,
    STACK,
    CORE,
    RSS,
    NPROC,
    NOFILE,
    MEMLOCK,
    AS,
    LOCKS,
    SIGPENDING,
    MSGQUEUE,
    NICE,
    RTPRIO,
    RTTIME,
    _,
};

pub const rusage = extern struct {
    utime: timeval,
    stime: timeval,
    maxrss: isize,
    ixrss: isize,
    idrss: isize,
    isrss: isize,
    minflt: isize,
    majflt: isize,
    nswap: isize,
    inblock: isize,
    oublock: isize,
    msgsnd: isize,
    msgrcv: isize,
    nsignals: isize,
    nvcsw: isize,
    nivcsw: isize,
    __reserved: [16]isize = [1]isize{0} ** 16,

    pub const SELF = 0;
    pub const CHILDREN = -1;
    pub const THREAD = 1;
};

pub const timeval = extern struct {
    sec: i64,
    usec: i32,
};

pub const REG = struct {
    pub const GS = 0;
    pub const FS = 1;
    pub const ES = 2;
    pub const DS = 3;
    pub const EDI = 4;
    pub const ESI = 5;
    pub const EBP = 6;
    pub const ESP = 7;
    pub const EBX = 8;
    pub const EDX = 9;
    pub const ECX = 10;
    pub const EAX = 11;
    pub const TRAPNO = 12;
    pub const ERR = 13;
    pub const EIP = 14;
    pub const CS = 15;
    pub const EFL = 16;
    pub const UESP = 17;
    pub const SS = 18;
};

pub const S = struct {
    pub const IFMT = 0o170000;

    pub const IFDIR = 0o040000;
    pub const IFCHR = 0o020000;
    pub const IFBLK = 0o060000;
    pub const IFREG = 0o100000;
    pub const IFIFO = 0o010000;
    pub const IFLNK = 0o120000;
    pub const IFSOCK = 0o140000;

    pub const ISUID = 0o4000;
    pub const ISGID = 0o2000;
    pub const ISVTX = 0o1000;
    pub const IRUSR = 0o400;
    pub const IWUSR = 0o200;
    pub const IXUSR = 0o100;
    pub const IRWXU = 0o700;
    pub const IRGRP = 0o040;
    pub const IWGRP = 0o020;
    pub const IXGRP = 0o010;
    pub const IRWXG = 0o070;
    pub const IROTH = 0o004;
    pub const IWOTH = 0o002;
    pub const IXOTH = 0o001;
    pub const IRWXO = 0o007;

    pub fn ISREG(m: mode_t) bool {
        return m & IFMT == IFREG;
    }

    pub fn ISDIR(m: mode_t) bool {
        return m & IFMT == IFDIR;
    }

    pub fn ISCHR(m: mode_t) bool {
        return m & IFMT == IFCHR;
    }

    pub fn ISBLK(m: mode_t) bool {
        return m & IFMT == IFBLK;
    }

    pub fn ISFIFO(m: mode_t) bool {
        return m & IFMT == IFIFO;
    }

    pub fn ISLNK(m: mode_t) bool {
        return m & IFMT == IFLNK;
    }

    pub fn ISSOCK(m: mode_t) bool {
        return m & IFMT == IFSOCK;
    }
};

pub const SA = struct {
    pub const NOCLDSTOP = 1;
    pub const NOCLDWAIT = 2;
    pub const SIGINFO = 4;
    pub const RESTART = 0x10000000;
    pub const RESETHAND = 0x80000000;
    pub const ONSTACK = 0x08000000;
    pub const NODEFER = 0x40000000;
    pub const RESTORER = 0x04000000;
};

pub const SEEK = struct {
    pub const SET = 0;
    pub const CUR = 1;
    pub const END = 2;
};

pub const SHUT = struct {
    pub const RD = 0;
    pub const WR = 1;
    pub const RDWR = 2;
};

pub const SIG = struct {
    pub const BLOCK = 0;
    pub const UNBLOCK = 1;
    pub const SETMASK = 2;

    pub const HUP = 1;
    pub const INT = 2;
    pub const QUIT = 3;
    pub const ILL = 4;
    pub const TRAP = 5;
    pub const ABRT = 6;
    pub const IOT = ABRT;
    pub const BUS = 7;
    pub const FPE = 8;
    pub const KILL = 9;
    pub const USR1 = 10;
    pub const SEGV = 11;
    pub const USR2 = 12;
    pub const PIPE = 13;
    pub const ALRM = 14;
    pub const TERM = 15;
    pub const STKFLT = 16;
    pub const CHLD = 17;
    pub const CONT = 18;
    pub const STOP = 19;
    pub const TSTP = 20;
    pub const TTIN = 21;
    pub const TTOU = 22;
    pub const URG = 23;
    pub const XCPU = 24;
    pub const XFSZ = 25;
    pub const VTALRM = 26;
    pub const PROF = 27;
    pub const WINCH = 28;
    pub const IO = 29;
    pub const POLL = 29;
    pub const PWR = 30;
    pub const SYS = 31;
    pub const UNUSED = SIG.SYS;

    pub const ERR: ?Sigaction.handler_fn = @ptrFromInt(std.math.maxInt(usize));
    pub const DFL: ?Sigaction.handler_fn = @ptrFromInt(0);
    pub const IGN: ?Sigaction.handler_fn = @ptrFromInt(1);
};

pub const Sigaction = extern struct {
    pub const handler_fn = *align(1) const fn (i32) callconv(.c) void;
    pub const sigaction_fn = *const fn (i32, *const siginfo_t, ?*anyopaque) callconv(.c) void;

    handler: extern union {
        handler: ?handler_fn,
        sigaction: ?sigaction_fn,
    },
    mask: sigset_t,
    flags: c_uint,
    restorer: ?*const fn () callconv(.c) void = null,
};

pub const sigset_t = [1024 / 32]u32;
pub const empty_sigset = [_]u32{0} ** @typeInfo(sigset_t).array.len;
pub const siginfo_t = extern struct {
    signo: i32,
    errno: i32,
    code: i32,
    fields: siginfo_fields_union,
};
const siginfo_fields_union = extern union {
    pad: [128 - 2 * @sizeOf(c_int) - @sizeOf(c_long)]u8,
    common: extern struct {
        first: extern union {
            piduid: extern struct {
                pid: pid_t,
                uid: uid_t,
            },
            timer: extern struct {
                timerid: i32,
                overrun: i32,
            },
        },
        second: extern union {
            value: sigval,
            sigchld: extern struct {
                status: i32,
                utime: clock_t,
                stime: clock_t,
            },
        },
    },
    sigfault: extern struct {
        addr: *allowzero anyopaque,
        addr_lsb: i16,
        first: extern union {
            addr_bnd: extern struct {
                lower: *anyopaque,
                upper: *anyopaque,
            },
            pkey: u32,
        },
    },
    sigpoll: extern struct {
        band: isize,
        fd: i32,
    },
    sigsys: extern struct {
        call_addr: *anyopaque,
        syscall: i32,
        native_arch: u32,
    },
};
pub const sigval = extern union {
    int: i32,
    ptr: *anyopaque,
};

pub const SIOCGIFINDEX = 0x8933;

pub const SO = struct {
    pub const DEBUG = 1;
    pub const REUSEADDR = 2;
    pub const TYPE = 3;
    pub const ERROR = 4;
    pub const DONTROUTE = 5;
    pub const BROADCAST = 6;
    pub const SNDBUF = 7;
    pub const RCVBUF = 8;
    pub const KEEPALIVE = 9;
    pub const OOBINLINE = 10;
    pub const NO_CHECK = 11;
    pub const PRIORITY = 12;
    pub const LINGER = 13;
    pub const BSDCOMPAT = 14;
    pub const REUSEPORT = 15;
    pub const PASSCRED = 16;
    pub const PEERCRED = 17;
    pub const RCVLOWAT = 18;
    pub const SNDLOWAT = 19;
    pub const RCVTIMEO = 20;
    pub const SNDTIMEO = 21;
    pub const ACCEPTCONN = 30;
    pub const PEERSEC = 31;
    pub const SNDBUFFORCE = 32;
    pub const RCVBUFFORCE = 33;
    pub const PROTOCOL = 38;
    pub const DOMAIN = 39;
    pub const SECURITY_AUTHENTICATION = 22;
    pub const SECURITY_ENCRYPTION_TRANSPORT = 23;
    pub const SECURITY_ENCRYPTION_NETWORK = 24;
    pub const BINDTODEVICE = 25;
    pub const ATTACH_FILTER = 26;
    pub const DETACH_FILTER = 27;
    pub const GET_FILTER = ATTACH_FILTER;
    pub const PEERNAME = 28;
    pub const TIMESTAMP_OLD = 29;
    pub const PASSSEC = 34;
    pub const TIMESTAMPNS_OLD = 35;
    pub const MARK = 36;
    pub const TIMESTAMPING_OLD = 37;
    pub const RXQ_OVFL = 40;
    pub const WIFI_STATUS = 41;
    pub const PEEK_OFF = 42;
    pub const NOFCS = 43;
    pub const LOCK_FILTER = 44;
    pub const SELECT_ERR_QUEUE = 45;
    pub const BUSY_POLL = 46;
    pub const MAX_PACING_RATE = 47;
    pub const BPF_EXTENSIONS = 48;
    pub const INCOMING_CPU = 49;
    pub const ATTACH_BPF = 50;
    pub const DETACH_BPF = DETACH_FILTER;
    pub const ATTACH_REUSEPORT_CBPF = 51;
    pub const ATTACH_REUSEPORT_EBPF = 52;
    pub const CNX_ADVICE = 53;
    pub const MEMINFO = 55;
    pub const INCOMING_NAPI_ID = 56;
    pub const COOKIE = 57;
    pub const PEERGROUPS = 59;
    pub const ZEROCOPY = 60;
    pub const TXTIME = 61;
    pub const BINDTOIFINDEX = 62;
    pub const TIMESTAMP_NEW = 63;
    pub const TIMESTAMPNS_NEW = 64;
    pub const TIMESTAMPING_NEW = 65;
    pub const RCVTIMEO_NEW = 66;
    pub const SNDTIMEO_NEW = 67;
    pub const DETACH_REUSEPORT_BPF = 68;
};

pub const SOCK = struct {
    pub const STREAM = 1;
    pub const DGRAM = 2;
    pub const RAW = 3;
    pub const RDM = 4;
    pub const SEQPACKET = 5;
    pub const DCCP = 6;
    pub const PACKET = 10;
    pub const CLOEXEC = 0o2000000;
    pub const NONBLOCK = 0o4000;
};

pub const SOL = struct {
    pub const SOCKET = 1;

    pub const IP = 0;
    pub const IPV6 = 41;
    pub const ICMPV6 = 58;

    pub const RAW = 255;
    pub const DECNET = 261;
    pub const X25 = 262;
    pub const PACKET = 263;
    pub const ATM = 264;
    pub const AAL = 265;
    pub const IRDA = 266;
    pub const NETBEUI = 267;
    pub const LLC = 268;
    pub const DCCP = 269;
    pub const NETLINK = 270;
    pub const TIPC = 271;
    pub const RXRPC = 272;
    pub const PPPOL2TP = 273;
    pub const BLUETOOTH = 274;
    pub const PNPIPE = 275;
    pub const RDS = 276;
    pub const IUCV = 277;
    pub const CAIF = 278;
    pub const ALG = 279;
    pub const NFC = 280;
    pub const KCM = 281;
    pub const TLS = 282;
    pub const XDP = 283;
};

pub const STDIN_FILENO = 0;
pub const STDOUT_FILENO = 1;
pub const STDERR_FILENO = 2;

pub const TCP = struct {
    pub const NODELAY = 1;
    pub const MAXSEG = 2;
    pub const CORK = 3;
    pub const KEEPIDLE = 4;
    pub const KEEPINTVL = 5;
    pub const KEEPCNT = 6;
    pub const SYNCNT = 7;
    pub const LINGER2 = 8;
    pub const DEFER_ACCEPT = 9;
    pub const WINDOW_CLAMP = 10;
    pub const INFO = 11;
    pub const QUICKACK = 12;
    pub const CONGESTION = 13;
    pub const MD5SIG = 14;
    pub const THIN_LINEAR_TIMEOUTS = 16;
    pub const THIN_DUPACK = 17;
    pub const USER_TIMEOUT = 18;
    pub const REPAIR = 19;
    pub const REPAIR_QUEUE = 20;
    pub const QUEUE_SEQ = 21;
    pub const REPAIR_OPTIONS = 22;
    pub const FASTOPEN = 23;
    pub const TIMESTAMP = 24;
    pub const NOTSENT_LOWAT = 25;
    pub const CC_INFO = 26;
    pub const SAVE_SYN = 27;
    pub const SAVED_SYN = 28;
    pub const REPAIR_WINDOW = 29;
    pub const FASTOPEN_CONNECT = 30;
    pub const ULP = 31;
    pub const MD5SIG_EXT = 32;
    pub const FASTOPEN_KEY = 33;
    pub const FASTOPEN_NO_COOKIE = 34;
    pub const ZEROCOPY_RECEIVE = 35;
    pub const INQ = 36;
    pub const CM_INQ = INQ;
    pub const TX_DELAY = 37;

    pub const REPAIR_ON = 1;
    pub const REPAIR_OFF = 0;
    pub const REPAIR_OFF_NO_WP = -1;
};

pub const TCSA = std.posix.TCSA;
pub const addrinfo = c.addrinfo;

pub const in_port_t = c.in_port_t;
pub const sa_family_t = c.sa_family_t;
pub const socklen_t = c.socklen_t;
pub const sockaddr = c.sockaddr;

pub const blksize_t = i32;
pub const nlink_t = u32;
pub const time_t = i64;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u32;
pub const blkcnt_t = i32;

pub const pid_t = i32;
pub const fd_t = c.fd_t;
pub const uid_t = u32;
pub const gid_t = u32;
pub const clock_t = i32;

pub const dl_phdr_info = extern struct {
    addr: usize,
    name: ?[*:0]const u8,
    phdr: [*]std.elf.Phdr,
    phnum: u16,
};

pub const mcontext_t = extern struct {
    gregs: [19]usize,
    fpregs: [*]u8,
    oldmask: usize,
    cr2: usize,
};

pub const msghdr = std.c.msghdr;
pub const msghdr_const = std.c.msghdr;

pub const nfds_t = usize;
pub const pollfd = extern struct {
    fd: fd_t,
    events: i16,
    revents: i16,
};

pub const stack_t = extern struct {
    sp: [*]u8,
    flags: i32,
    size: usize,
};

pub const timespec = extern struct {
    sec: time_t,
    nsec: isize,
};

pub const timezone = extern struct {
    minuteswest: i32,
    dsttime: i32,
};

pub const ucontext_t = extern struct {
    flags: usize,
    link: ?*ucontext_t,
    stack: stack_t,
    mcontext: mcontext_t,
    sigmask: sigset_t,
    regspace: [28]usize,
};

pub const utsname = extern struct {
    sysname: [64:0]u8,
    nodename: [64:0]u8,
    release: [64:0]u8,
    version: [64:0]u8,
    machine: [64:0]u8,
    domainname: [64:0]u8,
};

pub const Stat = extern struct {
    dev: dev_t,
    mode: mode_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
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

pub const TIMING = struct {
    pub const SETTIMEOUT = 0;
    pub const RAF = 1;
    pub const SETIMMEDIATE = 2;
};

pub const LOG = struct {
    pub const CONSOLE = 1;
    pub const WARN = 2;
    pub const ERROR = 4;
    pub const C_STACK = 8;
    pub const JS_STACK = 16;
    pub const DEMANGLE = 32;
    pub const NO_PATHS = 64;
    pub const FUNC_PARAMS = 128;
    pub const DEBUG = 256;
    pub const INFO = 512;
};

pub const em_callback_func = ?*const fn () callconv(.c) void;
pub const em_arg_callback_func = ?*const fn (?*anyopaque) callconv(.c) void;
pub const em_str_callback_func = ?*const fn ([*:0]const u8) callconv(.c) void;

pub extern "c" fn emscripten_async_wget(url: [*:0]const u8, file: [*:0]const u8, onload: em_str_callback_func, onerror: em_str_callback_func) void;

pub const em_async_wget_onload_func = ?*const fn (?*anyopaque, ?*anyopaque, c_int) callconv(.c) void;
pub extern "c" fn emscripten_async_wget_data(url: [*:0]const u8, arg: ?*anyopaque, onload: em_async_wget_onload_func, onerror: em_arg_callback_func) void;

pub const em_async_wget2_onload_func = ?*const fn (c_uint, ?*anyopaque, [*:0]const u8) callconv(.c) void;
pub const em_async_wget2_onstatus_func = ?*const fn (c_uint, ?*anyopaque, c_int) callconv(.c) void;

pub extern "c" fn emscripten_async_wget2(url: [*:0]const u8, file: [*:0]const u8, requesttype: [*:0]const u8, param: [*:0]const u8, arg: ?*anyopaque, onload: em_async_wget2_onload_func, onerror: em_async_wget2_onstatus_func, onprogress: em_async_wget2_onstatus_func) c_int;

pub const em_async_wget2_data_onload_func = ?*const fn (c_uint, ?*anyopaque, ?*anyopaque, c_uint) callconv(.c) void;
pub const em_async_wget2_data_onerror_func = ?*const fn (c_uint, ?*anyopaque, c_int, [*:0]const u8) callconv(.c) void;
pub const em_async_wget2_data_onprogress_func = ?*const fn (c_uint, ?*anyopaque, c_int, c_int) callconv(.c) void;

pub extern "c" fn emscripten_async_wget2_data(url: [*:0]const u8, requesttype: [*:0]const u8, param: [*:0]const u8, arg: ?*anyopaque, free: c_int, onload: em_async_wget2_data_onload_func, onerror: em_async_wget2_data_onerror_func, onprogress: em_async_wget2_data_onprogress_func) c_int;
pub extern "c" fn emscripten_async_wget2_abort(handle: c_int) void;
pub extern "c" fn emscripten_wget(url: [*:0]const u8, file: [*:0]const u8) c_int;
pub extern "c" fn emscripten_wget_data(url: [*:0]const u8, pbuffer: *(?*anyopaque), pnum: *c_int, perror: *c_int) void;
pub extern "c" fn emscripten_run_script(script: [*:0]const u8) void;
pub extern "c" fn emscripten_run_script_int(script: [*:0]const u8) c_int;
pub extern "c" fn emscripten_run_script_string(script: [*:0]const u8) [*:0]u8;
pub extern "c" fn emscripten_async_run_script(script: [*:0]const u8, millis: c_int) void;
pub extern "c" fn emscripten_async_load_script(script: [*:0]const u8, onload: em_callback_func, onerror: em_callback_func) void;
pub extern "c" fn emscripten_set_main_loop(func: em_callback_func, fps: c_int, simulate_infinite_loop: c_int) void;
pub extern "c" fn emscripten_set_main_loop_timing(mode: c_int, value: c_int) c_int;
pub extern "c" fn emscripten_get_main_loop_timing(mode: *c_int, value: *c_int) void;
pub extern "c" fn emscripten_set_main_loop_arg(func: em_arg_callback_func, arg: ?*anyopaque, fps: c_int, simulate_infinite_loop: c_int) void;
pub extern "c" fn emscripten_pause_main_loop() void;
pub extern "c" fn emscripten_resume_main_loop() void;
pub extern "c" fn emscripten_cancel_main_loop() void;

pub const em_socket_callback = ?*const fn (c_int, ?*anyopaque) callconv(.c) void;
pub const em_socket_error_callback = ?*const fn (c_int, c_int, [*:0]const u8, ?*anyopaque) callconv(.c) void;

pub extern "c" fn emscripten_set_socket_error_callback(userData: ?*anyopaque, callback: em_socket_error_callback) void;
pub extern "c" fn emscripten_set_socket_open_callback(userData: ?*anyopaque, callback: em_socket_callback) void;
pub extern "c" fn emscripten_set_socket_listen_callback(userData: ?*anyopaque, callback: em_socket_callback) void;
pub extern "c" fn emscripten_set_socket_connection_callback(userData: ?*anyopaque, callback: em_socket_callback) void;
pub extern "c" fn emscripten_set_socket_message_callback(userData: ?*anyopaque, callback: em_socket_callback) void;
pub extern "c" fn emscripten_set_socket_close_callback(userData: ?*anyopaque, callback: em_socket_callback) void;
pub extern "c" fn _emscripten_push_main_loop_blocker(func: em_arg_callback_func, arg: ?*anyopaque, name: [*:0]const u8) void;
pub extern "c" fn _emscripten_push_uncounted_main_loop_blocker(func: em_arg_callback_func, arg: ?*anyopaque, name: [*:0]const u8) void;
pub extern "c" fn emscripten_set_main_loop_expected_blockers(num: c_int) void;
pub extern "c" fn emscripten_async_call(func: em_arg_callback_func, arg: ?*anyopaque, millis: c_int) void;
pub extern "c" fn emscripten_exit_with_live_runtime() noreturn;
pub extern "c" fn emscripten_force_exit(status: c_int) noreturn;
pub extern "c" fn emscripten_get_device_pixel_ratio() f64;
pub extern "c" fn emscripten_get_window_title() [*:0]u8;
pub extern "c" fn emscripten_set_window_title([*:0]const u8) void;
pub extern "c" fn emscripten_get_screen_size(width: *c_int, height: *c_int) void;
pub extern "c" fn emscripten_hide_mouse() void;
pub extern "c" fn emscripten_set_canvas_size(width: c_int, height: c_int) void;
pub extern "c" fn emscripten_get_canvas_size(width: *c_int, height: *c_int, isFullscreen: *c_int) void;
pub extern "c" fn emscripten_get_now() f64;
pub extern "c" fn emscripten_random() f32;
pub const em_idb_onload_func = ?*const fn (?*anyopaque, ?*anyopaque, c_int) callconv(.c) void;
pub extern "c" fn emscripten_idb_async_load(db_name: [*:0]const u8, file_id: [*:0]const u8, arg: ?*anyopaque, onload: em_idb_onload_func, onerror: em_arg_callback_func) void;
pub extern "c" fn emscripten_idb_async_store(db_name: [*:0]const u8, file_id: [*:0]const u8, ptr: ?*anyopaque, num: c_int, arg: ?*anyopaque, onstore: em_arg_callback_func, onerror: em_arg_callback_func) void;
pub extern "c" fn emscripten_idb_async_delete(db_name: [*:0]const u8, file_id: [*:0]const u8, arg: ?*anyopaque, ondelete: em_arg_callback_func, onerror: em_arg_callback_func) void;
pub const em_idb_exists_func = ?*const fn (?*anyopaque, c_int) callconv(.c) void;
pub extern "c" fn emscripten_idb_async_exists(db_name: [*:0]const u8, file_id: [*:0]const u8, arg: ?*anyopaque, oncheck: em_idb_exists_func, onerror: em_arg_callback_func) void;
pub extern "c" fn emscripten_idb_load(db_name: [*:0]const u8, file_id: [*:0]const u8, pbuffer: *?*anyopaque, pnum: *c_int, perror: *c_int) void;
pub extern "c" fn emscripten_idb_store(db_name: [*:0]const u8, file_id: [*:0]const u8, buffer: *anyopaque, num: c_int, perror: *c_int) void;
pub extern "c" fn emscripten_idb_delete(db_name: [*:0]const u8, file_id: [*:0]const u8, perror: *c_int) void;
pub extern "c" fn emscripten_idb_exists(db_name: [*:0]const u8, file_id: [*:0]const u8, pexists: *c_int, perror: *c_int) void;
pub extern "c" fn emscripten_idb_load_blob(db_name: [*:0]const u8, file_id: [*:0]const u8, pblob: *c_int, perror: *c_int) void;
pub extern "c" fn emscripten_idb_store_blob(db_name: [*:0]const u8, file_id: [*:0]const u8, buffer: *anyopaque, num: c_int, perror: *c_int) void;
pub extern "c" fn emscripten_idb_read_from_blob(blob: c_int, start: c_int, num: c_int, buffer: ?*anyopaque) void;
pub extern "c" fn emscripten_idb_free_blob(blob: c_int) void;
pub extern "c" fn emscripten_run_preload_plugins(file: [*:0]const u8, onload: em_str_callback_func, onerror: em_str_callback_func) c_int;
pub const em_run_preload_plugins_data_onload_func = ?*const fn (?*anyopaque, [*:0]const u8) callconv(.c) void;
pub extern "c" fn emscripten_run_preload_plugins_data(data: [*]u8, size: c_int, suffix: [*:0]const u8, arg: ?*anyopaque, onload: em_run_preload_plugins_data_onload_func, onerror: em_arg_callback_func) void;
pub extern "c" fn emscripten_lazy_load_code() void;
pub const worker_handle = c_int;
pub extern "c" fn emscripten_create_worker(url: [*:0]const u8) worker_handle;
pub extern "c" fn emscripten_destroy_worker(worker: worker_handle) void;
pub const em_worker_callback_func = ?*const fn ([*]u8, c_int, ?*anyopaque) callconv(.c) void;
pub extern "c" fn emscripten_call_worker(worker: worker_handle, funcname: [*:0]const u8, data: [*]u8, size: c_int, callback: em_worker_callback_func, arg: ?*anyopaque) void;
pub extern "c" fn emscripten_worker_respond(data: [*]u8, size: c_int) void;
pub extern "c" fn emscripten_worker_respond_provisionally(data: [*]u8, size: c_int) void;
pub extern "c" fn emscripten_get_worker_queue_size(worker: worker_handle) c_int;
pub extern "c" fn emscripten_get_compiler_setting(name: [*:0]const u8) c_long;
pub extern "c" fn emscripten_has_asyncify() c_int;
pub extern "c" fn emscripten_debugger() void;

pub extern "c" fn emscripten_get_preloaded_image_data(path: [*:0]const u8, w: *c_int, h: *c_int) ?[*]u8;
pub extern "c" fn emscripten_get_preloaded_image_data_from_FILE(file: *FILE, w: *c_int, h: *c_int) ?[*]u8;
pub extern "c" fn emscripten_log(flags: c_int, format: [*:0]const u8, ...) void;
pub extern "c" fn emscripten_get_callstack(flags: c_int, out: ?[*]u8, maxbytes: c_int) c_int;
pub extern "c" fn emscripten_print_double(x: f64, to: ?[*]u8, max: c_int) c_int;
pub const em_scan_func = ?*const fn (?*anyopaque, ?*anyopaque) callconv(.c) void;
pub extern "c" fn emscripten_scan_registers(func: em_scan_func) void;
pub extern "c" fn emscripten_scan_stack(func: em_scan_func) void;
pub const em_dlopen_callback = ?*const fn (?*anyopaque, ?*anyopaque) callconv(.c) void;
pub extern "c" fn emscripten_dlopen(filename: [*:0]const u8, flags: c_int, user_data: ?*anyopaque, onsuccess: em_dlopen_callback, onerror: em_arg_callback_func) void;
pub extern "c" fn emscripten_dlopen_promise(filename: [*:0]const u8, flags: c_int) em_promise_t;
pub extern "c" fn emscripten_throw_number(number: f64) void;
pub extern "c" fn emscripten_throw_string(utf8String: [*:0]const u8) void;
pub extern "c" fn emscripten_sleep(ms: c_uint) void;

pub const PROMISE = struct {
    pub const FULFILL = 0;
    pub const MATCH = 1;
    pub const MATCH_RELEASE = 2;
    pub const REJECT = 3;
};

pub const struct__em_promise = opaque {};
pub const em_promise_t = ?*struct__em_promise;
pub const enum_em_promise_result_t = c_uint;
pub const em_promise_result_t = enum_em_promise_result_t;
pub const em_promise_callback_t = ?*const fn (?*?*anyopaque, ?*anyopaque, ?*anyopaque) callconv(.c) em_promise_result_t;

pub extern "c" fn emscripten_promise_create() em_promise_t;
pub extern "c" fn emscripten_promise_destroy(promise: em_promise_t) void;
pub extern "c" fn emscripten_promise_resolve(promise: em_promise_t, result: em_promise_result_t, value: ?*anyopaque) void;
pub extern "c" fn emscripten_promise_then(promise: em_promise_t, on_fulfilled: em_promise_callback_t, on_rejected: em_promise_callback_t, data: ?*anyopaque) em_promise_t;
pub extern "c" fn emscripten_promise_all(promises: [*]em_promise_t, results: ?[*]?*anyopaque, num_promises: usize) em_promise_t;

pub const struct_em_settled_result_t = extern struct {
    result: em_promise_result_t,
    value: ?*anyopaque,
};
pub const em_settled_result_t = struct_em_settled_result_t;
//! This file provides the system interface functions for Linux matching those
//! that are provided by libc, whether or not libc is linked. The following
//! abstractions are made:
//! * Work around kernel bugs and limitations. For example, see sendmmsg.
//! * Implement all the syscalls in the same way that libc functions will
//!   provide `rename` when only the `renameat` syscall exists.
//! * Does not support POSIX thread cancellation.
const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const maxInt = std.math.maxInt;
const elf = std.elf;
const vdso = @import("linux/vdso.zig");
const dl = @import("../dynamic_library.zig");
const native_arch = builtin.cpu.arch;
const native_abi = builtin.abi;
const native_endian = native_arch.endian();
const is_mips = native_arch.isMIPS();
const is_ppc = native_arch.isPowerPC();
const is_sparc = native_arch.isSPARC();
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const winsize = std.posix.winsize;
const ACCMODE = std.posix.ACCMODE;

test {
    if (builtin.os.tag == .linux) {
        _ = @import("linux/test.zig");
    }
}

const arch_bits = switch (native_arch) {
    .x86 => @import("linux/x86.zig"),
    .x86_64 => @import("linux/x86_64.zig"),
    .aarch64, .aarch64_be => @import("linux/aarch64.zig"),
    .arm, .armeb, .thumb, .thumbeb => @import("linux/arm.zig"),
    .hexagon => @import("linux/hexagon.zig"),
    .riscv32 => @import("linux/riscv32.zig"),
    .riscv64 => @import("linux/riscv64.zig"),
    .sparc64 => @import("linux/sparc64.zig"),
    .loongarch64 => @import("linux/loongarch64.zig"),
    .m68k => @import("linux/m68k.zig"),
    .mips, .mipsel => @import("linux/mips.zig"),
    .mips64, .mips64el => @import("linux/mips64.zig"),
    .powerpc, .powerpcle => @import("linux/powerpc.zig"),
    .powerpc64, .powerpc64le => @import("linux/powerpc64.zig"),
    .s390x => @import("linux/s390x.zig"),
    else => struct {
        pub const ucontext_t = void;
        pub const getcontext = {};
    },
};

const syscall_bits = if (native_arch.isThumb()) @import("linux/thumb.zig") else arch_bits;

pub const syscall0 = syscall_bits.syscall0;
pub const syscall1 = syscall_bits.syscall1;
pub const syscall2 = syscall_bits.syscall2;
pub const syscall3 = syscall_bits.syscall3;
pub const syscall4 = syscall_bits.syscall4;
pub const syscall5 = syscall_bits.syscall5;
pub const syscall6 = syscall_bits.syscall6;
pub const syscall7 = syscall_bits.syscall7;
pub const restore = syscall_bits.restore;
pub const restore_rt = syscall_bits.restore_rt;
pub const socketcall = syscall_bits.socketcall;
pub const syscall_pipe = syscall_bits.syscall_pipe;
pub const syscall_fork = syscall_bits.syscall_fork;

pub fn clone(
    func: *const fn (arg: usize) callconv(.c) u8,
    stack: usize,
    flags: u32,
    arg: usize,
    ptid: ?*i32,
    tp: usize, // aka tls
    ctid: ?*i32,
) usize {
    // Can't directly call a naked function; cast to C calling convention first.
    return @as(*const fn (
        *const fn (arg: usize) callconv(.c) u8,
        usize,
        u32,
        usize,
        ?*i32,
        usize,
        ?*i32,
    ) callconv(.c) usize, @ptrCast(&syscall_bits.clone))(func, stack, flags, arg, ptid, tp, ctid);
}

pub const ARCH = arch_bits.ARCH;
pub const Elf_Symndx = arch_bits.Elf_Symndx;
pub const F = arch_bits.F;
pub const Flock = arch_bits.Flock;
pub const HWCAP = arch_bits.HWCAP;
pub const REG = arch_bits.REG;
pub const SC = arch_bits.SC;
pub const Stat = arch_bits.Stat;
pub const VDSO = arch_bits.VDSO;
pub const blkcnt_t = arch_bits.blkcnt_t;
pub const blksize_t = arch_bits.blksize_t;
pub const dev_t = arch_bits.dev_t;
pub const ino_t = arch_bits.ino_t;
pub const mcontext_t = arch_bits.mcontext_t;
pub const mode_t = arch_bits.mode_t;
pub const msghdr = arch_bits.msghdr;
pub const msghdr_const = arch_bits.msghdr_const;
pub const nlink_t = arch_bits.nlink_t;
pub const off_t = arch_bits.off_t;
pub const time_t = arch_bits.time_t;
pub const timeval = arch_bits.timeval;
pub const timezone = arch_bits.timezone;
pub const ucontext_t = arch_bits.ucontext_t;
pub const user_desc = arch_bits.user_desc;
pub const getcontext = arch_bits.getcontext;

pub const tls = @import("linux/tls.zig");
pub const pie = @import("linux/pie.zig");
pub const BPF = @import("linux/bpf.zig");
pub const IOCTL = @import("linux/ioctl.zig");
pub const SECCOMP = @import("linux/seccomp.zig");

pub const syscalls = @import("linux/syscalls.zig");
pub const SYS = switch (@import("builtin").cpu.arch) {
    .arc => syscalls.Arc,
    .arm, .armeb, .thumb, .thumbeb => syscalls.Arm,
    .aarch64, .aarch64_be => syscalls.Arm64,
    .csky => syscalls.CSky,
    .hexagon => syscalls.Hexagon,
    .loongarch64 => syscalls.LoongArch64,
    .m68k => syscalls.M68k,
    .mips, .mipsel => syscalls.MipsO32,
    .mips64, .mips64el => switch (builtin.abi) {
        .gnuabin32, .muslabin32 => syscalls.MipsN32,
        else => syscalls.MipsN64,
    },
    .riscv32 => syscalls.RiscV32,
    .riscv64 => syscalls.RiscV64,
    .s390x => syscalls.S390x,
    .sparc => syscalls.Sparc,
    .sparc64 => syscalls.Sparc64,
    .powerpc, .powerpcle => syscalls.PowerPC,
    .powerpc64, .powerpc64le => syscalls.PowerPC64,
    .x86 => syscalls.X86,
    .x86_64 => switch (builtin.abi) {
        .gnux32, .muslx32 => syscalls.X32,
        else => syscalls.X64,
    },
    .xtensa => syscalls.Xtensa,
    else => @compileError("The Zig Standard Library is missing syscall definitions for the target CPU architecture"),
};

pub const MAP_TYPE = enum(u4) {
    SHARED = 0x01,
    PRIVATE = 0x02,
    SHARED_VALIDATE = 0x03,
};

pub const MAP = switch (native_arch) {
    .x86_64, .x86 => packed struct(u32) {
        TYPE: MAP_TYPE,
        FIXED: bool = false,
        ANONYMOUS: bool = false,
        @"32BIT": bool = false,
        _7: u1 = 0,
        GROWSDOWN: bool = false,
        _9: u2 = 0,
        DENYWRITE: bool = false,
        EXECUTABLE: bool = false,
        LOCKED: bool = false,
        NORESERVE: bool = false,
        POPULATE: bool = false,
        NONBLOCK: bool = false,
        STACK: bool = false,
        HUGETLB: bool = false,
        SYNC: bool = false,
        FIXED_NOREPLACE: bool = false,
        _21: u5 = 0,
        UNINITIALIZED: bool = false,
        _: u5 = 0,
    },
    .aarch64, .aarch64_be, .arm, .armeb, .thumb, .thumbeb => packed struct(u32) {
        TYPE: MAP_TYPE,
        FIXED: bool = false,
        ANONYMOUS: bool = false,
        _6: u2 = 0,
        GROWSDOWN: bool = false,
        _9: u2 = 0,
        DENYWRITE: bool = false,
        EXECUTABLE: bool = false,
        LOCKED: bool = false,
        NORESERVE: bool = false,
        POPULATE: bool = false,
        NONBLOCK: bool = false,
        STACK: bool = false,
        HUGETLB: bool = false,
        SYNC: bool = false,
        FIXED_NOREPLACE: bool = false,
        _21: u5 = 0,
        UNINITIALIZED: bool = false,
        _: u5 = 0,
    },
    .riscv32, .riscv64, .loongarch64 => packed struct(u32) {
        TYPE: MAP_TYPE,
        FIXED: bool = false,
        ANONYMOUS: bool = false,
        _6: u9 = 0,
        POPULATE: bool = false,
        NONBLOCK: bool = false,
        STACK: bool = false,
        HUGETLB: bool = false,
        SYNC: bool = false,
        FIXED_NOREPLACE: bool = false,
        _21: u5 = 0,
        UNINITIALIZED: bool = false,
        _: u5 = 0,
    },
    .sparc64 => packed struct(u32) {
        TYPE: MAP_TYPE,
        FIXED: bool = false,
        ANONYMOUS: bool = false,
        NORESERVE: bool = false,
        _7: u1 = 0,
        LOCKED: bool = false,
        GROWSDOWN: bool = false,
        _10: u1 = 0,
        DENYWRITE: bool = false,
        EXECUTABLE: bool = false,
        _13: u2 = 0,
        POPULATE: bool = false,
        NONBLOCK: bool = false,
        STACK: bool = false,
        HUGETLB: bool = false,
        SYNC: bool = false,
        FIXED_NOREPLACE: bool = false,
        _21: u5 = 0,
        UNINITIALIZED: bool = false,
        _: u5 = 0,
    },
    .mips, .mipsel, .mips64, .mips64el => packed struct(u32) {
        TYPE: MAP_TYPE,
        FIXED: bool = false,
        _5: u1 = 0,
        @"32BIT": bool = false,
        _7: u3 = 0,
        NORESERVE: bool = false,
        ANONYMOUS: bool = false,
        GROWSDOWN: bool = false,
        DENYWRITE: bool = false,
        EXECUTABLE: bool = false,
        LOCKED: bool = false,
        POPULATE: bool = false,
        NONBLOCK: bool = false,
        STACK: bool = false,
        HUGETLB: bool = false,
        FIXED_NOREPLACE: bool = false,
        _21: u5 = 0,
        UNINITIALIZED: bool = false,
        _: u5 = 0,
    },
    .powerpc, .powerpcle, .powerpc64, .powerpc64le => packed struct(u32) {
        TYPE: MAP_TYPE,
        FIXED: bool = false,
        ANONYMOUS: bool = false,
        NORESERVE: bool = false,
        LOCKED: bool = false,
        GROWSDOWN: bool = false,
        _9: u2 = 0,
        DENYWRITE: bool = false,
        EXECUTABLE: bool = false,
        _13: u2 = 0,
        POPULATE: bool = false,
        NONBLOCK: bool = false,
        STACK: bool = false,
        HUGETLB: bool = false,
        SYNC: bool = false,
        FIXED_NOREPLACE: bool = false,
        _21: u5 = 0,
        UNINITIALIZED: bool = false,
        _: u5 = 0,
    },
    .hexagon, .m68k, .s390x => packed struct(u32) {
        TYPE: MAP_TYPE,
        FIXED: bool = false,
        ANONYMOUS: bool = false,
        _4: u1 = 0,
        _5: u1 = 0,
        GROWSDOWN: bool = false,
        _7: u1 = 0,
        _8: u1 = 0,
        DENYWRITE: bool = false,
        EXECUTABLE: bool = false,
        LOCKED: bool = false,
        NORESERVE: bool = false,
        POPULATE: bool = false,
        NONBLOCK: bool = false,
        STACK: bool = false,
        HUGETLB: bool = false,
        SYNC: bool = false,
        FIXED_NOREPLACE: bool = false,
        _19: u5 = 0,
        UNINITIALIZED: bool = false,
        _: u5 = 0,
    },
    else => @compileError("missing std.os.linux.MAP constants for this architecture"),
};

pub const MREMAP = packed struct(u32) {
    MAYMOVE: bool = false,
    FIXED: bool = false,
    DONTUNMAP: bool = false,
    _: u29 = 0,
};

pub const O = switch (native_arch) {
    .x86_64 => packed struct(u32) {
        ACCMODE: ACCMODE = .RDONLY,
        _2: u4 = 0,
        CREAT: bool = false,
        EXCL: bool = false,
        NOCTTY: bool = false,
        TRUNC: bool = false,
        APPEND: bool = false,
        NONBLOCK: bool = false,
        DSYNC: bool = false,
        ASYNC: bool = false,
        DIRECT: bool = false,
        _15: u1 = 0,
        DIRECTORY: bool = false,
        NOFOLLOW: bool = false,
        NOATIME: bool = false,
        CLOEXEC: bool = false,
        SYNC: bool = false,
        PATH: bool = false,
        TMPFILE: bool = false,
        _23: u9 = 0,
    },
    .x86, .riscv32, .riscv64, .loongarch64 => packed struct(u32) {
        ACCMODE: ACCMODE = .RDONLY,
        _2: u4 = 0,
        CREAT: bool = false,
        EXCL: bool = false,
        NOCTTY: bool = false,
        TRUNC: bool = false,
        APPEND: bool = false,
        NONBLOCK: bool = false,
        DSYNC: bool = false,
        ASYNC: bool = false,
        DIRECT: bool = false,
        LARGEFILE: bool = false,
        DIRECTORY: bool = false,
        NOFOLLOW: bool = false,
        NOATIME: bool = false,
        CLOEXEC: bool = false,
        SYNC: bool = false,
        PATH: bool = false,
        TMPFILE: bool = false,
        _23: u9 = 0,
    },
    .aarch64, .aarch64_be, .arm, .armeb, .thumb, .thumbeb => packed struct(u32) {
        ACCMODE: ACCMODE = .RDONLY,
        _2: u4 = 0,
        CREAT: bool = false,
        EXCL: bool = false,
        NOCTTY: bool = false,
        TRUNC: bool = false,
        APPEND: bool = false,
        NONBLOCK: bool = false,
        DSYNC: bool = false,
        ASYNC: bool = false,
        DIRECTORY: bool = false,
        NOFOLLOW: bool = false,
        DIRECT: bool = false,
        LARGEFILE: bool = false,
        NOATIME: bool = false,
        CLOEXEC: bool = false,
        SYNC: bool = false,
        PATH: bool = false,
        TMPFILE: bool = false,
        _23: u9 = 0,
    },
    .sparc64 => packed struct(u32) {
        ACCMODE: ACCMODE = .RDONLY,
        _2: u1 = 0,
        APPEND: bool = false,
        _4: u2 = 0,
        ASYNC: bool = false,
        _7: u2 = 0,
        CREAT: bool = false,
        TRUNC: bool = false,
        EXCL: bool = false,
        _12: u1 = 0,
        DSYNC: bool = false,
        NONBLOCK: bool = false,
        NOCTTY: bool = false,
        DIRECTORY: bool = false,
        NOFOLLOW: bool = false,
        _18: u2 = 0,
        DIRECT: bool = false,
        NOATIME: bool = false,
        CLOEXEC: bool = false,
        SYNC: bool = false,
        PATH: bool = false,
        TMPFILE: bool = false,
        _27: u6 = 0,
    },
    .mips, .mipsel, .mips64, .mips64el => packed struct(u32) {
        ACCMODE: ACCMODE = .RDONLY,
        _2: u1 = 0,
        APPEND: bool = false,
        DSYNC: bool = false,
        _5: u2 = 0,
        NONBLOCK: bool = false,
        CREAT: bool = false,
        TRUNC: bool = false,
        EXCL: bool = false,
        NOCTTY: bool = false,
        ASYNC: bool = false,
        LARGEFILE: bool = false,
        SYNC: bool = false,
        DIRECT: bool = false,
        DIRECTORY: bool = false,
        NOFOLLOW: bool = false,
        NOATIME: bool = false,
        CLOEXEC: bool = false,
        _20: u1 = 0,
        PATH: bool = false,
        TMPFILE: bool = false,
        _23: u9 = 0,
    },
    .powerpc, .powerpcle, .powerpc64, .powerpc64le =>```
