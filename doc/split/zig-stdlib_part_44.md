```
rts_decoder.decode(u16);
                                const all_extd = try certs_decoder.sub(total_ext_size);
                                _ = all_extd;
                            }

                            const subject_cert: Certificate = .{
                                .buffer = certd.buf,
                                .index = @intCast(certd.idx),
                            };
                            const subject = try subject_cert.parse();
                            if (cert_index == 0) {
                                // Verify the host on the first certificate.
                                switch (options.host) {
                                    .no_verification => {},
                                    .explicit => try subject.verifyHostName(host),
                                }

                                // Keep track of the public key for the
                                // certificate_verify message later.
                                try main_cert_pub_key.init(subject.pub_key_algo, subject.pubKey());
                            } else {
                                try prev_cert.verify(subject, now_sec);
                            }

                            switch (options.ca) {
                                .no_verification => {
                                    handshake_state = .trust_chain_established;
                                    break :cert;
                                },
                                .self_signed => {
                                    try subject.verify(subject, now_sec);
                                    handshake_state = .trust_chain_established;
                                    break :cert;
                                },
                                .bundle => |ca_bundle| if (ca_bundle.verify(subject, now_sec)) |_| {
                                    handshake_state = .trust_chain_established;
                                    break :cert;
                                } else |err| switch (err) {
                                    error.CertificateIssuerNotFound => {},
                                    else => |e| return e,
                                },
                            }

                            prev_cert = subject;
                            cert_index += 1;
                        }
                        cert_buf_index += 1;
                    },
                    .server_key_exchange => {
                        if (tls_version != .tls_1_2) return error.TlsUnexpectedMessage;
                        if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                        switch (handshake_state) {
                            .trust_chain_established => {},
                            .certificate => return error.TlsCertificateNotVerified,
                            else => return error.TlsUnexpectedMessage,
                        }

                        switch (handshake_cipher) {
                            inline else => |*p| p.transcript_hash.update(wrapped_handshake),
                        }
                        try hsd.ensure(1 + 2 + 1);
                        const curve_type = hsd.decode(u8);
                        if (curve_type != 0x03) return error.TlsIllegalParameter; // named_curve
                        const named_group = hsd.decode(tls.NamedGroup);
                        const key_size = hsd.decode(u8);
                        try hsd.ensure(key_size);
                        const server_pub_key = hsd.slice(key_size);
                        try main_cert_pub_key.verifySignature(&hsd, &.{ &client_hello_rand, &server_hello_rand, hsd.buf[0..hsd.idx] });
                        try key_share.exchange(named_group, server_pub_key);
                        handshake_state = .server_hello_done;
                    },
                    .server_hello_done => {
                        if (tls_version != .tls_1_2) return error.TlsUnexpectedMessage;
                        if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .server_hello_done) return error.TlsUnexpectedMessage;

                        const client_key_exchange_msg = .{@intFromEnum(tls.ContentType.handshake)} ++
                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                            array(u16, u8, .{@intFromEnum(tls.HandshakeType.client_key_exchange)} ++
                                array(u24, u8, array(u8, u8, key_share.secp256r1_kp.public_key.toUncompressedSec1())));
                        const client_change_cipher_spec_msg = .{@intFromEnum(tls.ContentType.change_cipher_spec)} ++
                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                            array(u16, tls.ChangeCipherSpecType, .{.change_cipher_spec});
                        const pre_master_secret = key_share.getSharedSecret().?;
                        switch (handshake_cipher) {
                            inline else => |*p| {
                                const P = @TypeOf(p.*).A;
                                p.transcript_hash.update(wrapped_handshake);
                                p.transcript_hash.update(client_key_exchange_msg[tls.record_header_len..]);
                                const master_secret = hmacExpandLabel(P.Hmac, pre_master_secret, &.{
                                    "master secret",
                                    &client_hello_rand,
                                    &server_hello_rand,
                                }, 48);
                                if (options.ssl_key_log_file) |key_log_file| logSecrets(key_log_file, .{
                                    .client_random = &client_hello_rand,
                                }, .{
                                    .CLIENT_RANDOM = &master_secret,
                                });
                                const key_block = hmacExpandLabel(
                                    P.Hmac,
                                    &master_secret,
                                    &.{ "key expansion", &server_hello_rand, &client_hello_rand },
                                    @sizeOf(P.Tls_1_2),
                                );
                                const client_verify_cleartext = .{@intFromEnum(tls.HandshakeType.finished)} ++
                                    array(u24, u8, hmacExpandLabel(
                                        P.Hmac,
                                        &master_secret,
                                        &.{ "client finished", &p.transcript_hash.peek() },
                                        P.verify_data_length,
                                    ));
                                p.transcript_hash.update(&client_verify_cleartext);
                                p.version = .{ .tls_1_2 = .{
                                    .expected_server_verify_data = hmacExpandLabel(
                                        P.Hmac,
                                        &master_secret,
                                        &.{ "server finished", &p.transcript_hash.finalResult() },
                                        P.verify_data_length,
                                    ),
                                    .app_cipher = std.mem.bytesToValue(P.Tls_1_2, &key_block),
                                } };
                                const pv = &p.version.tls_1_2;
                                const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                                    const V = @Vector(P.AEAD.nonce_length, u8);
                                    const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                                    const operand: V = pad ++ @as([8]u8, @bitCast(big(write_seq)));
                                    break :nonce @as(V, pv.app_cipher.client_write_IV ++ pv.app_cipher.client_salt) ^ operand;
                                };
                                var client_verify_msg = .{@intFromEnum(tls.ContentType.handshake)} ++
                                    int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                                    array(u16, u8, nonce[P.fixed_iv_length..].* ++
                                        @as([client_verify_cleartext.len + P.mac_length]u8, undefined));
                                P.AEAD.encrypt(
                                    client_verify_msg[client_verify_msg.len - P.mac_length -
                                        client_verify_cleartext.len ..][0..client_verify_cleartext.len],
                                    client_verify_msg[client_verify_msg.len - P.mac_length ..][0..P.mac_length],
                                    &client_verify_cleartext,
                                    std.mem.toBytes(big(write_seq)) ++ client_verify_msg[0 .. 1 + 2] ++ int(u16, client_verify_cleartext.len),
                                    nonce,
                                    pv.app_cipher.client_write_key,
                                );
                                const all_msgs = client_key_exchange_msg ++ client_change_cipher_spec_msg ++ client_verify_msg;
                                var all_msgs_vec = [_]std.posix.iovec_const{
                                    .{ .base = &all_msgs, .len = all_msgs.len },
                                };
                                try stream.writevAll(&all_msgs_vec);
                            },
                        }
                        write_seq += 1;
                        pending_cipher_state = .application;
                        handshake_state = .finished;
                    },
                    .certificate_verify => {
                        if (tls_version != .tls_1_3) return error.TlsUnexpectedMessage;
                        if (cipher_state != .handshake) return error.TlsUnexpectedMessage;
                        switch (handshake_state) {
                            .trust_chain_established => {},
                            .certificate => return error.TlsCertificateNotVerified,
                            else => return error.TlsUnexpectedMessage,
                        }
                        switch (handshake_cipher) {
                            inline else => |*p| {
                                try main_cert_pub_key.verifySignature(&hsd, &.{
                                    " " ** 64 ++ "TLS 1.3, server CertificateVerify\x00",
                                    &p.transcript_hash.peek(),
                                });
                                p.transcript_hash.update(wrapped_handshake);
                            },
                        }
                        handshake_state = .finished;
                    },
                    .finished => {
                        if (cipher_state == .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .finished) return error.TlsUnexpectedMessage;
                        // This message is to trick buggy proxies into behaving correctly.
                        const client_change_cipher_spec_msg = .{@intFromEnum(tls.ContentType.change_cipher_spec)} ++
                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                            array(u16, tls.ChangeCipherSpecType, .{.change_cipher_spec});
                        const app_cipher = app_cipher: switch (handshake_cipher) {
                            inline else => |*p, tag| switch (tls_version) {
                                .tls_1_3 => {
                                    const pv = &p.version.tls_1_3;
                                    const P = @TypeOf(p.*).A;
                                    try hsd.ensure(P.Hmac.mac_length);
                                    const finished_digest = p.transcript_hash.peek();
                                    p.transcript_hash.update(wrapped_handshake);
                                    const expected_server_verify_data = tls.hmac(P.Hmac, &finished_digest, pv.server_finished_key);
                                    if (!std.crypto.timing_safe.eql([P.Hmac.mac_length]u8, expected_server_verify_data, hsd.array(P.Hmac.mac_length).*)) return error.TlsDecryptError;
                                    const handshake_hash = p.transcript_hash.finalResult();
                                    const verify_data = tls.hmac(P.Hmac, &handshake_hash, pv.client_finished_key);
                                    const out_cleartext = .{@intFromEnum(tls.HandshakeType.finished)} ++
                                        array(u24, u8, verify_data) ++
                                        .{@intFromEnum(tls.ContentType.handshake)};

                                    const wrapped_len = out_cleartext.len + P.AEAD.tag_length;

                                    var finished_msg = .{@intFromEnum(tls.ContentType.application_data)} ++
                                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                                        array(u16, u8, @as([wrapped_len]u8, undefined));

                                    const ad = finished_msg[0..tls.record_header_len];
                                    const ciphertext = finished_msg[tls.record_header_len..][0..out_cleartext.len];
                                    const auth_tag = finished_msg[finished_msg.len - P.AEAD.tag_length ..];
                                    const nonce = pv.client_handshake_iv;
                                    P.AEAD.encrypt(ciphertext, auth_tag, &out_cleartext, ad, nonce, pv.client_handshake_key);

                                    const all_msgs = client_change_cipher_spec_msg ++ finished_msg;
                                    var all_msgs_vec = [_]std.posix.iovec_const{
                                        .{ .base = &all_msgs, .len = all_msgs.len },
                                    };
                                    try stream.writevAll(&all_msgs_vec);

                                    const client_secret = hkdfExpandLabel(P.Hkdf, pv.master_secret, "c ap traffic", &handshake_hash, P.Hash.digest_length);
                                    const server_secret = hkdfExpandLabel(P.Hkdf, pv.master_secret, "s ap traffic", &handshake_hash, P.Hash.digest_length);
                                    if (options.ssl_key_log_file) |key_log_file| logSecrets(key_log_file, .{
                                        .counter = key_seq,
                                        .client_random = &client_hello_rand,
                                    }, .{
                                        .SERVER_TRAFFIC_SECRET = &server_secret,
                                        .CLIENT_TRAFFIC_SECRET = &client_secret,
                                    });
                                    key_seq += 1;
                                    break :app_cipher @unionInit(tls.ApplicationCipher, @tagName(tag), .{ .tls_1_3 = .{
                                        .client_secret = client_secret,
                                        .server_secret = server_secret,
                                        .client_key = hkdfExpandLabel(P.Hkdf, client_secret, "key", "", P.AEAD.key_length),
                                        .server_key = hkdfExpandLabel(P.Hkdf, server_secret, "key", "", P.AEAD.key_length),
                                        .client_iv = hkdfExpandLabel(P.Hkdf, client_secret, "iv", "", P.AEAD.nonce_length),
                                        .server_iv = hkdfExpandLabel(P.Hkdf, server_secret, "iv", "", P.AEAD.nonce_length),
                                    } });
                                },
                                .tls_1_2 => {
                                    const pv = &p.version.tls_1_2;
                                    const P = @TypeOf(p.*).A;
                                    try hsd.ensure(P.verify_data_length);
                                    if (!std.crypto.timing_safe.eql([P.verify_data_length]u8, pv.expected_server_verify_data, hsd.array(P.verify_data_length).*)) return error.TlsDecryptError;
                                    break :app_cipher @unionInit(tls.ApplicationCipher, @tagName(tag), .{ .tls_1_2 = pv.app_cipher });
                                },
                                else => unreachable,
                            },
                        };
                        const leftover = d.rest();
                        var client: Client = .{
                            .tls_version = tls_version,
                            .read_seq = switch (tls_version) {
                                .tls_1_3 => 0,
                                .tls_1_2 => read_seq,
                                else => unreachable,
                            },
                            .write_seq = switch (tls_version) {
                                .tls_1_3 => 0,
                                .tls_1_2 => write_seq,
                                else => unreachable,
                            },
                            .partial_cleartext_idx = 0,
                            .partial_ciphertext_idx = 0,
                            .partial_ciphertext_end = @intCast(leftover.len),
                            .received_close_notify = false,
                            .allow_truncation_attacks = false,
                            .application_cipher = app_cipher,
                            .partially_read_buffer = undefined,
                            .ssl_key_log = if (options.ssl_key_log_file) |key_log_file| .{
                                .client_key_seq = key_seq,
                                .server_key_seq = key_seq,
                                .client_random = client_hello_rand,
                                .file = key_log_file,
                            } else null,
                        };
                        @memcpy(client.partially_read_buffer[0..leftover.len], leftover);
                        return client;
                    },
                    else => return error.TlsUnexpectedMessage,
                }
                if (ctd.eof()) break;
                cleartext_fragment_start = ctd.idx;
            },
            else => return error.TlsUnexpectedMessage,
        }
        cleartext_fragment_start = 0;
        cleartext_fragment_end = 0;
    }
}

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
/// Returns the number of cleartext bytes sent, which may be fewer than `bytes.len`.
pub fn write(c: *Client, stream: anytype, bytes: []const u8) !usize {
    return writeEnd(c, stream, bytes, false);
}

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
pub fn writeAll(c: *Client, stream: anytype, bytes: []const u8) !void {
    var index: usize = 0;
    while (index < bytes.len) {
        index += try c.write(stream, bytes[index..]);
    }
}

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
/// If `end` is true, then this function additionally sends a `close_notify` alert,
/// which is necessary for the server to distinguish between a properly finished
/// TLS session, or a truncation attack.
pub fn writeAllEnd(c: *Client, stream: anytype, bytes: []const u8, end: bool) !void {
    var index: usize = 0;
    while (index < bytes.len) {
        index += try c.writeEnd(stream, bytes[index..], end);
    }
}

/// Sends TLS-encrypted data to `stream`, which must conform to `StreamInterface`.
/// Returns the number of cleartext bytes sent, which may be fewer than `bytes.len`.
/// If `end` is true, then this function additionally sends a `close_notify` alert,
/// which is necessary for the server to distinguish between a properly finished
/// TLS session, or a truncation attack.
pub fn writeEnd(c: *Client, stream: anytype, bytes: []const u8, end: bool) !usize {
    var ciphertext_buf: [tls.max_ciphertext_record_len * 4]u8 = undefined;
    var iovecs_buf: [6]std.posix.iovec_const = undefined;
    var prepared = prepareCiphertextRecord(c, &iovecs_buf, &ciphertext_buf, bytes, .application_data);
    if (end) {
        prepared.iovec_end += prepareCiphertextRecord(
            c,
            iovecs_buf[prepared.iovec_end..],
            ciphertext_buf[prepared.ciphertext_end..],
            &tls.close_notify_alert,
            .alert,
        ).iovec_end;
    }

    const iovec_end = prepared.iovec_end;
    const overhead_len = prepared.overhead_len;

    // Ideally we would call writev exactly once here, however, we must ensure
    // that we don't return with a record partially written.
    var i: usize = 0;
    var total_amt: usize = 0;
    while (true) {
        var amt = try stream.writev(iovecs_buf[i..iovec_end]);
        while (amt >= iovecs_buf[i].len) {
            const encrypted_amt = iovecs_buf[i].len;
            total_amt += encrypted_amt - overhead_len;
            amt -= encrypted_amt;
            i += 1;
            // Rely on the property that iovecs delineate records, meaning that
            // if amt equals zero here, we have fortunately found ourselves
            // with a short read that aligns at the record boundary.
            if (i >= iovec_end) return total_amt;
            // We also cannot return on a vector boundary if the final close_notify is
            // not sent; otherwise the caller would not know to retry the call.
            if (amt == 0 and (!end or i < iovec_end - 1)) return total_amt;
        }
        iovecs_buf[i].base += amt;
        iovecs_buf[i].len -= amt;
    }
}

fn prepareCiphertextRecord(
    c: *Client,
    iovecs: []std.posix.iovec_const,
    ciphertext_buf: []u8,
    bytes: []const u8,
    inner_content_type: tls.ContentType,
) struct {
    iovec_end: usize,
    ciphertext_end: usize,
    /// How many bytes are taken up by overhead per record.
    overhead_len: usize,
} {
    // Due to the trailing inner content type byte in the ciphertext, we need
    // an additional buffer for storing the cleartext into before encrypting.
    var cleartext_buf: [max_ciphertext_len]u8 = undefined;
    var ciphertext_end: usize = 0;
    var iovec_end: usize = 0;
    var bytes_i: usize = 0;
    switch (c.application_cipher) {
        inline else => |*p| switch (c.tls_version) {
            .tls_1_3 => {
                const pv = &p.tls_1_3;
                const P = @TypeOf(p.*);
                const overhead_len = tls.record_header_len + P.AEAD.tag_length + 1;
                const close_notify_alert_reserved = tls.close_notify_alert.len + overhead_len;
                while (true) {
                    const encrypted_content_len: u16 = @min(
                        bytes.len - bytes_i,
                        tls.max_ciphertext_inner_record_len,
                        ciphertext_buf.len -|
                            (close_notify_alert_reserved + overhead_len + ciphertext_end),
                    );
                    if (encrypted_content_len == 0) return .{
                        .iovec_end = iovec_end,
                        .ciphertext_end = ciphertext_end,
                        .overhead_len = overhead_len,
                    };

                    @memcpy(cleartext_buf[0..encrypted_content_len], bytes[bytes_i..][0..encrypted_content_len]);
                    cleartext_buf[encrypted_content_len] = @intFromEnum(inner_content_type);
                    bytes_i += encrypted_content_len;
                    const ciphertext_len = encrypted_content_len + 1;
                    const cleartext = cleartext_buf[0..ciphertext_len];

                    const record_start = ciphertext_end;
                    const ad = ciphertext_buf[ciphertext_end..][0..tls.record_header_len];
                    ad.* = .{@intFromEnum(tls.ContentType.application_data)} ++
                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                        int(u16, ciphertext_len + P.AEAD.tag_length);
                    ciphertext_end += ad.len;
                    const ciphertext = ciphertext_buf[ciphertext_end..][0..ciphertext_len];
                    ciphertext_end += ciphertext_len;
                    const auth_tag = ciphertext_buf[ciphertext_end..][0..P.AEAD.tag_length];
                    ciphertext_end += auth_tag.len;
                    const nonce = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                        const operand: V = pad ++ std.mem.toBytes(big(c.write_seq));
                        break :nonce @as(V, pv.client_iv) ^ operand;
                    };
                    P.AEAD.encrypt(ciphertext, auth_tag, cleartext, ad, nonce, pv.client_key);
                    c.write_seq += 1; // TODO send key_update on overflow

                    const record = ciphertext_buf[record_start..ciphertext_end];
                    iovecs[iovec_end] = .{
                        .base = record.ptr,
                        .len = record.len,
                    };
                    iovec_end += 1;
                }
            },
            .tls_1_2 => {
                const pv = &p.tls_1_2;
                const P = @TypeOf(p.*);
                const overhead_len = tls.record_header_len + P.record_iv_length + P.mac_length;
                const close_notify_alert_reserved = tls.close_notify_alert.len + overhead_len;
                while (true) {
                    const message_len: u16 = @min(
                        bytes.len - bytes_i,
                        tls.max_ciphertext_inner_record_len,
                        ciphertext_buf.len -|
                            (close_notify_alert_reserved + overhead_len + ciphertext_end),
                    );
                    if (message_len == 0) return .{
                        .iovec_end = iovec_end,
                        .ciphertext_end = ciphertext_end,
                        .overhead_len = overhead_len,
                    };

                    @memcpy(cleartext_buf[0..message_len], bytes[bytes_i..][0..message_len]);
                    bytes_i += message_len;
                    const cleartext = cleartext_buf[0..message_len];

                    const record_start = ciphertext_end;
                    const record_header = ciphertext_buf[ciphertext_end..][0..tls.record_header_len];
                    ciphertext_end += tls.record_header_len;
                    record_header.* = .{@intFromEnum(inner_content_type)} ++
                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                        int(u16, P.record_iv_length + message_len + P.mac_length);
                    const ad = std.mem.toBytes(big(c.write_seq)) ++ record_header[0 .. 1 + 2] ++ int(u16, message_len);
                    const record_iv = ciphertext_buf[ciphertext_end..][0..P.record_iv_length];
                    ciphertext_end += P.record_iv_length;
                    const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                        const operand: V = pad ++ @as([8]u8, @bitCast(big(c.write_seq)));
                        break :nonce @as(V, pv.client_write_IV ++ pv.client_salt) ^ operand;
                    };
                    record_iv.* = nonce[P.fixed_iv_length..].*;
                    const ciphertext = ciphertext_buf[ciphertext_end..][0..message_len];
                    ciphertext_end += message_len;
                    const auth_tag = ciphertext_buf[ciphertext_end..][0..P.mac_length];
                    ciphertext_end += P.mac_length;
                    P.AEAD.encrypt(ciphertext, auth_tag, cleartext, ad, nonce, pv.client_write_key);
                    c.write_seq += 1; // TODO send key_update on overflow

                    const record = ciphertext_buf[record_start..ciphertext_end];
                    iovecs[iovec_end] = .{
                        .base = record.ptr,
                        .len = record.len,
                    };
                    iovec_end += 1;
                }
            },
            else => unreachable,
        },
    }
}

pub fn eof(c: Client) bool {
    return c.received_close_notify and
        c.partial_cleartext_idx >= c.partial_ciphertext_idx and
        c.partial_ciphertext_idx >= c.partial_ciphertext_end;
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read, calling the underlying read function the
/// minimal number of times until the buffer has at least `len` bytes filled.
/// If the number read is less than `len` it means the stream reached the end.
/// Reaching the end of the stream is not an error condition.
pub fn readAtLeast(c: *Client, stream: anytype, buffer: []u8, len: usize) !usize {
    var iovecs = [1]std.posix.iovec{.{ .base = buffer.ptr, .len = buffer.len }};
    return readvAtLeast(c, stream, &iovecs, len);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
pub fn read(c: *Client, stream: anytype, buffer: []u8) !usize {
    return readAtLeast(c, stream, buffer, 1);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read. If the number read is smaller than
/// `buffer.len`, it means the stream reached the end. Reaching the end of the
/// stream is not an error condition.
pub fn readAll(c: *Client, stream: anytype, buffer: []u8) !usize {
    return readAtLeast(c, stream, buffer, buffer.len);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read. If the number read is less than the space
/// provided it means the stream reached the end. Reaching the end of the
/// stream is not an error condition.
/// The `iovecs` parameter is mutable because this function needs to mutate the fields in
/// order to handle partial reads from the underlying stream layer.
pub fn readv(c: *Client, stream: anytype, iovecs: []std.posix.iovec) !usize {
    return readvAtLeast(c, stream, iovecs, 1);
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns the number of bytes read, calling the underlying read function the
/// minimal number of times until the iovecs have at least `len` bytes filled.
/// If the number read is less than `len` it means the stream reached the end.
/// Reaching the end of the stream is not an error condition.
/// The `iovecs` parameter is mutable because this function needs to mutate the fields in
/// order to handle partial reads from the underlying stream layer.
pub fn readvAtLeast(c: *Client, stream: anytype, iovecs: []std.posix.iovec, len: usize) !usize {
    if (c.eof()) return 0;

    var off_i: usize = 0;
    var vec_i: usize = 0;
    while (true) {
        var amt = try c.readvAdvanced(stream, iovecs[vec_i..]);
        off_i += amt;
        if (c.eof() or off_i >= len) return off_i;
        while (amt >= iovecs[vec_i].len) {
            amt -= iovecs[vec_i].len;
            vec_i += 1;
        }
        iovecs[vec_i].base += amt;
        iovecs[vec_i].len -= amt;
    }
}

/// Receives TLS-encrypted data from `stream`, which must conform to `StreamInterface`.
/// Returns number of bytes that have been read, populated inside `iovecs`. A
/// return value of zero bytes does not mean end of stream. Instead, check the `eof()`
/// for the end of stream. The `eof()` may be true after any call to
/// `read`, including when greater than zero bytes are returned, and this
/// function asserts that `eof()` is `false`.
/// See `readv` for a higher level function that has the same, familiar API as
/// other read functions, such as `std.fs.File.read`.
pub fn readvAdvanced(c: *Client, stream: anytype, iovecs: []const std.posix.iovec) !usize {
    var vp: VecPut = .{ .iovecs = iovecs };

    // Give away the buffered cleartext we have, if any.
    const partial_cleartext = c.partially_read_buffer[c.partial_cleartext_idx..c.partial_ciphertext_idx];
    if (partial_cleartext.len > 0) {
        const amt: u15 = @intCast(vp.put(partial_cleartext));
        c.partial_cleartext_idx += amt;

        if (c.partial_cleartext_idx == c.partial_ciphertext_idx and
            c.partial_ciphertext_end == c.partial_ciphertext_idx)
        {
            // The buffer is now empty.
            c.partial_cleartext_idx = 0;
            c.partial_ciphertext_idx = 0;
            c.partial_ciphertext_end = 0;
        }

        if (c.received_close_notify) {
            c.partial_ciphertext_end = 0;
            assert(vp.total == amt);
            return amt;
        } else if (amt > 0) {
            // We don't need more data, so don't call read.
            assert(vp.total == amt);
            return amt;
        }
    }

    assert(!c.received_close_notify);

    // Ideally, this buffer would never be used. It is needed when `iovecs` are
    // too small to fit the cleartext, which may be as large as `max_ciphertext_len`.
    var cleartext_stack_buffer: [max_ciphertext_len]u8 = undefined;
    // Temporarily stores ciphertext before decrypting it and giving it to `iovecs`.
    var in_stack_buffer: [max_ciphertext_len * 4]u8 = undefined;
    // How many bytes left in the user's buffer.
    const free_size = vp.freeSize();
    // The amount of the user's buffer that we need to repurpose for storing
    // ciphertext. The end of the buffer will be used for such purposes.
    const ciphertext_buf_len = (free_size / 2) -| in_stack_buffer.len;
    // The amount of the user's buffer that will be used to give cleartext. The
    // beginning of the buffer will be used for such purposes.
    const cleartext_buf_len = free_size - ciphertext_buf_len;

    // Recoup `partially_read_buffer` space. This is necessary because it is assumed
    // below that `frag0` is big enough to hold at least one record.
    limitedOverlapCopy(c.partially_read_buffer[0..c.partial_ciphertext_end], c.partial_ciphertext_idx);
    c.partial_ciphertext_end -= c.partial_ciphertext_idx;
    c.partial_ciphertext_idx = 0;
    c.partial_cleartext_idx = 0;
    const first_iov = c.partially_read_buffer[c.partial_ciphertext_end..];

    var ask_iovecs_buf: [2]std.posix.iovec = .{
        .{
            .base = first_iov.ptr,
            .len = first_iov.len,
        },
        .{
            .base = &in_stack_buffer,
            .len = in_stack_buffer.len,
        },
    };

    // Cleartext capacity of output buffer, in records. Minimum one full record.
    const buf_cap = @max(cleartext_buf_len / max_ciphertext_len, 1);
    const wanted_read_len = buf_cap * (max_ciphertext_len + tls.record_header_len);
    const ask_len = @max(wanted_read_len, cleartext_stack_buffer.len) - c.partial_ciphertext_end;
    const ask_iovecs = limitVecs(&ask_iovecs_buf, ask_len);
    const actual_read_len = try stream.readv(ask_iovecs);
    if (actual_read_len == 0) {
        // This is either a truncation attack, a bug in the server, or an
        // intentional omission of the close_notify message due to truncation
        // detection handled above the TLS layer.
        if (c.allow_truncation_attacks) {
            c.received_close_notify = true;
        } else {
            return error.TlsConnectionTruncated;
        }
    }

    // There might be more bytes inside `in_stack_buffer` that need to be processed,
    // but at least frag0 will have one complete ciphertext record.
    const frag0_end = @min(c.partially_read_buffer.len, c.partial_ciphertext_end + actual_read_len);
    const frag0 = c.partially_read_buffer[c.partial_ciphertext_idx..frag0_end];
    var frag1 = in_stack_buffer[0..actual_read_len -| first_iov.len];
    // We need to decipher frag0 and frag1 but there may be a ciphertext record
    // straddling the boundary. We can handle this with two memcpy() calls to
    // assemble the straddling record in between handling the two sides.
    var frag = frag0;
    var in: usize = 0;
    while (true) {
        if (in == frag.len) {
            // Perfect split.
            if (frag.ptr == frag1.ptr) {
                c.partial_ciphertext_end = c.partial_ciphertext_idx;
                return vp.total;
            }
            frag = frag1;
            in = 0;
            continue;
        }

        if (in + tls.record_header_len > frag.len) {
            if (frag.ptr == frag1.ptr)
                return finishRead(c, frag, in, vp.total);

            const first = frag[in..];

            if (frag1.len < tls.record_header_len)
                return finishRead2(c, first, frag1, vp.total);

            // A record straddles the two fragments. Copy into the now-empty first fragment.
            const record_len_byte_0: u16 = straddleByte(frag, frag1, in + 3);
            const record_len_byte_1: u16 = straddleByte(frag, frag1, in + 4);
            const record_len = (record_len_byte_0 << 8) | record_len_byte_1;
            if (record_len > max_ciphertext_len) return error.TlsRecordOverflow;

            const full_record_len = record_len + tls.record_header_len;
            const second_len = full_record_len - first.len;
            if (frag1.len < second_len)
                return finishRead2(c, first, frag1, vp.total);

            limitedOverlapCopy(frag, in);
            @memcpy(frag[first.len..][0..second_len], frag1[0..second_len]);
            frag = frag[0..full_record_len];
            frag1 = frag1[second_len..];
            in = 0;
            continue;
        }
        const ct: tls.ContentType = @enumFromInt(frag[in]);
        in += 1;
        const legacy_version = mem.readInt(u16, frag[in..][0..2], .big);
        in += 2;
        _ = legacy_version;
        const record_len = mem.readInt(u16, frag[in..][0..2], .big);
        if (record_len > max_ciphertext_len) return error.TlsRecordOverflow;
        in += 2;
        const end = in + record_len;
        if (end > frag.len) {
            // We need the record header on the next iteration of the loop.
            in -= tls.record_header_len;

            if (frag.ptr == frag1.ptr)
                return finishRead(c, frag, in, vp.total);

            // A record straddles the two fragments. Copy into the now-empty first fragment.
            const first = frag[in..];
            const full_record_len = record_len + tls.record_header_len;
            const second_len = full_record_len - first.len;
            if (frag1.len < second_len)
                return finishRead2(c, first, frag1, vp.total);

            limitedOverlapCopy(frag, in);
            @memcpy(frag[first.len..][0..second_len], frag1[0..second_len]);
            frag = frag[0..full_record_len];
            frag1 = frag1[second_len..];
            in = 0;
            continue;
        }
        const cleartext, const inner_ct: tls.ContentType = cleartext: switch (c.application_cipher) {
            inline else => |*p| switch (c.tls_version) {
                .tls_1_3 => {
                    const pv = &p.tls_1_3;
                    const P = @TypeOf(p.*);
                    const ad = frag[in - tls.record_header_len ..][0..tls.record_header_len];
                    const ciphertext_len = record_len - P.AEAD.tag_length;
                    const ciphertext = frag[in..][0..ciphertext_len];
                    in += ciphertext_len;
                    const auth_tag = frag[in..][0..P.AEAD.tag_length].*;
                    const nonce = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                        const operand: V = pad ++ std.mem.toBytes(big(c.read_seq));
                        break :nonce @as(V, pv.server_iv) ^ operand;
                    };
                    const out_buf = vp.peek();
                    const cleartext_buf = if (ciphertext.len <= out_buf.len)
                        out_buf
                    else
                        &cleartext_stack_buffer;
                    const cleartext = cleartext_buf[0..ciphertext.len];
                    P.AEAD.decrypt(cleartext, ciphertext, auth_tag, ad, nonce, pv.server_key) catch
                        return error.TlsBadRecordMac;
                    const msg = mem.trimRight(u8, cleartext, "\x00");
                    break :cleartext .{ msg[0 .. msg.len - 1], @enumFromInt(msg[msg.len - 1]) };
                },
                .tls_1_2 => {
                    const pv = &p.tls_1_2;
                    const P = @TypeOf(p.*);
                    const message_len: u16 = record_len - P.record_iv_length - P.mac_length;
                    const ad = std.mem.toBytes(big(c.read_seq)) ++
                        frag[in - tls.record_header_len ..][0 .. 1 + 2] ++
                        std.mem.toBytes(big(message_len));
                    const record_iv = frag[in..][0..P.record_iv_length].*;
                    in += P.record_iv_length;
                    const masked_read_seq = c.read_seq &
                        comptime std.math.shl(u64, std.math.maxInt(u64), 8 * P.record_iv_length);
                    const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                        const operand: V = pad ++ @as([8]u8, @bitCast(big(masked_read_seq)));
                        break :nonce @as(V, pv.server_write_IV ++ record_iv) ^ operand;
                    };
                    const ciphertext = frag[in..][0..message_len];
                    in += message_len;
                    const auth_tag = frag[in..][0..P.mac_length].*;
                    in += P.mac_length;
                    const out_buf = vp.peek();
                    const cleartext_buf = if (message_len <= out_buf.len)
                        out_buf
                    else
                        &cleartext_stack_buffer;
                    const cleartext = cleartext_buf[0..ciphertext.len];
                    P.AEAD.decrypt(cleartext, ciphertext, auth_tag, ad, nonce, pv.server_write_key) catch
                        return error.TlsBadRecordMac;
                    break :cleartext .{ cleartext, ct };
                },
                else => unreachable,
            },
        };
        c.read_seq = try std.math.add(u64, c.read_seq, 1);
        switch (inner_ct) {
            .alert => {
                if (cleartext.len != 2) return error.TlsDecodeError;
                const level: tls.AlertLevel = @enumFromInt(cleartext[0]);
                const desc: tls.AlertDescription = @enumFromInt(cleartext[1]);
                if (desc == .close_notify) {
                    c.received_close_notify = true;
                    c.partial_ciphertext_end = c.partial_ciphertext_idx;
                    return vp.total;
                }
                _ = level;

                try desc.toError();
                // TODO: handle server-side closures
                return error.TlsUnexpectedMessage;
            },
            .handshake => {
                var ct_i: usize = 0;
                while (true) {
                    const handshake_type: tls.HandshakeType = @enumFromInt(cleartext[ct_i]);
                    ct_i += 1;
                    const handshake_len = mem.readInt(u24, cleartext[ct_i..][0..3], .big);
                    ct_i += 3;
                    const next_handshake_i = ct_i + handshake_len;
                    if (next_handshake_i > cleartext.len)
                        return error.TlsBadLength;
                    const handshake = cleartext[ct_i..next_handshake_i];
                    switch (handshake_type) {
                        .new_session_ticket => {
                            // This client implementation ignores new session tickets.
                        },
                        .key_update => {
                            switch (c.application_cipher) {
                                inline else => |*p| {
                                    const pv = &p.tls_1_3;
                                    const P = @TypeOf(p.*);
                                    const server_secret = hkdfExpandLabel(P.Hkdf, pv.server_secret, "traffic upd", "", P.Hash.digest_length);
                                    if (c.ssl_key_log) |*key_log| logSecrets(key_log.file, .{
                                        .counter = key_log.serverCounter(),
                                        .client_random = &key_log.client_random,
                                    }, .{
                                        .SERVER_TRAFFIC_SECRET = &server_secret,
                                    });
                                    pv.server_secret = server_secret;
                                    pv.server_key = hkdfExpandLabel(P.Hkdf, server_secret, "key", "", P.AEAD.key_length);
                                    pv.server_iv = hkdfExpandLabel(P.Hkdf, server_secret, "iv", "", P.AEAD.nonce_length);
                                },
                            }
                            c.read_seq = 0;

                            switch (@as(tls.KeyUpdateRequest, @enumFromInt(handshake[0]))) {
                                .update_requested => {
                                    switch (c.application_cipher) {
                                        inline else => |*p| {
                                            const pv = &p.tls_1_3;
                                            const P = @TypeOf(p.*);
                                            const client_secret = hkdfExpandLabel(P.Hkdf, pv.client_secret, "traffic upd", "", P.Hash.digest_length);
                                            if (c.ssl_key_log) |*key_log| logSecrets(key_log.file, .{
                                                .counter = key_log.clientCounter(),
                                                .client_random = &key_log.client_random,
                                            }, .{
                                                .CLIENT_TRAFFIC_SECRET = &client_secret,
                                            });
                                            pv.client_secret = client_secret;
                                            pv.client_key = hkdfExpandLabel(P.Hkdf, client_secret, "key", "", P.AEAD.key_length);
                                            pv.client_iv = hkdfExpandLabel(P.Hkdf, client_secret, "iv", "", P.AEAD.nonce_length);
                                        },
                                    }
                                    c.write_seq = 0;
                                },
                                .update_not_requested => {},
                                _ => return error.TlsIllegalParameter,
                            }
                        },
                        else => {
                            return error.TlsUnexpectedMessage;
                        },
                    }
                    ct_i = next_handshake_i;
                    if (ct_i >= cleartext.len) break;
                }
            },
            .application_data => {
                // Determine whether the output buffer or a stack
                // buffer was used for storing the cleartext.
                if (cleartext.ptr == &cleartext_stack_buffer) {
                    // Stack buffer was used, so we must copy to the output buffer.
                    if (c.partial_ciphertext_idx > c.partial_cleartext_idx) {
                        // We have already run out of room in iovecs. Continue
                        // appending to `partially_read_buffer`.
                        @memcpy(
                            c.partially_read_buffer[c.partial_ciphertext_idx..][0..cleartext.len],
                            cleartext,
                        );
                        c.partial_ciphertext_idx = @intCast(c.partial_ciphertext_idx + cleartext.len);
                    } else {
                        const amt = vp.put(cleartext);
                        if (amt < cleartext.len) {
                            const rest = cleartext[amt..];
                            c.partial_cleartext_idx = 0;
                            c.partial_ciphertext_idx = @intCast(rest.len);
                            @memcpy(c.partially_read_buffer[0..rest.len], rest);
                        }
                    }
                } else {
                    // Output buffer was used directly which means no
                    // memory copying needs to occur, and we can move
                    // on to the next ciphertext record.
                    vp.next(cleartext.len);
                }
            },
            else => return error.TlsUnexpectedMessage,
        }
        in = end;
    }
}

fn logSecrets(key_log_file: std.fs.File, context: anytype, secrets: anytype) void {
    const locked = if (key_log_file.lock(.exclusive)) |_| true else |_| false;
    defer if (locked) key_log_file.unlock();
    key_log_file.seekFromEnd(0) catch {};
    inline for (@typeInfo(@TypeOf(secrets)).@"struct".fields) |field| key_log_file.writer().print("{s}" ++
        (if (@hasField(@TypeOf(context), "counter")) "_{d}" else "") ++ " {} {}\n", .{field.name} ++
        (if (@hasField(@TypeOf(context), "counter")) .{context.counter} else .{}) ++ .{
        std.fmt.fmtSliceHexLower(context.client_random),
        std.fmt.fmtSliceHexLower(@field(secrets, field.name)),
    }) catch {};
}

fn finishRead(c: *Client, frag: []const u8, in: usize, out: usize) usize {
    const saved_buf = frag[in..];
    if (c.partial_ciphertext_idx > c.partial_cleartext_idx) {
        // There is cleartext at the beginning already which we need to preserve.
        c.partial_ciphertext_end = @intCast(c.partial_ciphertext_idx + saved_buf.len);
        @memcpy(c.partially_read_buffer[c.partial_ciphertext_idx..][0..saved_buf.len], saved_buf);
    } else {
        c.partial_cleartext_idx = 0;
        c.partial_ciphertext_idx = 0;
        c.partial_ciphertext_end = @intCast(saved_buf.len);
        @memcpy(c.partially_read_buffer[0..saved_buf.len], saved_buf);
    }
    return out;
}

/// Note that `first` usually overlaps with `c.partially_read_buffer`.
fn finishRead2(c: *Client, first: []const u8, frag1: []const u8, out: usize) usize {
    if (c.partial_ciphertext_idx > c.partial_cleartext_idx) {
        // There is cleartext at the beginning already which we need to preserve.
        c.partial_ciphertext_end = @intCast(c.partial_ciphertext_idx + first.len + frag1.len);
        // TODO: eliminate this call to copyForwards
        std.mem.copyForwards(u8, c.partially_read_buffer[c.partial_ciphertext_idx..][0..first.len], first);
        @memcpy(c.partially_read_buffer[c.partial_ciphertext_idx + first.len ..][0..frag1.len], frag1);
    } else {
        c.partial_cleartext_idx = 0;
        c.partial_ciphertext_idx = 0;
        c.partial_ciphertext_end = @intCast(first.len + frag1.len);
        // TODO: eliminate this call to copyForwards
        std.mem.copyForwards(u8, c.partially_read_buffer[0..first.len], first);
        @memcpy(c.partially_read_buffer[first.len..][0..frag1.len], frag1);
    }
    return out;
}

fn limitedOverlapCopy(frag: []u8, in: usize) void {
    const first = frag[in..];
    if (first.len <= in) {
        // A single, non-overlapping memcpy suffices.
        @memcpy(frag[0..first.len], first);
    } else {
        // One memcpy call would overlap, so just do this instead.
        std.mem.copyForwards(u8, frag, first);
    }
}

fn straddleByte(s1: []const u8, s2: []const u8, index: usize) u8 {
    if (index < s1.len) {
        return s1[index];
    } else {
        return s2[index - s1.len];
    }
}

const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

inline fn big(x: anytype) @TypeOf(x) {
    return switch (native_endian) {
        .big => x,
        .little => @byteSwap(x),
    };
}

const KeyShare = struct {
    ml_kem768_kp: crypto.kem.ml_kem.MLKem768.KeyPair,
    secp256r1_kp: crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
    secp384r1_kp: crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair,
    x25519_kp: crypto.dh.X25519.KeyPair,
    sk_buf: [sk_max_len]u8,
    sk_len: std.math.IntFittingRange(0, sk_max_len),

    const sk_max_len = @max(
        crypto.dh.X25519.shared_length + crypto.kem.ml_kem.MLKem768.shared_length,
        crypto.ecc.P256.scalar.encoded_length,
        crypto.ecc.P384.scalar.encoded_length,
        crypto.dh.X25519.shared_length,
    );

    fn init(seed: [112]u8) error{IdentityElement}!KeyShare {
        return .{
            .ml_kem768_kp = .generate(),
            .secp256r1_kp = try .generateDeterministic(seed[0..32].*),
            .secp384r1_kp = try .generateDeterministic(seed[32..80].*),
            .x25519_kp = try .generateDeterministic(seed[80..112].*),
            .sk_buf = undefined,
            .sk_len = 0,
        };
    }

    fn exchange(
        ks: *KeyShare,
        named_group: tls.NamedGroup,
        server_pub_key: []const u8,
    ) error{ TlsIllegalParameter, TlsDecryptFailure }!void {
        switch (named_group) {
            .x25519_ml_kem768 => {
                const hksl = crypto.kem.ml_kem.MLKem768.ciphertext_length;
                const xksl = hksl + crypto.dh.X25519.public_length;
                if (server_pub_key.len != xksl) return error.TlsIllegalParameter;

                const hsk = ks.ml_kem768_kp.secret_key.decaps(server_pub_key[0..hksl]) catch
                    return error.TlsDecryptFailure;
                const xsk = crypto.dh.X25519.scalarmult(ks.x25519_kp.secret_key, server_pub_key[hksl..xksl].*) catch
                    return error.TlsDecryptFailure;
                @memcpy(ks.sk_buf[0..hsk.len], &hsk);
                @memcpy(ks.sk_buf[hsk.len..][0..xsk.len], &xsk);
                ks.sk_len = hsk.len + xsk.len;
            },
            .secp256r1 => {
                const PublicKey = crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey;
                const pk = PublicKey.fromSec1(server_pub_key) catch return error.TlsDecryptFailure;
                const mul = pk.p.mulPublic(ks.secp256r1_kp.secret_key.bytes, .big) catch
                    return error.TlsDecryptFailure;
                const sk = mul.affineCoordinates().x.toBytes(.big);
                @memcpy(ks.sk_buf[0..sk.len], &sk);
                ks.sk_len = sk.len;
            },
            .secp384r1 => {
                const PublicKey = crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey;
                const pk = PublicKey.fromSec1(server_pub_key) catch return error.TlsDecryptFailure;
                const mul = pk.p.mulPublic(ks.secp384r1_kp.secret_key.bytes, .big) catch
                    return error.TlsDecryptFailure;
                const sk = mul.affineCoordinates().x.toBytes(.big);
                @memcpy(ks.sk_buf[0..sk.len], &sk);
                ks.sk_len = sk.len;
            },
            .x25519 => {
                const ksl = crypto.dh.X25519.public_length;
                if (server_pub_key.len != ksl) return error.TlsIllegalParameter;
                const sk = crypto.dh.X25519.scalarmult(ks.x25519_kp.secret_key, server_pub_key[0..ksl].*) catch
                    return error.TlsDecryptFailure;
                @memcpy(ks.sk_buf[0..sk.len], &sk);
                ks.sk_len = sk.len;
            },
            else => return error.TlsIllegalParameter,
        }
    }

    fn getSharedSecret(ks: *const KeyShare) ?[]const u8 {
        return if (ks.sk_len > 0) ks.sk_buf[0..ks.sk_len] else null;
    }
};

fn SchemeEcdsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => crypto.sign.ecdsa.EcdsaP256Sha256,
        .ecdsa_secp384r1_sha384 => crypto.sign.ecdsa.EcdsaP384Sha384,
        else => @compileError("bad scheme"),
    };
}

fn SchemeRsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .rsa_pkcs1_sha1,
        => Certificate.rsa.PKCS1v1_5Signature,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .rsa_pss_pss_sha256,
        .rsa_pss_pss_sha384,
        .rsa_pss_pss_sha512,
        => Certificate.rsa.PSSSignature,
        else => @compileError("bad scheme"),
    };
}

fn SchemeEddsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .ed25519 => crypto.sign.Ed25519,
        else => @compileError("bad scheme"),
    };
}

fn SchemeHash(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .rsa_pkcs1_sha256,
        .ecdsa_secp256r1_sha256,
        .rsa_pss_rsae_sha256,
        .rsa_pss_pss_sha256,
        => crypto.hash.sha2.Sha256,
        .rsa_pkcs1_sha384,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha384,
        .rsa_pss_pss_sha384,
        => crypto.hash.sha2.Sha384,
        .rsa_pkcs1_sha512,
        .ecdsa_secp521r1_sha512,
        .rsa_pss_rsae_sha512,
        .rsa_pss_pss_sha512,
        => crypto.hash.sha2.Sha512,
        .rsa_pkcs1_sha1,
        .ecdsa_sha1,
        => crypto.hash.Sha1,
        else => @compileError("bad scheme"),
    };
}

const CertificatePublicKey = struct {
    algo: Certificate.AlgorithmCategory,
    buf: [600]u8,
    len: u16,

    fn init(
        cert_pub_key: *CertificatePublicKey,
        algo: Certificate.AlgorithmCategory,
        pub_key: []const u8,
    ) error{CertificatePublicKeyInvalid}!void {
        if (pub_key.len > cert_pub_key.buf.len) return error.CertificatePublicKeyInvalid;
        cert_pub_key.algo = algo;
        @memcpy(cert_pub_key.buf[0..pub_key.len], pub_key);
        cert_pub_key.len = @intCast(pub_key.len);
    }

    const VerifyError = error{ TlsDecodeError, TlsBadSignatureScheme, InvalidEncoding } ||
        // ecdsa
        crypto.errors.EncodingError ||
        crypto.errors.NotSquareError ||
        crypto.errors.NonCanonicalError ||
        SchemeEcdsa(.ecdsa_secp256r1_sha256).Signature.VerifyError ||
        SchemeEcdsa(.ecdsa_secp384r1_sha384).Signature.VerifyError ||
        // rsa
        error{TlsBadRsaSignatureBitCount} ||
        Certificate.rsa.PublicKey.ParseDerError ||
        Certificate.rsa.PublicKey.FromBytesError ||
        Certificate.rsa.PSSSignature.VerifyError ||
        Certificate.rsa.PKCS1v1_5Signature.VerifyError ||
        // eddsa
        SchemeEddsa(.ed25519).Signature.VerifyError;

    fn verifySignature(
        cert_pub_key: *const CertificatePublicKey,
        sigd: *tls.Decoder,
        msg: []const []const u8,
    ) VerifyError!void {
        const pub_key = cert_pub_key.buf[0..cert_pub_key.len];

        try sigd.ensure(2 + 2);
        const scheme = sigd.decode(tls.SignatureScheme);
        const sig_len = sigd.decode(u16);
        try sigd.ensure(sig_len);
        const encoded_sig = sigd.slice(sig_len);

        if (cert_pub_key.algo != @as(Certificate.AlgorithmCategory, switch (scheme) {
            .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => .X9_62_id_ecPublicKey,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            .rsa_pkcs1_sha1,
            => .rsaEncryption,
            .rsa_pss_pss_sha256,
            .rsa_pss_pss_sha384,
            .rsa_pss_pss_sha512,
            => .rsassa_pss,
            else => return error.TlsBadSignatureScheme,
        })) return error.TlsBadSignatureScheme;

        switch (scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| {
                const Ecdsa = SchemeEcdsa(comptime_scheme);
                const sig = try Ecdsa.Signature.fromDer(encoded_sig);
                const key = try Ecdsa.PublicKey.fromSec1(pub_key);
                var ver = try sig.verifier(key);
                for (msg) |part| ver.update(part);
                try ver.verify();
            },
            inline .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            .rsa_pss_pss_sha256,
            .rsa_pss_pss_sha384,
            .rsa_pss_pss_sha512,
            .rsa_pkcs1_sha1,
            => |comptime_scheme| {
                const RsaSignature = SchemeRsa(comptime_scheme);
                const Hash = SchemeHash(comptime_scheme);
                const PublicKey = Certificate.rsa.PublicKey;
                const components = try PublicKey.parseDer(pub_key);
                const exponent = components.exponent;
                const modulus = components.modulus;
                switch (modulus.len) {
                    inline 128, 256, 384, 512 => |modulus_len| {
                        const key: PublicKey = try .fromBytes(exponent, modulus);
                        const sig = RsaSignature.fromBytes(modulus_len, encoded_sig);
                        try RsaSignature.concatVerify(modulus_len, sig, msg, key, Hash);
                    },
                    else => return error.TlsBadRsaSignatureBitCount,
                }
            },
            inline .ed25519 => |comptime_scheme| {
                const Eddsa = SchemeEddsa(comptime_scheme);
                if (encoded_sig.len != Eddsa.Signature.encoded_length) return error.InvalidEncoding;
                const sig = Eddsa.Signature.fromBytes(encoded_sig[0..Eddsa.Signature.encoded_length].*);
                if (pub_key.len != Eddsa.PublicKey.encoded_length) return error.InvalidEncoding;
                const key = try Eddsa.PublicKey.fromBytes(pub_key[0..Eddsa.PublicKey.encoded_length].*);
                var ver = try sig.verifier(key);
                for (msg) |part| ver.update(part);
                try ver.verify();
            },
            else => unreachable,
        }
    }
};

/// Abstraction for sending multiple byte buffers to a slice of iovecs.
const VecPut = struct {
    iovecs: []const std.posix.iovec,
    idx: usize = 0,
    off: usize = 0,
    total: usize = 0,

    /// Returns the amount actually put which is always equal to bytes.len
    /// unless the vectors ran out of space.
    fn put(vp: *VecPut, bytes: []const u8) usize {
        if (vp.idx >= vp.iovecs.len) return 0;
        var bytes_i: usize = 0;
        while (true) {
            const v = vp.iovecs[vp.idx];
            const dest = v.base[vp.off..v.len];
            const src = bytes[bytes_i..][0..@min(dest.len, bytes.len - bytes_i)];
            @memcpy(dest[0..src.len], src);
            bytes_i += src.len;
            vp.off += src.len;
            if (vp.off >= v.len) {
                vp.off = 0;
                vp.idx += 1;
                if (vp.idx >= vp.iovecs.len) {
                    vp.total += bytes_i;
                    return bytes_i;
                }
            }
            if (bytes_i >= bytes.len) {
                vp.total += bytes_i;
                return bytes_i;
            }
        }
    }

    /// Returns the next buffer that consecutive bytes can go into.
    fn peek(vp: VecPut) []u8 {
        if (vp.idx >= vp.iovecs.len) return &.{};
        const v = vp.iovecs[vp.idx];
        return v.base[vp.off..v.len];
    }

    // After writing to the result of peek(), one can call next() to
    // advance the cursor.
    fn next(vp: *VecPut, len: usize) void {
        vp.total += len;
        vp.off += len;
        if (vp.off >= vp.iovecs[vp.idx].len) {
            vp.off = 0;
            vp.idx += 1;
        }
    }

    fn freeSize(vp: VecPut) usize {
        if (vp.idx >= vp.iovecs.len) return 0;
        var total: usize = 0;
        total += vp.iovecs[vp.idx].len - vp.off;
        if (vp.idx + 1 >= vp.iovecs.len) return total;
        for (vp.iovecs[vp.idx + 1 ..]) |v| total += v.len;
        return total;
    }
};

/// Limit iovecs to a specific byte size.
fn limitVecs(iovecs: []std.posix.iovec, len: usize) []std.posix.iovec {
    var bytes_left: usize = len;
    for (iovecs, 0..) |*iovec, vec_i| {
        if (bytes_left <= iovec.len) {
            iovec.len = bytes_left;
            return iovecs[0 .. vec_i + 1];
        }
        bytes_left -= iovec.len;
    }
    return iovecs;
}

/// The priority order here is chosen based on what crypto algorithms Zig has
/// available in the standard library as well as what is faster. Following are
/// a few data points on the relative performance of these algorithms.
///
/// Measurement taken with 0.11.0-dev.810+c2f5848fe
/// on x86_64-linux Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz:
/// zig run .lib/std/crypto/benchmark.zig -OReleaseFast
///       aegis-128l:      15382 MiB/s
///        aegis-256:       9553 MiB/s
///       aes128-gcm:       3721 MiB/s
///       aes256-gcm:       3010 MiB/s
/// chacha20Poly1305:        597 MiB/s
///
/// Measurement taken with 0.11.0-dev.810+c2f5848fe
/// on x86_64-linux Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz:
/// zig run .lib/std/crypto/benchmark.zig -OReleaseFast -mcpu=baseline
///       aegis-128l:        629 MiB/s
/// chacha20Poly1305:        529 MiB/s
///        aegis-256:        461 MiB/s
///       aes128-gcm:        138 MiB/s
///       aes256-gcm:        120 MiB/s
const cipher_suites = if (crypto.core.aes.has_hardware_support)
    array(u16, tls.CipherSuite, .{
        .AEGIS_128L_SHA256,
        .AEGIS_256_SHA512,
        .AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .CHACHA20_POLY1305_SHA256,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    })
else
    array(u16, tls.CipherSuite, .{
        .CHACHA20_POLY1305_SHA256,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .AEGIS_128L_SHA256,
        .AEGIS_256_SHA512,
        .AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    });

test {
    _ = StreamInterface;
}
const builtin = @import("builtin");
const std = @import("std.zig");
const math = std.math;
const mem = std.mem;
const io = std.io;
const posix = std.posix;
const fs = std.fs;
const testing = std.testing;
const root = @import("root");
const File = std.fs.File;
const windows = std.os.windows;
const native_arch = builtin.cpu.arch;
const native_os = builtin.os.tag;
const native_endian = native_arch.endian();

pub const MemoryAccessor = @import("debug/MemoryAccessor.zig");
pub const FixedBufferReader = @import("debug/FixedBufferReader.zig");
pub const Dwarf = @import("debug/Dwarf.zig");
pub const Pdb = @import("debug/Pdb.zig");
pub const SelfInfo = @import("debug/SelfInfo.zig");
pub const Info = @import("debug/Info.zig");
pub const Coverage = @import("debug/Coverage.zig");

pub const simple_panic = @import("debug/simple_panic.zig");
pub const no_panic = @import("debug/no_panic.zig");

/// A fully-featured panic handler namespace which lowers all panics to calls to `panicFn`.
/// Safety panics will use formatted printing to provide a meaningful error message.
/// The signature of `panicFn` should match that of `defaultPanic`.
pub fn FullPanic(comptime panicFn: fn ([]const u8, ?usize) noreturn) type {
    return struct {
        pub const call = panicFn;
        pub fn sentinelMismatch(expected: anytype, found: @TypeOf(expected)) noreturn {
            @branchHint(.cold);
            std.debug.panicExtra(@returnAddress(), "sentinel mismatch: expected {any}, found {any}", .{
                expected, found,
            });
        }
        pub fn unwrapError(err: anyerror) noreturn {
            @branchHint(.cold);
            std.debug.panicExtra(@returnAddress(), "attempt to unwrap error: {s}", .{@errorName(err)});
        }
        pub fn outOfBounds(index: usize, len: usize) noreturn {
            @branchHint(.cold);
            std.debug.panicExtra(@returnAddress(), "index out of bounds: index {d}, len {d}", .{ index, len });
        }
        pub fn startGreaterThanEnd(start: usize, end: usize) noreturn {
            @branchHint(.cold);
            std.debug.panicExtra(@returnAddress(), "start index {d} is larger than end index {d}", .{ start, end });
        }
        pub fn inactiveUnionField(active: anytype, accessed: @TypeOf(active)) noreturn {
            @branchHint(.cold);
            std.debug.panicExtra(@returnAddress(), "access of union field '{s}' while field '{s}' is active", .{
                @tagName(accessed), @tagName(active),
            });
        }
        pub fn sliceCastLenRemainder(src_len: usize) noreturn {
            @branchHint(.cold);
            std.debug.panicExtra(@returnAddress(), "slice length '{d}' does not divide exactly into destination elements", .{src_len});
        }
        pub fn reachedUnreachable() noreturn {
            @branchHint(.cold);
            call("reached unreachable code", @returnAddress());
        }
        pub fn unwrapNull() noreturn {
            @branchHint(.cold);
            call("attempt to use null value", @returnAddress());
        }
        pub fn castToNull() noreturn {
            @branchHint(.cold);
            call("cast causes pointer to be null", @returnAddress());
        }
        pub fn incorrectAlignment() noreturn {
            @branchHint(.cold);
            call("incorrect alignment", @returnAddress());
        }
        pub fn invalidErrorCode() noreturn {
            @branchHint(.cold);
            call("invalid error code", @returnAddress());
        }
        pub fn castTruncatedData() noreturn {
            @branchHint(.cold);
            call("integer cast truncated bits", @returnAddress());
        }
        pub fn negativeToUnsigned() noreturn {
            @branchHint(.cold);
            call("attempt to cast negative value to unsigned integer", @returnAddress());
        }
        pub fn integerOverflow() noreturn {
            @branchHint(.cold);
            call("integer overflow", @returnAddress());
        }
        pub fn shlOverflow() noreturn {
            @branchHint(.cold);
            call("left shift overflowed bits", @returnAddress());
        }
        pub fn shrOverflow() noreturn {
            @branchHint(.cold);
            call("right shift overflowed bits", @returnAddress());
        }
        pub fn divideByZero() noreturn {
            @branchHint(.cold);
            call("division by zero", @returnAddress());
        }
        pub fn exactDivisionRemainder() noreturn {
            @branchHint(.cold);
            call("exact division produced remainder", @returnAddress());
        }
        pub fn integerPartOutOfBounds() noreturn {
            @branchHint(.cold);
            call("integer part of floating point value out of bounds", @returnAddress());
        }
        pub fn corruptSwitch() noreturn {
            @branchHint(.cold);
            call("switch on corrupt value", @returnAddress());
        }
        pub fn shiftRhsTooBig() noreturn {
            @branchHint(.cold);
            call("shift amount is greater than the type size", @returnAddress());
        }
        pub fn invalidEnumValue() noreturn {
            @branchHint(.cold);
            call("invalid enum value", @returnAddress());
        }
        pub fn forLenMismatch() noreturn {
            @branchHint(.cold);
            call("for loop over objects with non-equal lengths", @returnAddress());
        }
        pub fn memcpyLenMismatch() noreturn {
            @branchHint(.cold);
            call("@memcpy arguments have non-equal lengths", @returnAddress());
        }
        pub fn memcpyAlias() noreturn {
            @branchHint(.cold);
            call("@memcpy arguments alias", @returnAddress());
        }
        pub fn memmoveLenMismatch() noreturn {
            @branchHint(.cold);
            call("@memmove arguments have non-equal lengths", @returnAddress());
        }
        pub fn noreturnReturned() noreturn {
            @branchHint(.cold);
            call("'noreturn' function returned", @returnAddress());
        }
    };
}

/// Unresolved source locations can be represented with a single `usize` that
/// corresponds to a virtual memory address of the program counter. Combined
/// with debug information, those values can be converted into a resolved
/// source location, including file, line, and column.
pub const SourceLocation = struct {
    line: u64,
    column: u64,
    file_name: []const u8,

    pub const invalid: SourceLocation = .{
        .line = 0,
        .column = 0,
        .file_name = &.{},
    };
};

pub const Symbol = struct {
    name: []const u8 = "???",
    compile_unit_name: []const u8 = "???",
    source_location: ?SourceLocation = null,
};

/// Deprecated because it returns the optimization mode of the standard
/// library, when the caller probably wants to use the optimization mode of
/// their own module.
pub const runtime_safety = switch (builtin.mode) {
    .Debug, .ReleaseSafe => true,
    .ReleaseFast, .ReleaseSmall => false,
};

pub const sys_can_stack_trace = switch (builtin.cpu.arch) {
    // Observed to go into an infinite loop.
    // TODO: Make this work.
    .mips,
    .mipsel,
    .mips64,
    .mips64el,
    .s390x,
    => false,

    // `@returnAddress()` in LLVM 10 gives
    // "Non-Emscripten WebAssembly hasn't implemented __builtin_return_address".
    // On Emscripten, Zig only supports `@returnAddress()` in debug builds
    // because Emscripten's implementation is very slow.
    .wasm32,
    .wasm64,
    => native_os == .emscripten and builtin.mode == .Debug,

    // `@returnAddress()` is unsupported in LLVM 13.
    .bpfel,
    .bpfeb,
    => false,

    else => true,
};

/// Allows the caller to freely write to stderr until `unlockStdErr` is called.
///
/// During the lock, any `std.Progress` information is cleared from the terminal.
pub fn lockStdErr() void {
    std.Progress.lockStdErr();
}

pub fn unlockStdErr() void {
    std.Progress.unlockStdErr();
}

/// Print to stderr, unbuffered, and silently returning on failure. Intended
/// for use in "printf debugging." Use `std.log` functions for proper logging.
pub fn print(comptime fmt: []const u8, args: anytype) void {
    lockStdErr();
    defer unlockStdErr();
    const stderr = io.getStdErr().writer();
    nosuspend stderr.print(fmt, args) catch return;
}

pub fn getStderrMutex() *std.Thread.Mutex {
    @compileError("deprecated. call std.debug.lockStdErr() and std.debug.unlockStdErr() instead which will integrate properly with std.Progress");
}

/// TODO multithreaded awareness
var self_debug_info: ?SelfInfo = null;

pub fn getSelfDebugInfo() !*SelfInfo {
    if (self_debug_info) |*info| {
        return info;
    } else {
        self_debug_info = try SelfInfo.open(getDebugInfoAllocator());
        return &self_debug_info.?;
    }
}

/// Tries to print a hexadecimal view of the bytes, unbuffered, and ignores any error returned.
/// Obtains the stderr mutex while dumping.
pub fn dumpHex(bytes: []const u8) void {
    lockStdErr();
    defer unlockStdErr();
    dumpHexFallible(bytes) catch {};
}

/// Prints a hexadecimal view of the bytes, unbuffered, returning any error that occurs.
pub fn dumpHexFallible(bytes: []const u8) !void {
    const stderr = std.io.getStdErr();
    const ttyconf = std.io.tty.detectConfig(stderr);
    const writer = stderr.writer();
    try dumpHexInternal(bytes, ttyconf, writer);
}

fn dumpHexInternal(bytes: []const u8, ttyconf: std.io.tty.Config, writer: anytype) !void {
    var chunks = mem.window(u8, bytes, 16, 16);
    while (chunks.next()) |window| {
        // 1. Print the address.
        const address = (@intFromPtr(bytes.ptr) + 0x10 * (std.math.divCeil(usize, chunks.index orelse bytes.len, 16) catch unreachable)) - 0x10;
        try ttyconf.setColor(writer, .dim);
        // We print the address in lowercase and the bytes in uppercase hexadecimal to distinguish them more.
        // Also, make sure all lines are aligned by padding the address.
        try writer.print("{x:0>[1]}  ", .{ address, @sizeOf(usize) * 2 });
        try ttyconf.setColor(writer, .reset);

        // 2. Print the bytes.
        for (window, 0..) |byte, index| {
            try writer.print("{X:0>2} ", .{byte});
            if (index == 7) try writer.writeByte(' ');
        }
        try writer.writeByte(' ');
        if (window.len < 16) {
            var missing_columns = (16 - window.len) * 3;
            if (window.len < 8) missing_columns += 1;
            try writer.writeByteNTimes(' ', missing_columns);
        }

        // 3. Print the characters.
        for (window) |byte| {
            if (std.ascii.isPrint(byte)) {
                try writer.writeByte(byte);
            } else {
                // Related: https://github.com/ziglang/zig/issues/7600
                if (ttyconf == .windows_api) {
                    try writer.writeByte('.');
                    continue;
                }

                // Let's print some common control codes as graphical Unicode symbols.
                // We don't want to do this for all control codes because most control codes apart from
                // the ones that Zig has escape sequences for are likely not very useful to print as symbols.
                switch (byte) {
                    '\n' => try writer.writeAll("␊"),
                    '\r' => try writer.writeAll("␍"),
                    '\t' => try writer.writeAll("␉"),
                    else => try writer.writeByte('.'),
                }
            }
        }
        try writer.writeByte('\n');
    }
}

test dumpHexInternal {
    const bytes: []const u8 = &.{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x12, 0x13 };
    var output = std.ArrayList(u8).init(std.testing.allocator);
    defer output.deinit();
    try dumpHexInternal(bytes, .no_color, output.writer());
    const expected = try std.fmt.allocPrint(std.testing.allocator,
        \\{x:0>[2]}  00 11 22 33 44 55 66 77  88 99 AA BB CC DD EE FF  .."3DUfw........
        \\{x:0>[2]}  01 12 13                                          ...
        \\
    , .{
        @intFromPtr(bytes.ptr),
        @intFromPtr(bytes.ptr) + 16,
        @sizeOf(usize) * 2,
    });
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, output.items);
}

/// Tries to print the current stack trace to stderr, unbuffered, and ignores any error returned.
/// TODO multithreaded awareness
pub fn dumpCurrentStackTrace(start_addr: ?usize) void {
    nosuspend {
        if (builtin.target.cpu.arch.isWasm()) {
            if (native_os == .wasi) {
                const stderr = io.getStdErr().writer();
                stderr.print("Unable to dump stack trace: not implemented for Wasm\n", .{}) catch return;
            }
            return;
        }
        const stderr = io.getStdErr().writer();
        if (builtin.strip_debug_info) {
            stderr.print("Unable to dump stack trace: debug info stripped\n", .{}) catch return;
            return;
        }
        const debug_info = getSelfDebugInfo() catch |err| {
            stderr.print("Unable to dump stack trace: Unable to open debug info: {s}\n", .{@errorName(err)}) catch return;
            return;
        };
        writeCurrentStackTrace(stderr, debug_info, io.tty.detectConfig(io.getStdErr()), start_addr) catch |err| {
            stderr.print("Unable to dump stack trace: {s}\n", .{@errorName(err)}) catch return;
            return;
        };
    }
}

pub const have_ucontext = posix.ucontext_t != void;

/// Platform-specific thread state. This contains register state, and on some platforms
/// information about the stack. This is not safe to trivially copy, because some platforms
/// use internal pointers within this structure. To make a copy, use `copyContext`.
pub const ThreadContext = blk: {
    if (native_os == .windows) {
        break :blk windows.CONTEXT;
    } else if (have_ucontext) {
        break :blk posix.ucontext_t;
    } else {
        break :blk void;
    }
};

/// Copies one context to another, updating any internal pointers
pub fn copyContext(source: *const ThreadContext, dest: *ThreadContext) void {
    if (!have_ucontext) return {};
    dest.* = source.*;
    relocateContext(dest);
}

/// Updates any internal pointers in the context to reflect its current location
pub fn relocateContext(context: *ThreadContext) void {
    return switch (native_os) {
        .macos => {
            context.mcontext = &context.__mcontext_data;
        },
        else => {},
    };
}

pub const have_getcontext = @TypeOf(posix.system.getcontext) != void;

/// Capture the current context. The register values in the context will reflect the
/// state after the platform `getcontext` function returns.
///
/// It is valid to call this if the platform doesn't have context capturing support,
/// in that case false will be returned.
pub inline fn getContext(context: *ThreadContext) bool {
    if (native_os == .windows) {
        context.* = std.mem.zeroes(windows.CONTEXT);
        windows.ntdll.RtlCaptureContext(context);
        return true;
    }

    const result = have_getcontext and posix.system.getcontext(context) == 0;
    if (native_os == .macos) {
        assert(context.mcsize == @sizeOf(std.c.mcontext_t));

        // On aarch64-macos, the system getcontext doesn't write anything into the pc
        // register slot, it only writes lr. This makes the context consistent with
        // other aarch64 getcontext implementations which write the current lr
        // (where getcontext will return to) into both the lr and pc slot of the context.
        if (native_arch == .aarch64) context.mcontext.ss.pc = context.mcontext.ss.lr;
    }

    return result;
}

/// Tries to print the stack trace starting from the supplied base pointer to stderr,
/// unbuffered, and ignores any error returned.
/// TODO multithreaded awareness
pub fn dumpStackTraceFromBase(context: *ThreadContext) void {
    nosuspend {
        if (builtin.target.cpu.arch.isWasm()) {
            if (native_os == .wasi) {
                const stderr = io.getStdErr().writer();
                stderr.print("Unable to dump stack trace: not implemented for Wasm\n", .{}) catch return;
            }
            return;
        }
        const stderr = io.getStdErr().writer();
        if (builtin.strip_debug_info) {
            stderr.print("Unable to dump stack trace: debug info stripped\n", .{}) catch return;
            return;
        }
        const debug_info = getSelfDebugInfo() catch |err| {
            stderr.print("Unable to dump stack trace: Unable to open debug info: {s}\n", .{@errorName(err)}) catch return;
            return;
        };
        const tty_config = io.tty.detectConfig(io.getStdErr());
        if (native_os == .windows) {
            // On x86_64 and aarch64, the stack will be unwound using RtlVirtualUnwind using the context
            // provided by the exception handler. On x86, RtlVirtualUnwind doesn't exist. Instead, a new backtrace
            // will be captured and frames prior to the exception will be filtered.
            // The caveat is that RtlCaptureStackBackTrace does not include the KiUserExceptionDispatcher frame,
            // which is where the IP in `context` points to, so it can't be used as start_addr.
            // Instead, start_addr is recovered from the stack.
            const start_addr = if (builtin.cpu.arch == .x86) @as(*const usize, @ptrFromInt(context.getRegs().bp + 4)).* else null;
            writeStackTraceWindows(stderr, debug_info, tty_config, context, start_addr) catch return;
            return;
        }

        var it = StackIterator.initWithContext(null, debug_info, context) catch return;
        defer it.deinit();
        printSourceAtAddress(debug_info, stderr, it.unwind_state.?.dwarf_context.pc, tty_config) catch return;

        while (it.next()) |return_address| {
            printLastUnwindError(&it, debug_info, stderr, tty_config);

            // On arm64 macOS, the address of the last frame is 0x0 rather than 0x1 as on x86_64 macOS,
            // therefore, we do a check for `return_address == 0` before subtracting 1 from it to avoid
            // an overflow. We do not need to signal `StackIterator` as it will correctly detect this
            // condition on the subsequent iteration and return `null` thus terminating the loop.
            // same behaviour for x86-windows-msvc
            const address = if (return_address == 0) return_address else return_address - 1;
            printSourceAtAddress(debug_info, stderr, address, tty_config) catch return;
        } else printLastUnwindError(&it, debug_info, stderr, tty_config);
    }
}

/// Returns a slice with the same pointer as addresses, with a potentially smaller len.
/// On Windows, when first_address is not null, we ask for at least 32 stack frames,
/// and then try to find the first address. If addresses.len is more than 32, we
/// capture that many stack frames exactly, and then look for the first address,
/// chopping off the irrelevant frames and shifting so that the returned addresses pointer
/// equals the passed in addresses pointer.
pub fn captureStackTrace(first_address: ?usize, stack_trace: *std.builtin.StackTrace) void {
    if (native_os == .windows) {
        const addrs = stack_trace.instruction_addresses;
        const first_addr = first_address orelse {
            stack_trace.index = walkStackWindows(addrs[0..], null);
            return;
        };
        var addr_buf_stack: [32]usize = undefined;
        const addr_buf = if (addr_buf_stack.len > addrs.len) addr_buf_stack[0..] else addrs;
        const n = walkStackWindows(addr_buf[0..], null);
        const first_index = for (addr_buf[0..n], 0..) |addr, i| {
            if (addr == first_addr) {
                break i;
            }
        } else {
            stack_trace.index = 0;
            return;
        };
        const end_index = @min(first_index + addrs.len, n);
        const slice = addr_buf[first_index..end_index];
        // We use a for loop here because slice and addrs may alias.
        for (slice, 0..) |addr, i| {
            addrs[i] = addr;
        }
        stack_trace.index = slice.len;
    } else {
        // TODO: This should use the DWARF unwinder if .eh_frame_hdr is available (so that full debug info parsing isn't required).
        //       A new path for loading SelfInfo needs to be created which will only attempt to parse in-memory sections, because
        //       stopping to load other debug info (ie. source line info) from disk here is not required for unwinding.
        var it = StackIterator.init(first_address, null);
        defer it.deinit();
        for (stack_trace.instruction_addresses, 0..) |*addr, i| {
            addr.* = it.next() orelse {
                stack_trace.index = i;
                return;
            };
        }
        stack_trace.index = stack_trace.instruction_addresses.len;
    }
}

/// Tries to print a stack trace to stderr, unbuffered, and ignores any error returned.
/// TODO multithreaded awareness
pub fn dumpStackTrace(stack_trace: std.builtin.StackTrace) void {
    nosuspend {
        if (builtin.target.cpu.arch.isWasm()) {
            if (native_os == .wasi) {
                const stderr = io.getStdErr().writer();
                stderr.print("Unable to dump stack trace: not implemented for Wasm\n", .{}) catch return;
            }
            return;
        }
        const stderr = io.getStdErr().writer();
        if (builtin.strip_debug_info) {
            stderr.print("Unable to dump stack trace: debug info stripped\n", .{}) catch return;
            return;
        }
        const debug_info = getSelfDebugInfo() catch |err| {
            stderr.print("Unable to dump stack trace: Unable to open debug info: {s}\n", .{@errorName(err)}) catch return;
            return;
        };
        writeStackTrace(stack_trace, stderr, debug_info, io.tty.detectConfig(io.getStdErr())) catch |err| {
            stderr.print("Unable to dump stack trace: {s}\n", .{@errorName(err)}) catch return;
            return;
        };
    }
}

/// Invokes detectable illegal behavior when `ok` is `false`.
///
/// In Debug and ReleaseSafe modes, calls to this function are always
/// generated, and the `unreachable` statement triggers a panic.
///
/// In ReleaseFast and ReleaseSmall modes, calls to this function are optimized
/// away, and in fact the optimizer is able to use the assertion in its
/// heuristics.
///
/// Inside a test block, it is best to use the `std.testing` module rather than
/// this function, because this function may not detect a test failure in
/// ReleaseFast and ReleaseSmall mode. Outside of a test block, this assert
/// function is the correct function to use.
pub fn assert(ok: bool) void {
    if (!ok) unreachable; // assertion failure
}

/// Invokes detectable illegal behavior when the provided slice is not mapped
/// or lacks read permissions.
pub fn assertReadable(slice: []const volatile u8) void {
    if (!runtime_safety) return;
    for (slice) |*byte| _ = byte.*;
}

/// Equivalent to `@panic` but with a formatted message.
pub fn panic(comptime format: []const u8, args: anytype) noreturn {
    @branchHint(.cold);
    panicExtra(@returnAddress(), format, args);
}

/// Equivalent to `@panic` but with a formatted message, and with an explicitly
/// provided return address.
pub fn panicExtra(
    ret_addr: ?usize,
    comptime format: []const u8,
    args: anytype,
) noreturn {
    @branchHint(.cold);

    const size = 0x1000;
    const trunc_msg = "(msg truncated)";
    var buf: [size + trunc_msg.len]u8 = undefined;
    // a minor annoyance with this is that it will result in the NoSpaceLeft
    // error being part of the @panic stack trace (but that error should
    // only happen rarely)
    const msg = std.fmt.bufPrint(buf[0..size], format, args) catch |err| switch (err) {
        error.NoSpaceLeft => blk: {
            @memcpy(buf[size..], trunc_msg);
            break :blk &buf;
        },
    };
    std.builtin.panic.call(msg, ret_addr);
}

/// Non-zero whenever the program triggered a panic.
/// The counter is incremented/decremented atomically.
var panicking = std.atomic.Value(u8).init(0);

/// Counts how many times the panic handler is invoked by this thread.
/// This is used to catch and handle panics triggered by the panic handler.
threadlocal var panic_stage: usize = 0;

/// Dumps a stack trace to standard error, then aborts.
pub fn defaultPanic(
    msg: []const u8,
    first_trace_addr: ?usize,
) noreturn {
    @branchHint(.cold);

    // For backends that cannot handle the language features depended on by the
    // default panic handler, we have a simpler panic handler:
    if (builtin.zig_backend == .stage2_wasm or
        builtin.zig_backend == .stage2_arm or
        builtin.zig_backend == .stage2_aarch64 or
        builtin.zig_backend == .stage2_x86 or
        (builtin.zig_backend == .stage2_x86_64 and (builtin.target.ofmt != .elf and builtin.target.ofmt != .macho)) or
        builtin.zig_backend == .stage2_sparc64 or
        builtin.zig_backend == .stage2_spirv64)
    {
        @trap();
    }

    switch (builtin.os.tag) {
        .freestanding, .other => {
            @trap();
        },
        .uefi => {
            const uefi = std.os.uefi;

            var utf16_buffer: [1000]u16 = undefined;
            const len_minus_3 = std.unicode.utf8ToUtf16Le(&utf16_buffer, msg) catch 0;
            utf16_buffer[len_minus_3..][0..3].* = .{ '\r', '\n', 0 };
            const len = len_minus_3 + 3;
            const exit_msg = utf16_buffer[0 .. len - 1 :0];

            // Output to both std_err and con_out, as std_err is easier
            // to read in stuff like QEMU at times, but, unlike con_out,
            // isn't visible on actual hardware if directly booted into
            inline for ([_]?*uefi.protocol.SimpleTextOutput{ uefi.system_table.std_err, uefi.system_table.con_out }) |o| {
                if (o) |out| {
                    out.setAttribute(.{ .foreground = .red }) catch {};
                    _ = out.outputString(exit_msg) catch {};
                    out.setAttribute(.{ .foreground = .white }) catch {};
                }
            }

            if (uefi.system_table.boot_services) |bs| {
                // ExitData buffer must be allocated using boot_services.allocatePool (spec: page 220)
                const exit_data: []u16 = uefi.raw_pool_allocator.alloc(u16, exit_msg.len + 1) catch @trap();
                @memcpy(exit_data, exit_msg[0..exit_data.len]); // Includes null terminator.
                _ = bs.exit(uefi.handle, .aborted, exit_data.len, exit_data.ptr);
            }
            @trap();
        },
        .cuda, .amdhsa => std.posix.abort(),
        .plan9 => {
            var status: [std.os.plan9.ERRMAX]u8 = undefined;
            const len = @min(msg.len, status.len - 1);
            @memcpy(status[0..len], msg[0..len]);
            status[len] = 0;
            std.os.plan9.exits(status[0..len :0]);
        },
        else => {},
    }

    if (enable_segfault_handler) {
        // If a segfault happens while panicking, we want it to actually segfault, not trigger
        // the handler.
        resetSegfaultHandler();
    }

    // Note there is similar logic in handleSegfaultPosix and handleSegfaultWindowsExtra.
    nosuspend switch (panic_stage) {
        0 => {
            panic_stage = 1;

            _ = panicking.fetchAdd(1, .seq_cst);

            {
                lockStdErr();
                defer unlockStdErr();

                const stderr = io.getStdErr().writer();
                if (builtin.single_threaded) {
                    stderr.print("panic: ", .{}) catch posix.abort();
                } else {
                    const current_thread_id = std.Thread.getCurrentId();
                    stderr.print("thread {} panic: ", .{current_thread_id}) catch posix.abort();
                }
                stderr.print("{s}\n", .{msg}) catch posix.abort();

                if (@errorReturnTrace()) |t| dumpStackTrace(t.*);
                dumpCurrentStackTrace(first_trace_addr orelse @returnAddress());
            }

            waitForOtherThreadToFinishPanicking();
        },
        1 => {
            panic_stage = 2;

            // A panic happened while trying to print a previous panic message.
            // We're still holding the mutex but that's fine as we're going to
            // call abort().
            io.getStdErr().writeAll("aborting due to recursive panic\n") catch {};
        },
        else => {}, // Panicked while printing the recursive panic message.
    };

    posix.abort();
}

/// Must be called only after adding 1 to `panicking`. There are three callsites.
fn waitForOtherThreadToFinishPanicking() void {
    if (panicking.fetchSub(1, .seq_cst) != 1) {
        // Another thread is panicking, wait for the last one to finish
        // and call abort()
        if (builtin.single_threaded) unreachable;

        // Sleep forever without hammering the CPU
        var futex = std.atomic.Value(u32).init(0);
        while (true) std.Thread.Futex.wait(&futex, 0);
        unreachable;
    }
}

pub fn writeStackTrace(
    stack_trace: std.builtin.StackTrace,
    out_stream: anytype,
    debug_info: *SelfInfo,
    tty_config: io.tty.Config,
) !void {
    if (builtin.strip_debug_info) return error.MissingDebugInfo;
    var frame_index: usize = 0;
    var frames_left: usize = @min(stack_trace.index, stack_trace.instruction_addresses.len);

    while (frames_left != 0) : ({
        frames_left -= 1;
        frame_index = (frame_index + 1) % stack_trace.instruction_addresses.len;
    }) {
        const return_address = stack_trace.instruction_addresses[frame_index];
        try printSourceAtAddress(debug_info, out_stream, return_address - 1, tty_config);
    }

    if (stack_trace.index > stack_trace.instruction_addresses.len) {
        const dropped_frames = stack_trace.index - stack_trace.instruction_addresses.len;

        tty_config.setColor(out_stream, .bold) catch {};
        try out_stream.print("({d} additional stack frames skipped...)\n", .{dropped_frames});
        tty_config.setColor(out_stream, .reset) catch {};
    }
}

pub const UnwindError = if (have_ucontext)
    @typeInfo(@typeInfo(@TypeOf(StackIterator.next_unwind)).@"fn".return_type.?).error_union.error_set
else
    void;

pub const StackIterator = struct {
    // Skip every frame before this address is found.
    first_address: ?usize,
    // Last known value of the frame pointer register.
    fp: usize,
    ma: MemoryAccessor = MemoryAccessor.init,

    // When SelfInfo and a register context is available, this iterator can unwind
    // stacks with frames that don't use a frame pointer (ie. -fomit-frame-pointer),
    // using DWARF and MachO unwind info.
    unwind_state: if (have_ucontext) ?struct {
        debug_info: *SelfInfo,
        dwarf_context: SelfInfo.UnwindContext,
        last_error: ?UnwindError = null,
        failed: bool = false,
    } else void = if (have_ucontext) null else {},

    pub fn init(first_address: ?usize, fp: ?usize) StackIterator {
        if (native_arch.isSPARC()) {
            // Flush all the register windows on stack.
            asm volatile (if (std.Target.sparc.featureSetHas(builtin.cpu.features, .v9))
                    "flushw"
                else
                    "ta 3" // ST_FLUSH_WINDOWS
                ::: "memory");
        }

        return StackIterator{
            .first_address = first_address,
            // TODO: this is a workaround for #16876
            //.fp = fp orelse @frameAddress(),
            .fp = fp orelse blk: {
                const fa = @frameAddress();
                break :blk fa;
            },
        };
    }

    pub fn initWithContext(first_address: ?usize, debug_info: *SelfInfo, context: *posix.ucontext_t) !StackIterator {
        // The implementation of DWARF unwinding on aarch64-macos is not complete. However, Apple mandates that
        // the frame pointer register is always used, so on this platform we can safely use the FP-based unwinder.
        if (builtin.target.os.tag.isDarwin() and native_arch == .aarch64)
            return init(first_address, @truncate(context.mcontext.ss.fp));

        if (SelfInfo.supports_unwinding) {
            var iterator = init(first_address, null);
            iterator.unwind_state = .{
                .debug_info = debug_info,
                .dwarf_context = try SelfInfo.UnwindContext.init(debug_info.allocator, context),
            };
            return iterator;
        }

        return init(first_address, null);
    }

    pub fn deinit(it: *StackIterator) void {
        it.ma.deinit();
        if (have_ucontext and it.unwind_state != null) it.unwind_state.?.dwarf_context.deinit();
    }

    pub fn getLastError(it: *StackIterator) ?struct {
        err: UnwindError,
        address: usize,
    } {
        if (!have_ucontext) return null;
        if (it.unwind_state) |*unwind_state| {
            if (unwind_state.last_error) |err| {
                unwind_state.last_error = null;
                return .{
                    .err = err,
                    .address = unwind_state.dwarf_context.pc,
                };
            }
        }

        return null;
    }

    // Offset of the saved BP wrt the frame pointer.
    const fp_offset = if (native_arch.isRISCV())
        // On RISC-V the frame pointer points to the top of the saved register
        // area, on pretty mu```
