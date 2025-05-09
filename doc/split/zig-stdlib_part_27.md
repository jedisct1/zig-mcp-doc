```
07 }, .X9_62_prime256v1 },
    });

    pub fn Curve(comptime curve: NamedCurve) type {
        return switch (curve) {
            .X9_62_prime256v1 => crypto.ecc.P256,
            .secp384r1 => crypto.ecc.P384,
            .secp521r1 => @compileError("unimplemented"),
        };
    }
};

pub const ExtensionId = enum {
    subject_key_identifier,
    key_usage,
    private_key_usage_period,
    subject_alt_name,
    issuer_alt_name,
    basic_constraints,
    crl_number,
    certificate_policies,
    authority_key_identifier,
    msCertsrvCAVersion,
    commonName,
    ext_key_usage,
    crl_distribution_points,
    info_access,
    entrustVersInfo,
    enroll_certtype,
    pe_logotype,
    netscape_cert_type,
    netscape_comment,

    pub const map = std.StaticStringMap(ExtensionId).initComptime(.{
        .{ &.{ 0x55, 0x04, 0x03 }, .commonName },
        .{ &.{ 0x55, 0x1D, 0x01 }, .authority_key_identifier },
        .{ &.{ 0x55, 0x1D, 0x07 }, .subject_alt_name },
        .{ &.{ 0x55, 0x1D, 0x0E }, .subject_key_identifier },
        .{ &.{ 0x55, 0x1D, 0x0F }, .key_usage },
        .{ &.{ 0x55, 0x1D, 0x0A }, .basic_constraints },
        .{ &.{ 0x55, 0x1D, 0x10 }, .private_key_usage_period },
        .{ &.{ 0x55, 0x1D, 0x11 }, .subject_alt_name },
        .{ &.{ 0x55, 0x1D, 0x12 }, .issuer_alt_name },
        .{ &.{ 0x55, 0x1D, 0x13 }, .basic_constraints },
        .{ &.{ 0x55, 0x1D, 0x14 }, .crl_number },
        .{ &.{ 0x55, 0x1D, 0x1F }, .crl_distribution_points },
        .{ &.{ 0x55, 0x1D, 0x20 }, .certificate_policies },
        .{ &.{ 0x55, 0x1D, 0x23 }, .authority_key_identifier },
        .{ &.{ 0x55, 0x1D, 0x25 }, .ext_key_usage },
        .{ &.{ 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x01 }, .msCertsrvCAVersion },
        .{ &.{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 }, .info_access },
        .{ &.{ 0x2A, 0x86, 0x48, 0x86, 0xF6, 0x7D, 0x07, 0x41, 0x00 }, .entrustVersInfo },
        .{ &.{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02 }, .enroll_certtype },
        .{ &.{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0c }, .pe_logotype },
        .{ &.{ 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01 }, .netscape_cert_type },
        .{ &.{ 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x0d }, .netscape_comment },
    });
};

pub const GeneralNameTag = enum(u5) {
    otherName = 0,
    rfc822Name = 1,
    dNSName = 2,
    x400Address = 3,
    directoryName = 4,
    ediPartyName = 5,
    uniformResourceIdentifier = 6,
    iPAddress = 7,
    registeredID = 8,
    _,
};

pub const Parsed = struct {
    certificate: Certificate,
    issuer_slice: Slice,
    subject_slice: Slice,
    common_name_slice: Slice,
    signature_slice: Slice,
    signature_algorithm: Algorithm,
    pub_key_algo: PubKeyAlgo,
    pub_key_slice: Slice,
    message_slice: Slice,
    subject_alt_name_slice: Slice,
    validity: Validity,
    version: Version,

    pub const PubKeyAlgo = union(AlgorithmCategory) {
        rsaEncryption: void,
        rsassa_pss: void,
        X9_62_id_ecPublicKey: NamedCurve,
        curveEd25519: void,
    };

    pub const Validity = struct {
        not_before: u64,
        not_after: u64,
    };

    pub const Slice = der.Element.Slice;

    pub fn slice(p: Parsed, s: Slice) []const u8 {
        return p.certificate.buffer[s.start..s.end];
    }

    pub fn issuer(p: Parsed) []const u8 {
        return p.slice(p.issuer_slice);
    }

    pub fn subject(p: Parsed) []const u8 {
        return p.slice(p.subject_slice);
    }

    pub fn commonName(p: Parsed) []const u8 {
        return p.slice(p.common_name_slice);
    }

    pub fn signature(p: Parsed) []const u8 {
        return p.slice(p.signature_slice);
    }

    pub fn pubKey(p: Parsed) []const u8 {
        return p.slice(p.pub_key_slice);
    }

    pub fn pubKeySigAlgo(p: Parsed) []const u8 {
        return p.slice(p.pub_key_signature_algorithm_slice);
    }

    pub fn message(p: Parsed) []const u8 {
        return p.slice(p.message_slice);
    }

    pub fn subjectAltName(p: Parsed) []const u8 {
        return p.slice(p.subject_alt_name_slice);
    }

    pub const VerifyError = error{
        CertificateIssuerMismatch,
        CertificateNotYetValid,
        CertificateExpired,
        CertificateSignatureAlgorithmUnsupported,
        CertificateSignatureAlgorithmMismatch,
        CertificateFieldHasInvalidLength,
        CertificateFieldHasWrongDataType,
        CertificatePublicKeyInvalid,
        CertificateSignatureInvalidLength,
        CertificateSignatureInvalid,
        CertificateSignatureUnsupportedBitCount,
        CertificateSignatureNamedCurveUnsupported,
    };

    /// This function verifies:
    ///  * That the subject's issuer is indeed the provided issuer.
    ///  * The time validity of the subject.
    ///  * The signature.
    pub fn verify(parsed_subject: Parsed, parsed_issuer: Parsed, now_sec: i64) VerifyError!void {
        // Check that the subject's issuer name matches the issuer's
        // subject name.
        if (!mem.eql(u8, parsed_subject.issuer(), parsed_issuer.subject())) {
            return error.CertificateIssuerMismatch;
        }

        if (now_sec < parsed_subject.validity.not_before)
            return error.CertificateNotYetValid;
        if (now_sec > parsed_subject.validity.not_after)
            return error.CertificateExpired;

        switch (parsed_subject.signature_algorithm) {
            inline .sha1WithRSAEncryption,
            .sha224WithRSAEncryption,
            .sha256WithRSAEncryption,
            .sha384WithRSAEncryption,
            .sha512WithRSAEncryption,
            => |algorithm| return verifyRsa(
                algorithm.Hash(),
                parsed_subject.message(),
                parsed_subject.signature(),
                parsed_issuer.pub_key_algo,
                parsed_issuer.pubKey(),
            ),

            inline .ecdsa_with_SHA224,
            .ecdsa_with_SHA256,
            .ecdsa_with_SHA384,
            .ecdsa_with_SHA512,
            => |algorithm| return verify_ecdsa(
                algorithm.Hash(),
                parsed_subject.message(),
                parsed_subject.signature(),
                parsed_issuer.pub_key_algo,
                parsed_issuer.pubKey(),
            ),

            .md2WithRSAEncryption, .md5WithRSAEncryption => {
                return error.CertificateSignatureAlgorithmUnsupported;
            },

            .curveEd25519 => return verifyEd25519(
                parsed_subject.message(),
                parsed_subject.signature(),
                parsed_issuer.pub_key_algo,
                parsed_issuer.pubKey(),
            ),
        }
    }

    pub const VerifyHostNameError = error{
        CertificateHostMismatch,
        CertificateFieldHasInvalidLength,
    };

    pub fn verifyHostName(parsed_subject: Parsed, host_name: []const u8) VerifyHostNameError!void {
        // If the Subject Alternative Names extension is present, this is
        // what to check. Otherwise, only the common name is checked.
        const subject_alt_name = parsed_subject.subjectAltName();
        if (subject_alt_name.len == 0) {
            if (checkHostName(host_name, parsed_subject.commonName())) {
                return;
            } else {
                return error.CertificateHostMismatch;
            }
        }

        const general_names = try der.Element.parse(subject_alt_name, 0);
        var name_i = general_names.slice.start;
        while (name_i < general_names.slice.end) {
            const general_name = try der.Element.parse(subject_alt_name, name_i);
            name_i = general_name.slice.end;
            switch (@as(GeneralNameTag, @enumFromInt(@intFromEnum(general_name.identifier.tag)))) {
                .dNSName => {
                    const dns_name = subject_alt_name[general_name.slice.start..general_name.slice.end];
                    if (checkHostName(host_name, dns_name)) return;
                },
                else => {},
            }
        }

        return error.CertificateHostMismatch;
    }

    // Check hostname according to RFC2818 specification:
    //
    // If more than one identity of a given type is present in
    // the certificate (e.g., more than one DNSName name, a match in any one
    // of the set is considered acceptable.) Names may contain the wildcard
    // character * which is considered to match any single domain name
    // component or component fragment. E.g., *.a.com matches foo.a.com but
    // not bar.foo.a.com. f*.com matches foo.com but not bar.com.
    fn checkHostName(host_name: []const u8, dns_name: []const u8) bool {
        if (std.ascii.eqlIgnoreCase(dns_name, host_name)) {
            return true; // exact match
        }

        var it_host = std.mem.splitScalar(u8, host_name, '.');
        var it_dns = std.mem.splitScalar(u8, dns_name, '.');

        const len_match = while (true) {
            const host = it_host.next();
            const dns = it_dns.next();

            if (host == null or dns == null) {
                break host == null and dns == null;
            }

            // If not a wildcard and they dont
            // match then there is no match.
            if (mem.eql(u8, dns.?, "*") == false and std.ascii.eqlIgnoreCase(dns.?, host.?) == false) {
                return false;
            }
        };

        // If the components are not the same
        // length then there is no match.
        return len_match;
    }
};

test "Parsed.checkHostName" {
    const expectEqual = std.testing.expectEqual;

    try expectEqual(true, Parsed.checkHostName("ziglang.org", "ziglang.org"));
    try expectEqual(true, Parsed.checkHostName("bar.ziglang.org", "*.ziglang.org"));
    try expectEqual(false, Parsed.checkHostName("foo.bar.ziglang.org", "*.ziglang.org"));
    try expectEqual(false, Parsed.checkHostName("ziglang.org", "zig*.org"));
    try expectEqual(false, Parsed.checkHostName("lang.org", "zig*.org"));
    // host name check should be case insensitive
    try expectEqual(true, Parsed.checkHostName("ziglang.org", "Ziglang.org"));
    try expectEqual(true, Parsed.checkHostName("bar.ziglang.org", "*.Ziglang.ORG"));
}

pub const ParseError = der.Element.ParseError || ParseVersionError || ParseTimeError || ParseEnumError || ParseBitStringError;

pub fn parse(cert: Certificate) ParseError!Parsed {
    const cert_bytes = cert.buffer;
    const certificate = try der.Element.parse(cert_bytes, cert.index);
    const tbs_certificate = try der.Element.parse(cert_bytes, certificate.slice.start);
    const version_elem = try der.Element.parse(cert_bytes, tbs_certificate.slice.start);
    const version = try parseVersion(cert_bytes, version_elem);
    const serial_number = if (@as(u8, @bitCast(version_elem.identifier)) == 0xa0)
        try der.Element.parse(cert_bytes, version_elem.slice.end)
    else
        version_elem;
    // RFC 5280, section 4.1.2.3:
    // "This field MUST contain the same algorithm identifier as
    // the signatureAlgorithm field in the sequence Certificate."
    const tbs_signature = try der.Element.parse(cert_bytes, serial_number.slice.end);
    const issuer = try der.Element.parse(cert_bytes, tbs_signature.slice.end);
    const validity = try der.Element.parse(cert_bytes, issuer.slice.end);
    const not_before = try der.Element.parse(cert_bytes, validity.slice.start);
    const not_before_utc = try parseTime(cert, not_before);
    const not_after = try der.Element.parse(cert_bytes, not_before.slice.end);
    const not_after_utc = try parseTime(cert, not_after);
    const subject = try der.Element.parse(cert_bytes, validity.slice.end);

    const pub_key_info = try der.Element.parse(cert_bytes, subject.slice.end);
    const pub_key_signature_algorithm = try der.Element.parse(cert_bytes, pub_key_info.slice.start);
    const pub_key_algo_elem = try der.Element.parse(cert_bytes, pub_key_signature_algorithm.slice.start);
    const pub_key_algo: Parsed.PubKeyAlgo = switch (try parseAlgorithmCategory(cert_bytes, pub_key_algo_elem)) {
        inline else => |tag| @unionInit(Parsed.PubKeyAlgo, @tagName(tag), {}),
        .X9_62_id_ecPublicKey => pub_key_algo: {
            // RFC 5480 Section 2.1.1.1 Named Curve
            // ECParameters ::= CHOICE {
            //   namedCurve         OBJECT IDENTIFIER
            //   -- implicitCurve   NULL
            //   -- specifiedCurve  SpecifiedECDomain
            // }
            const params_elem = try der.Element.parse(cert_bytes, pub_key_algo_elem.slice.end);
            const named_curve = try parseNamedCurve(cert_bytes, params_elem);
            break :pub_key_algo .{ .X9_62_id_ecPublicKey = named_curve };
        },
    };
    const pub_key_elem = try der.Element.parse(cert_bytes, pub_key_signature_algorithm.slice.end);
    const pub_key = try parseBitString(cert, pub_key_elem);

    var common_name = der.Element.Slice.empty;
    var name_i = subject.slice.start;
    while (name_i < subject.slice.end) {
        const rdn = try der.Element.parse(cert_bytes, name_i);
        var rdn_i = rdn.slice.start;
        while (rdn_i < rdn.slice.end) {
            const atav = try der.Element.parse(cert_bytes, rdn_i);
            var atav_i = atav.slice.start;
            while (atav_i < atav.slice.end) {
                const ty_elem = try der.Element.parse(cert_bytes, atav_i);
                const val = try der.Element.parse(cert_bytes, ty_elem.slice.end);
                atav_i = val.slice.end;
                const ty = parseAttribute(cert_bytes, ty_elem) catch |err| switch (err) {
                    error.CertificateHasUnrecognizedObjectId => continue,
                    else => |e| return e,
                };
                switch (ty) {
                    .commonName => common_name = val.slice,
                    else => {},
                }
            }
            rdn_i = atav.slice.end;
        }
        name_i = rdn.slice.end;
    }

    const sig_algo = try der.Element.parse(cert_bytes, tbs_certificate.slice.end);
    const algo_elem = try der.Element.parse(cert_bytes, sig_algo.slice.start);
    const signature_algorithm = try parseAlgorithm(cert_bytes, algo_elem);
    const sig_elem = try der.Element.parse(cert_bytes, sig_algo.slice.end);
    const signature = try parseBitString(cert, sig_elem);

    // Extensions
    var subject_alt_name_slice = der.Element.Slice.empty;
    ext: {
        if (version == .v1)
            break :ext;

        if (pub_key_info.slice.end >= tbs_certificate.slice.end)
            break :ext;

        const outer_extensions = try der.Element.parse(cert_bytes, pub_key_info.slice.end);
        if (outer_extensions.identifier.tag != .bitstring)
            break :ext;

        const extensions = try der.Element.parse(cert_bytes, outer_extensions.slice.start);

        var ext_i = extensions.slice.start;
        while (ext_i < extensions.slice.end) {
            const extension = try der.Element.parse(cert_bytes, ext_i);
            ext_i = extension.slice.end;
            const oid_elem = try der.Element.parse(cert_bytes, extension.slice.start);
            const ext_id = parseExtensionId(cert_bytes, oid_elem) catch |err| switch (err) {
                error.CertificateHasUnrecognizedObjectId => continue,
                else => |e| return e,
            };
            const critical_elem = try der.Element.parse(cert_bytes, oid_elem.slice.end);
            const ext_bytes_elem = if (critical_elem.identifier.tag != .boolean)
                critical_elem
            else
                try der.Element.parse(cert_bytes, critical_elem.slice.end);
            switch (ext_id) {
                .subject_alt_name => subject_alt_name_slice = ext_bytes_elem.slice,
                else => continue,
            }
        }
    }

    return .{
        .certificate = cert,
        .common_name_slice = common_name,
        .issuer_slice = issuer.slice,
        .subject_slice = subject.slice,
        .signature_slice = signature,
        .signature_algorithm = signature_algorithm,
        .message_slice = .{ .start = certificate.slice.start, .end = tbs_certificate.slice.end },
        .pub_key_algo = pub_key_algo,
        .pub_key_slice = pub_key,
        .validity = .{
            .not_before = not_before_utc,
            .not_after = not_after_utc,
        },
        .subject_alt_name_slice = subject_alt_name_slice,
        .version = version,
    };
}

pub fn verify(subject: Certificate, issuer: Certificate, now_sec: i64) !void {
    const parsed_subject = try subject.parse();
    const parsed_issuer = try issuer.parse();
    return parsed_subject.verify(parsed_issuer, now_sec);
}

pub fn contents(cert: Certificate, elem: der.Element) []const u8 {
    return cert.buffer[elem.slice.start..elem.slice.end];
}

pub const ParseBitStringError = error{ CertificateFieldHasWrongDataType, CertificateHasInvalidBitString };

pub fn parseBitString(cert: Certificate, elem: der.Element) !der.Element.Slice {
    if (elem.identifier.tag != .bitstring) return error.CertificateFieldHasWrongDataType;
    if (cert.buffer[elem.slice.start] != 0) return error.CertificateHasInvalidBitString;
    return .{ .start = elem.slice.start + 1, .end = elem.slice.end };
}

pub const ParseTimeError = error{ CertificateTimeInvalid, CertificateFieldHasWrongDataType };

/// Returns number of seconds since epoch.
pub fn parseTime(cert: Certificate, elem: der.Element) ParseTimeError!u64 {
    const bytes = cert.contents(elem);
    switch (elem.identifier.tag) {
        .utc_time => {
            // Example: "YYMMDD000000Z"
            if (bytes.len != 13)
                return error.CertificateTimeInvalid;
            if (bytes[12] != 'Z')
                return error.CertificateTimeInvalid;

            return Date.toSeconds(.{
                .year = @as(u16, 2000) + try parseTimeDigits(bytes[0..2], 0, 99),
                .month = try parseTimeDigits(bytes[2..4], 1, 12),
                .day = try parseTimeDigits(bytes[4..6], 1, 31),
                .hour = try parseTimeDigits(bytes[6..8], 0, 23),
                .minute = try parseTimeDigits(bytes[8..10], 0, 59),
                .second = try parseTimeDigits(bytes[10..12], 0, 59),
            });
        },
        .generalized_time => {
            // Examples:
            // "19920521000000Z"
            // "19920622123421Z"
            // "19920722132100.3Z"
            if (bytes.len < 15)
                return error.CertificateTimeInvalid;
            return Date.toSeconds(.{
                .year = try parseYear4(bytes[0..4]),
                .month = try parseTimeDigits(bytes[4..6], 1, 12),
                .day = try parseTimeDigits(bytes[6..8], 1, 31),
                .hour = try parseTimeDigits(bytes[8..10], 0, 23),
                .minute = try parseTimeDigits(bytes[10..12], 0, 59),
                .second = try parseTimeDigits(bytes[12..14], 0, 59),
            });
        },
        else => return error.CertificateFieldHasWrongDataType,
    }
}

const Date = struct {
    /// example: 1999
    year: u16,
    /// range: 1 to 12
    month: u8,
    /// range: 1 to 31
    day: u8,
    /// range: 0 to 59
    hour: u8,
    /// range: 0 to 59
    minute: u8,
    /// range: 0 to 59
    second: u8,

    /// Convert to number of seconds since epoch.
    pub fn toSeconds(date: Date) u64 {
        var sec: u64 = 0;

        {
            var year: u16 = 1970;
            while (year < date.year) : (year += 1) {
                const days: u64 = std.time.epoch.getDaysInYear(year);
                sec += days * std.time.epoch.secs_per_day;
            }
        }

        {
            var month: u4 = 1;
            while (month < date.month) : (month += 1) {
                const days: u64 = std.time.epoch.getDaysInMonth(
                    date.year,
                    @as(std.time.epoch.Month, @enumFromInt(month)),
                );
                sec += days * std.time.epoch.secs_per_day;
            }
        }

        sec += (date.day - 1) * @as(u64, std.time.epoch.secs_per_day);
        sec += date.hour * @as(u64, 60 * 60);
        sec += date.minute * @as(u64, 60);
        sec += date.second;

        return sec;
    }
};

pub fn parseTimeDigits(text: *const [2]u8, min: u8, max: u8) !u8 {
    const result = if (use_vectors) result: {
        const nn: @Vector(2, u16) = .{ text[0], text[1] };
        const zero: @Vector(2, u16) = .{ '0', '0' };
        const mm: @Vector(2, u16) = .{ 10, 1 };
        break :result @reduce(.Add, (nn -% zero) *% mm);
    } else std.fmt.parseInt(u8, text, 10) catch return error.CertificateTimeInvalid;
    if (result < min) return error.CertificateTimeInvalid;
    if (result > max) return error.CertificateTimeInvalid;
    return @truncate(result);
}

test parseTimeDigits {
    const expectEqual = std.testing.expectEqual;
    try expectEqual(@as(u8, 0), try parseTimeDigits("00", 0, 99));
    try expectEqual(@as(u8, 99), try parseTimeDigits("99", 0, 99));
    try expectEqual(@as(u8, 42), try parseTimeDigits("42", 0, 99));

    const expectError = std.testing.expectError;
    try expectError(error.CertificateTimeInvalid, parseTimeDigits("13", 1, 12));
    try expectError(error.CertificateTimeInvalid, parseTimeDigits("00", 1, 12));
    try expectError(error.CertificateTimeInvalid, parseTimeDigits("Di", 0, 99));
}

pub fn parseYear4(text: *const [4]u8) !u16 {
    const result = if (use_vectors) result: {
        const nnnn: @Vector(4, u32) = .{ text[0], text[1], text[2], text[3] };
        const zero: @Vector(4, u32) = .{ '0', '0', '0', '0' };
        const mmmm: @Vector(4, u32) = .{ 1000, 100, 10, 1 };
        break :result @reduce(.Add, (nnnn -% zero) *% mmmm);
    } else std.fmt.parseInt(u16, text, 10) catch return error.CertificateTimeInvalid;
    if (result > 9999) return error.CertificateTimeInvalid;
    return @truncate(result);
}

test parseYear4 {
    const expectEqual = std.testing.expectEqual;
    try expectEqual(@as(u16, 0), try parseYear4("0000"));
    try expectEqual(@as(u16, 9999), try parseYear4("9999"));
    try expectEqual(@as(u16, 1988), try parseYear4("1988"));

    const expectError = std.testing.expectError;
    try expectError(error.CertificateTimeInvalid, parseYear4("999b"));
    try expectError(error.CertificateTimeInvalid, parseYear4("crap"));
    try expectError(error.CertificateTimeInvalid, parseYear4("r:bQ"));
}

pub fn parseAlgorithm(bytes: []const u8, element: der.Element) ParseEnumError!Algorithm {
    return parseEnum(Algorithm, bytes, element);
}

pub fn parseAlgorithmCategory(bytes: []const u8, element: der.Element) ParseEnumError!AlgorithmCategory {
    return parseEnum(AlgorithmCategory, bytes, element);
}

pub fn parseAttribute(bytes: []const u8, element: der.Element) ParseEnumError!Attribute {
    return parseEnum(Attribute, bytes, element);
}

pub fn parseNamedCurve(bytes: []const u8, element: der.Element) ParseEnumError!NamedCurve {
    return parseEnum(NamedCurve, bytes, element);
}

pub fn parseExtensionId(bytes: []const u8, element: der.Element) ParseEnumError!ExtensionId {
    return parseEnum(ExtensionId, bytes, element);
}

pub const ParseEnumError = error{ CertificateFieldHasWrongDataType, CertificateHasUnrecognizedObjectId };

fn parseEnum(comptime E: type, bytes: []const u8, element: der.Element) ParseEnumError!E {
    if (element.identifier.tag != .object_identifier)
        return error.CertificateFieldHasWrongDataType;
    const oid_bytes = bytes[element.slice.start..element.slice.end];
    return E.map.get(oid_bytes) orelse return error.CertificateHasUnrecognizedObjectId;
}

pub const ParseVersionError = error{ UnsupportedCertificateVersion, CertificateFieldHasInvalidLength };

pub fn parseVersion(bytes: []const u8, version_elem: der.Element) ParseVersionError!Version {
    if (@as(u8, @bitCast(version_elem.identifier)) != 0xa0)
        return .v1;

    if (version_elem.slice.end - version_elem.slice.start != 3)
        return error.CertificateFieldHasInvalidLength;

    const encoded_version = bytes[version_elem.slice.start..version_elem.slice.end];

    if (mem.eql(u8, encoded_version, "\x02\x01\x02")) {
        return .v3;
    } else if (mem.eql(u8, encoded_version, "\x02\x01\x01")) {
        return .v2;
    } else if (mem.eql(u8, encoded_version, "\x02\x01\x00")) {
        return .v1;
    }

    return error.UnsupportedCertificateVersion;
}

fn verifyRsa(
    comptime Hash: type,
    msg: []const u8,
    sig: []const u8,
    pub_key_algo: Parsed.PubKeyAlgo,
    pub_key: []const u8,
) !void {
    if (pub_key_algo != .rsaEncryption) return error.CertificateSignatureAlgorithmMismatch;
    const pk_components = try rsa.PublicKey.parseDer(pub_key);
    const exponent = pk_components.exponent;
    const modulus = pk_components.modulus;
    if (exponent.len > modulus.len) return error.CertificatePublicKeyInvalid;
    if (sig.len != modulus.len) return error.CertificateSignatureInvalidLength;

    switch (modulus.len) {
        inline 128, 256, 384, 512 => |modulus_len| {
            const public_key = rsa.PublicKey.fromBytes(exponent, modulus) catch
                return error.CertificateSignatureInvalid;
            rsa.PKCS1v1_5Signature.verify(modulus_len, sig[0..modulus_len].*, msg, public_key, Hash) catch
                return error.CertificateSignatureInvalid;
        },
        else => return error.CertificateSignatureUnsupportedBitCount,
    }
}

fn verify_ecdsa(
    comptime Hash: type,
    message: []const u8,
    encoded_sig: []const u8,
    pub_key_algo: Parsed.PubKeyAlgo,
    sec1_pub_key: []const u8,
) !void {
    const sig_named_curve = switch (pub_key_algo) {
        .X9_62_id_ecPublicKey => |named_curve| named_curve,
        else => return error.CertificateSignatureAlgorithmMismatch,
    };

    switch (sig_named_curve) {
        .secp521r1 => {
            return error.CertificateSignatureNamedCurveUnsupported;
        },
        inline .X9_62_prime256v1,
        .secp384r1,
        => |curve| {
            const Ecdsa = crypto.sign.ecdsa.Ecdsa(curve.Curve(), Hash);
            const sig = Ecdsa.Signature.fromDer(encoded_sig) catch |err| switch (err) {
                error.InvalidEncoding => return error.CertificateSignatureInvalid,
            };
            const pub_key = Ecdsa.PublicKey.fromSec1(sec1_pub_key) catch |err| switch (err) {
                error.InvalidEncoding => return error.CertificateSignatureInvalid,
                error.NonCanonical => return error.CertificateSignatureInvalid,
                error.NotSquare => return error.CertificateSignatureInvalid,
            };
            sig.verify(message, pub_key) catch |err| switch (err) {
                error.IdentityElement => return error.CertificateSignatureInvalid,
                error.NonCanonical => return error.CertificateSignatureInvalid,
                error.SignatureVerificationFailed => return error.CertificateSignatureInvalid,
            };
        },
    }
}

fn verifyEd25519(
    message: []const u8,
    encoded_sig: []const u8,
    pub_key_algo: Parsed.PubKeyAlgo,
    encoded_pub_key: []const u8,
) !void {
    if (pub_key_algo != .curveEd25519) return error.CertificateSignatureAlgorithmMismatch;
    const Ed25519 = crypto.sign.Ed25519;
    if (encoded_sig.len != Ed25519.Signature.encoded_length) return error.CertificateSignatureInvalid;
    const sig = Ed25519.Signature.fromBytes(encoded_sig[0..Ed25519.Signature.encoded_length].*);
    if (encoded_pub_key.len != Ed25519.PublicKey.encoded_length) return error.CertificateSignatureInvalid;
    const pub_key = Ed25519.PublicKey.fromBytes(encoded_pub_key[0..Ed25519.PublicKey.encoded_length].*) catch |err| switch (err) {
        error.NonCanonical => return error.CertificateSignatureInvalid,
    };
    sig.verify(message, pub_key) catch |err| switch (err) {
        error.IdentityElement => return error.CertificateSignatureInvalid,
        error.NonCanonical => return error.CertificateSignatureInvalid,
        error.SignatureVerificationFailed => return error.CertificateSignatureInvalid,
        error.InvalidEncoding => return error.CertificateSignatureInvalid,
        error.WeakPublicKey => return error.CertificateSignatureInvalid,
    };
}

const std = @import("../std.zig");
const crypto = std.crypto;
const mem = std.mem;
const Certificate = @This();

pub const der = struct {
    pub const Class = enum(u2) {
        universal,
        application,
        context_specific,
        private,
    };

    pub const PC = enum(u1) {
        primitive,
        constructed,
    };

    pub const Identifier = packed struct(u8) {
        tag: Tag,
        pc: PC,
        class: Class,
    };

    pub const Tag = enum(u5) {
        boolean = 1,
        integer = 2,
        bitstring = 3,
        octetstring = 4,
        null = 5,
        object_identifier = 6,
        sequence = 16,
        sequence_of = 17,
        utc_time = 23,
        generalized_time = 24,
        _,
    };

    pub const Element = struct {
        identifier: Identifier,
        slice: Slice,

        pub const Slice = struct {
            start: u32,
            end: u32,

            pub const empty: Slice = .{ .start = 0, .end = 0 };
        };

        pub const ParseError = error{CertificateFieldHasInvalidLength};

        pub fn parse(bytes: []const u8, index: u32) Element.ParseError!Element {
            var i = index;
            const identifier = @as(Identifier, @bitCast(bytes[i]));
            i += 1;
            const size_byte = bytes[i];
            i += 1;
            if ((size_byte >> 7) == 0) {
                return .{
                    .identifier = identifier,
                    .slice = .{
                        .start = i,
                        .end = i + size_byte,
                    },
                };
            }

            const len_size = @as(u7, @truncate(size_byte));
            if (len_size > @sizeOf(u32)) {
                return error.CertificateFieldHasInvalidLength;
            }

            const end_i = i + len_size;
            var long_form_size: u32 = 0;
            while (i < end_i) : (i += 1) {
                long_form_size = (long_form_size << 8) | bytes[i];
            }

            return .{
                .identifier = identifier,
                .slice = .{
                    .start = i,
                    .end = i + long_form_size,
                },
            };
        }
    };
};

test {
    _ = Bundle;
}

pub const rsa = struct {
    const max_modulus_bits = 4096;
    const Uint = std.crypto.ff.Uint(max_modulus_bits);
    const Modulus = std.crypto.ff.Modulus(max_modulus_bits);
    const Fe = Modulus.Fe;

    /// RFC 3447 8.1 RSASSA-PSS
    pub const PSSSignature = struct {
        pub fn fromBytes(comptime modulus_len: usize, msg: []const u8) [modulus_len]u8 {
            var result: [modulus_len]u8 = undefined;
            @memcpy(result[0..msg.len], msg);
            @memset(result[msg.len..], 0);
            return result;
        }

        pub const VerifyError = EncryptError || error{InvalidSignature};

        pub fn verify(
            comptime modulus_len: usize,
            sig: [modulus_len]u8,
            msg: []const u8,
            public_key: PublicKey,
            comptime Hash: type,
        ) VerifyError!void {
            try concatVerify(modulus_len, sig, &.{msg}, public_key, Hash);
        }

        pub fn concatVerify(
            comptime modulus_len: usize,
            sig: [modulus_len]u8,
            msg: []const []const u8,
            public_key: PublicKey,
            comptime Hash: type,
        ) VerifyError!void {
            const mod_bits = public_key.n.bits();
            const em_dec = try encrypt(modulus_len, sig, public_key);

            try EMSA_PSS_VERIFY(msg, &em_dec, mod_bits - 1, Hash.digest_length, Hash);
        }

        fn EMSA_PSS_VERIFY(msg: []const []const u8, em: []const u8, emBit: usize, sLen: usize, comptime Hash: type) VerifyError!void {
            // 1.   If the length of M is greater than the input limitation for
            //      the hash function (2^61 - 1 octets for SHA-1), output
            //      "inconsistent" and stop.
            // All the cryptographic hash functions in the standard library have a limit of >= 2^61 - 1.
            // Even then, this check is only there for paranoia. In the context of TLS certificates, emBit cannot exceed 4096.
            if (emBit >= 1 << 61) return error.InvalidSignature;

            // emLen = \ceil(emBits/8)
            const emLen = ((emBit - 1) / 8) + 1;
            std.debug.assert(emLen == em.len);

            // 2.   Let mHash = Hash(M), an octet string of length hLen.
            var mHash: [Hash.digest_length]u8 = undefined;
            {
                var hasher: Hash = .init(.{});
                for (msg) |part| hasher.update(part);
                hasher.final(&mHash);
            }

            // 3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
            if (emLen < Hash.digest_length + sLen + 2) {
                return error.InvalidSignature;
            }

            // 4.   If the rightmost octet of EM does not have hexadecimal value
            //      0xbc, output "inconsistent" and stop.
            if (em[em.len - 1] != 0xbc) {
                return error.InvalidSignature;
            }

            // 5.   Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
            //      and let H be the next hLen octets.
            const maskedDB = em[0..(emLen - Hash.digest_length - 1)];
            const h = em[(emLen - Hash.digest_length - 1)..(emLen - 1)][0..Hash.digest_length];

            // 6.   If the leftmost 8emLen - emBits bits of the leftmost octet in
            //      maskedDB are not all equal to zero, output "inconsistent" and
            //      stop.
            const zero_bits = emLen * 8 - emBit;
            var mask: u8 = maskedDB[0];
            var i: usize = 0;
            while (i < 8 - zero_bits) : (i += 1) {
                mask = mask >> 1;
            }
            if (mask != 0) {
                return error.InvalidSignature;
            }

            // 7.   Let dbMask = MGF(H, emLen - hLen - 1).
            const mgf_len = emLen - Hash.digest_length - 1;
            var mgf_out_buf: [512]u8 = undefined;
            if (mgf_len > mgf_out_buf.len) { // Modulus > 4096 bits
                return error.InvalidSignature;
            }
            const mgf_out = mgf_out_buf[0 .. ((mgf_len - 1) / Hash.digest_length + 1) * Hash.digest_length];
            var dbMask = try MGF1(Hash, mgf_out, h, mgf_len);

            // 8.   Let DB = maskedDB \xor dbMask.
            i = 0;
            while (i < dbMask.len) : (i += 1) {
                dbMask[i] = maskedDB[i] ^ dbMask[i];
            }

            // 9.   Set the leftmost 8emLen - emBits bits of the leftmost octet
            //      in DB to zero.
            i = 0;
            mask = 0;
            while (i < 8 - zero_bits) : (i += 1) {
                mask = mask << 1;
                mask += 1;
            }
            dbMask[0] = dbMask[0] & mask;

            // 10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not
            //      zero or if the octet at position emLen - hLen - sLen - 1 (the
            //      leftmost position is "position 1") does not have hexadecimal
            //      value 0x01, output "inconsistent" and stop.
            if (dbMask[mgf_len - sLen - 2] != 0x00) {
                return error.InvalidSignature;
            }

            if (dbMask[mgf_len - sLen - 1] != 0x01) {
                return error.InvalidSignature;
            }

            // 11.  Let salt be the last sLen octets of DB.
            const salt = dbMask[(mgf_len - sLen)..];

            // 12.  Let
            //         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
            //      M' is an octet string of length 8 + hLen + sLen with eight
            //      initial zero octets.
            if (sLen > Hash.digest_length) { // A seed larger than the hash length would be useless
                return error.InvalidSignature;
            }
            var m_p_buf: [8 + Hash.digest_length + Hash.digest_length]u8 = undefined;
            var m_p = m_p_buf[0 .. 8 + Hash.digest_length + sLen];
            std.mem.copyForwards(u8, m_p, &([_]u8{0} ** 8));
            std.mem.copyForwards(u8, m_p[8..], &mHash);
            std.mem.copyForwards(u8, m_p[(8 + Hash.digest_length)..], salt);

            // 13.  Let H' = Hash(M'), an octet string of length hLen.
            var h_p: [Hash.digest_length]u8 = undefined;
            Hash.hash(m_p, &h_p, .{});

            // 14.  If H = H', output "consistent".  Otherwise, output
            //      "inconsistent".
            if (!std.mem.eql(u8, h, &h_p)) {
                return error.InvalidSignature;
            }
        }

        fn MGF1(comptime Hash: type, out: []u8, seed: *const [Hash.digest_length]u8, len: usize) ![]u8 {
            var counter: u32 = 0;
            var idx: usize = 0;
            var hash = seed.* ++ @as([4]u8, undefined);

            while (idx < len) {
                std.mem.writeInt(u32, hash[seed.len..][0..4], counter, .big);
                Hash.hash(&hash, out[idx..][0..Hash.digest_length], .{});
                idx += Hash.digest_length;
                counter += 1;
            }

            return out[0..len];
        }
    };

    /// RFC 3447 8.2 RSASSA-PKCS1-v1_5
    pub const PKCS1v1_5Signature = struct {
        pub fn fromBytes(comptime modulus_len: usize, msg: []const u8) [modulus_len]u8 {
            var result: [modulus_len]u8 = undefined;
            @memcpy(result[0..msg.len], msg);
            @memset(result[msg.len..], 0);
            return result;
        }

        pub const VerifyError = EncryptError || error{InvalidSignature};

        pub fn verify(
            comptime modulus_len: usize,
            sig: [modulus_len]u8,
            msg: []const u8,
            public_key: PublicKey,
            comptime Hash: type,
        ) VerifyError!void {
            try concatVerify(modulus_len, sig, &.{msg}, public_key, Hash);
        }

        pub fn concatVerify(
            comptime modulus_len: usize,
            sig: [modulus_len]u8,
            msg: []const []const u8,
            public_key: PublicKey,
            comptime Hash: type,
        ) VerifyError!void {
            const em_dec = try encrypt(modulus_len, sig, public_key);
            const em = try EMSA_PKCS1_V1_5_ENCODE(msg, modulus_len, Hash);
            if (!std.mem.eql(u8, &em_dec, &em)) return error.InvalidSignature;
        }

        fn EMSA_PKCS1_V1_5_ENCODE(msg: []const []const u8, comptime emLen: usize, comptime Hash: type) VerifyError![emLen]u8 {
            comptime var em_index = emLen;
            var em: [emLen]u8 = undefined;

            // 1. Apply the hash function to the message M to produce a hash value
            //    H:
            //
            //       H = Hash(M).
            //
            //    If the hash function outputs "message too long," output "message
            //    too long" and stop.
            var hasher: Hash = .init(.{});
            for (msg) |part| hasher.update(part);
            em_index -= Hash.digest_length;
            hasher.final(em[em_index..]);

            // 2. Encode the algorithm ID for the hash function and the hash value
            //    into an ASN.1 value of type DigestInfo (see Appendix A.2.4) with
            //    the Distinguished Encoding Rules (DER), where the type DigestInfo
            //    has the syntax
            //
            //    DigestInfo ::= SEQUENCE {
            //        digestAlgorithm AlgorithmIdentifier,
            //        digest OCTET STRING
            //    }
            //
            //    The first field identifies the hash function and the second
            //    contains the hash value.  Let T be the DER encoding of the
            //    DigestInfo value (see the notes below) and let tLen be the length
            //    in octets of T.
            const hash_der: []const u8 = &switch (Hash) {
                crypto.hash.Sha1 => .{
                    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
                    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
                },
                crypto.hash.sha2.Sha224 => .{
                    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
                    0x00, 0x04, 0x1c,
                },
                crypto.hash.sha2.Sha256 => .{
                    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                    0x00, 0x04, 0x20,
                },
                crypto.hash.sha2.Sha384 => .{
                    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
                    0x00, 0x04, 0x30,
                },
                crypto.hash.sha2.Sha512 => .{
                    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                    0x00, 0x04, 0x40,
                },
                else => @compileError("unreachable"),
            };
            em_index -= hash_der.len;
            @memcpy(em[em_index..][0..hash_der.len], hash_der);

            // 3. If emLen < tLen + 11, output "intended encoded message length too
            //    short" and stop.

            // 4. Generate an octet string PS consisting of emLen - tLen - 3 octets
            //    with hexadecimal value 0xff.  The length of PS will be at least 8
            //    octets.
            em_index -= 1;
            @memset(em[2..em_index], 0xff);

            // 5. Concatenate PS, the DER encoding T, and other padding to form the
            //    encoded message EM as
            //
            //       EM = 0x00 || 0x01 || PS || 0x00 || T.
            em[em_index] = 0x00;
            em[1] = 0x01;
            em[0] = 0x00;

            // 6. Output EM.
            return em;
        }
    };

    pub const PublicKey = struct {
        n: Modulus,
        e: Fe,

        pub const FromBytesError = error{CertificatePublicKeyInvalid};

        pub fn fromBytes(pub_bytes: []const u8, modulus_bytes: []const u8) FromBytesError!PublicKey {
            // Reject modulus below 512 bits.
            // 512-bit RSA was factored in 1999, so this limit barely means anything,
            // but establish some limit now to ratchet in what we can.
            const _n = Modulus.fromBytes(modulus_bytes, .big) catch return error.CertificatePublicKeyInvalid;
            if (_n.bits() < 512) return error.CertificatePublicKeyInvalid;

            // Exponent must be odd and greater than 2.
            // Also, it must be less than 2^32 to mitigate DoS attacks.
            // Windows CryptoAPI doesn't support values larger than 32 bits [1], so it is
            // unlikely that exponents larger than 32 bits are being used for anything
            // Windows commonly does.
            // [1] https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey
            if (pub_bytes.len > 4) return error.CertificatePublicKeyInvalid;
            const _e = Fe.fromBytes(_n, pub_bytes, .big) catch return error.CertificatePublicKeyInvalid;
            if (!_e.isOdd()) return error.CertificatePublicKeyInvalid;
            const e_v = _e.toPrimitive(u32) catch return error.CertificatePublicKeyInvalid;
            if (e_v < 2) return error.CertificatePublicKeyInvalid;

            return .{
                .n = _n,
                .e = _e,
            };
        }

        pub const ParseDerError = der.Element.ParseError || error{CertificateFieldHasWrongDataType};

        pub fn parseDer(pub_key: []const u8) ParseDerError!struct { modulus: []const u8, exponent: []const u8 } {
            const pub_key_seq = try der.Element.parse(pub_key, 0);
            if (pub_key_seq.identifier.tag != .sequence) return error.CertificateFieldHasWrongDataType;
            const modulus_elem = try der.Element.parse(pub_key, pub_key_seq.slice.start);
            if (modulus_elem.identifier.tag != .integer) return error.CertificateFieldHasWrongDataType;
            const exponent_elem = try der.Element.parse(pub_key, modulus_elem.slice.end);
            if (exponent_elem.identifier.tag != .integer) return error.CertificateFieldHasWrongDataType;
            // Skip over meaningless zeroes in the modulus.
            const modulus_raw = pub_key[modulus_elem.slice.start..modulus_elem.slice.end];
            const modulus_offset = for (modulus_raw, 0..) |byte, i| {
                if (byte != 0) break i;
            } else modulus_raw.len;
            return .{
                .modulus = modulus_raw[modulus_offset..],
                .exponent = pub_key[exponent_elem.slice.start..exponent_elem.slice.end],
            };
        }
    };

    const EncryptError = error{MessageTooLong};

    fn encrypt(comptime modulus_len: usize, msg: [modulus_len]u8, public_key: PublicKey) EncryptError![modulus_len]u8 {
        const m = Fe.fromBytes(public_key.n, &msg, .big) catch return error.MessageTooLong;
        const e = public_key.n.powPublic(m, public_key.e) catch unreachable;
        var res: [modulus_len]u8 = undefined;
        e.toBytes(&res, .big) catch unreachable;
        return res;
    }
};

const use_vectors = @import("builtin").zig_backend != .stage2_x86_64;
//! A set of certificates. Typically pre-installed on every operating system,
//! these are "Certificate Authorities" used to validate SSL certificates.
//! This data structure stores certificates in DER-encoded form, all of them
//! concatenated together in the `bytes` array. The `map` field contains an
//! index from the DER-encoded subject name to the index of the containing
//! certificate within `bytes`.

/// The key is the contents slice of the subject.
map: std.HashMapUnmanaged(der.Element.Slice, u32, MapContext, std.hash_map.default_max_load_percentage) = .empty,
bytes: std.ArrayListUnmanaged(u8) = .empty,

pub const VerifyError = Certificate.Parsed.VerifyError || error{
    CertificateIssuerNotFound,
};

pub fn verify(cb: Bundle, subject: Certificate.Parsed, now_sec: i64) VerifyError!void {
    const bytes_index = cb.find(subject.issuer()) orelse return error.CertificateIssuerNotFound;
    const issuer_cert: Certificate = .{
        .buffer = cb.bytes.items,
        .index = bytes_index,
    };
    // Every certificate in the bundle is pre-parsed before adding it, ensuring
    // that parsing will succeed here.
    const issuer = issuer_cert.parse() catch unreachable;
    try subject.verify(issuer, now_sec);
}

/// The returned bytes become invalid after calling any of the rescan functions
/// or add functions.
pub fn find(cb: Bundle, subject_name: []const u8) ?u32 {
    const Adapter = struct {
        cb: Bundle,

        pub fn hash(ctx: @This(), k: []const u8) u64 {
            _ = ctx;
            return std.hash_map.hashString(k);
        }

        pub fn eql(ctx: @This(), a: []const u8, b_key: der.Element.Slice) bool {
            const b = ctx.cb.bytes.items[b_key.start..b_key.end];
            return mem.eql(u8, a, b);
        }
    };
    return cb.map.getAdapted(subject_name, Adapter{ .cb = cb });
}

pub fn deinit(cb: *Bundle, gpa: Allocator) void {
    cb.map.deinit(gpa);
    cb.bytes.deinit(gpa);
    cb.* = undefined;
}

pub const RescanError = RescanLinuxError || RescanMacError || RescanWithPathError || RescanWindowsError;

/// Clears the set of certificates and then scans the host operating system
/// file system standard locations for certificates.
/// For operating systems that do not have standard CA installations to be
/// found, this function clears the set of certificates.
pub fn rescan(cb: *Bundle, gpa: Allocator) RescanError!void {
    switch (builtin.os.tag) {
        .linux => return rescanLinux(cb, gpa),
        .macos => return rescanMac(cb, gpa),
        .freebsd, .openbsd => return rescanWithPath(cb, gpa, "/etc/ssl/cert.pem"),
        .netbsd => return rescanWithPath(cb, gpa, "/etc/openssl/certs/ca-certificates.crt"),
        .dragonfly => return rescanWithPath(cb, gpa, "/usr/local/etc/ssl/cert.pem"),
        .solaris, .illumos => return rescanWithPath(cb, gpa, "/etc/ssl/cacert.pem"),
        // https://github.com/SerenityOS/serenity/blob/222acc9d389bc6b490d4c39539761b043a4bfcb0/Ports/ca-certificates/package.sh#L19
        .serenity => return rescanWithPath(cb, gpa, "/etc/ssl/certs/ca-certificates.crt"),
        .windows => return rescanWindows(cb, gpa),
        else => {},
    }
}

const rescanMac = @import("Bundle/macos.zig").rescanMac;
const RescanMacError = @import("Bundle/macos.zig").RescanMacError;

const RescanLinuxError = AddCertsFromFilePathError || AddCertsFromDirPathError;

fn rescanLinux(cb: *Bundle, gpa: Allocator) RescanLinuxError!void {
    // Possible certificate files; stop after finding one.
    const cert_file_paths = [_][]const u8{
        "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo etc.
        "/etc/pki/tls/certs/ca-bundle.crt", // Fedora/RHEL 6
        "/etc/ssl/ca-bundle.pem", // OpenSUSE
        "/etc/pki/tls/cacert.pem", // OpenELEC
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
        "/etc/ssl/cert.pem", // Alpine Linux
    };

    // Possible directories with certificate files; all will be read.
    const cert_dir_paths = [_][]const u8{
        "/etc/ssl/certs", // SLES10/SLES11
        "/etc/pki/tls/certs", // Fedora/RHEL
        "/system/etc/security/cacerts", // Android
    };

    cb.bytes.clearRetainingCapacity();
    cb.map.clearRetainingCapacity();

    scan: {
        for (cert_file_paths) |cert_file_path| {
            if (addCertsFromFilePathAbsolute(cb, gpa, cert_file_path)) |_| {
                break :scan;
            } else |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            }
        }

        for (cert_dir_paths) |cert_dir_path| {
            addCertsFromDirPathAbsolute(cb, gpa, cert_dir_path) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            };
        }
    }

    cb.bytes.shrinkAndFree(gpa, cb.bytes.items.len);
}

const RescanWithPathError = AddCertsFromFilePathError;

fn rescanWithPath(cb: *Bundle, gpa: Allocator, cert_file_path: []const u8) RescanWithPathError!void {
    cb.bytes.clearRetainingCapacity();
    cb.map.clearRetainingCapacity();
    try addCertsFromFilePathAbsolute(cb, gpa, cert_file_path);
    cb.bytes.shrinkAndFree(gpa, cb.bytes.items.len);
}

const RescanWindowsError = Allocator.Error || ParseCertError || std.posix.UnexpectedError || error{FileNotFound};

fn rescanWindows(cb: *Bundle, gpa: Allocator) RescanWindowsError!void {
    cb.bytes.clearRetainingCapacity();
    cb.map.clearRetainingCapacity();

    const w = std.os.windows;
    const GetLastError = w.GetLastError;
    const root = [4:0]u16{ 'R', 'O', 'O', 'T' };
    const store = w.crypt32.CertOpenSystemStoreW(null, &root) orelse switch (GetLastError()) {
        .FILE_NOT_FOUND => return error.FileNotFound,
        else => |err| return w.unexpectedError(err),
    };
    defer _ = w.crypt32.CertCloseStore(store, 0);

    const now_sec = std.time.timestamp();

    var ctx = w.crypt32.CertEnumCertificatesInStore(store, null);
    while (ctx) |context| : (ctx = w.crypt32.CertEnumCertificatesInStore(store, ctx)) {
        const decoded_start = @as(u32, @intCast(cb.bytes.items.len));
        const encoded_cert = context.pbCertEncoded[0..context.cbCertEncoded];
        try cb.bytes.appendSlice(gpa, encoded_cert);
        try cb.parseCert(gpa, decoded_start, now_sec);
    }
    cb.bytes.shrinkAndFree(gpa, cb.bytes.items.len);
}

pub const AddCertsFromDirPathError = fs.File.OpenError || AddCertsFromDirError;

pub fn addCertsFromDirPath(
    cb: *Bundle,
    gpa: Allocator,
    dir: fs.Dir,
    sub_dir_path: []const u8,
) AddCertsFromDirPathError!void {
    var iterable_dir = try dir.openDir(sub_dir_path, .{ .iterate = true });
    defer iterable_dir.close();
    return addCertsFromDir(cb, gpa, iterable_dir);
}

pub fn addCertsFromDirPathAbsolute(
    cb: *Bundle,
    gpa: Allocator,
    abs_dir_path: []const u8,
) AddCertsFromDirPathError!void {
    assert(fs.path.isAbsolute(abs_dir_path));
    var iterable_dir = try fs.openDirAbsolute(abs_dir_path, .{ .iterate = true });
    defer iterable_dir.close();
    return addCertsFromDir(cb, gpa, iterable_dir);
}

pub const AddCertsFromDirError = AddCertsFromFilePathError;

pub fn addCertsFromDir(cb: *Bundle, gpa: Allocator, iterable_dir: fs.Dir) AddCertsFromDirError!void {
    var it = iterable_dir.iterate();
    while (try it.next()) |entry| {
        switch (entry.kind) {
            .file, .sym_link => {},
            else => continue,
        }

        try addCertsFromFilePath(cb, gpa, iterable_dir, entry.name);
    }
}

pub const AddCertsFromFilePathError = fs.File.OpenError || AddCertsFromFileError;

pub fn addCertsFromFilePathAbsolute(
    cb: *Bundle,
    gpa: Allocator,
    abs_file_path: []const u8,
) AddCertsFromFilePathError!void {
    assert(fs.path.isAbsolute(abs_file_path));
    var file = try fs.openFileAbsolute(abs_file_path, .{});
    defer file.close();
    return addCertsFromFile(cb, gpa, file);
}

pub fn addCertsFromFilePath(
    cb: *Bundle,
    gpa: Allocator,
    dir: fs.Dir,
    sub_file_path: []const u8,
) AddCertsFromFilePathError!void {
    var file = try dir.openFile(sub_file_path, .{});
    defer file.close();
    return addCertsFromFile(cb, gpa, file);
}

pub const AddCertsFromFileError = Allocator.Error ||
    fs.File.GetSeekPosError ||
    fs.File.ReadError ||
    ParseCertError ||
    std.base64.Error ||
    error{ CertificateAuthorityBundleTooBig, MissingEndCertificateMarker };

pub fn addCertsFromFile(cb: *Bundle, gpa: Allocator, file: fs.File) AddCertsFromFileError!void {
    const size = try file.getEndPos();

    // We borrow `bytes` as a temporary buffer for the base64-encoded data.
    // This is possible by computing the decoded length and reserving the space
    // for the decoded bytes first.
    const decoded_size_upper_bound = size / 4 * 3;
    const needed_capacity = std.math.cast(u32, decoded_size_upper_bound + size) orelse
        return error.CertificateAuthorityBundleTooBig;
    try cb.bytes.ensureUnusedCapacity(gpa, needed_capacity);
    const end_reserved: u32 = @intCast(cb.bytes.items.len + decoded_size_upper_bound);
    const buffer = cb.bytes.allocatedSlice()[end_reserved..];
    const end_index = try file.readAll(buffer);
    const encoded_bytes = buffer[0..end_index];

    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    const now_sec = std.time.timestamp();

    var start_index: usize = 0;
    while (mem.indexOfPos(u8, encoded_bytes, start_index, begin_marker)) |begin_marker_start| {
        const cert_start = begin_marker_start + begin_marker.len;
        const cert_end = mem.indexOfPos(u8, encoded_bytes, cert_start, end_marker) orelse
            return error.MissingEndCertificateMarker;
        start_index = cert_end + end_marker.len;
        const encoded_cert = mem.trim(u8, encoded_bytes[cert_start..cert_end], " \t\r\n");
        const decoded_start: u32 = @intCast(cb.bytes.items.len);
        const dest_buf = cb.bytes.allocatedSlice()[decoded_start..];
        cb.bytes.items.len += try base64.decode(dest_buf, encoded_cert);
        try cb.parseCert(gpa, decoded_start, now_sec);
    }
}

pub const ParseCertError = Allocator.Error || Certificate.ParseError;

pub fn parseCert(cb: *Bundle, gpa: Allocator, decoded_start: u32, now_sec: i64) ParseCertError!void {
    // Even though we could only partially parse the certificate to find
    // the subject name, we pre-parse all of them to make sure and only
    // include in the bundle ones that we know will parse. This way we can
    // use `catch unreachable` later.
    const parsed_cert = Certificate.parse(.{
        .buffer = cb.bytes.items,
        .index = decoded_start,
    }) catch |err| switch (err) {
        error.CertificateHasUnrecognizedObjectId => {
            cb.bytes.items.len = decoded_start;
            return;
        },
        else => |e| return e,
    };
    if (now_sec > parsed_cert.validity.not_after) {
        // Ignore expired cert.
        cb.bytes.items.len = decoded_start;
        return;
    }
    const gop = try cb.map.getOrPutContext(gpa, parsed_cert.subject_slice, .{ .cb = cb });
    if (gop.found_existing) {
        cb.bytes.items.len = decoded_start;
    } else {
        gop.value_ptr.* = decoded_start;
    }
}

const builtin = @import("builtin");
const std = @import("../../std.zig");
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const Certificate = std.crypto.Certificate;
const der = Certificate.der;
const Bundle = @This();

const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");

const MapContext = struct {
    cb: *const Bundle,

    pub fn hash(ctx: MapContext, k: der.Element.Slice) u64 {
        return std.hash_map.hashString(ctx.cb.bytes.items[k.start..k.end]);
    }

    pub fn eql(ctx: MapContext, a: der.Element.Slice, b: der.Element.Slice) bool {
        const bytes = ctx.cb.bytes.items;
        return mem.eql(
            u8,
            bytes[a.start..a.end],
            bytes[b.start..b.end],
        );
    }
};

test "scan for OS-provided certificates" {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    var bundle: Bundle = .{};
    defer bundle.deinit(std.testing.allocator);

    try bundle.rescan(std.testing.allocator);
}
const std = @import("std");
const assert = std.debug.assert;
const fs = std.fs;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const Bundle = @import("../Bundle.zig");

pub const RescanMacError = Allocator.Error || fs.File.OpenError || fs.File.ReadError || fs.File.SeekError || Bundle.ParseCertError || error{EndOfStream};

pub fn rescanMac(cb: *Bundle, gpa: Allocator) RescanMacError!void {
    cb.bytes.clearRetainingCapacity();
    cb.map.clearRetainingCapacity();

    const keychainPaths = [2][]const u8{
        "/System/Library/Keychains/SystemRootCertificates.keychain",
        "/Library/Keychains/System.keychain",
    };

    for (keychainPaths) |keychainPath| {
        const file = try fs.openFileAbsolute(keychainPath, .{});
        defer file.close();

        const bytes = try file.readToEndAlloc(gpa, std.math.maxInt(u32));
        defer gpa.free(bytes);

        var stream = std.io.fixedBufferStream(bytes);
        const reader = stream.reader();

        const db_header = try reader.readStructEndian(ApplDbHeader, .big);
        assert(mem.eql(u8, &db_header.signature, "kych"));

        try stream.seekTo(db_header.schema_offset);

        const db_schema = try reader.readStructEndian(ApplDbSchema, .big);

        var table_list = try gpa.alloc(u32, db_schema.table_count);
        defer gpa.free(table_list);

        var table_idx: u32 = 0;
        while (table_idx < table_list.len) : (table_idx += 1) {
            table_list[table_idx] = try reader.readInt(u32, .big);
        }

        const now_sec = std.time.timestamp();

        for (table_list) |table_offset| {
            try stream.seekTo(db_header.schema_offset + table_offset);

            const table_header = try reader.readStructEndian(TableHeader, .big);

            if (@as(std.c.DB_RECORDTYPE, @enumFromInt(table_header.table_id)) != .X509_CERTIFICATE) {
                continue;
            }

            var record_list = try gpa.alloc(u32, table_header.record_count);
            defer gpa.free(record_list);

            var record_idx: u32 = 0;
            while (record_idx < record_list.len) : (record_idx += 1) {
                record_list[record_idx] = try reader.readInt(u32, .big);
            }

            for (record_list) |record_offset| {
                // An offset of zero means that the record is not present.
                // An offset that is not 4-byte-aligned is invalid.
                if (record_offset == 0 or record_offset % 4 != 0) continue;

                try stream.seekTo(db_header.schema_offset + table_offset + record_offset);

                const cert_header = try reader.readStructEndian(X509CertHeader, .big);

                if (cert_header.cert_size == 0) continue;

                const cert_start = @as(u32, @intCast(cb.bytes.items.len));
                const dest_buf = try cb.bytes.addManyAsSlice(gpa, cert_header.cert_size);
                try reader.readNoEof(dest_buf);

                try cb.parseCert(gpa, cert_start, now_sec);
            }
        }
    }

    cb.bytes.shrinkAndFree(gpa, cb.bytes.items.len);
}

const ApplDbHeader = extern struct {
    signature: [4]u8,
    version: u32,
    header_size: u32,
    schema_offset: u32,
    auth_offset: u32,
};

const ApplDbSchema = extern struct {
    schema_size: u32,
    table_count: u32,
};

const TableHeader = extern struct {
    table_size: u32,
    table_id: u32,
    record_count: u32,
    records: u32,
    indexes_offset: u32,
    free_list_head: u32,
    record_numbers_count: u32,
};

const X509CertHeader = extern struct {
    record_size: u32,
    record_number: u32,
    unknown1: u32,
    unknown2: u32,
    cert_size: u32,
    unknown3: u32,
    cert_type: u32,
    cert_encoding: u32,
    print_name: u32,
    alias: u32,
    subject: u32,
    issuer: u32,
    serial_number: u32,
    subject_key_identifier: u32,
    public_key_hash: u32,
};
// Based on public domain Supercop by Daniel J. Bernstein

const std = @import("../std.zig");
const builtin = @import("builtin");
const crypto = std.crypto;
const math = std.math;
const mem = std.mem;
const assert = std.debug.assert;
const testing = std.testing;
const maxInt = math.maxInt;
const Poly1305 = crypto.onetimeauth.Poly1305;
const AuthenticationError = crypto.errors.AuthenticationError;

/// IETF-variant of the ChaCha20 stream cipher, as designed for TLS.
pub const ChaCha20IETF = ChaChaIETF(20);

/// IETF-variant of the ChaCha20 stream cipher, reduced to 12 rounds.
/// Reduced-rounds versions are faster than the full-round version, but have a lower security margin.
/// However, ChaCha is still believed to have a comfortable security even with only 8 rounds.
pub const ChaCha12IETF = ChaChaIETF(12);

/// IETF-variant of the ChaCha20 stream cipher, reduced to 8 rounds.
/// Reduced-rounds versions are faster than the full-round version, but have a lower security margin.
/// However, ChaCha is still believed to have a comfortable security even with only 8 rounds.
pub const ChaCha8IETF = ChaChaIETF(8);

/// Original ChaCha20 stream cipher.
pub const ChaCha20With64BitNonce = ChaChaWith64BitNonce(20);

/// Original ChaCha20 stream cipher, reduced to 12 rounds.
/// Reduced-rounds versions are faster than the full-round version, but have a lower security margin.
/// However, ChaCha is still believed to have a comfortable security even with only 8 rounds.
pub const ChaCha12With64BitNonce = ChaChaWith64BitNonce(12);

/// Original ChaCha20 stream cipher, reduced to 8 rounds.
/// Reduced-rounds versions are faster than the full-round version, but have a lower security margin.
/// However, ChaCha is still believed to have a comfortable security even with only 8 rounds.
pub const ChaCha8With64BitNonce = ChaChaWith64BitNonce(8);

/// XChaCha20 (nonce-extended version of the IETF ChaCha20 variant) stream cipher
pub const XChaCha20IETF = XChaChaIETF(20);

/// XChaCha20 (nonce-extended version of the IETF ChaCha20 variant) stream cipher, reduced to 12 rounds
/// Reduced-rounds versions are faster than the full-round version, but have a lower security margin.
/// However, ChaCha is still believed to have a comfortable security even with only 8 rounds.
pub const XChaCha12IETF = XChaChaIETF(12);

/// XChaCha20 (nonce-extended version of the IETF ChaCha20 variant) stream cipher, reduced to 8 rounds
/// Reduced-rounds versions are faster than the full-round version, but have a lower security margin.
/// However, ChaCha is still believed to have a comfortable security even with only 8 rounds.
pub const XChaCha8IETF = XChaChaIETF(8);

/// ChaCha20-Poly1305 authenticated cipher, as designed for TLS
pub const ChaCha20Poly1305 = ChaChaPoly1305(20);

/// ChaCha20-Poly1305 authenticated cipher, reduced to 12 rounds
/// Reduced-rounds versions are faster than the full-round version, but have a lower security margin.
/// However, ChaCha is still believed to have a comfortable security even with only 8 rounds.
pub const ChaCha12Poly1305 = ChaChaPoly1305(12);

/// ChaCha20-Poly1305 authenticated cipher, reduced to 8 rounds
/// Reduced-rounds versions are faster than the full-round version, but have a lower security margin.
/// However, ChaCha is still believed to have a comfortable security even with only 8 rounds.
pub const ChaCha8Poly1305 = ChaChaPoly1305(8);

/// XChaCha20-Poly1305 authenticated cipher
pub const XChaCha20Poly1305 = XChaChaPoly1305(20);

/// XChaCha20-Poly1305 authenticated cipher
/// Reduced-rounds versions are faster than the full-round version, but have a lower security margin.
/// However, ChaCha is still believed to have a comfortable security even with only 8 rounds.
pub const XChaCha12Poly1305 = XChaChaPoly1305(12);

/// XChaCha20-Poly1305 authenticated cipher
/// Reduced-rounds versions are faster than the full-round version, but have a lower security margin.
/// However, ChaCha is still believed to have a comfortable security even with only 8 rounds.
pub const XChaCha8Poly1305 = XChaChaPoly1305(8);

// Vectorized implementation of the core function
fn ChaChaVecImpl(comptime rounds_nb: usize, comptime degree: comptime_int) type {
    return struct {
        const Lane = @Vector(4 * degree, u32);
        const BlockVec = [4]Lane;

        fn initContext(key: [8]u32, d: [4]u32) BlockVec {
            const c = "expand 32-byte k";
            switch (degree) {
                1 => {
                    const constant_le = Lane{
                        mem.readInt(u32, c[0..4], .little),
                        mem.readInt(u32, c[4..8], .little),
                        mem.readInt(u32, c[8..12], .little),
                        mem.readInt(u32, c[12..16], .little),
                    };
                    return BlockVec{
                        constant_le,
                        Lane{ key[0], key[1], key[2], key[3] },
                        Lane{ key[4], key[5], key[6], key[7] },
                        Lane{ d[0], d[1], d[2], d[3] },
                    };
                },
                2 => {
                    const constant_le = Lane{
                        mem.readInt(u32, c[0..4], .little),
                        mem.readInt(u32, c[4..8], .little),
                        mem.readInt(u32, c[8..12], .little),
                        mem.readInt(u32, c[12..16], .little),
                        mem.readInt(u32, c[0..4], .little),
                        mem.readInt(u32, c[4..8], .little),
                        mem.readInt(u32, c[8..12], .little),
                        mem.readInt(u32, c[12..16], .little),
                    };
                    const n1 = @addWithOverflow(d[0], 1);
                    return BlockVec{
                        constant_le,
                        Lane{ key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3] },
                        Lane{ key[4], key[5], key[6], key[7], key[4], key[5], key[6], key[7] },
                        Lane{ d[0], d[1], d[2], d[3], n1[0], d[1] +% n1[1], d[2], d[3] },
                    };
                },
                4 => {
                    const n1 = @addWithOverflow(d[0], 1);
                    const n2 = @addWithOverflow(d[0], 2);
                    const n3 = @addWithOverflow(d[0], 3);
                    const constant_le = Lane{
                        mem.readInt(u32, c[0..4], .little),
                        mem.readInt(u32, c[4..8], .little),
                        mem.readInt(u32, c[8..12], .little),
                        mem.readInt(u32, c[12..16], .little),
                        mem.readInt(u32, c[0..4], .little),
                        mem.readInt(u32, c[4..8], .little),
                        mem.readInt(u32, c[8..12], .little),
                        mem.readInt(u32, c[12..16], .little),
                        mem.readInt(u32, c[0..4], .little),
                        mem.readInt(u32, c[4..8], .little),
                        mem.readInt(u32, c[8..12], .little),
                        mem.readInt(u32, c[12..16], .little),
                        mem.readInt(u32, c[0..4], .little),
                        mem.readInt(u32, c[4..8], .little),
                        mem.readInt(u32, c[8..12], .little),
                        mem.readInt(u32, c[12..16], .little),
                    };
                    return BlockVec{
                        constant_le,
                        Lane{ key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3] },
                        Lane{ key[4], key[5], key[6], key[7], key[4], key[5], key[6], key[7], key[4], key[5], key[6], key[7], key[4], key[5], key[6], key[7] },
                        Lane{ d[0], d[1], d[2], d[3], n1[0], d[1] +% n1[1], d[2], d[3], n2[0], d[1] +% n2[1], d[2], d[3], n3[0], d[1] +% n3[1], d[2], d[3] },
                    };
                },
                else => @compileError("invalid degree"),
            }
        }

        inline fn chacha20Core(x: *BlockVec, input: BlockVec) void {
            x.* = input;

            const m0 = switch (degree) {
                1 => [_]i32{ 3, 0, 1, 2 },
                2 => [_]i32{ 3, 0, 1, 2 } ++ [_]i32{ 7, 4, 5, 6 },
                4 => [_]i32{ 3, 0, 1, 2 } ++ [_]i32{ 7, 4, 5, 6 } ++ [_]i32{ 11, 8, 9, 10 } ++ [_]i32{ 15, 12, 13, 14 },
                else => @compileError("invalid degree"),
            };
            const m1 = switch (degree) {
                1 => [_]i32{ 2, 3, 0, 1 },
                2 => [_]i32{ 2, 3, 0, 1 } ++ [_]i32{ 6, 7, 4, 5 },
                4 => [_]i32{ 2, 3, 0, 1 } ++ [_]i32{ 6, 7, 4, 5 } ++ [_]i32{ 10, 11, 8, 9 } ++ [_]i32{ 14, 15, 12, 13 },
                else => @compileError("invalid degree"),
            };
            const m2 = switch (degree) {
                1 => [_]i32{ 1, 2, 3, 0 },
                2 => [_]i32{ 1, 2, 3, 0 } ++ [_]i32{ 5, 6, 7, 4 },
                4 => [_]i32{ 1, 2, 3, 0 } ++ [_]i32{ 5, 6, 7, 4 } ++ [_]i32{ 9, 10, 11, 8 } ++ [_]i32{ 13, 14, 15, 12 },
                else => @compileError("invalid degree"),
            };

            var r: usize = 0;
            while (r < rounds_nb) : (r += 2) {
                x[0] +%= x[1];
                x[3] ^= x[0];
                x[3] = math.rotl(Lane, x[3], 16);

                x[2] +%= x[3];
                x[1] ^= x[2];
                x[1] = math.rotl(Lane, x[1], 12);

                x[0] +%= x[1];
                x[3] ^= x[0];
                x[0] = @shuffle(u32, x[0], undefined, m0);
                x[3] = math.rotl(Lane, x[3], 8);

                x[2] +%= x[3];
                x[3] = @shuffle(u32, x[3], undefined, m1);
                x[1] ^= x[2];
                x[2] = @shuffle(u32, x[2], undefined, m2);
                x[1] = math.rotl(Lane, x[1], 7);

                x[0] +%= x[1];
                x[3] ^= x[0];
                x[3] = math.rotl(Lane, x[3], 16);

                x[2] +%= x[3];
                x[1] ^= x[2];
                x[1] = math.rotl(Lane, x[1], 12);

                x[0] +%= x[1];
                x[3] ^= x[0];
                x[0] = @shuffle(u32, x[0], undefined, m2);
                x[3] = math.rotl(Lane, x[3], 8);

                x[2] +%= x[3];
                x[3] = @shuffle(u32, x[3], undefined, m1);
                x[1] ^= x[2];
                x[2] = @shuffle(u32, x[2], undefined, m0);
                x[1] = math.rotl(Lane, x[1], 7);
            }
        }

        inline fn hashToBytes(comptime dm: usize, out: *[64 * dm]u8, x: BlockVec) void {
            for (0..dm) |d| {
                for (0..4) |i| {
                    mem.writeInt(u32, out[64 * d + 16 * i + 0 ..][0..4], x[i][0 + 4 * d], .little);
                    mem.writeInt(u32, out[64 * d + 16 * i + 4 ..][0..4], x[i][1 + 4 * d], .little);
                    mem.writeInt(u32, out[64 * d + 16 * i + 8 ..][0..4], x[i][2 + 4 * d], .little);
                    mem.writeInt(u32, out[64 * d + 16 * i + 12 ..][0..4], x[i][3 + 4 * d], .little);
                }
            }
        }

        inline fn contextFeedback(x: *BlockVec, ctx: BlockVec) void {
            x[0] +%= ctx[0];
            x[1] +%= ctx[1];
            x[2] +%= ctx[2];
            x[3] +%= ctx[3];
        }

        fn chacha20Xor(out: []u8, in: []const u8, key: [8]u32, nonce_and_counter: [4]u32, comptime count64: bool) void {
            var ctx = initContext(key, nonce_and_counter);
            var x: BlockVec = undefined;
            var buf: [64 * degree]u8 = undefined;
            var i: usize = 0;
            inline for ([_]comptime_int{ 4, 2, 1 }) |d| {
                while (degree >= d and i + 64 * d <= in.len) : (i += 64 * d) {
                    chacha20Core(x[0..], ctx);
                    contextFeedback(&x, ctx);
                    hashToBytes(d, buf[0 .. 64 * d], x);

                    var xout = out[i..];
                    const xin = in[i..];
                    for (0..64 * d) |j| {
                        xout[j] = xin[j];
                    }
                    for (0..64 * d) |j| {
                        xout[j] ^= buf[j];
                    }
                    inline for (0..d) |d_| {
                        if (count64) {
                            const next = @addWithOverflow(ctx[3][4 * d_], d);
                            ctx[3][4 * d_] = next[0];
                            ctx[3][4 * d_ + 1] +%= next[1];
                        } else {
                            ctx[3][4 * d_] +%= d;
                        }
                    }
                }
            }
            if (i < in.len) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);
                hashToBytes(1, buf[0..64], x);

                var xout = out[i..];
                const xin = in[i..];
                for (0..in.len % 64) |j| {
                    xout[j] = xin[j] ^ buf[j];
                }
            }
        }

        fn chacha20Stream(out: []u8, key: [8]u32, nonce_and_counter: [4]u32, comptime count64: bool) void {
            var ctx = initContext(key, nonce_and_counter);
            var x: BlockVec = undefined;
            var i: usize = 0;
            inline for ([_]comptime_int{ 4, 2, 1 }) |d| {
                while (degree >= d and i + 64 * d <= out.len) : (i += 64 * d) {
                    chacha20Core(x[0..], ctx);
                    contextFeedback(&x, ctx);
                    hashToBytes(d, out[i..][0 .. 64 * d], x);
                    inline for (0..d) |d_| {
                        if (count64) {
                            const next = @addWithOverflow(ctx[3][4 * d_], d);
                            ctx[3][4 * d_] = next[0];
                            ctx[3][4 * d_ + 1] +%= next[1];
                        } else {
                            ctx[3][4 * d_] +%= d;
                        }
                    }
                }
            }
            if (i < out.len) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);

                var buf: [64]u8 = undefined;
                hashToBytes(1, buf[0..], x);
                @memcpy(out[i..], buf[0 .. out.len - i]);
            }
        }

        fn hchacha20(input: [16]u8, key: [32]u8) [32]u8 {
            var c: [4]u32 = undefined;
            for (c, 0..) |_, i| {
                c[i] = mem.readInt(u32, input[4 * i ..][0..4], .little);
            }
            const ctx = initContext(keyToWords(key), c);
            var x: BlockVec = undefined;
            chacha20Core(x[0..], ctx);
            var out: [32]u8 = undefined;
            mem.writeInt(u32, out[0..4], x[0][0], .little);
            mem.writeInt(u32, out[4..8], x[0][1], .little);
            mem.writeInt(u32, out[8..12], x[0][2], .little);
            mem.writeInt(u32, out[12..16], x[0][3], .little);
            mem.writeInt(u32, out[16..20], x[3][0], .little);
            mem.writeInt(u32, out[20..24], x[3][1], .little);
            mem.writeInt(u32, out[24..28], x[3][2], .little);
            mem.writeInt(u32, out[28..32], x[3][3], .little);
            return out;
        }
    };
}

// Non-vectorized implementation of the core function
fn ChaChaNonVecImpl(comptime rounds_nb: usize) type {
    return struct {
        const BlockVec = [16]u32;

        fn initContext(key: [8]u32, d: [4]u32) BlockVec {
            const c = "expand 32-byte k";
            const constant_le = comptime [4]u32{
                mem.readInt(u32, c[0..4], .little),
                mem.readInt(u32, c[4..8], .little),
                mem.readInt(u32, c[8..12], .little),
                mem.readInt(u32, c[12..16], .little),
            };
            return BlockVec{
                constant_le[0], constant_le[1], constant_le[2], constant_le[3],
                key[0],         key[1],         key[2],         key[3],
                key[4],         key[5],         key[6],         key[7],
                d[0],           d[1],           d[2],           d[3],
            };
        }

        const QuarterRound = struct {
            a: usize,
            b: usize,
            c: usize,
            d: usize,
        };

        fn Rp(a: usize, b: usize, c: usize, d: usize) QuarterRound {
            return QuarterRound{
                .a = a,
                .b = b,
                .c = c,
                .d = d,
            };
        }

        inline fn chacha20Core(x: *BlockVec, input: BlockVec) void {
            x.* = input;

            const rounds = comptime [_]QuarterRound{
                Rp(0, 4, 8, 12),
                Rp(1, 5, 9, 13),
                Rp(2, 6, 10, 14),
                Rp(3, 7, 11, 15),
                Rp(0, 5, 10, 15),
                Rp(1, 6, 11, 12),
                Rp(2, 7, 8, 13),
                Rp(3, 4, 9, 14),
            };

            comptime var j: usize = 0;
            inline while (j < rounds_nb) : (j += 2) {
                inline for (rounds) |r| {
                    x[r.a] +%= x[r.b];
                    x[r.d] = math.rotl(u32, x[r.d] ^ x[r.a], @as(u32, 16));
                    x[r.c] +%= x[r.d];
                    x[r.b] = math.rotl(u32, x[r.b] ^ x[r.c], @as(u32, 12));
                    x[r.a] +%= x[r.b];
                    x[r.d] = math.rotl(u32, x[r.d] ^ x[r.a], @as(u32, 8));
                    x[r.c] +%= x[r.d];
                    x[r.b] = math.rotl(u32, x[r.b] ^ x[r.c], @as(u32, 7));
                }
            }
        }

        inline fn hashToBytes(out: *[64]u8, x: BlockVec) void {
            for (0..4) |i| {
                mem.writeInt(u32, out[16 * i + 0 ..][0..4], x[i * 4 + 0], .little);
                mem.writeInt(u32, out[16 * i + 4 ..][0..4], x[i * 4 + 1], .little);
                mem.writeInt(u32, out[16 * i + 8 ..][0..4], x[i * 4 + 2], .little);
                mem.writeInt(u32, out[16 * i + 12 ..][0..4], x[i * 4 + 3], .little);
            }
        }

        inline fn contextFeedback(x: *BlockVec, ctx: BlockVec) void {
            for (0..16) |i| {
                x[i] +%= ctx[i];
            }
        }

        fn chacha20Xor(out: []u8, in: []const u8, key: [8]u32, nonce_and_counter: [4]u32, comptime count64: bool) void {
            var ctx = initContext(key, nonce_and_counter);
            var x: BlockVec = undefined;
            var buf: [64]u8 = undefined;
            var i: usize = 0;
            while (i + 64 <= in.len) : (i += 64) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);
                hashToBytes(buf[0..], x);

                var xout = out[i..];
                const xin = in[i..];
                for (0..64) |j| {
                    xout[j] = xin[j];
                }
                for (0..64) |j| {
                    xout[j] ^= buf[j];
                }
                if (count64) {
                    const next = @addWithOverflow(ctx[12], 1);
                    ctx[12] = next[0];
                    ctx[13] +%= next[1];
                } else {
                    ctx[12] +%= 1;
                }
            }
            if (i < in.len) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);
                hashToBytes(buf[0..], x);

                var xout = out[i..];
                const xin = in[i..];
                for (0..in.len % 64) |j| {
                    xout[j] = xin[j] ^ buf[j];
                }
            }
        }

        fn chacha20Stream(out: []u8, key: [8]u32, nonce_and_counter: [4]u32, comptime count64: bool) void {
            var ctx = initContext(key, nonce_and_counter);
            var x: BlockVec = undefined;
            var i: usize = 0;
            while (i + 64 <= out.len) : (i += 64) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);
                hashToBytes(out[i..][0..64], x);
                if (count64) {
                    const next = @addWithOverflow(ctx[12], 1);
                    ctx[12] = next[0];
                    ctx[13] +%= next[1];
                } else {
                    ctx[12] +%= 1;
                }
            }
            if (i < out.len) {
                chacha20Core(x[0..], ctx);
                contextFeedback(&x, ctx);

                var buf: [64]u8 = undefined;
                hashToBytes(buf[0..], x);
                @memcpy(out[i..], buf[0 .. out.len - i]);
            }
        }

        fn hchacha20(input: [16]u8, key: [32]u8) [32]u8 {
            var c: [4]u32 = undefined;
            for (c, 0..) |_, i| {
                c[i] = mem.readInt(u32, input[4 * i ..][0..4], .little);
            }
            const ctx = initContext(keyToWords(key), c);
            var x: BlockVec = undefined;
            chacha20Core(x[0..], ctx);
            var out: [32]u8 = undefined;
            mem.writeInt(u32, out[0..4], x[0], .little);
            mem.writeInt(u32, out[4..8], x[1], .little);
            mem.writeInt(u32, out[8..12], x[2], .little);
            mem.writeInt(u32, out[12..16], x[3], .little);
            mem.writeInt(u32, out[16..20], x[12], .little);
            mem.writeInt(u32, out[20..24], x[13], .little);
            mem.writeInt(u32, out[24..28], x[14], .little);
            mem.writeInt(u32, out[28..32], x[15], .little);
            return out;
        }
    };
}

fn ChaChaImpl(comptime rounds_nb: usize) type {
    switch (builtin.cpu.arch) {
        .x86_64 => {
            const has_avx2 = std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);
            const has_avx512f = std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f);
            if (builtin.zig_backend != .stage2_x86_64 and has_avx512f) return ChaChaVecImpl(rounds_nb, 4);
            if (has_avx2) return ChaChaVecImpl(rounds_nb, 2);
            return ChaChaVecImpl(rounds_nb, 1);
        },
        .aarch64 => {
            const has_neon = std.Target.aarch64.featureSetHas(builtin.cpu.features, .neon);
            if (has_neon) return ChaChaVecImpl(rounds_nb, 4);
            return ChaChaNonVecImpl(rounds_nb);
        },
        else => return ChaChaNonVecImpl(rounds_nb),
    }
}

fn keyToWords(key: [32]u8) [8]u32 {
    var k: [8]u32 = undefined;
    for (0..8) |i| {
        k[i] = mem.readInt(u32, key[i * 4 ..][0..4], .little);
    }
    return k;
}

fn extend(key: [32]u8, nonce: [24]u8, comptime rounds_nb: usize) struct { key: [32]u8, nonce: [12]u8 } {
    var subnonce: [12]u8 = undefined;
    @memset(subnonce[0..4], 0);
    subnonce[4..].* = nonce[16..24].*;
    return .{
        .key = ChaChaImpl(rounds_nb).hchacha20(nonce[0..16].*, key),
        .nonce = subnonce,
    };
}

fn ChaChaIETF(comptime rounds_nb: usize) type {
    return struct {
        /// Nonce length in bytes.
        pub const nonce_length = 12;
        /// Key length in bytes.
        pub const key_length = 32;
        /// Block length in bytes.
        pub const block_length = 64;

        /// Add the output of the ChaCha20 stream cipher to `in` and stores the result into `out`.
        /// WARNING: This function doesn't provide authenticated encryption.
        /// Using the AEAD or one of the `box` versions is usually preferred.
        pub fn xor(out: []u8, in: []const u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
            assert(in.len == out.len);
            assert(in.len <= 64 * (@as(u39, 1 << 32) - counter));

            var d: [4]u32 = undefined;
            d[0] = counter;
            d[1] = mem.readInt(u32, nonce[0..4], .little);
            d[2] = mem.readInt(u32, nonce[4..8], .little);
            d[3] = mem.readInt(u32, nonce[8..12], .little);
            ChaChaImpl(rounds_nb).chacha20Xor(out, in, keyToWords(key), d, false);
        }

        /// Write the output of the ChaCha20 stream cipher into `out`.
        pub fn stream(out: []u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
            assert(out.len <= 64 * (@as(u39, 1 << 32) - counter));

            var d: [4]u32 = undefined;
            d[0] = counter;
            d[1] = mem.readInt(u32, nonce[0..4], .little);
            d[2] = mem.readInt(u32, nonce[4..8], .little);
            d[3] = mem.readInt(u32, nonce[8..12], .little);
            ChaChaImpl(rounds_nb).chacha20Stream(out, keyToWords(key), d, false);
        }
    };
}

fn ChaChaWith64BitNonce(comptime rounds_nb: usize) type {
    return struct {
        /// Nonce length in bytes.
        pub const nonce_length = 8;
        /// Key length in bytes.
        pub const key_length = 32;
        /// Block length in bytes.
        pub const block_length = 64;

        /// Add the output of the ChaCha20 stream cipher to `in` and stores the result into `out`.
        /// WARNING: This function doesn't provide authenticated encryption.
        /// Using the AEAD or one of the `box` versions is usually preferred.
        pub fn xor(out: []u8, in: []const u8, counter: u64, key: [key_length]u8, nonce: [nonce_length]u8) void {
            assert(in.len == out.len);
            assert(in.len <= 64 * (@as(u71, 1 << 64) - counter));

            const k = keyToWords(key);
            var c: [4]u32 = undefined;
            c[0] = @truncate(counter);
            c[1] = @truncate(counter >> 32);
            c[2] = mem.readInt(u32, nonce[0..4], .little);
            c[3] = mem.readInt(u32, nonce[4..8], .little);
            ChaChaImpl(rounds_nb).chacha20Xor(out, in, k, c, true);
        }

        /// Write the output of the ChaCha20 stream cipher into `out`.
        pub fn stream(out: []u8, counter: u64, key: [key_length]u8, nonce: [nonce_length]u8) void {
            assert(out.len <= 64 * (@as(u71, 1 << 64) - counter));

            const k = keyToWords(key);
            var c: [4]u32 = undefined;
            c[0] = @truncate(counter);
            c[1] = @truncate(counter >> 32);
            c[2] = mem.readInt(u32, nonce[0..4], .little);
            c[3] = mem.readInt(u32, nonce[4..8], .little);
            ChaChaImpl(rounds_nb).chacha20Stream(out, k, c, true);
        }
    };
}

fn XChaChaIETF(comptime rounds_nb: usize) type {
    return struct {
        /// Nonce length in bytes.
        pub const nonce_length = 24;
        /// Key length in bytes.
        pub const key_length = 32;
        /// Block length in bytes.
        pub const block_length = 64;

        /// Add the output of the XChaCha20 stream cipher to `in` and stores the result into `out`.
        /// WARNING: This function doesn't provide authenticated encryption.
        /// Using the AEAD or one of the `box` versions is usually preferred.
        pub fn xor(out: []u8, in: []const u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
            const extended = extend(key, nonce, rounds_nb);
            ChaChaIETF(rounds_nb).xor(out, in, counter, extended.key, extended.nonce);
        }

        /// Write the output of the XChaCha20 stream cipher into `out`.
        pub fn stream(out: []u8, counter: u32, key: [key_length]u8, nonce: [nonce_length]u8) void {
            const extended = extend(key, nonce, rounds_nb);
            ChaChaIETF(rounds_nb).stream(out, counter, extended.key, extended.nonce);
        }
    };
}

fn ChaChaPoly1305(comptime rounds_nb: usize) type {
    return struct {
        pub const tag_length = 16;
        pub const nonce_length = 12;
        pub const key_length = 32;

        /// c: ciphertext: output buffer should be of size m.len
        /// tag: authentication tag: output MAC
        /// m: message
        /// ad: Associated Data
        /// npub: public nonce
        /// k: private key
        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
            assert(c.len == m.len);
            assert(m.len <= 64 * (@as(u39, 1 << 32) - 1));

            var polyKey = [_]u8{0} ** 32;
            ChaChaIETF(rounds_nb).xor(polyKey[0..], polyKey[0..], 0, k, npub);

            ChaChaIETF(rounds_nb).xor(c[0..m.len], m, 1, k, npub);

            var mac = Poly1305.init(polyKey[0..]);
            mac.update(ad);
            if (ad.len % 16 != 0) {
                const zeros = [_]u8{0} ** 16;
                const padding = 16 - (ad.len % 16);
                mac.update(zeros[0..padding]);
            }
            mac.update(c[0..m.len]);
            if (m.len % 16 != 0) {
                const zeros = [_]u8{0} ** 16;
                const padding = 16 - (m.len % 16);
                mac.update(zeros[0..padding]);
            }
            var lens: [16]u8 = undefined;
            mem.writeInt(u64, lens[0..8], ad.len, .little);
            mem.writeInt(u64, lens[8..16], m.len, .little);
            mac.update(lens[0..]);
            mac.final(tag);
        }

        /// `m`: Message
        /// `c`: Ciphertext
        /// `tag`: Authentication tag
        /// `ad`: Associated data
        /// `npub`: Public nonce
        /// `k`: Private key
        /// Asserts `c.len == m.len`.
        ///
        /// Contents of `m` are undefined if an error is returned.
        pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
            assert(c.len == m.len);

            var polyKey = [_]u8{0} ** 32;
            ChaChaIETF(rounds_nb).xor(polyKey[0..], polyKey[0..], 0, k, npub);

            var mac = Poly1305.init(polyKey[0..]);

            mac.update(ad);
            if (ad.len % 16 != 0) {
                const zeros = [_]u8{0} ** 16;
                const padding = 16 - (ad.len % 16);
                mac.update(zeros[0..padding]);
            }
            mac.update(c);
            if (c.len % 16 != 0) {
                const zeros = [_]u8{0} ** 16;
                const padding = 16 - (c.len % 16);
                mac.update(zeros[0..padding]);
            }
            var lens: [16]u8 = undefined;
            mem.writeInt(u64, lens[0..8], ad.len, .little);
            mem.writeInt(u64, lens[8..16], c.len, .little);
            mac.update(lens[0..]);
            var computed_tag: [16]u8 = undefined;
            mac.final(computed_tag[0..]);

            const verify = crypto.timing_safe.eql([tag_length]u8, computed_tag, tag);
            if (!verify) {
                crypto.secureZero(u8, &computed_tag);
                @memset(m, undefined);
                return error.AuthenticationFailed;
            }
            ChaChaIETF(rounds_nb).xor(m[0..c.len], c, 1, k, npub);
        }
    };
}

fn XChaChaPoly1305(comptime rounds_nb: usize) type {
    return struct {
        pub const tag_length = 16;
        pub const nonce_length = 24;
        pub const key_length = 32;

        /// c: ciphertext: output buffer should be of size m.len
        /// tag: authentication tag: output MAC
        /// m: message
        /// ad: Associated Data
        /// npub: public nonce
        /// k: private key
        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) void {
            const extended = extend(k, npub, rounds_nb);
            return ChaChaPoly1305(rounds_nb).encrypt(c, tag, m, ad, extended.nonce, extended.key);
        }

        /// `m`: Message
        /// `c`: Ciphertext
        /// `tag`: Authentication tag
        /// `ad`: Associated data
        /// `npub`: Public nonce
        /// `k`: Private key
        /// Asserts `c.len == m.len`.
        ///
        /// Contents of `m` are undefined if an error is returned.
        pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, k: [key_length]u8) AuthenticationError!void {
            const extended = extend(k, npub, rounds_nb);
            return ChaChaPoly1305(rounds_nb).decrypt(m, c, tag, ad, extended.nonce, extended.key);
        }
    };
}

test "AEAD API" {
    const aeads = [_]type{ ChaCha20Poly1305, XChaCha20Poly1305 };
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const ad = "Additional data";

    inline for (aeads) |aead| {
        const key = [_]u8{69} ** aead.key_length;
        const nonce = [_]u8{42} ** aead.nonce_length;
        var c: [m.len]u8 = undefined;
        var tag: [aead.tag_length]u8 = undefined;
        var out: [m.len]u8 = undefined;

        aead.encrypt(c[0..], tag[0..], m, ad, nonce, key);
        try aead.decrypt(out[0..], c[0..], tag, ad[0..], nonce, key);
        try testing.expectEqualSlices(u8, out[0..], m);
        c[0] +%= 1;
        try testing.expectError(error.AuthenticationFailed, aead.decrypt(out[0..], c[0..], tag, ad[0..], nonce, key));
    }
}

// https://tools.ietf.org/html/rfc7539#section-2.4.2
test "test vector sunscreen" {
    const expected_result = [_]u8{
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    };
    const m = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    var result: [114]u8 = undefined;
    const key = [_]u8{
        0,  1,  2,  3,  4,  5,  6,  7,
        8,  9,  10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31,
    };
    const nonce = [_]u8{
        0, 0, 0, 0,
        0, 0, 0, 0x4a,
        0, 0, 0, 0,
    };

    ChaCha20IETF.xor(result[0..], m[0..], 1, key, nonce);
    try testing.expectEqualSlices(u8, &expected_result, &result);

    var m2: [114]u8 = undefined;
    ChaCha20IETF.xor(m2[0..], result[0..], 1, key, nonce);
    try testing.expect(mem.order(u8, m, &m2) == .eq);
}

// https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
test "test vector 1" {
    const expected_result = [_]u8{
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
        0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
        0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
        0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
        0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
        0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
        0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
        0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
    };
    const m = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    var result: [64]u8 = undefined;
    const key = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };
    const nonce = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };

    ChaCha20With64BitNonce.xor(result[0..], m[0..], 0, key, nonce);
    try testing.expectEqualSlices(u8, &expected_result, &result);
}

test "test vector 2" {
    const expected_result = [_]u8{
        0x45, 0x40, 0xf0, 0x5a, 0x9f, 0x1f, 0xb2, 0x96,
        0xd7, 0x73, 0x6e, 0x7b, 0x20, 0x8e, 0x3c, 0x96,
        0xeb, 0x4f, 0xe1, 0x83, 0x46, 0x88, 0xd2, 0x60,
        0x4f, 0x45, 0x09, 0x52, 0xed, 0x43, 0x2d, 0x41,
        0xbb, 0xe2, 0xa0, 0xb6, 0xea, 0x75, 0x66, 0xd2,
        0xa5, 0xd1, 0xe7, 0xe2, 0x0d, 0x42, 0xaf, 0x2c,
        0x53, 0xd7, 0x92, 0xb1, 0xc4, 0x3f, 0xea, 0x81,
        0x7e, 0x9a, 0xd2, 0x75, 0xae, 0x54, 0x69, 0x63,
    };
    const m = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    var result: [64]u8 = undefined;
    const key = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1,
    };
    const nonce = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };

    ChaCha20With64BitNonce.xor(result[0..], m[0..], 0, key, nonce);
    try testing.expectEqualSlices(u8, &expected_result, &result);
}

test "test vector 3" {
    const expected_result = [_]u8{
        0xde, 0x9c, 0xba, 0x7b, 0xf3, 0xd6, 0x9e, 0xf5,
        0xe7, 0x86, 0xdc, 0x63, 0x97, 0x3f, 0x65, 0x3a,
        0x0b, 0x49, 0xe0, 0x15, 0xad, 0xbf, 0xf7, 0x13,
        0x4f, 0xcb, 0x7d, 0xf1, 0x37, 0x82, 0x10, 0x31,
        0xe8, 0x5a, 0x05, 0x02, 0x78, 0xa7, 0x08, 0x45,
        0x27, 0x21, 0x4f, 0x73, 0xef, 0xc7, 0xfa, 0x5b,
        0x52, 0x77, 0x06, 0x2e, 0xb7, 0xa0, 0x43, 0x3e,
        0x44, 0x5f, 0x41, 0xe3,
    };
    const m = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0```
