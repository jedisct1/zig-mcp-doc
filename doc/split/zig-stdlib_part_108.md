```
                                   file.size = try std.fmt.parseInt(u64, try attr.value(&buf), 10);
                                },
                            }
                        }
                    },
                    // Ignored header type
                    .global_extended_header => {
                        self.reader.skipBytes(size, .{}) catch return error.TarHeadersTooBig;
                    },
                    // All other are unsupported header types
                    else => {
                        const d = self.diagnostics orelse return error.TarUnsupportedHeader;
                        try d.errors.append(d.allocator, .{ .unsupported_file_type = .{
                            .file_name = try d.allocator.dupe(u8, header.name()),
                            .file_type = kind,
                        } });
                        if (kind == .gnu_sparse) {
                            try self.skipGnuSparseExtendedHeaders(header);
                        }
                        self.reader.skipBytes(size, .{}) catch return error.TarHeadersTooBig;
                    },
                }
            }
            return null;
        }

        fn skipGnuSparseExtendedHeaders(self: *Self, header: Header) !void {
            var is_extended = header.bytes[482] > 0;
            while (is_extended) {
                var buf: [Header.SIZE]u8 = undefined;
                const n = try self.reader.readAll(&buf);
                if (n < Header.SIZE) return error.UnexpectedEndOfStream;
                is_extended = buf[504] > 0;
            }
        }
    };
}

/// Pax attributes iterator.
/// Size is length of pax extended header in reader.
fn paxIterator(reader: anytype, size: usize) PaxIterator(@TypeOf(reader)) {
    return PaxIterator(@TypeOf(reader)){
        .reader = reader,
        .size = size,
    };
}

const PaxAttributeKind = enum {
    path,
    linkpath,
    size,
};

// maxInt(u64) has 20 chars, base 10 in practice we got 24 chars
const pax_max_size_attr_len = 64;

fn PaxIterator(comptime ReaderType: type) type {
    return struct {
        size: usize, // cumulative size of all pax attributes
        reader: ReaderType,
        // scratch buffer used for reading attribute length and keyword
        scratch: [128]u8 = undefined,

        const Self = @This();

        const Attribute = struct {
            kind: PaxAttributeKind,
            len: usize, // length of the attribute value
            reader: ReaderType, // reader positioned at value start

            // Copies pax attribute value into destination buffer.
            // Must be called with destination buffer of size at least Attribute.len.
            pub fn value(self: Attribute, dst: []u8) ![]const u8 {
                if (self.len > dst.len) return error.TarInsufficientBuffer;
                // assert(self.len <= dst.len);
                const buf = dst[0..self.len];
                const n = try self.reader.readAll(buf);
                if (n < self.len) return error.UnexpectedEndOfStream;
                try validateAttributeEnding(self.reader);
                if (hasNull(buf)) return error.PaxNullInValue;
                return buf;
            }
        };

        // Iterates over pax attributes. Returns known only known attributes.
        // Caller has to call value in Attribute, to advance reader across value.
        pub fn next(self: *Self) !?Attribute {
            // Pax extended header consists of one or more attributes, each constructed as follows:
            // "%d %s=%s\n", <length>, <keyword>, <value>
            while (self.size > 0) {
                const length_buf = try self.readUntil(' ');
                const length = try std.fmt.parseInt(usize, length_buf, 10); // record length in bytes

                const keyword = try self.readUntil('=');
                if (hasNull(keyword)) return error.PaxNullInKeyword;

                // calculate value_len
                const value_start = length_buf.len + keyword.len + 2; // 2 separators
                if (length < value_start + 1 or self.size < length) return error.UnexpectedEndOfStream;
                const value_len = length - value_start - 1; // \n separator at end
                self.size -= length;

                const kind: PaxAttributeKind = if (eql(keyword, "path"))
                    .path
                else if (eql(keyword, "linkpath"))
                    .linkpath
                else if (eql(keyword, "size"))
                    .size
                else {
                    try self.reader.skipBytes(value_len, .{});
                    try validateAttributeEnding(self.reader);
                    continue;
                };
                if (kind == .size and value_len > pax_max_size_attr_len) {
                    return error.PaxSizeAttrOverflow;
                }
                return Attribute{
                    .kind = kind,
                    .len = value_len,
                    .reader = self.reader,
                };
            }

            return null;
        }

        fn readUntil(self: *Self, delimiter: u8) ![]const u8 {
            var fbs = std.io.fixedBufferStream(&self.scratch);
            try self.reader.streamUntilDelimiter(fbs.writer(), delimiter, null);
            return fbs.getWritten();
        }

        fn eql(a: []const u8, b: []const u8) bool {
            return std.mem.eql(u8, a, b);
        }

        fn hasNull(str: []const u8) bool {
            return (std.mem.indexOfScalar(u8, str, 0)) != null;
        }

        // Checks that each record ends with new line.
        fn validateAttributeEnding(reader: ReaderType) !void {
            if (try reader.readByte() != '\n') return error.PaxInvalidAttributeEnd;
        }
    };
}

/// Saves tar file content to the file systems.
pub fn pipeToFileSystem(dir: std.fs.Dir, reader: anytype, options: PipeOptions) !void {
    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var iter = iterator(reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
        .diagnostics = options.diagnostics,
    });

    while (try iter.next()) |file| {
        const file_name = stripComponents(file.name, options.strip_components);
        if (file_name.len == 0 and file.kind != .directory) {
            const d = options.diagnostics orelse return error.TarComponentsOutsideStrippedPrefix;
            try d.errors.append(d.allocator, .{ .components_outside_stripped_prefix = .{
                .file_name = try d.allocator.dupe(u8, file.name),
            } });
            continue;
        }
        if (options.diagnostics) |d| {
            try d.findRoot(file.kind, file_name);
        }

        switch (file.kind) {
            .directory => {
                if (file_name.len > 0 and !options.exclude_empty_directories) {
                    try dir.makePath(file_name);
                }
            },
            .file => {
                if (createDirAndFile(dir, file_name, fileMode(file.mode, options))) |fs_file| {
                    defer fs_file.close();
                    try file.writeAll(fs_file);
                } else |err| {
                    const d = options.diagnostics orelse return err;
                    try d.errors.append(d.allocator, .{ .unable_to_create_file = .{
                        .code = err,
                        .file_name = try d.allocator.dupe(u8, file_name),
                    } });
                }
            },
            .sym_link => {
                const link_name = file.link_name;
                createDirAndSymlink(dir, link_name, file_name) catch |err| {
                    const d = options.diagnostics orelse return error.UnableToCreateSymLink;
                    try d.errors.append(d.allocator, .{ .unable_to_create_sym_link = .{
                        .code = err,
                        .file_name = try d.allocator.dupe(u8, file_name),
                        .link_name = try d.allocator.dupe(u8, link_name),
                    } });
                };
            },
        }
    }
}

fn createDirAndFile(dir: std.fs.Dir, file_name: []const u8, mode: std.fs.File.Mode) !std.fs.File {
    const fs_file = dir.createFile(file_name, .{ .exclusive = true, .mode = mode }) catch |err| {
        if (err == error.FileNotFound) {
            if (std.fs.path.dirname(file_name)) |dir_name| {
                try dir.makePath(dir_name);
                return try dir.createFile(file_name, .{ .exclusive = true, .mode = mode });
            }
        }
        return err;
    };
    return fs_file;
}

// Creates a symbolic link at path `file_name` which points to `link_name`.
fn createDirAndSymlink(dir: std.fs.Dir, link_name: []const u8, file_name: []const u8) !void {
    dir.symLink(link_name, file_name, .{}) catch |err| {
        if (err == error.FileNotFound) {
            if (std.fs.path.dirname(file_name)) |dir_name| {
                try dir.makePath(dir_name);
                return try dir.symLink(link_name, file_name, .{});
            }
        }
        return err;
    };
}

fn stripComponents(path: []const u8, count: u32) []const u8 {
    var i: usize = 0;
    var c = count;
    while (c > 0) : (c -= 1) {
        if (std.mem.indexOfScalarPos(u8, path, i, '/')) |pos| {
            i = pos + 1;
        } else {
            i = path.len;
            break;
        }
    }
    return path[i..];
}

test stripComponents {
    const expectEqualStrings = testing.expectEqualStrings;
    try expectEqualStrings("a/b/c", stripComponents("a/b/c", 0));
    try expectEqualStrings("b/c", stripComponents("a/b/c", 1));
    try expectEqualStrings("c", stripComponents("a/b/c", 2));
    try expectEqualStrings("", stripComponents("a/b/c", 3));
    try expectEqualStrings("", stripComponents("a/b/c", 4));
}

test PaxIterator {
    const Attr = struct {
        kind: PaxAttributeKind,
        value: []const u8 = undefined,
        err: ?anyerror = null,
    };
    const cases = [_]struct {
        data: []const u8,
        attrs: []const Attr,
        err: ?anyerror = null,
    }{
        .{ // valid but unknown keys
            .data =
            \\30 mtime=1350244992.023960108
            \\6 k=1
            \\13 key1=val1
            \\10 a=name
            \\9 a=name
            \\
            ,
            .attrs = &[_]Attr{},
        },
        .{ // mix of known and unknown keys
            .data =
            \\6 k=1
            \\13 path=name
            \\17 linkpath=link
            \\13 key1=val1
            \\12 size=123
            \\13 key2=val2
            \\
            ,
            .attrs = &[_]Attr{
                .{ .kind = .path, .value = "name" },
                .{ .kind = .linkpath, .value = "link" },
                .{ .kind = .size, .value = "123" },
            },
        },
        .{ // too short size of the second key-value pair
            .data =
            \\13 path=name
            \\10 linkpath=value
            \\
            ,
            .attrs = &[_]Attr{
                .{ .kind = .path, .value = "name" },
            },
            .err = error.UnexpectedEndOfStream,
        },
        .{ // too long size of the second key-value pair
            .data =
            \\13 path=name
            \\6 k=1
            \\19 linkpath=value
            \\
            ,
            .attrs = &[_]Attr{
                .{ .kind = .path, .value = "name" },
            },
            .err = error.UnexpectedEndOfStream,
        },

        .{ // too long size of the second key-value pair
            .data =
            \\13 path=name
            \\19 linkpath=value
            \\6 k=1
            \\
            ,
            .attrs = &[_]Attr{
                .{ .kind = .path, .value = "name" },
                .{ .kind = .linkpath, .err = error.PaxInvalidAttributeEnd },
            },
        },
        .{ // null in keyword is not valid
            .data = "13 path=name\n" ++ "7 k\x00b=1\n",
            .attrs = &[_]Attr{
                .{ .kind = .path, .value = "name" },
            },
            .err = error.PaxNullInKeyword,
        },
        .{ // null in value is not valid
            .data = "23 path=name\x00with null\n",
            .attrs = &[_]Attr{
                .{ .kind = .path, .err = error.PaxNullInValue },
            },
        },
        .{ // 1000 characters path
            .data = "1011 path=" ++ "0123456789" ** 100 ++ "\n",
            .attrs = &[_]Attr{
                .{ .kind = .path, .value = "0123456789" ** 100 },
            },
        },
    };
    var buffer: [1024]u8 = undefined;

    outer: for (cases) |case| {
        var stream = std.io.fixedBufferStream(case.data);
        var iter = paxIterator(stream.reader(), case.data.len);

        var i: usize = 0;
        while (iter.next() catch |err| {
            if (case.err) |e| {
                try testing.expectEqual(e, err);
                continue;
            }
            return err;
        }) |attr| : (i += 1) {
            const exp = case.attrs[i];
            try testing.expectEqual(exp.kind, attr.kind);
            const value = attr.value(&buffer) catch |err| {
                if (exp.err) |e| {
                    try testing.expectEqual(e, err);
                    break :outer;
                }
                return err;
            };
            try testing.expectEqualStrings(exp.value, value);
        }
        try testing.expectEqual(case.attrs.len, i);
        try testing.expect(case.err == null);
    }
}

test {
    _ = @import("tar/test.zig");
    _ = @import("tar/writer.zig");
    _ = Diagnostics;
}

test "header parse size" {
    const cases = [_]struct {
        in: []const u8,
        want: u64 = 0,
        err: ?anyerror = null,
    }{
        // Test base-256 (binary) encoded values.
        .{ .in = "", .want = 0 },
        .{ .in = "\x80", .want = 0 },
        .{ .in = "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", .want = 1 },
        .{ .in = "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02", .want = 0x0102 },
        .{ .in = "\x80\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08", .want = 0x0102030405060708 },
        .{ .in = "\x80\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09", .err = error.TarNumericValueTooBig },
        .{ .in = "\x80\x00\x00\x00\x07\x76\xa2\x22\xeb\x8a\x72\x61", .want = 537795476381659745 },
        .{ .in = "\x80\x80\x80\x00\x01\x02\x03\x04\x05\x06\x07\x08", .err = error.TarNumericValueTooBig },

        // // Test base-8 (octal) encoded values.
        .{ .in = "00000000227\x00", .want = 0o227 },
        .{ .in = "  000000227\x00", .want = 0o227 },
        .{ .in = "00000000228\x00", .err = error.TarHeader },
        .{ .in = "11111111111\x00", .want = 0o11111111111 },
    };

    for (cases) |case| {
        var bytes = [_]u8{0} ** Header.SIZE;
        @memcpy(bytes[124 .. 124 + case.in.len], case.in);
        var header = Header{ .bytes = &bytes };
        if (case.err) |err| {
            try testing.expectError(err, header.size());
        } else {
            try testing.expectEqual(case.want, try header.size());
        }
    }
}

test "header parse mode" {
    const cases = [_]struct {
        in: []const u8,
        want: u64 = 0,
        err: ?anyerror = null,
    }{
        .{ .in = "0000644\x00", .want = 0o644 },
        .{ .in = "0000777\x00", .want = 0o777 },
        .{ .in = "7777777\x00", .want = 0o7777777 },
        .{ .in = "7777778\x00", .err = error.TarHeader },
        .{ .in = "77777777", .want = 0o77777777 },
        .{ .in = "777777777777", .want = 0o77777777 },
    };
    for (cases) |case| {
        var bytes = [_]u8{0} ** Header.SIZE;
        @memcpy(bytes[100 .. 100 + case.in.len], case.in);
        var header = Header{ .bytes = &bytes };
        if (case.err) |err| {
            try testing.expectError(err, header.mode());
        } else {
            try testing.expectEqual(case.want, try header.mode());
        }
    }
}

test "create file and symlink" {
    var root = testing.tmpDir(.{});
    defer root.cleanup();

    var file = try createDirAndFile(root.dir, "file1", default_mode);
    file.close();
    file = try createDirAndFile(root.dir, "a/b/c/file2", default_mode);
    file.close();

    createDirAndSymlink(root.dir, "a/b/c/file2", "symlink1") catch |err| {
        // On Windows when developer mode is not enabled
        if (err == error.AccessDenied) return error.SkipZigTest;
        return err;
    };
    try createDirAndSymlink(root.dir, "../../../file1", "d/e/f/symlink2");

    // Danglink symlnik, file created later
    try createDirAndSymlink(root.dir, "../../../g/h/i/file4", "j/k/l/symlink3");
    file = try createDirAndFile(root.dir, "g/h/i/file4", default_mode);
    file.close();
}

test iterator {
    // Example tar file is created from this tree structure:
    // $ tree example
    //    example
    //    ├── a
    //    │   └── file
    //    ├── b
    //    │   └── symlink -> ../a/file
    //    └── empty
    // $ cat example/a/file
    //   content
    // $ tar -cf example.tar example
    // $ tar -tvf example.tar
    //    example/
    //    example/b/
    //    example/b/symlink -> ../a/file
    //    example/a/
    //    example/a/file
    //    example/empty/

    const data = @embedFile("tar/testdata/example.tar");
    var fbs = std.io.fixedBufferStream(data);

    // User provided buffers to the iterator
    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    // Create iterator
    var iter = iterator(fbs.reader(), .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });
    // Iterate over files in example.tar
    var file_no: usize = 0;
    while (try iter.next()) |file| : (file_no += 1) {
        switch (file.kind) {
            .directory => {
                switch (file_no) {
                    0 => try testing.expectEqualStrings("example/", file.name),
                    1 => try testing.expectEqualStrings("example/b/", file.name),
                    3 => try testing.expectEqualStrings("example/a/", file.name),
                    5 => try testing.expectEqualStrings("example/empty/", file.name),
                    else => unreachable,
                }
            },
            .file => {
                try testing.expectEqualStrings("example/a/file", file.name);
                // Read file content
                var buf: [16]u8 = undefined;
                const n = try file.reader().readAll(&buf);
                try testing.expectEqualStrings("content\n", buf[0..n]);
            },
            .sym_link => {
                try testing.expectEqualStrings("example/b/symlink", file.name);
                try testing.expectEqualStrings("../a/file", file.link_name);
            },
        }
    }
}

test pipeToFileSystem {
    // Example tar file is created from this tree structure:
    // $ tree example
    //    example
    //    ├── a
    //    │   └── file
    //    ├── b
    //    │   └── symlink -> ../a/file
    //    └── empty
    // $ cat example/a/file
    //   content
    // $ tar -cf example.tar example
    // $ tar -tvf example.tar
    //    example/
    //    example/b/
    //    example/b/symlink -> ../a/file
    //    example/a/
    //    example/a/file
    //    example/empty/

    const data = @embedFile("tar/testdata/example.tar");
    var fbs = std.io.fixedBufferStream(data);
    const reader = fbs.reader();

    var tmp = testing.tmpDir(.{ .no_follow = true });
    defer tmp.cleanup();
    const dir = tmp.dir;

    // Save tar from `reader` to the file system `dir`
    pipeToFileSystem(dir, reader, .{
        .mode_mode = .ignore,
        .strip_components = 1,
        .exclude_empty_directories = true,
    }) catch |err| {
        // Skip on platform which don't support symlinks
        if (err == error.UnableToCreateSymLink) return error.SkipZigTest;
        return err;
    };

    try testing.expectError(error.FileNotFound, dir.statFile("empty"));
    try testing.expect((try dir.statFile("a/file")).kind == .file);
    try testing.expect((try dir.statFile("b/symlink")).kind == .file); // statFile follows symlink

    var buf: [32]u8 = undefined;
    try testing.expectEqualSlices(
        u8,
        "../a/file",
        normalizePath(try dir.readLink("b/symlink", &buf)),
    );
}

test "pipeToFileSystem root_dir" {
    const data = @embedFile("tar/testdata/example.tar");
    var fbs = std.io.fixedBufferStream(data);
    const reader = fbs.reader();

    // with strip_components = 1
    {
        var tmp = testing.tmpDir(.{ .no_follow = true });
        defer tmp.cleanup();
        var diagnostics: Diagnostics = .{ .allocator = testing.allocator };
        defer diagnostics.deinit();

        pipeToFileSystem(tmp.dir, reader, .{
            .strip_components = 1,
            .diagnostics = &diagnostics,
        }) catch |err| {
            // Skip on platform which don't support symlinks
            if (err == error.UnableToCreateSymLink) return error.SkipZigTest;
            return err;
        };

        // there is no root_dir
        try testing.expectEqual(0, diagnostics.root_dir.len);
        try testing.expectEqual(5, diagnostics.entries);
    }

    // with strip_components = 0
    {
        fbs.reset();
        var tmp = testing.tmpDir(.{ .no_follow = true });
        defer tmp.cleanup();
        var diagnostics: Diagnostics = .{ .allocator = testing.allocator };
        defer diagnostics.deinit();

        pipeToFileSystem(tmp.dir, reader, .{
            .strip_components = 0,
            .diagnostics = &diagnostics,
        }) catch |err| {
            // Skip on platform which don't support symlinks
            if (err == error.UnableToCreateSymLink) return error.SkipZigTest;
            return err;
        };

        // root_dir found
        try testing.expectEqualStrings("example", diagnostics.root_dir);
        try testing.expectEqual(6, diagnostics.entries);
    }
}

test "findRoot with single file archive" {
    const data = @embedFile("tar/testdata/22752.tar");
    var fbs = std.io.fixedBufferStream(data);
    const reader = fbs.reader();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var diagnostics: Diagnostics = .{ .allocator = testing.allocator };
    defer diagnostics.deinit();
    try pipeToFileSystem(tmp.dir, reader, .{ .diagnostics = &diagnostics });

    try testing.expectEqualStrings("", diagnostics.root_dir);
}

test "findRoot without explicit root dir" {
    const data = @embedFile("tar/testdata/19820.tar");
    var fbs = std.io.fixedBufferStream(data);
    const reader = fbs.reader();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var diagnostics: Diagnostics = .{ .allocator = testing.allocator };
    defer diagnostics.deinit();
    try pipeToFileSystem(tmp.dir, reader, .{ .diagnostics = &diagnostics });

    try testing.expectEqualStrings("root", diagnostics.root_dir);
}

test "pipeToFileSystem strip_components" {
    const data = @embedFile("tar/testdata/example.tar");
    var fbs = std.io.fixedBufferStream(data);
    const reader = fbs.reader();

    var tmp = testing.tmpDir(.{ .no_follow = true });
    defer tmp.cleanup();
    var diagnostics: Diagnostics = .{ .allocator = testing.allocator };
    defer diagnostics.deinit();

    pipeToFileSystem(tmp.dir, reader, .{
        .strip_components = 3,
        .diagnostics = &diagnostics,
    }) catch |err| {
        // Skip on platform which don't support symlinks
        if (err == error.UnableToCreateSymLink) return error.SkipZigTest;
        return err;
    };

    try testing.expectEqual(2, diagnostics.errors.items.len);
    try testing.expectEqualStrings("example/b/symlink", diagnostics.errors.items[0].components_outside_stripped_prefix.file_name);
    try testing.expectEqualStrings("example/a/file", diagnostics.errors.items[1].components_outside_stripped_prefix.file_name);
}

fn normalizePath(bytes: []u8) []u8 {
    const canonical_sep = std.fs.path.sep_posix;
    if (std.fs.path.sep == canonical_sep) return bytes;
    std.mem.replaceScalar(u8, bytes, std.fs.path.sep, canonical_sep);
    return bytes;
}

const default_mode = std.fs.File.default_mode;

// File system mode based on tar header mode and mode_mode options.
fn fileMode(mode: u32, options: PipeOptions) std.fs.File.Mode {
    if (!std.fs.has_executable_bit or options.mode_mode == .ignore)
        return default_mode;

    const S = std.posix.S;

    // The mode from the tar file is inspected for the owner executable bit.
    if (mode & S.IXUSR == 0)
        return default_mode;

    // This bit is copied to the group and other executable bits.
    // Other bits of the mode are left as the default when creating files.
    return default_mode | S.IXUSR | S.IXGRP | S.IXOTH;
}

test fileMode {
    if (!std.fs.has_executable_bit) return error.SkipZigTest;
    try testing.expectEqual(default_mode, fileMode(0o744, PipeOptions{ .mode_mode = .ignore }));
    try testing.expectEqual(0o777, fileMode(0o744, PipeOptions{}));
    try testing.expectEqual(0o666, fileMode(0o644, PipeOptions{}));
    try testing.expectEqual(0o666, fileMode(0o655, PipeOptions{}));
}

test "executable bit" {
    if (!std.fs.has_executable_bit) return error.SkipZigTest;

    const S = std.posix.S;
    const data = @embedFile("tar/testdata/example.tar");

    for ([_]PipeOptions.ModeMode{ .ignore, .executable_bit_only }) |opt| {
        var fbs = std.io.fixedBufferStream(data);
        const reader = fbs.reader();

        var tmp = testing.tmpDir(.{ .no_follow = true });
        //defer tmp.cleanup();

        pipeToFileSystem(tmp.dir, reader, .{
            .strip_components = 1,
            .exclude_empty_directories = true,
            .mode_mode = opt,
        }) catch |err| {
            // Skip on platform which don't support symlinks
            if (err == error.UnableToCreateSymLink) return error.SkipZigTest;
            return err;
        };

        const fs = try tmp.dir.statFile("a/file");
        try testing.expect(fs.kind == .file);

        if (opt == .executable_bit_only) {
            // Executable bit is set for user, group and others
            try testing.expect(fs.mode & S.IXUSR > 0);
            try testing.expect(fs.mode & S.IXGRP > 0);
            try testing.expect(fs.mode & S.IXOTH > 0);
        }
        if (opt == .ignore) {
            try testing.expect(fs.mode & S.IXUSR == 0);
            try testing.expect(fs.mode & S.IXGRP == 0);
            try testing.expect(fs.mode & S.IXOTH == 0);
        }
    }
}
const std = @import("std");
const tar = @import("../tar.zig");
const testing = std.testing;

const Case = struct {
    const File = struct {
        name: []const u8,
        size: u64 = 0,
        mode: u32 = 0,
        link_name: []const u8 = &[0]u8{},
        kind: tar.FileKind = .file,
        truncated: bool = false, // when there is no file body, just header, useful for huge files
    };

    data: []const u8, // testdata file content
    files: []const File = &[_]@This().File{}, // expected files to found in archive
    chksums: []const []const u8 = &[_][]const u8{}, // chksums of each file content
    err: ?anyerror = null, // parsing should fail with this error
};

const cases = [_]Case{
    .{
        .data = @embedFile("testdata/gnu.tar"),
        .files = &[_]Case.File{
            .{
                .name = "small.txt",
                .size = 5,
                .mode = 0o640,
            },
            .{
                .name = "small2.txt",
                .size = 11,
                .mode = 0o640,
            },
        },
        .chksums = &[_][]const u8{
            "e38b27eaccb4391bdec553a7f3ae6b2f",
            "c65bd2e50a56a2138bf1716f2fd56fe9",
        },
    },
    .{
        .data = @embedFile("testdata/sparse-formats.tar"),
        .err = error.TarUnsupportedHeader,
    },
    .{
        .data = @embedFile("testdata/star.tar"),
        .files = &[_]Case.File{
            .{
                .name = "small.txt",
                .size = 5,
                .mode = 0o640,
            },
            .{
                .name = "small2.txt",
                .size = 11,
                .mode = 0o640,
            },
        },
        .chksums = &[_][]const u8{
            "e38b27eaccb4391bdec553a7f3ae6b2f",
            "c65bd2e50a56a2138bf1716f2fd56fe9",
        },
    },
    .{
        .data = @embedFile("testdata/v7.tar"),
        .files = &[_]Case.File{
            .{
                .name = "small.txt",
                .size = 5,
                .mode = 0o444,
            },
            .{
                .name = "small2.txt",
                .size = 11,
                .mode = 0o444,
            },
        },
        .chksums = &[_][]const u8{
            "e38b27eaccb4391bdec553a7f3ae6b2f",
            "c65bd2e50a56a2138bf1716f2fd56fe9",
        },
    },
    .{
        .data = @embedFile("testdata/pax.tar"),
        .files = &[_]Case.File{
            .{
                .name = "a/123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100",
                .size = 7,
                .mode = 0o664,
            },
            .{
                .name = "a/b",
                .size = 0,
                .kind = .sym_link,
                .mode = 0o777,
                .link_name = "123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100",
            },
        },
        .chksums = &[_][]const u8{
            "3c382e8f5b6631aa2db52643912ffd4a",
        },
    },
    .{
        // pax attribute don't end with \n
        .data = @embedFile("testdata/pax-bad-hdr-file.tar"),
        .err = error.PaxInvalidAttributeEnd,
    },
    .{
        // size is in pax attribute
        .data = @embedFile("testdata/pax-pos-size-file.tar"),
        .files = &[_]Case.File{
            .{
                .name = "foo",
                .size = 999,
                .kind = .file,
                .mode = 0o640,
            },
        },
        .chksums = &[_][]const u8{
            "0afb597b283fe61b5d4879669a350556",
        },
    },
    .{
        // has pax records which we are not interested in
        .data = @embedFile("testdata/pax-records.tar"),
        .files = &[_]Case.File{
            .{
                .name = "file",
            },
        },
    },
    .{
        // has global records which we are ignoring
        .data = @embedFile("testdata/pax-global-records.tar"),
        .files = &[_]Case.File{
            .{
                .name = "file1",
            },
            .{
                .name = "file2",
            },
            .{
                .name = "file3",
            },
            .{
                .name = "file4",
            },
        },
    },
    .{
        .data = @embedFile("testdata/nil-uid.tar"),
        .files = &[_]Case.File{
            .{
                .name = "P1050238.JPG.log",
                .size = 14,
                .kind = .file,
                .mode = 0o664,
            },
        },
        .chksums = &[_][]const u8{
            "08d504674115e77a67244beac19668f5",
        },
    },
    .{
        // has xattrs and pax records which we are ignoring
        .data = @embedFile("testdata/xattrs.tar"),
        .files = &[_]Case.File{
            .{
                .name = "small.txt",
                .size = 5,
                .kind = .file,
                .mode = 0o644,
            },
            .{
                .name = "small2.txt",
                .size = 11,
                .kind = .file,
                .mode = 0o644,
            },
        },
        .chksums = &[_][]const u8{
            "e38b27eaccb4391bdec553a7f3ae6b2f",
            "c65bd2e50a56a2138bf1716f2fd56fe9",
        },
    },
    .{
        .data = @embedFile("testdata/gnu-multi-hdrs.tar"),
        .files = &[_]Case.File{
            .{
                .name = "GNU2/GNU2/long-path-name",
                .link_name = "GNU4/GNU4/long-linkpath-name",
                .kind = .sym_link,
            },
        },
    },
    .{
        // has gnu type D (directory) and S (sparse) blocks
        .data = @embedFile("testdata/gnu-incremental.tar"),
        .err = error.TarUnsupportedHeader,
    },
    .{
        // should use values only from last pax header
        .data = @embedFile("testdata/pax-multi-hdrs.tar"),
        .files = &[_]Case.File{
            .{
                .name = "bar",
                .link_name = "PAX4/PAX4/long-linkpath-name",
                .kind = .sym_link,
            },
        },
    },
    .{
        .data = @embedFile("testdata/gnu-long-nul.tar"),
        .files = &[_]Case.File{
            .{
                .name = "0123456789",
                .mode = 0o644,
            },
        },
    },
    .{
        .data = @embedFile("testdata/gnu-utf8.tar"),
        .files = &[_]Case.File{
            .{
                .name = "☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹",
                .mode = 0o644,
            },
        },
    },
    .{
        .data = @embedFile("testdata/gnu-not-utf8.tar"),
        .files = &[_]Case.File{
            .{
                .name = "hi\x80\x81\x82\x83bye",
                .mode = 0o644,
            },
        },
    },
    .{
        // null in pax key
        .data = @embedFile("testdata/pax-nul-xattrs.tar"),
        .err = error.PaxNullInKeyword,
    },
    .{
        .data = @embedFile("testdata/pax-nul-path.tar"),
        .err = error.PaxNullInValue,
    },
    .{
        .data = @embedFile("testdata/neg-size.tar"),
        .err = error.TarHeader,
    },
    .{
        .data = @embedFile("testdata/issue10968.tar"),
        .err = error.TarHeader,
    },
    .{
        .data = @embedFile("testdata/issue11169.tar"),
        .err = error.TarHeader,
    },
    .{
        .data = @embedFile("testdata/issue12435.tar"),
        .err = error.TarHeaderChksum,
    },
    .{
        // has magic with space at end instead of null
        .data = @embedFile("testdata/invalid-go17.tar"),
        .files = &[_]Case.File{
            .{
                .name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/foo",
            },
        },
    },
    .{
        .data = @embedFile("testdata/ustar-file-devs.tar"),
        .files = &[_]Case.File{
            .{
                .name = "file",
                .mode = 0o644,
            },
        },
    },
    .{
        .data = @embedFile("testdata/trailing-slash.tar"),
        .files = &[_]Case.File{
            .{
                .name = "123456789/" ** 30,
                .kind = .directory,
            },
        },
    },
    .{
        // Has size in gnu extended format. To represent size bigger than 8 GB.
        .data = @embedFile("testdata/writer-big.tar"),
        .files = &[_]Case.File{
            .{
                .name = "tmp/16gig.txt",
                .size = 16 * 1024 * 1024 * 1024,
                .truncated = true,
                .mode = 0o640,
            },
        },
    },
    .{
        // Size in gnu extended format, and name in pax attribute.
        .data = @embedFile("testdata/writer-big-long.tar"),
        .files = &[_]Case.File{
            .{
                .name = "longname/" ** 15 ++ "16gig.txt",
                .size = 16 * 1024 * 1024 * 1024,
                .mode = 0o644,
                .truncated = true,
            },
        },
    },
    .{
        .data = @embedFile("testdata/fuzz1.tar"),
        .err = error.TarInsufficientBuffer,
    },
    .{
        .data = @embedFile("testdata/fuzz2.tar"),
        .err = error.PaxSizeAttrOverflow,
    },
};

// used in test to calculate file chksum
const Md5Writer = struct {
    h: std.crypto.hash.Md5 = std.crypto.hash.Md5.init(.{}),

    pub fn writeAll(self: *Md5Writer, buf: []const u8) !void {
        self.h.update(buf);
    }

    pub fn writeByte(self: *Md5Writer, byte: u8) !void {
        self.h.update(&[_]u8{byte});
    }

    pub fn chksum(self: *Md5Writer) [32]u8 {
        var s = [_]u8{0} ** 16;
        self.h.final(&s);
        return std.fmt.bytesToHex(s, .lower);
    }
};

test "run test cases" {
    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;

    for (cases) |case| {
        var fsb = std.io.fixedBufferStream(case.data);
        var iter = tar.iterator(fsb.reader(), .{
            .file_name_buffer = &file_name_buffer,
            .link_name_buffer = &link_name_buffer,
        });
        var i: usize = 0;
        while (iter.next() catch |err| {
            if (case.err) |e| {
                try testing.expectEqual(e, err);
                continue;
            } else {
                return err;
            }
        }) |actual| : (i += 1) {
            const expected = case.files[i];
            try testing.expectEqualStrings(expected.name, actual.name);
            try testing.expectEqual(expected.size, actual.size);
            try testing.expectEqual(expected.kind, actual.kind);
            try testing.expectEqual(expected.mode, actual.mode);
            try testing.expectEqualStrings(expected.link_name, actual.link_name);

            if (case.chksums.len > i) {
                var md5writer = Md5Writer{};
                try actual.writeAll(&md5writer);
                const chksum = md5writer.chksum();
                try testing.expectEqualStrings(case.chksums[i], &chksum);
            } else {
                if (expected.truncated) {
                    iter.unread_file_bytes = 0;
                }
            }
        }
        try testing.expectEqual(case.files.len, i);
    }
}

test "pax/gnu long names with small buffer" {
    // should fail with insufficient buffer error

    var min_file_name_buffer: [256]u8 = undefined;
    var min_link_name_buffer: [100]u8 = undefined;
    const long_name_cases = [_]Case{ cases[11], cases[25], cases[28] };

    for (long_name_cases) |case| {
        var fsb = std.io.fixedBufferStream(case.data);
        var iter = tar.iterator(fsb.reader(), .{
            .file_name_buffer = &min_file_name_buffer,
            .link_name_buffer = &min_link_name_buffer,
        });

        var iter_err: ?anyerror = null;
        while (iter.next() catch |err| brk: {
            iter_err = err;
            break :brk null;
        }) |_| {}

        try testing.expect(iter_err != null);
        try testing.expectEqual(error.TarInsufficientBuffer, iter_err.?);
    }
}

test "insufficient buffer in Header name filed" {
    var min_file_name_buffer: [9]u8 = undefined;
    var min_link_name_buffer: [100]u8 = undefined;

    var fsb = std.io.fixedBufferStream(cases[0].data);
    var iter = tar.iterator(fsb.reader(), .{
        .file_name_buffer = &min_file_name_buffer,
        .link_name_buffer = &min_link_name_buffer,
    });

    var iter_err: ?anyerror = null;
    while (iter.next() catch |err| brk: {
        iter_err = err;
        break :brk null;
    }) |_| {}

    try testing.expect(iter_err != null);
    try testing.expectEqual(error.TarInsufficientBuffer, iter_err.?);
}

test "should not overwrite existing file" {
    // Starting from this folder structure:
    // $ tree root
    //    root
    //    ├── a
    //    │   └── b
    //    │       └── c
    //    │           └── file.txt
    //    └── d
    //        └── b
    //            └── c
    //                └── file.txt
    //
    // Packed with command:
    // $ cd root; tar cf overwrite_file.tar *
    // Resulting tar has following structure:
    // $ tar tvf overwrite_file.tar
    //  size path
    //  0    a/
    //  0    a/b/
    //  0    a/b/c/
    //  2    a/b/c/file.txt
    //  0    d/
    //  0    d/b/
    //  0    d/b/c/
    //  2    d/b/c/file.txt
    //
    // Note that there is no root folder in archive.
    //
    // With strip_components = 1 resulting unpacked folder was:
    //  root
    //     └── b
    //         └── c
    //             └── file.txt
    //
    // a/b/c/file.txt is overwritten with d/b/c/file.txt !!!
    // This ensures that file is not overwritten.
    //
    const data = @embedFile("testdata/overwrite_file.tar");
    var fsb = std.io.fixedBufferStream(data);

    // Unpack with strip_components = 1 should fail
    var root = std.testing.tmpDir(.{});
    defer root.cleanup();
    try testing.expectError(
        error.PathAlreadyExists,
        tar.pipeToFileSystem(root.dir, fsb.reader(), .{ .mode_mode = .ignore, .strip_components = 1 }),
    );

    // Unpack with strip_components = 0 should pass
    fsb.reset();
    var root2 = std.testing.tmpDir(.{});
    defer root2.cleanup();
    try tar.pipeToFileSystem(root2.dir, fsb.reader(), .{ .mode_mode = .ignore, .strip_components = 0 });
}

test "case sensitivity" {
    // Mimicking issue #18089, this tar contains, same file name in two case
    // sensitive name version. Should fail on case insensitive file systems.
    //
    // $ tar tvf 18089.tar
    //     18089/
    //     18089/alacritty/
    //     18089/alacritty/darkermatrix.yml
    //     18089/alacritty/Darkermatrix.yml
    //
    const data = @embedFile("testdata/18089.tar");
    var fsb = std.io.fixedBufferStream(data);

    var root = std.testing.tmpDir(.{});
    defer root.cleanup();

    tar.pipeToFileSystem(root.dir, fsb.reader(), .{ .mode_mode = .ignore, .strip_components = 1 }) catch |err| {
        // on case insensitive fs we fail on overwrite existing file
        try testing.expectEqual(error.PathAlreadyExists, err);
        return;
    };

    // on case sensitive os both files are created
    try testing.expect((try root.dir.statFile("alacritty/darkermatrix.yml")).kind == .file);
    try testing.expect((try root.dir.statFile("alacritty/Darkermatrix.yml")).kind == .file);
}
const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

/// Creates tar Writer which will write tar content to the `underlying_writer`.
/// Use setRoot to nest all following entries under single root. If file don't
/// fit into posix header (name+prefix: 100+155 bytes) gnu extented header will
/// be used for long names. Options enables setting file premission mode and
/// mtime. Default is to use current time for mtime and 0o664 for file mode.
pub fn writer(underlying_writer: anytype) Writer(@TypeOf(underlying_writer)) {
    return .{ .underlying_writer = underlying_writer };
}

pub fn Writer(comptime WriterType: type) type {
    return struct {
        const block_size = @sizeOf(Header);
        const empty_block: [block_size]u8 = [_]u8{0} ** block_size;

        /// Options for writing file/dir/link. If left empty 0o664 is used for
        /// file mode and current time for mtime.
        pub const Options = struct {
            /// File system permission mode.
            mode: u32 = 0,
            /// File system modification time.
            mtime: u64 = 0,
        };
        const Self = @This();

        underlying_writer: WriterType,
        prefix: []const u8 = "",
        mtime_now: u64 = 0,

        /// Sets prefix for all other write* method paths.
        pub fn setRoot(self: *Self, root: []const u8) !void {
            if (root.len > 0)
                try self.writeDir(root, .{});

            self.prefix = root;
        }

        /// Writes directory.
        pub fn writeDir(self: *Self, sub_path: []const u8, opt: Options) !void {
            try self.writeHeader(.directory, sub_path, "", 0, opt);
        }

        /// Writes file system file.
        pub fn writeFile(self: *Self, sub_path: []const u8, file: std.fs.File) !void {
            const stat = try file.stat();
            const mtime: u64 = @intCast(@divFloor(stat.mtime, std.time.ns_per_s));

            var header = Header{};
            try self.setPath(&header, sub_path);
            try header.setSize(stat.size);
            try header.setMtime(mtime);
            try header.write(self.underlying_writer);

            try self.underlying_writer.writeFile(file);
            try self.writePadding(stat.size);
        }

        /// Writes file reading file content from `reader`. Number of bytes in
        /// reader must be equal to `size`.
        pub fn writeFileStream(self: *Self, sub_path: []const u8, size: usize, reader: anytype, opt: Options) !void {
            try self.writeHeader(.regular, sub_path, "", @intCast(size), opt);

            var counting_reader = std.io.countingReader(reader);
            var fifo = std.fifo.LinearFifo(u8, .{ .Static = 4096 }).init();
            try fifo.pump(counting_reader.reader(), self.underlying_writer);
            if (counting_reader.bytes_read != size) return error.WrongReaderSize;
            try self.writePadding(size);
        }

        /// Writes file using bytes buffer `content` for size and file content.
        pub fn writeFileBytes(self: *Self, sub_path: []const u8, content: []const u8, opt: Options) !void {
            try self.writeHeader(.regular, sub_path, "", @intCast(content.len), opt);
            try self.underlying_writer.writeAll(content);
            try self.writePadding(content.len);
        }

        /// Writes symlink.
        pub fn writeLink(self: *Self, sub_path: []const u8, link_name: []const u8, opt: Options) !void {
            try self.writeHeader(.symbolic_link, sub_path, link_name, 0, opt);
        }

        /// Writes fs.Dir.WalkerEntry. Uses `mtime` from file system entry and
        /// default for entry mode .
        pub fn writeEntry(self: *Self, entry: std.fs.Dir.Walker.Entry) !void {
            switch (entry.kind) {
                .directory => {
                    try self.writeDir(entry.path, .{ .mtime = try entryMtime(entry) });
                },
                .file => {
                    var file = try entry.dir.openFile(entry.basename, .{});
                    defer file.close();
                    try self.writeFile(entry.path, file);
                },
                .sym_link => {
                    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
                    const link_name = try entry.dir.readLink(entry.basename, &link_name_buffer);
                    try self.writeLink(entry.path, link_name, .{ .mtime = try entryMtime(entry) });
                },
                else => {
                    return error.UnsupportedWalkerEntryKind;
                },
            }
        }

        fn writeHeader(
            self: *Self,
            typeflag: Header.FileType,
            sub_path: []const u8,
            link_name: []const u8,
            size: u64,
            opt: Options,
        ) !void {
            var header = Header.init(typeflag);
            try self.setPath(&header, sub_path);
            try header.setSize(size);
            try header.setMtime(if (opt.mtime != 0) opt.mtime else self.mtimeNow());
            if (opt.mode != 0)
                try header.setMode(opt.mode);
            if (typeflag == .symbolic_link)
                header.setLinkname(link_name) catch |err| switch (err) {
                    error.NameTooLong => try self.writeExtendedHeader(.gnu_long_link, &.{link_name}),
                    else => return err,
                };
            try header.write(self.underlying_writer);
        }

        fn mtimeNow(self: *Self) u64 {
            if (self.mtime_now == 0)
                self.mtime_now = @intCast(std.time.timestamp());
            return self.mtime_now;
        }

        fn entryMtime(entry: std.fs.Dir.Walker.Entry) !u64 {
            const stat = try entry.dir.statFile(entry.basename);
            return @intCast(@divFloor(stat.mtime, std.time.ns_per_s));
        }

        /// Writes path in posix header, if don't fit (in name+prefix; 100+155
        /// bytes) writes it in gnu extended header.
        fn setPath(self: *Self, header: *Header, sub_path: []const u8) !void {
            header.setPath(self.prefix, sub_path) catch |err| switch (err) {
                error.NameTooLong => {
                    // write extended header
                    const buffers: []const []const u8 = if (self.prefix.len == 0)
                        &.{sub_path}
                    else
                        &.{ self.prefix, "/", sub_path };
                    try self.writeExtendedHeader(.gnu_long_name, buffers);
                },
                else => return err,
            };
        }

        /// Writes gnu extended header: gnu_long_name or gnu_long_link.
        fn writeExtendedHeader(self: *Self, typeflag: Header.FileType, buffers: []const []const u8) !void {
            var len: usize = 0;
            for (buffers) |buf|
                len += buf.len;

            var header = Header.init(typeflag);
            try header.setSize(len);
            try header.write(self.underlying_writer);
            for (buffers) |buf|
                try self.underlying_writer.writeAll(buf);
            try self.writePadding(len);
        }

        fn writePadding(self: *Self, bytes: u64) !void {
            const pos: usize = @intCast(bytes % block_size);
            if (pos == 0) return;
            try self.underlying_writer.writeAll(empty_block[pos..]);
        }

        /// Tar should finish with two zero blocks, but 'reasonable system must
        /// not assume that such a block exists when reading an archive' (from
        /// reference). In practice it is safe to skip this finish.
        pub fn finish(self: *Self) !void {
            try self.underlying_writer.writeAll(&empty_block);
            try self.underlying_writer.writeAll(&empty_block);
        }
    };
}

/// A struct that is exactly 512 bytes and matches tar file format. This is
/// intended to be used for outputting tar files; for parsing there is
/// `std.tar.Header`.
const Header = extern struct {
    // This struct was originally copied from
    // https://github.com/mattnite/tar/blob/main/src/main.zig which is MIT
    // licensed.
    //
    // The name, linkname, magic, uname, and gname are null-terminated character
    // strings. All other fields are zero-filled octal numbers in ASCII. Each
    // numeric field of width w contains w minus 1 digits, and a null.
    // Reference: https://www.gnu.org/software/tar/manual/html_node/Standard.html
    // POSIX header:                                  byte offset
    name: [100]u8 = [_]u8{0} ** 100, //                         0
    mode: [7:0]u8 = default_mode.file, //                     100
    uid: [7:0]u8 = [_:0]u8{0} ** 7, // unused                 108
    gid: [7:0]u8 = [_:0]u8{0} ** 7, // unused                 116
    size: [11:0]u8 = [_:0]u8{'0'} ** 11, //                   124
    mtime: [11:0]u8 = [_:0]u8{'0'} ** 11, //                  136
    checksum: [7:0]u8 = [_:0]u8{' '} ** 7, //                 148
    typeflag: FileType = .regular, //                         156
    linkname: [100]u8 = [_]u8{0} ** 100, //                   157
    magic: [6]u8 = [_]u8{ 'u', 's', 't', 'a', 'r', 0 }, //    257
    version: [2]u8 = [_]u8{ '0', '0' }, //                    263
    uname: [32]u8 = [_]u8{0} ** 32, // unused                 265
    gname: [32]u8 = [_]u8{0} ** 32, // unused                 297
    devmajor: [7:0]u8 = [_:0]u8{0} ** 7, // unused            329
    devminor: [7:0]u8 = [_:0]u8{0} ** 7, // unused            337
    prefix: [155]u8 = [_]u8{0} ** 155, //                     345
    pad: [12]u8 = [_]u8{0} ** 12, // unused                   500

    pub const FileType = enum(u8) {
        regular = '0',
        symbolic_link = '2',
        directory = '5',
        gnu_long_name = 'L',
        gnu_long_link = 'K',
    };

    const default_mode = struct {
        const file = [_:0]u8{ '0', '0', '0', '0', '6', '6', '4' }; // 0o664
        const dir = [_:0]u8{ '0', '0', '0', '0', '7', '7', '5' }; // 0o775
        const sym_link = [_:0]u8{ '0', '0', '0', '0', '7', '7', '7' }; // 0o777
        const other = [_:0]u8{ '0', '0', '0', '0', '0', '0', '0' }; // 0o000
    };

    pub fn init(typeflag: FileType) Header {
        return .{
            .typeflag = typeflag,
            .mode = switch (typeflag) {
                .directory => default_mode.dir,
                .symbolic_link => default_mode.sym_link,
                .regular => default_mode.file,
                else => default_mode.other,
            },
        };
    }

    pub fn setSize(self: *Header, size: u64) !void {
        try octal(&self.size, size);
    }

    fn octal(buf: []u8, value: u64) !void {
        var remainder: u64 = value;
        var pos: usize = buf.len;
        while (remainder > 0 and pos > 0) {
            pos -= 1;
            const c: u8 = @as(u8, @intCast(remainder % 8)) + '0';
            buf[pos] = c;
            remainder /= 8;
            if (pos == 0 and remainder > 0) return error.OctalOverflow;
        }
    }

    pub fn setMode(self: *Header, mode: u32) !void {
        try octal(&self.mode, mode);
    }

    // Integer number of seconds since January 1, 1970, 00:00 Coordinated Universal Time.
    // mtime == 0 will use current time
    pub fn setMtime(self: *Header, mtime: u64) !void {
        try octal(&self.mtime, mtime);
    }

    pub fn updateChecksum(self: *Header) !void {
        var checksum: usize = ' '; // other 7 self.checksum bytes are initialized to ' '
        for (std.mem.asBytes(self)) |val|
            checksum += val;
        try octal(&self.checksum, checksum);
    }

    pub fn write(self: *Header, output_writer: anytype) !void {
        try self.updateChecksum();
        try output_writer.writeAll(std.mem.asBytes(self));
    }

    pub fn setLinkname(self: *Header, link: []const u8) !void {
        if (link.len > self.linkname.len) return error.NameTooLong;
        @memcpy(self.linkname[0..link.len], link);
    }

    pub fn setPath(self: *Header, prefix: []const u8, sub_path: []const u8) !void {
        const max_prefix = self.prefix.len;
        const max_name = self.name.len;
        const sep = std.fs.path.sep_posix;

        if (prefix.len + sub_path.len > max_name + max_prefix or prefix.len > max_prefix)
            return error.NameTooLong;

        // both fit into name
        if (prefix.len > 0 and prefix.len + sub_path.len < max_name) {
            @memcpy(self.name[0..prefix.len], prefix);
            self.name[prefix.len] = sep;
            @memcpy(self.name[prefix.len + 1 ..][0..sub_path.len], sub_path);
            return;
        }

        // sub_path fits into name
        // there is no prefix or prefix fits into prefix
        if (sub_path.len <= max_name) {
            @memcpy(self.name[0..sub_path.len], sub_path);
            @memcpy(self.prefix[0..prefix.len], prefix);
            return;
        }

        if (prefix.len > 0) {
            @memcpy(self.prefix[0..prefix.len], prefix);
            self.prefix[prefix.len] = sep;
        }
        const prefix_pos = if (prefix.len > 0) prefix.len + 1 else 0;

        // add as much to prefix as you can, must split at /
        const prefix_remaining = max_prefix - prefix_pos;
        if (std.mem.lastIndexOf(u8, sub_path[0..@min(prefix_remaining, sub_path.len)], &.{'/'})) |sep_pos| {
            @memcpy(self.prefix[prefix_pos..][0..sep_pos], sub_path[0..sep_pos]);
            if ((sub_path.len - sep_pos - 1) > max_name) return error.NameTooLong;
            @memcpy(self.name[0..][0 .. sub_path.len - sep_pos - 1], sub_path[sep_pos + 1 ..]);
            return;
        }

        return error.NameTooLong;
    }

    comptime {
        assert(@sizeOf(Header) == 512);
    }

    test setPath {
        const cases = [_]struct {
            in: []const []const u8,
            out: []const []const u8,
        }{
            .{
                .in = &.{ "", "123456789" },
                .out = &.{ "", "123456789" },
            },
            // can fit into name
            .{
                .in = &.{ "prefix", "sub_path" },
                .out = &.{ "", "prefix/sub_path" },
            },
            // no more both fits into name
            .{
                .in = &.{ "prefix", "0123456789/" ** 8 ++ "basename" },
                .out = &.{ "prefix", "0123456789/" ** 8 ++ "basename" },
            },
            // put as much as you can into prefix the rest goes into name
            .{
                .in = &.{ "prefix", "0123456789/" ** 10 ++ "basename" },
                .out = &.{ "prefix/" ++ "0123456789/" ** 9 ++ "0123456789", "basename" },
            },

            .{
                .in = &.{ "prefix", "0123456789/" ** 15 ++ "basename" },
                .out = &.{ "prefix/" ++ "0123456789/" ** 12 ++ "0123456789", "0123456789/0123456789/basename" },
            },
            .{
                .in = &.{ "prefix", "0123456789/" ** 21 ++ "basename" },
                .out = &.{ "prefix/" ++ "0123456789/" ** 12 ++ "0123456789", "0123456789/" ** 8 ++ "basename" },
            },
            .{
                .in = &.{ "", "012345678/" ** 10 ++ "foo" },
                .out = &.{ "012345678/" ** 9 ++ "012345678", "foo" },
            },
        };

        for (cases) |case| {
            var header = Header.init(.regular);
            try header.setPath(case.in[0], case.in[1]);
            try testing.expectEqualStrings(case.out[0], str(&header.prefix));
            try testing.expectEqualStrings(case.out[1], str(&header.name));
        }

        const error_cases = [_]struct {
            in: []const []const u8,
        }{
            // basename can't fit into name (106 characters)
            .{ .in = &.{ "zig", "test/cases/compile_errors/regression_test_2980_base_type_u32_is_not_type_checked_properly_when_assigning_a_value_within_a_struct.zig" } },
            // cant fit into 255 + sep
            .{ .in = &.{ "prefix", "0123456789/" ** 22 ++ "basename" } },
            // can fit but sub_path can't be split (there is no separator)
            .{ .in = &.{ "prefix", "0123456789" ** 10 ++ "a" } },
            .{ .in = &.{ "prefix", "0123456789" ** 14 ++ "basename" } },
        };

        for (error_cases) |case| {
            var header = Header.init(.regular);
            try testing.expectError(
                error.NameTooLong,
                header.setPath(case.in[0], case.in[1]),
            );
        }
    }

    // Breaks string on first null character.
    fn str(s: []const u8) []const u8 {
        for (s, 0..) |c, i| {
            if (c == 0) return s[0..i];
        }
        return s;
    }
};

test {
    _ = Header;
}

test "write files" {
    const files = [_]struct {
        path: []const u8,
        content: []const u8,
    }{
        .{ .path = "foo", .content = "bar" },
        .{ .path = "a12345678/" ** 10 ++ "foo", .content = "a" ** 511 },
        .{ .path = "b12345678/" ** 24 ++ "foo", .content = "b" ** 512 },
        .{ .path = "c12345678/" ** 25 ++ "foo", .content = "c" ** 513 },
        .{ .path = "d12345678/" ** 51 ++ "foo", .content = "d" ** 1025 },
        .{ .path = "e123456789" ** 11, .content = "e" },
    };

    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;

    // with root
    {
        const root = "root";

        var output = std.ArrayList(u8).init(testing.allocator);
        defer output.deinit();
        var wrt = writer(output.writer());
        try wrt.setRoot(root);
        for (files) |file|
            try wrt.writeFileBytes(file.path, file.content, .{});

        var input = std.io.fixedBufferStream(output.items);
        var iter = std.tar.iterator(
            input.reader(),
            .{ .file_name_buffer = &file_name_buffer, .link_name_buffer = &link_name_buffer },
        );

        // first entry is directory with prefix
        {
            const actual = (try iter.next()).?;
            try testing.expectEqualStrings(root, actual.name);
            try testing.expectEqual(std.tar.FileKind.directory, actual.kind);
        }

        var i: usize = 0;
        while (try iter.next()) |actual| {
            defer i += 1;
            const expected = files[i];
            try testing.expectEqualStrings(root, actual.name[0..root.len]);
            try testing.expectEqual('/', actual.name[root.len..][0]);
            try testing.expectEqualStrings(expected.path, actual.name[root.len + 1 ..]);

            var content = std.ArrayList(u8).init(testing.allocator);
            defer content.deinit();
            try actual.writeAll(content.writer());
            try testing.expectEqualSlices(u8, expected.content, content.items);
        }
    }
    // without root
    {
        var output = std.ArrayList(u8).init(testing.allocator);
        defer output.deinit();
        var wrt = writer(output.writer());
        for (files) |file| {
            var content = std.io.fixedBufferStream(file.content);
            try wrt.writeFileStream(file.path, file.content.len, content.reader(), .{});
        }

        var input = std.io.fixedBufferStream(output.items);
        var iter = std.tar.iterator(
            input.reader(),
            .{ .file_name_buffer = &file_name_buffer, .link_name_buffer = &link_name_buffer },
        );

        var i: usize = 0;
        while (try iter.next()) |actual| {
            defer i += 1;
            const expected = files[i];
            try testing.expectEqualStrings(expected.path, actual.name);

            var content = std.ArrayList(u8).init(testing.allocator);
            defer content.deinit();
            try actual.writeAll(content.writer());
            try testing.expectEqualSlices(u8, expected.content, content.items);
        }
        try wrt.finish();
    }
}
//! All the details about the machine that will be executing code.
//! Unlike `Query` which might leave some things as "default" or "host", this
//! data is fully resolved into a concrete set of OS versions, CPU features,
//! etc.

cpu: Cpu,
os: Os,
abi: Abi,
ofmt: ObjectFormat,
dynamic_linker: DynamicLinker = DynamicLinker.none,

pub const Query = @import("Target/Query.zig");

pub const Os = struct {
    tag: Tag,
    version_range: VersionRange,

    pub const Tag = enum {
        freestanding,
        other,

        contiki,
        fuchsia,
        hermit,

        aix,
        haiku,
        hurd,
        linux,
        plan9,
        rtems,
        serenity,
        zos,

        dragonfly,
        freebsd,
        netbsd,
        openbsd,

        driverkit,
        ios,
        macos,
        tvos,
        visionos,
        watchos,

        illumos,
        solaris,

        windows,
        uefi,

        ps3,
        ps4,
        ps5,

        emscripten,
        wasi,

        amdhsa,
        amdpal,
        cuda,
        mesa3d,
        nvcl,
        opencl,
        opengl,
        vulkan,

        // LLVM tags deliberately omitted:
        // - bridgeos
        // - darwin
        // - kfreebsd
        // - nacl
        // - shadermodel

        pub inline fn isDarwin(tag: Tag) bool {
            return switch (tag) {
                .driverkit,
                .ios,
                .macos,
                .tvos,
                .visionos,
                .watchos,
                => true,
                else => false,
            };
        }

        pub inline fn isBSD(tag: Tag) bool {
            return tag.isDarwin() or switch (tag) {
                .freebsd, .openbsd, .netbsd, .dragonfly => true,
                else => false,
            };
        }

        pub inline fn isSolarish(tag: Tag) bool {
            return tag == .solaris or tag == .illumos;
        }

        pub fn exeFileExt(tag: Tag, arch: Cpu.Arch) [:0]const u8 {
            return switch (tag) {
                .windows => ".exe",
                .uefi => ".efi",
                .plan9 => arch.plan9Ext(),
                else => switch (arch) {
                    .wasm32, .wasm64 => ".wasm",
                    else => "",
                },
            };
        }

        pub fn staticLibSuffix(tag: Tag, abi: Abi) [:0]const u8 {
            return switch (abi) {
                .msvc, .itanium => ".lib",
                else => switch (tag) {
                    .windows, .uefi => ".lib",
                    else => ".a",
                },
            };
        }

        pub fn dynamicLibSuffix(tag: Tag) [:0]const u8 {
            return switch (tag) {
                .windows, .uefi => ".dll",
                .driverkit,
                .ios,
                .macos,
                .tvos,
                .visionos,
                .watchos,
                => ".dylib",
                else => ".so",
            };
        }

        pub fn libPrefix(tag: Os.Tag, abi: Abi) [:0]const u8 {
            return switch (abi) {
                .msvc, .itanium => "",
                else => switch (tag) {
                    .windows, .uefi => "",
                    else => "lib",
                },
            };
        }

        pub fn defaultVersionRange(tag: Tag, arch: Cpu.Arch, abi: Abi) Os {
            return .{
                .tag = tag,
                .version_range = .default(arch, tag, abi),
            };
        }

        pub inline fn versionRangeTag(tag: Tag) @typeInfo(TaggedVersionRange).@"union".tag_type.? {
            return switch (tag) {
                .freestanding,
                .other,

                .haiku,
                .plan9,
                .serenity,

                .illumos,

                .ps3,
                .ps4,
                .ps5,

                .emscripten,

                .mesa3d,
                => .none,

                .contiki,
                .fuchsia,
                .hermit,

                .aix,
                .rtems,
                .zos,

                .dragonfly,
                .freebsd,
                .netbsd,
                .openbsd,

                .driverkit,
                .macos,
                .ios,
                .tvos,
                .visionos,
                .watchos,

                .solaris,

                .uefi,

                .wasi,

                .amdhsa,
                .amdpal,
                .cuda,
                .nvcl,
                .opencl,
                .opengl,
                .vulkan,
                => .semver,

                .hurd => .hurd,
                .linux => .linux,

                .windows => .windows,
            };
        }
    };

    /// Based on NTDDI version constants from
    /// https://docs.microsoft.com/en-us/cpp/porting/modifying-winver-and-win32-winnt
    pub const WindowsVersion = enum(u32) {
        nt4 = 0x04000000,
        win2k = 0x05000000,
        xp = 0x05010000,
        ws2003 = 0x05020000,
        vista = 0x06000000,
        win7 = 0x06010000,
        win8 = 0x06020000,
        win8_1 = 0x06030000,
        win10 = 0x0A000000, //aka win10_th1
        win10_th2 = 0x0A000001,
        win10_rs1 = 0x0A000002,
        win10_rs2 = 0x0A000003,
        win10_rs3 = 0x0A000004,
        win10_rs4 = 0x0A000005,
        win10_rs5 = 0x0A000006,
        win10_19h1 = 0x0A000007,
        win10_vb = 0x0A000008, //aka win10_19h2
        win10_mn = 0x0A000009, //aka win10_20h1
        win10_fe = 0x0A00000A, //aka win10_20h2
        win10_co = 0x0A00000B, //aka win10_21h1
        win10_ni = 0x0A00000C, //aka win10_21h2
        win10_cu = 0x0A00000D, //aka win10_22h2
        win11_zn = 0x0A00000E, //aka win11_21h2
        win11_ga = 0x0A00000F, //aka win11_22h2
        win11_ge = 0x0A000010, //aka win11_23h2
        win11_dt = 0x0A000011, //aka win11_24h2
        _,

        /// Latest Windows version that the Zig Standard Library is aware of
        pub const latest = WindowsVersion.win11_dt;

        /// Compared against build numbers reported by the runtime to distinguish win10 versions,
        /// where 0x0A000000 + index corresponds to the WindowsVersion u32 value.
        pub const known_win10_build_numbers = [_]u32{
            10240, //win10 aka win10_th1
            10586, //win10_th2
            14393, //win10_rs1
            15063, //win10_rs2
            16299, //win10_rs3
            17134, //win10_rs4
            17763, //win10_rs5
            18362, //win10_19h1
            18363, //win10_vb aka win10_19h2
            19041, //win10_mn aka win10_20h1
            19042, //win10_fe aka win10_20h2
            19043, //win10_co aka win10_21h1
            19044, //win10_ni aka win10_21h2
            19045, //win10_cu aka win10_22h2
            22000, //win11_zn aka win11_21h2
            22621, //win11_ga aka win11_22h2
            22631, //win11_ge aka win11_23h2
            26100, //win11_dt aka win11_24h2
        };

        /// Returns whether the first version `ver` is newer (greater) than or equal to the second version `ver`.
        pub inline fn isAtLeast(ver: WindowsVersion, min_ver: WindowsVersion) bool {
            return @intFromEnum(ver) >= @intFromEnum(min_ver);
        }

        pub const Range = struct {
            min: WindowsVersion,
            max: WindowsVersion,

            pub inline fn includesVersion(range: Range, ver: WindowsVersion) bool {
                return @intFromEnum(ver) >= @intFromEnum(range.min) and
                    @intFromEnum(ver) <= @intFromEnum(range.max);
            }

            /// Checks if system is guaranteed to be at least `version` or older than `version`.
            /// Returns `null` if a runtime check is required.
            pub inline fn isAtLeast(range: Range, min_ver: WindowsVersion) ?bool {
                if (@intFromEnum(range.min) >= @intFromEnum(min_ver)) return true;
                if (@intFromEnum(range.max) < @intFromEnum(min_ver)) return false;
                return null;
            }
        };

        pub fn parse(str: []const u8) !WindowsVersion {
            return std.meta.stringToEnum(WindowsVersion, str) orelse
                @enumFromInt(std.fmt.parseInt(u32, str, 0) catch
                    return error.InvalidOperatingSystemVersion);
        }

        /// This function is defined to serialize a Zig source code representation of this
        /// type, that, when parsed, will deserialize into the same data.
        pub fn format(
            ver: WindowsVersion,
            comptime fmt_str: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            const maybe_name = std.enums.tagName(WindowsVersion, ver);
            if (comptime std.mem.eql(u8, fmt_str, "s")) {
                if (maybe_name) |name|
                    try writer.print(".{s}", .{name})
                else
                    try writer.print(".{d}", .{@intFromEnum(ver)});
            } else if (comptime std.mem.eql(u8, fmt_str, "c")) {
                if (maybe_name) |name|
                    try writer.print(".{s}", .{name})
                else
                    try writer.print("@enumFromInt(0x{X:0>8})", .{@intFromEnum(ver)});
            } else if (fmt_str.len == 0) {
                if (maybe_name) |name|
                    try writer.print("WindowsVersion.{s}", .{name})
                else
                    try writer.print("WindowsVersion(0x{X:0>8})", .{@intFromEnum(ver)});
            } else std.fmt.invalidFmtError(fmt_str, ver);
        }
    };

    pub const HurdVersionRange = struct {
        range: std.SemanticVersion.Range,
        glibc: std.SemanticVersion,

        pub inline fn includesVersion(range: HurdVersionRange, ver: std.SemanticVersion) bool {
            return range.range.includesVersion(ver);
        }

        /// Checks if system is guaranteed to be at least `version` or older than `version`.
        /// Returns `null` if a runtime check is required.
        pub inline fn isAtLeast(range: HurdVersionRange, ver: std.SemanticVersion) ?bool {
            return range.range.isAtLeast(ver);
        }
    };

    pub const LinuxVersionRange = struct {
        range: std.SemanticVersion.Range,
        glibc: std.SemanticVersion,
        /// Android API level.
        android: u32,

        pub inline fn includesVersion(range: LinuxVersionRange, ver: std.SemanticVersion) bool {
            return range.range.includesVersion(ver);
        }

        /// Checks if system is guaranteed to be at least `version` or older than `version`.
        /// Returns `null` if a runtime check is required.
        pub inline fn isAtLeast(range: LinuxVersionRange, ver: std.SemanticVersion) ?bool {
            return range.range.isAtLeast(ver);
        }
    };

    /// The version ranges here represent the minimum OS version to be supported
    /// and the maximum OS version to be supported. The default values represent
    /// the range that the Zig Standard Library bases its abstractions on.
    ///
    /// The minimum version of the range is the main setting to tweak for a target.
    /// Usually, the maximum target OS version will remain the default, which is
    /// the latest released version of the OS.
    ///
    /// To test at compile time if the target is guaranteed to support a given OS feature,
    /// one should check that the minimum version of the range is greater than or equal to
    /// the version the feature was introduced in.
    ///
    /// To test at compile time if the target certainly will not support a given OS feature,
    /// one should check that the maximum version of the range is less than the version the
    /// feature was introduced in.
    ///
    /// If neither of these cases apply, a runtime check should be used to determine if the
    /// target supports a given OS feature.
    ///
    /// Binaries built with a given maximum version will continue to function on newer
    /// operating system versions. However, such a binary may not take full advantage of the
    /// newer operating system APIs.
    ///
    /// See `Os.isAtLeast`.
    pub const VersionRange = union {
        none: void,
        semver: std.SemanticVersion.Range,
        hurd: HurdVersionRange,
        linux: LinuxVersionRange,
        windows: WindowsVersion.Range,

        /// The default `VersionRange` represents the range that the Zig Standard Library
        /// bases its abstractions on.
        pub fn default(arch: Cpu.Arch, tag: Tag, abi: Abi) VersionRange {
            return switch (tag) {
                .freestanding,
                .other,

                .haiku,
                .plan9,
                .serenity,

                .illumos,

                .ps3,
                .ps4,
                .ps5,

                .emscripten,

                .mesa3d,
                => .{ .none = {} },

                .contiki => .{
                    .semver = .{
                        .min = .{ .major = 4, .minor = 0, .patch = 0 },
                        .max = .{ .major = 5, .minor = 0, .patch = 0 },
                    },
                },
                .fuchsia => .{
                    .semver = .{
                        .min = .{ .major = 1, .minor = 1, .patch = 0 },
                        .max = .{ .major = 21, .minor = 1, .patch = 0 },
                    },
                },
                .hermit => .{
                    .semver = .{
                        .min = .{ .major = 0, .minor = 4, .patch = 0 },
                        .max = .{ .major = 0, .minor = 10, .patch = 0 },
                    },
                },

                .aix => .{
                    .semver = .{
                        .min = .{ .major = 7, .minor = 2, .patch = 5 },
                        .max = .{ .major = 7, .minor = 3, .patch = 2 },
                    },
                },
                .hurd => .{
                    .hurd = .{
                        .range = .{
                            .min = .{ .major = 0, .minor = 9, .patch = 0 },
                            .max = .{ .major = 0, .minor = 9, .patch = 0 },
                        },
                        .glibc = .{ .major = 2, .minor = 28, .patch = 0 },
                    },
                },
                .linux => .{
                    .linux = .{
                        .range = .{
                            .min = blk: {
                                const default_min: std.SemanticVersion = .{ .major = 5, .minor = 10, .patch = 0 };

                                for (std.zig.target.available_libcs) |libc| {
                                    if (libc.arch != arch or libc.os != tag or libc.abi != abi) continue;

                                    if (libc.os_ver) |min| {
                                        if (min.order(default_min) == .gt) break :blk min;
                                    }
                                }

                                break :blk default_min;
                            },
                            .max = .{ .major = 6, .minor = 13, .patch = 4 },
                        },
                        .glibc = blk: {
                            // For 32-bit targets that traditionally used 32-bit time, we require
                            // glibc 2.34 for full 64-bit time support. For everything else, we only
                            // require glibc 2.31.
                            const default_min: std.SemanticVersion = switch (arch) {
                                .arm,
                                .armeb,
                                .csky,
                                .m68k,
                                .mips,
                                .mipsel,
                                .powerpc,
                                .sparc,
                                .x86,
                                => .{ .major = 2, .minor = 34, .patch = 0 },
                                .mips64,
                                .mips64el,
                                => if (abi == .gnuabin32)
                                    .{ .major = 2, .minor = 34, .patch = 0 }
                                else
                                    .{ .major = 2, .minor = 31, .patch = 0 },
                                else => .{ .major = 2, .minor = 31, .patch = 0 },
                            };

                            for (std.zig.target.available_libcs) |libc| {
                                if (libc.os != tag or libc.arch != arch or libc.abi != abi) continue;

                                if (libc.glibc_min) |min| {
                                    if (min.order(default_min) == .gt) break :blk min;
                                }
                            }

                            break :blk default_min;
                        },
                        .android = 24,
                    },
                },
                .rtems => .{
                    .semver = .{
                        .min = .{ .major = 5, .minor = 1, .patch = 0 },
                        .max = .{ .major = 6, .minor = 1, .patch = 0 },
                    },
                },
                .zos => .{
                    .semver = .{
                        .min = .{ .major = 2, .minor = 5, .patch = 0 },
                        .max = .{ .major = 3, .minor = 1, .patch = 0 },
                    },
                },

                .dragonfly => .{
                    .semver = .{
                        .min = .{ .major = 6, .minor = 0, .patch = 0 },
                        .max = .{ .major = 6, .minor = 4, .patch = 0 },
                    },
                },
                .freebsd => .{
                    .semver = .{
                        .min = .{ .major = 13, .minor = 4, .patch = 0 },
                        .max = .{ .major = 14, .minor = 2, .patch = 0 },
                    },
                },
                .netbsd => .{
                    .semver = .{
                        .min = .{ .major = 9, .minor = 4, .patch = 0 },
                        .max = .{ .major = 10, .minor = 1, .patch = 0 },
                    },
                },
                .openbsd => .{
                    .semver = .{
                        .min = .{ .major = 7, .minor = 5, .patch = 0 },
                        .max = .{ .major = 7, .minor = 6, .patch = 0 },
                    },
                },

                .driverkit => .{
                    .semver = .{
                        .min = .{ .major = 19, .minor = 0, .patch = 0 },
                        .max = .{ .major = 24, .minor = 2, .patch = 0 },
                    },
                },
                .macos => .{
                    .semver = .{
                        .min = .{ .major = 13, .minor = 0, .patch = 0 },
                        .max = .{ .major = 15, .minor = 3, .patch = 1 },
                    },
                },
                .ios => .{
                    .semver = .{
                        .min = .{ .major = 12, .minor = 0, .patch = 0 },
                        .max = .{ .major = 18, .minor = 3, .patch = 1 },
                    },
                },
                .tvos => .{
                    .semver = .{
                        .min = .{ .major = 13, .minor = 0, .patch = 0 },
                        .max = .{ .major = 18, .minor = 3, .patch = 0 },
                    },
                },
                .visionos => .{
                    .semver = .{
                        .min = .{ .major = 1, .minor = 0, .patch = 0 },
                        .max = .{ .major = 2, .minor = 3, .patch = 1 },
                    },
                },
                .watchos => .{
                    .semver = .{
                        .min = .{ .major = 6, .minor = 0, .patch = 0 },
                        .max = .{ .major = 11, .minor = 3, .patch = 1 },
                    },
                },

                .solaris => .{
                    .semver = .{
                        .min = .{ .major = 11, .minor = 0, .patch = 0 },
                        .max = .{ .major = 11, .minor = 4, .patch = 0 },
                    },
                },

                .windows => .{
                    .windows = .{
                        .min = .win10,
                        .max = WindowsVersion.latest,
                    },
                },
                .uefi => .{
                    .semver = .{
                        .min = .{ .major = 2, .minor = 0, .patch = 0 },
                        .max = .{ .major = 2, .minor = 11, .patch = 0 },
                    },
                },

                .wasi => .{
                    .semver = .{
                        .min = .{ .major = 0, .minor = 1, .patch = 0 },
                        .max = .{ .major = 0, .minor = 2, .patch = 2 },
                    },
                },

                .amdhsa => .{
                    .semver = .{
                        .min = .{ .major = 5, .minor = 0, .patch = 2 },
                        .max = .{ .major = 6, .minor = 3, .patch = 0 },
                    },
                },
                .amdpal => .{
                    .semver = .{
                        .min = .{ .major = 1, .minor = 1, .patch = 0 },
                        .max = .{ .major = 3, .minor = 5, .patch = 0 },
                    },
                },
                .cuda => .{
                    .semver = .{
                        .min = .{ .major = 11, .minor = 0, .patch = 1 },
                        .max = .{ .major = 12, .minor = 8, .patch = 0 },
                    },
                },
                .nvcl,
                .opencl,
                => .{
                    .semver = .{
                        .min = .{ .major = 2, .minor = 2, .patch = 0 },
                        .max = .{ .major = 3, .minor = 0, .patch = 17 },
                    },
                },
                .opengl => .{
                    .semver = .{
                        .min = .{ .major = 4, .minor = 5, .patch = 0 },
                        .max = .{ .major = 4, .minor = 6, .patch = 0 },
                    },
                },
                .vulkan => .{
                    .semver = .{
                        .min = .{ .major = 1, .minor = 2, .patch = 0 },
                        .max = .{ .major = 1, .minor = 4, .patch = 309 },
                    },
                },
            };
        }
    };

    pub const TaggedVersionRange = union(enum) {
        none: void,
        semver: std.SemanticVersion.Range,
        hurd: HurdVersionRange,
        linux: LinuxVersionRange,
        windows: WindowsVersion.Range,

        pub fn gnuLibCVersion(range: TaggedVersionRange) ?std.SemanticVersion {
            return switch (range) {
                .none, .semver, .windows => null,
                .hurd => |h| h.glibc,
                .linux => |l| l.glibc,
            };
        }
    };

    /// Provides a tagged union. `Target` does not store the tag because it is
    /// redundant with the OS tag; this function abstracts that part away.
    pub inline fn versionRange(os: Os) TaggedVersionRange {
        return switch (os.tag.versionRangeTag()) {
            .none => .{ .none = {} },
            .semver => .{ .semver = os.version_range.semver },
            .hurd => .{ .hurd = os.version_range.hurd },
            .linux => .{ .linux = os.version_range.linux },
            .windows => .{ .windows = os.version_range.windows },
        };
    }

    /// Checks if system is guaranteed to be at least `version` or older than `version`.
    /// Returns `null` if a runtime check is required.
    pub inline fn isAtLeast(os: Os, comptime tag: Tag, ver: switch (tag.versionRangeTag()) {
        .none => void,
        .semver, .hurd, .linux => std.SemanticVersion,
        .windows => WindowsVersion,
    }) ?bool {
        return if (os.tag != tag) false else switch (tag.versionRangeTag()) {
            .none => true,
            inline .semver,
            .hurd,
            .linux,
            .windows,
            => |field| @field(os.version_range, @tagName(field)).isAtLeast(ver),
        };
    }

    /// On Darwin, we always link libSystem which contains libc.
    /// Similarly on FreeBSD and NetBSD we always link system libc
    /// since this is the stable syscall interface.
    pub fn requiresLibC(os: Os) bool {
        return switch (os.tag) {
            .freebsd,
            .aix,
            .netbsd,
            .driverkit,
            .macos,
            .ios,
            .tvos,
            .watchos,
            .visionos,
            .dragonfly,
            .openbsd,
            .haiku,
            .solaris,
            .illumos,
            .serenity,
            => true,

            .linux,
            .windows,
            .freestanding,
            .fuchsia,
            .ps3,
            .zos,
            .rtems,
            .cuda,
            .nvcl,
            .amdhsa,
            .ps4,
            .ps5,
            .mesa3d,
            .contiki,
            .amdpal,
            .hermit,
            .hurd,
            .wasi,
            .emscripten,
            .uefi,
            .opencl,
            .opengl,
            .vulkan,
            .plan9,
            .other,
            => false,
        };
    }
};

pub const aarch64 = @import("Target/aarch64.zig");
pub const arc = @import("Target/arc.zig");
pub const amdgcn = @import("Target/amdgcn.zig");
pub const arm = @import("Target/arm.zig");
pub const avr = @import("Target/avr.zig");
pub const bpf = @import("Target/bpf.zig");
pub const csky = @import("Target/csky.zig");
pub const hexagon = @import("Target/hexagon.zig");
pub const lanai = @import("Target/lanai.zig");
pub const loongarch = @import("Target/loongarch.zig");
pub const m68k = @import("Target/m68k.zig");
pub const mips = @import("Target/mips.zig");
pub const msp430 = @import("Target/msp430.zig");
pub const nvptx = @import("Target/nvptx.zig");
pub const powerpc = @import("Target/powerpc.zig");
pub const propeller = @import("Target/propeller.zig");
pub const riscv = @import("Target/riscv.zig");
pub const sparc = @import("Target/sparc.zig");
pub const spirv = @import("Target/spirv.zig");
pub const s390x = @import("Target/s390x.zig");
pub const ve = @import("Target/ve.zig");
pub const wasm = @import("Target/wasm.zig");
pub const x86 = @import("Target/x86.zig");
pub const xcore = @import("Target/xcore.zig");
pub const xtensa = @import("Target/xtensa.zig");

pub const Abi = enum {
    none,
    gnu,
    gnuabin32,
    gnuabi64,
    gnueabi,
    gnueabihf,
    gnuf32,
    gnusf,
    gnux32,
    code16,
    eabi,
    eabihf,
    ilp32,
    android,
    androideabi,
    musl,
    muslabin32,
    muslabi64,
    musleabi,
    musleabihf,
    muslf32,
    muslsf,
    muslx32,
    msvc,
    itanium,
    cygnus,
    simulator,
    macabi,
    ohos,
    ohoseabi,

    // LLVM tags deliberately omitted:
    // - amplification
    // - anyhit
    // - callable
    // - closesthit
    // - compute
    // - coreclr
    // - domain
    // - geometry
    // - gnuf64
    // - hull
    // - intersection
    // - library
    // - mesh
    // - miss
    // - pixel
    // - raygeneration
    // - vertex

    pub fn default(arch: Cpu.Arch, os_tag: Os.Tag) Abi {
        return switch (os_tag) {
            .freestanding, .other => switch (arch) {
                // Soft float is usually a sane default for freestanding.
                .arm,
                .armeb,
                .thumb,
                .thumbeb,
                .csky,
                .mips,
                .mipsel,
                .powerpc,
                .powerpcle,
                => .eabi,
                else => .none,
            },
            .aix => if (arch == .powerpc) .eabihf else .none,
            .haiku => switch (arch) {
                .arm,
                .thumb,
                .powerpc,
                => .eabihf,
                else => .none,
            },
            .hurd => .gnu,
            .linux => switch (arch) {
                .arm,
                .armeb,
                .thumb,
                .thumbeb,
                .powerpc,
                .powerpcle,
                => .musleabihf,
                // Soft float tends to be more common for CSKY and MIPS.
                .csky,
                => .gnueabi, // No musl support.
                .mips,
                .mipsel,
                => .musleabi,
                .mips64,
                .mips64el,
                => .muslabi64,
                else => .musl,
            },
            .rtems => switch (arch) {
                .arm,
                .armeb,
                .thumb,
                .thumbeb,
                .mips,
                .mipsel,
                => .eabi,
                .powerpc,
                => .eabihf,
                else => .none,
            },
            .freebsd => switch (arch) {
                .arm,
                .armeb,
                .thumb,
                .thumbeb,
                .powerpc,
                => .eabihf,
                // Soft float tends to be more common for MIPS.
                .mips,
                .mipsel,
                => .eabi,
                else => .none,
            },
            .netbsd => switch (arch) {
                .arm,
                .armeb,
                .thumb,
                .thumbeb,
                .powerpc,
                => .eabihf,
                // Soft float tends to be more common for MIPS.
                .mips,
                .mipsel,
                => .eabi,
                else => .none,
            },
            .openbsd => switch (arch) {
                .arm,
                .thumb,
                => .eabi,
                .powerpc,
                => .eabihf,
                else => .none,
            },
            .ios => if (arch == .x86_64) .macabi else .none,
            .tvos, .visionos, .watchos => if (arch == .x86_64) .simulator else .none,
            .windows => .gnu,
            .uefi => .msvc,
            .wasi, .emscripten => .musl,

            .contiki,
            .fuchsia,
            .hermit,
            .plan9,
            .serenity,
            .zos,
            .dragonfly,
            .driverkit,
            .macos,
            .illumos,
            .solaris,
            .ps3,
            .ps4,
            .ps5,
            .amdhsa,
            .amdpal,
            .cuda,
            .mesa3d,
            .nvcl,
            .opencl,
            .opengl,
            .vulkan,
            => .none,
        };
    }

    pub inline fn isGnu(abi: Abi) bool {
        return switch (abi) {
            .gnu,
            .gnuabin32,
            .gnuabi64,
            .gnueabi,
            .gnueabihf,
            .gnuf32,
            .gnusf,
            .gnux32,
            => true,
            else => false,
        };
    }

    pub inline fn isMusl(abi: Abi) bool {
        return switch (abi) {
            .musl,
            .muslabin32,
            .muslabi64,
            .musleabi,
            .musleabihf,
            .muslf32,
            .muslsf,
            .muslx32,
            => true,
            else => abi.isOpenHarmony(),
        };
    }

    pub inline fn isOpenHarmony(abi: Abi) bool {
        return switch (abi) {
            .ohos, .ohoseabi => true,
            else => false,
        };
    }

    pub inline fn isAndroid(abi: Abi) bool {
        return switch (abi) {
            .android, .androideabi => true,
            else => false,
        };
    }

    pub const Float = enum {
        hard,
        soft,
    };

    pub inline fn float(abi: Abi) Float {
        return switch (abi) {
            .androideabi,
            .eabi,
            .gnueabi,
            .musleabi,
            .gnusf,
            .ohoseabi,
            => .soft,
            else => .hard,
        };
    }
};

pub const ObjectFormat = enum {
    /// C source code.
    c,
    /// The Common Object File Format used by Windows and UEFI.
    coff,
    /// The Executable and Linkable Format used by many Unixes.
    elf,
    /// The Generalized Object File Format used by z/OS.
    goff,
    /// The Intel HEX format for storing binary code in ASCII text.
    hex,
    /// The Mach object format used by macOS and other Apple platforms.
    macho,
    /// Nvidia's PTX (Parallel Thread Execution) assembly language.
    nvptx,
    /// The a.out format used by Plan 9 from Bell Labs.
    plan9,
    /// Machine code with no metadata.
    raw,
    /// The Khronos Group's Standard Portable Intermediate Representation V.
    spirv,
    /// The WebAssembly binary format.
    wasm,
    /// The eXtended Common Object File Format used by AIX.
    xcoff,

    // LLVM tags deliberately omitted:
    // - dxcontainer

    pub fn fileExt(of: ObjectFormat, arch: Cpu.Arch) [:0]const u8 {
        return switch (of) {
            .c => ".c",
            .coff => ".obj",
            .elf, .goff, .macho, .wasm, .xcoff => ".o",
            .hex => ".ihex",
            .nvptx => ".ptx",
            .plan9 => arch.plan9Ext(),
            .raw => ".bin",
            .spirv => ".spv",
        };
    }

    pub fn default(os_tag: Os.Tag, arch: Cpu.Arch) ObjectFormat {
        return switch (os_tag) {
            .aix => .xcoff,
            .driverkit, .ios, .macos, .tvos, .visionos, .watchos => .macho,
            .plan9 => .plan9,
            .uefi, .windows => .coff,
            .zos => .goff,
            else => switch (arch) {
                .nvptx, .nvptx64 => .nvptx,
                .spirv, .spirv32, .spirv64 => .spirv,
                .wasm32, .wasm64 => .wasm,
                else => .elf,
            },
        };
    }
};

pub fn toElfMachine(target: Target) std.elf.EM {
    return switch (target.cpu.arch) {
        .amdgcn => .AMDGPU,
        .arc => .ARC_COMPACT,
        .arm, .armeb, .thumb, .thumbeb => .ARM,
        .aarch64, .aarch64_be => .AARCH64,
        .avr => .AVR,
        .bpfel, .bpfeb => .BPF,
        .csky => .CSKY,
        .hexagon => .QDSP6,
        .kalimba => .CSR_KALIMBA,
        .lanai => .LANAI,
        .loongarch32, .loongarch64 => .LOONGARCH,
        .m68k => .@"68K",
        .mips, .mips64, .mipsel, .mips64el => .MIPS,
        .msp430 => .MSP430,
        .powerpc, .powerpcle => .PPC,
        .powerpc64, .powerpc64le => .PPC64,
        .propeller => .PROPELLER,
        .riscv32, .riscv64 => .RISCV,
        .s390x => .S390,
        .sparc => if (Target.sparc.featureSetHas(target.cpu.features, .v9)) .SPARC32PLUS else .SPARC,
        .sparc64 => .SPARCV9,
        .ve => .VE,
        .x86 => .@"386",
        .x86_64 => .X86_64,
        .xcore => .XCORE,
        .xtensa => .XTENSA,

        .nvptx,
        .nvptx64,
        .spirv,
        .spirv32,
        .spirv64,
        .wasm32,
        .wasm64,
        => .NONE,
    };
}

pub fn toCoffMachine(target: Target) std.coff.MachineType {
    return switch (target.cpu.arch) {
        .arm => .ARM,
        .thumb => .ARMNT,
        .aarch64 => .ARM64,
        .loongarch32 => .LOONGARCH32,
        .loongarch64 => .LOONGARCH64,
        .riscv32 => .RISCV32,
        .riscv64 => .RISCV64,
        .x86 => .I386,
        .x86_64 => .X64,

        .amdgcn,
        .arc,
        .armeb,
        .thumbeb,
        .aarch64_be,
        .avr,
        .bpfel,
        .bpfeb,
        .csky,
        .hexagon,
        .kalimba,
        .lanai,
        .m68k,
        .mips,
        .mipsel,
        .mips64,
        .mips64el,
        .msp430,
        .nvptx,
        .nvptx64,
        .powerpc,
        .powerpcle,
        .powerpc64,
        .powerpc64le,
        .s390x,
        .sparc,
        .sparc64,
        .spirv,
        .spirv32,
        .spirv64,
        .ve,
        .wasm32,
        .wasm64,
        .xcore,
        .xtensa,
        .propeller,
        => .UNKNOWN,
    };
}

pub const SubSystem = enum {
    Console,
    Windows,
    Posix,
    Native,
    EfiApplication,
    EfiBootServiceDriver,
    EfiRom,
    EfiRuntimeDriver,
};

pub const Cpu = struct {
    /// Architecture
    arch: Arch,

    /// The CPU model to target. It has a set of features
    /// which are overridden with the `features` field.
    model: *const Model,

    /// An explicit list of the entire CPU feature set. It may differ from the specific CPU model's features.
    features: Feature.Set,

    pub const Feature = struct {
        /// The bit index into `Set`. Has a default value of `undefined` because the canonical
        /// structures are populated via comptime logic.
        index: Set.Index = undefined,

        /// Has a default value of `undefined` because the canonical
        /// structures are populated via comptime logic.
        name: []const u8 = undefined,

        /// If this corresponds to an LLVM-recognized feature, this will be populated;
        /// otherwise null.
        llvm_name: ?[:0]const u8,

        /// Human-friendly UTF-8 text.
        description: []const u8,

        /// Sparse `Set` of features this depends on.
        dependencies: Set,

        /// A bit set of all the features.
        pub const Set = struct {
            ints: [usize_count]usize,

            pub const needed_bit_count = 288;
            pub const byte_count = (needed_bit_count + 7) / 8;
            pub const usize_count = (byte_count + (@sizeOf(usize) - 1)) / @sizeOf(usize);
            pub const Index = std.math.Log2Int(std.meta.Int(.unsigned, usize_count * @bitSizeOf(usize)));
            pub const ShiftInt = std.math.Log2Int(usize);

            pub const empty = Set{ .ints = [1]usize{0} ** usize_count };

            pub fn isEmpty(set: Set) bool {
        ```
