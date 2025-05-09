```
es.len),
    });
}

fn lowerAstErrors(zg: *ZonGen) Allocator.Error!void {
    const gpa = zg.gpa;
    const tree = zg.tree;
    assert(tree.errors.len > 0);

    var msg: std.ArrayListUnmanaged(u8) = .empty;
    defer msg.deinit(gpa);

    var notes: std.ArrayListUnmanaged(Zoir.CompileError.Note) = .empty;
    defer notes.deinit(gpa);

    var cur_err = tree.errors[0];
    for (tree.errors[1..]) |err| {
        if (err.is_note) {
            try tree.renderError(err, msg.writer(gpa));
            try notes.append(gpa, try zg.errNoteTok(err.token, "{s}", .{msg.items}));
        } else {
            // Flush error
            try tree.renderError(cur_err, msg.writer(gpa));
            const extra_offset = tree.errorOffset(cur_err);
            try zg.addErrorTokNotesOff(cur_err.token, extra_offset, "{s}", .{msg.items}, notes.items);
            notes.clearRetainingCapacity();
            cur_err = err;

            // TODO: `Parse` currently does not have good error recovery mechanisms, so the remaining errors could be bogus.
            // As such, we'll ignore all remaining errors for now. We should improve `Parse` so that we can report all the errors.
            return;
        }
        msg.clearRetainingCapacity();
    }

    // Flush error
    const extra_offset = tree.errorOffset(cur_err);
    try tree.renderError(cur_err, msg.writer(gpa));
    try zg.addErrorTokNotesOff(cur_err.token, extra_offset, "{s}", .{msg.items}, notes.items);
}

const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const Allocator = mem.Allocator;
const StringIndexAdapter = std.hash_map.StringIndexAdapter;
const StringIndexContext = std.hash_map.StringIndexContext;
const ZonGen = @This();
const Zoir = @import("Zoir.zig");
const Ast = @import("Ast.zig");
//! The .ZIP File Format Specification is found here:
//!    https://pkwaredownloads.blob.core.windows.net/pem/APPNOTE.txt
//!
//! Note that this file uses the abbreviation "cd" for "central directory"

const builtin = @import("builtin");
const std = @import("std");
const testing = std.testing;

pub const testutil = @import("zip/test.zig");
const File = testutil.File;
const FileStore = testutil.FileStore;

pub const CompressionMethod = enum(u16) {
    store = 0,
    deflate = 8,
    _,
};

pub const central_file_header_sig = [4]u8{ 'P', 'K', 1, 2 };
pub const local_file_header_sig = [4]u8{ 'P', 'K', 3, 4 };
pub const end_record_sig = [4]u8{ 'P', 'K', 5, 6 };
pub const end_record64_sig = [4]u8{ 'P', 'K', 6, 6 };
pub const end_locator64_sig = [4]u8{ 'P', 'K', 6, 7 };
pub const ExtraHeader = enum(u16) {
    zip64_info = 0x1,
    _,
};

const GeneralPurposeFlags = packed struct(u16) {
    encrypted: bool,
    _: u15,
};

pub const LocalFileHeader = extern struct {
    signature: [4]u8 align(1),
    version_needed_to_extract: u16 align(1),
    flags: GeneralPurposeFlags align(1),
    compression_method: CompressionMethod align(1),
    last_modification_time: u16 align(1),
    last_modification_date: u16 align(1),
    crc32: u32 align(1),
    compressed_size: u32 align(1),
    uncompressed_size: u32 align(1),
    filename_len: u16 align(1),
    extra_len: u16 align(1),
};

pub const CentralDirectoryFileHeader = extern struct {
    signature: [4]u8 align(1),
    version_made_by: u16 align(1),
    version_needed_to_extract: u16 align(1),
    flags: GeneralPurposeFlags align(1),
    compression_method: CompressionMethod align(1),
    last_modification_time: u16 align(1),
    last_modification_date: u16 align(1),
    crc32: u32 align(1),
    compressed_size: u32 align(1),
    uncompressed_size: u32 align(1),
    filename_len: u16 align(1),
    extra_len: u16 align(1),
    comment_len: u16 align(1),
    disk_number: u16 align(1),
    internal_file_attributes: u16 align(1),
    external_file_attributes: u32 align(1),
    local_file_header_offset: u32 align(1),
};

pub const EndRecord64 = extern struct {
    signature: [4]u8 align(1),
    end_record_size: u64 align(1),
    version_made_by: u16 align(1),
    version_needed_to_extract: u16 align(1),
    disk_number: u32 align(1),
    central_directory_disk_number: u32 align(1),
    record_count_disk: u64 align(1),
    record_count_total: u64 align(1),
    central_directory_size: u64 align(1),
    central_directory_offset: u64 align(1),
};

pub const EndLocator64 = extern struct {
    signature: [4]u8 align(1),
    zip64_disk_count: u32 align(1),
    record_file_offset: u64 align(1),
    total_disk_count: u32 align(1),
};

pub const EndRecord = extern struct {
    signature: [4]u8 align(1),
    disk_number: u16 align(1),
    central_directory_disk_number: u16 align(1),
    record_count_disk: u16 align(1),
    record_count_total: u16 align(1),
    central_directory_size: u32 align(1),
    central_directory_offset: u32 align(1),
    comment_len: u16 align(1),
    pub fn need_zip64(self: EndRecord) bool {
        return isMaxInt(self.record_count_disk) or
            isMaxInt(self.record_count_total) or
            isMaxInt(self.central_directory_size) or
            isMaxInt(self.central_directory_offset);
    }
};

/// Find and return the end record for the given seekable zip stream.
/// Note that `seekable_stream` must be an instance of `std.io.SeekableStream` and
/// its context must also have a `.reader()` method that returns an instance of
/// `std.io.Reader`.
pub fn findEndRecord(seekable_stream: anytype, stream_len: u64) !EndRecord {
    var buf: [@sizeOf(EndRecord) + std.math.maxInt(u16)]u8 = undefined;
    const record_len_max = @min(stream_len, buf.len);
    var loaded_len: u32 = 0;

    var comment_len: u16 = 0;
    while (true) {
        const record_len: u32 = @as(u32, comment_len) + @sizeOf(EndRecord);
        if (record_len > record_len_max)
            return error.ZipNoEndRecord;

        if (record_len > loaded_len) {
            const new_loaded_len = @min(loaded_len + 300, record_len_max);
            const read_len = new_loaded_len - loaded_len;

            try seekable_stream.seekTo(stream_len - @as(u64, new_loaded_len));
            const read_buf: []u8 = buf[buf.len - new_loaded_len ..][0..read_len];
            const len = try seekable_stream.context.reader().readAll(read_buf);
            if (len != read_len)
                return error.ZipTruncated;
            loaded_len = new_loaded_len;
        }

        const record_bytes = buf[buf.len - record_len ..][0..@sizeOf(EndRecord)];
        if (std.mem.eql(u8, record_bytes[0..4], &end_record_sig) and
            std.mem.readInt(u16, record_bytes[20..22], .little) == comment_len)
        {
            const record: *align(1) EndRecord = @ptrCast(record_bytes.ptr);
            if (builtin.target.cpu.arch.endian() != .little) {
                std.mem.byteSwapAllFields(@TypeOf(record.*), record);
            }
            return record.*;
        }

        if (comment_len == std.math.maxInt(u16))
            return error.ZipNoEndRecord;
        comment_len += 1;
    }
}

/// Decompresses the given data from `reader` into `writer`.  Stops early if more
/// than `uncompressed_size` bytes are processed and verifies that exactly that
/// number of bytes are decompressed.  Returns the CRC-32 of the uncompressed data.
/// `writer` can be anything with a `writeAll(self: *Self, chunk: []const u8) anyerror!void` method.
pub fn decompress(
    method: CompressionMethod,
    uncompressed_size: u64,
    reader: anytype,
    writer: anytype,
) !u32 {
    var hash = std.hash.Crc32.init();

    var total_uncompressed: u64 = 0;
    switch (method) {
        .store => {
            var buf: [4096]u8 = undefined;
            while (true) {
                const len = try reader.read(&buf);
                if (len == 0) break;
                try writer.writeAll(buf[0..len]);
                hash.update(buf[0..len]);
                total_uncompressed += @intCast(len);
            }
        },
        .deflate => {
            var br = std.io.bufferedReader(reader);
            var decompressor = std.compress.flate.decompressor(br.reader());
            while (try decompressor.next()) |chunk| {
                try writer.writeAll(chunk);
                hash.update(chunk);
                total_uncompressed += @intCast(chunk.len);
                if (total_uncompressed > uncompressed_size)
                    return error.ZipUncompressSizeTooSmall;
            }
            if (br.end != br.start)
                return error.ZipDeflateTruncated;
        },
        _ => return error.UnsupportedCompressionMethod,
    }
    if (total_uncompressed != uncompressed_size)
        return error.ZipUncompressSizeMismatch;

    return hash.final();
}

fn isBadFilename(filename: []const u8) bool {
    if (filename.len == 0 or filename[0] == '/')
        return true;

    var it = std.mem.splitScalar(u8, filename, '/');
    while (it.next()) |part| {
        if (std.mem.eql(u8, part, ".."))
            return true;
    }

    return false;
}

fn isMaxInt(uint: anytype) bool {
    return uint == std.math.maxInt(@TypeOf(uint));
}

const FileExtents = struct {
    uncompressed_size: u64,
    compressed_size: u64,
    local_file_header_offset: u64,
};

fn readZip64FileExtents(comptime T: type, header: T, extents: *FileExtents, data: []u8) !void {
    var data_offset: usize = 0;
    if (isMaxInt(header.uncompressed_size)) {
        if (data_offset + 8 > data.len)
            return error.ZipBadCd64Size;
        extents.uncompressed_size = std.mem.readInt(u64, data[data_offset..][0..8], .little);
        data_offset += 8;
    }
    if (isMaxInt(header.compressed_size)) {
        if (data_offset + 8 > data.len)
            return error.ZipBadCd64Size;
        extents.compressed_size = std.mem.readInt(u64, data[data_offset..][0..8], .little);
        data_offset += 8;
    }

    switch (T) {
        CentralDirectoryFileHeader => {
            if (isMaxInt(header.local_file_header_offset)) {
                if (data_offset + 8 > data.len)
                    return error.ZipBadCd64Size;
                extents.local_file_header_offset = std.mem.readInt(u64, data[data_offset..][0..8], .little);
                data_offset += 8;
            }
            if (isMaxInt(header.disk_number)) {
                if (data_offset + 4 > data.len)
                    return error.ZipInvalid;
                const disk_number = std.mem.readInt(u32, data[data_offset..][0..4], .little);
                if (disk_number != 0)
                    return error.ZipMultiDiskUnsupported;
                data_offset += 4;
            }
            if (data_offset > data.len)
                return error.ZipBadCd64Size;
        },
        else => {},
    }
}

pub fn Iterator(comptime SeekableStream: type) type {
    return struct {
        stream: SeekableStream,

        cd_record_count: u64,
        cd_zip_offset: u64,
        cd_size: u64,

        cd_record_index: u64 = 0,
        cd_record_offset: u64 = 0,

        const Self = @This();

        pub fn init(stream: SeekableStream) !Self {
            const stream_len = try stream.getEndPos();

            const end_record = try findEndRecord(stream, stream_len);

            if (!isMaxInt(end_record.record_count_disk) and end_record.record_count_disk > end_record.record_count_total)
                return error.ZipDiskRecordCountTooLarge;

            if (end_record.disk_number != 0 or end_record.central_directory_disk_number != 0)
                return error.ZipMultiDiskUnsupported;

            {
                const counts_valid = !isMaxInt(end_record.record_count_disk) and !isMaxInt(end_record.record_count_total);
                if (counts_valid and end_record.record_count_disk != end_record.record_count_total)
                    return error.ZipMultiDiskUnsupported;
            }

            var result = Self{
                .stream = stream,
                .cd_record_count = end_record.record_count_total,
                .cd_zip_offset = end_record.central_directory_offset,
                .cd_size = end_record.central_directory_size,
            };
            if (!end_record.need_zip64()) return result;

            const locator_end_offset: u64 = @as(u64, end_record.comment_len) + @sizeOf(EndRecord) + @sizeOf(EndLocator64);
            if (locator_end_offset > stream_len)
                return error.ZipTruncated;
            try stream.seekTo(stream_len - locator_end_offset);
            const locator = try stream.context.reader().readStructEndian(EndLocator64, .little);
            if (!std.mem.eql(u8, &locator.signature, &end_locator64_sig))
                return error.ZipBadLocatorSig;
            if (locator.zip64_disk_count != 0)
                return error.ZipUnsupportedZip64DiskCount;
            if (locator.total_disk_count != 1)
                return error.ZipMultiDiskUnsupported;

            try stream.seekTo(locator.record_file_offset);

            const record64 = try stream.context.reader().readStructEndian(EndRecord64, .little);

            if (!std.mem.eql(u8, &record64.signature, &end_record64_sig))
                return error.ZipBadEndRecord64Sig;

            if (record64.end_record_size < @sizeOf(EndRecord64) - 12)
                return error.ZipEndRecord64SizeTooSmall;
            if (record64.end_record_size > @sizeOf(EndRecord64) - 12)
                return error.ZipEndRecord64UnhandledExtraData;

            if (record64.version_needed_to_extract > 45)
                return error.ZipUnsupportedVersion;

            {
                const is_multidisk = record64.disk_number != 0 or
                    record64.central_directory_disk_number != 0 or
                    record64.record_count_disk != record64.record_count_total;
                if (is_multidisk)
                    return error.ZipMultiDiskUnsupported;
            }

            if (isMaxInt(end_record.record_count_total)) {
                result.cd_record_count = record64.record_count_total;
            } else if (end_record.record_count_total != record64.record_count_total)
                return error.Zip64RecordCountTotalMismatch;

            if (isMaxInt(end_record.central_directory_offset)) {
                result.cd_zip_offset = record64.central_directory_offset;
            } else if (end_record.central_directory_offset != record64.central_directory_offset)
                return error.Zip64CentralDirectoryOffsetMismatch;

            if (isMaxInt(end_record.central_directory_size)) {
                result.cd_size = record64.central_directory_size;
            } else if (end_record.central_directory_size != record64.central_directory_size)
                return error.Zip64CentralDirectorySizeMismatch;

            return result;
        }

        pub fn next(self: *Self) !?Entry {
            if (self.cd_record_index == self.cd_record_count) {
                if (self.cd_record_offset != self.cd_size)
                    return if (self.cd_size > self.cd_record_offset)
                        error.ZipCdOversized
                    else
                        error.ZipCdUndersized;

                return null;
            }

            const header_zip_offset = self.cd_zip_offset + self.cd_record_offset;
            try self.stream.seekTo(header_zip_offset);
            const header = try self.stream.context.reader().readStructEndian(CentralDirectoryFileHeader, .little);
            if (!std.mem.eql(u8, &header.signature, &central_file_header_sig))
                return error.ZipBadCdOffset;

            self.cd_record_index += 1;
            self.cd_record_offset += @sizeOf(CentralDirectoryFileHeader) + header.filename_len + header.extra_len + header.comment_len;

            // Note: checking the version_needed_to_extract doesn't seem to be helpful, i.e. the zip file
            // at https://github.com/ninja-build/ninja/releases/download/v1.12.0/ninja-linux.zip
            // has an undocumented version 788 but extracts just fine.

            if (header.flags.encrypted)
                return error.ZipEncryptionUnsupported;
            // TODO: check/verify more flags
            if (header.disk_number != 0)
                return error.ZipMultiDiskUnsupported;

            var extents: FileExtents = .{
                .uncompressed_size = header.uncompressed_size,
                .compressed_size = header.compressed_size,
                .local_file_header_offset = header.local_file_header_offset,
            };

            if (header.extra_len > 0) {
                var extra_buf: [std.math.maxInt(u16)]u8 = undefined;
                const extra = extra_buf[0..header.extra_len];

                {
                    try self.stream.seekTo(header_zip_offset + @sizeOf(CentralDirectoryFileHeader) + header.filename_len);
                    const len = try self.stream.context.reader().readAll(extra);
                    if (len != extra.len)
                        return error.ZipTruncated;
                }

                var extra_offset: usize = 0;
                while (extra_offset + 4 <= extra.len) {
                    const header_id = std.mem.readInt(u16, extra[extra_offset..][0..2], .little);
                    const data_size = std.mem.readInt(u16, extra[extra_offset..][2..4], .little);
                    const end = extra_offset + 4 + data_size;
                    if (end > extra.len)
                        return error.ZipBadExtraFieldSize;
                    const data = extra[extra_offset + 4 .. end];
                    switch (@as(ExtraHeader, @enumFromInt(header_id))) {
                        .zip64_info => try readZip64FileExtents(CentralDirectoryFileHeader, header, &extents, data),
                        else => {}, // ignore
                    }
                    extra_offset = end;
                }
            }

            return .{
                .version_needed_to_extract = header.version_needed_to_extract,
                .flags = header.flags,
                .compression_method = header.compression_method,
                .last_modification_time = header.last_modification_time,
                .last_modification_date = header.last_modification_date,
                .header_zip_offset = header_zip_offset,
                .crc32 = header.crc32,
                .filename_len = header.filename_len,
                .compressed_size = extents.compressed_size,
                .uncompressed_size = extents.uncompressed_size,
                .file_offset = extents.local_file_header_offset,
            };
        }

        pub const Entry = struct {
            version_needed_to_extract: u16,
            flags: GeneralPurposeFlags,
            compression_method: CompressionMethod,
            last_modification_time: u16,
            last_modification_date: u16,
            header_zip_offset: u64,
            crc32: u32,
            filename_len: u32,
            compressed_size: u64,
            uncompressed_size: u64,
            file_offset: u64,

            pub fn extract(
                self: Entry,
                stream: SeekableStream,
                options: ExtractOptions,
                filename_buf: []u8,
                dest: std.fs.Dir,
            ) !u32 {
                if (filename_buf.len < self.filename_len)
                    return error.ZipInsufficientBuffer;
                const filename = filename_buf[0..self.filename_len];

                try stream.seekTo(self.header_zip_offset + @sizeOf(CentralDirectoryFileHeader));

                {
                    const len = try stream.context.reader().readAll(filename);
                    if (len != filename.len)
                        return error.ZipBadFileOffset;
                }

                const local_data_header_offset: u64 = local_data_header_offset: {
                    const local_header = blk: {
                        try stream.seekTo(self.file_offset);
                        break :blk try stream.context.reader().readStructEndian(LocalFileHeader, .little);
                    };
                    if (!std.mem.eql(u8, &local_header.signature, &local_file_header_sig))
                        return error.ZipBadFileOffset;
                    if (local_header.version_needed_to_extract != self.version_needed_to_extract)
                        return error.ZipMismatchVersionNeeded;
                    if (local_header.last_modification_time != self.last_modification_time)
                        return error.ZipMismatchModTime;
                    if (local_header.last_modification_date != self.last_modification_date)
                        return error.ZipMismatchModDate;

                    if (@as(u16, @bitCast(local_header.flags)) != @as(u16, @bitCast(self.flags)))
                        return error.ZipMismatchFlags;
                    if (local_header.crc32 != 0 and local_header.crc32 != self.crc32)
                        return error.ZipMismatchCrc32;
                    var extents: FileExtents = .{
                        .uncompressed_size = local_header.uncompressed_size,
                        .compressed_size = local_header.compressed_size,
                        .local_file_header_offset = 0,
                    };
                    if (local_header.extra_len > 0) {
                        var extra_buf: [std.math.maxInt(u16)]u8 = undefined;
                        const extra = extra_buf[0..local_header.extra_len];

                        {
                            try stream.seekTo(self.file_offset + @sizeOf(LocalFileHeader) + local_header.filename_len);
                            const len = try stream.context.reader().readAll(extra);
                            if (len != extra.len)
                                return error.ZipTruncated;
                        }

                        var extra_offset: usize = 0;
                        while (extra_offset + 4 <= local_header.extra_len) {
                            const header_id = std.mem.readInt(u16, extra[extra_offset..][0..2], .little);
                            const data_size = std.mem.readInt(u16, extra[extra_offset..][2..4], .little);
                            const end = extra_offset + 4 + data_size;
                            if (end > local_header.extra_len)
                                return error.ZipBadExtraFieldSize;
                            const data = extra[extra_offset + 4 .. end];
                            switch (@as(ExtraHeader, @enumFromInt(header_id))) {
                                .zip64_info => try readZip64FileExtents(LocalFileHeader, local_header, &extents, data),
                                else => {}, // ignore
                            }
                            extra_offset = end;
                        }
                    }

                    if (extents.compressed_size != 0 and
                        extents.compressed_size != self.compressed_size)
                        return error.ZipMismatchCompLen;
                    if (extents.uncompressed_size != 0 and
                        extents.uncompressed_size != self.uncompressed_size)
                        return error.ZipMismatchUncompLen;

                    if (local_header.filename_len != self.filename_len)
                        return error.ZipMismatchFilenameLen;

                    break :local_data_header_offset @as(u64, local_header.filename_len) +
                        @as(u64, local_header.extra_len);
                };

                if (isBadFilename(filename))
                    return error.ZipBadFilename;

                if (options.allow_backslashes) {
                    std.mem.replaceScalar(u8, filename, '\\', '/');
                } else {
                    if (std.mem.indexOfScalar(u8, filename, '\\')) |_|
                        return error.ZipFilenameHasBackslash;
                }

                // All entries that end in '/' are directories
                if (filename[filename.len - 1] == '/') {
                    if (self.uncompressed_size != 0)
                        return error.ZipBadDirectorySize;
                    try dest.makePath(filename[0 .. filename.len - 1]);
                    return std.hash.Crc32.hash(&.{});
                }

                const out_file = blk: {
                    if (std.fs.path.dirname(filename)) |dirname| {
                        var parent_dir = try dest.makeOpenPath(dirname, .{});
                        defer parent_dir.close();

                        const basename = std.fs.path.basename(filename);
                        break :blk try parent_dir.createFile(basename, .{ .exclusive = true });
                    }
                    break :blk try dest.createFile(filename, .{ .exclusive = true });
                };
                defer out_file.close();
                const local_data_file_offset: u64 =
                    @as(u64, self.file_offset) +
                    @as(u64, @sizeOf(LocalFileHeader)) +
                    local_data_header_offset;
                try stream.seekTo(local_data_file_offset);
                var limited_reader = std.io.limitedReader(stream.context.reader(), self.compressed_size);
                const crc = try decompress(
                    self.compression_method,
                    self.uncompressed_size,
                    limited_reader.reader(),
                    out_file.writer(),
                );
                if (limited_reader.bytes_left != 0)
                    return error.ZipDecompressTruncated;
                return crc;
            }
        };
    };
}

// returns true if `filename` starts with `root` followed by a forward slash
fn filenameInRoot(filename: []const u8, root: []const u8) bool {
    return (filename.len >= root.len + 1) and
        (filename[root.len] == '/') and
        std.mem.eql(u8, filename[0..root.len], root);
}

pub const Diagnostics = struct {
    allocator: std.mem.Allocator,

    /// The common root directory for all extracted files if there is one.
    root_dir: []const u8 = "",

    saw_first_file: bool = false,

    pub fn deinit(self: *Diagnostics) void {
        self.allocator.free(self.root_dir);
        self.* = undefined;
    }

    // This function assumes name is a filename from a zip file which has already been verified to
    // not start with a slash, backslashes have been normalized to forward slashes, and directories
    // always end in a slash.
    pub fn nextFilename(self: *Diagnostics, name: []const u8) error{OutOfMemory}!void {
        if (!self.saw_first_file) {
            self.saw_first_file = true;
            std.debug.assert(self.root_dir.len == 0);
            const root_len = std.mem.indexOfScalar(u8, name, '/') orelse return;
            std.debug.assert(root_len > 0);
            self.root_dir = try self.allocator.dupe(u8, name[0..root_len]);
        } else if (self.root_dir.len > 0) {
            if (!filenameInRoot(name, self.root_dir)) {
                self.allocator.free(self.root_dir);
                self.root_dir = "";
            }
        }
    }
};

pub const ExtractOptions = struct {
    /// Allow filenames within the zip to use backslashes.  Back slashes are normalized
    /// to forward slashes before forwarding them to platform APIs.
    allow_backslashes: bool = false,

    diagnostics: ?*Diagnostics = null,
};

/// Extract the zipped files inside `seekable_stream` to the given `dest` directory.
/// Note that `seekable_stream` must be an instance of `std.io.SeekableStream` and
/// its context must also have a `.reader()` method that returns an instance of
/// `std.io.Reader`.
pub fn extract(dest: std.fs.Dir, seekable_stream: anytype, options: ExtractOptions) !void {
    const SeekableStream = @TypeOf(seekable_stream);
    var iter = try Iterator(SeekableStream).init(seekable_stream);

    var filename_buf: [std.fs.max_path_bytes]u8 = undefined;
    while (try iter.next()) |entry| {
        const crc32 = try entry.extract(seekable_stream, options, &filename_buf, dest);
        if (crc32 != entry.crc32)
            return error.ZipCrcMismatch;
        if (options.diagnostics) |d| {
            try d.nextFilename(filename_buf[0..entry.filename_len]);
        }
    }
}

fn testZip(options: ExtractOptions, comptime files: []const File, write_opt: testutil.WriteZipOptions) !void {
    var store: [files.len]FileStore = undefined;
    try testZipWithStore(options, files, write_opt, &store);
}
fn testZipWithStore(
    options: ExtractOptions,
    test_files: []const File,
    write_opt: testutil.WriteZipOptions,
    store: []FileStore,
) !void {
    var zip_buf: [4096]u8 = undefined;
    var fbs = try testutil.makeZipWithStore(&zip_buf, test_files, write_opt, store);

    var tmp = testing.tmpDir(.{ .no_follow = true });
    defer tmp.cleanup();
    try extract(tmp.dir, fbs.seekableStream(), options);
    try testutil.expectFiles(test_files, tmp.dir, .{});
}
fn testZipError(expected_error: anyerror, file: File, options: ExtractOptions) !void {
    var zip_buf: [4096]u8 = undefined;
    var store: [1]FileStore = undefined;
    var fbs = try testutil.makeZipWithStore(&zip_buf, &[_]File{file}, .{}, &store);
    var tmp = testing.tmpDir(.{ .no_follow = true });
    defer tmp.cleanup();
    try testing.expectError(expected_error, extract(tmp.dir, fbs.seekableStream(), options));
}

test "zip one file" {
    try testZip(.{}, &[_]File{
        .{ .name = "onefile.txt", .content = "Just a single file\n", .compression = .store },
    }, .{});
}
test "zip multiple files" {
    try testZip(.{ .allow_backslashes = true }, &[_]File{
        .{ .name = "foo", .content = "a foo file\n", .compression = .store },
        .{ .name = "subdir/bar", .content = "bar is this right?\nanother newline\n", .compression = .store },
        .{ .name = "subdir\\whoa", .content = "you can do backslashes", .compression = .store },
        .{ .name = "subdir/another/baz", .content = "bazzy mc bazzerson", .compression = .store },
    }, .{});
}
test "zip deflated" {
    try testZip(.{}, &[_]File{
        .{ .name = "deflateme", .content = "This is a deflated file.\nIt should be smaller in the Zip file1\n", .compression = .deflate },
        // TODO: re-enable this if/when we add support for deflate64
        //.{ .name = "deflateme64", .content = "The 64k version of deflate!\n", .compression = .deflate64 },
        .{ .name = "raw", .content = "Not all files need to be deflated in the same Zip.\n", .compression = .store },
    }, .{});
}
test "zip verify filenames" {
    // no empty filenames
    try testZipError(error.ZipBadFilename, .{ .name = "", .content = "", .compression = .store }, .{});
    // no absolute paths
    try testZipError(error.ZipBadFilename, .{ .name = "/", .content = "", .compression = .store }, .{});
    try testZipError(error.ZipBadFilename, .{ .name = "/foo", .content = "", .compression = .store }, .{});
    try testZipError(error.ZipBadFilename, .{ .name = "/foo/bar", .content = "", .compression = .store }, .{});
    // no '..' components
    try testZipError(error.ZipBadFilename, .{ .name = "..", .content = "", .compression = .store }, .{});
    try testZipError(error.ZipBadFilename, .{ .name = "foo/..", .content = "", .compression = .store }, .{});
    try testZipError(error.ZipBadFilename, .{ .name = "foo/bar/..", .content = "", .compression = .store }, .{});
    try testZipError(error.ZipBadFilename, .{ .name = "foo/bar/../", .content = "", .compression = .store }, .{});
    // no backslashes
    try testZipError(error.ZipFilenameHasBackslash, .{ .name = "foo\\bar", .content = "", .compression = .store }, .{});
}

test "zip64" {
    const test_files = [_]File{
        .{ .name = "fram", .content = "fram foo fro fraba", .compression = .store },
        .{ .name = "subdir/barro", .content = "aljdk;jal;jfd;lajkf", .compression = .store },
    };

    try testZip(.{}, &test_files, .{
        .end = .{
            .zip64 = .{},
            .record_count_disk = std.math.maxInt(u16), // trigger zip64
        },
    });
    try testZip(.{}, &test_files, .{
        .end = .{
            .zip64 = .{},
            .record_count_total = std.math.maxInt(u16), // trigger zip64
        },
    });
    try testZip(.{}, &test_files, .{
        .end = .{
            .zip64 = .{},
            .record_count_disk = std.math.maxInt(u16), // trigger zip64
            .record_count_total = std.math.maxInt(u16), // trigger zip64
        },
    });
    try testZip(.{}, &test_files, .{
        .end = .{
            .zip64 = .{},
            .central_directory_size = std.math.maxInt(u32), // trigger zip64
        },
    });
    try testZip(.{}, &test_files, .{
        .end = .{
            .zip64 = .{},
            .central_directory_offset = std.math.maxInt(u32), // trigger zip64
        },
    });
    try testZip(.{}, &test_files, .{
        .end = .{
            .zip64 = .{},
            .central_directory_offset = std.math.maxInt(u32), // trigger zip64
        },
        .local_header = .{
            .zip64 = .{ // trigger local header zip64
                .data_size = 16,
            },
            .compressed_size = std.math.maxInt(u32),
            .uncompressed_size = std.math.maxInt(u32),
            .extra_len = 20,
        },
    });
}

test "bad zip files" {
    var tmp = testing.tmpDir(.{ .no_follow = true });
    defer tmp.cleanup();
    var zip_buf: [4096]u8 = undefined;

    const file_a = [_]File{.{ .name = "a", .content = "", .compression = .store }};

    {
        var fbs = try testutil.makeZip(&zip_buf, &.{}, .{ .end = .{ .sig = [_]u8{ 1, 2, 3, 4 } } });
        try testing.expectError(error.ZipNoEndRecord, extract(tmp.dir, fbs.seekableStream(), .{}));
    }
    {
        var fbs = try testutil.makeZip(&zip_buf, &.{}, .{ .end = .{ .comment_len = 1 } });
        try testing.expectError(error.ZipNoEndRecord, extract(tmp.dir, fbs.seekableStream(), .{}));
    }
    {
        var fbs = try testutil.makeZip(&zip_buf, &.{}, .{ .end = .{ .comment = "a", .comment_len = 0 } });
        try testing.expectError(error.ZipNoEndRecord, extract(tmp.dir, fbs.seekableStream(), .{}));
    }
    {
        var fbs = try testutil.makeZip(&zip_buf, &.{}, .{ .end = .{ .disk_number = 1 } });
        try testing.expectError(error.ZipMultiDiskUnsupported, extract(tmp.dir, fbs.seekableStream(), .{}));
    }
    {
        var fbs = try testutil.makeZip(&zip_buf, &.{}, .{ .end = .{ .central_directory_disk_number = 1 } });
        try testing.expectError(error.ZipMultiDiskUnsupported, extract(tmp.dir, fbs.seekableStream(), .{}));
    }
    {
        var fbs = try testutil.makeZip(&zip_buf, &.{}, .{ .end = .{ .record_count_disk = 1 } });
        try testing.expectError(error.ZipDiskRecordCountTooLarge, extract(tmp.dir, fbs.seekableStream(), .{}));
    }
    {
        var fbs = try testutil.makeZip(&zip_buf, &.{}, .{ .end = .{ .central_directory_size = 1 } });
        try testing.expectError(error.ZipCdOversized, extract(tmp.dir, fbs.seekableStream(), .{}));
    }
    {
        var fbs = try testutil.makeZip(&zip_buf, &file_a, .{ .end = .{ .central_directory_size = 0 } });
        try testing.expectError(error.ZipCdUndersized, extract(tmp.dir, fbs.seekableStream(), .{}));
    }
    {
        var fbs = try testutil.makeZip(&zip_buf, &file_a, .{ .end = .{ .central_directory_offset = 0 } });
        try testing.expectError(error.ZipBadCdOffset, extract(tmp.dir, fbs.seekableStream(), .{}));
    }
    {
        var fbs = try testutil.makeZip(&zip_buf, &file_a, .{
            .end = .{
                .zip64 = .{ .locator_sig = [_]u8{ 1, 2, 3, 4 } },
                .central_directory_size = std.math.maxInt(u32), // trigger 64
            },
        });
        try testing.expectError(error.ZipBadLocatorSig, extract(tmp.dir, fbs.seekableStream(), .{}));
    }
}
const std = @import("std");
const testing = std.testing;
const zip = @import("../zip.zig");
const maxInt = std.math.maxInt;

pub const File = struct {
    name: []const u8,
    content: []const u8,
    compression: zip.CompressionMethod,
};

pub fn expectFiles(
    test_files: []const File,
    dir: std.fs.Dir,
    opt: struct {
        strip_prefix: ?[]const u8 = null,
    },
) !void {
    for (test_files) |test_file| {
        var normalized_sub_path_buf: [std.fs.max_path_bytes]u8 = undefined;

        const name = blk: {
            if (opt.strip_prefix) |strip_prefix| {
                try testing.expect(test_file.name.len >= strip_prefix.len);
                try testing.expectEqualStrings(strip_prefix, test_file.name[0..strip_prefix.len]);
                break :blk test_file.name[strip_prefix.len..];
            }
            break :blk test_file.name;
        };
        const normalized_sub_path = normalized_sub_path_buf[0..name.len];
        @memcpy(normalized_sub_path, name);
        std.mem.replaceScalar(u8, normalized_sub_path, '\\', '/');
        var file = try dir.openFile(normalized_sub_path, .{});
        defer file.close();
        var content_buf: [4096]u8 = undefined;
        const n = try file.reader().readAll(&content_buf);
        try testing.expectEqualStrings(test_file.content, content_buf[0..n]);
    }
}

// Used to store any data from writing a file to the zip archive that's needed
// when writing the corresponding central directory record.
pub const FileStore = struct {
    compression: zip.CompressionMethod,
    file_offset: u64,
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: usize,
};

pub fn makeZip(
    buf: []u8,
    comptime files: []const File,
    options: WriteZipOptions,
) !std.io.FixedBufferStream([]u8) {
    var store: [files.len]FileStore = undefined;
    return try makeZipWithStore(buf, files, options, &store);
}

pub fn makeZipWithStore(
    buf: []u8,
    files: []const File,
    options: WriteZipOptions,
    store: []FileStore,
) !std.io.FixedBufferStream([]u8) {
    var fbs = std.io.fixedBufferStream(buf);
    try writeZip(fbs.writer(), files, store, options);
    return std.io.fixedBufferStream(buf[0..fbs.pos]);
}

pub const WriteZipOptions = struct {
    end: ?EndRecordOptions = null,
    local_header: ?LocalHeaderOptions = null,
};
pub const LocalHeaderOptions = struct {
    zip64: ?LocalHeaderZip64Options = null,
    compressed_size: ?u32 = null,
    uncompressed_size: ?u32 = null,
    extra_len: ?u16 = null,
};
pub const LocalHeaderZip64Options = struct {
    data_size: ?u16 = null,
};
pub const EndRecordOptions = struct {
    zip64: ?Zip64Options = null,
    sig: ?[4]u8 = null,
    disk_number: ?u16 = null,
    central_directory_disk_number: ?u16 = null,
    record_count_disk: ?u16 = null,
    record_count_total: ?u16 = null,
    central_directory_size: ?u32 = null,
    central_directory_offset: ?u32 = null,
    comment_len: ?u16 = null,
    comment: ?[]const u8 = null,
};
pub const Zip64Options = struct {
    locator_sig: ?[4]u8 = null,
    locator_zip64_disk_count: ?u32 = null,
    locator_record_file_offset: ?u64 = null,
    locator_total_disk_count: ?u32 = null,
    //record_size: ?u64 = null,
    central_directory_size: ?u64 = null,
};

pub fn writeZip(
    writer: anytype,
    files: []const File,
    store: []FileStore,
    options: WriteZipOptions,
) !void {
    if (store.len < files.len) return error.FileStoreTooSmall;
    var zipper = initZipper(writer);
    for (files, 0..) |file, i| {
        store[i] = try zipper.writeFile(.{
            .name = file.name,
            .content = file.content,
            .compression = file.compression,
            .write_options = options,
        });
    }
    for (files, 0..) |file, i| {
        try zipper.writeCentralRecord(store[i], .{
            .name = file.name,
        });
    }
    try zipper.writeEndRecord(if (options.end) |e| e else .{});
}

pub fn initZipper(writer: anytype) Zipper(@TypeOf(writer)) {
    return .{ .counting_writer = std.io.countingWriter(writer) };
}

/// Provides methods to format and write the contents of a zip archive
/// to the underlying Writer.
pub fn Zipper(comptime Writer: type) type {
    return struct {
        counting_writer: std.io.CountingWriter(Writer),
        central_count: u64 = 0,
        first_central_offset: ?u64 = null,
        last_central_limit: ?u64 = null,

        const Self = @This();

        pub fn writeFile(
            self: *Self,
            opt: struct {
                name: []const u8,
                content: []const u8,
                compression: zip.CompressionMethod,
                write_options: WriteZipOptions,
            },
        ) !FileStore {
            const writer = self.counting_writer.writer();

            const file_offset: u64 = @intCast(self.counting_writer.bytes_written);
            const crc32 = std.hash.Crc32.hash(opt.content);

            const header_options = opt.write_options.local_header;
            {
                var compressed_size: u32 = 0;
                var uncompressed_size: u32 = 0;
                var extra_len: u16 = 0;
                if (header_options) |hdr_options| {
                    compressed_size = if (hdr_options.compressed_size) |size| size else 0;
                    uncompressed_size = if (hdr_options.uncompressed_size) |size| size else @intCast(opt.content.len);
                    extra_len = if (hdr_options.extra_len) |len| len else 0;
                }
                const hdr: zip.LocalFileHeader = .{
                    .signature = zip.local_file_header_sig,
                    .version_needed_to_extract = 10,
                    .flags = .{ .encrypted = false, ._ = 0 },
                    .compression_method = opt.compression,
                    .last_modification_time = 0,
                    .last_modification_date = 0,
                    .crc32 = crc32,
                    .compressed_size = compressed_size,
                    .uncompressed_size = uncompressed_size,
                    .filename_len = @intCast(opt.name.len),
                    .extra_len = extra_len,
                };
                try writer.writeStructEndian(hdr, .little);
            }
            try writer.writeAll(opt.name);

            if (header_options) |hdr| {
                if (hdr.zip64) |options| {
                    try writer.writeInt(u16, 0x0001, .little);
                    const data_size = if (options.data_size) |size| size else 8;
                    try writer.writeInt(u16, data_size, .little);
                    try writer.writeInt(u64, 0, .little);
                    try writer.writeInt(u64, @intCast(opt.content.len), .little);
                }
            }

            var compressed_size: u32 = undefined;
            switch (opt.compression) {
                .store => {
                    try writer.writeAll(opt.content);
                    compressed_size = @intCast(opt.content.len);
                },
                .deflate => {
                    const offset = self.counting_writer.bytes_written;
                    var fbs = std.io.fixedBufferStream(opt.content);
                    try std.compress.flate.deflate.compress(.raw, fbs.reader(), writer, .{});
                    std.debug.assert(fbs.pos == opt.content.len);
                    compressed_size = @intCast(self.counting_writer.bytes_written - offset);
                },
                else => unreachable,
            }
            return .{
                .compression = opt.compression,
                .file_offset = file_offset,
                .crc32 = crc32,
                .compressed_size = compressed_size,
                .uncompressed_size = opt.content.len,
            };
        }

        pub fn writeCentralRecord(
            self: *Self,
            store: FileStore,
            opt: struct {
                name: []const u8,
                version_needed_to_extract: u16 = 10,
            },
        ) !void {
            if (self.first_central_offset == null) {
                self.first_central_offset = self.counting_writer.bytes_written;
            }
            self.central_count += 1;

            const hdr: zip.CentralDirectoryFileHeader = .{
                .signature = zip.central_file_header_sig,
                .version_made_by = 0,
                .version_needed_to_extract = opt.version_needed_to_extract,
                .flags = .{ .encrypted = false, ._ = 0 },
                .compression_method = store.compression,
                .last_modification_time = 0,
                .last_modification_date = 0,
                .crc32 = store.crc32,
                .compressed_size = store.compressed_size,
                .uncompressed_size = @intCast(store.uncompressed_size),
                .filename_len = @intCast(opt.name.len),
                .extra_len = 0,
                .comment_len = 0,
                .disk_number = 0,
                .internal_file_attributes = 0,
                .external_file_attributes = 0,
                .local_file_header_offset = @intCast(store.file_offset),
            };
            try self.counting_writer.writer().writeStructEndian(hdr, .little);
            try self.counting_writer.writer().writeAll(opt.name);
            self.last_central_limit = self.counting_writer.bytes_written;
        }

        pub fn writeEndRecord(self: *Self, opt: EndRecordOptions) !void {
            const cd_offset = self.first_central_offset orelse 0;
            const cd_end = self.last_central_limit orelse 0;

            if (opt.zip64) |zip64| {
                const end64_off = cd_end;
                const fixed: zip.EndRecord64 = .{
                    .signature = zip.end_record64_sig,
                    .end_record_size = @sizeOf(zip.EndRecord64) - 12,
                    .version_made_by = 0,
                    .version_needed_to_extract = 45,
                    .disk_number = 0,
                    .central_directory_disk_number = 0,
                    .record_count_disk = @intCast(self.central_count),
                    .record_count_total = @intCast(self.central_count),
                    .central_directory_size = @intCast(cd_end - cd_offset),
                    .central_directory_offset = @intCast(cd_offset),
                };
                try self.counting_writer.writer().writeStructEndian(fixed, .little);
                const locator: zip.EndLocator64 = .{
                    .signature = if (zip64.locator_sig) |s| s else zip.end_locator64_sig,
                    .zip64_disk_count = if (zip64.locator_zip64_disk_count) |c| c else 0,
                    .record_file_offset = if (zip64.locator_record_file_offset) |o| o else @intCast(end64_off),
                    .total_disk_count = if (zip64.locator_total_disk_count) |c| c else 1,
                };
                try self.counting_writer.writer().writeStructEndian(locator, .little);
            }
            const hdr: zip.EndRecord = .{
                .signature = if (opt.sig) |s| s else zip.end_record_sig,
                .disk_number = if (opt.disk_number) |n| n else 0,
                .central_directory_disk_number = if (opt.central_directory_disk_number) |n| n else 0,
                .record_count_disk = if (opt.record_count_disk) |c| c else @intCast(self.central_count),
                .record_count_total = if (opt.record_count_total) |c| c else @intCast(self.central_count),
                .central_directory_size = if (opt.central_directory_size) |s| s else @intCast(cd_end - cd_offset),
                .central_directory_offset = if (opt.central_directory_offset) |o| o else @intCast(cd_offset),
                .comment_len = if (opt.comment_len) |l| l else (if (opt.comment) |c| @as(u16, @intCast(c.len)) else 0),
            };
            try self.counting_writer.writer().writeStructEndian(hdr, .little);
            if (opt.comment) |c|
                try self.counting_writer.writer().writeAll(c);
        }
    };
}
//! ZON parsing and stringification.
//!
//! ZON ("Zig Object Notation") is a textual file format. Outside of `nan` and `inf` literals, ZON's
//! grammar is a subset of Zig's.
//!
//! Supported Zig primitives:
//! * boolean literals
//! * number literals (including `nan` and `inf`)
//! * character literals
//! * enum literals
//! * `null` literals
//! * string literals
//! * multiline string literals
//!
//! Supported Zig container types:
//! * anonymous struct literals
//! * anonymous tuple literals
//!
//! Here is an example ZON object:
//! ```
//! .{
//!     .a = 1.5,
//!     .b = "hello, world!",
//!     .c = .{ true, false },
//!     .d = .{ 1, 2, 3 },
//! }
//! ```
//!
//! Individual primitives are also valid ZON, for example:
//! ```
//! "This string is a valid ZON object."
//! ```
//!
//! ZON may not contain type names.
//!
//! ZON does not have syntax for pointers, but the parsers will allocate as needed to match the
//! given Zig types. Similarly, the serializer will traverse pointers.

pub const parse = @import("zon/parse.zig");
pub const stringify = @import("zon/stringify.zig");

test {
    _ = parse;
    _ = stringify;
}
//! The simplest way to parse ZON at runtime is to use `fromSlice`. If you need to parse ZON at
//! compile time, you may use `@import`.
//!
//! Parsing from individual Zoir nodes is also available:
//! * `fromZoir`
//! * `fromZoirNode`
//!
//! For lower level control, it is possible to operate on `std.zig.Zoir` directly.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;
const Zoir = std.zig.Zoir;
const ZonGen = std.zig.ZonGen;
const TokenIndex = std.zig.Ast.TokenIndex;
const Base = std.zig.number_literal.Base;
const StrLitErr = std.zig.string_literal.Error;
const NumberLiteralError = std.zig.number_literal.Error;
const assert = std.debug.assert;
const ArrayListUnmanaged = std.ArrayListUnmanaged;

/// Rename when adding or removing support for a type.
const valid_types = {};

/// Configuration for the runtime parser.
pub const Options = struct {
    /// If true, unknown fields do not error.
    ignore_unknown_fields: bool = false,
    /// If true, the parser cleans up partially parsed values on error. This requires some extra
    /// bookkeeping, so you may want to turn it off if you don't need this feature (e.g. because
    /// you're using arena allocation.)
    free_on_error: bool = true,
};

pub const Error = union(enum) {
    zoir: Zoir.CompileError,
    type_check: Error.TypeCheckFailure,

    pub const Note = union(enum) {
        zoir: Zoir.CompileError.Note,
        type_check: TypeCheckFailure.Note,

        pub const Iterator = struct {
            index: usize = 0,
            err: Error,
            diag: *const Diagnostics,

            pub fn next(self: *@This()) ?Note {
                switch (self.err) {
                    .zoir => |err| {
                        if (self.index >= err.note_count) return null;
                        const note = err.getNotes(self.diag.zoir)[self.index];
                        self.index += 1;
                        return .{ .zoir = note };
                    },
                    .type_check => |err| {
                        if (self.index >= err.getNoteCount()) return null;
                        const note = err.getNote(self.index);
                        self.index += 1;
                        return .{ .type_check = note };
                    },
                }
            }
        };

        fn formatMessage(
            self: []const u8,
            comptime f: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = f;
            _ = options;

            // Just writes the string for now, but we're keeping this behind a formatter so we have
            // the option to extend it in the future to print more advanced messages (like `Error`
            // does) without breaking the API.
            try writer.writeAll(self);
        }

        pub fn fmtMessage(self: Note, diag: *const Diagnostics) std.fmt.Formatter(Note.formatMessage) {
            return .{ .data = switch (self) {
                .zoir => |note| note.msg.get(diag.zoir),
                .type_check => |note| note.msg,
            } };
        }

        pub fn getLocation(self: Note, diag: *const Diagnostics) Ast.Location {
            switch (self) {
                .zoir => |note| return zoirErrorLocation(diag.ast, note.token, note.node_or_offset),
                .type_check => |note| return diag.ast.tokenLocation(note.offset, note.token),
            }
        }
    };

    pub const Iterator = struct {
        index: usize = 0,
        diag: *const Diagnostics,

        pub fn next(self: *@This()) ?Error {
            if (self.index < self.diag.zoir.compile_errors.len) {
                const result: Error = .{ .zoir = self.diag.zoir.compile_errors[self.index] };
                self.index += 1;
                return result;
            }

            if (self.diag.type_check) |err| {
                if (self.index == self.diag.zoir.compile_errors.len) {
                    const result: Error = .{ .type_check = err };
                    self.index += 1;
                    return result;
                }
            }

            return null;
        }
    };

    const TypeCheckFailure = struct {
        const Note = struct {
            token: Ast.TokenIndex,
            offset: u32,
            msg: []const u8,
            owned: bool,

            fn deinit(self: @This(), gpa: Allocator) void {
                if (self.owned) gpa.free(self.msg);
            }
        };

        message: []const u8,
        owned: bool,
        token: Ast.TokenIndex,
        offset: u32,
        note: ?@This().Note,

        fn deinit(self: @This(), gpa: Allocator) void {
            if (self.note) |note| note.deinit(gpa);
            if (self.owned) gpa.free(self.message);
        }

        fn getNoteCount(self: @This()) usize {
            return @intFromBool(self.note != null);
        }

        fn getNote(self: @This(), index: usize) @This().Note {
            assert(index == 0);
            return self.note.?;
        }
    };

    const FormatMessage = struct {
        err: Error,
        diag: *const Diagnostics,
    };

    fn formatMessage(
        self: FormatMessage,
        comptime f: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = f;
        _ = options;
        switch (self.err) {
            .zoir => |err| try writer.writeAll(err.msg.get(self.diag.zoir)),
            .type_check => |tc| try writer.writeAll(tc.message),
        }
    }

    pub fn fmtMessage(self: @This(), diag: *const Diagnostics) std.fmt.Formatter(formatMessage) {
        return .{ .data = .{
            .err = self,
            .diag = diag,
        } };
    }

    pub fn getLocation(self: @This(), diag: *const Diagnostics) Ast.Location {
        return switch (self) {
            .zoir => |err| return zoirErrorLocation(
                diag.ast,
                err.token,
                err.node_or_offset,
            ),
            .type_check => |err| return diag.ast.tokenLocation(err.offset, err.token),
        };
    }

    pub fn iterateNotes(self: @This(), diag: *const Diagnostics) Note.Iterator {
        return .{ .err = self, .diag = diag };
    }

    fn zoirErrorLocation(ast: Ast, maybe_token: Ast.OptionalTokenIndex, node_or_offset: u32) Ast.Location {
        if (maybe_token.unwrap()) |token| {
            var location = ast.tokenLocation(0, token);
            location.column += node_or_offset;
            return location;
        } else {
            const ast_node: Ast.Node.Index = @enumFromInt(node_or_offset);
            const token = ast.nodeMainToken(ast_node);
            return ast.tokenLocation(0, token);
        }
    }
};

/// Information about the success or failure of a parse.
pub const Diagnostics = struct {
    ast: Ast = .{
        .source = "",
        .tokens = .empty,
        .nodes = .empty,
        .extra_data = &.{},
        .mode = .zon,
        .errors = &.{},
    },
    zoir: Zoir = .{
        .nodes = .empty,
        .extra = &.{},
        .limbs = &.{},
        .string_bytes = &.{},
        .compile_errors = &.{},
        .error_notes = &.{},
    },
    type_check: ?Error.TypeCheckFailure = null,

    fn assertEmpty(self: Diagnostics) void {
        assert(self.ast.tokens.len == 0);
        assert(self.zoir.nodes.len == 0);
        assert(self.type_check == null);
    }

    pub fn deinit(self: *Diagnostics, gpa: Allocator) void {
        self.ast.deinit(gpa);
        self.zoir.deinit(gpa);
        if (self.type_check) |tc| tc.deinit(gpa);
        self.* = undefined;
    }

    pub fn iterateErrors(self: *const Diagnostics) Error.Iterator {
        return .{ .diag = self };
    }

    pub fn format(
        self: *const @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        var errors = self.iterateErrors();
        while (errors.next()) |err| {
            const loc = err.getLocation(self);
            const msg = err.fmtMessage(self);
            try writer.print("{}:{}: error: {}\n", .{ loc.line + 1, loc.column + 1, msg });

            var notes = err.iterateNotes(self);
            while (notes.next()) |note| {
                const note_loc = note.getLocation(self);
                const note_msg = note.fmtMessage(self);
                try writer.print("{}:{}: note: {s}\n", .{
                    note_loc.line + 1,
                    note_loc.column + 1,
                    note_msg,
                });
            }
        }
    }
};

/// Parses the given slice as ZON.
///
/// Returns `error.OutOfMemory` on allocation failure, or `error.ParseZon` error if the ZON is
/// invalid or can not be deserialized into type `T`.
///
/// When the parser returns `error.ParseZon`, it will also store a human readable explanation in
/// `diag` if non null. If diag is not null, it must be initialized to `.{}`.
pub fn fromSlice(
    /// The type to deserialize into. May not be or contain any of the following types:
    /// * Any comptime-only type, except in a comptime field
    /// * `type`
    /// * `void`, except as a union payload
    /// * `noreturn`
    /// * An error set/error union
    /// * A many-pointer or C-pointer
    /// * An opaque type, including `anyopaque`
    /// * An async frame type, including `anyframe` and `anyframe->T`
    /// * A function
    ///
    /// All other types are valid. Unsupported types will fail at compile time.
    T: type,
    gpa: Allocator,
    source: [:0]const u8,
    diag: ?*Diagnostics,
    options: Options,
) error{ OutOfMemory, ParseZon }!T {
    if (diag) |s| s.assertEmpty();

    var ast = try std.zig.Ast.parse(gpa, source, .zon);
    defer if (diag == null) ast.deinit(gpa);
    if (diag) |s| s.ast = ast;

    // If there's no diagnostics, Zoir exists for the lifetime of this function. If there is a
    // diagnostics, ownership is transferred to diagnostics.
    var zoir = try ZonGen.generate(gpa, ast, .{ .parse_str_lits = false });
    defer if (diag == null) zoir.deinit(gpa);

    if (diag) |s| s.* = .{};
    return fromZoir(T, gpa, ast, zoir, diag, options);
}

/// Like `fromSlice`, but operates on `Zoir` instead of ZON source.
pub fn fromZoir(
    T: type,
    gpa: Allocator,
    ast: Ast,
    zoir: Zoir,
    diag: ?*Diagnostics,
    options: Options,
) error{ OutOfMemory, ParseZon }!T {
    return fromZoirNode(T, gpa, ast, zoir, .root, diag, options);
}

/// Like `fromZoir`, but the parse starts on `node` instead of root.
pub fn fromZoirNode(
    T: type,
    gpa: Allocator,
    ast: Ast,
    zoir: Zoir,
    node: Zoir.Node.Index,
    diag: ?*Diagnostics,
    options: Options,
) error{ OutOfMemory, ParseZon }!T {
    comptime assert(canParseType(T));

    if (diag) |s| {
        s.assertEmpty();
        s.ast = ast;
        s.zoir = zoir;
    }

    if (zoir.hasCompileErrors()) {
        return error.ParseZon;
    }

    var parser: Parser = .{
        .gpa = gpa,
        .ast = ast,
        .zoir = zoir,
        .options = options,
        .diag = diag,
    };

    return parser.parseExpr(T, node);
}

/// Frees ZON values.
///
/// Provided for convenience, you may also free these values on your own using the same allocator
/// passed into the parser.
///
/// Asserts at comptime that sufficient information is available via the type system to free this
/// value. Untagged unions, for example, will fail this assert.
pub fn free(gpa: Allocator, value: anytype) void {
    const Value = @TypeOf(value);

    _ = valid_types;
    switch (@typeInfo(Value)) {
        .bool, .int, .float, .@"enum" => {},
        .pointer => |pointer| {
            switch (pointer.size) {
                .one => {
                    free(gpa, value.*);
                    gpa.destroy(value);
                },
                .slice => {
                    for (value) |item| {
                        free(gpa, item);
                    }
                    gpa.free(value);
                },
                .many, .c => comptime unreachable,
            }
        },
        .array => for (value) |item| {
            free(gpa, item);
        },
        .@"struct" => |@"struct"| inline for (@"struct".fields) |field| {
            free(gpa, @field(value, field.name));
        },
        .@"union" => |@"union"| if (@"union".tag_type == null) {
            if (comptime requiresAllocator(Value)) unreachable;
        } else switch (value) {
            inline else => |_, tag| {
                free(gpa, @field(value, @tagName(tag)));
            },
        },
        .optional => if (value) |some| {
            free(gpa, some);
        },
        .vector => |vector| for (0..vector.len) |i| free(gpa, value[i]),
        .void => {},
        else => comptime unreachable,
    }
}

fn requiresAllocator(T: type) bool {
    _ = valid_types;
    return switch (@typeInfo(T)) {
        .pointer => true,
        .array => |array| return array.len > 0 and requiresAllocator(array.child),
        .@"struct" => |@"struct"| inline for (@"struct".fields) |field| {
            if (requiresAllocator(field.type)) {
                break true;
            }
        } else false,
        .@"union" => |@"union"| inline for (@"union".fields) |field| {
            if (requiresAllocator(field.type)) {
                break true;
            }
        } else false,
        .optional => |optional| requiresAllocator(optional.child),
        .vector => |vector| return vector.len > 0 and requiresAllocator(vector.child),
        else => false,
    };
}

const Parser = struct {
    gpa: Allocator,
    ast: Ast,
    zoir: Zoir,
    diag: ?*Diagnostics,
    options: Options,

    fn parseExpr(self: *@This(), T: type, node: Zoir.Node.Index) error{ ParseZon, OutOfMemory }!T {
        return self.parseExprInner(T, node) catch |err| switch (err) {
            error.WrongType => return self.failExpectedType(T, node),
            else => |e| return e,
        };
    }

    fn parseExprInner(
        self: *@This(),
        T: type,
        node: Zoir.Node.Index,
    ) error{ ParseZon, OutOfMemory, WrongType }!T {
        if (T == Zoir.Node.Index) {
            return node;
        }

        switch (@typeInfo(T)) {
            .optional => |optional| if (node.get(self.zoir) == .null) {
                return null;
            } else {
                return try self.parseExprInner(optional.child, node);
            },
            .bool => return self.parseBool(node),
            .int => return self.parseInt(T, node),
            .float => return self.parseFloat(T, node),
            .@"enum" => return self.parseEnumLiteral(T, node),
            .pointer => |pointer| switch (pointer.size) {
                .one => {
                    const result = try self.gpa.create(pointer.child);
                    errdefer self.gpa.destroy(result);
                    result.* = try self.parseExprInner(pointer.child, node);
                    return result;
                },
                .slice => return self.parseSlicePointer(T, node),
                else => comptime unreachable,
            },
            .array => return self.parseArray(T, node),
            .@"struct" => |@"struct"| if (@"struct".is_tuple)
                return self.parseTuple(T, node)
            else
                return self.parseStruct(T, node),
            .@"union" => return self.parseUnion(T, node),
            .vector => return self.parseVector(T, node),

            else => comptime unreachable,
        }
    }

    /// Prints a message of the form `expected T` where T is first converted to a ZON type. For
    /// example, `**?**u8` becomes `?u8`, and types that involve user specified type names are just
    /// referred to by the type of container.
    fn failExpectedType(
        self: @This(),
        T: type,
        node: Zoir.Node.Index,
    ) error{ ParseZon, OutOfMemory } {
        @branchHint(.cold);
        return self.failExpectedTypeInner(T, false, node);
    }

    fn failExpectedTypeInner(
        self: @This(),
        T: type,
        opt: bool,
        node: Zoir.Node.Index,
    ) error{ ParseZon, OutOfMemory } {
        _ = valid_types;
        switch (@typeInfo(T)) {
            .@"struct" => |@"struct"| if (@"struct".is_tuple) {
                if (opt) {
                    return self.failNode(node, "expected optional tuple");
                } else {
                    return self.failNode(node, "expected tuple");
                }
            } else {
                if (opt) {
                    return self.failNode(node, "expected optional struct");
                } else {
                    return self.failNode(node, "expected struct");
                }
            },
            .@"union" => if (opt) {
                return self.failNode(node, "expected optional union");
            } else {
                return self.failNode(node, "expected union");
            },
            .array => if (opt) {
                return self.failNode(node, "expected optional array");
            } else {
                return self.failNode(node, "expected array");
            },
            .pointer => |pointer| switch (pointer.size) {
                .one => return self.failExpectedTypeInner(pointer.child, opt, node),
                .slice => {
                    if (pointer.child == u8 and
                        pointer.is_const and
                        (pointer.sentinel() == null or pointer.sentinel() == 0) and
                        pointer.alignment == 1)
                    {
                        if (opt) {
                            return self.failNode(node, "expected optional string");
                        } else {
                            return self.failNode(node, "expected string");
                        }
                    } else {
                        if (opt) {
                            return self.failNode(node, "expected optional array");
                        } else {
                            return self.failNode(node, "expected array");
                        }
                    }
                },
                else => comptime unreachable,
            },
            .vector, .bool, .int, .float => if (opt) {
                return self.failNodeFmt(node, "expected type '{s}'", .{@typeName(?T)});
            } else {
                return self.failNodeFmt(node, "expected type '{s}'", .{@typeName(T)});
            },
            .@"enum" => if (opt) {
                return self.failNode(node, "expected optional enum literal");
            } else {
                return self.failNode(node, "expected enum literal");
            },
            .optional => |optional| {
                return self.failExpectedTypeInner(optional.child, true, node);
            },
            else => comptime unreachable,
        }
    }

    fn parseBool(self: @This(), node: Zoir.Node.Index) !bool {
        switch (node.get(self.zoir)) {
            .true => return true,
            .false => return false,
            else => return error.WrongType,
        }
    }

    fn parseInt(self: @This(), T: type, node: Zoir.Node.Index) !T {
        switch (node.get(self.zoir)) {
            .int_literal => |int| switch (int) {
                .small => |val| return std.math.cast(T, val) orelse
                    self.failCannotRepresent(T, node),
                .big => |val| return val.toInt(T) catch
                    self.failCannotRepresent(T, node),
            },
            .float_literal => |val| return intFromFloatExact(T, val) orelse
                self.failCannotRepresent(T, node),

            .char_literal => |val| return std.math.cast(T, val) orelse
                self.failCannotRepresent(T, node),
            else => return error.WrongType,
        }
    }

    fn parseFloat(self: @This(), T: type, node: Zoir.Node.Index) !T {
        switch (node.get(self.zoir)) {
            .int_literal => |int| switch (int) {
                .small => |val| return @floatFromInt(val),
                .big => |val| return val.toFloat(T),
            },
            .float_literal => |val| return @floatCast(val),
            .pos_inf => return std.math.inf(T),
            .neg_inf => return -std.math.inf(T),
            .nan => return std.math.nan(T),
            .char_literal => |val| return @floatFromInt(val),
            else => return error.WrongType,
        }
    }

    fn parseEnumLiteral(self: @This(), T: type, node: Zoir.Node.Index) !T {
        switch (node.get(self.zoir)) {
            .enum_literal => |field_name| {
                // Create a comptime string map for the enum fields
                const enum_fields = @typeInfo(T).@"enum".fields;
                comptime var kvs_list: [enum_fields.len]struct { []const u8, T } = undefined;
                inline for (enum_fields, 0..) |field, i| {
                    kvs_list[i] = .{ field.name, @enumFromInt(field.value) };
                }
                const enum_tags = std.StaticStringMap(T).initComptime(kvs_list);

                // Get the tag if it exists
                const field_name_str = field_name.get(self.zoir);
                return enum_tags.get(field_name_str) orelse
                    self.failUnexpected(T, "enum literal", node, null, field_name_str);
            },
            else => return error.WrongType,
        }
    }

    fn parseSlicePointer(self: *@This(), T: type, node: Zoir.Node.Index) !T {
        switch (node.get(self.zoir)) {
            .string_literal => return self.parseString(T, node),
            .array_literal => |nodes| return self.parseSlice(T, nodes),
            .empty_literal => return self.parseSlice(T, .{ .start = node, .len = 0 }),
            else => return error.WrongType,
        }
    }

    fn parseString(self: *@This(), T: type, node: Zoir.Node.Index) !T {
        const ast_node = node.getAstNode(self.zoir);
        const pointer = @typeInfo(T).pointer;
        var size_hint = ZonGen.strLitSizeHint(self.ast, ast_node);
        if (pointer.sentinel() != null) size_hint += 1;

        var buf: std.ArrayListUnmanaged(u8) = try .initCapacity(self.gpa, size_hint);
        defer buf.deinit(self.gpa);
        switch (try ZonGen.parseStrLit(self.ast, ast_node, buf.writer(self.gpa))) {
            .success => {},
            .failure => |err| {
                const token = self.ast.nodeMainToken(ast_node);
                const raw_string = self.ast.tokenSlice(token);
                return self.failTokenFmt(token, @intCast(err.offset()), "{s}", .{err.fmt(raw_string)});
            },
        }

        if (pointer.child != u8 or
            pointer.size != .slice or
            !pointer.is_const or
            (pointer.sentinel() != null and pointer.sentinel() != 0) or
            pointer.alignment != 1)
        {
            return error.WrongType;
        }

        if (pointer.sentinel() != null) {
            return buf.toOwnedSliceSentinel(self.gpa, 0);
        } else {
            return buf.toOwnedSlice(self.gpa);
        }
    }

    fn parseSlice(self: *@This(), T: type, nodes: Zoir.Node.Index.Range) !T {
        const pointer = @typeInfo(T).pointer;

        // Make sure we're working with a slice
        switch (pointer.size) {
            .slice => {},
            .one, .many, .c => comptime unreachable,
        }

        // Allocate the slice
        const slice = try self.gpa.allocWithOptions(
            pointer.child,
            nodes.len,
            .fromByteUnits(pointer.alignment),
            pointer.sentinel(),
        );
        errdefer self.gpa.free(slice);

        // Parse the elements and return the slice
        for (slice, 0..) |*elem, i| {
            errdefer if (self.options.free_on_error) {
                for (slice[0..i]) |item| {
                    free(self.gpa, item);
                }
            };
            elem.* = try self.parseExpr(pointer.child, nodes.at(@intCast(i)));
        }

        return slice;
    }

    fn parseArray(self: *@This(), T: type, node: Zoir.Node.Index) !T {
        const nodes: Zoir.Node.Index.Range = switch (node.get(self.zoir)) {
            .array_literal => |nodes| nodes,
            .empty_literal => .{ .start = node, .len = 0 },
            else => return error.WrongType,
        };

        const array_info = @typeInfo(T).array;

        // Check if the size matches
        if (nodes.len < array_info.len) {
            return self.failNodeFmt(
                node,
                "expected {} array elements; found {}",
                .{ array_info.len, nodes.len },
            );
        } else if (nodes.len > array_info.len) {
            return self.failNodeFmt(
                nodes.at(array_info.len),
                "index {} outside of array of length {}",
                .{ array_info.len, array_info.len },
            );
        }

        // Parse the elements and return the array
        var result: T = undefined;
        for (&result, 0..) |*elem, i| {
            // If we fail to parse this field, free all fields before it
            errdefer if (self.options.free_on_error) {
                for (result[0..i]) |item| {
                    free(self.gpa, item);
                }
            };

            elem.* = try self.parseExpr(array_info.child, nodes.at(@intCast(i)));
        }
        return result;
    }

    fn parseStruct(self: *@This(), T: type, node: Zoir.Node.Index) !T {
        const repr = node.get(self.zoir);
        const fields: @FieldType(Zoir.Node, "struct_literal") = switch (repr) {
            .struct_literal => |nodes| nodes,
            .empty_literal => .{ .names = &.{}, .vals = .{ .start = node, .len = 0 } },
            else => return error.WrongType,
        };

        const field_infos = @typeInfo(T).@"struct".fields;

        // Build a map from field name to index.
        // The special value `comptime_field` indicates that this is actually a comptime field.
        const comptime_field = std.math.maxInt(usize);
        const field_indices: std.StaticStringMap(usize) = comptime b: {
            var kvs_list: [field_infos.len]struct { []const u8, usize } = undefined;
            for (&kvs_list, field_infos, 0..) |*kv, field, i| {
                kv.* = .{ field.name, if (field.is_comptime) comptime_field else i };
            }
            break :b .initComptime(kvs_list);
        };

        // Parse the struct
        var result: T = undefined;
        var field_found: [field_infos.len]bool = @splat(false);

        // If we fail partway through, free all already initialized fields
        var initialized: usize = 0;
        errdefer if (self.options.free_on_error and field_infos.len > 0) {
            for (fields.names[0..initialized]) |name_runtime| {
                switch (field_indices.get(name_runtime.get(self.zoir)) orelse continue) {
                    inline 0...(field_infos.len - 1) => |name_index| {
                        const name = field_infos[name_index].name;
                        free(self.gpa, @field(result, name));
                    },
                    else => unreachable, // Can't be out of bounds
                }
            }
        };

        // Fill in the fields we found
        for (0..fields.names.len) |i| {
            const name = fields.names[i].get(self.zoir);
            const field_index = field_indices.get(name) orelse {
                if (self.options.ignore_unknown_fields) continue;
                return self.failUnexpected(T, "field", node, i, name);
            };
            if (field_index == comptime_field) {
                return self.failComptimeField(node, i);
            }

            // Mark the field as found. Assert that the found array is not zero length to satisfy
            // the type checker (it can't be since we made it into an iteration of this loop.)
            if (field_found.len == 0) unreachable;
            field_found[field_index] = true;

            switch (field_index) {
                inline 0...(field_infos.len - 1) => |j| {
                    if (field_infos[j].is_comptime) unreachable;

                    @field(result, field_infos[j].name) = try self.parseExpr(
                        field_infos[j].type,
                        fields.vals.at(@intCast(i)),
                    );
                },
                else => unreachable, // Can't be out of bounds
            }

            initialized += 1;
        }

        // Fill in any missing default fields
        inline for (field_found, 0..) |found, i| {
            if (!found) {
                const field_info = field_infos[i];
                if (field_info.default_value_ptr) |default| {
                    const typed: *const field_info.type = @ptrCast(@alignCast(default));
                    @field(result, field_info.name) = typed.*;
                } else {
                    return self.failNodeFmt(
                        node,
                        "missing required field {s}",
                        .{field_infos[i].name},
                    );
                }
            }
        }

        return result;
    }

    fn parseTuple(self: *@This(), T: type, node: Zoir.Node.Index) !T {
        const nodes: Zoir.Node.Index.Range = switch (node.get(self.zoir)) {
            .array_literal => |nodes| nodes,
            .empty_literal => .{ .start = node, .len = 0 },
            else => return error.WrongType,
        };

        var result: T = undefined;
        const field_infos = @typeInfo(T).@"struct".fields;

        if (nodes.len > field_infos.len) {
            return self.failNodeFmt(
                nodes.at(field_infos.len),
                "index {} outside of tuple length {}",
                .{ field_infos.len, field_infos.len },
            );
        }

        inline for (0..field_infos.len) |i| {
            // Check if we're out of bounds
            if (i >= nodes.len) {
                if (field_infos[i].default_value_ptr) |default| {
                    const typed: *const field_infos[i].type = @ptrCast(@alignCast(default));
                    @field(result, field_infos[i].name) = typed.*;
                } else {
                    return self.failNodeFmt(node, "missing tuple field with index {}", .{i});
                }
            } else {
                // If we fail to parse this field, free all fields before it
                errdefer if (self.options.free_on_error) {
                    inline for (0..i) |j| {
                        if (j >= i) break;
                        free(self.gpa, result[j]);
                    }
                };

                if (field_infos[i].is_comptime) {
                    return self.failComptimeField(node, i);
                } else {
                    result[i] = try self.parseExpr(field_infos[i].type, nodes.at(i));
                }
            }
        }

        return result;
    }

    fn parseUnion(self: *@This(), T: type, node: Zoir.Node.Index) !T {
        const @"union" = @typeInfo(T).@"union";
        const field_infos = @"union".fields;

        if (field_infos.len == 0) comptime unreachable;

        // Gather info on the fields
        const field_indices = b: {
            comptime var kvs_list: [field_infos.len]struct { []const u8, usize } = undefined;
            inline for (field_infos, 0..) |field, i| {
                kvs_list[i] = .{ field.name, i };
            }
            break :b std.StaticStringMap(usize).initComptime(kvs_list);
        };

        // Parse the union
        switch (node.get(self.zoir)) {
            .enum_literal => |field_name| {
                // The union must be tagged for an enum literal to coerce to it
                if (@"union".tag_type == null) {
                    return error.WrongType;
                }

                // Get the index of the named field. We don't use `parseEnum` here as
                // the order of the enum and the order of the union might not match!
                const field_index = b: {
                    const field_name_str = field_name.get(self.zoir);
                    break :b field_indices.get(field_name_str) orelse
                        return self.failUnexpected(T, "field", node, null, field_name_str);
                };

                // Initialize the union from the given field.
                switch (field_index) {
                    inline 0...field_infos.len - 1 => |i| {
                        // Fail if the field is not void
                        if (field_infos[i].type != void)
                            return self.failNode(node, "expected union");

                        // Instantiate the union
                        return @unionInit(T, field_infos[i].name, {});
                    },
                    else => unreachable, // Can't be out of bounds
                }
            },
            .struct_literal => |struct_fields| {
                if (struct_fields.names.len != 1) {
                    return error.WrongType;
                }

                // Fill in the field we found
                const field_name = struct_fields.names[0];
                const field_name_str = field_name.get(self.zoir);
                const field_val = struct_fields.vals.at(0);
                const field_index = field_indices.get(field_name_str) orelse
                    return self.failUnexpected(T, "field", node, 0, field_name_str);

                switch (field_index) {
                    inline 0...field_infos.len - 1 => |i| {
                        if (field_infos[i].type == void) {
                            return self.failNode(field_val, "expected type 'void'");
                        } else {
                            const value = try self.parseExpr(field_infos[i].type, field_val);
                            return @unionInit(T, field_infos[i].name, value);
                        }
                    },
                    else => unreachable, // Can't be out of bounds
                }
            },
            else => return error.WrongType,
        }
    }

    fn parseVector(
        self: *@This(),
        T: type,
        node: Zoir.Node.Index,
    ) !T {
        const vector_info = @typeInfo(T).vector;

        const nodes: Zoir.Node.Index.Range = switch (node.get(self.zoir)) {
            .array_literal => |nodes| nodes,
            .empty_literal => .{ .start = node, .len = 0 },
            else => return error.WrongType,
        };

        var result: T = undefined;

        if (nodes.len != vector_info.len) {
            return self.failNodeFmt(
                node,
                "expected {} vector elements; found {}",
                .{ vector_info.len, nodes.len },
            );
        }

        for (0..vector_info.len) |i| {
            errdefer for (0..i) |j| free(self.gpa, result[j]);
            result[i] = try self.parseExpr(vector_info.child, nodes.at(@intCast(i)));
        }

        return result;
    }

    fn failTokenFmt(
        self: @This(),
        token: Ast.TokenIndex,
        offset: u32,
        comptime fmt: []const u8,
        args: anytype,
    ) error{ OutOfMemory, ParseZon } {
        @branchHint(.cold);
        return self.failTokenFmtNote(token, offset, fmt, args, null);
    }

    fn failTokenFmtNote(
        self: @This(),
        token: Ast.TokenIndex,
        offset: u32,
        comptime fmt: []const u8,
        args: anytype,
        note: ?Error.TypeCheckFailure.Note,
    ) error{ OutOfMemory, ParseZon } {
        @branchHint(.cold);
        comptime assert(args.len > 0);
        if (self.diag) |s| s.type_check = .{
            .token = token,
            .offset = offset,
            .message = std.fmt.allocPrint(self.gpa, fmt, args) catch |err| {
                if (note) |n| n.deinit(self.gpa);
                return err;
            },
            .owned = true,
            .note = note,
        };
        return error.ParseZon;
    }

    fn failNodeFmt(
        self: @This(),
        node: Zoir.Node.Index,
        comptime fmt: []const u8,
        args: anytype,
    ) error{ OutOfMemory, ParseZon } {
        @branchHint(.cold);
        const token = self.ast.nodeMainToken(node.getAstNode(self.zoir));
        return self.failTokenFmt(token, 0, fmt, args);
    }

    fn failToken(
        self: @This(),
        failure: Error.TypeCheckFailure,
    ) error{ParseZon} {
        @branchHint(.cold);
        if (self.diag) |s| s.type_check = failure;
        return error.ParseZon;
    }

    fn failNode(
        self: @This(),
        node: Zoir.Node.Index,
        message: []const u8,
    ) error{ParseZon} {
        @branchHint(.cold);
        const token = self.ast.nodeMainToken(node.getAstNode(self.zoir));
        return self.failToken(.{
            .token = token,
            .offset = 0,
            .message = message,
            .owned = false,
            .note = null,
        });
    }

    fn failCannotRepresent(
        self: @This(),
        T: type,
        node: Zoir.Node.Index,
    ) error{ OutOfMemory, ParseZon } {
        @branchHint(.cold);
        return self.failNodeFmt(node, "type '{s}' cannot represent value", .{@typeName(T)});
    }

    fn failUnexpected(
        self: @This(),
        T: type,
        item_kind: []const u8,
        node: Zoir.Node.Index,
        field: ?usize,
        name: []const u8,
    ) error{ OutOfMemory, ParseZon } {
        @branchHint(.cold);
        const token = if (field) |f| b: {
            var buf: [2]Ast.Node.Index = undefined;
            const struct_init = self.ast.fullStructInit(&buf, node.getAstNode(self.zoir)).?;
            const field_node = struct_init.ast.fields[f];
            break :b self.ast.firstToken(field_node) - 2;
        } else self.ast.nodeMainToken(node.getAstNode(self.zoir));
        switch (@typeInfo(T)) {
            inline .@"struct", .@"union", .@"enum" => |info| {
                const note: Error.TypeCheckFailure.Note = if (info.fields.len == 0) b: {
                    break :b .{
                        .token = token,
                        .offset = 0,
                        .msg = "none expected",
                        .owned = false,
                    };
                } else b: {
                    const msg = "supported: ";
                    var buf: std.ArrayListUnmanaged(u8) = try .initCapacity(self.gpa, 64);
                    defer buf.deinit(self.gpa);
                    const writer = buf.writer(self.gpa);
                    try writer.writeAll(msg);
                    inline for (info.fields, 0..) |field_info, i| {
                        if (i != 0) try writer.writeAll(", ");
                        try writer.print("'{p_}'", .{std.zig.fmtId(field_info.name)});
                    }
                    break :b .{
                        .token = token,
                        .offset = 0,
                        .msg = try buf.toOwnedSlice(self.gpa),
                        .owned = true,
                    };
                };
                return self.failTokenFmtNote(
                    token,
                    0,
                    "unexpected {s} '{s}'",
                    .{ item_kind, name },
                    note,
                );
            },
            else => comptime unreachable,
        }
    }

    // Technically we could do this if we were willing to do a deep equal to verify
    // the value matched, but doing so doesn't seem to support any real use cases
    // so isn't worth the complexity at the moment.
    fn failComptimeField(
        self: @This(),
        node: Zoir.Node.Index,
        field: usize,
    ) error{ OutOfMemory, ParseZon } {
        @branchHint(.cold);
        const ast_node = node.getAstNode(self.zoir);
        var buf: [2]Ast.Node.Index = undefined;
        const token = if (self.ast.fullStructInit(&buf, ast_node)) |struct_init| b: {
            const field_node = struct_init.ast.fields[field];
            break :b self.ast.firstToken(field_node);
        } else b: {
            const array_init = self.ast.fullArrayInit(&buf, ast_node).?;
            const value_node = array_init.ast.elements[field];
            break :b self.ast.firstToken(value_node);
        };
        return self.failToken(.{
            .token = token,
            .offset = 0,
            .message = "cannot initialize comptime field",
            .owned = false,
            .note = null,
        });
    }
};

fn intFromFloatExact(T: type, value: anytype) ?T {
    if (value > std.math.maxInt(T) or value < std.math.minInt(T)) {
        return null;
    }

    if (std.math.isNan(value) or std.math.trunc(value) != value) {
        return null;
    }

    return @intFromFloat(value);
}

fn canParseType(T: type) bool {
    comptime return canParseTypeInner(T, &.{}, false);
}

fn canParseTypeInner(
    T: type,
    /// Visited structs and unions, to avoid infinite recursion.
    /// Tracking more types is unnecessary, and a little complex due to optional nesting.
    visited: []const type,
    parent_is_optional: bool,
) bool {
    return switch (@typeInfo(T)) {
        .bool,
        .int,
        .float,
        .null,
        .@"enum",
        => true,

        .noreturn,
        .void,
        .type,
        .undefined,
        .error_union,
        .error_set,
        .@"fn",
        .frame,
        .@"anyframe",
        .@"opaque",
        .comptime_int,
        .comptime_float,
        .enum_literal,
        => false,

        .pointer => |pointer| switch (pointer.size) {
            .one => canParseTypeInner(pointer.child, visited, parent_is_optional),
            .slice => canParseTypeInner(pointer.child, visited, false),
            .many, .c => false,
        },

        .optional => |optional| if (parent_is_optional)
            false
        else
            canParseTypeInner(optional.child, visited, true),

        .array => |array| canParseTypeInner(array.child, visited, false),
        .vector => |vector| canParseTypeInner(vector.child, visited, false),

        .@"struct" => |@"struct"| {
            for (visited) |V| if (T == V) return true;
            const new_visited = visited ++ .{T};
            for (@"struct".fields) |field| {
                if (!field.is_comptime and !canParseTypeInner(field.type, new_visited, false)) {
                    return false;
                }
            }
            return true;
        },
        .@"union" => |@"union"| {
            for (visited) |V| if (T == V) return true;
            const new_visited = visited ++ .{T};
            for (@"union".fields) |field| {
                if (field.type != void and !canParseTypeInner(field.type, new_visited, false)) {
                    return false;
                }
            }
            return true;
        },
    };
}

test "std.zon parse canParseType" {
    try std.testing.expect(!comptime canParseType(void));
    try std.testing.expect(!comptime canParseType(struct { f: [*]u8 }));
    try std.testing.expect(!comptime canParseType(struct { error{foo} }));
    try std.testing.expect(!comptime canParseType(union(enum) { a: void, b: [*c]u8 }));
    try std.testing.expect(!comptime canParseType(@Vector(0, [*c]u8)));
    try std.testing.expect(!comptime canParseType(*?[*c]u8));
    try std.testing.expect(comptime canParseType(enum(u8) { _ }));
    try std.testing.expect(comptime canParseType(union { foo: void }));
    try std.testing.expect(comptime canParseType(union(enum) { foo: void }));
    try std.testing.expect(!comptime canParseType(comptime_float));
    try std.testing.expect(!comptime canParseType(comptime_int));
    try std.testing.expect(comptime canParseType(struct { comptime foo: ??u8 = null }));
    try std.testing.expect(!comptime canParseType(@TypeOf(.foo)));
    try std.testing.expect(comptime canParseType(?u8));
    try std.testing.expect(comptime canParseType(*?*u8));
    try std.testing.expect(comptime canParseType(?struct {
        foo: ?struct {
            ?union(enum) {
                a: ?@Vector(0, ?*u8),
            },
            ?struct {
                f: ?[]?u8,
            },
        },
    }));
    try std.testing.expect(!comptime canParseType(??u8));
    try std.testing.expect(!comptime canParseType(?*?u8));
    try std.testing.expect(!comptime canParseType(*?*?*u8));
    try std.testing.expect(!comptime canParseType(struct { x: comptime_int = 2 }));
    try std.testing.expect(!comptime canParseType(struct { x: comptime_float = 2 }));
    try std.testing.expect(comptime canParseType(struct { comptime x: @TypeOf(.foo) = .foo }));
    try std.testing.expect(!comptime canParseType(struct { comptime_int }));
    const Recursive = struct { foo: ?*@This() };
    try std.testing.expect(comptime canParseType(Recursive));

    // Make sure we validate nested optional before we early out due to already having seen
    // a type recursion!
    try std.testing.expect(!comptime canParseType(struct {
        add_to_visited: ?u8,
        retrieve_from_visited: ??u8,
    }));
}

test "std.zon requiresAllocator" {
    try std.testing.expect(!requiresAllocator(u8));
    try std.testing.expect(!requiresAllocator(f32));
    try std.testing.expect(!requiresAllocator(enum { foo }));
    try std.testing.expect(!requiresAllocator(struct { f32 }));
    try std.testing.expect(!requiresAllocator(struct { x: f32 }));
    try std.testing.expect(!requiresAllocator([0][]const u8));
    try std.testing.expect(!requiresAllocator([2]u8));
    try std.testing.expect(!requiresAllocator(union { x: f32, y: f32 }));
    try std.testing.expect(!requiresAllocator(union(enum) { x: f32, y: f32 }));
    try std.testing.expect(!requiresAllocator(?f32));
    try std.testing.expect(!requiresAllocator(void));
    try std.testing.expect(!requiresAllocator(@TypeOf(null)));
    try std.testing.expect(!requiresAllocator(@Vector(3, u8)));
    try std.testing.expect(!requiresAllocator(@Vector(0, *const u8)));

    try std.testing.expect(requiresAllocator([]u8));
    try std.testing.expect(requiresAllocator(*struct { u8, u8 }));
    try std.testing.expect(requiresAllocator([1][]const u8));
    try std.testing.expect(requiresAllocator(struct { x: i32, y: []u8 }));
    try std.testing.expect(requiresAllocator(union { x: i32, y: []u8 }));
    try std.testing.expect(requiresAllocator(union(enum) { x: i32, y: []u8 }));
    try std.testing.expect(requiresAllocator(?[]u8));
    try std.testing.expect(requiresAllocator(@Vector(3, *const u8)));
}

test "std.zon ast errors" {
    const gpa = std.testing.allocator;
    var diag: Diagnostics = .{};
    defer diag.deinit(gpa);
    try std.testing.expectError(
        error.ParseZon,
        fromSlice(struct {}, gpa, ".{.x = 1 .y = 2}", &diag, .{}),
    );
    try std.testing.expectFmt("1:13: error: expected ',' after initializer\n", "{}", .{diag});
}

test "std.zon comments" {
    const gpa = std.testing.allocator;

    try std.testing.expectEqual(@as(u8, 10), fromSlice(u8, gpa,
        \\// comment
        \\10 // comment
        \\// comment
    , null, .{}));

    {
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(error.ParseZon, fromSlice(u8, gpa,
            \\//! comment
            \\10 // comment
            \\// comment
        , &diag, .{}));
        try std.testing.expectFmt(
            "1:1: error: expected expression, found 'a document comment'\n",
            "{}",
            .{diag},
        );
    }
}

test "std.zon failure/oom formatting" {
    const gpa = std.testing.allocator;
    var failing_allocator = std.testing.FailingAllocator.init(gpa, .{
        .fail_index = 0,
        .resize_fail_index = 0,
    });
    var diag: Diagnostics = .{};
    defer diag.deinit(gpa);
    try std.testing.expectError(error.OutOfMemory, fromSlice(
        []const u8,
        failing_allocator.allocator(),
        "\"foo\"",
        &diag,
        .{},
    ));
    try std.testing.expectFmt("", "{}", .{diag});
}

test "std.zon fromSlice syntax error" {
    try std.testing.expectError(
        error.ParseZon,
        fromSlice(u8, std.testing.allocator, ".{", null, .{}),
    );
}

test "std.zon optional" {
    const gpa = std.testing.allocator;

    // Basic usage
    {
        const none = try fromSlice(?u32, gpa, "null", null, .{});
        try std.testing.expect(none == null);
        const some = try fromSlice(?u32, gpa, "1", null, .{});
        try std.testing.expect(some.? == 1);
    }

    // Deep free
    {
        const none = try fromSlice(?[]const u8, gpa, "null", null, .{});
        try std.testing.expect(none == null);
        const some = try fromSlice(?[]const u8, gpa, "\"foo\"", null, .{});
        defer free(gpa, some);
        try std.testing.expectEqualStrings("foo", some.?);
    }
}

test "std.zon unions" {
    const gpa = std.testing.allocator;

    // Unions
    {
        const Tagged = union(enum) { x: f32, @"y y": bool, z, @"z z" };
        const Untagged = union { x: f32, @"y y": bool, z: void, @"z z": void };

        const tagged_x = try fromSlice(Tagged, gpa, ".{.x = 1.5}", null, .{});
        try std.testing.expectEqual(Tagged{ .x = 1.5 }, tagged_x);
        const tagged_y = try fromSlice(Tagged, gpa, ".{.@\"y y\" = true}", null, .{});
        try std.testing.expectEqual(Tagged{ .@"y y" = true }, tagged_y);
        const tagged_z_shorthand = try fromSlice(Tagged, gpa, ".z", null, .{});
        try std.testing.expectEqual(@as(Tagged, .z), tagged_z_shorthand);
        const tagged_zz_shorthand = try fromSlice(Tagged, gpa, ".@\"z z\"", null, .{});
        try std.testing.expectEqual(@as(Tagged, .@"z z"), tagged_zz_shorthand);

        const untagged_x = try fromSlice(Untagged, gpa, ".{.x = 1.5}", null, .{});
        try std.testing.expect(untagged_x.x == 1.5);
        const untagged_y = try fromSlice(Untagged, gpa, ".{.@\"y y\" = true}", null, .{});
        try std.testing.expect(untagged_y.@"y y");
    }

    // Deep free
    {
        const Union = union(enum) { bar: []const u8, baz: bool };

        const noalloc = try fromSlice(Union, gpa, ".{.baz = false}", null, .{});
        try std.testing.expectEqual(Union{ .baz = false }, noalloc);

        const alloc = try fromSlice(Union, gpa, ".{.bar = \"qux\"}", null, .{});
        defer free(gpa, alloc);
        try std.testing.expectEqualDeep(Union{ .bar = "qux" }, alloc);
    }

    // Unknown field
    {
        const Union = union { x: f32, y: f32 };
        var diag: Diagnostics = .{};
        defer diag.deinit(gpa);
        try std.testing.expectError(
            error.ParseZon,
            fromSlice(Union, gpa, ".{.z=2.5}", &diag, .{}),
        );
        try std.testing.expectFmt(
            \\1:4: error: unexpected field 'z'
            \\1:4: note: supported: 'x', 'y'
            \\
        ,
            "{}",
            .{diag},
        );
    }

    // Explicit void field
    {
        const Union = union(enum) { x: void };
        var diag: Diagnostics = .{};
        d```
