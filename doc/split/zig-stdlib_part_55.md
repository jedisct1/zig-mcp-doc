```
ub_path, open_dir_options) catch |err| switch (err) {
                error.FileNotFound => {
                    try self.makePath(sub_path);
                    return self.openDir(sub_path, open_dir_options);
                },
                else => |e| return e,
            };
        },
    };
}

pub const RealPathError = posix.RealPathError;

///  This function returns the canonicalized absolute pathname of
/// `pathname` relative to this `Dir`. If `pathname` is absolute, ignores this
/// `Dir` handle and returns the canonicalized absolute pathname of `pathname`
/// argument.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
/// On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
/// This function is not universally supported by all platforms.
/// Currently supported hosts are: Linux, macOS, and Windows.
/// See also `Dir.realpathZ`, `Dir.realpathW`, and `Dir.realpathAlloc`.
pub fn realpath(self: Dir, pathname: []const u8, out_buffer: []u8) RealPathError![]u8 {
    if (native_os == .wasi) {
        @compileError("realpath is not available on WASI");
    }
    if (native_os == .windows) {
        const pathname_w = try windows.sliceToPrefixedFileW(self.fd, pathname);
        return self.realpathW(pathname_w.span(), out_buffer);
    }
    const pathname_c = try posix.toPosixPath(pathname);
    return self.realpathZ(&pathname_c, out_buffer);
}

/// Same as `Dir.realpath` except `pathname` is null-terminated.
/// See also `Dir.realpath`, `realpathZ`.
pub fn realpathZ(self: Dir, pathname: [*:0]const u8, out_buffer: []u8) RealPathError![]u8 {
    if (native_os == .windows) {
        const pathname_w = try windows.cStrToPrefixedFileW(self.fd, pathname);
        return self.realpathW(pathname_w.span(), out_buffer);
    }

    var flags: posix.O = .{};
    if (@hasField(posix.O, "NONBLOCK")) flags.NONBLOCK = true;
    if (@hasField(posix.O, "CLOEXEC")) flags.CLOEXEC = true;
    if (@hasField(posix.O, "PATH")) flags.PATH = true;

    const fd = posix.openatZ(self.fd, pathname, flags, 0) catch |err| switch (err) {
        error.FileLocksNotSupported => return error.Unexpected,
        error.FileBusy => return error.Unexpected,
        error.WouldBlock => return error.Unexpected,
        error.InvalidUtf8 => unreachable, // WASI-only
        else => |e| return e,
    };
    defer posix.close(fd);

    var buffer: [fs.max_path_bytes]u8 = undefined;
    const out_path = try std.os.getFdPath(fd, &buffer);

    if (out_path.len > out_buffer.len) {
        return error.NameTooLong;
    }

    const result = out_buffer[0..out_path.len];
    @memcpy(result, out_path);
    return result;
}

/// Windows-only. Same as `Dir.realpath` except `pathname` is WTF16 LE encoded.
/// The result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// See also `Dir.realpath`, `realpathW`.
pub fn realpathW(self: Dir, pathname: []const u16, out_buffer: []u8) RealPathError![]u8 {
    const w = windows;

    const access_mask = w.GENERIC_READ | w.SYNCHRONIZE;
    const share_access = w.FILE_SHARE_READ | w.FILE_SHARE_WRITE | w.FILE_SHARE_DELETE;
    const creation = w.FILE_OPEN;
    const h_file = blk: {
        const res = w.OpenFile(pathname, .{
            .dir = self.fd,
            .access_mask = access_mask,
            .share_access = share_access,
            .creation = creation,
            .filter = .any,
        }) catch |err| switch (err) {
            error.WouldBlock => unreachable,
            else => |e| return e,
        };
        break :blk res;
    };
    defer w.CloseHandle(h_file);

    var wide_buf: [w.PATH_MAX_WIDE]u16 = undefined;
    const wide_slice = try w.GetFinalPathNameByHandle(h_file, .{}, &wide_buf);
    const len = std.unicode.calcWtf8Len(wide_slice);
    if (len > out_buffer.len)
        return error.NameTooLong;
    const end_index = std.unicode.wtf16LeToWtf8(out_buffer, wide_slice);
    return out_buffer[0..end_index];
}

pub const RealPathAllocError = RealPathError || Allocator.Error;

/// Same as `Dir.realpath` except caller must free the returned memory.
/// See also `Dir.realpath`.
pub fn realpathAlloc(self: Dir, allocator: Allocator, pathname: []const u8) RealPathAllocError![]u8 {
    // Use of max_path_bytes here is valid as the realpath function does not
    // have a variant that takes an arbitrary-size buffer.
    // TODO(#4812): Consider reimplementing realpath or using the POSIX.1-2008
    // NULL out parameter (GNU's canonicalize_file_name) to handle overelong
    // paths. musl supports passing NULL but restricts the output to PATH_MAX
    // anyway.
    var buf: [fs.max_path_bytes]u8 = undefined;
    return allocator.dupe(u8, try self.realpath(pathname, buf[0..]));
}

/// Changes the current working directory to the open directory handle.
/// This modifies global state and can have surprising effects in multi-
/// threaded applications. Most applications and especially libraries should
/// not call this function as a general rule, however it can have use cases
/// in, for example, implementing a shell, or child process execution.
/// Not all targets support this. For example, WASI does not have the concept
/// of a current working directory.
pub fn setAsCwd(self: Dir) !void {
    if (native_os == .wasi) {
        @compileError("changing cwd is not currently possible in WASI");
    }
    if (native_os == .windows) {
        var dir_path_buffer: [windows.PATH_MAX_WIDE]u16 = undefined;
        const dir_path = try windows.GetFinalPathNameByHandle(self.fd, .{}, &dir_path_buffer);
        if (builtin.link_libc) {
            return posix.chdirW(dir_path);
        }
        return windows.SetCurrentDirectory(dir_path);
    }
    try posix.fchdir(self.fd);
}

/// Deprecated: use `OpenOptions`
pub const OpenDirOptions = OpenOptions;

pub const OpenOptions = struct {
    /// `true` means the opened directory can be used as the `Dir` parameter
    /// for functions which operate based on an open directory handle. When `false`,
    /// such operations are Illegal Behavior.
    access_sub_paths: bool = true,

    /// `true` means the opened directory can be scanned for the files and sub-directories
    /// of the result. It means the `iterate` function can be called.
    iterate: bool = false,

    /// `true` means it won't dereference the symlinks.
    no_follow: bool = false,
};

/// Opens a directory at the given path. The directory is a system resource that remains
/// open until `close` is called on the result.
/// The directory cannot be iterated unless the `iterate` option is set to `true`.
///
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
/// Asserts that the path parameter has no null bytes.
pub fn openDir(self: Dir, sub_path: []const u8, args: OpenOptions) OpenError!Dir {
    switch (native_os) {
        .windows => {
            const sub_path_w = try windows.sliceToPrefixedFileW(self.fd, sub_path);
            return self.openDirW(sub_path_w.span().ptr, args);
        },
        .wasi => if (!builtin.link_libc) {
            var base: std.os.wasi.rights_t = .{
                .FD_FILESTAT_GET = true,
                .FD_FDSTAT_SET_FLAGS = true,
                .FD_FILESTAT_SET_TIMES = true,
            };
            if (args.access_sub_paths) {
                base.FD_READDIR = true;
                base.PATH_CREATE_DIRECTORY = true;
                base.PATH_CREATE_FILE = true;
                base.PATH_LINK_SOURCE = true;
                base.PATH_LINK_TARGET = true;
                base.PATH_OPEN = true;
                base.PATH_READLINK = true;
                base.PATH_RENAME_SOURCE = true;
                base.PATH_RENAME_TARGET = true;
                base.PATH_FILESTAT_GET = true;
                base.PATH_FILESTAT_SET_SIZE = true;
                base.PATH_FILESTAT_SET_TIMES = true;
                base.PATH_SYMLINK = true;
                base.PATH_REMOVE_DIRECTORY = true;
                base.PATH_UNLINK_FILE = true;
            }

            const result = posix.openatWasi(
                self.fd,
                sub_path,
                .{ .SYMLINK_FOLLOW = !args.no_follow },
                .{ .DIRECTORY = true },
                .{},
                base,
                base,
            );
            const fd = result catch |err| switch (err) {
                error.FileTooBig => unreachable, // can't happen for directories
                error.IsDir => unreachable, // we're setting DIRECTORY
                error.NoSpaceLeft => unreachable, // not setting CREAT
                error.PathAlreadyExists => unreachable, // not setting CREAT
                error.FileLocksNotSupported => unreachable, // locking folders is not supported
                error.WouldBlock => unreachable, // can't happen for directories
                error.FileBusy => unreachable, // can't happen for directories
                else => |e| return e,
            };
            return .{ .fd = fd };
        },
        else => {},
    }
    const sub_path_c = try posix.toPosixPath(sub_path);
    return self.openDirZ(&sub_path_c, args);
}

/// Same as `openDir` except the parameter is null-terminated.
pub fn openDirZ(self: Dir, sub_path_c: [*:0]const u8, args: OpenOptions) OpenError!Dir {
    switch (native_os) {
        .windows => {
            const sub_path_w = try windows.cStrToPrefixedFileW(self.fd, sub_path_c);
            return self.openDirW(sub_path_w.span().ptr, args);
        },
        // Use the libc API when libc is linked because it implements things
        // such as opening absolute directory paths.
        .wasi => if (!builtin.link_libc) {
            return openDir(self, mem.sliceTo(sub_path_c, 0), args);
        },
        .haiku => {
            const rc = posix.system._kern_open_dir(self.fd, sub_path_c);
            if (rc >= 0) return .{ .fd = rc };
            switch (@as(posix.E, @enumFromInt(rc))) {
                .FAULT => unreachable,
                .INVAL => unreachable,
                .BADF => unreachable,
                .ACCES => return error.AccessDenied,
                .LOOP => return error.SymLinkLoop,
                .MFILE => return error.ProcessFdQuotaExceeded,
                .NAMETOOLONG => return error.NameTooLong,
                .NFILE => return error.SystemFdQuotaExceeded,
                .NODEV => return error.NoDevice,
                .NOENT => return error.FileNotFound,
                .NOMEM => return error.SystemResources,
                .NOTDIR => return error.NotDir,
                .PERM => return error.PermissionDenied,
                .BUSY => return error.DeviceBusy,
                else => |err| return posix.unexpectedErrno(err),
            }
        },
        else => {},
    }

    var symlink_flags: posix.O = switch (native_os) {
        .wasi => .{
            .read = true,
            .NOFOLLOW = args.no_follow,
            .DIRECTORY = true,
        },
        else => .{
            .ACCMODE = .RDONLY,
            .NOFOLLOW = args.no_follow,
            .DIRECTORY = true,
            .CLOEXEC = true,
        },
    };

    if (@hasField(posix.O, "PATH") and !args.iterate)
        symlink_flags.PATH = true;

    return self.openDirFlagsZ(sub_path_c, symlink_flags);
}

/// Same as `openDir` except the path parameter is WTF-16 LE encoded, NT-prefixed.
/// This function asserts the target OS is Windows.
pub fn openDirW(self: Dir, sub_path_w: [*:0]const u16, args: OpenOptions) OpenError!Dir {
    const w = windows;
    // TODO remove some of these flags if args.access_sub_paths is false
    const base_flags = w.STANDARD_RIGHTS_READ | w.FILE_READ_ATTRIBUTES | w.FILE_READ_EA |
        w.SYNCHRONIZE | w.FILE_TRAVERSE;
    const flags: u32 = if (args.iterate) base_flags | w.FILE_LIST_DIRECTORY else base_flags;
    const dir = self.makeOpenDirAccessMaskW(sub_path_w, flags, .{
        .no_follow = args.no_follow,
        .create_disposition = w.FILE_OPEN,
    }) catch |err| switch (err) {
        error.ReadOnlyFileSystem => unreachable,
        error.DiskQuota => unreachable,
        error.NoSpaceLeft => unreachable,
        error.PathAlreadyExists => unreachable,
        error.LinkQuotaExceeded => unreachable,
        else => |e| return e,
    };
    return dir;
}

/// Asserts `flags` has `DIRECTORY` set.
fn openDirFlagsZ(self: Dir, sub_path_c: [*:0]const u8, flags: posix.O) OpenError!Dir {
    assert(flags.DIRECTORY);
    const fd = posix.openatZ(self.fd, sub_path_c, flags, 0) catch |err| switch (err) {
        error.FileTooBig => unreachable, // can't happen for directories
        error.IsDir => unreachable, // we're setting DIRECTORY
        error.NoSpaceLeft => unreachable, // not setting CREAT
        error.PathAlreadyExists => unreachable, // not setting CREAT
        error.FileLocksNotSupported => unreachable, // locking folders is not supported
        error.WouldBlock => unreachable, // can't happen for directories
        error.FileBusy => unreachable, // can't happen for directories
        else => |e| return e,
    };
    return Dir{ .fd = fd };
}

const MakeOpenDirAccessMaskWOptions = struct {
    no_follow: bool,
    create_disposition: u32,
};

fn makeOpenDirAccessMaskW(self: Dir, sub_path_w: [*:0]const u16, access_mask: u32, flags: MakeOpenDirAccessMaskWOptions) (MakeError || OpenError)!Dir {
    const w = windows;

    var result = Dir{
        .fd = undefined,
    };

    const path_len_bytes = @as(u16, @intCast(mem.sliceTo(sub_path_w, 0).len * 2));
    var nt_name = w.UNICODE_STRING{
        .Length = path_len_bytes,
        .MaximumLength = path_len_bytes,
        .Buffer = @constCast(sub_path_w),
    };
    var attr = w.OBJECT_ATTRIBUTES{
        .Length = @sizeOf(w.OBJECT_ATTRIBUTES),
        .RootDirectory = if (fs.path.isAbsoluteWindowsW(sub_path_w)) null else self.fd,
        .Attributes = 0, // Note we do not use OBJ_CASE_INSENSITIVE here.
        .ObjectName = &nt_name,
        .SecurityDescriptor = null,
        .SecurityQualityOfService = null,
    };
    const open_reparse_point: w.DWORD = if (flags.no_follow) w.FILE_OPEN_REPARSE_POINT else 0x0;
    var io: w.IO_STATUS_BLOCK = undefined;
    const rc = w.ntdll.NtCreateFile(
        &result.fd,
        access_mask,
        &attr,
        &io,
        null,
        w.FILE_ATTRIBUTE_NORMAL,
        w.FILE_SHARE_READ | w.FILE_SHARE_WRITE | w.FILE_SHARE_DELETE,
        flags.create_disposition,
        w.FILE_DIRECTORY_FILE | w.FILE_SYNCHRONOUS_IO_NONALERT | w.FILE_OPEN_FOR_BACKUP_INTENT | open_reparse_point,
        null,
        0,
    );

    switch (rc) {
        .SUCCESS => return result,
        .OBJECT_NAME_INVALID => return error.BadPathName,
        .OBJECT_NAME_NOT_FOUND => return error.FileNotFound,
        .OBJECT_NAME_COLLISION => return error.PathAlreadyExists,
        .OBJECT_PATH_NOT_FOUND => return error.FileNotFound,
        .NOT_A_DIRECTORY => return error.NotDir,
        // This can happen if the directory has 'List folder contents' permission set to 'Deny'
        // and the directory is trying to be opened for iteration.
        .ACCESS_DENIED => return error.AccessDenied,
        .INVALID_PARAMETER => unreachable,
        else => return w.unexpectedStatus(rc),
    }
}

pub const DeleteFileError = posix.UnlinkError;

/// Delete a file name and possibly the file it refers to, based on an open directory handle.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
/// Asserts that the path parameter has no null bytes.
pub fn deleteFile(self: Dir, sub_path: []const u8) DeleteFileError!void {
    if (native_os == .windows) {
        const sub_path_w = try windows.sliceToPrefixedFileW(self.fd, sub_path);
        return self.deleteFileW(sub_path_w.span());
    } else if (native_os == .wasi and !builtin.link_libc) {
        posix.unlinkat(self.fd, sub_path, 0) catch |err| switch (err) {
            error.DirNotEmpty => unreachable, // not passing AT.REMOVEDIR
            else => |e| return e,
        };
    } else {
        const sub_path_c = try posix.toPosixPath(sub_path);
        return self.deleteFileZ(&sub_path_c);
    }
}

/// Same as `deleteFile` except the parameter is null-terminated.
pub fn deleteFileZ(self: Dir, sub_path_c: [*:0]const u8) DeleteFileError!void {
    posix.unlinkatZ(self.fd, sub_path_c, 0) catch |err| switch (err) {
        error.DirNotEmpty => unreachable, // not passing AT.REMOVEDIR
        error.AccessDenied, error.PermissionDenied => |e| switch (native_os) {
            // non-Linux POSIX systems return permission errors when trying to delete a
            // directory, so we need to handle that case specifically and translate the error
            .macos, .ios, .freebsd, .netbsd, .dragonfly, .openbsd, .solaris, .illumos => {
                // Don't follow symlinks to match unlinkat (which acts on symlinks rather than follows them)
                const fstat = posix.fstatatZ(self.fd, sub_path_c, posix.AT.SYMLINK_NOFOLLOW) catch return e;
                const is_dir = fstat.mode & posix.S.IFMT == posix.S.IFDIR;
                return if (is_dir) error.IsDir else e;
            },
            else => return e,
        },
        else => |e| return e,
    };
}

/// Same as `deleteFile` except the parameter is WTF-16 LE encoded.
pub fn deleteFileW(self: Dir, sub_path_w: []const u16) DeleteFileError!void {
    posix.unlinkatW(self.fd, sub_path_w, 0) catch |err| switch (err) {
        error.DirNotEmpty => unreachable, // not passing AT.REMOVEDIR
        else => |e| return e,
    };
}

pub const DeleteDirError = error{
    DirNotEmpty,
    FileNotFound,
    AccessDenied,
    PermissionDenied,
    FileBusy,
    FileSystem,
    SymLinkLoop,
    NameTooLong,
    NotDir,
    SystemResources,
    ReadOnlyFileSystem,
    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,
    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,
    BadPathName,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
    ProcessNotFound,
    Unexpected,
};

/// Returns `error.DirNotEmpty` if the directory is not empty.
/// To delete a directory recursively, see `deleteTree`.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
/// Asserts that the path parameter has no null bytes.
pub fn deleteDir(self: Dir, sub_path: []const u8) DeleteDirError!void {
    if (native_os == .windows) {
        const sub_path_w = try windows.sliceToPrefixedFileW(self.fd, sub_path);
        return self.deleteDirW(sub_path_w.span());
    } else if (native_os == .wasi and !builtin.link_libc) {
        posix.unlinkat(self.fd, sub_path, posix.AT.REMOVEDIR) catch |err| switch (err) {
            error.IsDir => unreachable, // not possible since we pass AT.REMOVEDIR
            else => |e| return e,
        };
    } else {
        const sub_path_c = try posix.toPosixPath(sub_path);
        return self.deleteDirZ(&sub_path_c);
    }
}

/// Same as `deleteDir` except the parameter is null-terminated.
pub fn deleteDirZ(self: Dir, sub_path_c: [*:0]const u8) DeleteDirError!void {
    posix.unlinkatZ(self.fd, sub_path_c, posix.AT.REMOVEDIR) catch |err| switch (err) {
        error.IsDir => unreachable, // not possible since we pass AT.REMOVEDIR
        else => |e| return e,
    };
}

/// Same as `deleteDir` except the parameter is WTF16LE, NT prefixed.
/// This function is Windows-only.
pub fn deleteDirW(self: Dir, sub_path_w: []const u16) DeleteDirError!void {
    posix.unlinkatW(self.fd, sub_path_w, posix.AT.REMOVEDIR) catch |err| switch (err) {
        error.IsDir => unreachable, // not possible since we pass AT.REMOVEDIR
        else => |e| return e,
    };
}

pub const RenameError = posix.RenameError;

/// Change the name or location of a file or directory.
/// If new_sub_path already exists, it will be replaced.
/// Renaming a file over an existing directory or a directory
/// over an existing file will fail with `error.IsDir` or `error.NotDir`
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn rename(self: Dir, old_sub_path: []const u8, new_sub_path: []const u8) RenameError!void {
    return posix.renameat(self.fd, old_sub_path, self.fd, new_sub_path);
}

/// Same as `rename` except the parameters are null-terminated.
pub fn renameZ(self: Dir, old_sub_path_z: [*:0]const u8, new_sub_path_z: [*:0]const u8) RenameError!void {
    return posix.renameatZ(self.fd, old_sub_path_z, self.fd, new_sub_path_z);
}

/// Same as `rename` except the parameters are WTF16LE, NT prefixed.
/// This function is Windows-only.
pub fn renameW(self: Dir, old_sub_path_w: []const u16, new_sub_path_w: []const u16) RenameError!void {
    return posix.renameatW(self.fd, old_sub_path_w, self.fd, new_sub_path_w, windows.TRUE);
}

/// Use with `Dir.symLink`, `Dir.atomicSymLink`, and `symLinkAbsolute` to
/// specify whether the symlink will point to a file or a directory. This value
/// is ignored on all hosts except Windows where creating symlinks to different
/// resource types, requires different flags. By default, `symLinkAbsolute` is
/// assumed to point to a file.
pub const SymLinkFlags = struct {
    is_directory: bool = false,
};

/// Creates a symbolic link named `sym_link_path` which contains the string `target_path`.
/// A symbolic link (also known as a soft link) may point to an existing file or to a nonexistent
/// one; the latter case is known as a dangling link.
/// If `sym_link_path` exists, it will not be overwritten.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn symLink(
    self: Dir,
    target_path: []const u8,
    sym_link_path: []const u8,
    flags: SymLinkFlags,
) !void {
    if (native_os == .wasi and !builtin.link_libc) {
        return self.symLinkWasi(target_path, sym_link_path, flags);
    }
    if (native_os == .windows) {
        // Target path does not use sliceToPrefixedFileW because certain paths
        // are handled differently when creating a symlink than they would be
        // when converting to an NT namespaced path. CreateSymbolicLink in
        // symLinkW will handle the necessary conversion.
        var target_path_w: windows.PathSpace = undefined;
        if (try std.unicode.checkWtf8ToWtf16LeOverflow(target_path, &target_path_w.data)) {
            return error.NameTooLong;
        }
        target_path_w.len = try std.unicode.wtf8ToWtf16Le(&target_path_w.data, target_path);
        target_path_w.data[target_path_w.len] = 0;
        // However, we need to canonicalize any path separators to `\`, since if
        // the target path is relative, then it must use `\` as the path separator.
        mem.replaceScalar(
            u16,
            target_path_w.data[0..target_path_w.len],
            mem.nativeToLittle(u16, '/'),
            mem.nativeToLittle(u16, '\\'),
        );

        const sym_link_path_w = try windows.sliceToPrefixedFileW(self.fd, sym_link_path);
        return self.symLinkW(target_path_w.span(), sym_link_path_w.span(), flags);
    }
    const target_path_c = try posix.toPosixPath(target_path);
    const sym_link_path_c = try posix.toPosixPath(sym_link_path);
    return self.symLinkZ(&target_path_c, &sym_link_path_c, flags);
}

/// WASI-only. Same as `symLink` except targeting WASI.
pub fn symLinkWasi(
    self: Dir,
    target_path: []const u8,
    sym_link_path: []const u8,
    _: SymLinkFlags,
) !void {
    return posix.symlinkat(target_path, self.fd, sym_link_path);
}

/// Same as `symLink`, except the pathname parameters are null-terminated.
pub fn symLinkZ(
    self: Dir,
    target_path_c: [*:0]const u8,
    sym_link_path_c: [*:0]const u8,
    flags: SymLinkFlags,
) !void {
    if (native_os == .windows) {
        const target_path_w = try windows.cStrToPrefixedFileW(self.fd, target_path_c);
        const sym_link_path_w = try windows.cStrToPrefixedFileW(self.fd, sym_link_path_c);
        return self.symLinkW(target_path_w.span(), sym_link_path_w.span(), flags);
    }
    return posix.symlinkatZ(target_path_c, self.fd, sym_link_path_c);
}

/// Windows-only. Same as `symLink` except the pathname parameters
/// are WTF16 LE encoded.
pub fn symLinkW(
    self: Dir,
    /// WTF-16, does not need to be NT-prefixed. The NT-prefixing
    /// of this path is handled by CreateSymbolicLink.
    /// Any path separators must be `\`, not `/`.
    target_path_w: [:0]const u16,
    /// WTF-16, must be NT-prefixed or relative
    sym_link_path_w: []const u16,
    flags: SymLinkFlags,
) !void {
    return windows.CreateSymbolicLink(self.fd, sym_link_path_w, target_path_w, flags.is_directory);
}

/// Same as `symLink`, except tries to create the symbolic link until it
/// succeeds or encounters an error other than `error.PathAlreadyExists`.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn atomicSymLink(
    dir: Dir,
    target_path: []const u8,
    sym_link_path: []const u8,
    flags: SymLinkFlags,
) !void {
    if (dir.symLink(target_path, sym_link_path, flags)) {
        return;
    } else |err| switch (err) {
        error.PathAlreadyExists => {},
        else => |e| return e,
    }

    const dirname = path.dirname(sym_link_path) orelse ".";

    var rand_buf: [AtomicFile.random_bytes_len]u8 = undefined;

    const temp_path_len = dirname.len + 1 + base64_encoder.calcSize(rand_buf.len);
    var temp_path_buf: [fs.max_path_bytes]u8 = undefined;

    if (temp_path_len > temp_path_buf.len) return error.NameTooLong;
    @memcpy(temp_path_buf[0..dirname.len], dirname);
    temp_path_buf[dirname.len] = path.sep;

    const temp_path = temp_path_buf[0..temp_path_len];

    while (true) {
        crypto.random.bytes(rand_buf[0..]);
        _ = base64_encoder.encode(temp_path[dirname.len + 1 ..], rand_buf[0..]);

        if (dir.symLink(target_path, temp_path, flags)) {
            return dir.rename(temp_path, sym_link_path);
        } else |err| switch (err) {
            error.PathAlreadyExists => continue,
            else => |e| return e,
        }
    }
}

pub const ReadLinkError = posix.ReadLinkError;

/// Read value of a symbolic link.
/// The return value is a slice of `buffer`, from index `0`.
/// Asserts that the path parameter has no null bytes.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn readLink(self: Dir, sub_path: []const u8, buffer: []u8) ReadLinkError![]u8 {
    if (native_os == .wasi and !builtin.link_libc) {
        return self.readLinkWasi(sub_path, buffer);
    }
    if (native_os == .windows) {
        const sub_path_w = try windows.sliceToPrefixedFileW(self.fd, sub_path);
        return self.readLinkW(sub_path_w.span(), buffer);
    }
    const sub_path_c = try posix.toPosixPath(sub_path);
    return self.readLinkZ(&sub_path_c, buffer);
}

/// WASI-only. Same as `readLink` except targeting WASI.
pub fn readLinkWasi(self: Dir, sub_path: []const u8, buffer: []u8) ![]u8 {
    return posix.readlinkat(self.fd, sub_path, buffer);
}

/// Same as `readLink`, except the `sub_path_c` parameter is null-terminated.
pub fn readLinkZ(self: Dir, sub_path_c: [*:0]const u8, buffer: []u8) ![]u8 {
    if (native_os == .windows) {
        const sub_path_w = try windows.cStrToPrefixedFileW(self.fd, sub_path_c);
        return self.readLinkW(sub_path_w.span(), buffer);
    }
    return posix.readlinkatZ(self.fd, sub_path_c, buffer);
}

/// Windows-only. Same as `readLink` except the pathname parameter
/// is WTF16 LE encoded.
pub fn readLinkW(self: Dir, sub_path_w: []const u16, buffer: []u8) ![]u8 {
    return windows.ReadLink(self.fd, sub_path_w, buffer);
}

/// Read all of file contents using a preallocated buffer.
/// The returned slice has the same pointer as `buffer`. If the length matches `buffer.len`
/// the situation is ambiguous. It could either mean that the entire file was read, and
/// it exactly fits the buffer, or it could mean the buffer was not big enough for the
/// entire file.
/// On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `file_path` should be encoded as valid UTF-8.
/// On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
pub fn readFile(self: Dir, file_path: []const u8, buffer: []u8) ![]u8 {
    var file = try self.openFile(file_path, .{});
    defer file.close();

    const end_index = try file.readAll(buffer);
    return buffer[0..end_index];
}

/// On success, caller owns returned buffer.
/// If the file is larger than `max_bytes`, returns `error.FileTooBig`.
/// On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `file_path` should be encoded as valid UTF-8.
/// On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
pub fn readFileAlloc(self: Dir, allocator: mem.Allocator, file_path: []const u8, max_bytes: usize) ![]u8 {
    return self.readFileAllocOptions(allocator, file_path, max_bytes, null, .of(u8), null);
}

/// On success, caller owns returned buffer.
/// If the file is larger than `max_bytes`, returns `error.FileTooBig`.
/// If `size_hint` is specified the initial buffer size is calculated using
/// that value, otherwise the effective file size is used instead.
/// Allows specifying alignment and a sentinel value.
/// On Windows, `file_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `file_path` should be encoded as valid UTF-8.
/// On other platforms, `file_path` is an opaque sequence of bytes with no particular encoding.
pub fn readFileAllocOptions(
    self: Dir,
    allocator: mem.Allocator,
    file_path: []const u8,
    max_bytes: usize,
    size_hint: ?usize,
    comptime alignment: std.mem.Alignment,
    comptime optional_sentinel: ?u8,
) !(if (optional_sentinel) |s| [:s]align(alignment.toByteUnits()) u8 else []align(alignment.toByteUnits()) u8) {
    var file = try self.openFile(file_path, .{});
    defer file.close();

    // If the file size doesn't fit a usize it'll be certainly greater than
    // `max_bytes`
    const stat_size = size_hint orelse std.math.cast(usize, try file.getEndPos()) orelse
        return error.FileTooBig;

    return file.readToEndAllocOptions(allocator, max_bytes, stat_size, alignment, optional_sentinel);
}

pub const DeleteTreeError = error{
    AccessDenied,
    PermissionDenied,
    FileTooBig,
    SymLinkLoop,
    ProcessFdQuotaExceeded,
    NameTooLong,
    SystemFdQuotaExceeded,
    NoDevice,
    SystemResources,
    ReadOnlyFileSystem,
    FileSystem,
    FileBusy,
    DeviceBusy,
    ProcessNotFound,

    /// One of the path components was not a directory.
    /// This error is unreachable if `sub_path` does not contain a path separator.
    NotDir,

    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,

    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,

    /// On Windows, file paths cannot contain these characters:
    /// '/', '*', '?', '"', '<', '>', '|'
    BadPathName,

    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
} || posix.UnexpectedError;

/// Whether `sub_path` describes a symlink, file, or directory, this function
/// removes it. If it cannot be removed because it is a non-empty directory,
/// this function recursively removes its entries and then tries again.
/// This operation is not atomic on most file systems.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn deleteTree(self: Dir, sub_path: []const u8) DeleteTreeError!void {
    var initial_iterable_dir = (try self.deleteTreeOpenInitialSubpath(sub_path, .file)) orelse return;

    const StackItem = struct {
        name: []const u8,
        parent_dir: Dir,
        iter: Dir.Iterator,

        fn closeAll(items: []@This()) void {
            for (items) |*item| item.iter.dir.close();
        }
    };

    var stack_buffer: [16]StackItem = undefined;
    var stack = std.ArrayListUnmanaged(StackItem).initBuffer(&stack_buffer);
    defer StackItem.closeAll(stack.items);

    stack.appendAssumeCapacity(.{
        .name = sub_path,
        .parent_dir = self,
        .iter = initial_iterable_dir.iterateAssumeFirstIteration(),
    });

    process_stack: while (stack.items.len != 0) {
        var top = &stack.items[stack.items.len - 1];
        while (try top.iter.next()) |entry| {
            var treat_as_dir = entry.kind == .directory;
            handle_entry: while (true) {
                if (treat_as_dir) {
                    if (stack.unusedCapacitySlice().len >= 1) {
                        var iterable_dir = top.iter.dir.openDir(entry.name, .{
                            .no_follow = true,
                            .iterate = true,
                        }) catch |err| switch (err) {
                            error.NotDir => {
                                treat_as_dir = false;
                                continue :handle_entry;
                            },
                            error.FileNotFound => {
                                // That's fine, we were trying to remove this directory anyway.
                                break :handle_entry;
                            },

                            error.AccessDenied,
                            error.PermissionDenied,
                            error.SymLinkLoop,
                            error.ProcessFdQuotaExceeded,
                            error.ProcessNotFound,
                            error.NameTooLong,
                            error.SystemFdQuotaExceeded,
                            error.NoDevice,
                            error.SystemResources,
                            error.Unexpected,
                            error.InvalidUtf8,
                            error.InvalidWtf8,
                            error.BadPathName,
                            error.NetworkNotFound,
                            error.DeviceBusy,
                            => |e| return e,
                        };
                        stack.appendAssumeCapacity(.{
                            .name = entry.name,
                            .parent_dir = top.iter.dir,
                            .iter = iterable_dir.iterateAssumeFirstIteration(),
                        });
                        continue :process_stack;
                    } else {
                        try top.iter.dir.deleteTreeMinStackSizeWithKindHint(entry.name, entry.kind);
                        break :handle_entry;
                    }
                } else {
                    if (top.iter.dir.deleteFile(entry.name)) {
                        break :handle_entry;
                    } else |err| switch (err) {
                        error.FileNotFound => break :handle_entry,

                        // Impossible because we do not pass any path separators.
                        error.NotDir => unreachable,

                        error.IsDir => {
                            treat_as_dir = true;
                            continue :handle_entry;
                        },

                        error.AccessDenied,
                        error.PermissionDenied,
                        error.InvalidUtf8,
                        error.InvalidWtf8,
                        error.SymLinkLoop,
                        error.NameTooLong,
                        error.SystemResources,
                        error.ReadOnlyFileSystem,
                        error.FileSystem,
                        error.FileBusy,
                        error.BadPathName,
                        error.NetworkNotFound,
                        error.Unexpected,
                        => |e| return e,
                    }
                }
            }
        }

        // On Windows, we can't delete until the dir's handle has been closed, so
        // close it before we try to delete.
        top.iter.dir.close();

        // In order to avoid double-closing the directory when cleaning up
        // the stack in the case of an error, we save the relevant portions and
        // pop the value from the stack.
        const parent_dir = top.parent_dir;
        const name = top.name;
        stack.items.len -= 1;

        var need_to_retry: bool = false;
        parent_dir.deleteDir(name) catch |err| switch (err) {
            error.FileNotFound => {},
            error.DirNotEmpty => need_to_retry = true,
            else => |e| return e,
        };

        if (need_to_retry) {
            // Since we closed the handle that the previous iterator used, we
            // need to re-open the dir and re-create the iterator.
            var iterable_dir = iterable_dir: {
                var treat_as_dir = true;
                handle_entry: while (true) {
                    if (treat_as_dir) {
                        break :iterable_dir parent_dir.openDir(name, .{
                            .no_follow = true,
                            .iterate = true,
                        }) catch |err| switch (err) {
                            error.NotDir => {
                                treat_as_dir = false;
                                continue :handle_entry;
                            },
                            error.FileNotFound => {
                                // That's fine, we were trying to remove this directory anyway.
                                continue :process_stack;
                            },

                            error.AccessDenied,
                            error.PermissionDenied,
                            error.SymLinkLoop,
                            error.ProcessNotFound,
                            error.ProcessFdQuotaExceeded,
                            error.NameTooLong,
                            error.SystemFdQuotaExceeded,
                            error.NoDevice,
                            error.SystemResources,
                            error.Unexpected,
                            error.InvalidUtf8,
                            error.InvalidWtf8,
                            error.BadPathName,
                            error.NetworkNotFound,
                            error.DeviceBusy,
                            => |e| return e,
                        };
                    } else {
                        if (parent_dir.deleteFile(name)) {
                            continue :process_stack;
                        } else |err| switch (err) {
                            error.FileNotFound => continue :process_stack,

                            // Impossible because we do not pass any path separators.
                            error.NotDir => unreachable,

                            error.IsDir => {
                                treat_as_dir = true;
                                continue :handle_entry;
                            },

                            error.AccessDenied,
                            error.PermissionDenied,
                            error.InvalidUtf8,
                            error.InvalidWtf8,
                            error.SymLinkLoop,
                            error.NameTooLong,
                            error.SystemResources,
                            error.ReadOnlyFileSystem,
                            error.FileSystem,
                            error.FileBusy,
                            error.BadPathName,
                            error.NetworkNotFound,
                            error.Unexpected,
                            => |e| return e,
                        }
                    }
                }
            };
            // We know there is room on the stack since we are just re-adding
            // the StackItem that we previously popped.
            stack.appendAssumeCapacity(.{
                .name = name,
                .parent_dir = parent_dir,
                .iter = iterable_dir.iterateAssumeFirstIteration(),
            });
            continue :process_stack;
        }
    }
}

/// Like `deleteTree`, but only keeps one `Iterator` active at a time to minimize the function's stack size.
/// This is slower than `deleteTree` but uses less stack space.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn deleteTreeMinStackSize(self: Dir, sub_path: []const u8) DeleteTreeError!void {
    return self.deleteTreeMinStackSizeWithKindHint(sub_path, .file);
}

fn deleteTreeMinStackSizeWithKindHint(self: Dir, sub_path: []const u8, kind_hint: File.Kind) DeleteTreeError!void {
    start_over: while (true) {
        var dir = (try self.deleteTreeOpenInitialSubpath(sub_path, kind_hint)) orelse return;
        var cleanup_dir_parent: ?Dir = null;
        defer if (cleanup_dir_parent) |*d| d.close();

        var cleanup_dir = true;
        defer if (cleanup_dir) dir.close();

        // Valid use of max_path_bytes because dir_name_buf will only
        // ever store a single path component that was returned from the
        // filesystem.
        var dir_name_buf: [fs.max_path_bytes]u8 = undefined;
        var dir_name: []const u8 = sub_path;

        // Here we must avoid recursion, in order to provide O(1) memory guarantee of this function.
        // Go through each entry and if it is not a directory, delete it. If it is a directory,
        // open it, and close the original directory. Repeat. Then start the entire operation over.

        scan_dir: while (true) {
            var dir_it = dir.iterateAssumeFirstIteration();
            dir_it: while (try dir_it.next()) |entry| {
                var treat_as_dir = entry.kind == .directory;
                handle_entry: while (true) {
                    if (treat_as_dir) {
                        const new_dir = dir.openDir(entry.name, .{
                            .no_follow = true,
                            .iterate = true,
                        }) catch |err| switch (err) {
                            error.NotDir => {
                                treat_as_dir = false;
                                continue :handle_entry;
                            },
                            error.FileNotFound => {
                                // That's fine, we were trying to remove this directory anyway.
                                continue :dir_it;
                            },

                            error.AccessDenied,
                            error.PermissionDenied,
                            error.SymLinkLoop,
                            error.ProcessNotFound,
                            error.ProcessFdQuotaExceeded,
                            error.NameTooLong,
                            error.SystemFdQuotaExceeded,
                            error.NoDevice,
                            error.SystemResources,
                            error.Unexpected,
                            error.InvalidUtf8,
                            error.InvalidWtf8,
                            error.BadPathName,
                            error.NetworkNotFound,
                            error.DeviceBusy,
                            => |e| return e,
                        };
                        if (cleanup_dir_parent) |*d| d.close();
                        cleanup_dir_parent = dir;
                        dir = new_dir;
                        const result = dir_name_buf[0..entry.name.len];
                        @memcpy(result, entry.name);
                        dir_name = result;
                        continue :scan_dir;
                    } else {
                        if (dir.deleteFile(entry.name)) {
                            continue :dir_it;
                        } else |err| switch (err) {
                            error.FileNotFound => continue :dir_it,

                            // Impossible because we do not pass any path separators.
                            error.NotDir => unreachable,

                            error.IsDir => {
                                treat_as_dir = true;
                                continue :handle_entry;
                            },

                            error.AccessDenied,
                            error.PermissionDenied,
                            error.InvalidUtf8,
                            error.InvalidWtf8,
                            error.SymLinkLoop,
                            error.NameTooLong,
                            error.SystemResources,
                            error.ReadOnlyFileSystem,
                            error.FileSystem,
                            error.FileBusy,
                            error.BadPathName,
                            error.NetworkNotFound,
                            error.Unexpected,
                            => |e| return e,
                        }
                    }
                }
            }
            // Reached the end of the directory entries, which means we successfully deleted all of them.
            // Now to remove the directory itself.
            dir.close();
            cleanup_dir = false;

            if (cleanup_dir_parent) |d| {
                d.deleteDir(dir_name) catch |err| switch (err) {
                    // These two things can happen due to file system race conditions.
                    error.FileNotFound, error.DirNotEmpty => continue :start_over,
                    else => |e| return e,
                };
                continue :start_over;
            } else {
                self.deleteDir(sub_path) catch |err| switch (err) {
                    error.FileNotFound => return,
                    error.DirNotEmpty => continue :start_over,
                    else => |e| return e,
                };
                return;
            }
        }
    }
}

/// On successful delete, returns null.
fn deleteTreeOpenInitialSubpath(self: Dir, sub_path: []const u8, kind_hint: File.Kind) !?Dir {
    return iterable_dir: {
        // Treat as a file by default
        var treat_as_dir = kind_hint == .directory;

        handle_entry: while (true) {
            if (treat_as_dir) {
                break :iterable_dir self.openDir(sub_path, .{
                    .no_follow = true,
                    .iterate = true,
                }) catch |err| switch (err) {
                    error.NotDir => {
                        treat_as_dir = false;
                        continue :handle_entry;
                    },
                    error.FileNotFound => {
                        // That's fine, we were trying to remove this directory anyway.
                        return null;
                    },

                    error.AccessDenied,
                    error.PermissionDenied,
                    error.SymLinkLoop,
                    error.ProcessFdQuotaExceeded,
                    error.ProcessNotFound,
                    error.NameTooLong,
                    error.SystemFdQuotaExceeded,
                    error.NoDevice,
                    error.SystemResources,
                    error.Unexpected,
                    error.InvalidUtf8,
                    error.InvalidWtf8,
                    error.BadPathName,
                    error.DeviceBusy,
                    error.NetworkNotFound,
                    => |e| return e,
                };
            } else {
                if (self.deleteFile(sub_path)) {
                    return null;
                } else |err| switch (err) {
                    error.FileNotFound => return null,

                    error.IsDir => {
                        treat_as_dir = true;
                        continue :handle_entry;
                    },

                    error.AccessDenied,
                    error.PermissionDenied,
                    error.InvalidUtf8,
                    error.InvalidWtf8,
                    error.SymLinkLoop,
                    error.NameTooLong,
                    error.SystemResources,
                    error.ReadOnlyFileSystem,
                    error.NotDir,
                    error.FileSystem,
                    error.FileBusy,
                    error.BadPathName,
                    error.NetworkNotFound,
                    error.Unexpected,
                    => |e| return e,
                }
            }
        }
    };
}

pub const WriteFileError = File.WriteError || File.OpenError;

pub const WriteFileOptions = struct {
    /// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
    /// On WASI, `sub_path` should be encoded as valid UTF-8.
    /// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
    sub_path: []const u8,
    data: []const u8,
    flags: File.CreateFlags = .{},
};

/// Writes content to the file system, using the file creation flags provided.
pub fn writeFile(self: Dir, options: WriteFileOptions) WriteFileError!void {
    var file = try self.createFile(options.sub_path, options.flags);
    defer file.close();
    try file.writeAll(options.data);
}

pub const writeFile2 = @compileError("deprecated; renamed to writeFile");

pub const AccessError = posix.AccessError;

/// Test accessing `sub_path`.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
/// Be careful of Time-Of-Check-Time-Of-Use race conditions when using this function.
/// For example, instead of testing if a file exists and then opening it, just
/// open it and handle the error for file not found.
pub fn access(self: Dir, sub_path: []const u8, flags: File.OpenFlags) AccessError!void {
    if (native_os == .windows) {
        const sub_path_w = try windows.sliceToPrefixedFileW(self.fd, sub_path);
        return self.accessW(sub_path_w.span().ptr, flags);
    }
    const path_c = try posix.toPosixPath(sub_path);
    return self.accessZ(&path_c, flags);
}

/// Same as `access` except the path parameter is null-terminated.
pub fn accessZ(self: Dir, sub_path: [*:0]const u8, flags: File.OpenFlags) AccessError!void {
    if (native_os == .windows) {
        const sub_path_w = try windows.cStrToPrefixedFileW(self.fd, sub_path);
        return self.accessW(sub_path_w.span().ptr, flags);
    }
    const os_mode = switch (flags.mode) {
        .read_only => @as(u32, posix.F_OK),
        .write_only => @as(u32, posix.W_OK),
        .read_write => @as(u32, posix.R_OK | posix.W_OK),
    };
    const result = posix.faccessatZ(self.fd, sub_path, os_mode, 0);
    return result;
}

/// Same as `access` except asserts the target OS is Windows and the path parameter is
/// * WTF-16 LE encoded
/// * null-terminated
/// * relative or has the NT namespace prefix
/// TODO currently this ignores `flags`.
pub fn accessW(self: Dir, sub_path_w: [*:0]const u16, flags: File.OpenFlags) AccessError!void {
    _ = flags;
    return posix.faccessatW(self.fd, sub_path_w);
}

pub const CopyFileOptions = struct {
    /// When this is `null` the mode is copied from the source file.
    override_mode: ?File.Mode = null,
};

pub const PrevStatus = enum {
    stale,
    fresh,
};

/// Check the file size, mtime, and mode of `source_path` and `dest_path`. If they are equal, does nothing.
/// Otherwise, atomically copies `source_path` to `dest_path`. The destination file gains the mtime,
/// atime, and mode of the source file so that the next call to `updateFile` will not need a copy.
/// Returns the previous status of the file before updating.
/// If any of the directories do not exist for dest_path, they are created.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn updateFile(
    source_dir: Dir,
    source_path: []const u8,
    dest_dir: Dir,
    dest_path: []const u8,
    options: CopyFileOptions,
) !PrevStatus {
    var src_file = try source_dir.openFile(source_path, .{});
    defer src_file.close();

    const src_stat = try src_file.stat();
    const actual_mode = options.override_mode orelse src_stat.mode;
    check_dest_stat: {
        const dest_stat = blk: {
            var dest_file = dest_dir.openFile(dest_path, .{}) catch |err| switch (err) {
                error.FileNotFound => break :check_dest_stat,
                else => |e| return e,
            };
            defer dest_file.close();

            break :blk try dest_file.stat();
        };

        if (src_stat.size == dest_stat.size and
            src_stat.mtime == dest_stat.mtime and
            actual_mode == dest_stat.mode)
        {
            return PrevStatus.fresh;
        }
    }

    if (fs.path.dirname(dest_path)) |dirname| {
        try dest_dir.makePath(dirname);
    }

    var atomic_file = try dest_dir.atomicFile(dest_path, .{ .mode = actual_mode });
    defer atomic_file.deinit();

    try atomic_file.file.writeFileAll(src_file, .{ .in_len = src_stat.size });
    try atomic_file.file.updateTimes(src_stat.atime, src_stat.mtime);
    try atomic_file.finish();
    return PrevStatus.stale;
}

pub const CopyFileError = File.OpenError || File.StatError ||
    AtomicFile.InitError || CopyFileRawError || AtomicFile.FinishError;

/// Guaranteed to be atomic.
/// On Linux, until https://patchwork.kernel.org/patch/9636735/ is merged and readily available,
/// there is a possibility of power loss or application termination leaving temporary files present
/// in the same directory as dest_path.
/// On Windows, both paths should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, both paths should be encoded as valid UTF-8.
/// On other platforms, both paths are an opaque sequence of bytes with no particular encoding.
pub fn copyFile(
    source_dir: Dir,
    source_path: []const u8,
    dest_dir: Dir,
    dest_path: []const u8,
    options: CopyFileOptions,
) CopyFileError!void {
    var in_file = try source_dir.openFile(source_path, .{});
    defer in_file.close();

    var size: ?u64 = null;
    const mode = options.override_mode orelse blk: {
        const st = try in_file.stat();
        size = st.size;
        break :blk st.mode;
    };

    var atomic_file = try dest_dir.atomicFile(dest_path, .{ .mode = mode });
    defer atomic_file.deinit();

    try copy_file(in_file.handle, atomic_file.file.handle, size);
    try atomic_file.finish();
}

const CopyFileRawError = error{SystemResources} || posix.CopyFileRangeError || posix.SendFileError;

// Transfer all the data between two file descriptors in the most efficient way.
// The copy starts at offset 0, the initial offsets are preserved.
// No metadata is transferred over.
fn copy_file(fd_in: posix.fd_t, fd_out: posix.fd_t, maybe_size: ?u64) CopyFileRawError!void {
    if (builtin.target.os.tag.isDarwin()) {
        const rc = posix.system.fcopyfile(fd_in, fd_out, null, .{ .DATA = true });
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INVAL => unreachable,
            .NOMEM => return error.SystemResources,
            // The source file is not a directory, symbolic link, or regular file.
            // Try with the fallback path before giving up.
            .OPNOTSUPP => {},
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    if (native_os == .linux) {
        // Try copy_file_range first as that works at the FS level and is the
        // most efficient method (if available).
        var offset: u64 = 0;
        cfr_loop: while (true) {
            // The kernel checks the u64 value `offset+count` for overflow, use
            // a 32 bit value so that the syscall won't return EINVAL except for
            // impossibly large files (> 2^64-1 - 2^32-1).
            const amt = try posix.copy_file_range(fd_in, offset, fd_out, offset, std.math.maxInt(u32), 0);
            // Terminate as soon as we have copied size bytes or no bytes
            if (maybe_size) |s| {
                if (s == amt) break :cfr_loop;
            }
            if (amt == 0) break :cfr_loop;
            offset += amt;
        }
        return;
    }

    // Sendfile is a zero-copy mechanism iff the OS supports it, otherwise the
    // fallback code will copy the contents chunk by chunk.
    const empty_iovec = [0]posix.iovec_const{};
    var offset: u64 = 0;
    sendfile_loop: while (true) {
        const amt = try posix.sendfile(fd_out, fd_in, offset, 0, &empty_iovec, &empty_iovec, 0);
        // Terminate as soon as we have copied size bytes or no bytes
        if (maybe_size) |s| {
            if (s == amt) break :sendfile_loop;
        }
        if (amt == 0) break :sendfile_loop;
        offset += amt;
    }
}

pub const AtomicFileOptions = struct {
    mode: File.Mode = File.default_mode,
    make_path: bool = false,
};

/// Directly access the `.file` field, and then call `AtomicFile.finish` to
/// atomically replace `dest_path` with contents.
/// Always call `AtomicFile.deinit` to clean up, regardless of whether
/// `AtomicFile.finish` succeeded. `dest_path` must remain valid until
/// `AtomicFile.deinit` is called.
/// On Windows, `dest_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `dest_path` should be encoded as valid UTF-8.
/// On other platforms, `dest_path` is an opaque sequence of bytes with no particular encoding.
pub fn atomicFile(self: Dir, dest_path: []const u8, options: AtomicFileOptions) !AtomicFile {
    if (fs.path.dirname(dest_path)) |dirname| {
        const dir = if (options.make_path)
            try self.makeOpenPath(dirname, .{})
        else
            try self.openDir(dirname, .{});

        return AtomicFile.init(fs.path.basename(dest_path), options.mode, dir, true);
    } else {
        return AtomicFile.init(dest_path, options.mode, self, false);
    }
}

pub const Stat = File.Stat;
pub const StatError = File.StatError;

pub fn stat(self: Dir) StatError!Stat {
    const file: File = .{ .handle = self.fd };
    return file.stat();
}

pub const StatFileError = File.OpenError || File.StatError || posix.FStatAtError;

/// Returns metadata for a file inside the directory.
///
/// On Windows, this requires three syscalls. On other operating systems, it
/// only takes one.
///
/// Symlinks are followed.
///
/// `sub_path` may be absolute, in which case `self` is ignored.
/// On Windows, `sub_path` should be encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On WASI, `sub_path` should be encoded as valid UTF-8.
/// On other platforms, `sub_path` is an opaque sequence of bytes with no particular encoding.
pub fn statFile(self: Dir, sub_path: []const u8) StatFileError!Stat {
    if (native_os == .windows) {
        var file = try self.openFile(sub_path, .{});
        defer file.close();
        return file.stat();
    }
    if (native_os == .wasi and !builtin.link_libc) {
        const st = try std.os.fstatat_wasi(self.fd, sub_path, .{ .SYMLINK_FOLLOW = true });
        return Stat.fromWasi(st);
    }
    if (native_os == .linux) {
        const sub_path_c = try posix.toPosixPath(sub_path);
        var stx = std.mem.zeroes(linux.Statx);

        const rc = linux.statx(
            self.fd,
            &sub_path_c,
            linux.AT.NO_AUTOMOUNT,
            linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME,
            &stx,
        );

        return switch (linux.E.init(rc)) {
            .SUCCESS => Stat.fromLinux(stx),
            .ACCES => error.AccessDenied,
            .BADF => unreachable,
            .FAULT => unreachable,
            .INVAL => unreachable,
            .LOOP => error.SymLinkLoop,
            .NAMETOOLONG => unreachable, // Handled by posix.toPosixPath() above.
            .NOENT, .NOTDIR => error.FileNotFound,
            .NOMEM => error.SystemResources,
            else => |err| posix.unexpectedErrno(err),
        };
    }
    const st = try posix.fstatat(self.fd, sub_path, 0);
    return Stat.fromPosix(st);
}

pub const ChmodError = File.ChmodError;

/// Changes the mode of the directory.
/// The process must have the correct privileges in order to do this
/// successfully, or must have the effective user ID matching the owner
/// of the directory. Additionally, the directory must have been opened
/// with `OpenOptions{ .iterate = true }`.
pub fn chmod(self: Dir, new_mode: File.Mode) ChmodError!void {
    const file: File = .{ .handle = self.fd };
    try file.chmod(new_mode);
}

/// Changes the owner and group of the directory.
/// The process must have the correct privileges in order to do this
/// successfully. The group may be changed by the owner of the directory to
/// any group of which the owner is a member. Additionally, the directory
/// must have been opened with `OpenOptions{ .iterate = true }`. If the
/// owner or group is specified as `null`, the ID is not changed.
pub fn chown(self: Dir, owner: ?File.Uid, group: ?File.Gid) ChownError!void {
    const file: File = .{ .handle = self.fd };
    try file.chown(owner, group);
}

pub const ChownError = File.ChownError;

const Permissions = File.Permissions;
pub const SetPermissionsError = File.SetPermissionsError;

/// Sets permissions according to the provided `Permissions` struct.
/// This method is *NOT* available on WASI
pub fn setPermissions(self: Dir, permissions: Permissions) SetPermissionsError!void {
    const file: File = .{ .handle = self.fd };
    try file.setPermissions(permissions);
}

const Metadata = File.Metadata;
pub const MetadataError = File.MetadataError;

/// Returns a `Metadata` struct, representing the permissions on the directory
pub fn metadata(self: Dir) MetadataError!Metadata {
    const file: File = .{ .handle = self.fd };
    return try file.metadata();
}

const Dir = @This();
const builtin = @import("builtin");
const std = @import("../std.zig");
const File = std.fs.File;
const AtomicFile = std.fs.AtomicFile;
const base64_encoder = fs.base64_encoder;
const crypto = std.crypto;
const posix = std.posix;
const mem = std.mem;
const path = fs.path;
const fs = std.fs;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const linux = std.os.linux;
const windows = std.os.windows;
const native_os = builtin.os.tag;
const have_flock = @TypeOf(posix.system.flock) != void;
/// The OS-specific file descriptor or file handle.
handle: Handle,

pub const Handle = posix.fd_t;
pub const Mode = posix.mode_t;
pub const INode = posix.ino_t;
pub const Uid = posix.uid_t;
pub const Gid = posix.gid_t;

pub const Kind = enum {
    block_device,
    character_device,
    directory,
    named_pipe,
    sym_link,
    file,
    unix_domain_socket,
    whiteout,
    door,
    event_port,
    unknown,
};

/// This is the default mode given to POSIX operating systems for creating
/// files. `0o666` is "-rw-rw-rw-" which is counter-intuitive at first,
/// since most people would expect "-rw-r--r--", for example, when using
/// the `touch` command, which would correspond to `0o644`. However, POSIX
/// libc implementations use `0o666` inside `fopen` and then rely on the
/// process-scoped "umask" setting to adjust this number for file creation.
pub const default_mode = switch (builtin.os.tag) {
    .windows => 0,
    .wasi => 0,
    else => 0o666,
};

pub const OpenError = error{
    SharingViolation,
    PathAlreadyExists,
    FileNotFound,
    AccessDenied,
    PipeBusy,
    NoDevice,
    NameTooLong,
    /// WASI-only; file paths must be valid UTF-8.
    InvalidUtf8,
    /// Windows-only; file paths provided by the user must be valid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,
    /// On Windows, file paths cannot contain these characters:
    /// '/', '*', '?', '"', '<', '>', '|'
    BadPathName,
    Unexpected,
    /// On Windows, `\\server` or `\\server\share` was not found.
    NetworkNotFound,
    ProcessNotFound,
    /// On Windows, antivirus software is enabled by default. It can be
    /// disabled, but Windows Update sometimes ignores the user's preference
    /// and re-enables it. When enabled, antivirus software on Windows
    /// intercepts file system operations and makes them significantly slower
    /// in addition to possibly failing with this error code.
    AntivirusInterference,
} || posix.OpenError || posix.FlockError;

pub const OpenMode = enum {
    read_only,
    write_only,
    read_write,
};

pub const Lock = enum {
    none,
    shared,
    exclusive,
};

pub const OpenFlags = struct {
    mode: OpenMode = .read_only,

    /// Open the file with an advisory lock to coordinate with other processes
    /// accessing it at the same time. An exclusive lock will prevent other
    /// processes from acquiring a lock. A shared lock will prevent other
    /// processes from acquiring a exclusive lock, but does not prevent
    /// other process from getting their own shared locks.
    ///
    /// The lock is advisory, except on Linux in very specific circumstances[1].
    /// This means that a process that does not respect the locking API can still get access
    /// to the file, despite the lock.
    ///
    /// On these operating systems, the lock is acquired atomically with
    /// opening the file:
    /// * Darwin
    /// * DragonFlyBSD
    /// * FreeBSD
    /// * Haiku
    /// * NetBSD
    /// * OpenBSD
    /// On these operating systems, the lock is acquired via a separate syscall
    /// after opening the file:
    /// * Linux
    /// * Windows
    ///
    /// [1]: https://www.kernel.org/doc/Documentation/filesystems/mandatory-locking.txt
    lock: Lock = .none,

    /// Sets whether or not to wait until the file is locked to return. If set to true,
    /// `error.WouldBlock` will be returned. Otherwise, the file will wait until the file
    /// is available to proceed.
    lock_nonblocking: bool = false,

    /// Set this to allow the opened file to automatically become the
    /// controlling TTY for the current process.
    allow_ctty: bool = false,

    pub fn isRead(self: OpenFlags) bool {
        return self.mode != .write_only;
    }

    pub fn isWrite(self: OpenFlags) bool {
        return self.mode != .read_only;
    }
};

pub const CreateFlags = struct {
    /// Whether the file will be created with read access.
    read: bool = false,

    /// If the file already exists, and is a regular file, and the access
    /// mode allows writing, it will be truncated to length 0.
    truncate: bool = true,

    /// Ensures that this open call creates the file, otherwise causes
    /// `error.PathAlreadyExists` to be returned.
    exclusive: bool = false,

    /// Open the file with an advisory lock to coordinate with other processes
    /// accessing it at the same time. An exclusive lock will prevent other
    /// processes from acquiring a lock. A shared lock will prevent other
    /// processes from acquiring a exclusive lock, but does not prevent
    /// other process from getting their own shared locks.
    ///
    /// The lock is advisory, except on Linux in very specific circumstances[1].
    /// This means that a process that does not respect the locking API can still get access
    /// to the file, despite the lock.
    ///
    /// On these operating systems, the lock is acquired atomically with
    /// opening the file:
    /// * Darwin
    /// * DragonFlyBSD
    /// * FreeBSD
    /// * Haiku
    /// * NetBSD
    /// * OpenBSD
    /// On these operating systems, the lock is acquired via a separate syscall
    /// after opening the file:
    /// * Linux
    /// * Windows
    ///
    /// [1]: https://www.kernel.org/doc/Documentation/filesystems/mandatory-locking.txt
    lock: Lock = .none,

    /// Sets whether or not to wait until the file is locked to return. If set to true,
    /// `error.WouldBlock` will be returned. Otherwise, the file will wait until the file
    /// is available to proceed.
    lock_nonblocking: bool = false,

    /// For POSIX systems this is the file system mode the file will
    /// be created with. On other systems this is always 0.
    mode: Mode = default_mode,
};

/// Upon success, the stream is in an uninitialized state. To continue using it,
/// you must use the open() function.
pub fn close(self: File) void {
    if (is_windows) {
        windows.CloseHandle(self.handle);
    } else {
        posix.close(self.handle);
    }
}

pub const SyncError = posix.SyncError;

/// Blocks until all pending file contents and metadata modifications
/// for the file have been synchronized with the underlying filesystem.
///
/// Note that this does not ensure that metadata for the
/// directory containing the file has also reached disk.
pub fn sync(self: File) SyncError!void {
    return posix.fsync(self.handle);
}

/// Test whether the file refers to a terminal.
/// See also `getOrEnableAnsiEscapeSupport` and `supportsAnsiEscapeCodes`.
pub fn isTty(self: File) bool {
    return posix.isatty(self.handle);
}

pub fn isCygwinPty(file: File) bool {
    if (builtin.os.tag != .windows) return false;

    const handle = file.handle;

    // If this is a MSYS2/cygwin pty, then it will be a named pipe with a name in one of these formats:
    //   msys-[...]-ptyN-[...]
    //   cygwin-[...]-ptyN-[...]
    //
    // Example: msys-1888ae32e00d56aa-pty0-to-master

    // First, just check that the handle is a named pipe.
    // This allows us to avoid the more costly NtQueryInformationFile call
    // for handles that aren't named pipes.
    {
        var io_status: windows.IO_STATUS_BLOCK = undefined;
        var device_info: windows.FILE_FS_DEVICE_INFORMATION = undefined;
        const rc = windows.ntdll.NtQueryVolumeInformationFile(handle, &io_status, &device_info, @sizeOf(windows.FILE_FS_DEVICE_INFORMATION), .FileFsDeviceInformation);
        switch (rc) {
            .SUCCESS => {},
            else => return false,
        }
        if (device_info.DeviceType != windows.FILE_DEVICE_NAMED_PIPE) return false;
    }

    const name_bytes_offset = @offsetOf(windows.FILE_NAME_INFO, "FileName");
    // `NAME_MAX` UTF-16 code units (2 bytes each)
    // This buffer may not be long enough to handle *all* possible paths
    // (PATH_MAX_WIDE would be necessary for that), but because we only care
    // about certain paths and we know they must be within a reasonable length,
    // we can use this smaller buffer and just return false on any error from
    // NtQueryInformationFile.
    const num_name_bytes = windows.MAX_PATH * 2;
    var name_info_bytes align(@alignOf(windows.FILE_NAME_INFO)) = [_]u8{0} ** (name_bytes_offset + num_name_bytes);

    var io_status_block: windows.IO_STATUS_BLOCK = undefined;
    const rc = windows.ntdll.NtQueryInformationFile(handle, &io_status_block, &name_info_bytes, @intCast(name_info_bytes.len), .FileNameInformation);
    switch (rc) {
        .SUCCESS => {},
        .INVALID_PARAMETER => unreachable,
        else => return false,
    }

    const name_info: *const windows.FILE_NAME_INFO = @ptrCast(&name_info_bytes);
    const name_bytes = name_info_bytes[name_bytes_offset .. name_bytes_offset + name_info.FileNameLength];
    const name_wide = std.mem.bytesAsSlice(u16, name_bytes);
    // The name we get from NtQueryInformationFile will be prefixed with a '\', e.g. \msys-1888ae32e00d56aa-pty0-to-master
    return (std.mem.startsWith(u16, name_wide, &[_]u16{ '\\', 'm', 's', 'y', 's', '-' }) or
        std.mem.startsWith(u16, name_wide, &[_]u16{ '\\', 'c', 'y', 'g', 'w', 'i', 'n', '-' })) and
        std.mem.indexOf(u16, name_wide, &[_]u16{ '-', 'p', 't', 'y' }) != null;
}

/// Returns whether or not ANSI escape codes will be treated as such,
/// and attempts to enable support for ANSI escape codes if necessary
/// (on Windows).
///
/// Returns `true` if ANSI escape codes are supported or support was
/// successfully enabled. Returns false if ANSI escape codes are not
/// supported or support was unable to be enabled.
///
/// See also `supportsAnsiEscapeCodes`.
pub fn getOrEnableAnsiEscapeSupport(self: File) bool {
    if (builtin.os.tag == .windows) {
        var original_console_mode: windows.DWORD = 0;

        // For Windows Terminal, VT Sequences processing is enabled by default.
        if (windows.kernel32.GetConsoleMode(self.handle, &original_console_mode) != 0) {
            if (original_console_mode & windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0) return true;

            // For Windows Console, VT Sequences processing support was added in Windows 10 build 14361, but disabled by default.
            // https://devblogs.microsoft.com/commandline/tmux-support-arrives-for-bash-on-ubuntu-on-windows/
            //
            // Note: In Microsoft's example for enabling virtual terminal processing, it
            // shows attempting to enable `DISABLE_NEWLINE_AUTO_RETURN` as well:
            // https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences#example-of-enabling-virtual-terminal-processing
            // This is avoided because in the old Windows Console, that flag causes \n (as opposed to \r\n)
            // to behave unexpectedly (the cursor moves down 1 row but remains on the same column).
            // Additionally, the default console mode in Windows Terminal does not have
            // `DISABLE_NEWLINE_AUTO_RETURN` set, so by only enabling `ENABLE_VIRTUAL_TERMINAL_PROCESSING`
            // we end up matching the mode of Windows Terminal.
            const requested_console_modes = windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            const console_mode = original_console_mode | requested_console_modes;
            if (windows.kernel32.SetConsoleMode(self.handle, console_mode) != 0) return true;
        }

        return self.isCygwinPty();
    }
    return self.supportsAnsiEscapeCodes();
}

/// Test whether ANSI escape codes will be treated as such without
/// attempting to enable support for ANSI escape codes.
///
/// See also `getOrEnableAnsiEscapeSupport`.
pub fn supportsAnsiEscapeCodes(self: File) bool {
    if (builtin.os.tag == .windows) {
        var console_mode: windows.DWORD = 0;
        if (windows.kernel32.GetConsoleMode(self.handle, &console_mode) != 0) {
            if (console_mode & windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0) return true;
        }

        return self.isCygwinPty();
    }
    if (builtin.os.tag == .wasi) {
        // WASI sanitizes stdout when fd is a tty so ANSI escape codes
        // will not be interpreted as actual cursor commands, and
        // stderr is always sanitized.
        return false;
    }
    if (self.isTty()) {
        if (self.handle == posix.STDOUT_FILENO or self.handle == posix.STDERR_FILENO) {
            if (posix.getenvZ("TERM")) |term| {
                if (std.mem.eql(u8, term, "dumb"))
                    return false;
            }
        }
        return true;
    }
    return false;
}

pub const SetEndPosError = posix.TruncateError;

/// Shrinks or expands the file.
/// The file offset after this call is left unchanged.
pub fn setEndPos(self: File, length: u64) SetEndPosError!void {
    try posix.ftruncate(self.handle, length);
}

pub const SeekError = posix.SeekError;

/// Repositions read/write file offset relative to the current offset.
/// TODO: integrate with async I/O
pub fn seekBy(self: File, offset: i64) SeekError!void {
    return posix.lseek_CUR(self.handle, offset);
}

/// Repositions read/write file offset relative to the end.
/// TODO: integrate with async I/O
pub fn seekFromEnd(self: File, offset: i64) SeekError!void {
    return posix.lseek_END(self.handle, offset);
}

/// Repositions read/write file offset relative to the beginning.
/// TODO: integrate with async I/O
pub fn seekTo(self: File, offset: u64) SeekError!void {
    return posix.lseek_SET(self.handle, offset);
}

pub const GetSeekPosError = posix.SeekError || StatError;

/// TODO: integrate with async I/O
pub fn getPos(self: File) GetSeekPosError!u64 {
    return posix.lseek_CUR_get(self.handle);
}

/// TODO: integrate with async I/O
pub fn getEndPos(self: File) GetSeekPosError!u64 {
    if (builtin.os.tag == .windows) {
        return windows.GetFileSizeEx(self.handle);
    }
    return (try self.stat()).size;
}

pub const ModeError = StatError;

/// TODO: integrate with async I/O
pub fn mode(self: File) ModeError!Mode {
    if (builtin.os.tag == .windows) {
        return 0;
    }
    return (try self.stat()).mode;
}

pub const Stat = struct {
    /// A number that the system uses to point to the file metadata. This
    /// number is not guaranteed to be unique across time, as some file
    /// systems may reuse an inode after its file has been deleted. Some
    /// systems may change the inode of a file over time.
    ///
    /// On Linux, the inode is a structure that stores the metadata, and
    /// the inode _number_ is what you see here: the index number of the
    /// inode.
    ///
    /// The FileIndex on Windows is similar. It is a number for a file that
    /// is unique to each filesystem.
    inode: INode,
    size: u64,
    /// This is available on POSIX systems and is always 0 otherwise.
    mode: Mode,
    kind: Kind,

    /// Last access time in nanoseconds, relative to UTC 1970-01-01.
    atime: i128,
    /// Last modification time in nanoseconds, relative to UTC 1970-01-01.
    mtime: i128,
    /// Last status/metadata change time in nanoseconds, relative to UTC 1970-01-01.
    ctime: i128,

    pub fn fromPosix(st: posix.Stat) Stat {
        const atime = st.atime();
        const mtime = st.mtime();
        const ctime = st.ctime();
        return .{
            .inode = st.ino,
            .size = @bitCast(st.size),
            .mode = st.mode,
            .kind = k: {
                const m = st.mode & posix.S.IFMT;
                switch (m) {
                    posix.S.IFBLK => break :k .block_device,
                    posix.S.IFCHR => break :k .character_device,
                    posix.S.IFDIR => break :k .directory,
                    posix.S.IFIFO => break :k .named_pipe,
                    posix.S.IFLNK => break :k .sym_link,
                    posix.S.IFREG => break :k .file,
                    posix.S.IFSOCK => break :k .unix_domain_socket,
                    else => {},
                }
                if (builtin.os.tag.isSolarish()) switch (m) {
                    posix.S.IFDOOR => break :k .door,
                    posix.S.IFPORT => break :k .event_port,
                    else => {},
                };

                break :k .unknown;
            },
            .atime = @as(i128, atime.sec) * std.time.ns_per_s + atime.nsec,
            .mtime = @as(i128, mtime.sec) * std.time.ns_per_s + mtime.nsec,
            .ctime = @as(i128, ctime.sec) * std.time.ns_per_s + ctime.nsec,
        };
    }

    pub fn fromLinux(stx: linux.Statx) Stat {
        const atime = stx.atime;
        const mtime = stx.mtime;
        const ctime = stx.ctime;

        return .{
            .inode = stx.ino,
            .size = stx.size,
            .mode = stx.mode,
            .kind = switch (stx.mode & linux.S.IFMT) {
                linux.S.IFDIR => .directory,
                linux.S.IFCHR => .character_device,
                linux.S.IFBLK => .block_device,
                linux.S.IFREG => .file,
                linux.S.IFIFO => .named_pipe,
                linux.S.IFLNK => .sym_link,
                linux.S.IFSOCK => .unix_domain_socket,
                else => .unknown,
            },
            .atime = @as(i128, atime.sec) * std.time.ns_per_s + atime.nsec,
            .mtime = @as(i128, mtime.sec) * std.time.ns_per_s + mtime.nsec,
            .ctime = @as(i128, ctime.sec) * std.time.ns_per_s + ctime.nsec,
        };
    }

    pub fn fromWasi(st: std.os.wasi.filestat_t) Stat {
        return .{
            .inode = st.ino,
            .size = @bitCast(st.size),
            .mode = 0,
            .kind = switch (st.filetype) {
                .BLOCK_DEVICE => .block_device,
                .CHARACTER_DEVICE => .character_device,
                .DIRECTORY => .directory,
                .SYMBOLIC_LINK => .sym_link,
                .REGULAR_FILE => .file,
                .SOCKET_STREAM, .SOCKET_DGRAM => .unix_domain_socket,
                else => .unknown,
            },
            .atime = st.atim,
            .mtime = st.mtim,
            .ctime = st.ctim,
        };
    }
};

pub const StatError = posix.FStatError;

/// Returns `Stat` containing basic information about the `File`.
/// Use `metadata` to retrieve more detailed information (e.g. creation time, permissions).
/// TODO: integrate with async I/O
pub fn stat(self: File) StatError!Stat {
    if (builtin.os.tag == .windows) {
        var io_status_block: windows.IO_STATUS_BLOCK = undefined;
        var info: windows.FILE_ALL_INFORMATION = undefined;
        const rc = windows.ntdll.NtQueryInformationFile(self.handle, &io_status_block, &info, @sizeOf(windows.FILE_ALL_INFORMATION), .FileAllInformation);
        switch (rc) {
            .SUCCESS => {},
            // Buffer overflow here indicates that there is more information available than was able to be stored in the buffer
            // size provided. This is treated as success because the type of variable-length information that this would be relevant for
            // (name, volume name, etc) we don't care about.
            .BUFFER_OVERFLOW => {},
            .INVALID_PARAMETER => unreachable,
            .ACCESS_DENIED => return error.AccessDenied,
            else => return windows.unexpectedStatus(rc),
        }
        return .{
            .inode = info.InternalInformation.IndexNumber,
            .size = @as(u64, @bitCast(info.StandardInformation.EndOfFile)),
            .mode = 0,
            .kind = if (info.BasicInformation.FileAttributes & windows.FILE_ATTRIBUTE_REPARSE_POINT != 0) reparse_point: {
                var tag_info: windows.FILE_ATTRIBUTE_TAG_INFO = undefined;
                const tag_rc = windows.ntdll.NtQueryInformationFile(self.handle, &io_status_block, &tag_info, @sizeOf(windows.FILE_ATTRIBUTE_TAG_INFO), .FileAttributeTagInformation);
                switch (tag_rc) {
                    .SUCCESS => {},
                    // INFO_LENGTH_MISMATCH and ACCESS_DENIED are the only documented possible errors
                    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d295752f-ce89-4b98-8553-266d37c84f0e
                    .INFO_LENGTH_MISMATCH => unreachable,
                    .ACCESS_DENIED => return error.AccessDenied,
                    else => return windows.unexpectedStatus(rc),
                }
                if (tag_info.ReparseTag & windows.reparse_tag_name_surrogate_bit != 0) {
                    break :reparse_point .sym_link;
                }
                // Unknown reparse point
                break :reparse_point .unknown;
            } else if (info.BasicInformation.FileAttributes & windows.FILE_ATTRIBUTE_DIRECTORY != 0)
                .directory
            else
                .file,
            .atime = windows.fromSysTime(info.BasicInformation.LastAccessTime),
            .mtime = windows.fromSysTime(info.BasicInformation.LastWriteTime),
            .ctime = windows.fromSysTime(info.BasicInformation.ChangeTime),
        };
    }

    if (builtin.os.tag == .wasi and !builtin.link_libc) {
        const st = try std.os.fstat_wasi(self.handle);
        return Stat.fromWasi(st);
    }

    if (builtin.os.tag == .linux) {
        var stx = std.mem.zeroes(linux.Statx);

        const rc = linux.statx(
            self.handle,
            "",
            linux.AT.EMPTY_PATH,
            linux.STATX_TYPE | linux.STATX_MODE | linux.STATX_ATIME | linux.STATX_MTIME | linux.STATX_CTIME,
            &stx,
        );

        return switch (linux.E.init(rc)) {
            .SUCCESS => Stat.fromLinux(stx),
            .ACCES => unreachable,
            .BADF => unreachable,
            .FAULT => unreachable,
            .INVAL => unreachable,
            .LOOP => unreachable,
            .NAMETOOLONG => unreachable,
            .NOENT => unreachable,
            .NOMEM => error.SystemResources,
            .NOTDIR => unreachable,
            else => |err| posix.unexpectedErrno(err),
        };
    }

    const st = try posix.fstat(self.handle);
    return Stat.fromPosix(st);
}

pub const ChmodError = posix.FChmodError;

/// Changes the mode of the file.
/// The process must have the correct privileges in order to do this
/// successfully, or must have the effective user ID matching the owner
/// of the file.
pub fn chmod(self: File, new_mode: Mode) ChmodError!void {
    try posix.fchmod(self.handle, new_mode);
}

pub const ChownError = posix.FChownError;

/// Changes the owner and group of the file.
/// The process must have the correct privileges in order to do this
/// successfully. The group may be changed by the owner of the file to
/// any group of which the owner is a member. If the owner or group is
/// specified as `null`, the ID is not changed.
pub fn chown(self: File, owner: ?Uid, group: ?Gid) ChownError!void {
    try posix.fchown(self.handle, owner, group);
}

/// Cross-platform representation of permissions on a file.
/// The `readonly` and `setReadonly` are the only methods available across all platforms.
/// Platform-specific functionality is available through the `inner` field.
pub const Permissions = struct {
    /// You may use the `inner` field to use platform-specific functionality
    inner: switch (builtin.os.tag) {
        .windows => PermissionsWindows,
        else => PermissionsUnix,
    },

    const Self = @This();

    /// Returns `true` if permissions represent an unwritable file.
    /// On Unix, `true` is returned only if no class has write permissions.
    pub fn readOnly(self: Self) bool {
        return self.inner.readOnly();
    }

    /// Sets whether write permissions are provided.
    /// On Unix, this affects *all* classes. If this is undesired, use `unixSet`.
    /// This method *DOES NOT* set permissions on the filesystem: use `File.setPermissions(permissions)`
    pub fn setReadOnly(self: *Self, read_only: bool) void {
        self.inner.setReadOnly(read_only);
    }
};

pub const PermissionsWindows = struct {
    attributes: windows.DWORD,

    const Self = @This();

    /// Returns `true` if permissions represent an unwritable file.
    pub fn readOnly(self: Self) bool {
        return self.attributes & windows.FILE_ATTRIBUTE_READONLY != 0;
    }

    /// Sets whether write permissions are provided.
    /// This method *DOES NOT* set permissions on the filesystem: use `File.setPermissions(permissions)`
    pub fn setReadOnly(self: *Self, read_only: bool) void {
        if (read_only) {
            self.attributes |= windows.FILE_ATTRIBUTE_READONLY;
        } else {
            self.attributes &= ~@as(windows.DWORD, windows.FILE_ATTRIBUTE_READONLY);
        }
    }
};

pub const PermissionsUnix = struct {
    mode: Mode,

    const Self = @This();

    /// Returns `true` if permissions represent an unwritable file.
    /// `true` is returned only if no class has write permissions.
    pub fn readOnly(self: Self) bool {
        return self.mode & 0o222 == 0;
    }

    /// Sets whether write permissions are provided.
    /// This affects *all* classes. If this is undesired, use `unixSet`.
    /// This method *DOES NOT* set permissions on the filesystem: use `File.setPermissions(permissions)`
    pub fn setReadOnly(self: *Self, read_only: bool) void {
        if (read_only) {
            self.mode &= ~@as(Mode, 0o222);
        } else {
            self.mode |= @as(Mode, 0o222);
        }
    }

    pub const Class = enum(u2) {
        user = 2,
        group = 1,
        other = 0,
    };

    pub const Permission = enum(u3) {
        read = 0o4,
        write = 0o2,
        execute = 0o1,
    };

    /// Returns `true` if the chosen class has the selected permission.
    /// This method is only available on Unix platforms.
    pub fn unixHas(self: Self, class: Class, permission: Permission) bool {
        const mask = @as(Mode, @intFromEnum(permission)) << @as(u3, @intFromEnum(class)) * 3;
        return self.mode & mask != 0;
    }

    /// Sets the permissions for the chosen class. Any permissions set to `null` are left unchanged.
    /// This method *DOES NOT* set permissions on the filesystem: use `File.setPermissions(permissions)`
    pub fn unixSet(self: *Self, class: Class, permissions: struct {
        read: ?bool = null,
        write: ?bool = null,
        execute: ?bool = null,
    }) void {
        const shift = @as(u3, @intFromEnum(class)) * 3;
        if (permissions.read) |r| {
            if (r) {
                self.mode |= @as(Mode, 0o4) << shift;
            } else {
                self.mode &= ~(@as(Mode, 0o4) << shift);
            }
        }
        if (permissions.write) |w| {
            if (w) {
                self.mode |= @as(Mode, 0o2) << shift;
            } else {
                self.mode &= ~(@as(Mode, 0o2) << shift);
            }
        }
        if (permissions.execute) |x| {
            if (x) {
                self.mode |= @as(Mode, 0o1) << shift;
            } else {
                self.mode &= ~(@as(Mode, 0o1) << shift);
            }
        }
    }

    /// Returns a `Permissions` struct representing the permissions from the passed mode.
    pub fn unixNew(new_mode: Mode) Self {
        return Self{
            .mode = new_mode,
        };
    }
};

pub const SetPermissionsError = ChmodError;

/// Sets permissions according to the provided `Permissions` struct.
/// This method is *NOT* available on WASI
pub fn setPermissions(self: File, permissions: Permissions) SetPermissionsError!void {
    switch (builtin.os.tag) {
        .windows => {
            var io_status_block: windows.IO_STATUS_BLOCK = undefined;
            var info = windows.FILE_BASIC_INFORMATION{
                .CreationTime = 0,
                .LastAccessTime = 0,
                .LastWriteTime = 0,
                .ChangeTime = 0,
                .FileAttributes = permissions.inner.attributes,
            };
            const rc = windows.ntdll.NtSetInformationFile(
                self.handle,
                &io_status_block,
                &info,
                @sizeOf(windows.FILE_BASIC_INFORMATION),
                .FileBasicInformation,
            );
            switch (rc) {
                .SUCCESS => return,
                .INVALID_HANDLE => unreachable,
                .ACCESS_DENIED => return error.AccessDenied,
                else => return windows.unexpectedStatus(rc),
            }
        },
        .wasi => @compileError("Unsupported OS"), // Wasi filesystem does not *yet* support chmod
        else => {
            try self.chmod(permissions.inner.mode);
        },
    }
}

/// Cross-platform representation of file metadata.
/// Platform-specific functionality is available through the `inner` field.
pub const Metadata = struct {
    /// Exposes platform-specific functionality.
    inner: switch (builtin.os.tag) {
        .windows => MetadataWindows,
        .linux => MetadataLinux,
        .wasi => MetadataWasi,
        else => MetadataUnix,
    },

    const Self = @This();

    /// Returns the size of the file
    pub fn size(self: Self) u64 {
        return self.inner.size();
    }

    /// Returns a `Permissions` struct, representing the permissions on the file
    pub fn permissions(self: Self) Permissions {
        return self.inner.permissions();
    }

    /// Returns the `Kind` of file.
    /// On Windows, can only return: `.file`, `.directory`, `.sym_link` or `.unknown`
    pub fn kind(self: Self) Kind {
        return self.inner.kind();
    }

    /// Returns the last time the file was accessed in nanoseconds since UTC 1970-01-01
    pub fn accessed(self: Self) i128 {
        return self.inner.accessed();
    }

    /// Returns the time the file was modified in nanoseconds since UTC 1970-01-01
    pub fn modified(self: Self) i128 {
        return self.inner.modified();
    }

    /// Returns the time the file was created in nanoseconds since UTC 1970-01-01
    /// On Windows, this cannot return null
    /// On Linux, this returns null if the filesystem does not support creation times
    /// On Unices, this returns null if the filesystem or OS does not support creation times
    /// On MacOS, this returns the ctime if the filesystem does not support creation times; this is insanity, and yet another reason to hate on Apple
    pub fn created(self: Self) ?i128 {
        return self.inner.created();
    }
};

pub const MetadataUnix = struct {
    stat: posix.Stat,

    const Self = @This();

    /// Returns the size of the file
    pub fn size(self: Self) u64 {
        return @intCast(self.stat.size);
    }

    /// Returns a `Permissions` struct, representing the permissions on the file
    pub fn permissions(self: Self) Permissions {
        return .{ .inner = .{ .mode = self.stat.mode } };
    }

    /// Returns the `Kind` of the file
    pub fn kind(self: Self) Kind {
        if (builtin.os.tag == .wasi and !builtin.link_libc) return switch (self.stat.filetype) {
            .BLOCK_DEVICE => .block_device,
            .CHARACTER_DEVICE => .character_device,
            .DIRECTORY => .directory,
            .SYMBOLIC_LINK => .sym_link,
            .REGULAR_FILE => .file,
            .SOCKET_STREAM, .SOCKET_DGRAM => .unix_domain_socket,
            else => .unknown,
        };

        const m = self.stat.mode & posix.S.IFMT;

        switch (m) {
            posix.S.IFBLK => return .block_device,
            posix.S.IFCHR => return .character_device,
            posix.S.IFDIR => return .directory,
            posix.S.IFIFO => return .named_pipe,
            posix.S.IFLNK => return .sym_link,
            posix.S.IFREG => return .file,
            posix.S.IFSOCK => return .unix_domain_socket,
            else => {},
        }

        if (builtin.os.tag.isSolarish()) switch (m) {
            posix.S.IFDOOR => return .door,
            posix.S.IFPORT => return .event_port,
            else => {},
        };

        return .unknown;
    }

    /// Returns the last time the file was accessed in nanoseconds since UTC 1970-01-01
    pub fn accessed(self: Self) i128 {
        const atime = self.stat.atime();
        return @as(i128, atime.sec) * std.time.ns_per_s + atime.nsec;
    }

    /// Returns the last time the file was modified in nanoseconds since UTC 1970-01-01
    pub fn modified(self: Self) i128 {
        const mtime = self.stat.mtime();
        return @as(i128, mtime.sec) * std.time.ns_per_s + mtime.nsec;
    }

    /// Returns the time the file was created in nanoseconds since UTC 1970-01-01.
    /// Returns null if this is not supported by the OS or filesystem
    pub fn created(self: Self) ?i128 {
        if (!@hasDecl(@TypeOf(self.stat), "birthtime")) return null;
        const birthtime = self.stat.birthtime();

        // If the filesystem doesn't support this the value *should* be:
        // On FreeBSD: nsec = 0, sec = -1
        // On NetBSD and OpenBSD: nsec = 0, sec = 0
        // On MacOS, it is set to ctime -- we cannot detect this!!
        switch (builtin.os.tag) {
            .freebsd => if (birthtime.sec == -1 and birthtime.nsec == 0) return null,
            .netbsd, .openbsd => if (birthtime.sec == 0 and birthtime.nsec == 0) return null,
            .macos => {},
            else => @compileError("Creation time detection not implemented for OS"),
        }

        return @as(i128, birthtime.sec) * std.time.ns_per_s + birthtime.nsec;
    }
};

/// `MetadataUnix`, but using Linux's `statx` syscall.
pub const MetadataLinux = struct {
    statx: std.os.linux.Statx,

    const Self = @This();

    /// Returns the size of the file
    pub fn size(self: Self) u64 {
        return self.statx.size;
    }

    /// Returns a `Permissions` struct, representing the permissions on the file
    pub fn permissions(self: Self) Permissions {
        return Permissions{ .inner = PermissionsUnix{ .mode = self.statx.mode } };
    }

    /// Returns the `Kind` of the file
    pub fn kind(self: Self) Kind {
        const m = self.statx.mode & posix.S.IFMT;

        switch (m) {
            posix.S.IFBLK => return .block_device,
            posix.S.IFCHR => return .character_device,
            posix.S.IFDIR => return .directory,
            posix.S.IFIFO => return .named_pipe,
            posix.S.IFLNK => return .sym_link,
            posix.S.IFREG => return .file,
            posix.S.IFSOCK => return .unix_domain_socket,
            else => {},
        }

        return .unknown;
    }

    /// Returns the last time the file was accessed in nanoseconds since UTC 1970-01-01
    pub fn accessed(self: Self) i128 {
        return @as(i128, self.statx.atime.sec) * std.time.ns_per_s + self.statx.atime.nsec;
    }

    /// Returns the last time the file was modified in nanoseconds since UTC 1970-01-01
    pub fn modified(self: Self) i128 {
        return @as(i128, self.statx.mtime.sec) * std.time.ns_per_s + self.statx.mtime.nsec;
    }

    /// Returns the time the file was created in nanoseconds since UTC 1970-01-01.
    /// Returns null if this is not supported by the filesystem, or on kernels before than version 4.11
    pub fn created(self: Self) ?i128 {
        if (self.statx.mask & std.os.linux.STATX_BTIME == 0) return null;
        return @as(i128, self.statx.btime.sec) * std.time.ns_per_s + self.statx.btime.nsec;
    }
};

pub const MetadataWasi = struct {
    stat: std.os.wasi.filestat_t,

    pub fn size(self: @This()) u64 {
        return self.stat.size;
    }

    pub fn permissions(self: @This()) Permissions {
        return .{ .inner = .{ .mode = self.stat.mode } };
    }

    pub fn kind(self: @This()) Kind {
        return switch (self.stat.filetype) {
            .BLOCK_DEVICE => .block_device,
            .CHARACTER_DEVICE => .c```
