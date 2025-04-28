```
   return error.StaticElfFile;
    }

    if (builtin.target.os.tag == .linux and result.isGnuLibC() and
        query.glibc_version == null)
    {
        const shstrndx = elfInt(is_64, need_bswap, hdr32.e_shstrndx, hdr64.e_shstrndx);

        var shoff = elfInt(is_64, need_bswap, hdr32.e_shoff, hdr64.e_shoff);
        const shentsize = elfInt(is_64, need_bswap, hdr32.e_shentsize, hdr64.e_shentsize);
        const str_section_off = shoff + @as(u64, shentsize) * @as(u64, shstrndx);

        var sh_buf: [16 * @sizeOf(elf.Elf64_Shdr)]u8 align(@alignOf(elf.Elf64_Shdr)) = undefined;
        if (sh_buf.len < shentsize) return error.InvalidElfFile;

        _ = try preadAtLeast(file, &sh_buf, str_section_off, shentsize);
        const shstr32: *elf.Elf32_Shdr = @ptrCast(@alignCast(&sh_buf));
        const shstr64: *elf.Elf64_Shdr = @ptrCast(@alignCast(&sh_buf));
        const shstrtab_off = elfInt(is_64, need_bswap, shstr32.sh_offset, shstr64.sh_offset);
        const shstrtab_size = elfInt(is_64, need_bswap, shstr32.sh_size, shstr64.sh_size);
        var strtab_buf: [4096:0]u8 = undefined;
        const shstrtab_len = @min(shstrtab_size, strtab_buf.len);
        const shstrtab_read_len = try preadAtLeast(file, &strtab_buf, shstrtab_off, shstrtab_len);
        const shstrtab = strtab_buf[0..shstrtab_read_len];

        const shnum = elfInt(is_64, need_bswap, hdr32.e_shnum, hdr64.e_shnum);
        var sh_i: u16 = 0;
        const dynstr: ?struct { offset: u64, size: u64 } = find_dyn_str: while (sh_i < shnum) {
            // Reserve some bytes so that we can deref the 64-bit struct fields
            // even when the ELF file is 32-bits.
            const sh_reserve: usize = @sizeOf(elf.Elf64_Shdr) - @sizeOf(elf.Elf32_Shdr);
            const sh_read_byte_len = try preadAtLeast(
                file,
                sh_buf[0 .. sh_buf.len - sh_reserve],
                shoff,
                shentsize,
            );
            var sh_buf_i: usize = 0;
            while (sh_buf_i < sh_read_byte_len and sh_i < shnum) : ({
                sh_i += 1;
                shoff += shentsize;
                sh_buf_i += shentsize;
            }) {
                const sh32: *elf.Elf32_Shdr = @ptrCast(@alignCast(&sh_buf[sh_buf_i]));
                const sh64: *elf.Elf64_Shdr = @ptrCast(@alignCast(&sh_buf[sh_buf_i]));
                const sh_name_off = elfInt(is_64, need_bswap, sh32.sh_name, sh64.sh_name);
                const sh_name = mem.sliceTo(shstrtab[sh_name_off..], 0);
                if (mem.eql(u8, sh_name, ".dynstr")) {
                    break :find_dyn_str .{
                        .offset = elfInt(is_64, need_bswap, sh32.sh_offset, sh64.sh_offset),
                        .size = elfInt(is_64, need_bswap, sh32.sh_size, sh64.sh_size),
                    };
                }
            }
        } else null;

        if (dynstr) |ds| {
            if (rpath_offset) |rpoff| {
                if (rpoff > ds.size) return error.InvalidElfFile;
                const rpoff_file = ds.offset + rpoff;
                const rp_max_size = ds.size - rpoff;

                const strtab_len = @min(rp_max_size, strtab_buf.len);
                const strtab_read_len = try preadAtLeast(file, &strtab_buf, rpoff_file, strtab_len);
                const strtab = strtab_buf[0..strtab_read_len];

                const rpath_list = mem.sliceTo(strtab, 0);
                var it = mem.tokenizeScalar(u8, rpath_list, ':');
                while (it.next()) |rpath| {
                    if (glibcVerFromRPath(rpath)) |ver| {
                        result.os.version_range.linux.glibc = ver;
                        return result;
                    } else |err| switch (err) {
                        error.GLibCNotFound => continue,
                        else => |e| return e,
                    }
                }
            }
        }

        if (result.dynamic_linker.get()) |dl_path| glibc_ver: {
            // There is no DT_RUNPATH so we try to find libc.so.6 inside the same
            // directory as the dynamic linker.
            if (fs.path.dirname(dl_path)) |rpath| {
                if (glibcVerFromRPath(rpath)) |ver| {
                    result.os.version_range.linux.glibc = ver;
                    return result;
                } else |err| switch (err) {
                    error.GLibCNotFound => {},
                    else => |e| return e,
                }
            }

            // So far, no luck. Next we try to see if the information is
            // present in the symlink data for the dynamic linker path.
            var link_buf: [posix.PATH_MAX]u8 = undefined;
            const link_name = posix.readlink(dl_path, &link_buf) catch |err| switch (err) {
                error.NameTooLong => unreachable,
                error.InvalidUtf8 => unreachable, // WASI only
                error.InvalidWtf8 => unreachable, // Windows only
                error.BadPathName => unreachable, // Windows only
                error.UnsupportedReparsePointType => unreachable, // Windows only
                error.NetworkNotFound => unreachable, // Windows only

                error.AccessDenied,
                error.PermissionDenied,
                error.FileNotFound,
                error.NotLink,
                error.NotDir,
                => break :glibc_ver,

                error.SystemResources,
                error.FileSystem,
                error.SymLinkLoop,
                error.Unexpected,
                => |e| return e,
            };
            result.os.version_range.linux.glibc = glibcVerFromLinkName(
                fs.path.basename(link_name),
                "ld-",
            ) catch |err| switch (err) {
                error.UnrecognizedGnuLibCFileName,
                error.InvalidGnuLibCVersion,
                => break :glibc_ver,
            };
            return result;
        }

        // Nothing worked so far. Finally we fall back to hard-coded search paths.
        // Some distros such as Debian keep their libc.so.6 in `/lib/$triple/`.
        var path_buf: [posix.PATH_MAX]u8 = undefined;
        var index: usize = 0;
        const prefix = "/lib/";
        const cpu_arch = @tagName(result.cpu.arch);
        const os_tag = @tagName(result.os.tag);
        const abi = @tagName(result.abi);
        @memcpy(path_buf[index..][0..prefix.len], prefix);
        index += prefix.len;
        @memcpy(path_buf[index..][0..cpu_arch.len], cpu_arch);
        index += cpu_arch.len;
        path_buf[index] = '-';
        index += 1;
        @memcpy(path_buf[index..][0..os_tag.len], os_tag);
        index += os_tag.len;
        path_buf[index] = '-';
        index += 1;
        @memcpy(path_buf[index..][0..abi.len], abi);
        index += abi.len;
        const rpath = path_buf[0..index];
        if (glibcVerFromRPath(rpath)) |ver| {
            result.os.version_range.linux.glibc = ver;
            return result;
        } else |err| switch (err) {
            error.GLibCNotFound => {},
            else => |e| return e,
        }
    }

    return result;
}

fn glibcVerFromLinkName(link_name: []const u8, prefix: []const u8) error{ UnrecognizedGnuLibCFileName, InvalidGnuLibCVersion }!std.SemanticVersion {
    // example: "libc-2.3.4.so"
    // example: "libc-2.27.so"
    // example: "ld-2.33.so"
    const suffix = ".so";
    if (!mem.startsWith(u8, link_name, prefix) or !mem.endsWith(u8, link_name, suffix)) {
        return error.UnrecognizedGnuLibCFileName;
    }
    // chop off "libc-" and ".so"
    const link_name_chopped = link_name[prefix.len .. link_name.len - suffix.len];
    return Target.Query.parseVersion(link_name_chopped) catch |err| switch (err) {
        error.Overflow => return error.InvalidGnuLibCVersion,
        error.InvalidVersion => return error.InvalidGnuLibCVersion,
    };
}

test glibcVerFromLinkName {
    try std.testing.expectError(error.UnrecognizedGnuLibCFileName, glibcVerFromLinkName("ld-2.37.so", "this-prefix-does-not-exist"));
    try std.testing.expectError(error.UnrecognizedGnuLibCFileName, glibcVerFromLinkName("libc-2.37.so-is-not-end", "libc-"));

    try std.testing.expectError(error.InvalidGnuLibCVersion, glibcVerFromLinkName("ld-2.so", "ld-"));
    try std.testing.expectEqual(std.SemanticVersion{ .major = 2, .minor = 37, .patch = 0 }, try glibcVerFromLinkName("ld-2.37.so", "ld-"));
    try std.testing.expectEqual(std.SemanticVersion{ .major = 2, .minor = 37, .patch = 0 }, try glibcVerFromLinkName("ld-2.37.0.so", "ld-"));
    try std.testing.expectEqual(std.SemanticVersion{ .major = 2, .minor = 37, .patch = 1 }, try glibcVerFromLinkName("ld-2.37.1.so", "ld-"));
    try std.testing.expectError(error.InvalidGnuLibCVersion, glibcVerFromLinkName("ld-2.37.4.5.so", "ld-"));
}

fn glibcVerFromRPath(rpath: []const u8) !std.SemanticVersion {
    var dir = fs.cwd().openDir(rpath, .{}) catch |err| switch (err) {
        error.NameTooLong => unreachable,
        error.InvalidUtf8 => unreachable, // WASI only
        error.InvalidWtf8 => unreachable, // Windows-only
        error.BadPathName => unreachable,
        error.DeviceBusy => unreachable,
        error.NetworkNotFound => unreachable, // Windows-only

        error.FileNotFound,
        error.NotDir,
        error.AccessDenied,
        error.PermissionDenied,
        error.NoDevice,
        => return error.GLibCNotFound,

        error.ProcessNotFound,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.SystemResources,
        error.SymLinkLoop,
        error.Unexpected,
        => |e| return e,
    };
    defer dir.close();

    // Now we have a candidate for the path to libc shared object. In
    // the past, we used readlink() here because the link name would
    // reveal the glibc version. However, in more recent GNU/Linux
    // installations, there is no symlink. Thus we instead use a more
    // robust check of opening the libc shared object and looking at the
    // .dynstr section, and finding the max version number of symbols
    // that start with "GLIBC_2.".
    const glibc_so_basename = "libc.so.6";
    var f = dir.openFile(glibc_so_basename, .{}) catch |err| switch (err) {
        error.NameTooLong => unreachable,
        error.InvalidUtf8 => unreachable, // WASI only
        error.InvalidWtf8 => unreachable, // Windows only
        error.BadPathName => unreachable, // Windows only
        error.PipeBusy => unreachable, // Windows-only
        error.SharingViolation => unreachable, // Windows-only
        error.NetworkNotFound => unreachable, // Windows-only
        error.AntivirusInterference => unreachable, // Windows-only
        error.FileLocksNotSupported => unreachable, // No lock requested.
        error.NoSpaceLeft => unreachable, // read-only
        error.PathAlreadyExists => unreachable, // read-only
        error.DeviceBusy => unreachable, // read-only
        error.FileBusy => unreachable, // read-only
        error.WouldBlock => unreachable, // not using O_NONBLOCK
        error.NoDevice => unreachable, // not asking for a special device

        error.AccessDenied,
        error.PermissionDenied,
        error.FileNotFound,
        error.NotDir,
        error.IsDir,
        => return error.GLibCNotFound,

        error.FileTooBig => return error.Unexpected,

        error.ProcessNotFound,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.SystemResources,
        error.SymLinkLoop,
        error.Unexpected,
        => |e| return e,
    };
    defer f.close();

    return glibcVerFromSoFile(f) catch |err| switch (err) {
        error.InvalidElfMagic,
        error.InvalidElfEndian,
        error.InvalidElfClass,
        error.InvalidElfFile,
        error.InvalidElfVersion,
        error.InvalidGnuLibCVersion,
        error.UnexpectedEndOfFile,
        => return error.GLibCNotFound,

        error.SystemResources,
        error.UnableToReadElfFile,
        error.Unexpected,
        error.FileSystem,
        error.ProcessNotFound,
        => |e| return e,
    };
}

fn glibcVerFromSoFile(file: fs.File) !std.SemanticVersion {
    var hdr_buf: [@sizeOf(elf.Elf64_Ehdr)]u8 align(@alignOf(elf.Elf64_Ehdr)) = undefined;
    _ = try preadAtLeast(file, &hdr_buf, 0, hdr_buf.len);
    const hdr32: *elf.Elf32_Ehdr = @ptrCast(&hdr_buf);
    const hdr64: *elf.Elf64_Ehdr = @ptrCast(&hdr_buf);
    if (!mem.eql(u8, hdr32.e_ident[0..4], elf.MAGIC)) return error.InvalidElfMagic;
    const elf_endian: std.builtin.Endian = switch (hdr32.e_ident[elf.EI_DATA]) {
        elf.ELFDATA2LSB => .little,
        elf.ELFDATA2MSB => .big,
        else => return error.InvalidElfEndian,
    };
    const need_bswap = elf_endian != native_endian;
    if (hdr32.e_ident[elf.EI_VERSION] != 1) return error.InvalidElfVersion;

    const is_64 = switch (hdr32.e_ident[elf.EI_CLASS]) {
        elf.ELFCLASS32 => false,
        elf.ELFCLASS64 => true,
        else => return error.InvalidElfClass,
    };
    const shstrndx = elfInt(is_64, need_bswap, hdr32.e_shstrndx, hdr64.e_shstrndx);
    var shoff = elfInt(is_64, need_bswap, hdr32.e_shoff, hdr64.e_shoff);
    const shentsize = elfInt(is_64, need_bswap, hdr32.e_shentsize, hdr64.e_shentsize);
    const str_section_off = shoff + @as(u64, shentsize) * @as(u64, shstrndx);
    var sh_buf: [16 * @sizeOf(elf.Elf64_Shdr)]u8 align(@alignOf(elf.Elf64_Shdr)) = undefined;
    if (sh_buf.len < shentsize) return error.InvalidElfFile;

    _ = try preadAtLeast(file, &sh_buf, str_section_off, shentsize);
    const shstr32: *elf.Elf32_Shdr = @ptrCast(@alignCast(&sh_buf));
    const shstr64: *elf.Elf64_Shdr = @ptrCast(@alignCast(&sh_buf));
    const shstrtab_off = elfInt(is_64, need_bswap, shstr32.sh_offset, shstr64.sh_offset);
    const shstrtab_size = elfInt(is_64, need_bswap, shstr32.sh_size, shstr64.sh_size);
    var strtab_buf: [4096:0]u8 = undefined;
    const shstrtab_len = @min(shstrtab_size, strtab_buf.len);
    const shstrtab_read_len = try preadAtLeast(file, &strtab_buf, shstrtab_off, shstrtab_len);
    const shstrtab = strtab_buf[0..shstrtab_read_len];
    const shnum = elfInt(is_64, need_bswap, hdr32.e_shnum, hdr64.e_shnum);
    var sh_i: u16 = 0;
    const dynstr: struct { offset: u64, size: u64 } = find_dyn_str: while (sh_i < shnum) {
        // Reserve some bytes so that we can deref the 64-bit struct fields
        // even when the ELF file is 32-bits.
        const sh_reserve: usize = @sizeOf(elf.Elf64_Shdr) - @sizeOf(elf.Elf32_Shdr);
        const sh_read_byte_len = try preadAtLeast(
            file,
            sh_buf[0 .. sh_buf.len - sh_reserve],
            shoff,
            shentsize,
        );
        var sh_buf_i: usize = 0;
        while (sh_buf_i < sh_read_byte_len and sh_i < shnum) : ({
            sh_i += 1;
            shoff += shentsize;
            sh_buf_i += shentsize;
        }) {
            const sh32: *elf.Elf32_Shdr = @ptrCast(@alignCast(&sh_buf[sh_buf_i]));
            const sh64: *elf.Elf64_Shdr = @ptrCast(@alignCast(&sh_buf[sh_buf_i]));
            const sh_name_off = elfInt(is_64, need_bswap, sh32.sh_name, sh64.sh_name);
            const sh_name = mem.sliceTo(shstrtab[sh_name_off..], 0);
            if (mem.eql(u8, sh_name, ".dynstr")) {
                break :find_dyn_str .{
                    .offset = elfInt(is_64, need_bswap, sh32.sh_offset, sh64.sh_offset),
                    .size = elfInt(is_64, need_bswap, sh32.sh_size, sh64.sh_size),
                };
            }
        }
    } else return error.InvalidGnuLibCVersion;

    // Here we loop over all the strings in the dynstr string table, assuming that any
    // strings that start with "GLIBC_2." indicate the existence of such a glibc version,
    // and furthermore, that the system-installed glibc is at minimum that version.

    // Empirically, glibc 2.34 libc.so .dynstr section is 32441 bytes on my system.
    // Here I use double this value plus some headroom. This makes it only need
    // a single read syscall here.
    var buf: [80000]u8 = undefined;
    if (buf.len < dynstr.size) return error.InvalidGnuLibCVersion;

    const dynstr_size: usize = @intCast(dynstr.size);
    const dynstr_bytes = buf[0..dynstr_size];
    _ = try preadAtLeast(file, dynstr_bytes, dynstr.offset, dynstr_bytes.len);
    var it = mem.splitScalar(u8, dynstr_bytes, 0);
    var max_ver: std.SemanticVersion = .{ .major = 2, .minor = 2, .patch = 5 };
    while (it.next()) |s| {
        if (mem.startsWith(u8, s, "GLIBC_2.")) {
            const chopped = s["GLIBC_".len..];
            const ver = Target.Query.parseVersion(chopped) catch |err| switch (err) {
                error.Overflow => return error.InvalidGnuLibCVersion,
                error.InvalidVersion => return error.InvalidGnuLibCVersion,
            };
            switch (ver.order(max_ver)) {
                .gt => max_ver = ver,
                .lt, .eq => continue,
            }
        }
    }
    return max_ver;
}

/// In the past, this function attempted to use the executable's own binary if it was dynamically
/// linked to answer both the C ABI question and the dynamic linker question. However, this
/// could be problematic on a system that uses a RUNPATH for the compiler binary, locking
/// it to an older glibc version, while system binaries such as /usr/bin/env use a newer glibc
/// version. The problem is that libc.so.6 glibc version will match that of the system while
/// the dynamic linker will match that of the compiler binary. Executables with these versions
/// mismatching will fail to run.
///
/// Therefore, this function works the same regardless of whether the compiler binary is
/// dynamically or statically linked. It inspects `/usr/bin/env` as an ELF file to find the
/// answer to these questions, or if there is a shebang line, then it chases the referenced
/// file recursively. If that does not provide the answer, then the function falls back to
/// defaults.
fn detectAbiAndDynamicLinker(
    cpu: Target.Cpu,
    os: Target.Os,
    query: Target.Query,
) DetectError!Target {
    const native_target_has_ld = comptime Target.DynamicLinker.kind(builtin.os.tag) != .none;
    const is_linux = builtin.target.os.tag == .linux;
    const is_solarish = builtin.target.os.tag.isSolarish();
    const is_darwin = builtin.target.os.tag.isDarwin();
    const have_all_info = query.dynamic_linker.get() != null and
        query.abi != null and (!is_linux or query.abi.?.isGnu());
    const os_is_non_native = query.os_tag != null;
    // The Solaris/illumos environment is always the same.
    if (!native_target_has_ld or have_all_info or os_is_non_native or is_solarish or is_darwin) {
        return defaultAbiAndDynamicLinker(cpu, os, query);
    }
    if (query.abi) |abi| {
        if (abi.isMusl()) {
            // musl implies static linking.
            return defaultAbiAndDynamicLinker(cpu, os, query);
        }
    }
    // The current target's ABI cannot be relied on for this. For example, we may build the zig
    // compiler for target riscv64-linux-musl and provide a tarball for users to download.
    // A user could then run that zig compiler on riscv64-linux-gnu. This use case is well-defined
    // and supported by Zig. But that means that we must detect the system ABI here rather than
    // relying on `builtin.target`.
    const all_abis = comptime blk: {
        assert(@intFromEnum(Target.Abi.none) == 0);
        const fields = std.meta.fields(Target.Abi)[1..];
        var array: [fields.len]Target.Abi = undefined;
        for (fields, 0..) |field, i| {
            array[i] = @field(Target.Abi, field.name);
        }
        break :blk array;
    };
    var ld_info_list_buffer: [all_abis.len]LdInfo = undefined;
    var ld_info_list_len: usize = 0;

    switch (Target.DynamicLinker.kind(os.tag)) {
        // The OS has no dynamic linker. Leave the list empty and rely on `Abi.default()` to pick
        // something sensible in `abiAndDynamicLinkerFromFile()`.
        .none => {},
        // The OS has a system-wide dynamic linker. Unfortunately, this implies that there's no
        // useful ABI information that we can glean from it merely being present. That means the
        // best we can do for this case (for now) is also `Abi.default()`.
        .arch_os => {},
        // The OS can have different dynamic linker paths depending on libc/ABI. In this case, we
        // need to gather all the valid arch/OS/ABI combinations. `abiAndDynamicLinkerFromFile()`
        // will then look for a dynamic linker with a matching path on the system and pick the ABI
        // we associated it with here.
        .arch_os_abi => for (all_abis) |abi| {
            const ld = Target.DynamicLinker.standard(cpu, os, abi);

            // Does the generated target triple actually have a standard dynamic linker path?
            if (ld.get() == null) continue;

            ld_info_list_buffer[ld_info_list_len] = .{
                .ld = ld,
                .abi = abi,
            };
            ld_info_list_len += 1;
        },
    }

    const ld_info_list = ld_info_list_buffer[0..ld_info_list_len];

    // Best case scenario: the executable is dynamically linked, and we can iterate
    // over our own shared objects and find a dynamic linker.
    const elf_file = elf_file: {
        // This block looks for a shebang line in /usr/bin/env,
        // if it finds one, then instead of using /usr/bin/env as the ELF file to examine, it uses the file it references instead,
        // doing the same logic recursively in case it finds another shebang line.

        var file_name: []const u8 = switch (os.tag) {
            // Since /usr/bin/env is hard-coded into the shebang line of many portable scripts, it's a
            // reasonably reliable path to start with.
            else => "/usr/bin/env",
            // Haiku does not have a /usr root directory.
            .haiku => "/bin/env",
        };

        // According to `man 2 execve`:
        //
        // The kernel imposes a maximum length on the text
        // that follows the "#!" characters at the start of a script;
        // characters beyond the limit are ignored.
        // Before Linux 5.1, the limit is 127 characters.
        // Since Linux 5.1, the limit is 255 characters.
        //
        // Tests show that bash and zsh consider 255 as total limit,
        // *including* "#!" characters and ignoring newline.
        // For safety, we set max length as 255 + \n (1).
        var buffer: [255 + 1]u8 = undefined;
        while (true) {
            // Interpreter path can be relative on Linux, but
            // for simplicity we are asserting it is an absolute path.
            const file = fs.openFileAbsolute(file_name, .{}) catch |err| switch (err) {
                error.NoSpaceLeft => unreachable,
                error.NameTooLong => unreachable,
                error.PathAlreadyExists => unreachable,
                error.SharingViolation => unreachable,
                error.InvalidUtf8 => unreachable, // WASI only
                error.InvalidWtf8 => unreachable, // Windows only
                error.BadPathName => unreachable,
                error.PipeBusy => unreachable,
                error.FileLocksNotSupported => unreachable,
                error.WouldBlock => unreachable,
                error.FileBusy => unreachable, // opened without write permissions
                error.AntivirusInterference => unreachable, // Windows-only error

                error.IsDir,
                error.NotDir,
                error.AccessDenied,
                error.PermissionDenied,
                error.NoDevice,
                error.FileNotFound,
                error.NetworkNotFound,
                error.FileTooBig,
                error.Unexpected,
                => |e| {
                    std.log.warn("Encountered error: {s}, falling back to default ABI and dynamic linker.", .{@errorName(e)});
                    return defaultAbiAndDynamicLinker(cpu, os, query);
                },

                else => |e| return e,
            };
            var is_elf_file = false;
            defer if (is_elf_file == false) file.close();

            // Shortest working interpreter path is "#!/i" (4)
            // (interpreter is "/i", assuming all paths are absolute, like in above comment).
            // ELF magic number length is also 4.
            //
            // If file is shorter than that, it is definitely not ELF file
            // nor file with "shebang" line.
            const min_len: usize = 4;

            const len = preadAtLeast(file, &buffer, 0, min_len) catch |err| switch (err) {
                error.UnexpectedEndOfFile,
                error.UnableToReadElfFile,
                error.ProcessNotFound,
                => return defaultAbiAndDynamicLinker(cpu, os, query),

                else => |e| return e,
            };
            const content = buffer[0..len];

            if (mem.eql(u8, content[0..4], std.elf.MAGIC)) {
                // It is very likely ELF file!
                is_elf_file = true;
                break :elf_file file;
            } else if (mem.eql(u8, content[0..2], "#!")) {
                // We detected shebang, now parse entire line.

                // Trim leading "#!", spaces and tabs.
                const trimmed_line = mem.trimLeft(u8, content[2..], &.{ ' ', '\t' });

                // This line can have:
                // * Interpreter path only,
                // * Interpreter path and arguments, all separated by space, tab or NUL character.
                // And optionally newline at the end.
                const path_maybe_args = mem.trimRight(u8, trimmed_line, "\n");

                // Separate path and args.
                const path_end = mem.indexOfAny(u8, path_maybe_args, &.{ ' ', '\t', 0 }) orelse path_maybe_args.len;

                file_name = path_maybe_args[0..path_end];
                continue;
            } else {
                // Not a ELF file, not a shell script with "shebang line", invalid duck.
                return defaultAbiAndDynamicLinker(cpu, os, query);
            }
        }
    };
    defer elf_file.close();

    // TODO: inline this function and combine the buffer we already read above to find
    // the possible shebang line with the buffer we use for the ELF header.
    return abiAndDynamicLinkerFromFile(elf_file, cpu, os, ld_info_list, query) catch |err| switch (err) {
        error.FileSystem,
        error.SystemResources,
        error.SymLinkLoop,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.ProcessNotFound,
        => |e| return e,

        error.UnableToReadElfFile,
        error.InvalidElfClass,
        error.InvalidElfVersion,
        error.InvalidElfEndian,
        error.InvalidElfFile,
        error.InvalidElfMagic,
        error.Unexpected,
        error.UnexpectedEndOfFile,
        error.NameTooLong,
        error.StaticElfFile,
        // Finally, we fall back on the standard path.
        => |e| {
            std.log.warn("Encountered error: {s}, falling back to default ABI and dynamic linker.", .{@errorName(e)});
            return defaultAbiAndDynamicLinker(cpu, os, query);
        },
    };
}

fn defaultAbiAndDynamicLinker(cpu: Target.Cpu, os: Target.Os, query: Target.Query) Target {
    const abi = query.abi orelse Target.Abi.default(cpu.arch, os.tag);
    return .{
        .cpu = cpu,
        .os = os,
        .abi = abi,
        .ofmt = query.ofmt orelse Target.ObjectFormat.default(os.tag, cpu.arch),
        .dynamic_linker = if (query.dynamic_linker.get() == null)
            Target.DynamicLinker.standard(cpu, os, abi)
        else
            query.dynamic_linker,
    };
}

const LdInfo = struct {
    ld: Target.DynamicLinker,
    abi: Target.Abi,
};

fn preadAtLeast(file: fs.File, buf: []u8, offset: u64, min_read_len: usize) !usize {
    var i: usize = 0;
    while (i < min_read_len) {
        const len = file.pread(buf[i..], offset + i) catch |err| switch (err) {
            error.OperationAborted => unreachable, // Windows-only
            error.WouldBlock => unreachable, // Did not request blocking mode
            error.Canceled => unreachable, // timerfd is unseekable
            error.NotOpenForReading => unreachable,
            error.SystemResources => return error.SystemResources,
            error.IsDir => return error.UnableToReadElfFile,
            error.BrokenPipe => return error.UnableToReadElfFile,
            error.Unseekable => return error.UnableToReadElfFile,
            error.ConnectionResetByPeer => return error.UnableToReadElfFile,
            error.ConnectionTimedOut => return error.UnableToReadElfFile,
            error.SocketNotConnected => return error.UnableToReadElfFile,
            error.Unexpected => return error.Unexpected,
            error.InputOutput => return error.FileSystem,
            error.AccessDenied => return error.Unexpected,
            error.ProcessNotFound => return error.ProcessNotFound,
            error.LockViolation => return error.UnableToReadElfFile,
        };
        if (len == 0) return error.UnexpectedEndOfFile;
        i += len;
    }
    return i;
}

fn elfInt(is_64: bool, need_bswap: bool, int_32: anytype, int_64: anytype) @TypeOf(int_64) {
    if (is_64) {
        if (need_bswap) {
            return @byteSwap(int_64);
        } else {
            return int_64;
        }
    } else {
        if (need_bswap) {
            return @byteSwap(int_32);
        } else {
            return int_32;
        }
    }
}

const builtin = @import("builtin");
const std = @import("../std.zig");
const mem = std.mem;
const elf = std.elf;
const fs = std.fs;
const assert = std.debug.assert;
const Target = std.Target;
const native_endian = builtin.cpu.arch.endian();
const posix = std.posix;

test {
    _ = NativePaths;

    _ = darwin;
    _ = linux;
    _ = windows;
}
const std = @import("std");
const Target = std.Target;

pub const CoreInfo = struct {
    architecture: u8 = 0,
    implementer: u8 = 0,
    variant: u8 = 0,
    part: u16 = 0,
};

pub const cpu_models = struct {
    // Shorthands to simplify the tables below.
    const A32 = Target.arm.cpu;
    const A64 = Target.aarch64.cpu;

    const E = struct {
        part: u16,
        variant: ?u8 = null, // null if matches any variant
        m32: ?*const Target.Cpu.Model = null,
        m64: ?*const Target.Cpu.Model = null,
    };

    // implementer = 0x41
    const ARM = [_]E{
        E{ .part = 0x926, .m32 = &A32.arm926ej_s },
        E{ .part = 0xb02, .m32 = &A32.mpcore },
        E{ .part = 0xb36, .m32 = &A32.arm1136j_s },
        E{ .part = 0xb56, .m32 = &A32.arm1156t2_s },
        E{ .part = 0xb76, .m32 = &A32.arm1176jz_s },
        E{ .part = 0xc05, .m32 = &A32.cortex_a5 },
        E{ .part = 0xc07, .m32 = &A32.cortex_a7 },
        E{ .part = 0xc08, .m32 = &A32.cortex_a8 },
        E{ .part = 0xc09, .m32 = &A32.cortex_a9 },
        E{ .part = 0xc0d, .m32 = &A32.cortex_a17 },
        E{ .part = 0xc0e, .m32 = &A32.cortex_a17 },
        E{ .part = 0xc0f, .m32 = &A32.cortex_a15 },
        E{ .part = 0xc14, .m32 = &A32.cortex_r4 },
        E{ .part = 0xc15, .m32 = &A32.cortex_r5 },
        E{ .part = 0xc17, .m32 = &A32.cortex_r7 },
        E{ .part = 0xc18, .m32 = &A32.cortex_r8 },
        E{ .part = 0xc20, .m32 = &A32.cortex_m0 },
        E{ .part = 0xc21, .m32 = &A32.cortex_m1 },
        E{ .part = 0xc23, .m32 = &A32.cortex_m3 },
        E{ .part = 0xc24, .m32 = &A32.cortex_m4 },
        E{ .part = 0xc27, .m32 = &A32.cortex_m7 },
        E{ .part = 0xc60, .m32 = &A32.cortex_m0plus },
        E{ .part = 0xd01, .m32 = &A32.cortex_a32 },
        E{ .part = 0xd02, .m64 = &A64.cortex_a34 },
        E{ .part = 0xd03, .m32 = &A32.cortex_a53, .m64 = &A64.cortex_a53 },
        E{ .part = 0xd04, .m32 = &A32.cortex_a35, .m64 = &A64.cortex_a35 },
        E{ .part = 0xd05, .m32 = &A32.cortex_a55, .m64 = &A64.cortex_a55 },
        E{ .part = 0xd06, .m64 = &A64.cortex_a65 },
        E{ .part = 0xd07, .m32 = &A32.cortex_a57, .m64 = &A64.cortex_a57 },
        E{ .part = 0xd08, .m32 = &A32.cortex_a72, .m64 = &A64.cortex_a72 },
        E{ .part = 0xd09, .m32 = &A32.cortex_a73, .m64 = &A64.cortex_a73 },
        E{ .part = 0xd0a, .m32 = &A32.cortex_a75, .m64 = &A64.cortex_a75 },
        E{ .part = 0xd0b, .m32 = &A32.cortex_a76, .m64 = &A64.cortex_a76 },
        E{ .part = 0xd0c, .m32 = &A32.neoverse_n1, .m64 = &A64.neoverse_n1 },
        E{ .part = 0xd0d, .m32 = &A32.cortex_a77, .m64 = &A64.cortex_a77 },
        E{ .part = 0xd0e, .m32 = &A32.cortex_a76ae, .m64 = &A64.cortex_a76ae },
        E{ .part = 0xd13, .m32 = &A32.cortex_r52 },
        E{ .part = 0xd14, .m64 = &A64.cortex_r82ae },
        E{ .part = 0xd15, .m64 = &A64.cortex_r82 },
        E{ .part = 0xd16, .m32 = &A32.cortex_r52plus },
        E{ .part = 0xd20, .m32 = &A32.cortex_m23 },
        E{ .part = 0xd21, .m32 = &A32.cortex_m33 },
        E{ .part = 0xd40, .m32 = &A32.neoverse_v1, .m64 = &A64.neoverse_v1 },
        E{ .part = 0xd41, .m32 = &A32.cortex_a78, .m64 = &A64.cortex_a78 },
        E{ .part = 0xd42, .m32 = &A32.cortex_a78ae, .m64 = &A64.cortex_a78ae },
        E{ .part = 0xd43, .m64 = &A64.cortex_a65ae },
        E{ .part = 0xd44, .m32 = &A32.cortex_x1, .m64 = &A64.cortex_x1 },
        E{ .part = 0xd46, .m64 = &A64.cortex_a510 },
        E{ .part = 0xd47, .m32 = &A32.cortex_a710, .m64 = &A64.cortex_a710 },
        E{ .part = 0xd48, .m64 = &A64.cortex_x2 },
        E{ .part = 0xd49, .m32 = &A32.neoverse_n2, .m64 = &A64.neoverse_n2 },
        E{ .part = 0xd4a, .m64 = &A64.neoverse_e1 },
        E{ .part = 0xd4b, .m32 = &A32.cortex_a78c, .m64 = &A64.cortex_a78c },
        E{ .part = 0xd4c, .m32 = &A32.cortex_x1c, .m64 = &A64.cortex_x1c },
        E{ .part = 0xd4d, .m64 = &A64.cortex_a715 },
        E{ .part = 0xd4e, .m64 = &A64.cortex_x3 },
        E{ .part = 0xd4f, .m64 = &A64.neoverse_v2 },
        E{ .part = 0xd80, .m64 = &A64.cortex_a520 },
        E{ .part = 0xd81, .m64 = &A64.cortex_a720 },
        E{ .part = 0xd82, .m64 = &A64.cortex_x4 },
        E{ .part = 0xd83, .m64 = &A64.neoverse_v3ae },
        E{ .part = 0xd84, .m64 = &A64.neoverse_v3 },
        E{ .part = 0xd85, .m64 = &A64.cortex_x925 },
        E{ .part = 0xd87, .m64 = &A64.cortex_a725 },
        E{ .part = 0xd88, .m64 = &A64.cortex_a520ae },
        E{ .part = 0xd89, .m64 = &A64.cortex_a720ae },
        E{ .part = 0xd8e, .m64 = &A64.neoverse_n3 },
    };
    // implementer = 0x42
    const Broadcom = [_]E{
        E{ .part = 0x516, .m64 = &A64.thunderx2t99 },
    };
    // implementer = 0x43
    const Cavium = [_]E{
        E{ .part = 0x0a0, .m64 = &A64.thunderx },
        E{ .part = 0x0a2, .m64 = &A64.thunderxt81 },
        E{ .part = 0x0a3, .m64 = &A64.thunderxt83 },
        E{ .part = 0x0a1, .m64 = &A64.thunderxt88 },
        E{ .part = 0x0af, .m64 = &A64.thunderx2t99 },
    };
    // implementer = 0x46
    const Fujitsu = [_]E{
        E{ .part = 0x001, .m64 = &A64.a64fx },
    };
    // implementer = 0x48
    const HiSilicon = [_]E{
        E{ .part = 0xd01, .m64 = &A64.tsv110 },
    };
    // implementer = 0x4e
    const Nvidia = [_]E{
        E{ .part = 0x004, .m64 = &A64.carmel },
    };
    // implementer = 0x50
    const Ampere = [_]E{
        E{ .part = 0x000, .variant = 3, .m64 = &A64.emag },
        E{ .part = 0x000, .m64 = &A64.xgene1 },
    };
    // implementer = 0x51
    const Qualcomm = [_]E{
        E{ .part = 0x001, .m64 = &A64.oryon_1 },
        E{ .part = 0x06f, .m32 = &A32.krait },
        E{ .part = 0x201, .m64 = &A64.kryo, .m32 = &A64.kryo },
        E{ .part = 0x205, .m64 = &A64.kryo, .m32 = &A64.kryo },
        E{ .part = 0x211, .m64 = &A64.kryo, .m32 = &A64.kryo },
        E{ .part = 0x800, .m64 = &A64.cortex_a73, .m32 = &A64.cortex_a73 },
        E{ .part = 0x801, .m64 = &A64.cortex_a73, .m32 = &A64.cortex_a73 },
        E{ .part = 0x802, .m64 = &A64.cortex_a75, .m32 = &A64.cortex_a75 },
        E{ .part = 0x803, .m64 = &A64.cortex_a75, .m32 = &A64.cortex_a75 },
        E{ .part = 0x804, .m64 = &A64.cortex_a76, .m32 = &A64.cortex_a76 },
        E{ .part = 0x805, .m64 = &A64.cortex_a76, .m32 = &A64.cortex_a76 },
        E{ .part = 0xc00, .m64 = &A64.falkor },
        E{ .part = 0xc01, .m64 = &A64.saphira },
    };
    // implementer = 0x61
    const Apple = [_]E{
        E{ .part = 0x022, .m64 = &A64.apple_m1 },
        E{ .part = 0x023, .m64 = &A64.apple_m1 },
        E{ .part = 0x024, .m64 = &A64.apple_m1 },
        E{ .part = 0x025, .m64 = &A64.apple_m1 },
        E{ .part = 0x028, .m64 = &A64.apple_m1 },
        E{ .part = 0x029, .m64 = &A64.apple_m1 },
        E{ .part = 0x032, .m64 = &A64.apple_m2 },
        E{ .part = 0x033, .m64 = &A64.apple_m2 },
        E{ .part = 0x034, .m64 = &A64.apple_m2 },
        E{ .part = 0x035, .m64 = &A64.apple_m2 },
        E{ .part = 0x038, .m64 = &A64.apple_m2 },
        E{ .part = 0x039, .m64 = &A64.apple_m2 },
    };

    pub fn isKnown(core: CoreInfo, is_64bit: bool) ?*const Target.Cpu.Model {
        const models = switch (core.implementer) {
            0x41 => &ARM,
            0x42 => &Broadcom,
            0x43 => &Cavium,
            0x46 => &Fujitsu,
            0x48 => &HiSilicon,
            0x4e => &Nvidia,
            0x50 => &Ampere,
            0x51 => &Qualcomm,
            0x61 => &Apple,
            else => return null,
        };

        for (models) |model| {
            if (model.part == core.part and
                (model.variant == null or model.variant.? == core.variant))
                return if (is_64bit) model.m64 else model.m32;
        }

        return null;
    }
};

pub const aarch64 = struct {
    fn setFeature(cpu: *Target.Cpu, feature: Target.aarch64.Feature, enabled: bool) void {
        const idx = @as(Target.Cpu.Feature.Set.Index, @intFromEnum(feature));

        if (enabled) cpu.features.addFeature(idx) else cpu.features.removeFeature(idx);
    }

    inline fn bitField(input: u64, offset: u6) u4 {
        return @as(u4, @truncate(input >> offset));
    }

    /// Input array should consist of readouts from 12 system registers such that:
    /// 0  -> MIDR_EL1
    /// 1  -> ID_AA64PFR0_EL1
    /// 2  -> ID_AA64PFR1_EL1
    /// 3  -> ID_AA64DFR0_EL1
    /// 4  -> ID_AA64DFR1_EL1
    /// 5  -> ID_AA64AFR0_EL1
    /// 6  -> ID_AA64AFR1_EL1
    /// 7  -> ID_AA64ISAR0_EL1
    /// 8  -> ID_AA64ISAR1_EL1
    /// 9  -> ID_AA64MMFR0_EL1
    /// 10 -> ID_AA64MMFR1_EL1
    /// 11 -> ID_AA64MMFR2_EL1
    pub fn detectNativeCpuAndFeatures(arch: Target.Cpu.Arch, registers: [12]u64) ?Target.Cpu {
        const info = detectNativeCoreInfo(registers[0]);
        const model = cpu_models.isKnown(info, true) orelse return null;

        var cpu = Target.Cpu{
            .arch = arch,
            .model = model,
            .features = Target.Cpu.Feature.Set.empty,
        };

        detectNativeCpuFeatures(&cpu, registers[1..12]);
        addInstructionFusions(&cpu, info);

        return cpu;
    }

    /// Takes readout of MIDR_EL1 register as input.
    fn detectNativeCoreInfo(midr: u64) CoreInfo {
        var info = CoreInfo{
            .implementer = @as(u8, @truncate(midr >> 24)),
            .part = @as(u12, @truncate(midr >> 4)),
        };

        blk: {
            if (info.implementer == 0x41) {
                // ARM Ltd.
                const special_bits: u4 = @truncate(info.part >> 8);
                if (special_bits == 0x0 or special_bits == 0x7) {
                    // TODO Variant and arch encoded differently.
                    break :blk;
                }
            }

            info.variant |= @as(u8, @intCast(@as(u4, @truncate(midr >> 20)))) << 4;
            info.variant |= @as(u4, @truncate(midr));
            info.architecture = @as(u4, @truncate(midr >> 16));
        }

        return info;
    }

    /// Input array should consist of readouts from 11 system registers such that:
    /// 0  -> ID_AA64PFR0_EL1
    /// 1  -> ID_AA64PFR1_EL1
    /// 2  -> ID_AA64DFR0_EL1
    /// 3  -> ID_AA64DFR1_EL1
    /// 4  -> ID_AA64AFR0_EL1
    /// 5  -> ID_AA64AFR1_EL1
    /// 6  -> ID_AA64ISAR0_EL1
    /// 7  -> ID_AA64ISAR1_EL1
    /// 8  -> ID_AA64MMFR0_EL1
    /// 9  -> ID_AA64MMFR1_EL1
    /// 10 -> ID_AA64MMFR2_EL1
    fn detectNativeCpuFeatures(cpu: *Target.Cpu, registers: *const [11]u64) void {
        // ID_AA64PFR0_EL1
        setFeature(cpu, .dit, bitField(registers[0], 48) >= 1);
        setFeature(cpu, .am, bitField(registers[0], 44) >= 1);
        setFeature(cpu, .amvs, bitField(registers[0], 44) >= 2);
        setFeature(cpu, .mpam, bitField(registers[0], 40) >= 1); // MPAM v1.0
        setFeature(cpu, .sel2, bitField(registers[0], 36) >= 1);
        setFeature(cpu, .sve, bitField(registers[0], 32) >= 1);
        setFeature(cpu, .el3, bitField(registers[0], 12) >= 1);
        setFeature(cpu, .ras, bitField(registers[0], 28) >= 1);

        if (bitField(registers[0], 20) < 0xF) blk: {
            if (bitField(registers[0], 16) != bitField(registers[0], 20)) break :blk; // This should never occur

            setFeature(cpu, .neon, true);
            setFeature(cpu, .fp_armv8, true);
            setFeature(cpu, .fullfp16, bitField(registers[0], 20) > 0);
        }

        // ID_AA64PFR1_EL1
        setFeature(cpu, .mpam, bitField(registers[1], 16) > 0 and bitField(registers[0], 40) == 0); // MPAM v0.1
        setFeature(cpu, .mte, bitField(registers[1], 8) >= 1);
        setFeature(cpu, .ssbs, bitField(registers[1], 4) >= 1);
        setFeature(cpu, .bti, bitField(registers[1], 0) >= 1);

        // ID_AA64DFR0_EL1
        setFeature(cpu, .tracev8_4, bitField(registers[2], 40) >= 1);
        setFeature(cpu, .spe, bitField(registers[2], 32) >= 1);
        setFeature(cpu, .perfmon, bitField(registers[2], 8) >= 1 and bitField(registers[2], 8) < 0xF);

        // ID_AA64DFR1_EL1 reserved
        // ID_AA64AFR0_EL1 reserved / implementation defined
        // ID_AA64AFR1_EL1 reserved

        // ID_AA64ISAR0_EL1
        setFeature(cpu, .rand, bitField(registers[6], 60) >= 1);
        setFeature(cpu, .tlb_rmi, bitField(registers[6], 56) >= 1);
        setFeature(cpu, .flagm, bitField(registers[6], 52) >= 1);
        setFeature(cpu, .fp16fml, bitField(registers[6], 48) >= 1);
        setFeature(cpu, .dotprod, bitField(registers[6], 44) >= 1);
        setFeature(cpu, .sm4, bitField(registers[6], 40) >= 1 and bitField(registers[6], 36) >= 1);
        setFeature(cpu, .sha3, bitField(registers[6], 32) >= 1 and bitField(registers[6], 12) >= 2);
        setFeature(cpu, .rdm, bitField(registers[6], 28) >= 1);
        setFeature(cpu, .lse, bitField(registers[6], 20) >= 1);
        setFeature(cpu, .crc, bitField(registers[6], 16) >= 1);
        setFeature(cpu, .sha2, bitField(registers[6], 12) >= 1 and bitField(registers[6], 8) >= 1);
        setFeature(cpu, .aes, bitField(registers[6], 4) >= 1);

        // ID_AA64ISAR1_EL1
        setFeature(cpu, .i8mm, bitField(registers[7], 52) >= 1);
        setFeature(cpu, .bf16, bitField(registers[7], 44) >= 1);
        setFeature(cpu, .predres, bitField(registers[7], 40) >= 1);
        setFeature(cpu, .sb, bitField(registers[7], 36) >= 1);
        setFeature(cpu, .fptoint, bitField(registers[7], 32) >= 1);
        setFeature(cpu, .rcpc, bitField(registers[7], 20) >= 1);
        setFeature(cpu, .rcpc_immo, bitField(registers[7], 20) >= 2);
        setFeature(cpu, .complxnum, bitField(registers[7], 16) >= 1);
        setFeature(cpu, .jsconv, bitField(registers[7], 12) >= 1);
        setFeature(cpu, .pauth, bitField(registers[7], 8) >= 1 or bitField(registers[7], 4) >= 1);
        setFeature(cpu, .ccpp, bitField(registers[7], 0) >= 1);
        setFeature(cpu, .ccdp, bitField(registers[7], 0) >= 2);

        // ID_AA64MMFR0_EL1
        setFeature(cpu, .ecv, bitField(registers[8], 60) >= 1);
        setFeature(cpu, .fgt, bitField(registers[8], 56) >= 1);

        // ID_AA64MMFR1_EL1
        setFeature(cpu, .pan, bitField(registers[9], 20) >= 1);
        setFeature(cpu, .pan_rwv, bitField(registers[9], 20) >= 2);
        setFeature(cpu, .lor, bitField(registers[9], 16) >= 1);
        setFeature(cpu, .vh, bitField(registers[9], 8) >= 1);
        setFeature(cpu, .contextidr_el2, bitField(registers[9], 8) >= 1);

        // ID_AA64MMFR2_EL1
        setFeature(cpu, .nv, bitField(registers[10], 24) >= 1);
        setFeature(cpu, .ccidx, bitField(registers[10], 20) >= 1);
        setFeature(cpu, .uaops, bitField(registers[10], 4) >= 1);
    }

    fn addInstructionFusions(cpu: *Target.Cpu, info: CoreInfo) void {
        switch (info.implementer) {
            0x41 => switch (info.part) {
                0xd4b, 0xd4c => {
                    // According to A78C/X1C Core Software Optimization Guide, CPU fuses certain instructions.
                    setFeature(cpu, .cmp_bcc_fusion, true);
                    setFeature(cpu, .fuse_aes, true);
                },
                else => {},
            },
            else => {},
        }
    }
};
const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Target = std.Target;
const Version = std.SemanticVersion;

pub const macos = @import("darwin/macos.zig");

/// Check if SDK is installed on Darwin without triggering CLT installation popup window.
/// Note: simply invoking `xcrun` will inevitably trigger the CLT installation popup.
/// Therefore, we resort to invoking `xcode-select --print-path` and checking
/// if the status is nonzero.
/// stderr from xcode-select is ignored.
/// If error.OutOfMemory occurs in Allocator, this function returns null.
pub fn isSdkInstalled(allocator: Allocator) bool {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "xcode-select", "--print-path" },
    }) catch return false;

    defer {
        allocator.free(result.stderr);
        allocator.free(result.stdout);
    }

    return switch (result.term) {
        .Exited => |code| if (code == 0) result.stdout.len > 0 else false,
        else => false,
    };
}

/// Detect SDK on Darwin.
/// Calls `xcrun --sdk <target_sdk> --show-sdk-path` which fetches the path to the SDK.
/// Caller owns the memory.
/// stderr from xcrun is ignored.
/// If error.OutOfMemory occurs in Allocator, this function returns null.
pub fn getSdk(allocator: Allocator, target: Target) ?[]const u8 {
    const is_simulator_abi = target.abi == .simulator;
    const sdk = switch (target.os.tag) {
        .ios => switch (target.abi) {
            .macabi => "macosx",
            .simulator => "iphonesimulator",
            else => "iphoneos",
        },
        .driverkit => "driverkit",
        .macos => "macosx",
        .tvos => if (is_simulator_abi) "appletvsimulator" else "appletvos",
        .visionos => if (is_simulator_abi) "xrsimulator" else "xros",
        .watchos => if (is_simulator_abi) "watchsimulator" else "watchos",
        else => return null,
    };
    const argv = &[_][]const u8{ "xcrun", "--sdk", sdk, "--show-sdk-path" };
    const result = std.process.Child.run(.{ .allocator = allocator, .argv = argv }) catch return null;
    defer {
        allocator.free(result.stderr);
        allocator.free(result.stdout);
    }
    switch (result.term) {
        .Exited => |code| if (code != 0) return null,
        else => return null,
    }
    return allocator.dupe(u8, mem.trimRight(u8, result.stdout, "\r\n")) catch null;
}

test {
    _ = macos;
}
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const mem = std.mem;
const testing = std.testing;

const Target = std.Target;

/// Detect macOS version.
/// `target_os` is not modified in case of error.
pub fn detect(target_os: *Target.Os) !void {
    // Drop use of osproductversion sysctl because:
    //   1. only available 10.13.4 High Sierra and later
    //   2. when used from a binary built against < SDK 11.0 it returns 10.16 and masks Big Sur 11.x version
    //
    // NEW APPROACH, STEP 1, parse file:
    //
    //   /System/Library/CoreServices/SystemVersion.plist
    //
    // NOTE: Historically `SystemVersion.plist` first appeared circa '2003
    // with the release of Mac OS X 10.3.0 Panther.
    //
    // and if it contains a `10.16` value where the `16` is `>= 16` then it is non-canonical,
    // discarded, and we move on to next step. Otherwise we accept the version.
    //
    // BACKGROUND: `10.(16+)` is not a proper version and does not have enough fidelity to
    // indicate minor/point version of Big Sur and later. It is a context-sensitive result
    // issued by the kernel for backwards compatibility purposes. Likely the kernel checks
    // if the executable was linked against an SDK older than Big Sur.
    //
    // STEP 2, parse next file:
    //
    //   /System/Library/CoreServices/.SystemVersionPlatform.plist
    //
    // NOTE: Historically `SystemVersionPlatform.plist` first appeared circa '2020
    // with the release of macOS 11.0 Big Sur.
    //
    // Accessing the content via this path circumvents a context-sensitive result and
    // yields a canonical Big Sur version.
    //
    // At this time there is no other known way for a < SDK 11.0 executable to obtain a
    // canonical Big Sur version.
    //
    // This implementation uses a reasonably simplified approach to parse .plist file
    // that while it is an xml document, we have good history on the file and its format
    // such that I am comfortable with implementing a minimalistic parser.
    // Things like string and general escapes are not supported.
    const prefixSlash = "/System/Library/CoreServices/";
    const paths = [_][]const u8{
        prefixSlash ++ "SystemVersion.plist",
        prefixSlash ++ ".SystemVersionPlatform.plist",
    };
    for (paths) |path| {
        // approx. 4 times historical file size
        var buf: [2048]u8 = undefined;

        if (std.fs.cwd().readFile(path, &buf)) |bytes| {
            if (parseSystemVersion(bytes)) |ver| {
                // never return non-canonical `10.(16+)`
                if (!(ver.major == 10 and ver.minor >= 16)) {
                    target_os.version_range.semver.min = ver;
                    target_os.version_range.semver.max = ver;
                    return;
                }
                continue;
            } else |_| {
                return error.OSVersionDetectionFail;
            }
        } else |_| {
            return error.OSVersionDetectionFail;
        }
    }
    return error.OSVersionDetectionFail;
}

fn parseSystemVersion(buf: []const u8) !std.SemanticVersion {
    var svt = SystemVersionTokenizer{ .bytes = buf };
    try svt.skipUntilTag(.start, "dict");
    while (true) {
        try svt.skipUntilTag(.start, "key");
        const content = try svt.expectContent();
        try svt.skipUntilTag(.end, "key");
        if (mem.eql(u8, content, "ProductVersion")) break;
    }
    try svt.skipUntilTag(.start, "string");
    const ver = try svt.expectContent();
    try svt.skipUntilTag(.end, "string");

    return try std.Target.Query.parseVersion(ver);
}

const SystemVersionTokenizer = struct {
    bytes: []const u8,
    index: usize = 0,
    state: State = .begin,

    fn next(self: *@This()) !?Token {
        var mark: usize = self.index;
        var tag = Tag{};
        var content: []const u8 = "";

        while (self.index < self.bytes.len) {
            const char = self.bytes[self.index];
            switch (self.state) {
                .begin => switch (char) {
                    '<' => {
                        self.state = .tag0;
                        self.index += 1;
                        tag = Tag{};
                        mark = self.index;
                    },
                    '>' => {
                        return error.BadToken;
                    },
                    else => {
                        self.state = .content;
                        content = "";
                        mark = self.index;
                    },
                },
                .tag0 => switch (char) {
                    '<' => {
                        return error.BadToken;
                    },
                    '>' => {
                        self.state = .begin;
                        self.index += 1;
                        tag.name = self.bytes[mark..self.index];
                        return Token{ .tag = tag };
                    },
                    '"' => {
                        self.state = .tag_string;
                        self.index += 1;
                    },
                    '/' => {
                        self.state = .tag0_end_or_empty;
                        self.index += 1;
                    },
                    'A'...'Z', 'a'...'z' => {
                        self.state = .tagN;
                        tag.kind = .start;
                        self.index += 1;
                    },
                    else => {
                        self.state = .tagN;
                        self.index += 1;
                    },
                },
                .tag0_end_or_empty => switch (char) {
                    '<' => {
                        return error.BadToken;
                    },
                    '>' => {
                        self.state = .begin;
                        tag.kind = .empty;
                        tag.name = self.bytes[self.index..self.index];
                        self.index += 1;
                        return Token{ .tag = tag };
                    },
                    else => {
                        self.state = .tagN;
                        tag.kind = .end;
                        mark = self.index;
                        self.index += 1;
                    },
                },
                .tagN => switch (char) {
                    '<' => {
                        return error.BadToken;
                    },
                    '>' => {
                        self.state = .begin;
                        tag.name = self.bytes[mark..self.index];
                        self.index += 1;
                        return Token{ .tag = tag };
                    },
                    '"' => {
                        self.state = .tag_string;
                        self.index += 1;
                    },
                    '/' => {
                        self.state = .tagN_end;
                        tag.kind = .end;
                        self.index += 1;
                    },
                    else => {
                        self.index += 1;
                    },
                },
                .tagN_end => switch (char) {
                    '>' => {
                        self.state = .begin;
                        tag.name = self.bytes[mark..self.index];
                        self.index += 1;
                        return Token{ .tag = tag };
                    },
                    else => {
                        return error.BadToken;
                    },
                },
                .tag_string => switch (char) {
                    '"' => {
                        self.state = .tagN;
                        self.index += 1;
                    },
                    else => {
                        self.index += 1;
                    },
                },
                .content => switch (char) {
                    '<' => {
                        self.state = .tag0;
                        content = self.bytes[mark..self.index];
                        self.index += 1;
                        tag = Tag{};
                        mark = self.index;
                        return Token{ .content = content };
                    },
                    '>' => {
                        return error.BadToken;
                    },
                    else => {
                        self.index += 1;
                    },
                },
            }
        }

        return null;
    }

    fn expectContent(self: *@This()) ![]const u8 {
        if (try self.next()) |tok| {
            switch (tok) {
                .content => |content| {
                    return content;
                },
                else => {},
            }
        }
        return error.UnexpectedToken;
    }

    fn skipUntilTag(self: *@This(), kind: Tag.Kind, name: []const u8) !void {
        while (try self.next()) |tok| {
            switch (tok) {
                .tag => |tag| {
                    if (tag.kind == kind and mem.eql(u8, tag.name, name)) return;
                },
                else => {},
            }
        }
        return error.TagNotFound;
    }

    const State = enum {
        begin,
        tag0,
        tag0_end_or_empty,
        tagN,
        tagN_end,
        tag_string,
        content,
    };

    const Token = union(enum) {
        tag: Tag,
        content: []const u8,
    };

    const Tag = struct {
        kind: Kind = .unknown,
        name: []const u8 = "",

        const Kind = enum { unknown, start, end, empty };
    };
};

test "detect" {
    const cases: [5]struct { []const u8, std.SemanticVersion } = .{
        .{
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            \\<plist version="1.0">
            \\<dict>
            \\    <key>ProductBuildVersion</key>
            \\    <string>7B85</string>
            \\    <key>ProductCopyright</key>
            \\    <string>Apple Computer, Inc. 1983-2003</string>
            \\    <key>ProductName</key>
            \\    <string>Mac OS X</string>
            \\    <key>ProductUserVisibleVersion</key>
            \\    <string>10.3</string>
            \\    <key>ProductVersion</key>
            \\    <string>10.3</string>
            \\</dict>
            \\</plist>
            ,
            .{ .major = 10, .minor = 3, .patch = 0 },
        },
        .{
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            \\<plist version="1.0">
            \\<dict>
            \\ <key>ProductBuildVersion</key>
            \\ <string>7W98</string>
            \\ <key>ProductCopyright</key>
            \\ <string>Apple Computer, Inc. 1983-2004</string>
            \\ <key>ProductName</key>
            \\ <string>Mac OS X</string>
            \\ <key>ProductUserVisibleVersion</key>
            \\ <string>10.3.9</string>
            \\ <key>ProductVersion</key>
            \\ <string>10.3.9</string>
            \\</dict>
            \\</plist>
            ,
            .{ .major = 10, .minor = 3, .patch = 9 },
        },
        .{
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            \\<plist version="1.0">
            \\<dict>
            \\ <key>ProductBuildVersion</key>
            \\ <string>19G68</string>
            \\ <key>ProductCopyright</key>
            \\ <string>1983-2020 Apple Inc.</string>
            \\ <key>ProductName</key>
            \\ <string>Mac OS X</string>
            \\ <key>ProductUserVisibleVersion</key>
            \\ <string>10.15.6</string>
            \\ <key>ProductVersion</key>
            \\ <string>10.15.6</string>
            \\ <key>iOSSupportVersion</key>
            \\ <string>13.6</string>
            \\</dict>
            \\</plist>
            ,
            .{ .major = 10, .minor = 15, .patch = 6 },
        },
        .{
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            \\<plist version="1.0">
            \\<dict>
            \\ <key>ProductBuildVersion</key>
            \\ <string>20A2408</string>
            \\ <key>ProductCopyright</key>
            \\ <string>1983-2020 Apple Inc.</string>
            \\ <key>ProductName</key>
            \\ <string>macOS</string>
            \\ <key>ProductUserVisibleVersion</key>
            \\ <string>11.0</string>
            \\ <key>ProductVersion</key>
            \\ <string>11.0</string>
            \\ <key>iOSSupportVersion</key>
            \\ <string>14.2</string>
            \\</dict>
            \\</plist>
            ,
            .{ .major = 11, .minor = 0, .patch = 0 },
        },
        .{
            \\<?xml version="1.0" encoding="UTF-8"?>
            \\<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            \\<plist version="1.0">
            \\<dict>
            \\ <key>ProductBuildVersion</key>
            \\ <string>20C63</string>
            \\ <key>ProductCopyright</key>
            \\ <string>1983-2020 Apple Inc.</string>
            \\ <key>ProductName</key>
            \\ <string>macOS</string>
            \\ <key>ProductUserVisibleVersion</key>
            \\ <string>11.1</string>
            \\ <key>ProductVersion</key>
            \\ <string>11.1</string>
            \\ <key>iOSSupportVersion</key>
            \\ <string>14.3</string>
            \\</dict>
            \\</plist>
            ,
            .{ .major = 11, .minor = 1, .patch = 0 },
        },
    };

    inline for (cases) |case| {
        const ver0 = try parseSystemVersion(case[0]);
        const ver1 = case[1];
        try testing.expectEqual(std.math.Order.eq, ver0.order(ver1));
    }
}

pub fn detectNativeCpuAndFeatures() ?Target.Cpu {
    var cpu_family: std.c.CPUFAMILY = undefined;
    var len: usize = @sizeOf(std.c.CPUFAMILY);
    std.posix.sysctlbynameZ("hw.cpufamily", &cpu_family, &len, null, 0) catch |err| switch (err) {
        error.NameTooLong => unreachable, // constant, known good value
        error.PermissionDenied => unreachable, // only when setting values,
        error.SystemResources => unreachable, // memory already on the stack
        error.UnknownName => unreachable, // constant, known good value
        error.Unexpected => unreachable, // EFAULT: stack should be safe, EISDIR/ENOTDIR: constant, known good value
    };

    const current_arch = builtin.cpu.arch;
    switch (current_arch) {
        .aarch64, .aarch64_be => {
            const model = switch (cpu_family) {
                .ARM_CYCLONE => &Target.aarch64.cpu.apple_a7,
                .ARM_TYPHOON => &Target.aarch64.cpu.apple_a8,
                .ARM_TWISTER => &Target.aarch64.cpu.apple_a9,
                .ARM_HURRICANE => &Target.aarch64.cpu.apple_a10,
                .ARM_MONSOON_MISTRAL => &Target.aarch64.cpu.apple_a11,
                .ARM_VORTEX_TEMPEST => &Target.aarch64.cpu.apple_a12,
                .ARM_LIGHTNING_THUNDER => &Target.aarch64.cpu.apple_a13,
                .ARM_FIRESTORM_ICESTORM => &Target.aarch64.cpu.apple_m1, // a14
                .ARM_BLIZZARD_AVALANCHE => &Target.aarch64.cpu.apple_m2, // a15
                .ARM_EVEREST_SAWTOOTH => &Target.aarch64.cpu.apple_m3, // a16
                .ARM_IBIZA => &Target.aarch64.cpu.apple_m3, // base
                .ARM_PALMA => &Target.aarch64.cpu.apple_m3, // max
                .ARM_LOBOS => &Target.aarch64.cpu.apple_m3, // pro
                .ARM_COLL => &Target.aarch64.cpu.apple_a17, // a17 pro
                .ARM_DONAN => &Target.aarch64.cpu.apple_m4, // base
                .ARM_BRAVA => &Target.aarch64.cpu.apple_m4, // pro/max
                .ARM_TAHITI => &Target.aarch64.cpu.apple_m4, // a18 pro
                .ARM_TUPAI => &Target.aarch64.cpu.apple_m4, // a18
                else => return null,
            };

            return Target.Cpu{
                .arch = current_arch,
                .model = model,
                .features = model.features,
            };
        },
        else => {},
    }

    return null;
}
const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const io = std.io;
const fs = std.fs;
const fmt = std.fmt;
const testing = std.testing;
const Target = std.Target;
const assert = std.debug.assert;

const SparcCpuinfoImpl = struct {
    model: ?*const Target.Cpu.Model = null,
    is_64bit: bool = false,

    const cpu_names = .{
        .{ "SuperSparc", &Target.sparc.cpu.supersparc },
        .{ "HyperSparc", &Target.sparc.cpu.hypersparc },
        .{ "SpitFire", &Target.sparc.cpu.ultrasparc },
        .{ "BlackBird", &Target.sparc.cpu.ultrasparc },
        .{ "Sabre", &Target.sparc.cpu.ultrasparc },
        .{ "Hummingbird", &Target.sparc.cpu.ultrasparc },
        .{ "Cheetah", &Target.sparc.cpu.ultrasparc3 },
        .{ "Jalapeno", &Target.sparc.cpu.ultrasparc3 },
        .{ "Jaguar", &Target.sparc.cpu.ultrasparc3 },
        .{ "Panther", &Target.sparc.cpu.ultrasparc3 },
        .{ "Serrano", &Target.sparc.cpu.ultrasparc3 },
        .{ "UltraSparc T1", &Target.sparc.cpu.niagara },
        .{ "UltraSparc T2", &Target.sparc.cpu.niagara2 },
        .{ "UltraSparc T3", &Target.sparc.cpu.niagara3 },
        .{ "UltraSparc T4", &Target.sparc.cpu.niagara4 },
        .{ "UltraSparc T5", &Target.sparc.cpu.niagara4 },
        .{ "LEON", &Target.sparc.cpu.leon3 },
    };

    fn line_hook(self: *SparcCpuinfoImpl, key: []const u8, value: []const u8) !bool {
        if (mem.eql(u8, key, "cpu")) {
            inline for (cpu_names) |pair| {
                if (mem.indexOfPos(u8, value, 0, pair[0]) != null) {
                    self.model = pair[1];
                    break;
                }
            }
        } else if (mem.eql(u8, key, "type")) {
            self.is_64bit = mem.eql(u8, value, "sun4u") or mem.eql(u8, value, "sun4v");
        }

        return true;
    }

    fn finalize(self: *const SparcCpuinfoImpl, arch: Target.Cpu.Arch) ?Target.Cpu {
        // At the moment we only support 64bit SPARC systems.
        assert(self.is_64bit);

        const model = self.model orelse return null;
        return Target.Cpu{
            .arch = arch,
            .model = model,
            .features = model.features,
        };
    }
};

const SparcCpuinfoParser = CpuinfoParser(SparcCpuinfoImpl);

test "cpuinfo: SPARC" {
    try testParser(SparcCpuinfoParser, .sparc64, &Target.sparc.cpu.niagara2,
        \\cpu             : UltraSparc T2 (Niagara2)
        \\fpu             : UltraSparc T2 integrated FPU
        \\pmu             : niagara2
        \\type            : sun4v
    );
}

const RiscvCpuinfoImpl = struct {
    model: ?*const Target.Cpu.Model = null,

    const cpu_names = .{
        .{ "sifive,u54", &Target.riscv.cpu.sifive_u54 },
        .{ "sifive,u7", &Target.riscv.cpu.sifive_7_series },
        .{ "sifive,u74", &Target.riscv.cpu.sifive_u74 },
        .{ "sifive,u74-mc", &Target.riscv.cpu.sifive_u74 },
    };

    fn line_hook(self: *RiscvCpuinfoImpl, key: []const u8, value: []const u8) !bool {
        if (mem.eql(u8, key, "uarch")) {
            inline for (cpu_names) |pair| {
                if (mem.eql(u8, value, pair[0])) {
                    self.model = pair[1];
                    break;
                }
            }
            return false;
        }

        return true;
    }

    fn finalize(self: *const RiscvCpuinfoImpl, arch: Target.Cpu.Arch) ?Target.Cpu {
        const model = self.model orelse return null;
        return Target.Cpu{
            .arch = arch,
            .model = model,
            .features = model.features,
        };
    }
};

const RiscvCpuinfoParser = CpuinfoParser(RiscvCpuinfoImpl);

test "cpuinfo: RISC-V" {
    try testParser(RiscvCpuinfoParser, .riscv64, &Target.riscv.cpu.sifive_u74,
        \\processor : 0
        \\hart      : 1
        \\isa       : rv64imafdc
        \\mmu       : sv39
        \\isa-ext   :
        \\uarch     : sifive,u74-mc
    );
}

const PowerpcCpuinfoImpl = struct {
    model: ?*const Target.Cpu.Model = null,

    const cpu_names = .{
        .{ "604e", &Target.powerpc.cpu.@"604e" },
        .{ "604", &Target.powerpc.cpu.@"604" },
        .{ "7400", &Target.powerpc.cpu.@"7400" },
        .{ "7410", &Target.powerpc.cpu.@"7400" },
        .{ "7447", &Target.powerpc.cpu.@"7400" },
        .{ "7455", &Target.powerpc.cpu.@"7450" },
        .{ "G4", &Target.powerpc.cpu.g4 },
        .{ "POWER4", &Target.powerpc.cpu.@"970" },
        .{ "PPC970FX", &Target.powerpc.cpu.@"970" },
        .{ "PPC970MP", &Target.powerpc.cpu.@"970" },
        .{ "G5", &Target.powerpc.cpu.g5 },
        .{ "POWER5", &Target.powerpc.cpu.g5 },
        .{ "A2", &Target.powerpc.cpu.a2 },
        .{ "POWER6", &Target.powerpc.cpu.pwr6 },
        .{ "POWER7", &Target.powerpc.cpu.pwr7 },
        .{ "POWER8", &Target.powerpc.cpu.pwr8 },
        .{ "POWER8E", &Target.powerpc.cpu.pwr8 },
        .{ "POWER8NVL", &Target.powerpc.cpu.pwr8 },
        .{ "POWER9", &Target.powerpc.cpu.pwr9 },
        .{ "POWER10", &Target.powerpc.cpu.pwr10 },
    };

    fn line_hook(self: *PowerpcCpuinfoImpl, key: []const u8, value: []const u8) !bool {
        if (mem.eql(u8, key, "cpu")) {
            // The model name is often followed by a comma or space and extra
            // info.
            inline for (cpu_names) |pair| {
                const end_index = mem.indexOfAny(u8, value, ", ") orelse value.len;
                if (mem.eql(u8, value[0..end_index], pair[0])) {
                    self.model = pair[1];
                    break;
                }
            }

            // Stop the detection once we've seen the first core.
            return false;
        }

        return true;
    }

    fn finalize(self: *const PowerpcCpuinfoImpl, arch: Target.Cpu.Arch) ?Target.Cpu {
        const model = self.model orelse return null;
        return Target.Cpu{
            .arch = arch,
            .model = model,
            .features = model.features,
        };
    }
};

const PowerpcCpuinfoParser = CpuinfoParser(PowerpcCpuinfoImpl);

test "cpuinfo: PowerPC" {
    try testParser(PowerpcCpuinfoParser, .powerpc, &Target.powerpc.cpu.@"970",
        \\processor : 0
        \\cpu       : PPC970MP, altivec supported
        \\clock     : 1250.000000MHz
        \\revision  : 1.1 (pvr 0044 0101)
    );
    try testParser(PowerpcCpuinfoParser, .powerpc64le, &Target.powerpc.cpu.pwr8,
        \\processor : 0
        \\cpu       : POWER8 (raw), altivec supported
        \\clock     : 2926.000000MHz
        \\revision  : 2.0 (pvr 004d 0200)
    );
}

const ArmCpuinfoImpl = struct {
    const num_cores = 4;

    cores: [num_cores]CoreInfo = undefined,
    core_no: usize = 0,
    have_fields: usize = 0,

    const CoreInfo = struct {
        architecture: u8 = 0,
        implementer: u8 = 0,
        variant: u8 = 0,
        part: u16 = 0,
        is_really_v6: bool = false,
    };

    const cpu_models = @import("arm.zig").cpu_models;

    fn addOne(self: *ArmCpuinfoImpl) void {
        if (self.have_fields == 4 and self.core_no < num_cores) {
            if (self.core_no > 0) {
                // Deduplicate the core info.
                for (self.cores[0..self.core_no]) |it| {
                    if (std.meta.eql(it, self.cores[self.core_no]))
                        return;
                }
            }
            self.core_no += 1;
        }
    }

    fn line_hook(self: *ArmCpuinfoImpl, key: []const u8, value: []const u8) !bool {
        const info = &self.cores[self.core_no];

        if (mem.eql(u8, key, "processor")) {
            // Handle both old-style and new-style cpuinfo formats.
            // The former prints a sequence of "processor: N" lines for each
            // core and then the info for the core that's executing this code(!)
            // while the latter prints the infos for each core right after the
            // "processor" key.
            self.have_fields = 0;
            self.cores[self.core_no] = .{};
        } else if (mem.eql(u8, key, "CPU implementer")) {
            info.implementer = try fmt.parseInt(u8, value, 0);
            self.have_fields += 1;
        } else if (mem.eql(u8, key, "CPU architecture")) {
            // "AArch64" on older kernels.
            info.architecture = if (mem.startsWith(u8, value, "AArch64"))
                8
            else
                try fmt.parseInt(u8, value, 0);
            self.have_fields += 1;
        } else if (mem.eql(u8, key, "CPU variant")) {
            info.variant = try fmt.parseInt(u8, value, 0);
            self.have_fields += 1;
        } else if (mem.eql(u8, key, "CPU part")) {
            info.part = try fmt.parseInt(u16, value, 0);
            self.have_fields += 1;
        } else if (mem.eql(u8, key, "model name")) {
            // ARMv6 cores report "CPU architecture" equal to 7.
            if (mem.indexOf(u8, value, "(v6l)")) |_| {
                info.is_really_v6 = true;
            }
        } else if (mem.eql(u8, key, "CPU revision")) {
            // This field is always the last one for each CPU section.
            _ = self.addOne();
        }

        return true;
    }

    fn finalize(self: *ArmCpuinfoImpl, arch: Target.Cpu.Arch) ?Target.Cpu {
        if (self.core_no == 0) return null;

        const is_64bit = switch (arch) {
            .aarch64, .aarch64_be => true,
            else => false,
        };

        var known_models: [num_cores]?*const Target.Cpu.Model = undefined;
        for (self.cores[0..self.core_no], 0..) |core, i| {
            known_models[i] = cpu_models.isKnown(.{
                .architecture = core.architecture,
                .implementer = core.implementer,
                .variant = core.variant,
                .part = core.part,
            }, is_64bit);
        }

        // XXX We pick the first core on big.LITTLE systems, hopefully the
        // LITTLE one.
        const model = known_models[0] orelse return null;
        return Target.Cpu{
            .arch = arch,
            .model = model,
            .features = model.features,
        };
    }
};

const ArmCpuinfoParser = CpuinfoParser(ArmCpuinfoImpl);

test "cpuinfo: ARM" {
    try testParser(ArmCpuinfoParser, .arm, &Target.arm.cpu.arm1176jz_s,
        \\processor       : 0
        \\model name      : ARMv6-compatible processor rev 7 (v6l)
        \\BogoMIPS        : 997.08
        \\Features        : half thumb fastmult vfp edsp java tls
        \\CPU implementer : 0x41
        \\CPU architecture: 7
        \\CPU variant     : 0x0
        \\CPU part        : 0xb76
        \\CPU revision    : 7
    );
    try testParser(ArmCpuinfoParser, .arm, &Target.arm.cpu.cortex_a7,
        \\processor : 0
        \\model name : ARMv7 Processor rev 3 (v7l)
        \\BogoMIPS : 18.00
        \\Features : half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae
        \\CPU implementer : 0x41
        \\CPU architecture: 7
        \\CPU variant : 0x0
        \\CPU part : 0xc07
        \\CPU revision : 3
        \\
        \\processor : 4
        \\model name : ARMv7 Processor rev 3 (v7l)
        \\BogoMIPS : 90.00
        \\Features : half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 idiva idivt vfpd32 lpae
        \\CPU implementer : 0x41
        \\CPU architecture: 7
        \\CPU variant : 0x2
        \\CPU part : 0xc0f
        \\CPU revision : 3
    );
    try testParser(ArmCpuinfoParser, .aarch64, &Target.aarch64.cpu.cortex_a72,
        \\processor       : 0
        \\BogoMIPS        : 108.00
        \\Features        : fp asimd evtstrm crc32 cpuid
        \\CPU implementer : 0x41
        \\CPU architecture: 8
        \\CPU variant     : 0x0
        \\CPU part        : 0xd08
        \\CPU revision    : 3
    );
}

fn testParser(
    parser: anytype,
    arch: Target.Cpu.Arch,
    expected_model: *const Target.Cpu.Model,
    input: []const u8,
) !void {
    var fbs = io.fixedBufferStream(input);
    const result = try parser.parse(arch, fbs.reader());
    try testing.expectEqual(expected_model, result.?.model);
    try testing.expect(expected_model.features.eql(result.?.features));
}

// The generic implementation of a /proc/cpuinfo parser.
// For every line it invokes the line_hook method with the key and value strings
// as first and second parameters. Returning false from the hook function stops
// the iteration without raising an error.
// When all the lines have been analyzed the finalize method is called.
fn CpuinfoParser(comptime impl: anytype) type {
    return struct {
        fn parse(arch: Target.Cpu.Arch, reader: anytype) anyerror!?Target.Cpu {
            var line_buf: [1024]u8 = undefined;
            var obj: impl = .{};

            while (true) {
                const line = (try reader.readUntilDelimiterOrEof(&line_buf, '\n')) orelse break;
                const colon_pos = mem.indexOfScalar(u8, line, ':') orelse continue;
                const key = mem.trimRight(u8, line[0..colon_pos], " \t");
                const value = mem.trimLeft(u8, line[colon_pos + 1 ..], " \t");

                if (!try obj.line_hook(key, value))
                    break;
            }

            return obj.finalize(arch);
        }
    };
}

inline fn getAArch64CpuFeature(comptime feat_reg: []const u8) u64 {
    return asm ("mrs %[ret], " ++ feat_reg
        : [ret] "=r" (-> u64),
    );
}

pub fn detectNativeCpuAndFeatures() ?Target.Cpu {
    var f = fs.openFileAbsolute("/proc/cpuinfo", .{}) catch |err| switch (err) {
        else => return null,
    };
    defer f.close();

    const current_arch = builtin.cpu.arch;
    switch (current_arch) {
        .arm, .armeb, .thumb, .thumbeb => {
            return ArmCpuinfoParser.parse(current_arch, f.reader()) catch null;
        },
        .aarch64, .aarch64_be => {
            const registers = [12]u64{
                getAArch64CpuFeature("MIDR_EL1"),
                getAArch64CpuFeature("ID_AA64PFR0_EL1"),
                getAArch64CpuFeature("ID_AA64PFR1_EL1"),
                getAArch64CpuFeature("ID_AA64DFR0_EL1"),
                getAArch64CpuFeature("ID_AA64DFR1_EL1"),
                getAArch64CpuFeature("ID_AA64AFR0_EL1"),
                getAArch64CpuFeature("ID_AA64AFR1_EL1"),
                getAArch64CpuFeature("ID_AA64ISAR0_EL1"),
                getAArch64CpuFeature("ID_AA64ISAR1_EL1"),
                getAArch64CpuFeature("ID_AA64MMFR0_EL1"),
                getAArch64CpuFeature("ID_AA64MMFR1_EL1"),
                getAArch64CpuFeature("ID_AA64MMFR2_EL1"),
            };

            const core = @import("arm.zig").aarch64.detectNativeCpuAndFeatures(current_arch, registers);
            return core;
        },
        .sparc64 => {
            return SparcCpuinfoParser.parse(current_arch, f.reader()) catch null;
        },
        .powerpc, .powerpcle, .powerpc64, .powerpc64le => {
            return PowerpcCpuinfoParser.parse(current_arch, f.reader()) catch null;
        },
        .riscv64, .riscv32 => {
            return RiscvCpuinfoParser.parse(current_arch, f.reader()) catch null;
        },
        else => {},
    }

    return null;
}
const std = @import("../../std.zig");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const process = std.process;
const mem = std.mem;

const NativePaths = @This();

arena: Allocator,
include_dirs: std.ArrayListUnmanaged([]const u8) = .empty,
lib_dirs: std.ArrayListUnmanaged([]const u8) = .empty,
framework_dirs: std.ArrayListUnmanaged([]const u8) = .empty,
rpaths: std.ArrayListUnmanaged([]const u8) = .empty,
warnings: std.ArrayListUnmanaged([]const u8) = .empty,

pub fn detect(arena: Allocator, native_target: std.Target) !NativePaths {
    var self: NativePaths = .{ .arena = arena };
    var is_nix = false;
    if (process.getEnvVarOwned(arena, "NIX_CFLAGS_COMPILE")) |nix_cflags_compile| {
        is_nix = true;
        var it = mem.tokenizeScalar(u8, nix_cflags_compile, ' ');
        while (true) {
            const word = it.next() orelse break;
            if (mem.eql(u8, word, "-isystem")) {
                const include_path = it.next() orelse {
                    try self.addWarning("Expected argument after -isystem in NIX_CFLAGS_COMPILE");
                    break;
                };
                try self.addIncludeDir(include_path);
            } else if (mem.eql(u8, word, "-iframework")) {
                const framework_path = it.next() orelse {
                    try self.addWarning("Expected argument after -iframework in NIX_CFLAGS_COMPILE");
                    break;
                };
                try self.addFrameworkDir(framework_path);
            } else {
                if (mem.startsWith(u8, word, "-frandom-seed=")) {
                    continue;
                }
                try self.addWarningFmt("Unrecognized C flag from NIX_CFLAGS_COMPILE: {s}", .{word});
            }
        }
    } else |err| switch (err) {
        error.InvalidWtf8 => unreachable,
        error.EnvironmentVariableNotFound => {},
        error.OutOfMemory => |e| return e,
    }
    if (process.getEnvVarOwned(arena, "NIX_LDFLAGS")) |nix_ldflags| {
        is_nix = true;
        var it = mem.tokenizeScalar(u8, nix_ldflags, ' ');
        while (true) {
            const word = it.next() orelse break;
            if (mem.eql(u8, word, "-rpath")) {
                const rpath = it.next() orelse {
                    try self.addWarning("Expected argument after -rpath in NIX_LDFLAGS");
                    break;
                };
                try self.addRPath(rpath);
            } else if (mem.eql(u8, word, "-L") or mem.eql(u8, word, "-l")) {
                _ = it.next() orelse {
                    try self.addWarning("Expected argument after -L or -l in NIX_LDFLAGS");
                    break;
                };
            } else if (mem.startsWith(u8, word, "-L")) {
                const lib_path = word[2..];
                try self.addLibDir(lib_path);
                try self.addRPath(lib_path);
            } else if (mem.startsWith(u8, word, "-l")) {
                // Ignore this argument.
            } else {
                try self.addWarningFmt("Unrecognized C flag from NIX_LDFLAGS: {s}", .{word});
                break;
            }
        }
    } else |err| switch (err) {
        error.InvalidWtf8 => unreachable,
        error.EnvironmentVariableNotFound => {},
        error.OutOfMemory => |e| return e,
    }
    if (is_nix) {
        return self;
    }

    // TODO: consider also adding macports paths
    if (builtin.target.os.tag.isDarwin()) {
        if (std.zig.system.darwin.isSdkInstalled(arena)) sdk: {
            const sdk = std.zig.system.darwin.getSdk(arena, native_target) orelse break :sdk;
            try self.addLibDir(try std.fs.path.join(arena, &.{ sdk, "usr/lib" }));
            try self.addFrameworkDir(try std.fs.path.join(arena, &.{ sdk, "System/Library/Frameworks" }));
            try self.addIncludeDir(try std.fs.path.join(arena, &.{ sdk, "usr/include" }));
        }

        // Check for homebrew paths
        if (std.posix.getenv("HOMEBREW_PREFIX")) |prefix| {
            try self.addLibDir(try std.fs.path.join(arena, &.{ prefix, "/lib" }));
            try self.addIncludeDir(try std.fs.path.join(arena, &.{ prefix, "/include" }));
        }

        return self;
    }

    if (builtin.os.tag.isSolarish()) {
        try self.addLibDir("/usr/lib/64");
        try self.addLibDir("/usr/local/lib/64");
        try self.addLibDir("/lib/64");

        try self.addIncludeDir("/usr/include");
        try self.addIncludeDir("/usr/local/include");

        return self;
    }

    if (builtin.os.tag == .haiku) {
        try self.addLibDir("/system/non-packaged/lib");
        try self.addLibDir("/system/develop/lib");
        try self.addLibDir("/system/lib");
        return self;
    }

    if (builtin.os.tag != .windows and builtin.os.tag != .wasi) {
        const triple = try native_target.linuxTriple(arena);

        const qual = native_target.ptrBitWidth();

        // TODO: $ ld --verbose | grep SEARCH_DIR
        // the output contains some paths that end with lib64, maybe include them too?
        // TODO: what is the best possible order of things?
        // TODO: some of these are suspect and should only be added on some systems. audit needed.

        try self.addIncludeDir("/usr/local/include");
        try self.addLibDirFmt("/usr/local/lib{d}", .{qual});
        try self.addLibDir("/usr/local/lib");

        try self.addIncludeDirFmt("/usr/include/{s}", .{triple});
        try self.addLibDirFmt("/usr/lib/{s}", .{triple});

        try self.addIncludeDir("/usr/include");
        try self.addLibDirFmt("/lib{d}", .{qual});
        try self.addLibDir("/lib");
        try self.addLibDirFmt("/usr/lib{d}", .{qual});
        try self.addLibDir("/usr/lib");

        // example: on a 64-bit debian-based linux distro, with zlib installed from apt:
        // zlib.h is in /usr/include (added above)
        // libz.so.1 is in /lib/x86_64-linux-gnu (added here)
        try self.addLibDirFmt("/lib/{s}", .{triple});

        // Distros like guix don't use FHS, so they rely on environment
        // variables to search for headers and libraries.
        // We use os.getenv here since this part won't be executed on
        // windows, to get rid of unnecessary error handling.
        if (std.posix.getenv("C_INCLUDE_PATH")) |c_include_path| {
            var it = mem.tokenizeScalar(u8, c_include_path, ':');
            while (it.next()) |dir| {
                try self.addIncludeDir(dir);
            }
        }

        if (std.posix.getenv("CPLUS_INCLUDE_PATH")) |cplus_include_path| {
            var it = mem.tokenizeScalar(u8, cplus_include_path, ':');
            while (it.next()) |dir| {
                try self.addIncludeDir(dir);
            }
        }

        if (std.posix.getenv("LIBRARY_PATH")) |library_path| {
            var it = mem.tokenizeScalar(u8, library_path, ':');
            while (it.next()) |dir| {
                try self.addLibDir(dir);
            }
        }
    }

    return self;
}

pub fn addIncludeDir(self: *NativePaths, s: []const u8) !void {
    return self.include_dirs.append(self.arena, s);
}

pub fn addIncludeDirFmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
    const item = try std.fmt.allocPrint(self.arena, fmt, args);
    try self.include_dirs.append(self.arena, item);
}

pub fn addLibDir(self: *NativePaths, s: []const u8) !void {
    try self.lib_dirs.append(self.arena, s);
}

pub fn addLibDirFmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
    const item = try std.fmt.allocPrint(self.arena, fmt, args);
    try self.lib_dirs.append(self.arena, item);
}

pub fn addWarning(self: *NativePaths, s: []const u8) !void {
    return self.warnings.append(self.arena, s);
}

pub fn addFrameworkDir(self: *NativePaths, s: []const u8) !void {
    return self.framework_dirs.append(self.arena, s);
}

pub fn addFrameworkDirFmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
    const item = try std.fmt.allocPrint(self.arena, fmt, args);
    try self.framework_dirs.append(self.arena, item);
}

pub fn addWarningFmt(self: *NativePaths, comptime fmt: []const u8, args: anytype) !void {
    const item = try std.fmt.allocPrint(self.arena, fmt, args);
    try self.warnings.append(self.arena, item);
}

pub fn addRPath(self: *NativePaths, s: []const u8) !void {
    try self.rpaths.append(self.arena, s);
}
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const mem = std.mem;
const Target = std.Target;

pub const WindowsVersion = std.Target.Os.WindowsVersion;
pub const PF = std.os.windows.PF;
pub const REG = std.os.windows.REG;
pub const IsProcessorFeaturePresent = std.os.windows.IsProcessorFeaturePresent;

/// Returns the highest known WindowsVersion deduced from reported runtime information.
/// Discards information about in-between versions we don't differentiate.
pub fn detectRuntimeVersion() WindowsVersion {
    var version_info: std.os.windows.RTL_OSVERSIONINFOW = undefined;
    version_info.dwOSVersionInfoSize = @sizeOf(@TypeOf(version_info));

    switch (std.os.windows.ntdll.RtlGetVersion(&version_info)) {
        .SUCCESS => {},
        else => unreachable,
    }

    // Starting from the system infos build a NTDDI-like version
    // constant whose format is:
    //   B0 B1 B2 B3
    //   `---` `` ``--> Sub-version (Starting from Windows 10 onwards)
    //     \    `--> Service pack (Always zero in the constants defined)
    //      `--> OS version (Major & minor)
    const os_ver: u16 = @as(u16, @intCast(version_info.dwMajorVersion & 0xff)) << 8 |
        @as(u16, @intCast(version_info.dwMinorVersion & 0xff));
    const sp_ver: u8 = 0;
    const sub_ver: u8 = if (os_ver >= 0x0A00) subver: {
        // There's no other way to obtain this info beside
        // checking the build number against a known set of
        // values
        var last_idx: usize = 0;
        for (WindowsVersion.known_win10_build_numbers, 0..) |build, i| {
            if (version_info.dwBuildNumber >= build)
                last_idx = i;
        }
        break :subver @as(u8, @truncate(last_idx));
    } else 0;

    const version: u32 = @as(u32, os_ver) << 16 | @as(u16, sp_ver) << 8 | sub_ver;

    return @as(WindowsVersion, @enumFromInt(version));
}

// Technically, a registry value can be as long as 1MB. However, MS recommends storing
// values larger than 2048 bytes in a file rather than directly in the registry, and since we
// are only accessing a system hive \Registry\Machine, we stick to MS guidelines.
// https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
const max_value_len = 2048;

fn getCpuInfoFromRegistry(core: usize, args: anytype) !void {
    const ArgsType = @TypeOf(args);
    const args_type_info = @typeInfo(ArgsType);

    if (args_type_info != .@"struct") {
        @compileError("expected tuple or struct argument, found " ++ @typeName(ArgsType));
    }

    const fields_info = args_type_info.@"struct".fields;

    // Originally, I wanted to issue a single call with a more complex table structure such that we
    // would sequentially visit each CPU#d subkey in the registry and pull the value of interest into
    // a buffer, however, NT seems to be expecting a single buffer per each table meaning we would
    // end up pulling only the last CPU core info, overwriting everything else.
    // If anyone can come up with a solution to this, please do!
    const table_size = 1 + fields_info.len;
    var table: [table_size + 1]std.os.windows.RTL_QUERY_REGISTRY_TABLE = undefined;

    const topkey = std.unicode.utf8ToUtf16LeStringLiteral("\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor");

    const max_cpu_buf = 4;
    var next_cpu_buf: [max_cpu_buf]u8 = undefined;
    const next_cpu = try std.fmt.bufPrint(&next_cpu_buf, "{d}", .{core});

    var subkey: [max_cpu_buf + 1]u16 = undefined;
    const subkey_len = try std.unicode.utf8ToUtf16Le(&subkey, next_cpu);
    subkey[subkey_len] = 0;

    table[0] = .{
        .QueryRoutine = null,
        .Flags = std.os.windows.RTL_QUERY_REGISTRY_SUBKEY | std.os.windows.RTL_QUERY_REGISTRY_REQUIRED,
        .Name = subkey[0..subkey_len :0],
        .EntryContext = null,
        .DefaultType = REG.NONE,
        .DefaultData = null,
        .DefaultLength = 0,
    };

    var tmp_bufs: [fields_info.len][max_value_len]u8 align(@alignOf(std.os.windows.UNICODE_STRING)) = undefined;

    inline for (fields_info, 0..) |field, i| {
        const ctx: *anyopaque = blk: {
            switch (@field(args, field.name).value_type) {
                REG.SZ,
                REG.EXPAND_SZ,
                REG.MULTI_SZ,
                => {
                    comptime assert(@sizeOf(std.os.windows.UNICODE_STRING) % 2 == 0);
                    const unicode = @as(*std.os.windows.UNICODE_STRING, @ptrCast(&tmp_bufs[i]));
                    unicode.* = .{
                        .Length = 0,
                        .MaximumLength = max_value_len - @sizeOf(std.os.windows.UNICODE_STRING),
                        .Buffer = @as([*]u16, @ptrCast(tmp_bufs[i][@sizeOf(std.os.windows.UNICODE_STRING)..])),
                    };
                    break :blk unicode;
                },

                REG.DWORD,
                REG.DWORD_BIG_ENDIAN,
                REG.QWORD,
                => break :blk &tmp_bufs[i],

                else => unreachable,
            }
        };

        var key_buf: [max_value_len / 2 + 1]u16 = undefined;
        const key_len = try std.unicode.utf8ToUtf16Le(&key_buf, @field(args, field.name).key);
        key_buf[key_len] = 0;

        table[i + 1] = .{
            .QueryRoutine = null,
            .Flags = std.os.windows.RTL_QUERY_REGISTRY_DIRECT | std.os.windows.RTL_QUERY_REGISTRY_REQUIRED,
            .Name = key_buf[0..key_len :0],
            .EntryContext = ctx,
            .DefaultType = REG.NONE,
            .DefaultData = null,
            .DefaultLength = 0,
        };
    }

    // Table sentinel
    table[table_size] = .{
        .QueryRoutine = null,
        .Flags = 0,
        .Name = null,
        .EntryContext = null,
        .DefaultType = 0,
        .DefaultData = null,
        .DefaultLength = 0,
    };

    const res = std.os.windows.ntdll.RtlQueryRegistryValues(
        std.os.windows.RTL_REGISTRY_ABSOLUTE,
        topkey,
        &table,
        null,
        null,
    );
    switch (res) {
        .SUCCESS => {
            inline for (fields_info, 0..) |field, i| switch (@field(args, field.name).value_type) {
                REG.SZ,
                REG.EXPAND_SZ,
                REG.MULTI_SZ,
                => {
                    var buf = @field(args, field.name).value_buf;
                    const entry = @as(*align(1) const std.os.windows.UNICODE_STRING, @ptrCast(table[i + 1].EntryContext));
                    const len = try std.unicode.utf16LeToUtf8(buf, entry.Buffer.?[0 .. entry.Length / 2]);
                    buf[len] = 0;
                },

                REG.DWORD,
                REG.DWORD_BIG_ENDIAN,
                REG.QWORD,
                => {
                    const entry = @as([*]align(1) const u8, @ptrCast(table[i + 1].EntryContext));
                    switch (@field(args, field.name).value_type) {
                        REG.DWORD, REG.DWORD_BIG_ENDIAN => {
                            @memcpy(@field(args, field.name).value_buf[0..4], entry[0..4]);
                        },
                        REG.QWORD => {
                            @memcpy(@field(args, field.name).value_buf[0..8], entry[0..8]);
                        },
                        else => unreachable,
                    }
                },

                else => unreachable,
            };
        },
        else => return error.Unexpected,
    }
}

fn setFeature(comptime Feature: type, cpu: *Target.Cpu, feature: Feature, enabled: bool) void {
    const idx = @as(Target.Cpu.Feature.Set.Index, @intFromEnum(feature));

    if (enabled) cpu.features.addFeature(idx) else cpu.features.removeFeature(idx);
}

fn getCpuCount() usize {
    return std.os.windows.peb().NumberOfProcessors;
}

/// If the fine-grained detection of CPU features via Win registry fails,
/// we fallback to a generic CPU model but we override the feature set
/// using `SharedUserData` contents.
/// This is effectively what LLVM does for all ARM chips on Windows.
fn genericCpuAndNativeFeatures(arch: Target.Cpu.Arch) Target.Cpu {
    var cpu = Target.Cpu{
        .arch = arch,
        .model = Target.Cpu.Model.generic(arch),
        .features = Target.Cpu.Feature.Set.empty,
    };

    switch (arch) {
        .aarch64, .aarch64_be => {
            const Feature = Target.aarch64.Feature;

            // Override any features that are either present or absent
            setFeature(Feature, &cpu, .neon, IsProcessorFeaturePresent(PF.ARM_NEON_INSTRUCTIONS_AVAILABLE));
            setFeature(Feature, &cpu, .crc, IsProcessorFeaturePresent(PF.ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE));
            setFeature(Feature, &cpu, .crypto, IsProcessorFeaturePresent(PF.ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE));
            setFeature(Feature, &cpu, .lse, IsProcessorFeaturePresent(PF.ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE));
            setFeature(Feature, &cpu, .dotprod, IsProcessorFeaturePresent(PF.ARM_V82_DP_INSTRUCTIONS_AVAILABLE));
            setFeature(Feature, &cpu, .jsconv, IsProcessorFeaturePresent(PF.ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE));
        },
        else => {},
    }

    return cpu;
}

pub fn detectNativeCpuAndFeatures() ?Target.Cpu {
    const current_arch = builtin.cpu.arch;
    const cpu: ?Target.Cpu = switch (current_arch) {
        .aarch64, .aarch64_be => blk: {
            var cores: [128]Target.Cpu = undefined;
            const core_count = getCpuCount();

            if (core_count > cores.len) break :blk null;

            var i: usize = 0;
            while (i < core_count) : (i += 1) {
                // Backing datastore
                var registers: [12]u64 = undefined;

                // Registry key to system ID register mapping
                // CP 4000 -> MIDR_EL1
                // CP 4020 -> ID_AA64PFR0_EL1
                // CP 4021 -> ID_AA64PFR1_EL1
                // CP 4028 -> ID_AA64DFR0_EL1
                // CP 4029 -> ID_AA64DFR1_EL1
                // CP 402C -> ID_AA64AFR0_EL1
                // CP 402D -> ID_AA64AFR1_EL1
                // CP 4030 -> ID_AA64ISAR0_EL1
                // CP 4031 -> ID_AA64ISAR1_EL1
                // CP 4038 -> ID_AA64MMFR0_EL1
                // CP 4039 -> ID_AA64MMFR1_EL1
                // CP 403A -> ID_AA64MMFR2_EL1
                getCpuInfoFromRegistry(i, .{
                    .{ .key = "CP 4000", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[0])) },
                    .{ .key = "CP 4020", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[1])) },
                    .{ .key = "CP 4021", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[2])) },
                    .{ .key = "CP 4028", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[3])) },
                    .{ .key = "CP 4029", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[4])) },
                    .{ .key = "CP 402C", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[5])) },
                    .{ .key = "CP 402D", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[6])) },
                    .{ .key = "CP 4030", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[7])) },
                    .{ .key = "CP 4031", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[8])) },
                    .{ .key = "CP 4038", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[9])) },
                    .{ .key = "CP 4039", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[10])) },
                    .{ .key = "CP 403A", .value_type = REG.QWORD, .value_buf = @as(*[8]u8, @ptrCast(&registers[11])) },
                }) catch break :blk null;

                cores[i] = @import("arm.zig").aarch64.detectNativeCpuAndFeatures(current_arch, registers) orelse
                    break :blk null;
            }

            // Pick the first core, usually LITTLE in big.LITTLE architecture.
            break :blk cores[0];
        },
        else => null,
    };
    return cpu orelse genericCpuAndNativeFeatures(current_arch);
}
const std = @import("std");
const builtin = @import("builtin");
const Target = std.Target;

/// Only covers EAX for now.
const Xcr0 = packed struct(u32) {
    x87: bool,
    sse: bool,
    avx: bool,
    bndreg: bool,
    bndcsr: bool,
    opmask: bool,
    zmm_hi256: bool,
    hi16_zmm: bool,
    pt: bool,
    pkru: bool,
    pasid: bool,
    cet_u: bool,```
