```
x_str, 10) catch return error.InvalidFormat;
            if (prefix >= self.cache.prefixes_len) return error.InvalidFormat;

            if (file_path.len == 0) return error.InvalidFormat;

            const cache_hash_file = f: {
                const prefixed_path: PrefixedPath = .{
                    .prefix = prefix,
                    .sub_path = file_path, // expires with file_contents
                };
                if (idx < input_file_count) {
                    const file = &self.files.keys()[idx];
                    if (!file.prefixed_path.eql(prefixed_path))
                        return error.InvalidFormat;

                    file.stat = .{
                        .size = stat_size,
                        .inode = stat_inode,
                        .mtime = stat_mtime,
                    };
                    file.bin_digest = file_bin_digest;
                    break :f file;
                }
                const gop = try self.files.getOrPutAdapted(gpa, prefixed_path, FilesAdapter{});
                errdefer _ = self.files.pop();
                if (!gop.found_existing) {
                    gop.key_ptr.* = .{
                        .prefixed_path = .{
                            .prefix = prefix,
                            .sub_path = try gpa.dupe(u8, file_path),
                        },
                        .contents = null,
                        .max_file_size = null,
                        .handle = null,
                        .stat = .{
                            .size = stat_size,
                            .inode = stat_inode,
                            .mtime = stat_mtime,
                        },
                        .bin_digest = file_bin_digest,
                    };
                }
                break :f gop.key_ptr;
            };

            const pp = cache_hash_file.prefixed_path;
            const dir = self.cache.prefixes()[pp.prefix].handle;
            const this_file = dir.openFile(pp.sub_path, .{ .mode = .read_only }) catch |err| switch (err) {
                error.FileNotFound => {
                    // Every digest before this one has been populated successfully.
                    return .{ .miss = .{ .file_digests_populated = idx } };
                },
                else => |e| {
                    self.diagnostic = .{ .file_open = .{
                        .file_index = idx,
                        .err = e,
                    } };
                    return error.CacheCheckFailed;
                },
            };
            defer this_file.close();

            const actual_stat = this_file.stat() catch |err| {
                self.diagnostic = .{ .file_stat = .{
                    .file_index = idx,
                    .err = err,
                } };
                return error.CacheCheckFailed;
            };
            const size_match = actual_stat.size == cache_hash_file.stat.size;
            const mtime_match = actual_stat.mtime == cache_hash_file.stat.mtime;
            const inode_match = actual_stat.inode == cache_hash_file.stat.inode;

            if (!size_match or !mtime_match or !inode_match) {
                cache_hash_file.stat = .{
                    .size = actual_stat.size,
                    .mtime = actual_stat.mtime,
                    .inode = actual_stat.inode,
                };

                if (self.isProblematicTimestamp(cache_hash_file.stat.mtime)) {
                    // The actual file has an unreliable timestamp, force it to be hashed
                    cache_hash_file.stat.mtime = 0;
                    cache_hash_file.stat.inode = 0;
                }

                var actual_digest: BinDigest = undefined;
                hashFile(this_file, &actual_digest) catch |err| {
                    self.diagnostic = .{ .file_read = .{
                        .file_index = idx,
                        .err = err,
                    } };
                    return error.CacheCheckFailed;
                };

                if (!mem.eql(u8, &cache_hash_file.bin_digest, &actual_digest)) {
                    cache_hash_file.bin_digest = actual_digest;
                    // keep going until we have the input file digests
                    any_file_changed = true;
                }
            }

            if (!any_file_changed) {
                self.hash.hasher.update(&cache_hash_file.bin_digest);
            }
        }

        // If the manifest was somehow missing one of our input files, or if any file hash has changed,
        // then this is a cache miss. However, we have successfully populated some or all of the file
        // digests.
        if (any_file_changed or idx < input_file_count) {
            return .{ .miss = .{ .file_digests_populated = idx } };
        }

        return .hit;
    }

    /// Reset `self.hash.hasher` to the state it should be in after `hit` returns `false`.
    /// The hasher contains the original input digest, and all original input file digests (i.e.
    /// not including post files).
    /// Assumes that `bin_digest` is populated for all files up to `input_file_count`. As such,
    /// this is not necessarily safe to call within `hit`.
    pub fn unhit(self: *Manifest, bin_digest: BinDigest, input_file_count: usize) void {
        // Reset the hash.
        self.hash.hasher = hasher_init;
        self.hash.hasher.update(&bin_digest);

        // Remove files not in the initial hash.
        while (self.files.count() != input_file_count) {
            var file = self.files.pop().?;
            file.key.deinit(self.cache.gpa);
        }

        for (self.files.keys()) |file| {
            self.hash.hasher.update(&file.bin_digest);
        }
    }

    fn isProblematicTimestamp(man: *Manifest, file_time: i128) bool {
        // If the file_time is prior to the most recent problematic timestamp
        // then we don't need to access the filesystem.
        if (file_time < man.recent_problematic_timestamp)
            return false;

        // Next we will check the globally shared Cache timestamp, which is accessed
        // from multiple threads.
        man.cache.mutex.lock();
        defer man.cache.mutex.unlock();

        // Save the global one to our local one to avoid locking next time.
        man.recent_problematic_timestamp = man.cache.recent_problematic_timestamp;
        if (file_time < man.recent_problematic_timestamp)
            return false;

        // This flag prevents multiple filesystem writes for the same hit() call.
        if (man.want_refresh_timestamp) {
            man.want_refresh_timestamp = false;

            var file = man.cache.manifest_dir.createFile("timestamp", .{
                .read = true,
                .truncate = true,
            }) catch return true;
            defer file.close();

            // Save locally and also save globally (we still hold the global lock).
            man.recent_problematic_timestamp = (file.stat() catch return true).mtime;
            man.cache.recent_problematic_timestamp = man.recent_problematic_timestamp;
        }

        return file_time >= man.recent_problematic_timestamp;
    }

    fn populateFileHash(self: *Manifest, ch_file: *File) !void {
        if (ch_file.handle) |handle| {
            return populateFileHashHandle(self, ch_file, handle);
        } else {
            const pp = ch_file.prefixed_path;
            const dir = self.cache.prefixes()[pp.prefix].handle;
            const handle = try dir.openFile(pp.sub_path, .{});
            defer handle.close();
            return populateFileHashHandle(self, ch_file, handle);
        }
    }

    fn populateFileHashHandle(self: *Manifest, ch_file: *File, handle: fs.File) !void {
        const actual_stat = try handle.stat();
        ch_file.stat = .{
            .size = actual_stat.size,
            .mtime = actual_stat.mtime,
            .inode = actual_stat.inode,
        };

        if (self.isProblematicTimestamp(ch_file.stat.mtime)) {
            // The actual file has an unreliable timestamp, force it to be hashed
            ch_file.stat.mtime = 0;
            ch_file.stat.inode = 0;
        }

        if (ch_file.max_file_size) |max_file_size| {
            if (ch_file.stat.size > max_file_size) {
                return error.FileTooBig;
            }

            const contents = try self.cache.gpa.alloc(u8, @as(usize, @intCast(ch_file.stat.size)));
            errdefer self.cache.gpa.free(contents);

            // Hash while reading from disk, to keep the contents in the cpu cache while
            // doing hashing.
            var hasher = hasher_init;
            var off: usize = 0;
            while (true) {
                const bytes_read = try handle.pread(contents[off..], off);
                if (bytes_read == 0) break;
                hasher.update(contents[off..][0..bytes_read]);
                off += bytes_read;
            }
            hasher.final(&ch_file.bin_digest);

            ch_file.contents = contents;
        } else {
            try hashFile(handle, &ch_file.bin_digest);
        }

        self.hash.hasher.update(&ch_file.bin_digest);
    }

    /// Add a file as a dependency of process being cached, after the initial hash has been
    /// calculated. This is useful for processes that don't know all the files that
    /// are depended on ahead of time. For example, a source file that can import other files
    /// will need to be recompiled if the imported file is changed.
    pub fn addFilePostFetch(self: *Manifest, file_path: []const u8, max_file_size: usize) ![]const u8 {
        assert(self.manifest_file != null);

        const gpa = self.cache.gpa;
        const prefixed_path = try self.cache.findPrefix(file_path);
        errdefer gpa.free(prefixed_path.sub_path);

        const gop = try self.files.getOrPutAdapted(gpa, prefixed_path, FilesAdapter{});
        errdefer _ = self.files.pop();

        if (gop.found_existing) {
            gpa.free(prefixed_path.sub_path);
            return gop.key_ptr.contents.?;
        }

        gop.key_ptr.* = .{
            .prefixed_path = prefixed_path,
            .max_file_size = max_file_size,
            .stat = undefined,
            .bin_digest = undefined,
            .contents = null,
        };

        self.files.lockPointers();
        defer self.files.unlockPointers();

        try self.populateFileHash(gop.key_ptr);
        return gop.key_ptr.contents.?;
    }

    /// Add a file as a dependency of process being cached, after the initial hash has been
    /// calculated.
    ///
    /// This is useful for processes that don't know the all the files that are
    /// depended on ahead of time. For example, a source file that can import
    /// other files will need to be recompiled if the imported file is changed.
    pub fn addFilePost(self: *Manifest, file_path: []const u8) !void {
        assert(self.manifest_file != null);

        const gpa = self.cache.gpa;
        const prefixed_path = try self.cache.findPrefix(file_path);
        errdefer gpa.free(prefixed_path.sub_path);

        const gop = try self.files.getOrPutAdapted(gpa, prefixed_path, FilesAdapter{});
        errdefer _ = self.files.pop();

        if (gop.found_existing) {
            gpa.free(prefixed_path.sub_path);
            return;
        }

        gop.key_ptr.* = .{
            .prefixed_path = prefixed_path,
            .max_file_size = null,
            .handle = null,
            .stat = undefined,
            .bin_digest = undefined,
            .contents = null,
        };

        self.files.lockPointers();
        defer self.files.unlockPointers();

        try self.populateFileHash(gop.key_ptr);
    }

    /// Like `addFilePost` but when the file contents have already been loaded from disk.
    /// On success, cache takes ownership of `resolved_path`.
    pub fn addFilePostContents(
        self: *Manifest,
        resolved_path: []u8,
        bytes: []const u8,
        stat: File.Stat,
    ) !void {
        assert(self.manifest_file != null);
        const gpa = self.cache.gpa;

        const prefixed_path = try self.cache.findPrefixResolved(resolved_path);
        errdefer gpa.free(prefixed_path.sub_path);

        const gop = try self.files.getOrPutAdapted(gpa, prefixed_path, FilesAdapter{});
        errdefer _ = self.files.pop();

        if (gop.found_existing) {
            gpa.free(prefixed_path.sub_path);
            return;
        }

        const new_file = gop.key_ptr;

        new_file.* = .{
            .prefixed_path = prefixed_path,
            .max_file_size = null,
            .handle = null,
            .stat = stat,
            .bin_digest = undefined,
            .contents = null,
        };

        if (self.isProblematicTimestamp(new_file.stat.mtime)) {
            // The actual file has an unreliable timestamp, force it to be hashed
            new_file.stat.mtime = 0;
            new_file.stat.inode = 0;
        }

        {
            var hasher = hasher_init;
            hasher.update(bytes);
            hasher.final(&new_file.bin_digest);
        }

        self.hash.hasher.update(&new_file.bin_digest);
    }

    pub fn addDepFilePost(self: *Manifest, dir: fs.Dir, dep_file_basename: []const u8) !void {
        assert(self.manifest_file != null);
        return self.addDepFileMaybePost(dir, dep_file_basename);
    }

    fn addDepFileMaybePost(self: *Manifest, dir: fs.Dir, dep_file_basename: []const u8) !void {
        const dep_file_contents = try dir.readFileAlloc(self.cache.gpa, dep_file_basename, manifest_file_size_max);
        defer self.cache.gpa.free(dep_file_contents);

        var error_buf = std.ArrayList(u8).init(self.cache.gpa);
        defer error_buf.deinit();

        var it: DepTokenizer = .{ .bytes = dep_file_contents };

        while (it.next()) |token| {
            switch (token) {
                // We don't care about targets, we only want the prereqs
                // Clang is invoked in single-source mode but other programs may not
                .target, .target_must_resolve => {},
                .prereq => |file_path| if (self.manifest_file == null) {
                    _ = try self.addFile(file_path, null);
                } else try self.addFilePost(file_path),
                .prereq_must_resolve => {
                    var resolve_buf = std.ArrayList(u8).init(self.cache.gpa);
                    defer resolve_buf.deinit();

                    try token.resolve(resolve_buf.writer());
                    if (self.manifest_file == null) {
                        _ = try self.addFile(resolve_buf.items, null);
                    } else try self.addFilePost(resolve_buf.items);
                },
                else => |err| {
                    try err.printError(error_buf.writer());
                    log.err("failed parsing {s}: {s}", .{ dep_file_basename, error_buf.items });
                    return error.InvalidDepFile;
                },
            }
        }
    }

    /// Returns a binary hash of the inputs.
    pub fn finalBin(self: *Manifest) BinDigest {
        assert(self.manifest_file != null);

        // We don't close the manifest file yet, because we want to
        // keep it locked until the API user is done using it.
        // We also don't write out the manifest yet, because until
        // cache_release is called we still might be working on creating
        // the artifacts to cache.

        var bin_digest: BinDigest = undefined;
        self.hash.hasher.final(&bin_digest);
        return bin_digest;
    }

    /// Returns a hex encoded hash of the inputs.
    pub fn final(self: *Manifest) HexDigest {
        const bin_digest = self.finalBin();
        return binToHex(bin_digest);
    }

    /// If `want_shared_lock` is true, this function automatically downgrades the
    /// lock from exclusive to shared.
    pub fn writeManifest(self: *Manifest) !void {
        assert(self.have_exclusive_lock);

        const manifest_file = self.manifest_file.?;
        if (self.manifest_dirty) {
            self.manifest_dirty = false;

            var contents = std.ArrayList(u8).init(self.cache.gpa);
            defer contents.deinit();

            const writer = contents.writer();
            try writer.writeAll(manifest_header ++ "\n");
            for (self.files.keys()) |file| {
                try writer.print("{d} {d} {d} {} {d} {s}\n", .{
                    file.stat.size,
                    file.stat.inode,
                    file.stat.mtime,
                    fmt.fmtSliceHexLower(&file.bin_digest),
                    file.prefixed_path.prefix,
                    file.prefixed_path.sub_path,
                });
            }

            try manifest_file.setEndPos(contents.items.len);
            try manifest_file.pwriteAll(contents.items, 0);
        }

        if (self.want_shared_lock) {
            try self.downgradeToSharedLock();
        }
    }

    fn downgradeToSharedLock(self: *Manifest) !void {
        if (!self.have_exclusive_lock) return;

        // WASI does not currently support flock, so we bypass it here.
        // TODO: If/when flock is supported on WASI, this check should be removed.
        //       See https://github.com/WebAssembly/wasi-filesystem/issues/2
        if (builtin.os.tag != .wasi or std.process.can_spawn or !builtin.single_threaded) {
            const manifest_file = self.manifest_file.?;
            try manifest_file.downgradeLock();
        }

        self.have_exclusive_lock = false;
    }

    fn upgradeToExclusiveLock(self: *Manifest) error{CacheCheckFailed}!bool {
        if (self.have_exclusive_lock) return false;
        assert(self.manifest_file != null);

        // WASI does not currently support flock, so we bypass it here.
        // TODO: If/when flock is supported on WASI, this check should be removed.
        //       See https://github.com/WebAssembly/wasi-filesystem/issues/2
        if (builtin.os.tag != .wasi or std.process.can_spawn or !builtin.single_threaded) {
            const manifest_file = self.manifest_file.?;
            // Here we intentionally have a period where the lock is released, in case there are
            // other processes holding a shared lock.
            manifest_file.unlock();
            manifest_file.lock(.exclusive) catch |err| {
                self.diagnostic = .{ .manifest_lock = err };
                return error.CacheCheckFailed;
            };
        }
        self.have_exclusive_lock = true;
        return true;
    }

    /// Obtain only the data needed to maintain a lock on the manifest file.
    /// The `Manifest` remains safe to deinit.
    /// Don't forget to call `writeManifest` before this!
    pub fn toOwnedLock(self: *Manifest) Lock {
        const lock: Lock = .{
            .manifest_file = self.manifest_file.?,
        };

        self.manifest_file = null;
        return lock;
    }

    /// Releases the manifest file and frees any memory the Manifest was using.
    /// `Manifest.hit` must be called first.
    /// Don't forget to call `writeManifest` before this!
    pub fn deinit(self: *Manifest) void {
        if (self.manifest_file) |file| {
            if (builtin.os.tag == .windows) {
                // See Lock.release for why this is required on Windows
                file.unlock();
            }

            file.close();
        }
        for (self.files.keys()) |*file| {
            file.deinit(self.cache.gpa);
        }
        self.files.deinit(self.cache.gpa);
    }

    pub fn populateFileSystemInputs(man: *Manifest, buf: *std.ArrayListUnmanaged(u8)) Allocator.Error!void {
        assert(@typeInfo(std.zig.Server.Message.PathPrefix).@"enum".fields.len == man.cache.prefixes_len);
        buf.clearRetainingCapacity();
        const gpa = man.cache.gpa;
        const files = man.files.keys();
        if (files.len > 0) {
            for (files) |file| {
                try buf.ensureUnusedCapacity(gpa, file.prefixed_path.sub_path.len + 2);
                buf.appendAssumeCapacity(file.prefixed_path.prefix + 1);
                buf.appendSliceAssumeCapacity(file.prefixed_path.sub_path);
                buf.appendAssumeCapacity(0);
            }
            // The null byte is a separator, not a terminator.
            buf.items.len -= 1;
        }
    }

    pub fn populateOtherManifest(man: *Manifest, other: *Manifest, prefix_map: [4]u8) Allocator.Error!void {
        const gpa = other.cache.gpa;
        assert(@typeInfo(std.zig.Server.Message.PathPrefix).@"enum".fields.len == man.cache.prefixes_len);
        assert(man.cache.prefixes_len == 4);
        for (man.files.keys()) |file| {
            const prefixed_path: PrefixedPath = .{
                .prefix = prefix_map[file.prefixed_path.prefix],
                .sub_path = try gpa.dupe(u8, file.prefixed_path.sub_path),
            };
            errdefer gpa.free(prefixed_path.sub_path);

            const gop = try other.files.getOrPutAdapted(gpa, prefixed_path, FilesAdapter{});
            errdefer _ = other.files.pop();

            if (gop.found_existing) {
                gpa.free(prefixed_path.sub_path);
                continue;
            }

            gop.key_ptr.* = .{
                .prefixed_path = prefixed_path,
                .max_file_size = file.max_file_size,
                .handle = file.handle,
                .stat = file.stat,
                .bin_digest = file.bin_digest,
                .contents = null,
            };

            other.hash.hasher.update(&gop.key_ptr.bin_digest);
        }
    }
};

/// On operating systems that support symlinks, does a readlink. On other operating systems,
/// uses the file contents. Windows supports symlinks but only with elevated privileges, so
/// it is treated as not supporting symlinks.
pub fn readSmallFile(dir: fs.Dir, sub_path: []const u8, buffer: []u8) ![]u8 {
    if (builtin.os.tag == .windows) {
        return dir.readFile(sub_path, buffer);
    } else {
        return dir.readLink(sub_path, buffer);
    }
}

/// On operating systems that support symlinks, does a symlink. On other operating systems,
/// uses the file contents. Windows supports symlinks but only with elevated privileges, so
/// it is treated as not supporting symlinks.
/// `data` must be a valid UTF-8 encoded file path and 255 bytes or fewer.
pub fn writeSmallFile(dir: fs.Dir, sub_path: []const u8, data: []const u8) !void {
    assert(data.len <= 255);
    if (builtin.os.tag == .windows) {
        return dir.writeFile(.{ .sub_path = sub_path, .data = data });
    } else {
        return dir.symLink(data, sub_path, .{});
    }
}

fn hashFile(file: fs.File, bin_digest: *[Hasher.mac_length]u8) fs.File.PReadError!void {
    var buf: [1024]u8 = undefined;
    var hasher = hasher_init;
    var off: u64 = 0;
    while (true) {
        const bytes_read = try file.pread(&buf, off);
        if (bytes_read == 0) break;
        hasher.update(buf[0..bytes_read]);
        off += bytes_read;
    }
    hasher.final(bin_digest);
}

// Create/Write a file, close it, then grab its stat.mtime timestamp.
fn testGetCurrentFileTimestamp(dir: fs.Dir) !i128 {
    const test_out_file = "test-filetimestamp.tmp";

    var file = try dir.createFile(test_out_file, .{
        .read = true,
        .truncate = true,
    });
    defer {
        file.close();
        dir.deleteFile(test_out_file) catch {};
    }

    return (try file.stat()).mtime;
}

test "cache file and then recall it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const temp_file = "test.txt";
    const temp_manifest_dir = "temp_manifest_dir";

    try tmp.dir.writeFile(.{ .sub_path = temp_file, .data = "Hello, world!\n" });

    // Wait for file timestamps to tick
    const initial_time = try testGetCurrentFileTimestamp(tmp.dir);
    while ((try testGetCurrentFileTimestamp(tmp.dir)) == initial_time) {
        std.time.sleep(1);
    }

    var digest1: HexDigest = undefined;
    var digest2: HexDigest = undefined;

    {
        var cache = Cache{
            .gpa = testing.allocator,
            .manifest_dir = try tmp.dir.makeOpenPath(temp_manifest_dir, .{}),
        };
        cache.addPrefix(.{ .path = null, .handle = tmp.dir });
        defer cache.manifest_dir.close();

        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.add(true);
            ch.hash.add(@as(u16, 1234));
            ch.hash.addBytes("1234");
            _ = try ch.addFile(temp_file, null);

            // There should be nothing in the cache
            try testing.expectEqual(false, try ch.hit());

            digest1 = ch.final();
            try ch.writeManifest();
        }
        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.add(true);
            ch.hash.add(@as(u16, 1234));
            ch.hash.addBytes("1234");
            _ = try ch.addFile(temp_file, null);

            // Cache hit! We just "built" the same file
            try testing.expect(try ch.hit());
            digest2 = ch.final();

            try testing.expectEqual(false, ch.have_exclusive_lock);
        }

        try testing.expectEqual(digest1, digest2);
    }
}

test "check that changing a file makes cache fail" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const temp_file = "cache_hash_change_file_test.txt";
    const temp_manifest_dir = "cache_hash_change_file_manifest_dir";
    const original_temp_file_contents = "Hello, world!\n";
    const updated_temp_file_contents = "Hello, world; but updated!\n";

    try tmp.dir.writeFile(.{ .sub_path = temp_file, .data = original_temp_file_contents });

    // Wait for file timestamps to tick
    const initial_time = try testGetCurrentFileTimestamp(tmp.dir);
    while ((try testGetCurrentFileTimestamp(tmp.dir)) == initial_time) {
        std.time.sleep(1);
    }

    var digest1: HexDigest = undefined;
    var digest2: HexDigest = undefined;

    {
        var cache = Cache{
            .gpa = testing.allocator,
            .manifest_dir = try tmp.dir.makeOpenPath(temp_manifest_dir, .{}),
        };
        cache.addPrefix(.{ .path = null, .handle = tmp.dir });
        defer cache.manifest_dir.close();

        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.addBytes("1234");
            const temp_file_idx = try ch.addFile(temp_file, 100);

            // There should be nothing in the cache
            try testing.expectEqual(false, try ch.hit());

            try testing.expect(mem.eql(u8, original_temp_file_contents, ch.files.keys()[temp_file_idx].contents.?));

            digest1 = ch.final();

            try ch.writeManifest();
        }

        try tmp.dir.writeFile(.{ .sub_path = temp_file, .data = updated_temp_file_contents });

        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.addBytes("1234");
            const temp_file_idx = try ch.addFile(temp_file, 100);

            // A file that we depend on has been updated, so the cache should not contain an entry for it
            try testing.expectEqual(false, try ch.hit());

            // The cache system does not keep the contents of re-hashed input files.
            try testing.expect(ch.files.keys()[temp_file_idx].contents == null);

            digest2 = ch.final();

            try ch.writeManifest();
        }

        try testing.expect(!mem.eql(u8, digest1[0..], digest2[0..]));
    }
}

test "no file inputs" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const temp_manifest_dir = "no_file_inputs_manifest_dir";

    var digest1: HexDigest = undefined;
    var digest2: HexDigest = undefined;

    var cache = Cache{
        .gpa = testing.allocator,
        .manifest_dir = try tmp.dir.makeOpenPath(temp_manifest_dir, .{}),
    };
    cache.addPrefix(.{ .path = null, .handle = tmp.dir });
    defer cache.manifest_dir.close();

    {
        var man = cache.obtain();
        defer man.deinit();

        man.hash.addBytes("1234");

        // There should be nothing in the cache
        try testing.expectEqual(false, try man.hit());

        digest1 = man.final();

        try man.writeManifest();
    }
    {
        var man = cache.obtain();
        defer man.deinit();

        man.hash.addBytes("1234");

        try testing.expect(try man.hit());
        digest2 = man.final();
        try testing.expectEqual(false, man.have_exclusive_lock);
    }

    try testing.expectEqual(digest1, digest2);
}

test "Manifest with files added after initial hash work" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const temp_file1 = "cache_hash_post_file_test1.txt";
    const temp_file2 = "cache_hash_post_file_test2.txt";
    const temp_manifest_dir = "cache_hash_post_file_manifest_dir";

    try tmp.dir.writeFile(.{ .sub_path = temp_file1, .data = "Hello, world!\n" });
    try tmp.dir.writeFile(.{ .sub_path = temp_file2, .data = "Hello world the second!\n" });

    // Wait for file timestamps to tick
    const initial_time = try testGetCurrentFileTimestamp(tmp.dir);
    while ((try testGetCurrentFileTimestamp(tmp.dir)) == initial_time) {
        std.time.sleep(1);
    }

    var digest1: HexDigest = undefined;
    var digest2: HexDigest = undefined;
    var digest3: HexDigest = undefined;

    {
        var cache = Cache{
            .gpa = testing.allocator,
            .manifest_dir = try tmp.dir.makeOpenPath(temp_manifest_dir, .{}),
        };
        cache.addPrefix(.{ .path = null, .handle = tmp.dir });
        defer cache.manifest_dir.close();

        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.addBytes("1234");
            _ = try ch.addFile(temp_file1, null);

            // There should be nothing in the cache
            try testing.expectEqual(false, try ch.hit());

            _ = try ch.addFilePost(temp_file2);

            digest1 = ch.final();
            try ch.writeManifest();
        }
        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.addBytes("1234");
            _ = try ch.addFile(temp_file1, null);

            try testing.expect(try ch.hit());
            digest2 = ch.final();

            try testing.expectEqual(false, ch.have_exclusive_lock);
        }
        try testing.expect(mem.eql(u8, &digest1, &digest2));

        // Modify the file added after initial hash
        try tmp.dir.writeFile(.{ .sub_path = temp_file2, .data = "Hello world the second, updated\n" });

        // Wait for file timestamps to tick
        const initial_time2 = try testGetCurrentFileTimestamp(tmp.dir);
        while ((try testGetCurrentFileTimestamp(tmp.dir)) == initial_time2) {
            std.time.sleep(1);
        }

        {
            var ch = cache.obtain();
            defer ch.deinit();

            ch.hash.addBytes("1234");
            _ = try ch.addFile(temp_file1, null);

            // A file that we depend on has been updated, so the cache should not contain an entry for it
            try testing.expectEqual(false, try ch.hit());

            _ = try ch.addFilePost(temp_file2);

            digest3 = ch.final();

            try ch.writeManifest();
        }

        try testing.expect(!mem.eql(u8, &digest1, &digest3));
    }
}
const Tokenizer = @This();

index: usize = 0,
bytes: []const u8,
state: State = .lhs,

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

pub fn next(self: *Tokenizer) ?Token {
    var start = self.index;
    var must_resolve = false;
    while (self.index < self.bytes.len) {
        const char = self.bytes[self.index];
        switch (self.state) {
            .lhs => switch (char) {
                '\t', '\n', '\r', ' ' => {
                    // silently ignore whitespace
                    self.index += 1;
                },
                else => {
                    start = self.index;
                    self.state = .target;
                },
            },
            .target => switch (char) {
                '\n', '\r' => {
                    return errorIllegalChar(.invalid_target, self.index, char);
                },
                '$' => {
                    self.state = .target_dollar_sign;
                    self.index += 1;
                },
                '\\' => {
                    self.state = .target_reverse_solidus;
                    self.index += 1;
                },
                ':' => {
                    self.state = .target_colon;
                    self.index += 1;
                },
                '\t', ' ' => {
                    self.state = .target_space;

                    const bytes = self.bytes[start..self.index];
                    std.debug.assert(bytes.len != 0);
                    self.index += 1;

                    return finishTarget(must_resolve, bytes);
                },
                else => {
                    self.index += 1;
                },
            },
            .target_reverse_solidus => switch (char) {
                '\t', '\n', '\r' => {
                    return errorIllegalChar(.bad_target_escape, self.index, char);
                },
                ' ', '#', '\\' => {
                    must_resolve = true;
                    self.state = .target;
                    self.index += 1;
                },
                '$' => {
                    self.state = .target_dollar_sign;
                    self.index += 1;
                },
                else => {
                    self.state = .target;
                    self.index += 1;
                },
            },
            .target_dollar_sign => switch (char) {
                '$' => {
                    must_resolve = true;
                    self.state = .target;
                    self.index += 1;
                },
                else => {
                    return errorIllegalChar(.expected_dollar_sign, self.index, char);
                },
            },
            .target_colon => switch (char) {
                '\n', '\r' => {
                    const bytes = self.bytes[start .. self.index - 1];
                    if (bytes.len != 0) {
                        self.state = .lhs;
                        return finishTarget(must_resolve, bytes);
                    }
                    // silently ignore null target
                    self.state = .lhs;
                },
                '/', '\\' => {
                    self.state = .target_colon_reverse_solidus;
                    self.index += 1;
                },
                else => {
                    const bytes = self.bytes[start .. self.index - 1];
                    if (bytes.len != 0) {
                        self.state = .rhs;
                        return finishTarget(must_resolve, bytes);
                    }
                    // silently ignore null target
                    self.state = .lhs;
                },
            },
            .target_colon_reverse_solidus => switch (char) {
                '\n', '\r' => {
                    const bytes = self.bytes[start .. self.index - 2];
                    if (bytes.len != 0) {
                        self.state = .lhs;
                        return finishTarget(must_resolve, bytes);
                    }
                    // silently ignore null target
                    self.state = .lhs;
                },
                else => {
                    self.state = .target;
                },
            },
            .target_space => switch (char) {
                '\t', ' ' => {
                    // silently ignore additional horizontal whitespace
                    self.index += 1;
                },
                ':' => {
                    self.state = .rhs;
                    self.index += 1;
                },
                else => {
                    return errorIllegalChar(.expected_colon, self.index, char);
                },
            },
            .rhs => switch (char) {
                '\t', ' ' => {
                    // silently ignore horizontal whitespace
                    self.index += 1;
                },
                '\n', '\r' => {
                    self.state = .lhs;
                },
                '\\' => {
                    self.state = .rhs_continuation;
                    self.index += 1;
                },
                '"' => {
                    self.state = .prereq_quote;
                    self.index += 1;
                    start = self.index;
                },
                else => {
                    start = self.index;
                    self.state = .prereq;
                },
            },
            .rhs_continuation => switch (char) {
                '\n' => {
                    self.state = .rhs;
                    self.index += 1;
                },
                '\r' => {
                    self.state = .rhs_continuation_linefeed;
                    self.index += 1;
                },
                else => {
                    return errorIllegalChar(.continuation_eol, self.index, char);
                },
            },
            .rhs_continuation_linefeed => switch (char) {
                '\n' => {
                    self.state = .rhs;
                    self.index += 1;
                },
                else => {
                    return errorIllegalChar(.continuation_eol, self.index, char);
                },
            },
            .prereq_quote => switch (char) {
                '"' => {
                    self.index += 1;
                    self.state = .rhs;
                    return finishPrereq(must_resolve, self.bytes[start .. self.index - 1]);
                },
                else => {
                    self.index += 1;
                },
            },
            .prereq => switch (char) {
                '\t', ' ' => {
                    self.state = .rhs;
                    return finishPrereq(must_resolve, self.bytes[start..self.index]);
                },
                '\n', '\r' => {
                    self.state = .lhs;
                    return finishPrereq(must_resolve, self.bytes[start..self.index]);
                },
                '\\' => {
                    self.state = .prereq_continuation;
                    self.index += 1;
                },
                else => {
                    self.index += 1;
                },
            },
            .prereq_continuation => switch (char) {
                '\n' => {
                    self.index += 1;
                    self.state = .rhs;
                    return finishPrereq(must_resolve, self.bytes[start .. self.index - 2]);
                },
                '\r' => {
                    self.state = .prereq_continuation_linefeed;
                    self.index += 1;
                },
                '\\' => {
                    // The previous \ wasn't a continuation, but this one might be.
                    self.index += 1;
                },
                ' ' => {
                    // not continuation, but escaped space must be resolved
                    must_resolve = true;
                    self.state = .prereq;
                    self.index += 1;
                },
                else => {
                    // not continuation
                    self.state = .prereq;
                    self.index += 1;
                },
            },
            .prereq_continuation_linefeed => switch (char) {
                '\n' => {
                    self.index += 1;
                    self.state = .rhs;
                    return finishPrereq(must_resolve, self.bytes[start .. self.index - 3]);
                },
                else => {
                    return errorIllegalChar(.continuation_eol, self.index, char);
                },
            },
        }
    } else {
        switch (self.state) {
            .lhs,
            .rhs,
            .rhs_continuation,
            .rhs_continuation_linefeed,
            => return null,
            .target => {
                return errorPosition(.incomplete_target, start, self.bytes[start..]);
            },
            .target_reverse_solidus,
            .target_dollar_sign,
            => {
                const idx = self.index - 1;
                return errorIllegalChar(.incomplete_escape, idx, self.bytes[idx]);
            },
            .target_colon => {
                const bytes = self.bytes[start .. self.index - 1];
                if (bytes.len != 0) {
                    self.index += 1;
                    self.state = .rhs;
                    return finishTarget(must_resolve, bytes);
                }
                // silently ignore null target
                self.state = .lhs;
                return null;
            },
            .target_colon_reverse_solidus => {
                const bytes = self.bytes[start .. self.index - 2];
                if (bytes.len != 0) {
                    self.index += 1;
                    self.state = .rhs;
                    return finishTarget(must_resolve, bytes);
                }
                // silently ignore null target
                self.state = .lhs;
                return null;
            },
            .target_space => {
                const idx = self.index - 1;
                return errorIllegalChar(.expected_colon, idx, self.bytes[idx]);
            },
            .prereq_quote => {
                return errorPosition(.incomplete_quoted_prerequisite, start, self.bytes[start..]);
            },
            .prereq => {
                self.state = .lhs;
                return finishPrereq(must_resolve, self.bytes[start..]);
            },
            .prereq_continuation => {
                self.state = .lhs;
                return finishPrereq(must_resolve, self.bytes[start .. self.index - 1]);
            },
            .prereq_continuation_linefeed => {
                self.state = .lhs;
                return finishPrereq(must_resolve, self.bytes[start .. self.index - 2]);
            },
        }
    }
    unreachable;
}

fn errorPosition(comptime id: std.meta.Tag(Token), index: usize, bytes: []const u8) Token {
    return @unionInit(Token, @tagName(id), .{ .index = index, .bytes = bytes });
}

fn errorIllegalChar(comptime id: std.meta.Tag(Token), index: usize, char: u8) Token {
    return @unionInit(Token, @tagName(id), .{ .index = index, .char = char });
}

fn finishTarget(must_resolve: bool, bytes: []const u8) Token {
    return if (must_resolve) .{ .target_must_resolve = bytes } else .{ .target = bytes };
}

fn finishPrereq(must_resolve: bool, bytes: []const u8) Token {
    return if (must_resolve) .{ .prereq_must_resolve = bytes } else .{ .prereq = bytes };
}

const State = enum {
    lhs,
    target,
    target_reverse_solidus,
    target_dollar_sign,
    target_colon,
    target_colon_reverse_solidus,
    target_space,
    rhs,
    rhs_continuation,
    rhs_continuation_linefeed,
    prereq_quote,
    prereq,
    prereq_continuation,
    prereq_continuation_linefeed,
};

pub const Token = union(enum) {
    target: []const u8,
    target_must_resolve: []const u8,
    prereq: []const u8,
    prereq_must_resolve: []const u8,

    incomplete_quoted_prerequisite: IndexAndBytes,
    incomplete_target: IndexAndBytes,

    invalid_target: IndexAndChar,
    bad_target_escape: IndexAndChar,
    expected_dollar_sign: IndexAndChar,
    continuation_eol: IndexAndChar,
    incomplete_escape: IndexAndChar,
    expected_colon: IndexAndChar,

    pub const IndexAndChar = struct {
        index: usize,
        char: u8,
    };

    pub const IndexAndBytes = struct {
        index: usize,
        bytes: []const u8,
    };

    /// Resolve escapes in target or prereq. Only valid with .target_must_resolve or .prereq_must_resolve.
    pub fn resolve(self: Token, writer: anytype) @TypeOf(writer).Error!void {
        switch (self) {
            .target_must_resolve => |bytes| {
                var state: enum { start, escape, dollar } = .start;
                for (bytes) |c| {
                    switch (state) {
                        .start => {
                            switch (c) {
                                '\\' => state = .escape,
                                '$' => state = .dollar,
                                else => try writer.writeByte(c),
                            }
                        },
                        .escape => {
                            switch (c) {
                                ' ', '#', '\\' => {},
                                '$' => {
                                    try writer.writeByte('\\');
                                    state = .dollar;
                                    continue;
                                },
                                else => try writer.writeByte('\\'),
                            }
                            try writer.writeByte(c);
                            state = .start;
                        },
                        .dollar => {
                            try writer.writeByte('$');
                            switch (c) {
                                '$' => {},
                                else => try writer.writeByte(c),
                            }
                            state = .start;
                        },
                    }
                }
            },
            .prereq_must_resolve => |bytes| {
                var state: enum { start, escape } = .start;
                for (bytes) |c| {
                    switch (state) {
                        .start => {
                            switch (c) {
                                '\\' => state = .escape,
                                else => try writer.writeByte(c),
                            }
                        },
                        .escape => {
                            switch (c) {
                                ' ' => {},
                                '\\' => {
                                    try writer.writeByte(c);
                                    continue;
                                },
                                else => try writer.writeByte('\\'),
                            }
                            try writer.writeByte(c);
                            state = .start;
                        },
                    }
                }
            },
            else => unreachable,
        }
    }

    pub fn printError(self: Token, writer: anytype) @TypeOf(writer).Error!void {
        switch (self) {
            .target, .target_must_resolve, .prereq, .prereq_must_resolve => unreachable, // not an error
            .incomplete_quoted_prerequisite,
            .incomplete_target,
            => |index_and_bytes| {
                try writer.print("{s} '", .{self.errStr()});
                if (self == .incomplete_target) {
                    const tmp = Token{ .target_must_resolve = index_and_bytes.bytes };
                    try tmp.resolve(writer);
                } else {
                    try printCharValues(writer, index_and_bytes.bytes);
                }
                try writer.print("' at position {d}", .{index_and_bytes.index});
            },
            .invalid_target,
            .bad_target_escape,
            .expected_dollar_sign,
            .continuation_eol,
            .incomplete_escape,
            .expected_colon,
            => |index_and_char| {
                try writer.writeAll("illegal char ");
                try printUnderstandableChar(writer, index_and_char.char);
                try writer.print(" at position {d}: {s}", .{ index_and_char.index, self.errStr() });
            },
        }
    }

    fn errStr(self: Token) []const u8 {
        return switch (self) {
            .target, .target_must_resolve, .prereq, .prereq_must_resolve => unreachable, // not an error
            .incomplete_quoted_prerequisite => "incomplete quoted prerequisite",
            .incomplete_target => "incomplete target",
            .invalid_target => "invalid target",
            .bad_target_escape => "bad target escape",
            .expected_dollar_sign => "expecting '$'",
            .continuation_eol => "continuation expecting end-of-line",
            .incomplete_escape => "incomplete escape",
            .expected_colon => "expecting ':'",
        };
    }
};

test "empty file" {
    try depTokenizer("", "");
}

test "empty whitespace" {
    try depTokenizer("\n", "");
    try depTokenizer("\r", "");
    try depTokenizer("\r\n", "");
    try depTokenizer(" ", "");
}

test "empty colon" {
    try depTokenizer(":", "");
    try depTokenizer("\n:", "");
    try depTokenizer("\r:", "");
    try depTokenizer("\r\n:", "");
    try depTokenizer(" :", "");
}

test "empty target" {
    try depTokenizer("foo.o:", "target = {foo.o}");
    try depTokenizer(
        \\foo.o:
        \\bar.o:
        \\abcd.o:
    ,
        \\target = {foo.o}
        \\target = {bar.o}
        \\target = {abcd.o}
    );
}

test "whitespace empty target" {
    try depTokenizer("\nfoo.o:", "target = {foo.o}");
    try depTokenizer("\rfoo.o:", "target = {foo.o}");
    try depTokenizer("\r\nfoo.o:", "target = {foo.o}");
    try depTokenizer(" foo.o:", "target = {foo.o}");
}

test "escape empty target" {
    try depTokenizer("\\ foo.o:", "target = { foo.o}");
    try depTokenizer("\\#foo.o:", "target = {#foo.o}");
    try depTokenizer("\\\\foo.o:", "target = {\\foo.o}");
    try depTokenizer("$$foo.o:", "target = {$foo.o}");
}

test "empty target linefeeds" {
    try depTokenizer("\n", "");
    try depTokenizer("\r\n", "");

    const expect = "target = {foo.o}";
    try depTokenizer(
        \\foo.o:
    , expect);
    try depTokenizer(
        \\foo.o:
        \\
    , expect);
    try depTokenizer(
        \\foo.o:
    , expect);
    try depTokenizer(
        \\foo.o:
        \\
    , expect);
}

test "empty target linefeeds + continuations" {
    const expect = "target = {foo.o}";
    try depTokenizer(
        \\foo.o:\
    , expect);
    try depTokenizer(
        \\foo.o:\
        \\
    , expect);
    try depTokenizer(
        \\foo.o:\
    , expect);
    try depTokenizer(
        \\foo.o:\
        \\
    , expect);
}

test "empty target linefeeds + hspace + continuations" {
    const expect = "target = {foo.o}";
    try depTokenizer(
        \\foo.o: \
    , expect);
    try depTokenizer(
        \\foo.o: \
        \\
    , expect);
    try depTokenizer(
        \\foo.o: \
    , expect);
    try depTokenizer(
        \\foo.o: \
        \\
    , expect);
}

test "empty target + hspace + colon" {
    const expect = "target = {foo.o}";

    try depTokenizer("foo.o :", expect);
    try depTokenizer("foo.o\t\t\t:", expect);
    try depTokenizer("foo.o \t \t :", expect);
    try depTokenizer("\r\nfoo.o :", expect);
    try depTokenizer(" foo.o :", expect);
}

test "prereq" {
    const expect =
        \\target = {foo.o}
        \\prereq = {foo.c}
    ;
    try depTokenizer("foo.o: foo.c", expect);
    try depTokenizer(
        \\foo.o: \
        \\foo.c
    , expect);
    try depTokenizer(
        \\foo.o: \
        \\ foo.c
    , expect);
    try depTokenizer(
        \\foo.o:    \
        \\    foo.c
    , expect);
}

test "prereq continuation" {
    const expect =
        \\target = {foo.o}
        \\prereq = {foo.h}
        \\prereq = {bar.h}
    ;
    try depTokenizer(
        \\foo.o: foo.h\
        \\bar.h
    , expect);
    try depTokenizer(
        \\foo.o: foo.h\
        \\bar.h
    , expect);
}

test "prereq continuation (CRLF)" {
    const expect =
        \\target = {foo.o}
        \\prereq = {foo.h}
        \\prereq = {bar.h}
    ;
    try depTokenizer("foo.o: foo.h\\\r\nbar.h", expect);
}

test "multiple prereqs" {
    const expect =
        \\target = {foo.o}
        \\prereq = {foo.c}
        \\prereq = {foo.h}
        \\prereq = {bar.h}
    ;
    try depTokenizer("foo.o: foo.c foo.h bar.h", expect);
    try depTokenizer(
        \\foo.o: \
        \\foo.c foo.h bar.h
    , expect);
    try depTokenizer(
        \\foo.o: foo.c foo.h bar.h\
    , expect);
    try depTokenizer(
        \\foo.o: foo.c foo.h bar.h\
        \\
    , expect);
    try depTokenizer(
        \\foo.o: \
        \\foo.c       \
        \\     foo.h\
        \\bar.h
        \\
    , expect);
    try depTokenizer(
        \\foo.o: \
        \\foo.c       \
        \\     foo.h\
        \\bar.h\
        \\
    , expect);
    try depTokenizer(
        \\foo.o: \
        \\foo.c       \
        \\     foo.h\
        \\bar.h\
    , expect);
}

test "multiple targets and prereqs" {
    try depTokenizer(
        \\foo.o: foo.c
        \\bar.o: bar.c a.h b.h c.h
        \\abc.o: abc.c \
        \\  one.h two.h \
        \\  three.h four.h
    ,
        \\target = {foo.o}
        \\prereq = {foo.c}
        \\target = {bar.o}
        \\prereq = {bar.c}
        \\prereq = {a.h}
        \\prereq = {b.h}
        \\prereq = {c.h}
        \\target = {abc.o}
        \\prereq = {abc.c}
        \\prereq = {one.h}
        \\prereq = {two.h}
        \\prereq = {three.h}
        \\prereq = {four.h}
    );
    try depTokenizer(
        \\ascii.o: ascii.c
        \\base64.o: base64.c stdio.h
        \\elf.o: elf.c a.h b.h c.h
        \\macho.o: \
        \\  macho.c\
        \\  a.h b.h c.h
    ,
        \\target = {ascii.o}
        \\prereq = {ascii.c}
        \\target = {base64.o}
        \\prereq = {base64.c}
        \\prereq = {stdio.h}
        \\target = {elf.o}
        \\prereq = {elf.c}
        \\prereq = {a.h}
        \\prereq = {b.h}
        \\prereq = {c.h}
        \\target = {macho.o}
        \\prereq = {macho.c}
        \\prereq = {a.h}
        \\prereq = {b.h}
        \\prereq = {c.h}
    );
    try depTokenizer(
        \\a$$scii.o: ascii.c
        \\\\base64.o: "\base64.c" "s t#dio.h"
        \\e\\lf.o: "e\lf.c" "a.h$$" "$$b.h c.h$$"
        \\macho.o: \
        \\  "macho!.c" \
        \\  a.h b.h c.h
    ,
        \\target = {a$scii.o}
        \\prereq = {ascii.c}
        \\target = {\base64.o}
        \\prereq = {\base64.c}
        \\prereq = {s t#dio.h}
        \\target = {e\lf.o}
        \\prereq = {e\lf.c}
        \\prereq = {a.h$$}
        \\prereq = {$$b.h c.h$$}
        \\target = {macho.o}
        \\prereq = {macho!.c}
        \\prereq = {a.h}
        \\prereq = {b.h}
        \\prereq = {c.h}
    );
}

test "windows quoted prereqs" {
    try depTokenizer(
        \\c:\foo.o: "C:\Program Files (x86)\Microsoft Visual Studio\foo.c"
        \\c:\foo2.o: "C:\Program Files (x86)\Microsoft Visual Studio\foo2.c" \
        \\  "C:\Program Files (x86)\Microsoft Visual Studio\foo1.h" \
        \\  "C:\Program Files (x86)\Microsoft Visual Studio\foo2.h"
    ,
        \\target = {c:\foo.o}
        \\prereq = {C:\Program Files (x86)\Microsoft Visual Studio\foo.c}
        \\target = {c:\foo2.o}
        \\prereq = {C:\Program Files (x86)\Microsoft Visual Studio\foo2.c}
        \\prereq = {C:\Program Files (x86)\Microsoft Visual Studio\foo1.h}
        \\prereq = {C:\Program Files (x86)\Microsoft Visual Studio\foo2.h}
    );
}

test "windows mixed prereqs" {
    try depTokenizer(
        \\cimport.o: \
        \\  C:\msys64\home\anon\project\zig\master\zig-cache\o\qhvhbUo7GU5iKyQ5mpA8TcQpncCYaQu0wwvr3ybiSTj_Dtqi1Nmcb70kfODJ2Qlg\cimport.h \
        \\  "C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\stdio.h" \
        \\  "C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt.h" \
        \\  "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.21.27702\lib\x64\\..\..\include\vcruntime.h" \
        \\  "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.21.27702\lib\x64\\..\..\include\sal.h" \
        \\  "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.21.27702\lib\x64\\..\..\include\concurrencysal.h" \
        \\  C:\msys64\opt\zig\lib\zig\include\vadefs.h \
        \\  "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.21.27702\lib\x64\\..\..\include\vadefs.h" \
        \\  "C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt_wstdio.h" \
        \\  "C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt_stdio_config.h" \
        \\  "C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\string.h" \
        \\  "C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt_memory.h" \
        \\  "C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt_memcpy_s.h" \
        \\  "C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\errno.h" \
        \\  "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.21.27702\lib\x64\\..\..\include\vcruntime_string.h" \
        \\  "C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt_wstring.h"
    ,
        \\target = {cimport.o}
        \\prereq = {C:\msys64\home\anon\project\zig\master\zig-cache\o\qhvhbUo7GU5iKyQ5mpA8TcQpncCYaQu0wwvr3ybiSTj_Dtqi1Nmcb70kfODJ2Qlg\cimport.h}
        \\prereq = {C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\stdio.h}
        \\prereq = {C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt.h}
        \\prereq = {C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.21.27702\lib\x64\\..\..\include\vcruntime.h}
        \\prereq = {C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.21.27702\lib\x64\\..\..\include\sal.h}
        \\prereq = {C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.21.27702\lib\x64\\..\..\include\concurrencysal.h}
        \\prereq = {C:\msys64\opt\zig\lib\zig\include\vadefs.h}
        \\prereq = {C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.21.27702\lib\x64\\..\..\include\vadefs.h}
        \\prereq = {C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt_wstdio.h}
        \\prereq = {C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt_stdio_config.h}
        \\prereq = {C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\string.h}
        \\prereq = {C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt_memory.h}
        \\prereq = {C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt_memcpy_s.h}
        \\prereq = {C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\errno.h}
        \\prereq = {C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Tools\MSVC\14.21.27702\lib\x64\\..\..\include\vcruntime_string.h}
        \\prereq = {C:\Program Files (x86)\Windows Kits\10\\Include\10.0.17763.0\ucrt\corecrt_wstring.h}
    );
}

test "windows funky targets" {
    try depTokenizer(
        \\C:\Users\anon\foo.o:
        \\C:\Users\anon\foo\ .o:
        \\C:\Users\anon\foo\#.o:
        \\C:\Users\anon\foo$$.o:
        \\C:\Users\anon\\\ foo.o:
        \\C:\Users\anon\\#foo.o:
        \\C:\Users\anon\$$foo.o:
        \\C:\Users\anon\\\ \ \ \ \ foo.o:
    ,
        \\target = {C:\Users\anon\foo.o}
        \\target = {C:\Users\anon\foo .o}
        \\target = {C:\Users\anon\foo#.o}
        \\target = {C:\Users\anon\foo$.o}
        \\target = {C:\Users\anon\ foo.o}
        \\target = {C:\Users\anon\#foo.o}
        \\target = {C:\Users\anon\$foo.o}
        \\target = {C:\Users\anon\     foo.o}
    );
}

test "windows funky prereqs" {
    // Note we don't support unquoted escaped spaces at the very beginning of a relative path
    // e.g. `\ SpaceAtTheBeginning.c`
    // This typically wouldn't be seen in the wild, since depfiles usually use absolute paths
    // and supporting it would degrade error messages for cases where it was meant to be a
    // continuation, but the line ending is missing.
    try depTokenizer(
        \\cimport.o: \
        \\  trailingbackslash\\
        \\  C:\Users\John\ Smith\AppData\Local\zig\p\1220d14057af1a9d6dde4643293527bd5ee5099517d655251a066666a4320737ea7c\cimport.c \
        \\  somedir\\ a.c\
        \\  somedir/\ a.c\
        \\  somedir\\ \ \ b.c\
        \\  somedir\\ \\ \c.c\
        \\
    ,
        \\target = {cimport.o}
        \\prereq = {trailingbackslash\}
        \\prereq = {C:\Users\John Smith\AppData\Local\zig\p\1220d14057af1a9d6dde4643293527bd5ee5099517d655251a066666a4320737ea7c\cimport.c}
        \\prereq = {somedir\ a.c}
        \\prereq = {somedir/ a.c}
        \\prereq = {somedir\   b.c}
        \\prereq = {somedir\ \ \c.c}
    );
}

test "windows drive and forward slashes" {
    try depTokenizer(
        \\C:/msys64/what/zig-cache\tmp\48ac4d78dd531abd-cxa_thread_atexit.obj: \
        \\  C:/msys64/opt/zig3/lib/zig/libc/mingw/crt/cxa_thread_atexit.c
    ,
        \\target = {C:/msys64/what/zig-cache\tmp\48ac4d78dd531abd-cxa_thread_atexit.obj}
        \\prereq = {C:/msys64/opt/zig3/lib/zig/libc/mingw/crt/cxa_thread_atexit.c}
    );
}

test "error incomplete escape - reverse_solidus" {
    try depTokenizer("\\",
        \\ERROR: illegal char '\' at position 0: incomplete escape
    );
    try depTokenizer("\t\\",
        \\ERROR: illegal char '\' at position 1: incomplete escape
    );
    try depTokenizer("\n\\",
        \\ERROR: illegal char '\' at position 1: incomplete escape
    );
    try depTokenizer("\r\\",
        \\ERROR: illegal char '\' at position 1: incomplete escape
    );
    try depTokenizer("\r\n\\",
        \\ERROR: illegal char '\' at position 2: incomplete escape
    );
    try depTokenizer(" \\",
        \\ERROR: illegal char '\' at position 1: incomplete escape
    );
}

test "error incomplete escape - dollar_sign" {
    try depTokenizer("$",
        \\ERROR: illegal char '$' at position 0: incomplete escape
    );
    try depTokenizer("\t$",
        \\ERROR: illegal char '$' at position 1: incomplete escape
    );
    try depTokenizer("\n$",
        \\ERROR: illegal char '$' at position 1: incomplete escape
    );
    try depTokenizer("\r$",
        \\ERROR: illegal char '$' at position 1: incomplete escape
    );
    try depTokenizer("\r\n$",
        \\ERROR: illegal char '$' at position 2: incomplete escape
    );
    try depTokenizer(" $",
        \\ERROR: illegal char '$' at position 1: incomplete escape
    );
}

test "error incomplete target" {
    try depTokenizer("foo.o",
        \\ERROR: incomplete target 'foo.o' at position 0
    );
    try depTokenizer("\tfoo.o",
        \\ERROR: incomplete target 'foo.o' at position 1
    );
    try depTokenizer("\nfoo.o",
        \\ERROR: incomplete target 'foo.o' at position 1
    );
    try depTokenizer("\rfoo.o",
        \\ERROR: incomplete target 'foo.o' at position 1
    );
    try depTokenizer("\r\nfoo.o",
        \\ERROR: incomplete target 'foo.o' at position 2
    );
    try depTokenizer(" foo.o",
        \\ERROR: incomplete target 'foo.o' at position 1
    );

    try depTokenizer("\\ foo.o",
        \\ERROR: incomplete target ' foo.o' at position 0
    );
    try depTokenizer("\\#foo.o",
        \\ERROR: incomplete target '#foo.o' at position 0
    );
    try depTokenizer("\\\\foo.o",
        \\ERROR: incomplete target '\foo.o' at position 0
    );
    try depTokenizer("$$foo.o",
        \\ERROR: incomplete target '$foo.o' at position 0
    );
}

test "error illegal char at position - bad target escape" {
    try depTokenizer("\\\t",
        \\ERROR: illegal char \x09 at position 1: bad target escape
    );
    try depTokenizer("\\\n",
        \\ERROR: illegal char \x0A at position 1: bad target escape
    );
    try depTokenizer("\\\r",
        \\ERROR: illegal char \x0D at position 1: bad target escape
    );
    try depTokenizer("\\\r\n",
        \\ERROR: illegal char \x0D at position 1: bad target escape
    );
}

test "error illegal char at position - expecting dollar_sign" {
    try depTokenizer("$\t",
        \\ERROR: illegal char \x09 at position 1: expecting '$'
    );
    try depTokenizer("$\n",
        \\ERROR: illegal char \x0A at position 1: expecting '$'
    );
    try depTokenizer("$\r",
        \\ERROR: illegal char \x0D at position 1: expecting '$'
    );
    try depTokenizer("$\r\n",
        \\ERROR: illegal char \x0D at position 1: expecting '$'
    );
}

test "error illegal char at position - invalid target" {
    try depTokenizer("foo\n.o",
        \\ERROR: illegal char \x0A at position 3: invalid target
    );
    try depTokenizer("foo\r.o",
        \\ERROR: illegal char \x0D at position 3: invalid target
    );
    try depTokenizer("foo\r\n.o",
        \\ERROR: illegal char \x0D at position 3: invalid target
    );
}

test "error target - continuation expecting end-of-line" {
    try depTokenizer("foo.o: \\\t",
        \\target = {foo.o}
        \\ERROR: illegal char \x09 at position 8: continuation expecting end-of-line
    );
    try depTokenizer("foo.o: \\ ",
        \\target = {foo.o}
        \\ERROR: illegal char ' ' at position 8: continuation expecting end-of-line
    );
    try depTokenizer("foo.o: \\x",
        \\target = {foo.o}
        \\ERROR: illegal char 'x' at position 8: continuation expecting end-of-line
    );
    try depTokenizer("foo.o: \\\x0dx",
        \\target = {foo.o}
        \\ERROR: illegal char 'x' at position 9: continuation expecting end-of-line
    );
}

test "error prereq - continuation expecting end-of-line" {
    try depTokenizer("foo.o: foo.h\\\x0dx",
        \\target = {foo.o}
        \\ERROR: illegal char 'x' at position 14: continuation expecting end-of-line
    );
}

test "error illegal char at position - expecting colon" {
    try depTokenizer("foo\t.o:",
        \\target = {foo}
        \\ERROR: illegal char '.' at position 4: expecting ':'
    );
    try depTokenizer("foo .o:",
        \\target = {foo}
        \\ERROR: illegal char '.' at position 4: expecting ':'
    );
    try depTokenizer("foo \n.o:",
        \\target = {foo}
        \\ERROR: illegal char \x0A at position 4: expecting ':'
    );
    try depTokenizer("foo.o\t\n:",
        \\target = {foo.o}
        \\ERROR: illegal char \x0A at position 6: expecting ':'
    );
}

// - tokenize input, emit textual representation, and compare to expect
fn depTokenizer(input: []const u8, expect: []const u8) !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.testing.allocator);
    const arena = arena_allocator.allocator();
    defer arena_allocator.deinit();

    var it: Tokenizer = .{ .bytes = input };
    var buffer = std.ArrayList(u8).init(arena);
    var resolve_buf = std.ArrayList(u8).init(arena);
    var i: usize = 0;
    while (it.next()) |token| {
        if (i != 0) try buffer.appendSlice("\n");
        switch (token) {
            .target, .prereq => |bytes| {
                try buffer.appendSlice(@tagName(token));
                try buffer.appendSlice(" = {");
                for (bytes) |b| {
                    try buffer.append(printable_char_tab[b]);
                }
                try buffer.appendSlice("}");
            },
            .target_must_resolve => {
                try buffer.appendSlice("target = {");
                try token.resolve(resolve_buf.writer());
                for (resolve_buf.items) |b| {
                    try buffer.append(printable_char_tab[b]);
                }
                resolve_buf.items.len = 0;
                try buffer.appendSlice("}");
            },
            .prereq_must_resolve => {
                try buffer.appendSlice("prereq = {");
                try token.resolve(resolve_buf.writer());
                for (resolve_buf.items) |b| {
                    try buffer.append(printable_char_tab[b]);
                }
                resolve_buf.items.len = 0;
                try buffer.appendSlice("}");
            },
            else => {
                try buffer.appendSlice("ERROR: ");
                try token.printError(buffer.writer());
                break;
            },
        }
        i += 1;
    }

    if (std.mem.eql(u8, expect, buffer.items)) {
        try testing.expect(true);
        return;
    }

    const out = std.io.getStdErr().writer();

    try out.writeAll("\n");
    try printSection(out, "<<<< input", input);
    try printSection(out, "==== expect", expect);
    try printSection(out, ">>>> got", buffer.items);
    try printRuler(out);

    try testing.expect(false);
}

fn printSection(out: anytype, label: []const u8, bytes: []const u8) !void {
    try printLabel(out, label, bytes);
    try hexDump(out, bytes);
    try printRuler(out);
    try out.writeAll(bytes);
    try out.writeAll("\n");
}

fn printLabel(out: anytype, label: []const u8, bytes: []const u8) !void {
    var buf: [80]u8 = undefined;
    const text = try std.fmt.bufPrint(buf[0..], "{s} {d} bytes ", .{ label, bytes.len });
    try out.writeAll(text);
    var i: usize = text.len;
    const end = 79;
    while (i < end) : (i += 1) {
        try out.writeAll(&[_]u8{label[0]});
    }
    try out.writeAll("\n");
}

fn printRuler(out: anytype) !void {
    var i: usize = 0;
    const end = 79;
    while (i < end) : (i += 1) {
        try out.writeAll("-");
    }
    try out.writeAll("\n");
}

fn hexDump(out: anytype, bytes: []const u8) !void {
    const n16 = bytes.len >> 4;
    var line: usize = 0;
    var offset: usize = 0;
    while (line < n16) : (line += 1) {
        try hexDump16(out, offset, bytes[offset..][0..16]);
        offset += 16;
    }

    const n = bytes.len & 0x0f;
    if (n > 0) {
        try printDecValue(out, offset, 8);
        try out.writeAll(":");
        try out.writeAll(" ");
        const end1 = @min(offset + n, offset + 8);
        for (bytes[offset..end1]) |b| {
            try out.writeAll(" ");
            try printHexValue(out, b, 2);
        }
        const end2 = offset + n;
        if (end2 > end1) {
            try out.writeAll(" ");
            for (bytes[end1..end2]) |b| {
                try out.writeAll(" ");
                try printHexValue(out, b, 2);
            }
        }
        const short = 16 - n;
        var i: usize = 0;
        while (i < short) : (i += 1) {
            try out.writeAll("   ");
        }
        if (end2 > end1) {
            try out.writeAll("  |");
        } else {
            try out.writeAll("   |");
        }
        try printCharValues(out, bytes[offset..end2]);
        try out.writeAll("|\n");
        offset += n;
    }

    try printDecValue(out, offset, 8);
    try out.writeAll(":");
    try out.writeAll("\n");
}

fn hexDump16(out: anytype, offset: usize, bytes: []const u8) !void {
    try printDecValue(out, offset, 8);
    try out.writeAll(":");
    try out.writeAll(" ");
    for (bytes[0..8]) |b| {
        try out.writeAll(" ");
        try printHexValue(out, b, 2);
    }
    try out.writeAll(" ");
    for (bytes[8..16]) |b| {
        try out.writeAll(" ");
        try printHexValue(out, b, 2);
    }
    try out.writeAll("  |");
    try printCharValues(out, bytes);
    try out.writeAll("|\n");
}

fn printDecValue(out: anytype, value: u64, width: u8) !void {
    var buffer: [20]u8 = undefined;
    const len = std.fmt.formatIntBuf(buffer[0..], value, 10, .lower, .{ .width = width, .fill = '0' });
    try out.writeAll(buffer[0..len]);
}

fn printHexValue(out: anytype, value: u64, width: u8) !void {
    var buffer: [16]u8 = undefined;
    const len = std.fmt.formatIntBuf(buffer[0..], value, 16, .lower, .{ .width = width, .fill = '0' });
    try out.writeAll(buffer[0..len]);
}

fn printCharValues(out: anytype, bytes: []const u8) !void {
    for (bytes) |b| {
        try out.writeAll(&[_]u8{printable_char_tab[b]});
    }
}

fn printUnderstandableChar(out: anytype, char: u8) !void {
    if (std.ascii.isPrint(char)) {
        try out.print("'{c}'", .{char});
    } else {
        try out.print("\\x{X:0>2}", .{char});
    }
}

// zig fmt: off
const printable_char_tab: [256]u8 = (
    "................................ !\"#$%&'()*+,-./0123456789:;<=>?" ++
    "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~." ++
    "................................................................" ++
    "................................................................"
).*;
const Directory = @This();
const std = @import("../../std.zig");
const fs = std.fs;
const fmt = std.fmt;
const Allocator = std.mem.Allocator;

/// This field is redundant for operations that can act on the open directory handle
/// directly, but it is needed when passing the directory to a child process.
/// `null` means cwd.
path: ?[]const u8,
handle: fs.Dir,

pub fn clone(d: Directory, arena: Allocator) Allocator.Error!Directory {
    return .{
        .path = if (d.path) |p| try arena.dupe(u8, p) else null,
        .handle = d.handle,
    };
}

pub fn cwd() Directory {
    return .{
        .path = null,
        .handle = fs.cwd(),
    };
}

pub fn join(self: Directory, allocator: Allocator, paths: []const []const u8) ![]u8 {
    if (self.path) |p| {
        // TODO clean way to do this with only 1 allocation
        const part2 = try fs.path.join(allocator, paths);
        defer allocator.free(part2);
        return fs.path.join(allocator, &[_][]const u8{ p, part2 });
    } else {
        return fs.path.join(allocator, paths);
    }
}

pub fn joinZ(self: Directory, allocator: Allocator, paths: []const []const u8) ![:0]u8 {
    if (self.path) |p| {
        // TODO clean way to do this with only 1 allocation
        const part2 = try fs.path.join(allocator, paths);
        defer allocator.free(part2);
        return fs.path.joinZ(allocator, &[_][]const u8{ p, part2 });
    } else {
        return fs.path.joinZ(allocator, paths);
    }
}

/// Whether or not the handle should be closed, or the path should be freed
/// is determined by usage, however this function is provided for convenience
/// if it happens to be what the caller needs.
pub fn closeAndFree(self: *Directory, gpa: Allocator) void {
    self.handle.close();
    if (self.path) |p| gpa.free(p);
    self.* = undefined;
}

pub fn format(
    self: Directory,
    comptime fmt_string: []const u8,
    options: fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    if (fmt_string.len != 0) fmt.invalidFmtError(fmt_string, self);
    if (self.path) |p| {
        try writer.writeAll(p);
        try writer.writeAll(fs.path.sep_str);
    }
}

pub fn eql(self: Directory, other: Directory) bool {
    return self.handle.fd == other.handle.fd;
}
root_dir: Cache.Directory,
/// The path, relative to the root dir, that this `Path` represents.
/// Empty string means the root_dir is the path.
sub_path: []const u8 = "",

pub fn clone(p: Path, arena: Allocator) Allocator.Error!Path {
    return .{
        .root_dir = try p.root_dir.clone(arena),
        .sub_path = try arena.dupe(u8, p.sub_path),
    };
}

pub fn cwd() Path {
    return initCwd("");
}

pub fn initCwd(sub_path: []const u8) Path {
    return .{ .root_dir = Cache.Directory.cwd(), .sub_path = sub_path };
}

pub fn join(p: Path, arena: Allocator, sub_path: []const u8) Allocator.Error!Path {
    if (sub_path.len == 0) return p;
    const parts: []const []const u8 =
        if (p.sub_path.len == 0) &.{sub_path} else &.{ p.sub_path, sub_path };
    return .{
        .root_dir = p.root_dir,
        .sub_path = try fs.path.join(arena, parts),
    };
}

pub fn resolvePosix(p: Path, arena: Allocator, sub_path: []const u8) Allocator.Error!Path {
    if (sub_path.len == 0) return p;
    return .{
        .root_dir = p.root_dir,
        .sub_path = try fs.path.resolvePosix(arena, &.{ p.sub_path, sub_path }),
    };
}

pub fn joinString(p: Path, gpa: Allocator, sub_path: []const u8) Allocator.Error![]u8 {
    const parts: []const []const u8 =
        if (p.sub_path.len == 0) &.{sub_path} else &.{ p.sub_path, sub_path };
    return p.root_dir.join(gpa, parts);
}

pub fn joinStringZ(p: Path, gpa: Allocator, sub_path: []const u8) Allocator.Error![:0]u8 {
    const parts: []const []const u8 =
        if (p.sub_path.len == 0) &.{sub_path} else &.{ p.sub_path, sub_path };
    return p.root_dir.joinZ(gpa, parts);
}

pub fn openFile(
    p: Path,
    sub_path: []const u8,
    flags: fs.File.OpenFlags,
) !fs.File {
    var buf: [fs.max_path_bytes]u8 = undefined;
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.bufPrint(&buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.openFile(joined_path, flags);
}

pub fn openDir(
    p: Path,
    sub_path: []const u8,
    args: fs.Dir.OpenOptions,
) fs.Dir.OpenError!fs.Dir {
    var buf: [fs.max_path_bytes]u8 = undefined;
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.bufPrint(&buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.openDir(joined_path, args);
}

pub fn makeOpenPath(p: Path, sub_path: []const u8, opts: fs.Dir.OpenOptions) !fs.Dir {
    var buf: [fs.max_path_bytes]u8 = undefined;
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.bufPrint(&buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.makeOpenPath(joined_path, opts);
}

pub fn statFile(p: Path, sub_path: []const u8) !fs.Dir.Stat {
    var buf: [fs.max_path_bytes]u8 = undefined;
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.bufPrint(&buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.statFile(joined_path);
}

pub fn atomicFile(
    p: Path,
    sub_path: []const u8,
    options: fs.Dir.AtomicFileOptions,
    buf: *[fs.max_path_bytes]u8,
) !fs.AtomicFile {
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.bufPrint(buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.atomicFile(joined_path, options);
}

pub fn access(p: Path, sub_path: []const u8, flags: fs.File.OpenFlags) !void {
    var buf: [fs.max_path_bytes]u8 = undefined;
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.bufPrint(&buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.access(joined_path, flags);
}

pub fn makePath(p: Path, sub_path: []const u8) !void {
    var buf: [fs.max_path_bytes]u8 = undefined;
    const joined_path = if (p.sub_path.len == 0) sub_path else p: {
        break :p std.fmt.bufPrint(&buf, "{s}" ++ fs.path.sep_str ++ "{s}", .{
            p.sub_path, sub_path,
        }) catch return error.NameTooLong;
    };
    return p.root_dir.handle.makePath(joined_path);
}

pub fn toString(p: Path, allocator: Allocator) Allocator.Error![]u8 {
    return std.fmt.allocPrint(allocator, "{}", .{p});
}

pub fn toStringZ(p: Path, allocator: Allocator) Allocator.Error![:0]u8 {
    return std.fmt.allocPrintZ(allocator, "{}", .{p});
}

pub fn format(
    self: Path,
    comptime fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    if (fmt_string.len == 1) {
        // Quote-escape the string.
        const stringEscape = std.zig.stringEscape;
        const f = switch (fmt_string[0]) {
            'q' => "",
            '\'' => "\'",
            else => @compileError("unsupported format string: " ++ fmt_string),
        };
        if (self.root_dir.path) |p| {
            try stringEscape(p, f, options, writer);
            if (self.sub_path.len > 0) try stringEscape(fs.path.sep_str, f, options, writer);
        }
        if (self.sub_path.len > 0) {
            try stringEscape(self.sub_path, f, options, writer);
        }
        return;
    }
    if (fmt_string.len > 0)
        std.fmt.invalidFmtError(fmt_string, self);
    if (std.fs.path.isAbsolute(self.sub_path)) {
        try writer.writeAll(self.sub_path);
        return;
    }
    if (self.root_dir.path) |p| {
        try writer.writeAll(p);
        if (self.sub_path.len > 0) {
            try writer.writeAll(fs.path.sep_str);
            try writer.writeAll(self.sub_path);
        }
        return;
    }
    if (self.sub_path.len > 0) {
        try writer.writeAll(self.sub_path);
        return;
    }
    try writer.writeByte('.');
}

pub fn eql(self: Path, other: Path) bool {
    return self.root_dir.eql(other.root_dir) and std.mem.eql(u8, self.sub_path, other.sub_path);
}

pub fn subPathOpt(self: Path) ?[]const u8 {
    return if (self.sub_path.len == 0) null else self.sub_path;
}

pub fn subPathOrDot(self: Path) []const u8 {
    return if (self.sub_path.len == 0) "." else self.sub_path;
}

pub fn stem(p: Path) []const u8 {
    return fs.path.stem(p.sub_path);
}

pub fn basename(p: Path) []const u8 {
    return fs.path.basename(p.sub_path);
}

/// Useful to make `Path` a key in `std.ArrayHashMap`.
pub const TableAdapter = struct {
    pub const Hash = std.hash.Wyhash;

    pub fn hash(self: TableAdapter, a: Cache.Path) u32 {
        _ = self;
        const seed = switch (@typeInfo(@TypeOf(a.root_dir.handle.fd))) {
            .pointer => @intFromPtr(a.root_dir.handle.fd),
            .int => @as(u32, @bitCast(a.root_dir.handle.fd)),
            else => @compileError("unimplemented hash function"),
        };
        return @truncate(Hash.hash(seed, a.sub_path));
    }
    pub fn eql(self: TableAdapter, a: Cache.Path, b: Cache.Path, b_index: usize) bool {
        _ = self;
        _ = b_index;
        return a.eql(b);
    }
};

const Path = @This();
const std = @import("../../std.zig");
const fs = std.fs;
const Allocator = std.mem.Allocator;
const Cache = std.Build.Cache;
const builtin = @import("builtin");
const std = @import("../std.zig");
const Build = std.Build;
const Step = std.Build.Step;
const assert = std.debug.assert;
const fatal = std.process.fatal;
const Allocator = std.mem.Allocator;
const log = std.log;

const Fuzz = @This();
const build_runner = @import("root");

pub const WebServer = @import("Fuzz/WebServer.zig");
pub const abi = @import("Fuzz/abi.zig");

pub fn start(
    gpa: Allocator,
    arena: Allocator,
    global_cache_directory: Build.Cache.Directory,
    zig_lib_directory: Build.Cache.Directory,
    zig_exe_path: []const u8,
    thread_pool: *std.Thread.Pool,
    all_steps: []const *Step,
    ttyconf: std.io.tty.Config,
    listen_address: std.net.Address,
    prog_node: std.Progress.Node,
) Allocator.Error!void {
    const fuzz_run_steps = block: {
        const rebuild_node = prog_node.start("Rebuilding Unit Tests", 0);
        defer rebuild_node.end();
        var wait_group: std.Thread.WaitGroup = .{};
        defer wait_group.wait();
        var fuzz_run_steps: std.ArrayListUnmanaged(*Step.Run) = .empty;
        defer fuzz_run_steps.deinit(gpa);
        for (all_steps) |step| {
            const run = step.cast(Step.Run) orelse continue;
            if (run.fuzz_tests.items.len > 0 and run.producer != null) {
                thread_pool.spawnWg(&wait_group, rebuildTestsWorkerRun, .{ run, ttyconf, rebuild_node });
                try fuzz_run_steps.append(gpa, run);
            }
        }
        if (fuzz_run_steps.items.len == 0) fatal("no fuzz tests found", .{});
        rebuild_node.setEstimatedTotalItems(fuzz_run_steps.items.len);
        break :block try arena.dupe(*Step.Run, fuzz_run_steps.items);
    };

    // Detect failure.
    for (fuzz_run_steps) |run| {
        assert(run.fuzz_tests.items.len > 0);
        if (run.rebuilt_executable == null)
            fatal("one or more unit tests failed to be rebuilt in fuzz mode", .{});
    }

    var web_server: WebServer = .{
        .gpa = gpa,
        .global_cache_directory = global_cache_directory,
        .zig_lib_directory = zig_lib_directory,
        .zig_exe_path = zig_exe_path,
        .listen_address = listen_address,
        .fuzz_run_steps = fuzz_run_steps,

        .msg_queue = .{},
        .mutex = .{},
        .condition = .{},

        .coverage_files = .{},
        .coverage_mutex = .{},
        .coverage_condition = .{},

        .base_timestamp = std.time.nanoTimestamp(),
    };

    // For accepting HTTP connections.
    const web_server_thread = std.Thread.spawn(.{}, WebServer.run, .{&web_server}) catch |err| {
        fatal("unable to spawn web server thread: {s}", .{@errorName(err)});
    };
    defer web_server_thread.join();

    // For polling messages and sending updates to subscribers.
    const coverage_thread = std.Thread.spawn(.{}, WebServer.coverageRun, .{&web_server}) catch |err| {
        fatal("unable to spawn coverage thread: {s}", .{@errorName(err)});
    };
    defer coverage_thread.join();

    {
        const fuzz_node = prog_node.start("Fuzzing", fuzz_run_steps.len);
        defer fuzz_node.end();
        var wait_group: std.Thread.WaitGroup = .{};
        defer wait_group.wait();

        for (fuzz_run_steps) |run| {
            for (run.fuzz_tests.items) |unit_test_index| {
                assert(run.rebuilt_executable != null);
                thread_pool.spawnWg(&wait_group, fuzzWorkerRun, .{
                    run, &web_server, unit_test_index, ttyconf, fuzz_node,
                });
            }
        }
    }

    log.err("all fuzz workers crashed", .{});
}

fn rebuildTestsWorkerRun(run: *Step.Run, ttyconf: std.io.tty.Config, parent_prog_node: std.Progress.Node) void {
    rebuildTestsWorkerRunFallible(run, ttyconf, parent_prog_node) catch |err| {
        const compile = run.producer.?;
        log.err("step '{s}': failed to rebuild in fuzz mode: {s}", .{
            compile.step.name, @errorName(err),
        });
    };
}

fn rebuildTestsWorkerRunFallible(run: *Step.Run, ttyconf: std.io.tty.Config, parent_prog_node: std.Progress.Node) !void {
    const gpa = run.step.owner.allocator;
    const stderr = std.io.getStdErr();

    const compile = run.producer.?;
    const prog_node = parent_prog_node.start(compile.step.name, 0);
    defer prog_node.end();

    const result = compile.rebuildInFuzzMode(prog_node);

    const show_compile_errors = compile.step.result_error_bundle.errorMessageCount() > 0;
    const show_error_msgs = compile.step.result_error_msgs.items.len > 0;
    const show_stderr = compile.step.result_stderr.len > 0;

    if (show_error_msgs or show_compile_errors or show_stderr) {
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();
        build_runner.printErrorMessages(gpa, &compile.step, .{ .ttyconf = ttyconf }, stderr, false) catch {};
    }

    const rebuilt_bin_path = result catch |err| switch (err) {
        error.MakeFailed => return,
        else => |other| return other,
    };
    run.rebuilt_executable = try rebuilt_bin_path.join(gpa, compile.out_filename);
}

fn fuzzWorkerRun(
    run: *Step.Run,
    web_server: *WebServer,
    unit_test_index: u32,
    ttyconf: std.io.tty.Config,
    parent_prog_node: std.Progress.Node,
) void {
    const gpa = run.step.owner.allocator;
    const test_name = run.cached_test_metadata.?.testName(unit_test_index);

    const prog_node = parent_prog_node.start(test_name, 0);
    defer prog_node.end();

    run.rerunInFuzzMode(web_server, unit_test_index, prog_node) catch |err| switch (err) {
        error.MakeFailed => {
            const stderr = std.io.getStdErr();
            std.debug.lockStdErr();
            defer std.debug.unlockStdErr();
            build_runner.printErrorMessages(gpa, &run.step, .{ .ttyconf = ttyconf }, stderr, false) catch {};
            return;
        },
        else => {
            log.err("step '{s}': failed to rerun '{s}' in fuzz mode: {s}", .{
                run.step.name, test_name, @errorName(err),
            });
            return;
        },
    };
}
//! This file is shared among Zig code running in wildly different contexts:
//! libfuzzer, compiled alongside unit tests, the build runner, running on the
//! host computer, and the fuzzing web interface webassembly code running in
//! the browser. All of these components interface to some degree via an ABI.

/// libfuzzer uses this and its usize is the one that counts. To match the ABI,
/// make the ints be the size of the target used with libfuzzer.
///
/// Trailing:
/// * 1 bit per pc_addr, usize elements
/// * pc_addr: usize for each pcs_len
pub const SeenPcsHeader = extern struct {
    n_runs: usize,
    unique_runs: usize,
    pcs_len: usize,

    /// Used for comptime assertions. Provides a mechanism for strategically
    /// causing compile errors.
    pub const trailing = .{
        .pc_bits_usize,
        .pc_addr,
    };

    pub fn headerEnd(header: *const SeenPcsHeader) []const usize {
        const ptr: [*]align(@alignOf(usize)) const u8 = @ptrCast(header);
        const header_end_ptr: [*]const usize = @ptrCast(ptr + @sizeOf(SeenPcsHeader));
        const pcs_len = header.pcs_len;
        return header_end_ptr[0 .. pcs_len + seenElemsLen(pcs_len)];
    }

    pub fn seenBits(header: *const SeenPcsHeader) []const usize {
        return header.headerEnd()[0..seenElemsLen(header.pcs_len)];
    }

    pub fn seenElemsLen(pcs_len: usize) usize {
        return (pcs_len + @bitSizeOf(usize) - 1) / @bitSizeOf(usize);
    }

    pub fn pcAddrs(header: *const SeenPcsHeader) []const usize {
        const pcs_len = header.pcs_len;
        return header.headerEnd()[seenElemsLen(pcs_len)..][0..pcs_len];
    }
};

pub const ToClientTag = enum(u8) {
    current_time,
    source_index,
    coverage_update,
    entry_points,
    _,
};

pub const CurrentTime = extern struct {
    tag: ToClientTag = .current_time,
    /// Number of nanoseconds that all other timestamps are in reference to.
    base: i64 align(1),
};

/// Sent to the fuzzer web client on first connection to the websocket URL.
///
/// Trailing:
/// * std.debug.Coverage.String for each directories_len
/// * std.debug.Coverage.File for each files_len
/// * std.debug.Coverage.SourceLocation for each source_locations_len
/// * u8 for each string_bytes_len
pub const SourceIndexHeader = extern struct {
    flags: Flags,
    directories_len: u32,
    files_len: u32,
    source_locations_len: u32,
    string_bytes_len: u32,
    /// When, according to the server, fuzzing started.
    start_timestamp: i64 align(4),

    pub const Flags = packed struct(u32) {
        tag: ToClientTag = .source_index,
        _: u24 = 0,
    };
};

/// Sent to the fuzzer web client whenever the set of covered source locations
/// changes.
///
/// Trailing:
/// * one bit per source_locations_len, contained in u64 elements
pub const CoverageUpdateHeader = extern struct {
    flags: Flags = .{},
    n_runs: u64,
    unique_runs: u64,

    pub const Flags = packed struct(u64) {
        tag: ToClientTag = .coverage_update,
        _: u56 = 0,
    };

    pub const trailing = .{
        .pc_bits_usize,
    };
};

/// Sent to the fuzzer web client when the set of entry points is updated.
///
/// Trailing:
/// * one u32 index of source_locations per locs_len
pub const EntryPointHeader = extern struct {
    flags: Flags,

    pub const Flags = packed struct(u32) {
        tag: ToClientTag = .entry_points,
        locs_len: u24,
    };
};
const builtin = @import("builtin");

const std = @import("../../std.zig");
const Allocator = std.mem.Allocator;
const Build = std.Build;
const Step = std.Build.Step;
const Coverage = std.debug.Coverage;
const abi = std.Build.Fuzz.abi;
const log = std.log;
const assert = std.debug.assert;
const Cache = std.Build.Cache;
const Path = Cache.Path;

const WebServer = @This();

gpa: Allocator,
global_cache_directory: Build.Cache.Directory,
zig_lib_directory: Build.Cache.Directory,
zig_exe_path: []const u8,
listen_address: std.net.Address,
fuzz_run_steps: []const *Step.Run,

/// Messages from fuzz workers. Protected by mutex.
msg_queue: std.ArrayListUnmanaged(Msg),
/// Protects `msg_queue` only.
mutex: std.Thread.Mutex,
/// Signaled when there is a message in `msg_queue`.
condition: std.Thread.Condition,

coverage_files: std.AutoArrayHashMapUnmanaged(u64, CoverageMap),
/// Protects `coverage_files` only.
coverage_mutex: std.Thread.Mutex,
/// Signaled when `coverage_files` changes.
coverage_condition: std.Thread.Condition,

/// Time at initialization of WebServer.
base_timestamp: i128,

const fuzzer_bin_name = "fuzzer";
const fuzzer_arch_os_abi = "wasm32-freestanding";
const fuzzer_cpu_features = "baseline+atomics+bulk_memory+multivalue+mutable_globals+nontrapping_fptoint+reference_types+sign_ext";

const CoverageMap = struct {
    mapped_memory: []align(std.heap.page_size_min) const u8,
    coverage: Coverage,
    source_locations: []Coverage.SourceLocation,
    /// Elements are indexes into `source_locations` pointing to the unit tests that are being fuzz tested.
    entry_points: std.ArrayListUnmanaged(u32),
    start_timestamp: i64,

    fn deinit(cm: *CoverageMap, gpa: Allocator) void {
        std.posix.munmap(cm.mapped_memory);
        cm.coverage.deinit(gpa);
        cm.* = undefined;
    }
};

const Msg = union(enum) {
    coverage: struct {
        id: u64,
        run: *Step.Run,
    },
    entry_point: struct {
        coverage_id: u64,
        addr: u64,
    },
};

pub fn run(ws: *WebServer) void {
    var http_server = ws.listen_address.listen(.{
        .reuse_address = true,
    }) catch |err| {
        log.err("failed to listen to port {d}: {s}", .{ ws.listen_address.in.getPort(), @errorName(err) });
        return;
    };
    const port = http_server.listen_address.in.getPort();
    log.info("web interface listening at http://127.0.0.1:{d}/", .{port});
    if (ws.listen_address.in.getPort() == 0)
        log.info("hint: pass --port {d} to use this same port next time", .{port});

    while (true) {
        const connection = http_server.accept() catch |err| {
            log.err("failed to accept connection: {s}", .{@errorName(err)});
            return;
        };
        _ = std.Thread.spawn(.{}, accept, .{ ws, connection }) catch |err| {
            log.err("unable to spawn connection thread: {s}", .{@errorName(err)});
            connection.stream.close();
            continue;
        };
    }
}

fn now(s: *const WebServer) i64 {
    return @intCast(std.time.nanoTimestamp() - s.base_timestamp);
}

fn accept(ws: *WebServer, connection: std.net.Server.Connection) void {
    defer connection.stream.close();

    var read_buffer: [0x4000]u8 = undefined;
    var server = std.http.Server.init(connection, &read_buffer);
    var web_socket: std.http.WebSocket = undefined;
    var send_buffer: [0x4000]u8 = undefined;
    var ws_recv_buffer: [0x4000]u8 align(4) = undefined;
    while (server.state == .ready) {
        var request = server.receiveHead() catch |err| switch (err) {
            error.HttpConnectionClosing => return,
            else => {
                log.err("closing http connection: {s}", .{@errorName(err)});
                return;
            },
        };
        if (web_socket.init(&request, &send_buffer, &ws_recv_buffer) catch |err| {
            log.err("initializing web socket: {s}", .{@errorName(err)});
            return;
        }) {
            serveWebSocket(ws, &web_socket) catch |err| {
                log.err("unable to serve web socket connection: {s}", .{@errorName(err)});
                return;
            };
        } else {
            serveRequest(ws, &request) catch |err| switch (err) {
                error.AlreadyReported => return,
                else => |e| {
                    log.err("unable to serve {s}: {s}", .{ request.head.target, @errorName(e) });
                    return;
                },
            };
        }
    }
}

fn serveRequest(ws: *WebServer, request: *std.http.Server.Request) !void {
    if (std.mem.eql(u8, request.head.target, "/") or
        std.mem.eql(u8, request.head.target, "/debug") or
        std.mem.eql(u8, request.head.target, "/debug/"))
    {
        try serveFile(ws, request, "fuzzer/web/index.html", "text/html");
    } else if (std.mem.eql(u8, request.head.target, "/main.js") or
        std.mem.eql(u8, request.head.target, "/debug/main.js"))
    {
        try serveFile(ws, request, "fuzzer/web/main.js", "application/javascript");
    } else if (std.mem.eql(u8, request.head.target, "/main.wasm")) {
        try serveWasm(ws, request, .ReleaseFast);
    } else if (std.mem.eql(u8, request.head.target, "/debug/main.wasm")) {
        try serveWasm(ws, request, .Debug);
    } else if (std.mem.eql(u8, request.head.target, "/sources.tar") or
        std.mem.eql(u8, request.head.target, "/debug/sources.tar"))
    {
        try serveSourcesTar(ws, request);
    } else {
        try request.respond("not found", .{
            .status = .not_found,
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/plain" },
            },
        });
    }
}

fn serveFile(
    ws: *WebServer,
    request: *std.http.Server.Request,
    name: []const u8,
    content_type: []const u8,
) !void {
    const gpa = ws.gpa;
    // The desired API is actually sendfile, which will require enhancing std.http.Server.
    // We load the file with every request so that the user can make changes to the file
    // and refresh the HTML page without restarting this server.
    const file_contents = ws.zig_lib_directory.handle.readFileAlloc(gpa, name, 10 * 1024 * 1024) catch |err| {
        log.err("failed to read '{}{s}': {s}", .{ ws.zig_lib_directory, name, @errorName(err) });
        return error.AlreadyReported;
    };
    defer gpa.free(file_contents);
    try request.respond(file_contents, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = content_type },
            cache_control_header,
        },
    });
}

fn serveWasm(
    ws: *WebServer,
    request: *std.http.Server.Request,
    optimize_mode: std.builtin.OptimizeMode,
) !void {
    const gpa = ws.gpa;

    var arena_instance = std.heap.ArenaAllocator.init(gpa);
    defer arena_instance.deinit();
    const arena = arena_instance.allocator();

    // Do the compilation every request, so that the user can edit the files
    // and see the changes without restarting the server.
    const wasm_base_path = try buildWasmBinary(ws, arena, optimize_mode);
    const bin_name = try std.zig.binNameAlloc(arena, .{
        .root_name = fuzzer_bin_name,
        .target = std.zig.system.resolveTargetQuery(std.Build.parseTargetQuery(.{
            .arch_os_abi = fuzzer_arch_os_abi,
            .cpu_features = fuzzer_cpu_features,
        }) catch unreachable) catch unreachable,
        .output_mode = .Exe,
    });
    // std.http.Server does not have a sendfile API yet.
    const bin_path = try wasm_base_path.join(arena, bin_name);
    const file_contents = try bin_path.root_dir.handle.readFileAlloc(gpa, bin_path.sub_path, 10 * 1024 * 1024);
    defer gpa.free(file_contents);
    try request.respond(file_contents, .{
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/wasm" },
            cache_control_header,
        },
    });
}

fn buildWasmBinary(
    ws: *WebServer,
    arena: Allocator,
    optimize_mode: std.builtin.OptimizeMode,
) !Path {
    const gpa = ws.gpa;

    const main_src_path: Build.Cache.Path = .{
        .root_dir = ws.zig_lib_directory,
        .sub_path = "fuzzer/web/main.zig",
    };
    const walk_src_path: Build.Cache.Path = .{
        .root_dir = ws.zig_lib_directory,
        .sub_path = "docs/wasm/Walk.zig",
    };
    const html_render_src_path: Build.Cache.Path =```
