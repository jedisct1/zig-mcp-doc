```
v.ptr, argv_buf.ptr)) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }

        var result_args = try allocator.alloc([:0]u8, count);
        var i: usize = 0;
        while (i < count) : (i += 1) {
            result_args[i] = mem.sliceTo(argv[i], 0);
        }

        return result_args;
    }

    pub fn next(self: *ArgIteratorWasi) ?[:0]const u8 {
        if (self.index == self.args.len) return null;

        const arg = self.args[self.index];
        self.index += 1;
        return arg;
    }

    pub fn skip(self: *ArgIteratorWasi) bool {
        if (self.index == self.args.len) return false;

        self.index += 1;
        return true;
    }

    /// Call to free the internal buffer of the iterator.
    pub fn deinit(self: *ArgIteratorWasi) void {
        const last_item = self.args[self.args.len - 1];
        const last_byte_addr = @intFromPtr(last_item.ptr) + last_item.len + 1; // null terminated
        const first_item_ptr = self.args[0].ptr;
        const len = last_byte_addr - @intFromPtr(first_item_ptr);
        self.allocator.free(first_item_ptr[0..len]);
        self.allocator.free(self.args);
    }
};

/// Iterator that implements the Windows command-line parsing algorithm.
/// The implementation is intended to be compatible with the post-2008 C runtime,
/// but is *not* intended to be compatible with `CommandLineToArgvW` since
/// `CommandLineToArgvW` uses the pre-2008 parsing rules.
///
/// This iterator faithfully implements the parsing behavior observed from the C runtime with
/// one exception: if the command-line string is empty, the iterator will immediately complete
/// without returning any arguments (whereas the C runtime will return a single argument
/// representing the name of the current executable).
///
/// The essential parts of the algorithm are described in Microsoft's documentation:
///
/// - https://learn.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?view=msvc-170#parsing-c-command-line-arguments
///
/// David Deley explains some additional undocumented quirks in great detail:
///
/// - https://daviddeley.com/autohotkey/parameters/parameters.htm#WINCRULES
pub const ArgIteratorWindows = struct {
    allocator: Allocator,
    /// Encoded as WTF-16 LE.
    cmd_line: []const u16,
    index: usize = 0,
    /// Owned by the iterator. Long enough to hold contiguous NUL-terminated slices
    /// of each argument encoded as WTF-8.
    buffer: []u8,
    start: usize = 0,
    end: usize = 0,

    pub const InitError = error{OutOfMemory};

    /// `cmd_line_w` *must* be a WTF16-LE-encoded string.
    ///
    /// The iterator stores and uses `cmd_line_w`, so its memory must be valid for
    /// at least as long as the returned ArgIteratorWindows.
    pub fn init(allocator: Allocator, cmd_line_w: []const u16) InitError!ArgIteratorWindows {
        const wtf8_len = unicode.calcWtf8Len(cmd_line_w);

        // This buffer must be large enough to contain contiguous NUL-terminated slices
        // of each argument.
        // - During parsing, the length of a parsed argument will always be equal to
        //   to less than its unparsed length
        // - The first argument needs one extra byte of space allocated for its NUL
        //   terminator, but for each subsequent argument the necessary whitespace
        //   between arguments guarantees room for their NUL terminator(s).
        const buffer = try allocator.alloc(u8, wtf8_len + 1);
        errdefer allocator.free(buffer);

        return .{
            .allocator = allocator,
            .cmd_line = cmd_line_w,
            .buffer = buffer,
        };
    }

    /// Returns the next argument and advances the iterator. Returns `null` if at the end of the
    /// command-line string. The iterator owns the returned slice.
    /// The result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
    pub fn next(self: *ArgIteratorWindows) ?[:0]const u8 {
        return self.nextWithStrategy(next_strategy);
    }

    /// Skips the next argument and advances the iterator. Returns `true` if an argument was
    /// skipped, `false` if at the end of the command-line string.
    pub fn skip(self: *ArgIteratorWindows) bool {
        return self.nextWithStrategy(skip_strategy);
    }

    const next_strategy = struct {
        const T = ?[:0]const u8;

        const eof = null;

        /// Returns '\' if any backslashes are emitted, otherwise returns `last_emitted_code_unit`.
        fn emitBackslashes(self: *ArgIteratorWindows, count: usize, last_emitted_code_unit: ?u16) ?u16 {
            for (0..count) |_| {
                self.buffer[self.end] = '\\';
                self.end += 1;
            }
            return if (count != 0) '\\' else last_emitted_code_unit;
        }

        /// If `last_emitted_code_unit` and `code_unit` form a surrogate pair, then
        /// the previously emitted high surrogate is overwritten by the codepoint encoded
        /// by the surrogate pair, and `null` is returned.
        /// Otherwise, `code_unit` is emitted and returned.
        fn emitCharacter(self: *ArgIteratorWindows, code_unit: u16, last_emitted_code_unit: ?u16) ?u16 {
            // Because we are emitting WTF-8, we need to
            // check to see if we've emitted two consecutive surrogate
            // codepoints that form a valid surrogate pair in order
            // to ensure that we're always emitting well-formed WTF-8
            // (https://simonsapin.github.io/wtf-8/#concatenating).
            //
            // If we do have a valid surrogate pair, we need to emit
            // the UTF-8 sequence for the codepoint that they encode
            // instead of the WTF-8 encoding for the two surrogate pairs
            // separately.
            //
            // This is relevant when dealing with a WTF-16 encoded
            // command line like this:
            // "<0xD801>"<0xDC37>
            // which would get parsed and converted to WTF-8 as:
            // <0xED><0xA0><0x81><0xED><0xB0><0xB7>
            // but instead, we need to recognize the surrogate pair
            // and emit the codepoint it encodes, which in this
            // example is U+10437 (𐐷), which is encoded in UTF-8 as:
            // <0xF0><0x90><0x90><0xB7>
            if (last_emitted_code_unit != null and
                std.unicode.utf16IsLowSurrogate(code_unit) and
                std.unicode.utf16IsHighSurrogate(last_emitted_code_unit.?))
            {
                const codepoint = std.unicode.utf16DecodeSurrogatePair(&.{ last_emitted_code_unit.?, code_unit }) catch unreachable;

                // Unpaired surrogate is 3 bytes long
                const dest = self.buffer[self.end - 3 ..];
                const len = unicode.utf8Encode(codepoint, dest) catch unreachable;
                // All codepoints that require a surrogate pair (> U+FFFF) are encoded as 4 bytes
                assert(len == 4);
                self.end += 1;
                return null;
            }

            const wtf8_len = std.unicode.wtf8Encode(code_unit, self.buffer[self.end..]) catch unreachable;
            self.end += wtf8_len;
            return code_unit;
        }

        fn yieldArg(self: *ArgIteratorWindows) [:0]const u8 {
            self.buffer[self.end] = 0;
            const arg = self.buffer[self.start..self.end :0];
            self.end += 1;
            self.start = self.end;
            return arg;
        }
    };

    const skip_strategy = struct {
        const T = bool;

        const eof = false;

        fn emitBackslashes(_: *ArgIteratorWindows, _: usize, last_emitted_code_unit: ?u16) ?u16 {
            return last_emitted_code_unit;
        }

        fn emitCharacter(_: *ArgIteratorWindows, _: u16, last_emitted_code_unit: ?u16) ?u16 {
            return last_emitted_code_unit;
        }

        fn yieldArg(_: *ArgIteratorWindows) bool {
            return true;
        }
    };

    fn nextWithStrategy(self: *ArgIteratorWindows, comptime strategy: type) strategy.T {
        var last_emitted_code_unit: ?u16 = null;
        // The first argument (the executable name) uses different parsing rules.
        if (self.index == 0) {
            if (self.cmd_line.len == 0 or self.cmd_line[0] == 0) {
                // Immediately complete the iterator.
                // The C runtime would return the name of the current executable here.
                return strategy.eof;
            }

            var inside_quotes = false;
            while (true) : (self.index += 1) {
                const char = if (self.index != self.cmd_line.len)
                    mem.littleToNative(u16, self.cmd_line[self.index])
                else
                    0;
                switch (char) {
                    0 => {
                        return strategy.yieldArg(self);
                    },
                    '"' => {
                        inside_quotes = !inside_quotes;
                    },
                    ' ', '\t' => {
                        if (inside_quotes) {
                            last_emitted_code_unit = strategy.emitCharacter(self, char, last_emitted_code_unit);
                        } else {
                            self.index += 1;
                            return strategy.yieldArg(self);
                        }
                    },
                    else => {
                        last_emitted_code_unit = strategy.emitCharacter(self, char, last_emitted_code_unit);
                    },
                }
            }
        }

        // Skip spaces and tabs. The iterator completes if we reach the end of the string here.
        while (true) : (self.index += 1) {
            const char = if (self.index != self.cmd_line.len)
                mem.littleToNative(u16, self.cmd_line[self.index])
            else
                0;
            switch (char) {
                0 => return strategy.eof,
                ' ', '\t' => continue,
                else => break,
            }
        }

        // Parsing rules for subsequent arguments:
        //
        // - The end of the string always terminates the current argument.
        // - When not in 'inside_quotes' mode, a space or tab terminates the current argument.
        // - 2n backslashes followed by a quote emit n backslashes (note: n can be zero).
        //   If in 'inside_quotes' and the quote is immediately followed by a second quote,
        //   one quote is emitted and the other is skipped, otherwise, the quote is skipped
        //   and 'inside_quotes' is toggled.
        // - 2n + 1 backslashes followed by a quote emit n backslashes followed by a quote.
        // - n backslashes not followed by a quote emit n backslashes.
        var backslash_count: usize = 0;
        var inside_quotes = false;
        while (true) : (self.index += 1) {
            const char = if (self.index != self.cmd_line.len)
                mem.littleToNative(u16, self.cmd_line[self.index])
            else
                0;
            switch (char) {
                0 => {
                    last_emitted_code_unit = strategy.emitBackslashes(self, backslash_count, last_emitted_code_unit);
                    return strategy.yieldArg(self);
                },
                ' ', '\t' => {
                    last_emitted_code_unit = strategy.emitBackslashes(self, backslash_count, last_emitted_code_unit);
                    backslash_count = 0;
                    if (inside_quotes) {
                        last_emitted_code_unit = strategy.emitCharacter(self, char, last_emitted_code_unit);
                    } else return strategy.yieldArg(self);
                },
                '"' => {
                    const char_is_escaped_quote = backslash_count % 2 != 0;
                    last_emitted_code_unit = strategy.emitBackslashes(self, backslash_count / 2, last_emitted_code_unit);
                    backslash_count = 0;
                    if (char_is_escaped_quote) {
                        last_emitted_code_unit = strategy.emitCharacter(self, '"', last_emitted_code_unit);
                    } else {
                        if (inside_quotes and
                            self.index + 1 != self.cmd_line.len and
                            mem.littleToNative(u16, self.cmd_line[self.index + 1]) == '"')
                        {
                            last_emitted_code_unit = strategy.emitCharacter(self, '"', last_emitted_code_unit);
                            self.index += 1;
                        } else {
                            inside_quotes = !inside_quotes;
                        }
                    }
                },
                '\\' => {
                    backslash_count += 1;
                },
                else => {
                    last_emitted_code_unit = strategy.emitBackslashes(self, backslash_count, last_emitted_code_unit);
                    backslash_count = 0;
                    last_emitted_code_unit = strategy.emitCharacter(self, char, last_emitted_code_unit);
                },
            }
        }
    }

    /// Frees the iterator's copy of the command-line string and all previously returned
    /// argument slices.
    pub fn deinit(self: *ArgIteratorWindows) void {
        self.allocator.free(self.buffer);
    }
};

/// Optional parameters for `ArgIteratorGeneral`
pub const ArgIteratorGeneralOptions = struct {
    comments: bool = false,
    single_quotes: bool = false,
};

/// A general Iterator to parse a string into a set of arguments
pub fn ArgIteratorGeneral(comptime options: ArgIteratorGeneralOptions) type {
    return struct {
        allocator: Allocator,
        index: usize = 0,
        cmd_line: []const u8,

        /// Should the cmd_line field be free'd (using the allocator) on deinit()?
        free_cmd_line_on_deinit: bool,

        /// buffer MUST be long enough to hold the cmd_line plus a null terminator.
        /// buffer will we free'd (using the allocator) on deinit()
        buffer: []u8,
        start: usize = 0,
        end: usize = 0,

        pub const Self = @This();

        pub const InitError = error{OutOfMemory};

        /// cmd_line_utf8 MUST remain valid and constant while using this instance
        pub fn init(allocator: Allocator, cmd_line_utf8: []const u8) InitError!Self {
            const buffer = try allocator.alloc(u8, cmd_line_utf8.len + 1);
            errdefer allocator.free(buffer);

            return Self{
                .allocator = allocator,
                .cmd_line = cmd_line_utf8,
                .free_cmd_line_on_deinit = false,
                .buffer = buffer,
            };
        }

        /// cmd_line_utf8 will be free'd (with the allocator) on deinit()
        pub fn initTakeOwnership(allocator: Allocator, cmd_line_utf8: []const u8) InitError!Self {
            const buffer = try allocator.alloc(u8, cmd_line_utf8.len + 1);
            errdefer allocator.free(buffer);

            return Self{
                .allocator = allocator,
                .cmd_line = cmd_line_utf8,
                .free_cmd_line_on_deinit = true,
                .buffer = buffer,
            };
        }

        // Skips over whitespace in the cmd_line.
        // Returns false if the terminating sentinel is reached, true otherwise.
        // Also skips over comments (if supported).
        fn skipWhitespace(self: *Self) bool {
            while (true) : (self.index += 1) {
                const character = if (self.index != self.cmd_line.len) self.cmd_line[self.index] else 0;
                switch (character) {
                    0 => return false,
                    ' ', '\t', '\r', '\n' => continue,
                    '#' => {
                        if (options.comments) {
                            while (true) : (self.index += 1) {
                                switch (self.cmd_line[self.index]) {
                                    '\n' => break,
                                    0 => return false,
                                    else => continue,
                                }
                            }
                            continue;
                        } else {
                            break;
                        }
                    },
                    else => break,
                }
            }
            return true;
        }

        pub fn skip(self: *Self) bool {
            if (!self.skipWhitespace()) {
                return false;
            }

            var backslash_count: usize = 0;
            var in_quote = false;
            while (true) : (self.index += 1) {
                const character = if (self.index != self.cmd_line.len) self.cmd_line[self.index] else 0;
                switch (character) {
                    0 => return true,
                    '"', '\'' => {
                        if (!options.single_quotes and character == '\'') {
                            backslash_count = 0;
                            continue;
                        }
                        const quote_is_real = backslash_count % 2 == 0;
                        if (quote_is_real) {
                            in_quote = !in_quote;
                        }
                    },
                    '\\' => {
                        backslash_count += 1;
                    },
                    ' ', '\t', '\r', '\n' => {
                        if (!in_quote) {
                            return true;
                        }
                        backslash_count = 0;
                    },
                    else => {
                        backslash_count = 0;
                        continue;
                    },
                }
            }
        }

        /// Returns a slice of the internal buffer that contains the next argument.
        /// Returns null when it reaches the end.
        pub fn next(self: *Self) ?[:0]const u8 {
            if (!self.skipWhitespace()) {
                return null;
            }

            var backslash_count: usize = 0;
            var in_quote = false;
            while (true) : (self.index += 1) {
                const character = if (self.index != self.cmd_line.len) self.cmd_line[self.index] else 0;
                switch (character) {
                    0 => {
                        self.emitBackslashes(backslash_count);
                        self.buffer[self.end] = 0;
                        const token = self.buffer[self.start..self.end :0];
                        self.end += 1;
                        self.start = self.end;
                        return token;
                    },
                    '"', '\'' => {
                        if (!options.single_quotes and character == '\'') {
                            self.emitBackslashes(backslash_count);
                            backslash_count = 0;
                            self.emitCharacter(character);
                            continue;
                        }
                        const quote_is_real = backslash_count % 2 == 0;
                        self.emitBackslashes(backslash_count / 2);
                        backslash_count = 0;

                        if (quote_is_real) {
                            in_quote = !in_quote;
                        } else {
                            self.emitCharacter('"');
                        }
                    },
                    '\\' => {
                        backslash_count += 1;
                    },
                    ' ', '\t', '\r', '\n' => {
                        self.emitBackslashes(backslash_count);
                        backslash_count = 0;
                        if (in_quote) {
                            self.emitCharacter(character);
                        } else {
                            self.buffer[self.end] = 0;
                            const token = self.buffer[self.start..self.end :0];
                            self.end += 1;
                            self.start = self.end;
                            return token;
                        }
                    },
                    else => {
                        self.emitBackslashes(backslash_count);
                        backslash_count = 0;
                        self.emitCharacter(character);
                    },
                }
            }
        }

        fn emitBackslashes(self: *Self, emit_count: usize) void {
            var i: usize = 0;
            while (i < emit_count) : (i += 1) {
                self.emitCharacter('\\');
            }
        }

        fn emitCharacter(self: *Self, char: u8) void {
            self.buffer[self.end] = char;
            self.end += 1;
        }

        /// Call to free the internal buffer of the iterator.
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buffer);

            if (self.free_cmd_line_on_deinit) {
                self.allocator.free(self.cmd_line);
            }
        }
    };
}

/// Cross-platform command line argument iterator.
pub const ArgIterator = struct {
    const InnerType = switch (native_os) {
        .windows => ArgIteratorWindows,
        .wasi => if (builtin.link_libc) ArgIteratorPosix else ArgIteratorWasi,
        else => ArgIteratorPosix,
    };

    inner: InnerType,

    /// Initialize the args iterator. Consider using initWithAllocator() instead
    /// for cross-platform compatibility.
    pub fn init() ArgIterator {
        if (native_os == .wasi) {
            @compileError("In WASI, use initWithAllocator instead.");
        }
        if (native_os == .windows) {
            @compileError("In Windows, use initWithAllocator instead.");
        }

        return ArgIterator{ .inner = InnerType.init() };
    }

    pub const InitError = InnerType.InitError;

    /// You must deinitialize iterator's internal buffers by calling `deinit` when done.
    pub fn initWithAllocator(allocator: Allocator) InitError!ArgIterator {
        if (native_os == .wasi and !builtin.link_libc) {
            return ArgIterator{ .inner = try InnerType.init(allocator) };
        }
        if (native_os == .windows) {
            const cmd_line = std.os.windows.peb().ProcessParameters.CommandLine;
            const cmd_line_w = cmd_line.Buffer.?[0 .. cmd_line.Length / 2];
            return ArgIterator{ .inner = try InnerType.init(allocator, cmd_line_w) };
        }

        return ArgIterator{ .inner = InnerType.init() };
    }

    /// Get the next argument. Returns 'null' if we are at the end.
    /// Returned slice is pointing to the iterator's internal buffer.
    /// On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
    /// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
    pub fn next(self: *ArgIterator) ?([:0]const u8) {
        return self.inner.next();
    }

    /// Parse past 1 argument without capturing it.
    /// Returns `true` if skipped an arg, `false` if we are at the end.
    pub fn skip(self: *ArgIterator) bool {
        return self.inner.skip();
    }

    /// Call this to free the iterator's internal buffer if the iterator
    /// was created with `initWithAllocator` function.
    pub fn deinit(self: *ArgIterator) void {
        // Unless we're targeting WASI or Windows, this is a no-op.
        if (native_os == .wasi and !builtin.link_libc) {
            self.inner.deinit();
        }

        if (native_os == .windows) {
            self.inner.deinit();
        }
    }
};

/// Holds the command-line arguments, with the program name as the first entry.
/// Use argsWithAllocator() for cross-platform code.
pub fn args() ArgIterator {
    return ArgIterator.init();
}

/// You must deinitialize iterator's internal buffers by calling `deinit` when done.
pub fn argsWithAllocator(allocator: Allocator) ArgIterator.InitError!ArgIterator {
    return ArgIterator.initWithAllocator(allocator);
}

/// Caller must call argsFree on result.
/// On Windows, the result is encoded as [WTF-8](https://simonsapin.github.io/wtf-8/).
/// On other platforms, the result is an opaque sequence of bytes with no particular encoding.
pub fn argsAlloc(allocator: Allocator) ![][:0]u8 {
    // TODO refactor to only make 1 allocation.
    var it = try argsWithAllocator(allocator);
    defer it.deinit();

    var contents = std.ArrayList(u8).init(allocator);
    defer contents.deinit();

    var slice_list = std.ArrayList(usize).init(allocator);
    defer slice_list.deinit();

    while (it.next()) |arg| {
        try contents.appendSlice(arg[0 .. arg.len + 1]);
        try slice_list.append(arg.len);
    }

    const contents_slice = contents.items;
    const slice_sizes = slice_list.items;
    const slice_list_bytes = try math.mul(usize, @sizeOf([]u8), slice_sizes.len);
    const total_bytes = try math.add(usize, slice_list_bytes, contents_slice.len);
    const buf = try allocator.alignedAlloc(u8, .of([]u8), total_bytes);
    errdefer allocator.free(buf);

    const result_slice_list = mem.bytesAsSlice([:0]u8, buf[0..slice_list_bytes]);
    const result_contents = buf[slice_list_bytes..];
    @memcpy(result_contents[0..contents_slice.len], contents_slice);

    var contents_index: usize = 0;
    for (slice_sizes, 0..) |len, i| {
        const new_index = contents_index + len;
        result_slice_list[i] = result_contents[contents_index..new_index :0];
        contents_index = new_index + 1;
    }

    return result_slice_list;
}

pub fn argsFree(allocator: Allocator, args_alloc: []const [:0]u8) void {
    var total_bytes: usize = 0;
    for (args_alloc) |arg| {
        total_bytes += @sizeOf([]u8) + arg.len + 1;
    }
    const unaligned_allocated_buf = @as([*]const u8, @ptrCast(args_alloc.ptr))[0..total_bytes];
    const aligned_allocated_buf: []align(@alignOf([]u8)) const u8 = @alignCast(unaligned_allocated_buf);
    return allocator.free(aligned_allocated_buf);
}

test ArgIteratorWindows {
    const t = testArgIteratorWindows;

    try t(
        \\"C:\Program Files\zig\zig.exe" run .\src\main.zig -target x86_64-windows-gnu -O ReleaseSafe -- --emoji=🗿 --eval="new Regex(\"Dwayne \\\"The Rock\\\" Johnson\")"
    , &.{
        \\C:\Program Files\zig\zig.exe
        ,
        \\run
        ,
        \\.\src\main.zig
        ,
        \\-target
        ,
        \\x86_64-windows-gnu
        ,
        \\-O
        ,
        \\ReleaseSafe
        ,
        \\--
        ,
        \\--emoji=🗿
        ,
        \\--eval=new Regex("Dwayne \"The Rock\" Johnson")
        ,
    });

    // Empty
    try t("", &.{});

    // Separators
    try t("aa bb cc", &.{ "aa", "bb", "cc" });
    try t("aa\tbb\tcc", &.{ "aa", "bb", "cc" });
    try t("aa\nbb\ncc", &.{"aa\nbb\ncc"});
    try t("aa\r\nbb\r\ncc", &.{"aa\r\nbb\r\ncc"});
    try t("aa\rbb\rcc", &.{"aa\rbb\rcc"});
    try t("aa\x07bb\x07cc", &.{"aa\x07bb\x07cc"});
    try t("aa\x7Fbb\x7Fcc", &.{"aa\x7Fbb\x7Fcc"});
    try t("aa🦎bb🦎cc", &.{"aa🦎bb🦎cc"});

    // Leading/trailing whitespace
    try t("  ", &.{""});
    try t("  aa  bb  ", &.{ "", "aa", "bb" });
    try t("\t\t", &.{""});
    try t("\t\taa\t\tbb\t\t", &.{ "", "aa", "bb" });
    try t("\n\n", &.{"\n\n"});
    try t("\n\naa\n\nbb\n\n", &.{"\n\naa\n\nbb\n\n"});

    // Executable name with quotes/backslashes
    try t("\"aa bb\tcc\ndd\"", &.{"aa bb\tcc\ndd"});
    try t("\"", &.{""});
    try t("\"\"", &.{""});
    try t("\"\"\"", &.{""});
    try t("\"\"\"\"", &.{""});
    try t("\"\"\"\"\"", &.{""});
    try t("aa\"bb\"cc\"dd", &.{"aabbccdd"});
    try t("aa\"bb cc\"dd", &.{"aabb ccdd"});
    try t("\"aa\\\"bb\"", &.{"aa\\bb"});
    try t("\"aa\\\\\"", &.{"aa\\\\"});
    try t("aa\\\"bb", &.{"aa\\bb"});
    try t("aa\\\\\"bb", &.{"aa\\\\bb"});

    // Arguments with quotes/backslashes
    try t(". \"aa bb\tcc\ndd\"", &.{ ".", "aa bb\tcc\ndd" });
    try t(". aa\" \"bb\"\t\"cc\"\n\"dd\"", &.{ ".", "aa bb\tcc\ndd" });
    try t(". ", &.{"."});
    try t(". \"", &.{ ".", "" });
    try t(". \"\"", &.{ ".", "" });
    try t(". \"\"\"", &.{ ".", "\"" });
    try t(". \"\"\"\"", &.{ ".", "\"" });
    try t(". \"\"\"\"\"", &.{ ".", "\"\"" });
    try t(". \"\"\"\"\"\"", &.{ ".", "\"\"" });
    try t(". \" \"", &.{ ".", " " });
    try t(". \" \"\"", &.{ ".", " \"" });
    try t(". \" \"\"\"", &.{ ".", " \"" });
    try t(". \" \"\"\"\"", &.{ ".", " \"\"" });
    try t(". \" \"\"\"\"\"", &.{ ".", " \"\"" });
    try t(". \" \"\"\"\"\"\"", &.{ ".", " \"\"\"" });
    try t(". \\\"", &.{ ".", "\"" });
    try t(". \\\"\"", &.{ ".", "\"" });
    try t(". \\\"\"\"", &.{ ".", "\"" });
    try t(". \\\"\"\"\"", &.{ ".", "\"\"" });
    try t(". \\\"\"\"\"\"", &.{ ".", "\"\"" });
    try t(". \\\"\"\"\"\"\"", &.{ ".", "\"\"\"" });
    try t(". \" \\\"", &.{ ".", " \"" });
    try t(". \" \\\"\"", &.{ ".", " \"" });
    try t(". \" \\\"\"\"", &.{ ".", " \"\"" });
    try t(". \" \\\"\"\"\"", &.{ ".", " \"\"" });
    try t(". \" \\\"\"\"\"\"", &.{ ".", " \"\"\"" });
    try t(". \" \\\"\"\"\"\"\"", &.{ ".", " \"\"\"" });
    try t(". aa\\bb\\\\cc\\\\\\dd", &.{ ".", "aa\\bb\\\\cc\\\\\\dd" });
    try t(". \\\\\\\"aa bb\"", &.{ ".", "\\\"aa", "bb" });
    try t(". \\\\\\\\\"aa bb\"", &.{ ".", "\\\\aa bb" });

    // From https://learn.microsoft.com/en-us/cpp/cpp/main-function-command-line-args#results-of-parsing-command-lines
    try t(
        \\foo.exe "abc" d e
    , &.{ "foo.exe", "abc", "d", "e" });
    try t(
        \\foo.exe a\\b d"e f"g h
    , &.{ "foo.exe", "a\\\\b", "de fg", "h" });
    try t(
        \\foo.exe a\\\"b c d
    , &.{ "foo.exe", "a\\\"b", "c", "d" });
    try t(
        \\foo.exe a\\\\"b c" d e
    , &.{ "foo.exe", "a\\\\b c", "d", "e" });
    try t(
        \\foo.exe a"b"" c d
    , &.{ "foo.exe", "ab\" c d" });

    // From https://daviddeley.com/autohotkey/parameters/parameters.htm#WINCRULESEX
    try t("foo.exe CallMeIshmael", &.{ "foo.exe", "CallMeIshmael" });
    try t("foo.exe \"Call Me Ishmael\"", &.{ "foo.exe", "Call Me Ishmael" });
    try t("foo.exe Cal\"l Me I\"shmael", &.{ "foo.exe", "Call Me Ishmael" });
    try t("foo.exe CallMe\\\"Ishmael", &.{ "foo.exe", "CallMe\"Ishmael" });
    try t("foo.exe \"CallMe\\\"Ishmael\"", &.{ "foo.exe", "CallMe\"Ishmael" });
    try t("foo.exe \"Call Me Ishmael\\\\\"", &.{ "foo.exe", "Call Me Ishmael\\" });
    try t("foo.exe \"CallMe\\\\\\\"Ishmael\"", &.{ "foo.exe", "CallMe\\\"Ishmael" });
    try t("foo.exe a\\\\\\b", &.{ "foo.exe", "a\\\\\\b" });
    try t("foo.exe \"a\\\\\\b\"", &.{ "foo.exe", "a\\\\\\b" });

    // Surrogate pair encoding of 𐐷 separated by quotes.
    // Encoded as WTF-16:
    // "<0xD801>"<0xDC37>
    // Encoded as WTF-8:
    // "<0xED><0xA0><0x81>"<0xED><0xB0><0xB7>
    // During parsing, the quotes drop out and the surrogate pair
    // should end up encoded as its normal UTF-8 representation.
    try t("foo.exe \"\xed\xa0\x81\"\xed\xb0\xb7", &.{ "foo.exe", "𐐷" });
}

fn testArgIteratorWindows(cmd_line: []const u8, expected_args: []const []const u8) !void {
    const cmd_line_w = try unicode.wtf8ToWtf16LeAllocZ(testing.allocator, cmd_line);
    defer testing.allocator.free(cmd_line_w);

    // next
    {
        var it = try ArgIteratorWindows.init(testing.allocator, cmd_line_w);
        defer it.deinit();

        for (expected_args) |expected| {
            if (it.next()) |actual| {
                try testing.expectEqualStrings(expected, actual);
            } else {
                return error.TestUnexpectedResult;
            }
        }
        try testing.expect(it.next() == null);
    }

    // skip
    {
        var it = try ArgIteratorWindows.init(testing.allocator, cmd_line_w);
        defer it.deinit();

        for (0..expected_args.len) |_| {
            try testing.expect(it.skip());
        }
        try testing.expect(!it.skip());
    }
}

test "general arg parsing" {
    try testGeneralCmdLine("a   b\tc d", &.{ "a", "b", "c", "d" });
    try testGeneralCmdLine("\"abc\" d e", &.{ "abc", "d", "e" });
    try testGeneralCmdLine("a\\\\\\b d\"e f\"g h", &.{ "a\\\\\\b", "de fg", "h" });
    try testGeneralCmdLine("a\\\\\\\"b c d", &.{ "a\\\"b", "c", "d" });
    try testGeneralCmdLine("a\\\\\\\\\"b c\" d e", &.{ "a\\\\b c", "d", "e" });
    try testGeneralCmdLine("a   b\tc \"d f", &.{ "a", "b", "c", "d f" });
    try testGeneralCmdLine("j k l\\", &.{ "j", "k", "l\\" });
    try testGeneralCmdLine("\"\" x y z\\\\", &.{ "", "x", "y", "z\\\\" });

    try testGeneralCmdLine("\".\\..\\zig-cache\\build\" \"bin\\zig.exe\" \".\\..\" \".\\..\\zig-cache\" \"--help\"", &.{
        ".\\..\\zig-cache\\build",
        "bin\\zig.exe",
        ".\\..",
        ".\\..\\zig-cache",
        "--help",
    });

    try testGeneralCmdLine(
        \\ 'foo' "bar"
    , &.{ "'foo'", "bar" });
}

fn testGeneralCmdLine(input_cmd_line: []const u8, expected_args: []const []const u8) !void {
    var it = try ArgIteratorGeneral(.{}).init(std.testing.allocator, input_cmd_line);
    defer it.deinit();
    for (expected_args) |expected_arg| {
        const arg = it.next().?;
        try testing.expectEqualStrings(expected_arg, arg);
    }
    try testing.expect(it.next() == null);
}

test "response file arg parsing" {
    try testResponseFileCmdLine(
        \\a b
        \\c d\
    , &.{ "a", "b", "c", "d\\" });
    try testResponseFileCmdLine("a b c d\\", &.{ "a", "b", "c", "d\\" });

    try testResponseFileCmdLine(
        \\j
        \\ k l # this is a comment \\ \\\ \\\\ "none" "\\" "\\\"
        \\ "m" #another comment
        \\
    , &.{ "j", "k", "l", "m" });

    try testResponseFileCmdLine(
        \\ "" q ""
        \\ "r s # t" "u\" v" #another comment
        \\
    , &.{ "", "q", "", "r s # t", "u\" v" });

    try testResponseFileCmdLine(
        \\ -l"advapi32" a# b#c d#
        \\e\\\
    , &.{ "-ladvapi32", "a#", "b#c", "d#", "e\\\\\\" });

    try testResponseFileCmdLine(
        \\ 'foo' "bar"
    , &.{ "foo", "bar" });
}

fn testResponseFileCmdLine(input_cmd_line: []const u8, expected_args: []const []const u8) !void {
    var it = try ArgIteratorGeneral(.{ .comments = true, .single_quotes = true })
        .init(std.testing.allocator, input_cmd_line);
    defer it.deinit();
    for (expected_args) |expected_arg| {
        const arg = it.next().?;
        try testing.expectEqualStrings(expected_arg, arg);
    }
    try testing.expect(it.next() == null);
}

pub const UserInfo = struct {
    uid: posix.uid_t,
    gid: posix.gid_t,
};

/// POSIX function which gets a uid from username.
pub fn getUserInfo(name: []const u8) !UserInfo {
    return switch (native_os) {
        .linux,
        .macos,
        .watchos,
        .visionos,
        .tvos,
        .ios,
        .freebsd,
        .netbsd,
        .openbsd,
        .haiku,
        .solaris,
        .illumos,
        .serenity,
        => posixGetUserInfo(name),
        else => @compileError("Unsupported OS"),
    };
}

/// TODO this reads /etc/passwd. But sometimes the user/id mapping is in something else
/// like NIS, AD, etc. See `man nss` or look at an strace for `id myuser`.
pub fn posixGetUserInfo(name: []const u8) !UserInfo {
    const file = try std.fs.openFileAbsolute("/etc/passwd", .{});
    defer file.close();

    const reader = file.reader();

    const State = enum {
        Start,
        WaitForNextLine,
        SkipPassword,
        ReadUserId,
        ReadGroupId,
    };

    var buf: [std.heap.page_size_min]u8 = undefined;
    var name_index: usize = 0;
    var state = State.Start;
    var uid: posix.uid_t = 0;
    var gid: posix.gid_t = 0;

    while (true) {
        const amt_read = try reader.read(buf[0..]);
        for (buf[0..amt_read]) |byte| {
            switch (state) {
                .Start => switch (byte) {
                    ':' => {
                        state = if (name_index == name.len) State.SkipPassword else State.WaitForNextLine;
                    },
                    '\n' => return error.CorruptPasswordFile,
                    else => {
                        if (name_index == name.len or name[name_index] != byte) {
                            state = .WaitForNextLine;
                        }
                        name_index += 1;
                    },
                },
                .WaitForNextLine => switch (byte) {
                    '\n' => {
                        name_index = 0;
                        state = .Start;
                    },
                    else => continue,
                },
                .SkipPassword => switch (byte) {
                    '\n' => return error.CorruptPasswordFile,
                    ':' => {
                        state = .ReadUserId;
                    },
                    else => continue,
                },
                .ReadUserId => switch (byte) {
                    ':' => {
                        state = .ReadGroupId;
                    },
                    '\n' => return error.CorruptPasswordFile,
                    else => {
                        const digit = switch (byte) {
                            '0'...'9' => byte - '0',
                            else => return error.CorruptPasswordFile,
                        };
                        {
                            const ov = @mulWithOverflow(uid, 10);
                            if (ov[1] != 0) return error.CorruptPasswordFile;
                            uid = ov[0];
                        }
                        {
                            const ov = @addWithOverflow(uid, digit);
                            if (ov[1] != 0) return error.CorruptPasswordFile;
                            uid = ov[0];
                        }
                    },
                },
                .ReadGroupId => switch (byte) {
                    '\n', ':' => {
                        return UserInfo{
                            .uid = uid,
                            .gid = gid,
                        };
                    },
                    else => {
                        const digit = switch (byte) {
                            '0'...'9' => byte - '0',
                            else => return error.CorruptPasswordFile,
                        };
                        {
                            const ov = @mulWithOverflow(gid, 10);
                            if (ov[1] != 0) return error.CorruptPasswordFile;
                            gid = ov[0];
                        }
                        {
                            const ov = @addWithOverflow(gid, digit);
                            if (ov[1] != 0) return error.CorruptPasswordFile;
                            gid = ov[0];
                        }
                    },
                },
            }
        }
        if (amt_read < buf.len) return error.UserNotFound;
    }
}

pub fn getBaseAddress() usize {
    switch (native_os) {
        .linux => {
            const getauxval = if (builtin.link_libc) std.c.getauxval else std.os.linux.getauxval;
            const base = getauxval(std.elf.AT_BASE);
            if (base != 0) {
                return base;
            }
            const phdr = getauxval(std.elf.AT_PHDR);
            return phdr - @sizeOf(std.elf.Ehdr);
        },
        .driverkit, .ios, .macos, .tvos, .visionos, .watchos => {
            return @intFromPtr(&std.c._mh_execute_header);
        },
        .windows => return @intFromPtr(windows.kernel32.GetModuleHandleW(null)),
        else => @compileError("Unsupported OS"),
    }
}

/// Tells whether calling the `execv` or `execve` functions will be a compile error.
pub const can_execv = switch (native_os) {
    .windows, .haiku, .wasi => false,
    else => true,
};

/// Tells whether spawning child processes is supported (e.g. via Child)
pub const can_spawn = switch (native_os) {
    .wasi, .watchos, .tvos, .visionos => false,
    else => true,
};

pub const ExecvError = std.posix.ExecveError || error{OutOfMemory};

/// Replaces the current process image with the executed process.
/// This function must allocate memory to add a null terminating bytes on path and each arg.
/// It must also convert to KEY=VALUE\0 format for environment variables, and include null
/// pointers after the args and after the environment variables.
/// `argv[0]` is the executable path.
/// This function also uses the PATH environment variable to get the full path to the executable.
/// Due to the heap-allocation, it is illegal to call this function in a fork() child.
/// For that use case, use the `std.posix` functions directly.
pub fn execv(allocator: Allocator, argv: []const []const u8) ExecvError {
    return execve(allocator, argv, null);
}

/// Replaces the current process image with the executed process.
/// This function must allocate memory to add a null terminating bytes on path and each arg.
/// It must also convert to KEY=VALUE\0 format for environment variables, and include null
/// pointers after the args and after the environment variables.
/// `argv[0]` is the executable path.
/// This function also uses the PATH environment variable to get the full path to the executable.
/// Due to the heap-allocation, it is illegal to call this function in a fork() child.
/// For that use case, use the `std.posix` functions directly.
pub fn execve(
    allocator: Allocator,
    argv: []const []const u8,
    env_map: ?*const EnvMap,
) ExecvError {
    if (!can_execv) @compileError("The target OS does not support execv");

    var arena_allocator = std.heap.ArenaAllocator.init(allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const argv_buf = try arena.allocSentinel(?[*:0]const u8, argv.len, null);
    for (argv, 0..) |arg, i| argv_buf[i] = (try arena.dupeZ(u8, arg)).ptr;

    const envp = m: {
        if (env_map) |m| {
            const envp_buf = try createNullDelimitedEnvMap(arena, m);
            break :m envp_buf.ptr;
        } else if (builtin.link_libc) {
            break :m std.c.environ;
        } else if (builtin.output_mode == .Exe) {
            // Then we have Zig start code and this works.
            // TODO type-safety for null-termination of `os.environ`.
            break :m @as([*:null]const ?[*:0]const u8, @ptrCast(std.os.environ.ptr));
        } else {
            // TODO come up with a solution for this.
            @compileError("missing std lib enhancement: std.process.execv implementation has no way to collect the environment variables to forward to the child process");
        }
    };

    return posix.execvpeZ_expandArg0(.no_expand, argv_buf.ptr[0].?, argv_buf.ptr, envp);
}

pub const TotalSystemMemoryError = error{
    UnknownTotalSystemMemory,
};

/// Returns the total system memory, in bytes as a u64.
/// We return a u64 instead of usize due to PAE on ARM
/// and Linux's /proc/meminfo reporting more memory when
/// using QEMU user mode emulation.
pub fn totalSystemMemory() TotalSystemMemoryError!u64 {
    switch (native_os) {
        .linux => {
            var info: std.os.linux.Sysinfo = undefined;
            const result: usize = std.os.linux.sysinfo(&info);
            if (std.os.linux.E.init(result) != .SUCCESS) {
                return error.UnknownTotalSystemMemory;
            }
            return info.totalram * info.mem_unit;
        },
        .freebsd => {
            var physmem: c_ulong = undefined;
            var len: usize = @sizeOf(c_ulong);
            posix.sysctlbynameZ("hw.physmem", &physmem, &len, null, 0) catch |err| switch (err) {
                error.NameTooLong, error.UnknownName => unreachable,
                else => return error.UnknownTotalSystemMemory,
            };
            return @as(usize, @intCast(physmem));
        },
        .openbsd => {
            const mib: [2]c_int = [_]c_int{
                posix.CTL.HW,
                posix.HW.PHYSMEM64,
            };
            var physmem: i64 = undefined;
            var len: usize = @sizeOf(@TypeOf(physmem));
            posix.sysctl(&mib, &physmem, &len, null, 0) catch |err| switch (err) {
                error.NameTooLong => unreachable, // constant, known good value
                error.PermissionDenied => unreachable, // only when setting values,
                error.SystemResources => unreachable, // memory already on the stack
                error.UnknownName => unreachable, // constant, known good value
                else => return error.UnknownTotalSystemMemory,
            };
            assert(physmem >= 0);
            return @as(u64, @bitCast(physmem));
        },
        .windows => {
            var sbi: windows.SYSTEM_BASIC_INFORMATION = undefined;
            const rc = windows.ntdll.NtQuerySystemInformation(
                .SystemBasicInformation,
                &sbi,
                @sizeOf(windows.SYSTEM_BASIC_INFORMATION),
                null,
            );
            if (rc != .SUCCESS) {
                return error.UnknownTotalSystemMemory;
            }
            return @as(u64, sbi.NumberOfPhysicalPages) * sbi.PageSize;
        },
        else => return error.UnknownTotalSystemMemory,
    }
}

/// Indicate that we are now terminating with a successful exit code.
/// In debug builds, this is a no-op, so that the calling code's
/// cleanup mechanisms are tested and so that external tools that
/// check for resource leaks can be accurate. In release builds, this
/// calls exit(0), and does not return.
pub fn cleanExit() void {
    if (builtin.mode == .Debug) {
        return;
    } else {
        std.debug.lockStdErr();
        exit(0);
    }
}

/// Raise the open file descriptor limit.
///
/// On some systems, this raises the limit before seeing ProcessFdQuotaExceeded
/// errors. On other systems, this does nothing.
pub fn raiseFileDescriptorLimit() void {
    const have_rlimit = posix.rlimit_resource != void;
    if (!have_rlimit) return;

    var lim = posix.getrlimit(.NOFILE) catch return; // Oh well; we tried.
    if (native_os.isDarwin()) {
        // On Darwin, `NOFILE` is bounded by a hardcoded value `OPEN_MAX`.
        // According to the man pages for setrlimit():
        //   setrlimit() now returns with errno set to EINVAL in places that historically succeeded.
        //   It no longer accepts "rlim_cur = RLIM.INFINITY" for RLIM.NOFILE.
        //   Use "rlim_cur = min(OPEN_MAX, rlim_max)".
        lim.max = @min(std.c.OPEN_MAX, lim.max);
    }
    if (lim.cur == lim.max) return;

    // Do a binary search for the limit.
    var min: posix.rlim_t = lim.cur;
    var max: posix.rlim_t = 1 << 20;
    // But if there's a defined upper bound, don't search, just set it.
    if (lim.max != posix.RLIM.INFINITY) {
        min = lim.max;
        max = lim.max;
    }

    while (true) {
        lim.cur = min + @divTrunc(max - min, 2); // on freebsd rlim_t is signed
        if (posix.setrlimit(.NOFILE, lim)) |_| {
            min = lim.cur;
        } else |_| {
            max = lim.cur;
        }
        if (min + 1 >= max) break;
    }
}

test raiseFileDescriptorLimit {
    raiseFileDescriptorLimit();
}

pub const CreateEnvironOptions = struct {
    /// `null` means to leave the `ZIG_PROGRESS` environment variable unmodified.
    /// If non-null, negative means to remove the environment variable, and >= 0
    /// means to provide it with the given integer.
    zig_progress_fd: ?i32 = null,
};

/// Creates a null-delimited environment variable block in the format
/// expected by POSIX, from a hash map plus options.
pub fn createEnvironFromMap(
    arena: Allocator,
    map: *const EnvMap,
    options: CreateEnvironOptions,
) Allocator.Error![:null]?[*:0]u8 {
    const ZigProgressAction = enum { nothing, edit, delete, add };
    const zig_progress_action: ZigProgressAction = a: {
        const fd = options.zig_progress_fd orelse break :a .nothing;
        const contains = map.get("ZIG_PROGRESS") != null;
        if (fd >= 0) {
            break :a if (contains) .edit else .add;
        } else {
            if (contains) break :a .delete;
        }
        break :a .nothing;
    };

    const envp_count: usize = c: {
        var count: usize = map.count();
        switch (zig_progress_action) {
            .add => count += 1,
            .delete => count -= 1,
            .nothing, .edit => {},
        }
        break :c count;
    };

    const envp_buf = try arena.allocSentinel(?[*:0]u8, envp_count, null);
    var i: usize = 0;

    if (zig_progress_action == .add) {
        envp_buf[i] = try std.fmt.allocPrintZ(arena, "ZIG_PROGRESS={d}", .{options.zig_progress_fd.?});
        i += 1;
    }

    {
        var it = map.iterator();
        while (it.next()) |pair| {
            if (mem.eql(u8, pair.key_ptr.*, "ZIG_PROGRESS")) switch (zig_progress_action) {
                .add => unreachable,
                .delete => continue,
                .edit => {
                    envp_buf[i] = try std.fmt.allocPrintZ(arena, "{s}={d}", .{
                        pair.key_ptr.*, options.zig_progress_fd.?,
                    });
                    i += 1;
                    continue;
                },
                .nothing => {},
            };

            envp_buf[i] = try std.fmt.allocPrintZ(arena, "{s}={s}", .{ pair.key_ptr.*, pair.value_ptr.* });
            i += 1;
        }
    }

    assert(i == envp_count);
    return envp_buf;
}

/// Creates a null-delimited environment variable block in the format
/// expected by POSIX, from a hash map plus options.
pub fn createEnvironFromExisting(
    arena: Allocator,
    existing: [*:null]const ?[*:0]const u8,
    options: CreateEnvironOptions,
) Allocator.Error![:null]?[*:0]u8 {
    const existing_count, const contains_zig_progress = c: {
        var count: usize = 0;
        var contains = false;
        while (existing[count]) |line| : (count += 1) {
            contains = contains or mem.eql(u8, mem.sliceTo(line, '='), "ZIG_PROGRESS");
        }
        break :c .{ count, contains };
    };
    const ZigProgressAction = enum { nothing, edit, delete, add };
    const zig_progress_action: ZigProgressAction = a: {
        const fd = options.zig_progress_fd orelse break :a .nothing;
        if (fd >= 0) {
            break :a if (contains_zig_progress) .edit else .add;
        } else {
            if (contains_zig_progress) break :a .delete;
        }
        break :a .nothing;
    };

    const envp_count: usize = c: {
        var count: usize = existing_count;
        switch (zig_progress_action) {
            .add => count += 1,
            .delete => count -= 1,
            .nothing, .edit => {},
        }
        break :c count;
    };

    const envp_buf = try arena.allocSentinel(?[*:0]u8, envp_count, null);
    var i: usize = 0;
    var existing_index: usize = 0;

    if (zig_progress_action == .add) {
        envp_buf[i] = try std.fmt.allocPrintZ(arena, "ZIG_PROGRESS={d}", .{options.zig_progress_fd.?});
        i += 1;
    }

    while (existing[existing_index]) |line| : (existing_index += 1) {
        if (mem.eql(u8, mem.sliceTo(line, '='), "ZIG_PROGRESS")) switch (zig_progress_action) {
            .add => unreachable,
            .delete => continue,
            .edit => {
                envp_buf[i] = try std.fmt.allocPrintZ(arena, "ZIG_PROGRESS={d}", .{options.zig_progress_fd.?});
                i += 1;
                continue;
            },
            .nothing => {},
        };
        envp_buf[i] = try arena.dupeZ(u8, mem.span(line));
        i += 1;
    }

    assert(i == envp_count);
    return envp_buf;
}

pub fn createNullDelimitedEnvMap(arena: mem.Allocator, env_map: *const EnvMap) Allocator.Error![:null]?[*:0]u8 {
    return createEnvironFromMap(arena, env_map, .{});
}

test createNullDelimitedEnvMap {
    const allocator = testing.allocator;
    var envmap = EnvMap.init(allocator);
    defer envmap.deinit();

    try envmap.put("HOME", "/home/ifreund");
    try envmap.put("WAYLAND_DISPLAY", "wayland-1");
    try envmap.put("DISPLAY", ":1");
    try envmap.put("DEBUGINFOD_URLS", " ");
    try envmap.put("XCURSOR_SIZE", "24");

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const environ = try createNullDelimitedEnvMap(arena.allocator(), &envmap);

    try testing.expectEqual(@as(usize, 5), environ.len);

    inline for (.{
        "HOME=/home/ifreund",
        "WAYLAND_DISPLAY=wayland-1",
        "DISPLAY=:1",
        "DEBUGINFOD_URLS= ",
        "XCURSOR_SIZE=24",
    }) |target| {
        for (environ) |variable| {
            if (mem.eql(u8, mem.span(variable orelse continue), target)) break;
        } else {
            try testing.expect(false); // Environment variable not found
        }
    }
}

/// Caller must free result.
pub fn createWindowsEnvBlock(allocator: mem.Allocator, env_map: *const EnvMap) ![]u16 {
    // count bytes needed
    const max_chars_needed = x: {
        // Only need 2 trailing NUL code units for an empty environment
        var max_chars_needed: usize = if (env_map.count() == 0) 2 else 1;
        var it = env_map.iterator();
        while (it.next()) |pair| {
            // +1 for '='
            // +1 for null byte
            max_chars_needed += pair.key_ptr.len + pair.value_ptr.len + 2;
        }
        break :x max_chars_needed;
    };
    const result = try allocator.alloc(u16, max_chars_needed);
    errdefer allocator.free(result);

    var it = env_map.iterator();
    var i: usize = 0;
    while (it.next()) |pair| {
        i += try unicode.wtf8ToWtf16Le(result[i..], pair.key_ptr.*);
        result[i] = '=';
        i += 1;
        i += try unicode.wtf8ToWtf16Le(result[i..], pair.value_ptr.*);
        result[i] = 0;
        i += 1;
    }
    result[i] = 0;
    i += 1;
    // An empty environment is a special case that requires a redundant
    // NUL terminator. CreateProcess will read the second code unit even
    // though theoretically the first should be enough to recognize that the
    // environment is empty (see https://nullprogram.com/blog/2023/08/23/)
    if (env_map.count() == 0) {
        result[i] = 0;
        i += 1;
    }
    return try allocator.realloc(result, i);
}

/// Logs an error and then terminates the process with exit code 1.
pub fn fatal(comptime format: []const u8, format_arguments: anytype) noreturn {
    std.log.err(format, format_arguments);
    exit(1);
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const unicode = std.unicode;
const fs = std.fs;
const process = std.process;
const File = std.fs.File;
const windows = std.os.windows;
const linux = std.os.linux;
const posix = std.posix;
const mem = std.mem;
const EnvMap = std.process.EnvMap;
const maxInt = std.math.maxInt;
const assert = std.debug.assert;
const native_os = builtin.os.tag;
const Allocator = std.mem.Allocator;
const ChildProcess = @This();

pub const Id = switch (native_os) {
    .windows => windows.HANDLE,
    .wasi => void,
    else => posix.pid_t,
};

/// Available after calling `spawn()`. This becomes `undefined` after calling `wait()`.
/// On Windows this is the hProcess.
/// On POSIX this is the pid.
id: Id,
thread_handle: if (native_os == .windows) windows.HANDLE else void,

allocator: mem.Allocator,

/// The writing end of the child process's standard input pipe.
/// Usage requires `stdin_behavior == StdIo.Pipe`.
/// Available after calling `spawn()`.
stdin: ?File,

/// The reading end of the child process's standard output pipe.
/// Usage requires `stdout_behavior == StdIo.Pipe`.
/// Available after calling `spawn()`.
stdout: ?File,

/// The reading end of the child process's standard error pipe.
/// Usage requires `stderr_behavior == StdIo.Pipe`.
/// Available after calling `spawn()`.
stderr: ?File,

/// Terminated state of the child process.
/// Available after calling `wait()`.
term: ?(SpawnError!Term),

argv: []const []const u8,

/// Leave as null to use the current env map using the supplied allocator.
env_map: ?*const EnvMap,

stdin_behavior: StdIo,
stdout_behavior: StdIo,
stderr_behavior: StdIo,

/// Set to change the user id when spawning the child process.
uid: if (native_os == .windows or native_os == .wasi) void else ?posix.uid_t,

/// Set to change the group id when spawning the child process.
gid: if (native_os == .windows or native_os == .wasi) void else ?posix.gid_t,

/// Set to change the process group id when spawning the child process.
pgid: if (native_os == .windows or native_os == .wasi) void else ?posix.pid_t,

/// Set to change the current working directory when spawning the child process.
cwd: ?[]const u8,
/// Set to change the current working directory when spawning the child process.
/// This is not yet implemented for Windows. See https://github.com/ziglang/zig/issues/5190
/// Once that is done, `cwd` will be deprecated in favor of this field.
cwd_dir: ?fs.Dir = null,

err_pipe: if (native_os == .windows) void else ?posix.fd_t,

expand_arg0: Arg0Expand,

/// Darwin-only. Disable ASLR for the child process.
disable_aslr: bool = false,

/// Darwin and Windows only. Start child process in suspended state. For Darwin it's started
/// as if SIGSTOP was sent.
start_suspended: bool = false,

/// Windows-only. Sets the CREATE_NO_WINDOW flag in CreateProcess.
create_no_window: bool = false,

/// Set to true to obtain rusage information for the child process.
/// Depending on the target platform and implementation status, the
/// requested statistics may or may not be available. If they are
/// available, then the `resource_usage_statistics` field will be populated
/// after calling `wait`.
/// On Linux and Darwin, this obtains rusage statistics from wait4().
request_resource_usage_statistics: bool = false,

/// This is available after calling wait if
/// `request_resource_usage_statistics` was set to `true` before calling
/// `spawn`.
resource_usage_statistics: ResourceUsageStatistics = .{},

/// When populated, a pipe will be created for the child process to
/// communicate progress back to the parent. The file descriptor of the
/// write end of the pipe will be specified in the `ZIG_PROGRESS`
/// environment variable inside the child process. The progress reported by
/// the child will be attached to this progress node in the parent process.
///
/// The child's progress tree will be grafted into the parent's progress tree,
/// by substituting this node with the child's root node.
progress_node: std.Progress.Node = std.Progress.Node.none,

pub const ResourceUsageStatistics = struct {
    rusage: @TypeOf(rusage_init) = rusage_init,

    /// Returns the peak resident set size of the child process, in bytes,
    /// if available.
    pub inline fn getMaxRss(rus: ResourceUsageStatistics) ?usize {
        switch (native_os) {
            .linux => {
                if (rus.rusage) |ru| {
                    return @as(usize, @intCast(ru.maxrss)) * 1024;
                } else {
                    return null;
                }
            },
            .windows => {
                if (rus.rusage) |ru| {
                    return ru.PeakWorkingSetSize;
                } else {
                    return null;
                }
            },
            .macos, .ios => {
                if (rus.rusage) |ru| {
                    // Darwin oddly reports in bytes instead of kilobytes.
                    return @as(usize, @intCast(ru.maxrss));
                } else {
                    return null;
                }
            },
            else => return null,
        }
    }

    const rusage_init = switch (native_os) {
        .linux, .macos, .ios => @as(?posix.rusage, null),
        .windows => @as(?windows.VM_COUNTERS, null),
        else => {},
    };
};

pub const Arg0Expand = posix.Arg0Expand;

pub const SpawnError = error{
    OutOfMemory,

    /// POSIX-only. `StdIo.Ignore` was selected and opening `/dev/null` returned ENODEV.
    NoDevice,

    /// Windows-only. `cwd` or `argv` was provided and it was invalid WTF-8.
    /// https://simonsapin.github.io/wtf-8/
    InvalidWtf8,

    /// Windows-only. `cwd` was provided, but the path did not exist when spawning the child process.
    CurrentWorkingDirectoryUnlinked,

    /// Windows-only. NUL (U+0000), LF (U+000A), CR (U+000D) are not allowed
    /// within arguments when executing a `.bat`/`.cmd` script.
    /// - NUL/LF signifiies end of arguments, so anything afterwards
    ///   would be lost after execution.
    /// - CR is stripped by `cmd.exe`, so any CR codepoints
    ///   would be lost after execution.
    InvalidBatchScriptArg,
} ||
    posix.ExecveError ||
    posix.SetIdError ||
    posix.SetPgidError ||
    posix.ChangeCurDirError ||
    windows.CreateProcessError ||
    windows.GetProcessMemoryInfoError ||
    windows.WaitForSingleObjectError;

pub const Term = union(enum) {
    Exited: u8,
    Signal: u32,
    Stopped: u32,
    Unknown: u32,
};

/// Behavior of the child process's standard input, output, and error
/// streams.
pub const StdIo = enum {
    /// Inherit the stream from the parent process.
    Inherit,

    /// Pass a null stream to the child process.
    /// This is /dev/null on POSIX and NUL on Windows.
    Ignore,

    /// Create a pipe for the stream.
    /// The corresponding field (`stdout`, `stderr`, or `stdin`)
    /// will be assigned a `File` object that can be used
    /// to read from or write to the pipe.
    Pipe,

    /// Close the stream after the child process spawns.
    Close,
};

/// First argument in argv is the executable.
pub fn init(argv: []const []const u8, allocator: mem.Allocator) ChildProcess {
    return .{
        .allocator = allocator,
        .argv = argv,
        .id = undefined,
        .thread_handle = undefined,
        .err_pipe = if (native_os == .windows) {} else null,
        .term = null,
        .env_map = null,
        .cwd = null,
        .uid = if (native_os == .windows or native_os == .wasi) {} else null,
        .gid = if (native_os == .windows or native_os == .wasi) {} else null,
        .pgid = if (native_os == .windows or native_os == .wasi) {} else null,
        .stdin = null,
        .stdout = null,
        .stderr = null,
        .stdin_behavior = .Inherit,
        .stdout_behavior = .Inherit,
        .stderr_behavior = .Inherit,
        .expand_arg0 = .no_expand,
    };
}

pub fn setUserName(self: *ChildProcess, name: []const u8) !void {
    const user_info = try process.getUserInfo(name);
    self.uid = user_info.uid;
    self.gid = user_info.gid;
}

/// On success must call `kill` or `wait`.
/// After spawning the `id` is available.
pub fn spawn(self: *ChildProcess) SpawnError!void {
    if (!process.can_spawn) {
        @compileError("the target operating system cannot spawn processes");
    }

    if (native_os == .windows) {
        return self.spawnWindows();
    } else {
        return self.spawnPosix();
    }
}

pub fn spawnAndWait(self: *ChildProcess) SpawnError!Term {
    try self.spawn();
    return self.wait();
}

/// Forcibly terminates child process and then cleans up all resources.
pub fn kill(self: *ChildProcess) !Term {
    if (native_os == .windows) {
        return self.killWindows(1);
    } else {
        return self.killPosix();
    }
}

pub fn killWindows(self: *ChildProcess, exit_code: windows.UINT) !Term {
    if (self.term) |term| {
        self.cleanupStreams();
        return term;
    }

    windows.TerminateProcess(self.id, exit_code) catch |err| switch (err) {
        error.AccessDenied => {
            // Usually when TerminateProcess triggers a ACCESS_DENIED error, it
            // indicates that the process has already exited, but there may be
            // some rare edge cases where our process handle no longer has the
            // PROCESS_TERMINATE access right, so let's do another check to make
            // sure the process is really no longer running:
            windows.WaitForSingleObjectEx(self.id, 0, false) catch return err;
            return error.AlreadyTerminated;
        },
        else => return err,
    };
    try self.waitUnwrappedWindows();
    return self.term.?;
}

pub fn killPosix(self: *ChildProcess) !Term {
    if (self.term) |term| {
        self.cleanupStreams();
        return term;
    }
    posix.kill(self.id, posix.SIG.TERM) catch |err| switch (err) {
        error.ProcessNotFound => return error.AlreadyTerminated,
        else => return err,
    };
    self.waitUnwrappedPosix();
    return self.term.?;
}

pub const WaitError = SpawnError || std.os.windows.GetProcessMemoryInfoError;

/// On some targets, `spawn` may not report all spawn errors, such as `error.InvalidExe`.
/// This function will block until any spawn errors can be reported, and return them.
pub fn waitForSpawn(self: *ChildProcess) SpawnError!void {
    if (native_os == .windows) return; // `spawn` reports everything
    if (self.term) |term| {
        _ = term catch |spawn_err| return spawn_err;
        return;
    }

    const err_pipe = self.err_pipe orelse return;
    self.err_pipe = null;

    // Wait for the child to report any errors in or before `execvpe`.
    if (readIntFd(err_pipe)) |child_err_int| {
        posix.close(err_pipe);
        const child_err: SpawnError = @errorCast(@errorFromInt(child_err_int));
        self.term = child_err;
        return child_err;
    } else |_| {
        // Write end closed by CLOEXEC at the time of the `execvpe` call, indicating success!
        posix.close(err_pipe);
    }
}

/// Blocks until child process terminates and then cleans up all resources.
pub fn wait(self: *ChildProcess) WaitError!Term {
    try self.waitForSpawn(); // report spawn errors
    if (self.term) |term| {
        self.cleanupStreams();
        return term;
    }
    switch (native_os) {
        .windows => try self.waitUnwrappedWindows(),
        else => self.waitUnwrappedPosix(),
    }
    self.id = undefined;
    return self.term.?;
}

pub const RunResult = struct {
    term: Term,
    stdout: []u8,
    stderr: []u8,
};

fn writeFifoDataToArrayList(allocator: Allocator, list: *std.ArrayListUnmanaged(u8), fifo: *std.io.PollFifo) !void {
    if (fifo.head != 0) fifo.realign();
    if (list.capacity == 0) {
        list.* = .{
            .items = fifo.buf[0..fifo.count],
            .capacity = fifo.buf.len,
        };
        fifo.* = std.io.PollFifo.init(fifo.allocator);
    } else {
        try list.appendSlice(allocator, fifo.buf[0..fifo.count]);
    }
}

/// Collect the output from the process's stdout and stderr. Will return once all output
/// has been collected. This does not mean that the process has ended. `wait` should still
/// be called to wait for and clean up the process.
///
/// The process must be started with stdout_behavior and stderr_behavior == .Pipe
pub fn collectOutput(
    child: ChildProcess,
    /// Used for `stdout` and `stderr`.
    allocator: Allocator,
    stdout: *std.ArrayListUnmanaged(u8),
    stderr: *std.ArrayListUnmanaged(u8),
    max_output_bytes: usize,
) !void {
    assert(child.stdout_behavior == .Pipe);
    assert(child.stderr_behavior == .Pipe);

    var poller = std.io.poll(allocator, enum { stdout, stderr }, .{
        .stdout = child.stdout.?,
        .stderr = child.stderr.?,
    });
    defer poller.deinit();

    while (try poller.poll()) {
        if (poller.fifo(.stdout).count > max_output_bytes)
            return error.StdoutStreamTooLong;
        if (poller.fifo(.stderr).count > max_output_bytes)
            return error.StderrStreamTooLong;
    }

    try writeFifoDataToArrayList(allocator, stdout, poller.fifo(.stdout));
    try writeFifoDataToArrayList(allocator, stderr, poller.fifo(.stderr));
}

pub const RunError = posix.GetCwdError || posix.ReadError || SpawnError || posix.PollError || error{
    StdoutStreamTooLong,
    StderrStreamTooLong,
};

/// Spawns a child process, waits for it, collecting stdout and stderr, and then returns.
/// If it succeeds, the caller owns result.stdout and result.stderr memory.
pub fn run(args: struct {
    allocator: mem.Allocator,
    argv: []const []const u8,
    cwd: ?[]const u8 = null,
    cwd_dir: ?fs.Dir = null,
    env_map: ?*const EnvMap = null,
    max_output_bytes: usize = 50 * 1024,
    expand_arg0: Arg0Expand = .no_expand,
    progress_node: std.Progress.Node = std.Progress.Node.none,
}) RunError!RunResult {
    var child = ChildProcess.init(args.argv, args.allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.cwd = args.cwd;
    child.cwd_dir = args.cwd_dir;
    child.env_map = args.env_map;
    child.expand_arg0 = args.expand_arg0;
    child.progress_node = args.progress_node;

    var stdout: std.ArrayListUnmanaged(u8) = .empty;
    errdefer stdout.deinit(args.allocator);
    var stderr: std.ArrayListUnmanaged(u8) = .empty;
    errdefer stderr.deinit(args.allocator);

    try child.spawn();
    errdefer {
        _ = child.kill() catch {};
    }
    try child.collectOutput(args.allocator, &stdout, &stderr, args.max_output_bytes);

    return RunResult{
        .stdout = try stdout.toOwnedSlice(args.allocator),
        .stderr = try stderr.toOwnedSlice(args.allocator),
        .term = try child.wait(),
    };
}

fn waitUnwrappedWindows(self: *ChildProcess) WaitError!void {
    const result = windows.WaitForSingleObjectEx(self.id, windows.INFINITE, false);

    self.term = @as(SpawnError!Term, x: {
        var exit_code: windows.DWORD = undefined;
        if (windows.kernel32.GetExitCodeProcess(self.id, &exit_code) == 0) {
            break :x Term{ .Unknown = 0 };
        } else {
            break :x Term{ .Exited = @as(u8, @truncate(exit_code)) };
        }
    });

    if (self.request_resource_usage_statistics) {
        self.resource_usage_statistics.rusage = try windows.GetProcessMemoryInfo(self.id);
    }

    posix.close(self.id);
    posix.close(self.thread_handle);
    self.cleanupStreams();
    return result;
}

fn waitUnwrappedPosix(self: *ChildProcess) void {
    const res: posix.WaitPidResult = res: {
        if (self.request_resource_usage_statistics) {
            switch (native_os) {
                .linux, .macos, .ios => {
                    var ru: posix.rusage = undefined;
                    const res = posix.wait4(self.id, 0, &ru);
                    self.resource_usage_statistics.rusage = ru;
                    break :res res;
                },
                else => {},
            }
        }

        break :res posix.waitpid(self.id, 0);
    };
    const status = res.status;
    self.cleanupStreams();
    self.handleWaitResult(status);
}

fn handleWaitResult(self: *ChildProcess, status: u32) void {
    self.term = statusToTerm(status);
}

fn cleanupStreams(self: *ChildProcess) void {
    if (self.stdin) |*stdin| {
        stdin.close();
        self.stdin = null;
    }
    if (self.stdout) |*stdout| {
        stdout.close();
        self.stdout = null;
    }
    if (self.stderr) |*stderr| {
        stderr.close();
        self.stderr = null;
    }
}

fn statusToTerm(status: u32) Term {
    return if (posix.W.IFEXITED(status))
        Term{ .Exited = posix.W.EXITSTATUS(status) }
    else if (posix.W.IFSIGNALED(status))
        Term{ .Signal = posix.W.TERMSIG(status) }
    else if (posix.W.IFSTOPPED(status))
        Term{ .Stopped = posix.W.STOPSIG(status) }
    else
        Term{ .Unknown = status };
}

fn spawnPosix(self: *ChildProcess) SpawnError!void {
    // The child process does need to access (one end of) these pipes. However,
    // we must initially set CLOEXEC to avoid a race condition. If another thread
    // is racing to spawn a different child process, we don't want it to inherit
    // these FDs in any scenario; that would mean that, for instance, calls to
    // `poll` from the parent would not report the child's stdout as closing when
    // expected, since the other child may retain a reference to the write end of
    // the pipe. So, we create the pipes with CLOEXEC initially. After fork, we
    // need to do something in the new child to make sure we preserve the reference
    // we want. We could use `fcntl` to remove CLOEXEC from the FD, but as it
    // turns out, we `dup2` everything anyway, so there's no need!
    const pipe_flags: posix.O = .{ .CLOEXEC = true };

    const stdin_pipe = if (self.stdin_behavior == .Pipe) try posix.pipe2(pipe_flags) else undefined;
    errdefer if (self.stdin_behavior == .Pipe) {
        destroyPipe(stdin_pipe);
    };

    const stdout_pipe = if (self.stdout_behavior == .Pipe) try posix.pipe2(pipe_flags) else undefined;
    errdefer if (self.stdout_behavior == .Pipe) {
        destroyPipe(stdout_pipe);
    };

    const stderr_pipe = if (self.stderr_behavior == .Pipe) try posix.pipe2(pipe_flags) else undefined;
    errdefer if (self.stderr_behavior == .Pipe) {
        destroyPipe(stderr_pipe);
    };

    const any_ignore = (self.stdin_behavior == .Ignore or self.stdout_behavior == .Ignore or self.stderr_behavior == .Ignore);
    const dev_null_fd = if (any_ignore)
        posix.openZ("/dev/null", .{ .ACCMODE = .RDWR }, 0) catch |err| switch (err) {
            error.PathAlreadyExists => unreachable,
            error.NoSpaceLeft => unreachable,
            error.FileTooBig => unreachable,
            error.DeviceBusy => unreachable,
            error.FileLocksNotSupported => unreachable,
            error.BadPathName => unreachable, // Windows-only
            error.WouldBlock => unreachable,
            error.NetworkNotFound => unreachable, // Windows-only
            else => |e| return e,
        }
    else
        undefined;
    defer {
        if (any_ignore) posix.close(dev_null_fd);
    }

    const prog_pipe: [2]posix.fd_t = p: {
        if (self.progress_node.index == .none) {
            break :p .{ -1, -1 };
        } else {
            // We use CLOEXEC for the same reason as in `pipe_flags`.
            break :p try posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
        }
    };
    errdefer destroyPipe(prog_pipe);

    var arena_allocator = std.heap.ArenaAllocator.init(self.allocator);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    // The POSIX standard does not allow malloc() between fork() and execve(),
    // and `self.allocator` may be a libc allocator.
    // I have personally observed the child process deadlocking when it tries
    // to call malloc() due to a heap allocation between fork() and execve(),
    // in musl v1.1.24.
    // Additionally, we want to reduce the number of possible ways things
    // can fail between fork() and execve().
    // Therefore, we do all the allocation for the execve() before the fork().
    // This means we must do the null-termination of argv and env vars here.
    const argv_buf = try arena.allocSentinel(?[*:0]const u8, self.argv.len, null);
    for (self.argv, 0..) |arg, i| argv_buf[i] = (try arena.dupeZ(u8, arg)).ptr;

    const prog_fileno = 3;
    comptime assert(@max(posix.STDIN_FILENO, posix.STDOUT_FILENO, posix.STDERR_FILENO) + 1 == prog_fileno);

    const envp: [*:null]const ?[*:0]const u8 = m: {
        const prog_fd: i32 = if (prog_pipe[1] == -1) -1 else prog_fileno;
        if (self.env_map) |env_map| {
            break :m (try process.createEnvironFromMap(arena, env_map, .{
                .zig_progress_fd = prog_fd,
            })).ptr;
        } else if (builtin.link_libc) {
            break :m (try process.createEnvironFromExisting(arena, std.c.environ, .{
                .zig_progress_fd = prog_fd,
            })).ptr;
        } else if (builtin.output_mode == .Exe) {
            // Then we have Zig start code and this works.
            // TODO type-safety for null-termination of `os.environ`.
            break :m (try process.createEnvironFromExisting(arena, @ptrCast(std.os.environ.ptr), .{
                .zig_progress_fd = prog_fd,
            })).ptr;
        } else {
            // TODO come up with a solution for this.
            @compileError("missing std lib enhancement: ChildProcess implementation has no way to collect the environment variables to forward to the child process");
        }
    };

    // This pipe communicates to the parent errors in the child between `fork` and `execvpe`.
    // It is closed by the child (via CLOEXEC) without writing if `execvpe` succeeds.
    const err_pipe: [2]posix.fd_t = try posix.pipe2(.{ .CLOEXEC = true });
    errdefer destroyPipe(err_pipe);

    const pid_result = try posix.fork();
    if (pid_result == 0) {
        // we are the child
        setUpChildIo(self.stdin_behavior, stdin_pipe[0], posix.STDIN_FILENO, dev_null_fd) catch |err| forkChildErrReport(err_pipe[1], err);
        setUpChildIo(self.stdout_behavior, stdout_pipe[1], posix.STDOUT_FILENO, dev_null_fd) catch |err| forkChildErrReport(err_pipe[1], err);
        setUpChildIo(self.stderr_behavior, stderr_pipe[1], posix.STDERR_FILENO, dev_null_fd) catch |err| forkChildErrReport(err_pipe[1], err);

        if (self.cwd_dir) |cwd| {
            posix.fchdir(cwd.fd) catch |err| forkChildErrReport(err_pipe[1], err);
        } else if (self.cwd) |cwd| {
            posix.chdir(cwd) catch |err| forkChildErrReport(err_pipe[1], err);
        }

        // Must happen after fchdir above, the cwd file descriptor might be
        // equal to prog_fileno and be clobbered by this dup2 call.
        if (prog_pipe[1] != -1) posix.dup2(prog_pipe[1], prog_fileno) catch |err| forkChildErrReport(err_pipe[1], err);

        if (self.gid) |gid| {
            posix.setregid(gid, gid) catch |err| forkChildErrReport(err_pipe[1], err);
        }

        if (self.uid) |uid| {
            posix.setreuid(uid, uid) catch |err| forkChildErrReport(err_pipe[1], err);
        }

        if (self.pgid) |pid| {
            posix.setpgid(0, pid) catch |err| forkChildErrReport(err_pipe[1], err);
        }

        const err = switch (self.expand_arg0) {
            .expand => posix.execvpeZ_expandArg0(.expand, argv_buf.ptr[0].?, argv_buf.ptr, envp),
            .no_expand => posix.execvpeZ_expandArg0(.no_expand, argv_buf.ptr[0].?, argv_buf.ptr, envp),
        };
        forkChildErrReport(err_pipe[1], err);
    }

    // we are the parent
    errdefer comptime unreachable; // The child is forked; we must not error from now on

    posix.close(err_pipe[1]); // make sure only the child holds the write end open
    self.err_pipe = err_pipe[0];

    const pid: i32 = @intCast(pid_result);
    if (self.stdin_behavior == .Pipe) {
        self.stdin = .{ .handle = stdin_pipe[1] };
    } else {
        self.stdin = null;
    }
    if (self.stdout_behavior == .Pipe) {
        self.stdout = .{ .handle = stdout_pipe[0] };
    } else {
        self.stdout = null;
    }
    if (self.stderr_behavior == .Pipe) {
        self.stderr = .{ .handle = stderr_pipe[0] };
    } else {
        self.stderr = null;
    }

    self.id = pid;
    self.term = null;

    if (self.stdin_behavior == .Pipe) {
        posix.close(stdin_pipe[0]);
    }
    if (self.stdout_behavior == .Pipe) {
        posix.close(stdout_pipe[1]);
    }
    if (self.stderr_behavior == .Pipe) {
        posix.close(stderr_pipe[1]);
    }

    if (prog_pipe[1] != -1) {
        posix.close(prog_pipe[1]);
    }
    self.progress_node.setIpcFd(prog_pipe[0]);
}

fn spawnWindows(self: *ChildProcess) SpawnError!void {
    var saAttr = windows.SECURITY_ATTRIBUTES{
        .nLength = @sizeOf(windows.SECURITY_ATTRIBUTES),
        .bInheritHandle = windows.TRUE,
        .lpSecurityDescriptor = null,
    };

    const any_ignore = (self.stdin_behavior == StdIo.Ignore or self.stdout_behavior == StdIo.Ignore or self.stderr_behavior == StdIo.Ignore);

    const nul_handle = if (any_ignore)
        // "\Device\Null" or "\??\NUL"
        windows.OpenFile(&[_]u16{ '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'N', 'u', 'l', 'l' }, .{
            .access_mask = windows.GENERIC_READ | windows.GENERIC_WRITE | windows.SYNCHRONIZE,
            .share_access = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE,
            .sa = &saAttr,
            .creation = windows.OPEN_EXISTING,
        }) catch |err| switch (err) {
            error.PathAlreadyExists => return error.Unexpected, // not possible for "NUL"
            error.PipeBusy => return error.Unexpected, // not possible for "NUL"
            error.NoDevice => return error.Unexpected, // not possible for "NUL"
            error.FileNotFound => return error.Unexpected, // not possible for "NUL"
            error.AccessDenied => return error.Unexpected, // not possible for "NUL"
            error.NameTooLong => return error.Unexpected, // not possible for "NUL"
            error.WouldBlock => return error.Unexpected, // not possible for "NUL"
            error.NetworkNotFound => return error.Unexpected, // not possible for "NUL"
            error.AntivirusInterference => return error.Unexpected, // not possible for "NUL"
            else => |e| return e,
        }
    else
        undefined;
    defer {
        if (any_ignore) posix.close(nul_handle);
    }

    var g_hChildStd_IN_Rd: ?windows.HANDLE = null;
    var g_hChildStd_IN_Wr: ?windows.HANDLE = null;
    switch (self.stdin_behavior) {
        StdIo.Pipe => {
            try windowsMakePipeIn(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr);
        },
        StdIo.Ignore => {
            g_hChildStd_IN_Rd = nul_handle;
        },
        StdIo.Inherit => {
            g_hChildStd_IN_Rd = windows.GetStdHandle(windows.STD_INPUT_HANDLE) catch null;
        },
        StdIo.Close => {
            g_hChildStd_IN_Rd = null;
        },
    }
    errdefer if (self.stdin_behavior == StdIo.Pipe) {
        windowsDestroyPipe(g_hChildStd_IN_Rd, g_hChildStd_IN_Wr);
    };

    var g_hChildStd_OUT_Rd: ?windows.HANDLE = null;
    var g_hChildStd_OUT_Wr: ?windows.HANDLE = null;
    switch (self.stdout_behavior) {
        StdIo.Pipe => {
            try windowsMakeAsyncPipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr);
        },
        StdIo.Ignore => {
            g_hChildStd_OUT_Wr = nul_handle;
        },
        StdIo.Inherit => {
            g_hChildStd_OUT_Wr = windows.GetStdHandle(windows.STD_OUTPUT_HANDLE) catch null;
        },
        StdIo.Close => {
            g_hChildStd_OUT_Wr = null;
        },
    }
    errdefer if (self.stdout_behavior == StdIo.Pipe) {
        windowsDestroyPipe(g_hChildStd_OUT_Rd, g_hChildStd_OUT_Wr);
    };

    var g_hChildStd_ERR_Rd: ?windows.HANDLE = null;
    var g_hChildStd_ERR_Wr: ?windows.HANDLE = null;
    switch (self.stderr_behavior) {
        StdIo.Pipe => {
            try windowsMakeAsyncPipe(&g_hChildStd_ERR_Rd, &g_hChildStd_ERR_Wr, &saAttr);
        },
        StdIo.Ignore => {
            g_hChildStd_ERR_Wr = nul_handle;
        },
        StdIo.Inherit => {
            g_hChildStd_ERR_Wr = windows.GetStdHandle(windows.STD_ERROR_HANDLE) catch null;
        },
        StdIo.Close => {
            g_hChildStd_ERR_Wr = null;
        },
    }
    errdefer if (self.stderr_behavior == StdIo.Pipe) {
        windowsDestroyPipe(g_hChildStd_ERR_Rd, g_hChildStd_ERR_Wr);
    };

    var siStartInfo = windows.STARTUPINFOW{
        .cb = @sizeOf(windows.STARTUPINFOW),
        .hStdError = g_hChildStd_ERR_Wr,
        .hStdOutput = g_hChildStd_OUT_Wr,
        .hStdInput = g_hChildStd_IN_Rd,
        .dwFlags = windows.STARTF_USESTDHANDLES,

        .lpReserved = null,
        .lpDesktop = null,
        .lpTitle = null,
        .dwX = 0,
        .dwY = 0,
        .dwXSize = 0,
        .dwYSize = 0,
        .dwXCountChars = 0,
        .dwYCountChars = 0,
        .dwFillAttribute = 0,
        .wShowWindow = 0,
        .cbReserved2 = 0,
        .lpReserved2 = null,
    };
    var piProcInfo: windows.PROCESS_INFORMATION = undefined;

    const cwd_w = if (self.cwd) |cwd| try unicode.wtf8ToWtf16LeAllocZ(self.allocator, cwd) else null;
    defer if (cwd_w) |cwd| self.allocator.free(cwd);
    const cwd_w_ptr = if (cwd_w) |cwd| cwd.ptr else null;

    const maybe_envp_buf = if (self.env_map) |env_map| try process.createWindowsEnvBlock(self.allocator, env_map) else null;
    defer if (maybe_envp_buf) |envp_buf| self.allocator.free(envp_buf);
    const envp_ptr = if (maybe_envp_buf) |envp_buf| envp_buf.ptr else null;

    const app_name_wtf8 = self.argv[0];
    const app_name_is_absolute = fs.path.isAbsolute(app_name_wtf8);

    // the cwd set in ChildProcess is in effect when choosing the executable path
    // to match posix semantics
    var cwd_path_w_needs_free = false;
    const cwd_path_w = x: {
        // If the app name is absolute, then we need to use its dirname as the cwd
        if (app_name_is_absolute) {
            cwd_path_w_needs_free = true;
            const dir = fs.path.dirname(app_name_wtf8).?;
            break :x try unicode.wtf8ToWtf16LeAllocZ(self.allocator, dir);
        } else if (self.cwd) |cwd| {
            cwd_path_w_needs_free = true;
            break :x try unicode.wtf8ToWtf16LeAllocZ(self.allocator, cwd);
        } else {
            break :x &[_:0]u16{}; // empty for cwd
        }
    };
    defer if (cwd_path_w_needs_free) self.allocator.free(cwd_path_w);

    // If the app name has more than just a filename, then we need to separate that
    // into the basename and dirname and use the dirname as an addition to the cwd
    // path. This is because NtQueryDirectoryFile cannot accept FileName params with
    // path separators.
    const app_basename_wtf8 = fs.path.basename(app_name_wtf8);
    // If the app name is absolute, then the cwd will already have the app's dirname in it,
    // so only populate app_dirname if app name is a relative path with > 0 path separators.
    const maybe_app_dirname_wtf8 = if (!app_name_is_absolute) fs.path.dirname(app_name_wtf8) else null;
    const app_dirname_w: ?[:0]u16 = x: {
        if (maybe_app_dirname_wtf8) |app_dirname_wtf8| {
            break :x try unicode.wtf8ToWtf16LeAllocZ(self.allocator, app_dirname_wtf8);
        }
        break :x null;
    };
    defer if (app_dirname_w != null) self.allocator.free(app_dirname_w.?);

    const app_name_w = try unicode.wtf8ToWtf16LeAllocZ(self.allocator, app_basename_wtf8);
    defer self.allocator.free(app_name_w);

    const flags: windows.CreateProcessFlags = .{
        .create_suspended = self.start_suspended,
        .create_unicode_environment = true,
        .create_no_window = self.create_no_window,
    };

    run: {
        const PATH: [:0]const u16 = process.getenvW(unicode.utf8ToUtf16LeStringLiteral("PATH")) orelse &[_:0]u16{};
        const PATHEXT: [:0]const u16 = process.getenvW(unicode.utf8ToUtf16LeStringLiteral("PATHEXT")) orelse &[_:0]u16{};

        // In case the command ends up being a .bat/.cmd script, we need to escape things using the cmd.exe rules
        // and invoke cmd.exe ourselves in order to mitigate arbitrary command execution from maliciously
        // constructed arguments.
        //
        // We'll need to wait until we're actually trying to run the command to know for sure
        // if the resolved command has the `.bat` or `.cmd` extension, so we defer actually
        // serializing the command line until we determine how it should be serialized.
        var cmd_line_cache = WindowsCommandLineCache.init(self.allocator, self.argv);
        defer cmd_line_cache.deinit();

        var app_buf: std.ArrayListUnmanaged(u16) = .empty;
        defer app_buf.deinit(self.allocator);

        try app_buf.appendSlice(self.allocator, app_name_w);

        var dir_buf: std.ArrayListUnmanaged(u16) = .empty;
        defer dir_buf.deinit(self.allocator);

        if (cwd_path_w.len > 0) {
            try dir_buf.appendSlice(self.allocator, cwd_path_w);
        }
        if (app_dirname_w) |app_dir| {
            if (dir_buf.items.len > 0) try dir_buf.append(self.allocator, fs.path.sep);
            try dir_buf.appendSlice(self.allocator, app_dir);
        }
        if (dir_buf.items.len > 0) {
            // Need to normalize the path, openDirW can't handle things like double backslashes
            const normalized_len = windows.normalizePath(u16, dir_buf.items) catch return error.BadPathName;
            dir_buf.shrinkRetainingCapacity(normalized_len);
        }

        windowsCreateProcessPathExt(self.allocator, &dir_buf, &app_buf, PATHEXT, &cmd_line_cache, envp_ptr, cwd_w_ptr, flags, &siStartInfo, &piProcInfo) catch |no_path_err| {
            const original_err = switch (no_path_err) {
                // argv[0] contains unsupported characters that will never resolve to a valid exe.
                error.InvalidArg0 => return error.FileNotFound,
                error.FileNotFound, error.InvalidExe, error.AccessDenied => |e| e,
                error.UnrecoverableInvalidExe => return error.InvalidExe,
                else => |e| return e,
            };

            // If the app name had path separators, that disallows PATH searching,
            // and there's no need to search the PATH if the app name is absolute.
            // We still search the path if the cwd is absolute because of the
            // "cwd set in ChildProcess is in effect when choosing the executable path
            // to match posix semantics" behavior--we don't want to skip searching
            // the PATH just because we were trying to set the cwd of the child process.
            if (app_dirname_w != null or app_name_is_absolute) {
                return original_err;
            }

            var it = mem.tokenizeScalar(u16, PATH, ';');
            while (it.next()) |search_path| {
                dir_buf.clearRetainingCapacity();
                try dir_buf.appendSlice(self.allocator, search_path);
                // Need to normalize the path, some PATH values can contain things like double
                // backslashes which openDirW can't handle
                const normalized_len = windows.normalizePath(u16, dir_buf.items) catch continue;
                dir_buf.shrinkRetainingCapacity(normalized_len);

                if (windowsCreateProcessPathExt(self.allocator, &dir_buf, &app_buf, PATHEXT, &cmd_line_cache, envp_ptr, cwd_w_ptr, flags, &siStartInfo, &piProcInfo)) {
                    break :run;
                } else |err| switch (err) {
                    // argv[0] contains unsupported characters that will never resolve to a valid exe.
                    error.InvalidArg0 => return error.FileNotFound,
                    error.FileNotFound, error.AccessDenied, error.InvalidExe => continue,
                    error.UnrecoverableInvalidExe => return error.InvalidExe,
                    else => |e| return e,
                }
            } else {
                return original_err;
            }
        };
    }

    if (g_hChildStd_IN_Wr) |h| {
        self.stdin = File{ .handle = h };
    } else {
        self.stdin = null;
    }
    if (g_hChildStd_OUT_Rd) |h| {
        self.stdout = File{ .handle = h };
    } else {
        self.stdout = null;
    }
    if (g_hChildStd_ERR_Rd) |h| {
        self.stderr = File{ .handle = h };
    } else {
        self.stderr = null;
    }

    self.id = piProcInfo.hProcess;
    self.thread_handle = piProcInfo.hThread;
    self.term = null;

    if (self.stdin_behavior == StdIo.Pipe) {
        posix.close(g_hChildStd_IN_Rd.?);
    }
    if (self.stderr_behavior == StdIo.Pipe) {
        posix.close(g_hChildStd_ERR_Wr.?);
    }
    if (self.stdout_behavior == StdIo.Pipe) {
        posix.close(g_hChildStd_OUT_Wr.?);
    }
}

fn setUpChildIo(stdio: StdIo, pipe_fd: i32, std_fileno: i32, dev_null_fd: i32) !void {
    switch (stdio) {
        .Pipe => try posix.dup2(pipe_fd, std_fileno),
        .Close => posix.close(std_fileno),
        .Inherit => {},
        .Ignore => try posix.dup2(dev_null_fd, std_fileno),
    }
}

fn destroyPipe(pipe: [2]posix.fd_t) void {
    if (pipe[0] != -1) posix.close(pipe[0]);
    if (pipe[0] != pipe[1]) posix.close(pipe[1]);
}

// Child of fork calls this to report an error to the fork parent.
// Then the child exits.
fn forkChildErrReport(fd: i32, err: ChildProcess.SpawnError) noreturn {
    writeIntFd(fd, @as(ErrInt, @intFromError(err))) catch {};
    // If we're linking libc, some naughty applications may have registered atexit handlers
    // which we really do not want to run in the fork child. I caught LLVM doing this and
    // it caused a deadlock instead of doing an exit syscall. In the words of Avril Lavigne,
    // "Why'd you have to go and make things so complicated?"
    if (builtin.link_libc) {
        // The _exit(2) function does nothing but make the exit syscall, unlike exit(3)
        std.c._exit(1);
    }
    posix.exit(1);
}

fn writeIntFd(fd: i32, value: ErrInt) !void {
    const file: File = .{ .handle = fd };
    file.writer().writeInt(u64, @intCast(value), .little) catch return error.SystemResources;
}

fn readIntFd(fd: i32) !ErrInt {
    const file: File = .{ .handle = fd };
    return @intCast(file.reader().readInt(u64, .little) catch return error.SystemResources);
}

const ErrInt = std.meta.Int(.unsigned, @sizeOf(anyerror) * 8);

/// Expects `app_buf` to contain exactly the app name, and `dir_buf` to contain exactly the dir path.
/// After return, `app_buf` will always contain exactly the app name and `dir_buf` will always contain exactly the dir path.
/// Note: `app_buf` should not contain any leading path separators.
/// Note: If the dir is the cwd, dir_buf should be empty (len = 0).
fn windowsCreateProcessPathExt(
    allocator: mem.Allocator,
    dir_buf: *std.ArrayListUnmanaged(u16),
    app_buf: *std.ArrayListUnmanaged(u16),
    pathext: [:0]const u16,
    cmd_line_cache: *WindowsCommandLineCache,
    envp_ptr: ?[*]u16,
    cwd_ptr: ?[*:0]u16,
    flags: windows.CreateProcessFlags,
    lpStartupInfo: *windows.STARTUPINFOW,
    lpProcessInformation: *windows.PROCESS_INFORMATION,
) !void {
    const app_name_len = app_buf.items.len;
    const dir_path_len = dir_buf.items.len;

    if (app_name_len == 0) return error.FileNotFound;

    defer app_buf.shrinkRetainingCapacity(app_name_len);
    defer dir_buf.shrinkRetainingCapacity(dir_path_len);

    // The name of the game here is to avoid CreateProcessW calls at all costs,
    // and only ever try calling it when we have a real candidate for execution.
    // Secondarily, we want to minimize the number of syscalls used when checking
    // for each PATHEXT-appended version of the app name.
    //
    // An overview of the technique used:
    // - Open the search directory for iteration (either cwd or a path from PATH)
    // - Use NtQueryDirectoryFile with a wildcard filename of `<app name>*` to
    //   check if anything that could possibly match either the unappended version
    //   of the app name or any of the versions with a PATHEXT value appended exists.
    // - If the wildcard NtQueryDirectoryFile call found nothing, we can exit early
    //   without needing to use PATHEXT at all.
    //
    // This allows us to use a <open dir, NtQueryDirectoryFile, close dir> sequence
    // for any directory that doesn't contain any possible matches, instead of having
    // to use a separate look up for each individual filename combination (unappended +
    // each PATHEXT appended). For directories where the wildcard *does* match something,
    // we iterate the matches and take note of any that are either the unappended version,
    // or a version with a supported PATHEXT appended. We then try calling CreateProcessW
    // with the found versions in the appropriate order.

    var dir = dir: {
        // needs to be null-terminated
        try dir_buf.append(allocator, 0);
        defer dir_buf.shrinkRetainingCapacity(dir_path_len);
        const dir_path_z = dir_buf.items[0 .. dir_buf.items.len - 1 :0];
        const prefixed_path = try windows.wToPrefixedFileW(null, dir_path_z);
        break :dir fs.cwd().openDirW(prefixed_path.span().ptr, .{ .iterate = true }) catch
            return error.FileNotFound;
    };
    defer dir.close();

    // Add wildcard and null-terminator
    try app_buf.append(allocator, '*');
    try app_buf.append(allocator, 0);
    const app_name_wildcard = app_buf.items[0 .. app_buf.items.len - 1 :0];

    // This 2048 is arbitrary, we just want it to be large enough to get multiple FILE_DIRECTORY_INFORMATION entries
    // returned per NtQueryDirectoryFile call.
    var file_information_buf: [2048]u8 align(@alignOf(windows.FILE_DIRECTORY_INFORMATION)) = undefined;
    const file_info_maximum_single_entry_size = @sizeOf(windows.FILE_DIRECTORY_INFORMATION) + (windows.NAME_MAX * 2);
    if (file_information_buf.len < file_info_maximum_single_entry_size) {
        @compileError("file_information_buf must be large enough to contain at least one maximum size FILE_DIRECTORY_INFORMATION entry");
    }
    var io_status: windows.IO_STATUS_BLOCK = undefined;

    const num_supported_pathext = @typeInfo(WindowsExtension).@"enum".fields.len;
    var pathext_seen = [_]bool{false} ** num_supported_pathext;
    var any_pathext_seen = false;
    var unappended_exists = false;

    // Fully iterate the wildcard matches via NtQueryDirectoryFile and take note of all versions
    // of the app_name we should try to spawn.
    // Note: This is necessary because the order of the files returned is filesystem-dependent:
    //       On NTFS, `blah.exe*` will always return `blah.exe` first if it exists.
    //       On FAT32, it's possible for something like `blah.exe.obj` to be returned first.
    while (true) {
        const app_name_len_bytes = std.math.cast(u16, app_name_wildcard.len * 2) orelse return error.NameTooLong;
        var app_name_unicode_string = windows.UNICODE_STRING{
            .Length = app_name_len_bytes,
            .MaximumLength = app_name_len_bytes,
            .Buffer = @constCast(app_name_wildcard.ptr),
        };
        const rc = windows.ntdll.NtQueryDirectoryFile(
            dir.fd,
            null,
            null,
            null,
            &io_status,
            &file_information_buf,
            file_information_buf.len,
            .FileDirectoryInformation,
            windows.FALSE, // single result
            &app_name_unicode_string,
            windows.FALSE, // restart iteration
        );

        // If we get nothing with the wildcard, then we can just bail out
        // as we know appending PATHEXT will not yield anything.
        switch (rc) {
            .SUCCESS => {},
            .NO_SUCH_FILE => return error.FileNotFound,
            .NO_MORE_FILES => break,
            .ACCESS_DENIED => return error.AccessDenied,
            else => return windows.unexpectedStatus(rc),
        }

        // According to the docs, this can only happen if there is not enough room in the
        // buffer to write at least one complete FILE_DIRECTORY_INFORMATION entry.
        // Therefore, this condition should not be possible to hit with the buffer size we use.
        std.debug.assert(io_status.Information != 0);

        var it = windows.FileInformationIterator(windows.FILE_DIRECTORY_INFORMATION){ .buf = &file_information_buf };
        while (it.next()) |info| {
            // Skip directories
            if (info.FileAttributes & windows.FILE_ATTRIBUTE_DIRECTORY != 0) continue;
            const filename = @as([*]u16, @ptrCast(&info.FileName))[0 .. info.FileNameLength / 2];
            // Because all results start with the app_name since we're using the wildcard `app_name*`,
            // if the length is equal to app_name then this is an exact match
            if (filename.len == app_name_len) {
                // Note: We can't break early here because it's possible that the unappended version
                //       fails to spawn, in which case we still want to try the PATHEXT appended versions.
                unappended_exists = true;
            } else if (windowsCreateProcessSupportsExtension(filename[app_name_len..])) |pathext_ext| {
                pathext_seen[@intFromEnum(pathext_ex```
