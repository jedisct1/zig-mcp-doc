```
t)] = true;
                any_pathext_seen = true;
            }
        }
    }

    const unappended_err = unappended: {
        if (unappended_exists) {
            if (dir_path_len != 0) switch (dir_buf.items[dir_buf.items.len - 1]) {
                '/', '\\' => {},
                else => try dir_buf.append(allocator, fs.path.sep),
            };
            try dir_buf.appendSlice(allocator, app_buf.items[0..app_name_len]);
            try dir_buf.append(allocator, 0);
            const full_app_name = dir_buf.items[0 .. dir_buf.items.len - 1 :0];

            const is_bat_or_cmd = bat_or_cmd: {
                const app_name = app_buf.items[0..app_name_len];
                const ext_start = std.mem.lastIndexOfScalar(u16, app_name, '.') orelse break :bat_or_cmd false;
                const ext = app_name[ext_start..];
                const ext_enum = windowsCreateProcessSupportsExtension(ext) orelse break :bat_or_cmd false;
                switch (ext_enum) {
                    .cmd, .bat => break :bat_or_cmd true,
                    else => break :bat_or_cmd false,
                }
            };
            const cmd_line_w = if (is_bat_or_cmd)
                try cmd_line_cache.scriptCommandLine(full_app_name)
            else
                try cmd_line_cache.commandLine();
            const app_name_w = if (is_bat_or_cmd)
                try cmd_line_cache.cmdExePath()
            else
                full_app_name;

            if (windowsCreateProcess(app_name_w.ptr, cmd_line_w.ptr, envp_ptr, cwd_ptr, flags, lpStartupInfo, lpProcessInformation)) |_| {
                return;
            } else |err| switch (err) {
                error.FileNotFound,
                error.AccessDenied,
                => break :unappended err,
                error.InvalidExe => {
                    // On InvalidExe, if the extension of the app name is .exe then
                    // it's treated as an unrecoverable error. Otherwise, it'll be
                    // skipped as normal.
                    const app_name = app_buf.items[0..app_name_len];
                    const ext_start = std.mem.lastIndexOfScalar(u16, app_name, '.') orelse break :unappended err;
                    const ext = app_name[ext_start..];
                    if (windows.eqlIgnoreCaseWTF16(ext, unicode.utf8ToUtf16LeStringLiteral(".EXE"))) {
                        return error.UnrecoverableInvalidExe;
                    }
                    break :unappended err;
                },
                else => return err,
            }
        }
        break :unappended error.FileNotFound;
    };

    if (!any_pathext_seen) return unappended_err;

    // Now try any PATHEXT appended versions that we've seen
    var ext_it = mem.tokenizeScalar(u16, pathext, ';');
    while (ext_it.next()) |ext| {
        const ext_enum = windowsCreateProcessSupportsExtension(ext) orelse continue;
        if (!pathext_seen[@intFromEnum(ext_enum)]) continue;

        dir_buf.shrinkRetainingCapacity(dir_path_len);
        if (dir_path_len != 0) switch (dir_buf.items[dir_buf.items.len - 1]) {
            '/', '\\' => {},
            else => try dir_buf.append(allocator, fs.path.sep),
        };
        try dir_buf.appendSlice(allocator, app_buf.items[0..app_name_len]);
        try dir_buf.appendSlice(allocator, ext);
        try dir_buf.append(allocator, 0);
        const full_app_name = dir_buf.items[0 .. dir_buf.items.len - 1 :0];

        const is_bat_or_cmd = switch (ext_enum) {
            .cmd, .bat => true,
            else => false,
        };
        const cmd_line_w = if (is_bat_or_cmd)
            try cmd_line_cache.scriptCommandLine(full_app_name)
        else
            try cmd_line_cache.commandLine();
        const app_name_w = if (is_bat_or_cmd)
            try cmd_line_cache.cmdExePath()
        else
            full_app_name;

        if (windowsCreateProcess(app_name_w.ptr, cmd_line_w.ptr, envp_ptr, cwd_ptr, flags, lpStartupInfo, lpProcessInformation)) |_| {
            return;
        } else |err| switch (err) {
            error.FileNotFound => continue,
            error.AccessDenied => continue,
            error.InvalidExe => {
                // On InvalidExe, if the extension of the app name is .exe then
                // it's treated as an unrecoverable error. Otherwise, it'll be
                // skipped as normal.
                if (windows.eqlIgnoreCaseWTF16(ext, unicode.utf8ToUtf16LeStringLiteral(".EXE"))) {
                    return error.UnrecoverableInvalidExe;
                }
                continue;
            },
            else => return err,
        }
    }

    return unappended_err;
}

fn windowsCreateProcess(
    app_name: [*:0]u16,
    cmd_line: [*:0]u16,
    envp_ptr: ?[*]u16,
    cwd_ptr: ?[*:0]u16,
    flags: windows.CreateProcessFlags,
    lpStartupInfo: *windows.STARTUPINFOW,
    lpProcessInformation: *windows.PROCESS_INFORMATION,
) !void {
    // TODO the docs for environment pointer say:
    // > A pointer to the environment block for the new process. If this parameter
    // > is NULL, the new process uses the environment of the calling process.
    // > ...
    // > An environment block can contain either Unicode or ANSI characters. If
    // > the environment block pointed to by lpEnvironment contains Unicode
    // > characters, be sure that dwCreationFlags includes CREATE_UNICODE_ENVIRONMENT.
    // > If this parameter is NULL and the environment block of the parent process
    // > contains Unicode characters, you must also ensure that dwCreationFlags
    // > includes CREATE_UNICODE_ENVIRONMENT.
    // This seems to imply that we have to somehow know whether our process parent passed
    // CREATE_UNICODE_ENVIRONMENT if we want to pass NULL for the environment parameter.
    // Since we do not know this information that would imply that we must not pass NULL
    // for the parameter.
    // However this would imply that programs compiled with -DUNICODE could not pass
    // environment variables to programs that were not, which seems unlikely.
    // More investigation is needed.
    return windows.CreateProcessW(
        app_name,
        cmd_line,
        null,
        null,
        windows.TRUE,
        flags,
        @as(?*anyopaque, @ptrCast(envp_ptr)),
        cwd_ptr,
        lpStartupInfo,
        lpProcessInformation,
    );
}

fn windowsMakePipeIn(rd: *?windows.HANDLE, wr: *?windows.HANDLE, sattr: *const windows.SECURITY_ATTRIBUTES) !void {
    var rd_h: windows.HANDLE = undefined;
    var wr_h: windows.HANDLE = undefined;
    try windows.CreatePipe(&rd_h, &wr_h, sattr);
    errdefer windowsDestroyPipe(rd_h, wr_h);
    try windows.SetHandleInformation(wr_h, windows.HANDLE_FLAG_INHERIT, 0);
    rd.* = rd_h;
    wr.* = wr_h;
}

fn windowsDestroyPipe(rd: ?windows.HANDLE, wr: ?windows.HANDLE) void {
    if (rd) |h| posix.close(h);
    if (wr) |h| posix.close(h);
}

fn windowsMakeAsyncPipe(rd: *?windows.HANDLE, wr: *?windows.HANDLE, sattr: *const windows.SECURITY_ATTRIBUTES) !void {
    var tmp_bufw: [128]u16 = undefined;

    // Anonymous pipes are built upon Named pipes.
    // https://docs.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe
    // Asynchronous (overlapped) read and write operations are not supported by anonymous pipes.
    // https://docs.microsoft.com/en-us/windows/win32/ipc/anonymous-pipe-operations
    const pipe_path = blk: {
        var tmp_buf: [128]u8 = undefined;
        // Forge a random path for the pipe.
        const pipe_path = std.fmt.bufPrintZ(
            &tmp_buf,
            "\\\\.\\pipe\\zig-childprocess-{d}-{d}",
            .{ windows.GetCurrentProcessId(), pipe_name_counter.fetchAdd(1, .monotonic) },
        ) catch unreachable;
        const len = std.unicode.wtf8ToWtf16Le(&tmp_bufw, pipe_path) catch unreachable;
        tmp_bufw[len] = 0;
        break :blk tmp_bufw[0..len :0];
    };

    // Create the read handle that can be used with overlapped IO ops.
    const read_handle = windows.kernel32.CreateNamedPipeW(
        pipe_path.ptr,
        windows.PIPE_ACCESS_INBOUND | windows.FILE_FLAG_OVERLAPPED,
        windows.PIPE_TYPE_BYTE,
        1,
        4096,
        4096,
        0,
        sattr,
    );
    if (read_handle == windows.INVALID_HANDLE_VALUE) {
        switch (windows.GetLastError()) {
            else => |err| return windows.unexpectedError(err),
        }
    }
    errdefer posix.close(read_handle);

    var sattr_copy = sattr.*;
    const write_handle = windows.kernel32.CreateFileW(
        pipe_path.ptr,
        windows.GENERIC_WRITE,
        0,
        &sattr_copy,
        windows.OPEN_EXISTING,
        windows.FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (write_handle == windows.INVALID_HANDLE_VALUE) {
        switch (windows.GetLastError()) {
            else => |err| return windows.unexpectedError(err),
        }
    }
    errdefer posix.close(write_handle);

    try windows.SetHandleInformation(read_handle, windows.HANDLE_FLAG_INHERIT, 0);

    rd.* = read_handle;
    wr.* = write_handle;
}

var pipe_name_counter = std.atomic.Value(u32).init(1);

/// File name extensions supported natively by `CreateProcess()` on Windows.
// Should be kept in sync with `windowsCreateProcessSupportsExtension`.
pub const WindowsExtension = enum {
    bat,
    cmd,
    com,
    exe,
};

/// Case-insensitive WTF-16 lookup
fn windowsCreateProcessSupportsExtension(ext: []const u16) ?WindowsExtension {
    if (ext.len != 4) return null;
    const State = enum {
        start,
        dot,
        b,
        ba,
        c,
        cm,
        co,
        e,
        ex,
    };
    var state: State = .start;
    for (ext) |c| switch (state) {
        .start => switch (c) {
            '.' => state = .dot,
            else => return null,
        },
        .dot => switch (c) {
            'b', 'B' => state = .b,
            'c', 'C' => state = .c,
            'e', 'E' => state = .e,
            else => return null,
        },
        .b => switch (c) {
            'a', 'A' => state = .ba,
            else => return null,
        },
        .c => switch (c) {
            'm', 'M' => state = .cm,
            'o', 'O' => state = .co,
            else => return null,
        },
        .e => switch (c) {
            'x', 'X' => state = .ex,
            else => return null,
        },
        .ba => switch (c) {
            't', 'T' => return .bat,
            else => return null,
        },
        .cm => switch (c) {
            'd', 'D' => return .cmd,
            else => return null,
        },
        .co => switch (c) {
            'm', 'M' => return .com,
            else => return null,
        },
        .ex => switch (c) {
            'e', 'E' => return .exe,
            else => return null,
        },
    };
    return null;
}

test windowsCreateProcessSupportsExtension {
    try std.testing.expectEqual(WindowsExtension.exe, windowsCreateProcessSupportsExtension(&[_]u16{ '.', 'e', 'X', 'e' }).?);
    try std.testing.expect(windowsCreateProcessSupportsExtension(&[_]u16{ '.', 'e', 'X', 'e', 'c' }) == null);
}

/// Serializes argv into a WTF-16 encoded command-line string for use with CreateProcessW.
///
/// Serialization is done on-demand and the result is cached in order to allow for:
/// - Only serializing the particular type of command line needed (`.bat`/`.cmd`
///   command line serialization is different from `.exe`/etc)
/// - Reusing the serialized command lines if necessary (i.e. if the execution
///   of a command fails and the PATH is going to be continued to be searched
///   for more candidates)
const WindowsCommandLineCache = struct {
    cmd_line: ?[:0]u16 = null,
    script_cmd_line: ?[:0]u16 = null,
    cmd_exe_path: ?[:0]u16 = null,
    argv: []const []const u8,
    allocator: mem.Allocator,

    fn init(allocator: mem.Allocator, argv: []const []const u8) WindowsCommandLineCache {
        return .{
            .allocator = allocator,
            .argv = argv,
        };
    }

    fn deinit(self: *WindowsCommandLineCache) void {
        if (self.cmd_line) |cmd_line| self.allocator.free(cmd_line);
        if (self.script_cmd_line) |script_cmd_line| self.allocator.free(script_cmd_line);
        if (self.cmd_exe_path) |cmd_exe_path| self.allocator.free(cmd_exe_path);
    }

    fn commandLine(self: *WindowsCommandLineCache) ![:0]u16 {
        if (self.cmd_line == null) {
            self.cmd_line = try argvToCommandLineWindows(self.allocator, self.argv);
        }
        return self.cmd_line.?;
    }

    /// Not cached, since the path to the batch script will change during PATH searching.
    /// `script_path` should be as qualified as possible, e.g. if the PATH is being searched,
    /// then script_path should include both the search path and the script filename
    /// (this allows avoiding cmd.exe having to search the PATH again).
    fn scriptCommandLine(self: *WindowsCommandLineCache, script_path: []const u16) ![:0]u16 {
        if (self.script_cmd_line) |v| self.allocator.free(v);
        self.script_cmd_line = try argvToScriptCommandLineWindows(
            self.allocator,
            script_path,
            self.argv[1..],
        );
        return self.script_cmd_line.?;
    }

    fn cmdExePath(self: *WindowsCommandLineCache) ![:0]u16 {
        if (self.cmd_exe_path == null) {
            self.cmd_exe_path = try windowsCmdExePath(self.allocator);
        }
        return self.cmd_exe_path.?;
    }
};

/// Returns the absolute path of `cmd.exe` within the Windows system directory.
/// The caller owns the returned slice.
fn windowsCmdExePath(allocator: mem.Allocator) error{ OutOfMemory, Unexpected }![:0]u16 {
    var buf = try std.ArrayListUnmanaged(u16).initCapacity(allocator, 128);
    errdefer buf.deinit(allocator);
    while (true) {
        const unused_slice = buf.unusedCapacitySlice();
        // TODO: Get the system directory from PEB.ReadOnlyStaticServerData
        const len = windows.kernel32.GetSystemDirectoryW(@ptrCast(unused_slice), @intCast(unused_slice.len));
        if (len == 0) {
            switch (windows.GetLastError()) {
                else => |err| return windows.unexpectedError(err),
            }
        }
        if (len > unused_slice.len) {
            try buf.ensureUnusedCapacity(allocator, len);
        } else {
            buf.items.len = len;
            break;
        }
    }
    switch (buf.items[buf.items.len - 1]) {
        '/', '\\' => {},
        else => try buf.append(allocator, fs.path.sep),
    }
    try buf.appendSlice(allocator, unicode.utf8ToUtf16LeStringLiteral("cmd.exe"));
    return try buf.toOwnedSliceSentinel(allocator, 0);
}

const ArgvToCommandLineError = error{ OutOfMemory, InvalidWtf8, InvalidArg0 };

/// Serializes `argv` to a Windows command-line string suitable for passing to a child process and
/// parsing by the `CommandLineToArgvW` algorithm. The caller owns the returned slice.
///
/// To avoid arbitrary command execution, this function should not be used when spawning `.bat`/`.cmd` scripts.
/// https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/
///
/// When executing `.bat`/`.cmd` scripts, use `argvToScriptCommandLineWindows` instead.
fn argvToCommandLineWindows(
    allocator: mem.Allocator,
    argv: []const []const u8,
) ArgvToCommandLineError![:0]u16 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    if (argv.len != 0) {
        const arg0 = argv[0];

        // The first argument must be quoted if it contains spaces or ASCII control characters
        // (excluding DEL). It also follows special quoting rules where backslashes have no special
        // interpretation, which makes it impossible to pass certain first arguments containing
        // double quotes to a child process without characters from the first argument leaking into
        // subsequent ones (which could have security implications).
        //
        // Empty arguments technically don't need quotes, but we quote them anyway for maximum
        // compatibility with different implementations of the 'CommandLineToArgvW' algorithm.
        //
        // Double quotes are illegal in paths on Windows, so for the sake of simplicity we reject
        // all first arguments containing double quotes, even ones that we could theoretically
        // serialize in unquoted form.
        var needs_quotes = arg0.len == 0;
        for (arg0) |c| {
            if (c <= ' ') {
                needs_quotes = true;
            } else if (c == '"') {
                return error.InvalidArg0;
            }
        }
        if (needs_quotes) {
            try buf.append('"');
            try buf.appendSlice(arg0);
            try buf.append('"');
        } else {
            try buf.appendSlice(arg0);
        }

        for (argv[1..]) |arg| {
            try buf.append(' ');

            // Subsequent arguments must be quoted if they contain spaces, tabs or double quotes,
            // or if they are empty. For simplicity and for maximum compatibility with different
            // implementations of the 'CommandLineToArgvW' algorithm, we also quote all ASCII
            // control characters (again, excluding DEL).
            needs_quotes = for (arg) |c| {
                if (c <= ' ' or c == '"') {
                    break true;
                }
            } else arg.len == 0;
            if (!needs_quotes) {
                try buf.appendSlice(arg);
                continue;
            }

            try buf.append('"');
            var backslash_count: usize = 0;
            for (arg) |byte| {
                switch (byte) {
                    '\\' => {
                        backslash_count += 1;
                    },
                    '"' => {
                        try buf.appendNTimes('\\', backslash_count * 2 + 1);
                        try buf.append('"');
                        backslash_count = 0;
                    },
                    else => {
                        try buf.appendNTimes('\\', backslash_count);
                        try buf.append(byte);
                        backslash_count = 0;
                    },
                }
            }
            try buf.appendNTimes('\\', backslash_count * 2);
            try buf.append('"');
        }
    }

    return try unicode.wtf8ToWtf16LeAllocZ(allocator, buf.items);
}

test argvToCommandLineWindows {
    const t = testArgvToCommandLineWindows;

    try t(&.{
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
    },
        \\"C:\Program Files\zig\zig.exe" run .\src\main.zig -target x86_64-windows-gnu -O ReleaseSafe -- --emoji=🗿 "--eval=new Regex(\"Dwayne \\\"The Rock\\\" Johnson\")"
    );

    try t(&.{}, "");
    try t(&.{""}, "\"\"");
    try t(&.{" "}, "\" \"");
    try t(&.{"\t"}, "\"\t\"");
    try t(&.{"\x07"}, "\"\x07\"");
    try t(&.{"🦎"}, "🦎");

    try t(
        &.{ "zig", "aa aa", "bb\tbb", "cc\ncc", "dd\r\ndd", "ee\x7Fee" },
        "zig \"aa aa\" \"bb\tbb\" \"cc\ncc\" \"dd\r\ndd\" ee\x7Fee",
    );

    try t(
        &.{ "\\\\foo bar\\foo bar\\", "\\\\zig zag\\zig zag\\" },
        "\"\\\\foo bar\\foo bar\\\" \"\\\\zig zag\\zig zag\\\\\"",
    );

    try std.testing.expectError(
        error.InvalidArg0,
        argvToCommandLineWindows(std.testing.allocator, &.{"\"quotes\"quotes\""}),
    );
    try std.testing.expectError(
        error.InvalidArg0,
        argvToCommandLineWindows(std.testing.allocator, &.{"quotes\"quotes"}),
    );
    try std.testing.expectError(
        error.InvalidArg0,
        argvToCommandLineWindows(std.testing.allocator, &.{"q u o t e s \" q u o t e s"}),
    );
}

fn testArgvToCommandLineWindows(argv: []const []const u8, expected_cmd_line: []const u8) !void {
    const cmd_line_w = try argvToCommandLineWindows(std.testing.allocator, argv);
    defer std.testing.allocator.free(cmd_line_w);

    const cmd_line = try unicode.wtf16LeToWtf8Alloc(std.testing.allocator, cmd_line_w);
    defer std.testing.allocator.free(cmd_line);

    try std.testing.expectEqualStrings(expected_cmd_line, cmd_line);
}

const ArgvToScriptCommandLineError = error{
    OutOfMemory,
    InvalidWtf8,
    /// NUL (U+0000), LF (U+000A), CR (U+000D) are not allowed
    /// within arguments when executing a `.bat`/`.cmd` script.
    /// - NUL/LF signifiies end of arguments, so anything afterwards
    ///   would be lost after execution.
    /// - CR is stripped by `cmd.exe`, so any CR codepoints
    ///   would be lost after execution.
    InvalidBatchScriptArg,
};

/// Serializes `argv` to a Windows command-line string that uses `cmd.exe /c` and `cmd.exe`-specific
/// escaping rules. The caller owns the returned slice.
///
/// Escapes `argv` using the suggested mitigation against arbitrary command execution from:
/// https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/
///
/// The return of this function will look like
/// `cmd.exe /d /e:ON /v:OFF /c "<escaped command line>"`
/// and should be used as the `lpCommandLine` of `CreateProcessW`, while the
/// return of `windowsCmdExePath` should be used as `lpApplicationName`.
///
/// Should only be used when spawning `.bat`/`.cmd` scripts, see `argvToCommandLineWindows` otherwise.
/// The `.bat`/`.cmd` file must be known to both have the `.bat`/`.cmd` extension and exist on the filesystem.
fn argvToScriptCommandLineWindows(
    allocator: mem.Allocator,
    /// Path to the `.bat`/`.cmd` script. If this path is relative, it is assumed to be relative to the CWD.
    /// The script must have been verified to exist at this path before calling this function.
    script_path: []const u16,
    /// Arguments, not including the script name itself. Expected to be encoded as WTF-8.
    script_args: []const []const u8,
) ArgvToScriptCommandLineError![:0]u16 {
    var buf = try std.ArrayList(u8).initCapacity(allocator, 64);
    defer buf.deinit();

    // `/d` disables execution of AutoRun commands.
    // `/e:ON` and `/v:OFF` are needed for BatBadBut mitigation:
    // > If delayed expansion is enabled via the registry value DelayedExpansion,
    // > it must be disabled by explicitly calling cmd.exe with the /V:OFF option.
    // > Escaping for % requires the command extension to be enabled.
    // > If it’s disabled via the registry value EnableExtensions, it must be enabled with the /E:ON option.
    // https://flatt.tech/research/posts/batbadbut-you-cant-securely-execute-commands-on-windows/
    buf.appendSliceAssumeCapacity("cmd.exe /d /e:ON /v:OFF /c \"");

    // Always quote the path to the script arg
    buf.appendAssumeCapacity('"');
    // We always want the path to the batch script to include a path separator in order to
    // avoid cmd.exe searching the PATH for the script. This is not part of the arbitrary
    // command execution mitigation, we just know exactly what script we want to execute
    // at this point, and potentially making cmd.exe re-find it is unnecessary.
    //
    // If the script path does not have a path separator, then we know its relative to CWD and
    // we can just put `.\` in the front.
    if (mem.indexOfAny(u16, script_path, &[_]u16{ mem.nativeToLittle(u16, '\\'), mem.nativeToLittle(u16, '/') }) == null) {
        try buf.appendSlice(".\\");
    }
    // Note that we don't do any escaping/mitigations for this argument, since the relevant
    // characters (", %, etc) are illegal in file paths and this function should only be called
    // with script paths that have been verified to exist.
    try unicode.wtf16LeToWtf8ArrayList(&buf, script_path);
    buf.appendAssumeCapacity('"');

    for (script_args) |arg| {
        // Literal carriage returns get stripped when run through cmd.exe
        // and NUL/newlines act as 'end of command.' Because of this, it's basically
        // always a mistake to include these characters in argv, so it's
        // an error condition in order to ensure that the return of this
        // function can always roundtrip through cmd.exe.
        if (std.mem.indexOfAny(u8, arg, "\x00\r\n") != null) {
            return error.InvalidBatchScriptArg;
        }

        // Separate args with a space.
        try buf.append(' ');

        // Need to quote if the argument is empty (otherwise the arg would just be lost)
        // or if the last character is a `\`, since then something like "%~2" in a .bat
        // script would cause the closing " to be escaped which we don't want.
        var needs_quotes = arg.len == 0 or arg[arg.len - 1] == '\\';
        if (!needs_quotes) {
            for (arg) |c| {
                switch (c) {
                    // Known good characters that don't need to be quoted
                    'A'...'Z', 'a'...'z', '0'...'9', '#', '$', '*', '+', '-', '.', '/', ':', '?', '@', '\\', '_' => {},
                    // When in doubt, quote
                    else => {
                        needs_quotes = true;
                        break;
                    },
                }
            }
        }
        if (needs_quotes) {
            try buf.append('"');
        }
        var backslashes: usize = 0;
        for (arg) |c| {
            switch (c) {
                '\\' => {
                    backslashes += 1;
                },
                '"' => {
                    try buf.appendNTimes('\\', backslashes);
                    try buf.append('"');
                    backslashes = 0;
                },
                // Replace `%` with `%%cd:~,%`.
                //
                // cmd.exe allows extracting a substring from an environment
                // variable with the syntax: `%foo:~<start_index>,<end_index>%`.
                // Therefore, `%cd:~,%` will always expand to an empty string
                // since both the start and end index are blank, and it is assumed
                // that `%cd%` is always available since it is a built-in variable
                // that corresponds to the current directory.
                //
                // This means that replacing `%foo%` with `%%cd:~,%foo%%cd:~,%`
                // will stop `%foo%` from being expanded and *after* expansion
                // we'll still be left with `%foo%` (the literal string).
                '%' => {
                    // the trailing `%` is appended outside the switch
                    try buf.appendSlice("%%cd:~,");
                    backslashes = 0;
                },
                else => {
                    backslashes = 0;
                },
            }
            try buf.append(c);
        }
        if (needs_quotes) {
            try buf.appendNTimes('\\', backslashes);
            try buf.append('"');
        }
    }

    try buf.append('"');

    return try unicode.wtf8ToWtf16LeAllocZ(allocator, buf.items);
}
//! This API is non-allocating, non-fallible, thread-safe, and lock-free.

const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const testing = std.testing;
const assert = std.debug.assert;
const Progress = @This();
const posix = std.posix;
const is_big_endian = builtin.cpu.arch.endian() == .big;
const is_windows = builtin.os.tag == .windows;

/// `null` if the current node (and its children) should
/// not print on update()
terminal: std.fs.File,

terminal_mode: TerminalMode,

update_thread: ?std.Thread,

/// Atomically set by SIGWINCH as well as the root done() function.
redraw_event: std.Thread.ResetEvent,
/// Indicates a request to shut down and reset global state.
/// Accessed atomically.
done: bool,
need_clear: bool,

refresh_rate_ns: u64,
initial_delay_ns: u64,

rows: u16,
cols: u16,

/// Accessed only by the update thread.
draw_buffer: []u8,

/// This is in a separate array from `node_storage` but with the same length so
/// that it can be iterated over efficiently without trashing too much of the
/// CPU cache.
node_parents: []Node.Parent,
node_storage: []Node.Storage,
node_freelist: []Node.OptionalIndex,
node_freelist_first: Node.OptionalIndex,
node_end_index: u32,

pub const TerminalMode = union(enum) {
    off,
    ansi_escape_codes,
    /// This is not the same as being run on windows because other terminals
    /// exist like MSYS/git-bash.
    windows_api: if (is_windows) WindowsApi else void,

    pub const WindowsApi = struct {
        /// The output code page of the console.
        code_page: windows.UINT,
    };
};

pub const Options = struct {
    /// User-provided buffer with static lifetime.
    ///
    /// Used to store the entire write buffer sent to the terminal. Progress output will be truncated if it
    /// cannot fit into this buffer which will look bad but not cause any malfunctions.
    ///
    /// Must be at least 200 bytes.
    draw_buffer: []u8 = &default_draw_buffer,
    /// How many nanoseconds between writing updates to the terminal.
    refresh_rate_ns: u64 = 80 * std.time.ns_per_ms,
    /// How many nanoseconds to keep the output hidden
    initial_delay_ns: u64 = 200 * std.time.ns_per_ms,
    /// If provided, causes the progress item to have a denominator.
    /// 0 means unknown.
    estimated_total_items: usize = 0,
    root_name: []const u8 = "",
    disable_printing: bool = false,
};

/// Represents one unit of progress. Each node can have children nodes, or
/// one can use integers with `update`.
pub const Node = struct {
    index: OptionalIndex,

    pub const none: Node = .{ .index = .none };

    pub const max_name_len = 40;

    const Storage = extern struct {
        /// Little endian.
        completed_count: u32,
        /// 0 means unknown.
        /// Little endian.
        estimated_total_count: u32,
        name: [max_name_len]u8 align(@alignOf(usize)),

        /// Not thread-safe.
        fn getIpcFd(s: Storage) ?posix.fd_t {
            return if (s.estimated_total_count == std.math.maxInt(u32)) switch (@typeInfo(posix.fd_t)) {
                .int => @bitCast(s.completed_count),
                .pointer => @ptrFromInt(s.completed_count),
                else => @compileError("unsupported fd_t of " ++ @typeName(posix.fd_t)),
            } else null;
        }

        /// Thread-safe.
        fn setIpcFd(s: *Storage, fd: posix.fd_t) void {
            const integer: u32 = switch (@typeInfo(posix.fd_t)) {
                .int => @bitCast(fd),
                .pointer => @intFromPtr(fd),
                else => @compileError("unsupported fd_t of " ++ @typeName(posix.fd_t)),
            };
            // `estimated_total_count` max int indicates the special state that
            // causes `completed_count` to be treated as a file descriptor, so
            // the order here matters.
            @atomicStore(u32, &s.completed_count, integer, .monotonic);
            @atomicStore(u32, &s.estimated_total_count, std.math.maxInt(u32), .release);
        }

        /// Not thread-safe.
        fn byteSwap(s: *Storage) void {
            s.completed_count = @byteSwap(s.completed_count);
            s.estimated_total_count = @byteSwap(s.estimated_total_count);
        }

        comptime {
            assert((@sizeOf(Storage) % 4) == 0);
        }
    };

    const Parent = enum(u8) {
        /// Unallocated storage.
        unused = std.math.maxInt(u8) - 1,
        /// Indicates root node.
        none = std.math.maxInt(u8),
        /// Index into `node_storage`.
        _,

        fn unwrap(i: @This()) ?Index {
            return switch (i) {
                .unused, .none => return null,
                else => @enumFromInt(@intFromEnum(i)),
            };
        }
    };

    pub const OptionalIndex = enum(u8) {
        none = std.math.maxInt(u8),
        /// Index into `node_storage`.
        _,

        pub fn unwrap(i: @This()) ?Index {
            if (i == .none) return null;
            return @enumFromInt(@intFromEnum(i));
        }

        fn toParent(i: @This()) Parent {
            assert(@intFromEnum(i) != @intFromEnum(Parent.unused));
            return @enumFromInt(@intFromEnum(i));
        }
    };

    /// Index into `node_storage`.
    pub const Index = enum(u8) {
        _,

        fn toParent(i: @This()) Parent {
            assert(@intFromEnum(i) != @intFromEnum(Parent.unused));
            assert(@intFromEnum(i) != @intFromEnum(Parent.none));
            return @enumFromInt(@intFromEnum(i));
        }

        pub fn toOptional(i: @This()) OptionalIndex {
            return @enumFromInt(@intFromEnum(i));
        }
    };

    /// Create a new child progress node. Thread-safe.
    ///
    /// Passing 0 for `estimated_total_items` means unknown.
    pub fn start(node: Node, name: []const u8, estimated_total_items: usize) Node {
        if (noop_impl) {
            assert(node.index == .none);
            return Node.none;
        }
        const node_index = node.index.unwrap() orelse return Node.none;
        const parent = node_index.toParent();

        const freelist_head = &global_progress.node_freelist_first;
        var opt_free_index = @atomicLoad(Node.OptionalIndex, freelist_head, .seq_cst);
        while (opt_free_index.unwrap()) |free_index| {
            const freelist_ptr = freelistByIndex(free_index);
            const next = @atomicLoad(Node.OptionalIndex, freelist_ptr, .seq_cst);
            opt_free_index = @cmpxchgWeak(Node.OptionalIndex, freelist_head, opt_free_index, next, .seq_cst, .seq_cst) orelse {
                // We won the allocation race.
                return init(free_index, parent, name, estimated_total_items);
            };
        }

        const free_index = @atomicRmw(u32, &global_progress.node_end_index, .Add, 1, .monotonic);
        if (free_index >= global_progress.node_storage.len) {
            // Ran out of node storage memory. Progress for this node will not be tracked.
            _ = @atomicRmw(u32, &global_progress.node_end_index, .Sub, 1, .monotonic);
            return Node.none;
        }

        return init(@enumFromInt(free_index), parent, name, estimated_total_items);
    }

    /// This is the same as calling `start` and then `end` on the returned `Node`. Thread-safe.
    pub fn completeOne(n: Node) void {
        const index = n.index.unwrap() orelse return;
        const storage = storageByIndex(index);
        _ = @atomicRmw(u32, &storage.completed_count, .Add, 1, .monotonic);
    }

    /// Thread-safe.
    pub fn setCompletedItems(n: Node, completed_items: usize) void {
        const index = n.index.unwrap() orelse return;
        const storage = storageByIndex(index);
        @atomicStore(u32, &storage.completed_count, std.math.lossyCast(u32, completed_items), .monotonic);
    }

    /// Thread-safe. 0 means unknown.
    pub fn setEstimatedTotalItems(n: Node, count: usize) void {
        const index = n.index.unwrap() orelse return;
        const storage = storageByIndex(index);
        // Avoid u32 max int which is used to indicate a special state.
        const saturated = @min(std.math.maxInt(u32) - 1, count);
        @atomicStore(u32, &storage.estimated_total_count, saturated, .monotonic);
    }

    /// Thread-safe.
    pub fn increaseEstimatedTotalItems(n: Node, count: usize) void {
        const index = n.index.unwrap() orelse return;
        const storage = storageByIndex(index);
        _ = @atomicRmw(u32, &storage.estimated_total_count, .Add, std.math.lossyCast(u32, count), .monotonic);
    }

    /// Finish a started `Node`. Thread-safe.
    pub fn end(n: Node) void {
        if (noop_impl) {
            assert(n.index == .none);
            return;
        }
        const index = n.index.unwrap() orelse return;
        const parent_ptr = parentByIndex(index);
        if (parent_ptr.unwrap()) |parent_index| {
            _ = @atomicRmw(u32, &storageByIndex(parent_index).completed_count, .Add, 1, .monotonic);
            @atomicStore(Node.Parent, parent_ptr, .unused, .seq_cst);

            const freelist_head = &global_progress.node_freelist_first;
            var first = @atomicLoad(Node.OptionalIndex, freelist_head, .seq_cst);
            while (true) {
                @atomicStore(Node.OptionalIndex, freelistByIndex(index), first, .seq_cst);
                first = @cmpxchgWeak(Node.OptionalIndex, freelist_head, first, index.toOptional(), .seq_cst, .seq_cst) orelse break;
            }
        } else {
            @atomicStore(bool, &global_progress.done, true, .seq_cst);
            global_progress.redraw_event.set();
            if (global_progress.update_thread) |thread| thread.join();
        }
    }

    /// Posix-only. Used by `std.process.Child`. Thread-safe.
    pub fn setIpcFd(node: Node, fd: posix.fd_t) void {
        const index = node.index.unwrap() orelse return;
        assert(fd >= 0);
        assert(fd != posix.STDOUT_FILENO);
        assert(fd != posix.STDIN_FILENO);
        assert(fd != posix.STDERR_FILENO);
        storageByIndex(index).setIpcFd(fd);
    }

    /// Posix-only. Thread-safe. Assumes the node is storing an IPC file
    /// descriptor.
    pub fn getIpcFd(node: Node) ?posix.fd_t {
        const index = node.index.unwrap() orelse return null;
        const storage = storageByIndex(index);
        const int = @atomicLoad(u32, &storage.completed_count, .monotonic);
        return switch (@typeInfo(posix.fd_t)) {
            .int => @bitCast(int),
            .pointer => @ptrFromInt(int),
            else => @compileError("unsupported fd_t of " ++ @typeName(posix.fd_t)),
        };
    }

    fn storageByIndex(index: Node.Index) *Node.Storage {
        return &global_progress.node_storage[@intFromEnum(index)];
    }

    fn parentByIndex(index: Node.Index) *Node.Parent {
        return &global_progress.node_parents[@intFromEnum(index)];
    }

    fn freelistByIndex(index: Node.Index) *Node.OptionalIndex {
        return &global_progress.node_freelist[@intFromEnum(index)];
    }

    fn init(free_index: Index, parent: Parent, name: []const u8, estimated_total_items: usize) Node {
        assert(parent == .none or @intFromEnum(parent) < node_storage_buffer_len);

        const storage = storageByIndex(free_index);
        @atomicStore(u32, &storage.completed_count, 0, .monotonic);
        @atomicStore(u32, &storage.estimated_total_count, std.math.lossyCast(u32, estimated_total_items), .monotonic);
        const name_len = @min(max_name_len, name.len);
        copyAtomicStore(storage.name[0..name_len], name[0..name_len]);
        if (name_len < storage.name.len)
            @atomicStore(u8, &storage.name[name_len], 0, .monotonic);

        const parent_ptr = parentByIndex(free_index);
        assert(parent_ptr.* == .unused);
        @atomicStore(Node.Parent, parent_ptr, parent, .release);

        return .{ .index = free_index.toOptional() };
    }
};

var global_progress: Progress = .{
    .terminal = undefined,
    .terminal_mode = .off,
    .update_thread = null,
    .redraw_event = .{},
    .refresh_rate_ns = undefined,
    .initial_delay_ns = undefined,
    .rows = 0,
    .cols = 0,
    .draw_buffer = undefined,
    .done = false,
    .need_clear = false,

    .node_parents = &node_parents_buffer,
    .node_storage = &node_storage_buffer,
    .node_freelist = &node_freelist_buffer,
    .node_freelist_first = .none,
    .node_end_index = 0,
};

const node_storage_buffer_len = 83;
var node_parents_buffer: [node_storage_buffer_len]Node.Parent = undefined;
var node_storage_buffer: [node_storage_buffer_len]Node.Storage = undefined;
var node_freelist_buffer: [node_storage_buffer_len]Node.OptionalIndex = undefined;

var default_draw_buffer: [4096]u8 = undefined;

var debug_start_trace = std.debug.Trace.init;

pub const have_ipc = switch (builtin.os.tag) {
    .wasi, .freestanding, .windows => false,
    else => true,
};

const noop_impl = builtin.single_threaded or switch (builtin.os.tag) {
    .wasi, .freestanding => true,
    else => false,
};

/// Initializes a global Progress instance.
///
/// Asserts there is only one global Progress instance.
///
/// Call `Node.end` when done.
pub fn start(options: Options) Node {
    // Ensure there is only 1 global Progress object.
    if (global_progress.node_end_index != 0) {
        debug_start_trace.dump();
        unreachable;
    }
    debug_start_trace.add("first initialized here");

    @memset(global_progress.node_parents, .unused);
    const root_node = Node.init(@enumFromInt(0), .none, options.root_name, options.estimated_total_items);
    global_progress.done = false;
    global_progress.node_end_index = 1;

    assert(options.draw_buffer.len >= 200);
    global_progress.draw_buffer = options.draw_buffer;
    global_progress.refresh_rate_ns = options.refresh_rate_ns;
    global_progress.initial_delay_ns = options.initial_delay_ns;

    if (noop_impl)
        return Node.none;

    if (std.process.parseEnvVarInt("ZIG_PROGRESS", u31, 10)) |ipc_fd| {
        global_progress.update_thread = std.Thread.spawn(.{}, ipcThreadRun, .{
            @as(posix.fd_t, switch (@typeInfo(posix.fd_t)) {
                .int => ipc_fd,
                .pointer => @ptrFromInt(ipc_fd),
                else => @compileError("unsupported fd_t of " ++ @typeName(posix.fd_t)),
            }),
        }) catch |err| {
            std.log.warn("failed to spawn IPC thread for communicating progress to parent: {s}", .{@errorName(err)});
            return Node.none;
        };
    } else |env_err| switch (env_err) {
        error.EnvironmentVariableNotFound => {
            if (options.disable_printing) {
                return Node.none;
            }
            const stderr = std.io.getStdErr();
            global_progress.terminal = stderr;
            if (stderr.getOrEnableAnsiEscapeSupport()) {
                global_progress.terminal_mode = .ansi_escape_codes;
            } else if (is_windows and stderr.isTty()) {
                global_progress.terminal_mode = TerminalMode{ .windows_api = .{
                    .code_page = windows.kernel32.GetConsoleOutputCP(),
                } };
            }

            if (global_progress.terminal_mode == .off) {
                return Node.none;
            }

            if (have_sigwinch) {
                var act: posix.Sigaction = .{
                    .handler = .{ .sigaction = handleSigWinch },
                    .mask = posix.empty_sigset,
                    .flags = (posix.SA.SIGINFO | posix.SA.RESTART),
                };
                posix.sigaction(posix.SIG.WINCH, &act, null);
            }

            if (switch (global_progress.terminal_mode) {
                .off => unreachable, // handled a few lines above
                .ansi_escape_codes => std.Thread.spawn(.{}, updateThreadRun, .{}),
                .windows_api => if (is_windows) std.Thread.spawn(.{}, windowsApiUpdateThreadRun, .{}) else unreachable,
            }) |thread| {
                global_progress.update_thread = thread;
            } else |err| {
                std.log.warn("unable to spawn thread for printing progress to terminal: {s}", .{@errorName(err)});
                return Node.none;
            }
        },
        else => |e| {
            std.log.warn("invalid ZIG_PROGRESS file descriptor integer: {s}", .{@errorName(e)});
            return Node.none;
        },
    }

    return root_node;
}

/// Returns whether a resize is needed to learn the terminal size.
fn wait(timeout_ns: u64) bool {
    const resize_flag = if (global_progress.redraw_event.timedWait(timeout_ns)) |_|
        true
    else |err| switch (err) {
        error.Timeout => false,
    };
    global_progress.redraw_event.reset();
    return resize_flag or (global_progress.cols == 0);
}

fn updateThreadRun() void {
    // Store this data in the thread so that it does not need to be part of the
    // linker data of the main executable.
    var serialized_buffer: Serialized.Buffer = undefined;

    {
        const resize_flag = wait(global_progress.initial_delay_ns);
        if (@atomicLoad(bool, &global_progress.done, .seq_cst)) return;
        maybeUpdateSize(resize_flag);

        const buffer, _ = computeRedraw(&serialized_buffer);
        if (stderr_mutex.tryLock()) {
            defer stderr_mutex.unlock();
            write(buffer) catch return;
            global_progress.need_clear = true;
        }
    }

    while (true) {
        const resize_flag = wait(global_progress.refresh_rate_ns);

        if (@atomicLoad(bool, &global_progress.done, .seq_cst)) {
            stderr_mutex.lock();
            defer stderr_mutex.unlock();
            return clearWrittenWithEscapeCodes() catch {};
        }

        maybeUpdateSize(resize_flag);

        const buffer, _ = computeRedraw(&serialized_buffer);
        if (stderr_mutex.tryLock()) {
            defer stderr_mutex.unlock();
            write(buffer) catch return;
            global_progress.need_clear = true;
        }
    }
}

fn windowsApiWriteMarker() void {
    // Write the marker that we will use to find the beginning of the progress when clearing.
    // Note: This doesn't have to use WriteConsoleW, but doing so avoids dealing with the code page.
    var num_chars_written: windows.DWORD = undefined;
    const handle = global_progress.terminal.handle;
    _ = windows.kernel32.WriteConsoleW(handle, &[_]u16{windows_api_start_marker}, 1, &num_chars_written, null);
}

fn windowsApiUpdateThreadRun() void {
    var serialized_buffer: Serialized.Buffer = undefined;

    {
        const resize_flag = wait(global_progress.initial_delay_ns);
        if (@atomicLoad(bool, &global_progress.done, .seq_cst)) return;
        maybeUpdateSize(resize_flag);

        const buffer, const nl_n = computeRedraw(&serialized_buffer);
        if (stderr_mutex.tryLock()) {
            defer stderr_mutex.unlock();
            windowsApiWriteMarker();
            write(buffer) catch return;
            global_progress.need_clear = true;
            windowsApiMoveToMarker(nl_n) catch return;
        }
    }

    while (true) {
        const resize_flag = wait(global_progress.refresh_rate_ns);

        if (@atomicLoad(bool, &global_progress.done, .seq_cst)) {
            stderr_mutex.lock();
            defer stderr_mutex.unlock();
            return clearWrittenWindowsApi() catch {};
        }

        maybeUpdateSize(resize_flag);

        const buffer, const nl_n = computeRedraw(&serialized_buffer);
        if (stderr_mutex.tryLock()) {
            defer stderr_mutex.unlock();
            clearWrittenWindowsApi() catch return;
            windowsApiWriteMarker();
            write(buffer) catch return;
            global_progress.need_clear = true;
            windowsApiMoveToMarker(nl_n) catch return;
        }
    }
}

/// Allows the caller to freely write to stderr until `unlockStdErr` is called.
///
/// During the lock, any `std.Progress` information is cleared from the terminal.
///
/// The lock is recursive; the same thread may hold the lock multiple times.
pub fn lockStdErr() void {
    stderr_mutex.lock();
    clearWrittenWithEscapeCodes() catch {};
}

pub fn unlockStdErr() void {
    stderr_mutex.unlock();
}

fn ipcThreadRun(fd: posix.fd_t) anyerror!void {
    // Store this data in the thread so that it does not need to be part of the
    // linker data of the main executable.
    var serialized_buffer: Serialized.Buffer = undefined;

    {
        _ = wait(global_progress.initial_delay_ns);

        if (@atomicLoad(bool, &global_progress.done, .seq_cst))
            return;

        const serialized = serialize(&serialized_buffer);
        writeIpc(fd, serialized) catch |err| switch (err) {
            error.BrokenPipe => return,
        };
    }

    while (true) {
        _ = wait(global_progress.refresh_rate_ns);

        if (@atomicLoad(bool, &global_progress.done, .seq_cst))
            return;

        const serialized = serialize(&serialized_buffer);
        writeIpc(fd, serialized) catch |err| switch (err) {
            error.BrokenPipe => return,
        };
    }
}

const start_sync = "\x1b[?2026h";
const up_one_line = "\x1bM";
const clear = "\x1b[J";
const save = "\x1b7";
const restore = "\x1b8";
const finish_sync = "\x1b[?2026l";

const TreeSymbol = enum {
    /// ├─
    tee,
    /// │
    line,
    /// └─
    langle,

    const Encoding = enum {
        ansi_escapes,
        code_page_437,
        utf8,
        ascii,
    };

    /// The escape sequence representation as a string literal
    fn escapeSeq(symbol: TreeSymbol) *const [9:0]u8 {
        return switch (symbol) {
            .tee => "\x1B\x28\x30\x74\x71\x1B\x28\x42 ",
            .line => "\x1B\x28\x30\x78\x1B\x28\x42  ",
            .langle => "\x1B\x28\x30\x6d\x71\x1B\x28\x42 ",
        };
    }

    fn bytes(symbol: TreeSymbol, encoding: Encoding) []const u8 {
        return switch (encoding) {
            .ansi_escapes => escapeSeq(symbol),
            .code_page_437 => switch (symbol) {
                .tee => "\xC3\xC4 ",
                .line => "\xB3  ",
                .langle => "\xC0\xC4 ",
            },
            .utf8 => switch (symbol) {
                .tee => "├─ ",
                .line => "│  ",
                .langle => "└─ ",
            },
            .ascii => switch (symbol) {
                .tee => "|- ",
                .line => "|  ",
                .langle => "+- ",
            },
        };
    }

    fn maxByteLen(symbol: TreeSymbol) usize {
        var max: usize = 0;
        inline for (@typeInfo(Encoding).@"enum".fields) |field| {
            const len = symbol.bytes(@field(Encoding, field.name)).len;
            max = @max(max, len);
        }
        return max;
    }
};

fn appendTreeSymbol(symbol: TreeSymbol, buf: []u8, start_i: usize) usize {
    switch (global_progress.terminal_mode) {
        .off => unreachable,
        .ansi_escape_codes => {
            const bytes = symbol.escapeSeq();
            buf[start_i..][0..bytes.len].* = bytes.*;
            return start_i + bytes.len;
        },
        .windows_api => |windows_api| {
            const bytes = if (!is_windows) unreachable else switch (windows_api.code_page) {
                // Code page 437 is the default code page and contains the box drawing symbols
                437 => symbol.bytes(.code_page_437),
                // UTF-8
                65001 => symbol.bytes(.utf8),
                // Fall back to ASCII approximation
                else => symbol.bytes(.ascii),
            };
            @memcpy(buf[start_i..][0..bytes.len], bytes);
            return start_i + bytes.len;
        },
    }
}

fn clearWrittenWithEscapeCodes() anyerror!void {
    if (!global_progress.need_clear) return;

    global_progress.need_clear = false;
    try write(clear);
}

/// U+25BA or ►
const windows_api_start_marker = 0x25BA;

fn clearWrittenWindowsApi() error{Unexpected}!void {
    // This uses a 'marker' strategy. The idea is:
    // - Always write a marker (in this case U+25BA or ►) at the beginning of the progress
    // - Get the current cursor position (at the end of the progress)
    // - Subtract the number of lines written to get the expected start of the progress
    // - Check to see if the first character at the start of the progress is the marker
    // - If it's not the marker, keep checking the line before until we find it
    // - Clear the screen from that position down, and set the cursor position to the start
    //
    // This strategy works even if there is line wrapping, and can handle the window
    // being resized/scrolled arbitrarily.
    //
    // Notes:
    // - Ideally, the marker would be a zero-width character, but the Windows console
    //   doesn't seem to support rendering zero-width characters (they show up as a space)
    // - This same marker idea could technically be done with an attribute instead
    //   (https://learn.microsoft.com/en-us/windows/console/console-screen-buffers#character-attributes)
    //   but it must be a valid attribute and it actually needs to apply to the first
    //   character in order to be readable via ReadConsoleOutputAttribute. It doesn't seem
    //   like any of the available attributes are invisible/benign.
    if (!global_progress.need_clear) return;
    const handle = global_progress.terminal.handle;
    const screen_area = @as(windows.DWORD, global_progress.cols) * global_progress.rows;

    var console_info: windows.CONSOLE_SCREEN_BUFFER_INFO = undefined;
    if (windows.kernel32.GetConsoleScreenBufferInfo(handle, &console_info) == 0) {
        return error.Unexpected;
    }
    var num_chars_written: windows.DWORD = undefined;
    if (windows.kernel32.FillConsoleOutputCharacterW(handle, ' ', screen_area, console_info.dwCursorPosition, &num_chars_written) == 0) {
        return error.Unexpected;
    }
}

fn windowsApiMoveToMarker(nl_n: usize) error{Unexpected}!void {
    const handle = global_progress.terminal.handle;
    var console_info: windows.CONSOLE_SCREEN_BUFFER_INFO = undefined;
    if (windows.kernel32.GetConsoleScreenBufferInfo(handle, &console_info) == 0) {
        return error.Unexpected;
    }
    const cursor_pos = console_info.dwCursorPosition;
    const expected_y = cursor_pos.Y - @as(i16, @intCast(nl_n));
    var start_pos: windows.COORD = .{ .X = 0, .Y = expected_y };
    while (start_pos.Y >= 0) {
        var wchar: [1]u16 = undefined;
        var num_console_chars_read: windows.DWORD = undefined;
        if (windows.kernel32.ReadConsoleOutputCharacterW(handle, &wchar, wchar.len, start_pos, &num_console_chars_read) == 0) {
            return error.Unexpected;
        }

        if (wchar[0] == windows_api_start_marker) break;
        start_pos.Y -= 1;
    } else {
        // If we couldn't find the marker, then just assume that no lines wrapped
        start_pos = .{ .X = 0, .Y = expected_y };
    }
    if (windows.kernel32.SetConsoleCursorPosition(handle, start_pos) == 0) {
        return error.Unexpected;
    }
}

const Children = struct {
    child: Node.OptionalIndex,
    sibling: Node.OptionalIndex,
};

const Serialized = struct {
    parents: []Node.Parent,
    storage: []Node.Storage,

    const Buffer = struct {
        parents: [node_storage_buffer_len]Node.Parent,
        storage: [node_storage_buffer_len]Node.Storage,
        map: [node_storage_buffer_len]Node.OptionalIndex,

        parents_copy: [node_storage_buffer_len]Node.Parent,
        storage_copy: [node_storage_buffer_len]Node.Storage,
        ipc_metadata_fds_copy: [node_storage_buffer_len]Fd,
        ipc_metadata_copy: [node_storage_buffer_len]SavedMetadata,

        ipc_metadata_fds: [node_storage_buffer_len]Fd,
        ipc_metadata: [node_storage_buffer_len]SavedMetadata,
    };
};

fn serialize(serialized_buffer: *Serialized.Buffer) Serialized {
    var serialized_len: usize = 0;
    var any_ipc = false;

    // Iterate all of the nodes and construct a serializable copy of the state that can be examined
    // without atomics.
    const end_index = @atomicLoad(u32, &global_progress.node_end_index, .monotonic);
    for (
        global_progress.node_parents[0..end_index],
        global_progress.node_storage[0..end_index],
        serialized_buffer.map[0..end_index],
    ) |*parent_ptr, *storage_ptr, *map| {
        var begin_parent = @atomicLoad(Node.Parent, parent_ptr, .acquire);
        while (begin_parent != .unused) {
            const dest_storage = &serialized_buffer.storage[serialized_len];
            copyAtomicLoad(&dest_storage.name, &storage_ptr.name);
            dest_storage.estimated_total_count = @atomicLoad(u32, &storage_ptr.estimated_total_count, .acquire);
            dest_storage.completed_count = @atomicLoad(u32, &storage_ptr.completed_count, .monotonic);
            const end_parent = @atomicLoad(Node.Parent, parent_ptr, .acquire);
            if (begin_parent == end_parent) {
                any_ipc = any_ipc or (dest_storage.getIpcFd() != null);
                serialized_buffer.parents[serialized_len] = begin_parent;
                map.* = @enumFromInt(serialized_len);
                serialized_len += 1;
                break;
            }

            begin_parent = end_parent;
        } else {
            // A node may be freed during the execution of this loop, causing
            // there to be a parent reference to a nonexistent node. Without
            // this assignment, this would lead to the map entry containing
            // stale data. By assigning none, the child node with the bad
            // parent pointer will be harmlessly omitted from the tree.
            map.* = .none;
        }
    }

    // Remap parents to point inside serialized arrays.
    for (serialized_buffer.parents[0..serialized_len]) |*parent| {
        parent.* = switch (parent.*) {
            .unused => unreachable,
            .none => .none,
            _ => |p| serialized_buffer.map[@intFromEnum(p)].toParent(),
        };
    }

    // Find nodes which correspond to child processes.
    if (any_ipc)
        serialized_len = serializeIpc(serialized_len, serialized_buffer);

    return .{
        .parents = serialized_buffer.parents[0..serialized_len],
        .storage = serialized_buffer.storage[0..serialized_len],
    };
}

const SavedMetadata = struct {
    remaining_read_trash_bytes: u16,
    main_index: u8,
    start_index: u8,
    nodes_len: u8,
};

const Fd = enum(i32) {
    _,

    fn init(fd: posix.fd_t) Fd {
        return @enumFromInt(if (is_windows) @as(isize, @bitCast(@intFromPtr(fd))) else fd);
    }

    fn get(fd: Fd) posix.fd_t {
        return if (is_windows)
            @ptrFromInt(@as(usize, @bitCast(@as(isize, @intFromEnum(fd)))))
        else
            @intFromEnum(fd);
    }
};

var ipc_metadata_len: u8 = 0;

fn serializeIpc(start_serialized_len: usize, serialized_buffer: *Serialized.Buffer) usize {
    const ipc_metadata_fds_copy = &serialized_buffer.ipc_metadata_fds_copy;
    const ipc_metadata_copy = &serialized_buffer.ipc_metadata_copy;
    const ipc_metadata_fds = &serialized_buffer.ipc_metadata_fds;
    const ipc_metadata = &serialized_buffer.ipc_metadata;

    var serialized_len = start_serialized_len;
    var pipe_buf: [2 * 4096]u8 = undefined;

    const old_ipc_metadata_fds = ipc_metadata_fds_copy[0..ipc_metadata_len];
    const old_ipc_metadata = ipc_metadata_copy[0..ipc_metadata_len];
    ipc_metadata_len = 0;

    main_loop: for (
        serialized_buffer.parents[0..serialized_len],
        serialized_buffer.storage[0..serialized_len],
        0..,
    ) |main_parent, *main_storage, main_index| {
        if (main_parent == .unused) continue;
        const fd = main_storage.getIpcFd() orelse continue;
        const opt_saved_metadata = findOld(fd, old_ipc_metadata_fds, old_ipc_metadata);
        var bytes_read: usize = 0;
        while (true) {
            const n = posix.read(fd, pipe_buf[bytes_read..]) catch |err| switch (err) {
                error.WouldBlock => break,
                else => |e| {
                    std.log.debug("failed to read child progress data: {s}", .{@errorName(e)});
                    main_storage.completed_count = 0;
                    main_storage.estimated_total_count = 0;
                    continue :main_loop;
                },
            };
            if (n == 0) break;
            if (opt_saved_metadata) |m| {
                if (m.remaining_read_trash_bytes > 0) {
                    assert(bytes_read == 0);
                    if (m.remaining_read_trash_bytes >= n) {
                        m.remaining_read_trash_bytes = @intCast(m.remaining_read_trash_bytes - n);
                        continue;
                    }
                    const src = pipe_buf[m.remaining_read_trash_bytes..n];
                    std.mem.copyForwards(u8, &pipe_buf, src);
                    m.remaining_read_trash_bytes = 0;
                    bytes_read = src.len;
                    continue;
                }
            }
            bytes_read += n;
        }
        // Ignore all but the last message on the pipe.
        var input: []u8 = pipe_buf[0..bytes_read];
        if (input.len == 0) {
            serialized_len = useSavedIpcData(serialized_len, serialized_buffer, main_storage, main_index, opt_saved_metadata, 0, fd);
            continue;
        }

        const storage, const parents = while (true) {
            const subtree_len: usize = input[0];
            const expected_bytes = 1 + subtree_len * (@sizeOf(Node.Storage) + @sizeOf(Node.Parent));
            if (input.len < expected_bytes) {
                // Ignore short reads. We'll handle the next full message when it comes instead.
                const remaining_read_trash_bytes: u16 = @intCast(expected_bytes - input.len);
                serialized_len = useSavedIpcData(serialized_len, serialized_buffer, main_storage, main_index, opt_saved_metadata, remaining_read_trash_bytes, fd);
                continue :main_loop;
            }
            if (input.len > expected_bytes) {
                input = input[expected_bytes..];
                continue;
            }
            const storage_bytes = input[1..][0 .. subtree_len * @sizeOf(Node.Storage)];
            const parents_bytes = input[1 + storage_bytes.len ..][0 .. subtree_len * @sizeOf(Node.Parent)];
            break .{
                std.mem.bytesAsSlice(Node.Storage, storage_bytes),
                std.mem.bytesAsSlice(Node.Parent, parents_bytes),
            };
        };

        const nodes_len: u8 = @intCast(@min(parents.len - 1, serialized_buffer.storage.len - serialized_len));

        // Remember in case the pipe is empty on next update.
        ipc_metadata_fds[ipc_metadata_len] = Fd.init(fd);
        ipc_metadata[ipc_metadata_len] = .{
            .remaining_read_trash_bytes = 0,
            .start_index = @intCast(serialized_len),
            .nodes_len = nodes_len,
            .main_index = @intCast(main_index),
        };
        ipc_metadata_len += 1;

        // Mount the root here.
        copyRoot(main_storage, &storage[0]);
        if (is_big_endian) main_storage.byteSwap();

        // Copy the rest of the tree to the end.
        const storage_dest = serialized_buffer.storage[serialized_len..][0..nodes_len];
        @memcpy(storage_dest, storage[1..][0..nodes_len]);

        // Always little-endian over the pipe.
        if (is_big_endian) for (storage_dest) |*s| s.byteSwap();

        // Patch up parent pointers taking into account how the subtree is mounted.
        for (serialized_buffer.parents[serialized_len..][0..nodes_len], parents[1..][0..nodes_len]) |*dest, p| {
            dest.* = switch (p) {
                // Fix bad data so the rest of the code does not see `unused`.
                .none, .unused => .none,
                // Root node is being mounted here.
                @as(Node.Parent, @enumFromInt(0)) => @enumFromInt(main_index),
                // Other nodes mounted at the end.
                // Don't trust child data; if the data is outside the expected range, ignore the data.
                // This also handles the case when data was truncated.
                _ => |off| if (@intFromEnum(off) > nodes_len)
                    .none
                else
                    @enumFromInt(serialized_len + @intFromEnum(off) - 1),
            };
        }

        serialized_len += nodes_len;
    }

    // Save a copy in case any pipes are empty on the next update.
    @memcpy(serialized_buffer.parents_copy[0..serialized_len], serialized_buffer.parents[0..serialized_len]);
    @memcpy(serialized_buffer.storage_copy[0..serialized_len], serialized_buffer.storage[0..serialized_len]);
    @memcpy(ipc_metadata_fds_copy[0..ipc_metadata_len], ipc_metadata_fds[0..ipc_metadata_len]);
    @memcpy(ipc_metadata_copy[0..ipc_metadata_len], ipc_metadata[0..ipc_metadata_len]);

    return serialized_len;
}

fn copyRoot(dest: *Node.Storage, src: *align(1) Node.Storage) void {
    dest.* = .{
        .completed_count = src.completed_count,
        .estimated_total_count = src.estimated_total_count,
        .name = if (src.name[0] == 0) dest.name else src.name,
    };
}

fn findOld(
    ipc_fd: posix.fd_t,
    old_metadata_fds: []Fd,
    old_metadata: []SavedMetadata,
) ?*SavedMetadata {
    for (old_metadata_fds, old_metadata) |fd, *m| {
        if (fd.get() == ipc_fd)
            return m;
    }
    return null;
}

fn useSavedIpcData(
    start_serialized_len: usize,
    serialized_buffer: *Serialized.Buffer,
    main_storage: *Node.Storage,
    main_index: usize,
    opt_saved_metadata: ?*SavedMetadata,
    remaining_read_trash_bytes: u16,
    fd: posix.fd_t,
) usize {
    const parents_copy = &serialized_buffer.parents_copy;
    const storage_copy = &serialized_buffer.storage_copy;
    const ipc_metadata_fds = &serialized_buffer.ipc_metadata_fds;
    const ipc_metadata = &serialized_buffer.ipc_metadata;

    const saved_metadata = opt_saved_metadata orelse {
        main_storage.completed_count = 0;
        main_storage.estimated_total_count = 0;
        if (remaining_read_trash_bytes > 0) {
            ipc_metadata_fds[ipc_metadata_len] = Fd.init(fd);
            ipc_metadata[ipc_metadata_len] = .{
                .remaining_read_trash_bytes = remaining_read_trash_bytes,
                .start_index = @intCast(start_serialized_len),
                .nodes_len = 0,
                .main_index = @intCast(main_index),
            };
            ipc_metadata_len += 1;
        }
        return start_serialized_len;
    };

    const start_index = saved_metadata.start_index;
    const nodes_len = @min(saved_metadata.nodes_len, serialized_buffer.storage.len - start_serialized_len);
    const old_main_index = saved_metadata.main_index;

    ipc_metadata_fds[ipc_metadata_len] = Fd.init(fd);
    ipc_metadata[ipc_metadata_len] = .{
        .remaining_read_trash_bytes = remaining_read_trash_bytes,
        .start_index = @intCast(start_serialized_len),
        .nodes_len = nodes_len,
        .main_index = @intCast(main_index),
    };
    ipc_metadata_len += 1;

    const parents = parents_copy[start_index..][0..nodes_len];
    const storage = storage_copy[start_index..][0..nodes_len];

    copyRoot(main_storage, &storage_copy[old_main_index]);

    @memcpy(serialized_buffer.storage[start_serialized_len..][0..storage.len], storage);

    for (serialized_buffer.parents[start_serialized_len..][0..parents.len], parents) |*dest, p| {
        dest.* = switch (p) {
            .none, .unused => .none,
            _ => |prev| d: {
                if (@intFromEnum(prev) == old_main_index) {
                    break :d @enumFromInt(main_index);
                } else if (@intFromEnum(prev) > nodes_len) {
                    break :d .none;
                } else {
                    break :d @enumFromInt(@intFromEnum(prev) - start_index + start_serialized_len);
                }
            },
        };
    }

    return start_serialized_len + storage.len;
}

fn computeRedraw(serialized_buffer: *Serialized.Buffer) struct { []u8, usize } {
    const serialized = serialize(serialized_buffer);

    // Now we can analyze our copy of the graph without atomics, reconstructing
    // children lists which do not exist in the canonical data. These are
    // needed for tree traversal below.

    var children_buffer: [node_storage_buffer_len]Children = undefined;
    const children = children_buffer[0..serialized.parents.len];

    @memset(children, .{ .child = .none, .sibling = .none });

    for (serialized.parents, 0..) |parent, child_index_usize| {
        const child_index: Node.Index = @enumFromInt(child_index_usize);
        assert(parent != .unused);
        const parent_index = parent.unwrap() orelse continue;
        const children_node = &children[@intFromEnum(parent_index)];
        if (children_node.child.unwrap()) |existing_child_index| {
            const existing_child = &children[@intFromEnum(existing_child_index)];
            children[@intFromEnum(child_index)].sibling = existing_child.sibling;
            existing_child.sibling = child_index.toOptional();
        } else {
            children_node.child = child_index.toOptional();
        }
    }

    // The strategy is, with every redraw:
    // erase to end of screen, write, move cursor to beginning of line, move cursor up N lines
    // This keeps the cursor at the beginning so that unlocked stderr writes
    // don't get eaten by the clear.

    var i: usize = 0;
    const buf = global_progress.draw_buffer;

    if (global_progress.terminal_mode == .ansi_escape_codes) {
        buf[i..][0..start_sync.len].* = start_sync.*;
        i += start_sync.len;
    }

    switch (global_progress.terminal_mode) {
        .off => unreachable,
        .ansi_escape_codes => {
            buf[i..][0..clear.len].* = clear.*;
            i += clear.len;
        },
        .windows_api => if (!is_windows) unreachable,
    }

    const root_node_index: Node.Index = @enumFromInt(0);
    i, const nl_n = computeNode(buf, i, 0, serialized, children, root_node_index);

    if (global_progress.terminal_mode == .ansi_escape_codes) {
        if (nl_n > 0) {
            buf[i] = '\r';
            i += 1;
            for (0..nl_n) |_| {
                buf[i..][0..up_one_line.len].* = up_one_line.*;
                i += up_one_line.len;
            }
        }

        buf[i..][0..finish_sync.len].* = finish_sync.*;
        i += finish_sync.len;
    }

    return .{ buf[0..i], nl_n };
}

fn computePrefix(
    buf: []u8,
    start_i: usize,
    nl_n: usize,
    serialized: Serialized,
    children: []const Children,
    node_index: Node.Index,
) usize {
    var i = start_i;
    const parent_index = serialized.parents[@intFromEnum(node_index)].unwrap() orelse return i;
    if (serialized.parents[@intFromEnum(parent_index)] == .none) return i;
    if (@intFromEnum(serialized.parents[@intFromEnum(parent_index)]) == 0 and
        serialized.storage[0].name[0] == 0)
    {
        return i;
    }
    i = computePrefix(buf, i, nl_n, serialized, children, parent_index);
    if (children[@intFromEnum(parent_index)].sibling == .none) {
        const prefix = "   ";
        const upper_bound_len = prefix.len + lineUpperBoundLen(nl_n);
        if (i + upper_bound_len > buf.len) return buf.len;
        buf[i..][0..prefix.len].* = prefix.*;
        i += prefix.len;
    } else {
        const upper_bound_len = TreeSymbol.line.maxByteLen() + lineUpperBoundLen(nl_n);
        if (i + upper_bound_len > buf.len) return buf.len;
        i = appendTreeSymbol(.line, buf, i);
    }
    return i;
}

fn lineUpperBoundLen(nl_n: usize) usize {
    // \r\n on Windows, \n otherwise.
    const nl_len = if (is_windows) 2 else 1;
    return @max(TreeSymbol.tee.maxByteLen(), TreeSymbol.langle.maxByteLen()) +
        "[4294967296/4294967296] ".len + Node.max_name_len + nl_len +
        (1 + (nl_n + 1) * up_one_line.len) +
        finish_sync.len;
}

fn computeNode(
    buf: []u8,
    start_i: usize,
    start_nl_n: usize,
    serialized: Serialized,
    children: []const Children,
    node_index: Node.Index,
) struct { usize, usize } {
    var i = start_i;
    var nl_n = start_nl_n;

    i = computePrefix(buf, i, nl_n, serialized, children, node_index);

    if (i + lineUpperBoundLen(nl_n) > buf.len)
        return .{ start_i, start_nl_n };

    const storage = &serialized.storage[@intFromEnum(node_index)];
    const estimated_total = storage.estimated_total_count;
    const completed_items = storage.completed_count;
    const name = if (std.mem.indexOfScalar(u8, &storage.name, 0)) |end| storage.name[0..end] else &storage.name;
    const parent = serialized.parents[@intFromEnum(node_index)];

    if (parent != .none) p: {
        if (@intFromEnum(parent) == 0 and serialized.storage[0].name[0] == 0) {
            break :p;
        }
        if (children[@intFromEnum(node_index)].sibling == .none) {
            i = appendTreeSymbol(.langle, buf, i);
        } else {
            i = appendTreeSymbol(.tee, buf, i);
        }
    }

    const is_empty_root = @intFromEnum(node_index) == 0 and serialized.storage[0].name[0] == 0;
    if (!is_empty_root) {
        if (name.len != 0 or estimated_total > 0) {
            if (estimated_total > 0) {
                i += (std.fmt.bufPrint(buf[i..], "[{d}/{d}] ", .{ completed_items, estimated_total }) catch &.{}).len;
            } else if (completed_items != 0) {
                i += (std.fmt.bufPrint(buf[i..], "[{d}] ", .{completed_items}) catch &.{}).len;
            }
            if (name.len != 0) {
                i += (std.fmt.bufPrint(buf[i..], "{s}", .{name}) catch &.{}).len;
            }
        }

        i = @min(global_progress.cols + start_i, i);
        if (is_windows) {
            // \r\n on Windows is necessary for the old console with the
            // ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN
            // console modes set to behave properly.
            buf[i] = '\r';
            i += 1;
        }
        buf[i] = '\n';
        i += 1;
        nl_n += 1;
    }

    if (global_progress.withinRowLimit(nl_n)) {
        if (children[@intFromEnum(node_index)].child.unwrap()) |child| {
            i, nl_n = computeNode(buf, i, nl_n, serialized, children, child);
        }
    }

    if (global_progress.withinRowLimit(nl_n)) {
        if (children[@intFromEnum(node_index)].sibling.unwrap()) |sibling| {
            i, nl_n = computeNode(buf, i, nl_n, serialized, children, sibling);
        }
    }

    return .{ i, nl_n };
}

fn withinRowLimit(p: *Progress, nl_n: usize) bool {
    // The +2 here is so that the PS1 is not scrolled off the top of the terminal.
    // one because we keep the cursor on the next line
    // one more to account for the PS1
    return nl_n + 2 < p.rows;
}

fn write(buf: []const u8) anyerror!void {
    try global_progress.terminal.writeAll(buf);
}

var remaining_write_trash_bytes: usize = 0;

fn writeIpc(fd: posix.fd_t, serialized: Serialized) error{BrokenPipe}!void {
    // Byteswap if necessary to ensure little endian over the pipe. This is
    // needed because the parent or child process might be running in qemu.
    if (is_big_endian) for (serialized.storage) |*s| s.byteSwap();

    assert(serialized.parents.len == serialized.storage.len);
    const serialized_len: u8 = @intCast(serialized.parents.len);
    const header = std.mem.asBytes(&serialized_len);
    const storage = std.mem.sliceAsBytes(serialized.storage);
    const parents = std.mem.sliceAsBytes(serialized.parents);

    var vecs: [3]posix.iovec_const = .{
        .{ .base = header.ptr, .len = header.len },
        .{ .base = storage.ptr, .len = storage.len },
        .{ .base = parents.ptr, .len = parents.len },
    };

    // Ensures the packet can fit in the pipe buffer.
    const upper_bound_msg_len = 1 + node_storage_buffer_len * @sizeOf(Node.Storage) +
        node_storage_buffer_len * @sizeOf(Node.OptionalIndex);
    comptime assert(upper_bound_msg_len <= 4096);

    while (remaining_write_trash_bytes > 0) {
        // We do this in a separate write call to give a better chance for the
        // writev below to be in a single packet.
        const n = @min(parents.len, remaining_write_trash_bytes);
        if (posix.write(fd, parents[0..n])) |written| {
            remaining_write_trash_bytes -= written;
            continue;
        } else |err| switch (err) {
            error.WouldBlock => return,
            error.BrokenPipe => return error.BrokenPipe,
            else => |e| {
                std.log.debug("failed to send progress to parent process: {s}", .{@errorName(e)});
                return error.BrokenPipe;
            },
        }
    }

    // If this write would block we do not want to keep trying, but we need to
    // know if a partial message was written.
    if (writevNonblock(fd, &vecs)) |written| {
        const total = header.len + storage.len + parents.len;
        if (written < total) {
            remaining_write_trash_bytes = total - written;
        }
    } else |err| switch (err) {
        error.WouldBlock => {},
        error.BrokenPipe => return error.BrokenPipe,
        else => |e| {
            std.log.debug("failed to send progress to parent process: {s}", .{@errorName(e)});
            return error.BrokenPipe;
        },
    }
}

fn writevNonblock(fd: posix.fd_t, iov: []posix.iovec_const) posix.WriteError!usize {
    var iov_index: usize = 0;
    var written: usize = 0;
    var total_written: usize = 0;
    while (true) {
        while (if (iov_index < iov.len)
            written >= iov[iov_index].len
        else
            return total_written) : (iov_index += 1) written -= iov[iov_index].len;
        iov[iov_index].base += written;
        iov[iov_index].len -= written;
        written = try posix.writev(fd, iov[iov_index..]);
        if (written == 0) return total_written;
        total_written += written;
    }
}

fn maybeUpdateSize(resize_flag: bool) void {
    if (!resize_flag) return;

    const fd = global_progress.terminal.handle;

    if (is_windows) {
        var info: windows.CONSOLE_SCREEN_BUFFER_INFO = undefined;

        if (windows.kernel32.GetConsoleScreenBufferInfo(fd, &info) != windows.FALSE) {
            // In the old Windows console, dwSize.Y is the line count of the
            // entire scrollback buffer, so we use this instead so that we
            // always get the size of the screen.
            const screen_height = info.srWindow.Bottom - info.srWindow.Top;
            global_progress.rows = @intCast(screen_height);
            global_progress.cols = @intCast(info.dwSize.X);
        } else {
            std.log.debug("failed to determine terminal size; using conservative guess 80x25", .{});
            global_progress.rows = 25;
            global_progress.cols = 80;
        }
    } else {
        var winsize: posix.winsize = .{
            .row = 0,
            .col = 0,
            .xpixel = 0,
            .ypixel = 0,
        };

        const err = posix.system.ioctl(fd, posix.T.IOCGWINSZ, @intFromPtr(&winsize));
        if (posix.errno(err) == .SUCCESS) {
            global_progress.rows = winsize.row;
            global_progress.cols = winsize.col;
        } else {
            std.log.debug("failed to determine terminal size; using conservative guess 80x25", .{});
            global_progress.rows = 25;
            global_progress.cols = 80;
        }
    }
}

fn handleSigWinch(sig: i32, info: *const posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) void {
    _ = info;
    _ = ctx_ptr;
    assert(sig == posix.SIG.WINCH);
    global_progress.redraw_event.set();
}

const have_sigwinch = switch (builtin.os.tag) {
    .linux,
    .plan9,
    .solaris,
    .netbsd,
    .openbsd,
    .haiku,
    .macos,
    .ios,
    .watchos,
    .tvos,
    .visionos,
    .dragonfly,
    .freebsd,
    => true,

    else => false,
};

/// The primary motivation for recursive mutex here is so that a panic while
/// stderr mutex is held still dumps the stack trace and other debug
/// information.
var stderr_mutex = std.Thread.Mutex.Recursive.init;

fn copyAtomicStore(dest: []align(@alignOf(usize)) u8, src: []const u8) void {
    assert(dest.len == src.len);
    const chunked_len = dest.len / @sizeOf(usize);
    const dest_chunked: []usize = @as([*]usize, @ptrCast(dest))[0..chunked_len];
    const src_chunked: []align(1) const usize = @as([*]align(1) const usize, @ptrCast(src))[0..chunked_len];
    for (dest_chunked, src_chunked) |*d, s| {
        @atomicStore(usize, d, s, .monotonic);
    }
    const remainder_start = chunked_len * @sizeOf(usize);
    for (dest[remainder_start..], src[remainder_start..]) |*d, s| {
        @atomicStore(u8, d, s, .monotonic);
    }
}

fn copyAtomicLoad(
    dest: *align(@alignOf(usize)) [Node.max_name_len]u8,
    src: *align(@alignOf(usize)) const [Node.max_name_len]u8,
) void {
    const chunked_len = @divExact(dest.len, @sizeOf(usize));
    const dest_chunked: *[chunked_len]usize = @ptrCast(dest);
    const src_chunked: *const [chunked_len]usize = @ptrCast(src);
    for (dest_chunked, src_chunked) |*d, *s| {
        d.* = @atomicLoad(usize, s, .monotonic);
    }
}
//! CSPRNG based on the 12-rounds Keccak-F(1600) permutation.

const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const mem = std.mem;
const Random = std.rand.Random;
const Self = @This();

const KeccakF = std.crypto.core.keccak.KeccakF(1600);

state: KeccakF,
offset: usize = 0,

const security_level = 128;
const rate = KeccakF.block_bytes - security_level / 8;
pub const secret_seed_length = 32;

/// The seed must be uniform, secret and `secret_seed_length` bytes long.
pub fn init(secret_seed: [secret_seed_length]u8) Self {
    var self = Self{ .state = .{} };
    self.addEntropy(&secret_seed);
    return self;
}

/// Inserts entropy to refresh the internal state.
pub fn addEntropy(self: *Self, bytes: []const u8) void {
    var i: usize = 0;
    while (i + rate <= bytes.len) : (i += rate) {
        self.state.addBytes(bytes[i..][0..rate]);
        self.state.permuteR(12);
    }
    self.state.addBytes(bytes[i..]);
    self.state.addByte(0x01, self.offset);
    self.state.addByte(0x80, rate - 1);
    self.state.permuteR(12);
    self.offset = 0;
}

/// Returns a `std.rand.Random` structure backed by the current RNG.
pub fn random(self: *Self) Random {
    return Random.init(self, fill);
}

/// Fills the buffer with random bytes.
pub fn fill(self: *Self, buf_: []u8) void {
    var buf = buf_;

    var available = rate - self.offset;
    if (available > 0) {
        // Copy the remaining bytes from the internal state.
        const n = @min(available, buf.len);
        var st_bytes = self.state.asBytes();
        mem.copy(u8, buf[0..n], st_bytes[self.offset..][0..n]);
        buf = buf[n..];

        // The remaining bytes were enough to fully fill the buffer.
        if (buf.len == 0) {
            if (self.offset == rate) {
                // If every byte was used, reset the internal state.
                self.state.clear(0, security_level / 8);
                self.state.permuteR(12);
                self.offset = 0;
            } else {
                // Otherwise, overwrite what we used and keep the rest.
                mem.set(u8, st_bytes[self.offset..][0..n], 0);
                self.offset += n;
            }
            return;
        }
    }

    // The internal state was not enough to fill the buffer, so we need to
    // permute and extract more bytes.
    self.state.permuteR(12);

    // Extract full blocks first.
    while (buf.len > rate) {
        self.state.extractBytes(buf[0..rate]);
        buf = buf[rate..];
        self.state.permuteR(12);
    }
    // Then, extract the remaining bytes.
    self.state.extractBytes(buf);
    self.offset = buf.len;

    if (self.offset == rate) {
        // If every byte was used, reset the internal state.
        self.state.clear(0, security_level / 8);
        self.state.permuteR(12);
        self.offset = 0;
    } else {
        // Otherwise, overwrite what we used and keep the rest.
        mem.set(u8, self.state.asBytes()[0..buf.len], 0);
    }
}
//! The engines provided here should be initialized from an external source.
//! For a thread-local cryptographically secure pseudo random number generator,
//! use `std.crypto.random`.
//! Be sure to use a CSPRNG when required, otherwise using a normal PRNG will
//! be faster and use substantially less stack space.

const std = @import("std.zig");
const math = std.math;
const mem = std.mem;
const assert = std.debug.assert;
const maxInt = std.math.maxInt;
const Random = @This();

/// Fast unbiased random numbers.
pub const DefaultPrng = Xoshiro256;

/// Cryptographically secure random numbers.
pub const DefaultCsprng = ChaCha;

pub const Ascon = @import("Random/Ascon.zig");
pub const ChaCha = @import("Random/ChaCha.zig");

pub const Isaac64 = @import("Random/Isaac64.zig");
pub const Pcg = @import("Random/Pcg.zig");
pub const Xoroshiro128 = @import("Random/Xoroshiro128.zig");
pub const Xoshiro256 = @import("Random/Xoshiro256.zig");
pub const Sfc64 = @import("Random/Sfc64.zig");
pub const RomuTrio = @import("Random/RomuTrio.zig");
pub const SplitMix64 = @import("Random/SplitMix64.zig");
pub const ziggurat = @import("Random/ziggurat.zig");

/// Any comparison of this field may result in illegal behavior, since it may be set to
/// `undefined` in cases where the random implementation does not have any associated
/// state.
ptr: *anyopaque,
fillFn: *const fn (ptr: *anyopaque, buf: []u8) void,

pub fn init(pointer: anytype, comptime fillFn: fn (ptr: @TypeOf(pointer), buf: []u8) void) Random {
    const Ptr = @TypeOf(pointer);
    assert(@typeInfo(Ptr) == .pointer); // Must be a pointer
    assert(@typeInfo(Ptr).pointer.size == .one); // Must be a single-item pointer
    assert(@typeInfo(@typeInfo(Ptr).pointer.child) == .@"struct"); // Must point to a struct
    const gen = struct {
        fn fill(ptr: *anyopaque, buf: []u8) void {
            const self: Ptr = @ptrCast(@alignCast(ptr));
            fillFn(self, buf);
        }
    };

    return .{
        .ptr = pointer,
        .fillFn = gen.fill,
    };
}

/// Read random bytes into the specified buffer until full.
pub fn bytes(r: Random, buf: []u8) void {
    r.fillFn(r.ptr, buf);
}

pub fn boolean(r: Random) bool {
    return r.int(u1) != 0;
}

/// Returns a random value from an enum, evenly distributed.
///
/// Note that this will not yield consistent results across all targets
/// due to dependence on the representation of `usize` as an index.
/// See `enumValueWithIndex` for further commentary.
pub inline fn enumValue(r: Random, comptime EnumType: type) EnumType {
    return r.enumValueWithIndex(EnumType, usize);
}

/// Returns a random value from an enum, evenly distributed.
///
/// An index into an array of all named values is generated using the
/// specified `Index` type to determine the return value.
/// This allows for results to be independent of `usize` representation.
///
/// Prefer `enumValue` if this isn't important.
///
/// See `uintLessThan`, which this function uses in most cases,
/// for commentary on the runtime of this function.
pub fn enumValueWithIndex(r: Random, comptime EnumType: type, comptime Index: type) EnumType {
    comptime assert(@typeInfo(EnumType) == .@"enum");

    // We won't use int -> enum casting because enum elements can have
    //  arbitrary values.  Instead we'll randomly pick one of the type's values.
    const values = comptime std.enums.values(EnumType);
    comptime assert(values.len > 0); // can't return anything
    comptime assert(maxInt(Index) >= values.len - 1); // can't access all values
    if (values.len == 1) return values[0];

    const index = if (comptime values.len - 1 == maxInt(Index))
        r.int(Index)
    else
        r.uintLessThan(Index, values.len);

    const MinInt = MinArrayIndex(Index);
    return values[@as(MinInt, @intCast(index))];
}

/// Returns a random int `i` such that `minInt(T) <= i <= maxInt(T)`.
/// `i` is evenly distributed.
pub fn int(r: Random, comptime T: type) T {
    const bits = @typeInfo(T).int.bits;
    const UnsignedT = std.meta.Int(.unsigned, bits);
    const ceil_bytes = comptime std.math.divCeil(u16, bits, 8) catch unreachable;
    const ByteAlignedT = std.meta.Int(.unsigned, ceil_bytes * 8);

    var rand_bytes: [ceil_bytes]u8 = undefined;
    r.bytes(&rand_bytes);

    // use LE instead of native endian for better portability maybe?
    // TODO: endian portability is pointless if the underlying prng isn't endian portable.
    // TODO: document the endian portability of this library.
    const byte_aligned_result = mem.readInt(ByteAlignedT, &rand_bytes, .little);
    const unsigned_result: UnsignedT = @truncate(byte_aligned_result);
    return @bitCast(unsigned_result);
}

/// Constant-time implementation off `uintLessThan`.
/// The results of this function may be biased.
pub fn uintLessThanBiased(r: Random, comptime T: type, less_than: T) T {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    assert(0 < less_than);
    return limitRangeBiased(T, r.int(T), less_than);
}

/// Returns an evenly distributed random unsigned integer `0 <= i < less_than`.
/// This function assumes that the underlying `fillFn` produces evenly distributed values.
/// Within this assumption, the runtime of this function is exponentially distributed.
/// If `fillFn` were backed by a true random generator,
/// the runtime of this function would technically be unbounded.
/// However, if `fillFn` is backed by any evenly distributed pseudo random number generator,
/// this function is guaranteed to return.
/// If you need deterministic runtime bounds, use `uintLessThanBiased`.
pub fn uintLessThan(r: Random, comptime T: type, less_than: T) T {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    const bits = @typeInfo(T).int.bits;
    assert(0 < less_than);

    // adapted from:
    //   http://www.pcg-random.org/posts/bounded-rands.html
    //   "Lemire's (with an extra tweak from me)"
    var x = r.int(T);
    var m = math.mulWide(T, x, less_than);
    var l: T = @truncate(m);
    if (l < less_than) {
        var t = -%less_than;

        if (t >= less_than) {
            t -= less_than;
            if (t >= less_than) {
                t %= less_than;
            }
        }
        while (l < t) {
            x = r.int(T);
            m = math.mulWide(T, x, less_than);
            l = @truncate(m);
        }
    }
    return @intCast(m >> bits);
}

/// Constant-time implementation off `uintAtMost`.
/// The results of this function may be biased.
pub fn uintAtMostBiased(r: Random, comptime T: type, at_most: T) T {
    assert(@typeInfo(T).int.signedness == .unsigned);
    if (at_most == maxInt(T)) {
        // have the full range
        return r.int(T);
    }
    return r.uintLessThanBiased(T, at_most + 1);
}

/// Returns an evenly distributed random unsigned integer `0 <= i <= at_most`.
/// See `uintLessThan`, which this function uses in most cases,
/// for commentary on the runtime of this function.
pub fn uintAtMost(r: Random, comptime T: type, at_most: T) T {
    assert(@typeInfo(T).int.signedness == .unsigned);
    if (at_most == maxInt(T)) {
        // have the full range
        return r.int(T);
    }
    return r.uintLessThan(T, at_most + 1);
}

/// Constant-time implementation off `intRangeLessThan`.
/// The results of this function may be biased.
pub fn intRangeLessThanBiased(r: Random, comptime T: type, at_least: T, less_than: T) T {
    assert(at_least < less_than);
    const info = @typeInfo(T).int;
    if (info.signedness == .signed) {
        // Two's complement makes this math pretty easy.
        const UnsignedT = std.meta.Int(.unsigned, info.bits);
        const lo: UnsignedT = @bitCast(at_least);
        const hi: UnsignedT = @bitCast(less_than);
        const result = lo +% r.uintLessThanBiased(UnsignedT, hi -% lo);
        return @bitCast(result);
    } else {
        // The signed implementation would work fine, but we can use stricter arithmetic operators here.
        return at_least + r.uintLessThanBiased(T, less_than - at_least);
    }
}

/// Returns an evenly distributed random integer `at_least <= i < less_than`.
/// See `uintLessThan`, which this function uses in most cases,
/// for commentary on the runtime of this function.
pub fn intRangeLessThan(r: Random, comptime T: type, at_least: T, less_than: T) T {
    assert(at_least < less_than);
    const info = @typeInfo(T).int;
    if (info.signedness == .signed) {
        // Two's complement makes this math pretty easy.
        const UnsignedT = std.meta.Int(.unsigned, info.bits);
        const lo: UnsignedT = @bitCast(at_least);
        const hi: UnsignedT = @bitCast(less_than);
        const result = lo +% r.uintLessThan(UnsignedT, hi -% lo);
        return @bitCast(result);
    } else {
        // The signed implementation would work fine, but we can use stricter arithmetic operators here.
        return at_least + r.uintLessThan(T, less_than - at_least);
    }
}

/// Constant-time implementation off `intRangeAtMostBiased`.
/// The results of this function may be biased.
pub fn intRangeAtMostBiased(r: Random, comptime T: type, at_least: T, at_most: T) T {
    assert(at_least <= at_most);
    const info = @typeInfo(T).int;
    if (info.signedness == .signed) {
        // Two's complement makes this math pretty easy.
        const UnsignedT = std.meta.Int(.unsigned, info.bits);
        const lo: UnsignedT = @bitCast(at_least);
        const hi: UnsignedT = @bitCast(at_most);
        const result = lo +% r.uintAtMostBiased(UnsignedT, hi -% lo);
        return @bitCast(result);
    } else {
        // The signed implementation would work fine, but we can use stricter arithmetic operators here.
        return at_least + r.uintAtMostBiased(T, at_most - at_least);
    }
}

/// Returns an evenly distributed random integer `at_least <= i <= at_most`.
/// See `uintLessThan`, which this function uses in most cases,
/// for commentary on the runtime of this function.
pub fn intRangeAtMost(r: Random, comptime T: type, at_least: T, at_most: T) T {
    assert(at_least <= at_most);
    const info = @typeInfo(T).int;
    if (info.signedness == .signed) {
        // Two's complement makes this math pretty easy.
        const UnsignedT = std.meta.Int(.unsigned, info.bits);
        const lo: UnsignedT = @bitCast(at_least);
        const hi: UnsignedT = @bitCast(at_most);
        const result = lo +% r.uintAtMost(UnsignedT, hi -% lo);
        return @bitCast(result);
    } else {
        // The signed implementation would work fine, but we can use stricter arithmetic operators here.
        return at_least + r.uintAtMost(T, at_most - at_least);
    }
}

/// Return a floating point value evenly distributed in the range [0, 1).
pub fn float(r: Random, comptime T: type) T {
    // Generate a uniformly random value for the mantissa.
    // Then generate an exponentially biased random value for the exponent.
    // This covers every possible value in the range.
    switch (T) {
        f32 => {
            // Use 23 random bits for the mantissa, and the rest for the exponent.
            // If all 41 bits are zero, generate additional random bits, until a
            // set bit is found, or 126 bits have been generated.
            const rand = r.int(u64);
            var rand_lz = @clz(rand);
            if (rand_lz >= 41) {
                @branchHint(.unlikely);
                rand_lz = 41 + @clz(r.int(u64));
                if (rand_lz == 41 + 64) {
                    @branchHint(.unlikely);
                    // It is astronomically unlikely to reach this point.
                    rand_lz += @clz(r.int(u32) | 0x7FF);
                }
            }
            const mantissa: u23 = @truncate(rand);
            const exponent = @as(u32, 126 - rand_lz) << 23;
            return @bitCast(exponent | mantissa);
        },
        f64 => {
            // Use 52 random bits for the mantissa, and the rest for the exponent.
            // If all 12 bits are zero, generate additional random bits, until a
            // set bit is found, or 1022 bits have been generated.
            const rand = r.int(u64);
            var rand_lz: u64 = @clz(rand);
            if (rand_lz >= 12) {
                rand_lz = 12;
                while (true) {
                    // It is astronomically unlikely for this loop to execute more than once.
                    const addl_rand_lz = @clz(r.int(u64));
                    rand_lz += addl_rand_lz;
                    if (addl_rand_lz != 64) {
                        @branchHint(.likely);
                        break;
                    }
                    if (rand_lz >= 1022) {
                        rand_lz = 1022;
                        break;
                    }
                }
            }
            const mantissa = rand & 0xFFFFFFFFFFFFF;
            const exponent = (1022 - rand_lz) << 52;
            return @bitCast(exponent | mantissa);
        },
        else => @compileError("unknown floating point type"),
    }
}

/// Return a floating point value normally distributed with mean = 0, stddev = 1.
///
/// To use different parameters, use: floatNorm(...) * desiredStddev + desiredMean.
pub fn floatNorm(r: Random, comptime T: type) T {
    const value = ziggurat.next_f64(r, ziggurat.NormDist);
    switch (T) {
        f32 => return @floatCast(value),
        f64 => return value,
        else => @compileError("unknown floating point type"),
    }
}

/// Return an exponentially distributed float with a rate parameter of 1.
///
/// To use a different rate parameter, use: floatExp(...) / desiredRate.
pub fn floatExp(r: Random, comptime T: type) T {
    const value = ziggurat.next_f64(r, ziggurat.ExpDist);
    switch (T) {
        f32 => return @floatCast(value),
        f64 => return value,
        else => @compileError("unknown floating point type"),
    }
}

/// Shuffle a slice into a random order.
///
/// Note that this will not yield consistent results across all targets
/// due to dependence on the representation of `usize` as an index.
/// See `shuffleWithIndex` for further commentary.
pub inline fn shuffle(r: Random, comptime T: type, buf: []T) void {
    r.shuffleWithIndex(T, buf, usize);
}

/// Shuffle a slice into a random order, using an index of a
/// specified type to maintain distribution across targets.
/// Asserts the index type can represent `buf.len`.
///
/// Indexes into the slice are generated using the specified `Index`
/// type, which determines distribution properties. This allows for
/// results to be independent of `usize` representation.
///
/// Prefer `shuffle` if this isn't important.
///
/// See `intRangeLessThan`, which this function uses,
/// for commentary on the runtime of this function.
pub fn shuffleWithIndex(r: Random, comptime T: type, buf: []T, comptime Index: type) void {
    const MinInt = MinArrayIndex(Index);
    if (buf.len < 2) {
        return;
    }

    // `i <= j < max <= maxInt(MinInt)`
    const max: MinInt = @intCast(buf.len);
    var i: MinInt = 0;
    while (i < max - 1) : (i += 1) {
        const j: MinInt = @intCast(r.intRangeLessThan(Index, i, max));
        mem.swap(T, &buf[i], &buf[j]);
    }
}

/// Randomly selects an index into `proportions`, where the likelihood of each
/// index is weighted by that proportion.
/// It is more likely for the index of the last proportion to be returned
/// than the index of the first proportion in the slice, and vice versa.
///
/// This is useful for selecting an item from a slice where weights are not equal.
/// `T` must be a numeric type capable of holding the sum of `proportions`.
pub fn weightedIndex(r: Random, comptime T: type, proportions: []const T) usize {
    // This implementation works by summing the proportions and picking a
    // random point in [0, sum).  We then loop over the proportions,
    // accumulating until our accumulator is greater than the random point.

    const sum = s: {
        var sum: T = 0;
        for (proportions) |v| sum += v;
        break :s sum;
    };

    const point = switch (@typeInfo(T)) {
        .int => |int_info| switch (int_info.signedness) {
            .signed => r.intRangeLessThan(T, 0, sum),
            .unsigned => r.uintLessThan(T, sum),
        },
        // take care that imprecision doesn't lead to a value slightly greater than sum
        .float => @min(r.float(T) * sum, sum - std.math.floatEps(T)),
        else => @compileError("weightedIndex does not support proportions of type " ++
            @typeName(T)),
    };

    assert(point < sum);

    var accumulator: T = 0;
    for (propo```
