```
  200,
        \\    30,    4,
        \\    50000, 60,
        \\};
        \\const a = []u8{
        \\    0,  1,  2,   3, 40,
        \\    4,  5,  600, 7, 80,
        \\    9,  10, 11,  0, 13,
        \\    14, 15,
        \\};
        \\const a = [12]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
        \\const a = [12]u8{
        \\    31,
        \\    28,
        \\    31,
        \\    30,
        \\    31,
        \\    30,
        \\    31,
        \\    31,
        \\    30,
        \\    31,
        \\    30,
        \\    31,
        \\};
        \\
    );
}

test "zig fmt: multiline string with backslash at end of line" {
    try testCanonical(
        \\comptime {
        \\    err(
        \\        \\\
        \\    );
        \\}
        \\
    );
}

test "zig fmt: multiline string parameter in fn call with trailing comma" {
    try testCanonical(
        \\fn foo() void {
        \\    try stdout.print(
        \\        \\ZIG_CMAKE_BINARY_DIR {s}
        \\        \\ZIG_C_HEADER_FILES   {s}
        \\        \\ZIG_DIA_GUIDS_LIB    {s}
        \\        \\
        \\    ,
        \\        std.mem.sliceTo(c.ZIG_CMAKE_BINARY_DIR, 0),
        \\        std.mem.sliceTo(c.ZIG_CXX_COMPILER, 0),
        \\        std.mem.sliceTo(c.ZIG_DIA_GUIDS_LIB, 0),
        \\    );
        \\}
        \\
    );
}

test "zig fmt: trailing comma on fn call" {
    try testCanonical(
        \\comptime {
        \\    var module = try Module.create(
        \\        allocator,
        \\        zig_lib_dir,
        \\        full_cache_dir,
        \\    );
        \\}
        \\
    );
}

test "zig fmt: multi line arguments without last comma" {
    try testTransform(
        \\pub fn foo(
        \\    a: usize,
        \\    b: usize,
        \\    c: usize,
        \\    d: usize
        \\) usize {
        \\    return a + b + c + d;
        \\}
        \\
    ,
        \\pub fn foo(a: usize, b: usize, c: usize, d: usize) usize {
        \\    return a + b + c + d;
        \\}
        \\
    );
}

test "zig fmt: empty block with only comment" {
    try testCanonical(
        \\comptime {
        \\    {
        \\        // comment
        \\    }
        \\}
        \\
    );
}

test "zig fmt: trailing commas on struct decl" {
    try testTransform(
        \\const RoundParam = struct {
        \\    k: usize, s: u32, t: u32
        \\};
        \\const RoundParam = struct {
        \\    k: usize, s: u32, t: u32,
        \\};
    ,
        \\const RoundParam = struct { k: usize, s: u32, t: u32 };
        \\const RoundParam = struct {
        \\    k: usize,
        \\    s: u32,
        \\    t: u32,
        \\};
        \\
    );
}

test "zig fmt: extra newlines at the end" {
    try testTransform(
        \\const a = b;
        \\
        \\
        \\
    ,
        \\const a = b;
        \\
    );
}

test "zig fmt: simple asm" {
    try testTransform(
        \\comptime {
        \\    asm volatile (
        \\        \\.globl aoeu;
        \\        \\.type aoeu, @function;
        \\        \\.set aoeu, derp;
        \\    );
        \\
        \\    asm ("not real assembly"
        \\        :[a] "x" (x),);
        \\    asm ("not real assembly"
        \\        :[a] "x" (->i32),:[a] "x" (1),);
        \\    asm ("still not real assembly"
        \\        :::"a","b",);
        \\}
    ,
        \\comptime {
        \\    asm volatile (
        \\        \\.globl aoeu;
        \\        \\.type aoeu, @function;
        \\        \\.set aoeu, derp;
        \\    );
        \\
        \\    asm ("not real assembly"
        \\        : [a] "x" (x),
        \\    );
        \\    asm ("not real assembly"
        \\        : [a] "x" (-> i32),
        \\        : [a] "x" (1),
        \\    );
        \\    asm ("still not real assembly" ::: "a", "b");
        \\}
        \\
    );
}

test "zig fmt: nested struct literal with one item" {
    try testCanonical(
        \\const a = foo{
        \\    .item = bar{ .a = b },
        \\};
        \\
    );
}

test "zig fmt: switch cases trailing comma" {
    try testTransform(
        \\test "switch cases trailing comma"{
        \\    switch (x) {
        \\        1,2,3 => {},
        \\        4,5, => {},
        \\        6... 8, => {},
        \\        9 ...
        \\        10 => {},
        \\        11 => {},
        \\        12, => {},
        \\        else => {},
        \\    }
        \\}
    ,
        \\test "switch cases trailing comma" {
        \\    switch (x) {
        \\        1, 2, 3 => {},
        \\        4,
        \\        5,
        \\        => {},
        \\        6...8,
        \\        => {},
        \\        9...10 => {},
        \\        11 => {},
        \\        12,
        \\        => {},
        \\        else => {},
        \\    }
        \\}
        \\
    );
}

test "zig fmt: slice align" {
    try testCanonical(
        \\const A = struct {
        \\    items: []align(A) T,
        \\};
        \\
    );
}

test "zig fmt: add trailing comma to array literal" {
    try testTransform(
        \\comptime {
        \\    return []u16{'m', 's', 'y', 's', '-' // hi
        \\   };
        \\    return []u16{'m', 's', 'y', 's',
        \\      '-'};
        \\    return []u16{'m', 's', 'y', 's', '-'};
        \\}
    ,
        \\comptime {
        \\    return []u16{
        \\        'm', 's', 'y', 's', '-', // hi
        \\    };
        \\    return []u16{ 'm', 's', 'y', 's', '-' };
        \\    return []u16{ 'm', 's', 'y', 's', '-' };
        \\}
        \\
    );
}

test "zig fmt: first thing in file is line comment" {
    try testCanonical(
        \\// Introspection and determination of system libraries needed by zig.
        \\
        \\// Introspection and determination of system libraries needed by zig.
        \\
        \\const std = @import("std");
        \\
    );
}

test "zig fmt: line comment after doc comment" {
    try testCanonical(
        \\/// doc comment
        \\// line comment
        \\fn foo() void {}
        \\
    );
}

test "zig fmt: bit field alignment" {
    try testCanonical(
        \\test {
        \\    assert(@TypeOf(&blah.b) == *align(1:3:6) const u3);
        \\}
        \\
    );
}

test "zig fmt: nested switch" {
    try testCanonical(
        \\test {
        \\    switch (state) {
        \\        TermState.Start => switch (c) {
        \\            '\x1b' => state = TermState.Escape,
        \\            else => try out.writeByte(c),
        \\        },
        \\    }
        \\}
        \\
    );
}

test "zig fmt: float literal with exponent" {
    try testCanonical(
        \\pub const f64_true_min = 4.94065645841246544177e-324;
        \\const threshold = 0x1.a827999fcef32p+1022;
        \\
    );
}

test "zig fmt: if-else end of comptime" {
    try testCanonical(
        \\comptime {
        \\    if (a) {
        \\        b();
        \\    } else {
        \\        b();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: nested blocks" {
    try testCanonical(
        \\comptime {
        \\    {
        \\        {
        \\            {
        \\                a();
        \\            }
        \\        }
        \\    }
        \\}
        \\
    );
}

test "zig fmt: block with same line comment after end brace" {
    try testCanonical(
        \\comptime {
        \\    {
        \\        b();
        \\    } // comment
        \\}
        \\
    );
}

test "zig fmt: statements with comment between" {
    try testCanonical(
        \\comptime {
        \\    a = b;
        \\    // comment
        \\    a = b;
        \\}
        \\
    );
}

test "zig fmt: statements with empty line between" {
    try testCanonical(
        \\comptime {
        \\    a = b;
        \\
        \\    a = b;
        \\}
        \\
    );
}

test "zig fmt: ptr deref operator and unwrap optional operator" {
    try testCanonical(
        \\const a = b.*;
        \\const a = b.?;
        \\
    );
}

test "zig fmt: comment after if before another if" {
    try testCanonical(
        \\test "aoeu" {
        \\    // comment
        \\    if (x) {
        \\        bar();
        \\    }
        \\}
        \\
        \\test "aoeu" {
        \\    if (x) {
        \\        foo();
        \\    }
        \\    // comment
        \\    if (x) {
        \\        bar();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: line comment between if block and else keyword" {
    try testCanonical(
        \\test "aoeu" {
        \\    // cexp(finite|nan +- i inf|nan) = nan + i nan
        \\    if ((hx & 0x7fffffff) != 0x7f800000) {
        \\        return Complex(f32).init(y - y, y - y);
        \\    }
        \\    // cexp(-inf +- i inf|nan) = 0 + i0
        \\    else if (hx & 0x80000000 != 0) {
        \\        return Complex(f32).init(0, 0);
        \\    }
        \\    // cexp(+inf +- i inf|nan) = inf + i nan
        \\    // another comment
        \\    else {
        \\        return Complex(f32).init(x, y - y);
        \\    }
        \\}
        \\
    );
}

test "zig fmt: same line comments in expression" {
    try testCanonical(
        \\test "aoeu" {
        \\    const x = ( // a
        \\        0 // b
        \\    ); // c
        \\}
        \\
    );
}

test "zig fmt: add comma on last switch prong" {
    try testTransform(
        \\test "aoeu" {
        \\switch (self.init_arg_expr) {
        \\    InitArg.Type => |t| { },
        \\    InitArg.None,
        \\    InitArg.Enum => { }
        \\}
        \\ switch (self.init_arg_expr) {
        \\     InitArg.Type => |t| { },
        \\     InitArg.None,
        \\     InitArg.Enum => { }//line comment
        \\ }
        \\}
    ,
        \\test "aoeu" {
        \\    switch (self.init_arg_expr) {
        \\        InitArg.Type => |t| {},
        \\        InitArg.None, InitArg.Enum => {},
        \\    }
        \\    switch (self.init_arg_expr) {
        \\        InitArg.Type => |t| {},
        \\        InitArg.None, InitArg.Enum => {}, //line comment
        \\    }
        \\}
        \\
    );
}

test "zig fmt: same-line comment after a statement" {
    try testCanonical(
        \\test "" {
        \\    a = b;
        \\    debug.assert(H.digest_size <= H.block_size); // HMAC makes this assumption
        \\    a = b;
        \\}
        \\
    );
}

test "zig fmt: same-line comment after var decl in struct" {
    try testCanonical(
        \\pub const vfs_cap_data = extern struct {
        \\    const Data = struct {}; // when on disk.
        \\};
        \\
    );
}

test "zig fmt: same-line comment after field decl" {
    try testCanonical(
        \\pub const dirent = extern struct {
        \\    d_name: u8,
        \\    d_name: u8, // comment 1
        \\    d_name: u8,
        \\    d_name: u8, // comment 2
        \\    d_name: u8,
        \\};
        \\
    );
}

test "zig fmt: same-line comment after switch prong" {
    try testCanonical(
        \\test "" {
        \\    switch (err) {
        \\        error.PathAlreadyExists => {}, // comment 2
        \\        else => return err, // comment 1
        \\    }
        \\}
        \\
    );
}

test "zig fmt: same-line comment after non-block if expression" {
    try testCanonical(
        \\comptime {
        \\    if (sr > n_uword_bits - 1) // d > r
        \\        return 0;
        \\}
        \\
    );
}

test "zig fmt: same-line comment on comptime expression" {
    try testCanonical(
        \\test "" {
        \\    comptime assert(@typeInfo(T) == .int); // must pass an integer to absInt
        \\}
        \\
    );
}

test "zig fmt: switch with empty body" {
    try testCanonical(
        \\test "" {
        \\    foo() catch |err| switch (err) {};
        \\}
        \\
    );
}

test "zig fmt: line comments in struct initializer" {
    try testCanonical(
        \\fn foo() void {
        \\    return Self{
        \\        .a = b,
        \\
        \\        // Initialize these two fields to buffer_size so that
        \\        // in `readFn` we treat the state as being able to read
        \\        .start_index = buffer_size,
        \\        .end_index = buffer_size,
        \\
        \\        // middle
        \\
        \\        .a = b,
        \\
        \\        // end
        \\    };
        \\}
        \\
    );
}

test "zig fmt: first line comment in struct initializer" {
    try testCanonical(
        \\pub fn acquire(self: *Self) HeldLock {
        \\    return HeldLock{
        \\        // guaranteed allocation elision
        \\        .held = self.lock.acquire(),
        \\        .value = &self.private_data,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: doc comments before struct field" {
    try testCanonical(
        \\pub const Allocator = struct {
        \\    /// Allocate byte_count bytes and return them in a slice, with the
        \\    /// slice's pointer aligned at least to alignment bytes.
        \\    allocFn: fn () void,
        \\};
        \\
    );
}

test "zig fmt: error set declaration" {
    try testCanonical(
        \\const E = error{
        \\    A,
        \\    B,
        \\
        \\    C,
        \\};
        \\
        \\const Error = error{
        \\    /// no more memory
        \\    OutOfMemory,
        \\};
        \\
        \\const Error = error{
        \\    /// no more memory
        \\    OutOfMemory,
        \\
        \\    /// another
        \\    Another,
        \\
        \\    // end
        \\};
        \\
        \\const Error = error{OutOfMemory};
        \\const Error = error{};
        \\
        \\const Error = error{ OutOfMemory, OutOfTime };
        \\
    );
}

test "zig fmt: union(enum(u32)) with assigned enum values" {
    try testCanonical(
        \\const MultipleChoice = union(enum(u32)) {
        \\    A = 20,
        \\    B = 40,
        \\    C = 60,
        \\    D = 1000,
        \\};
        \\
    );
}

test "zig fmt: resume from suspend block" {
    try testCanonical(
        \\fn foo() void {
        \\    suspend {
        \\        resume @frame();
        \\    }
        \\}
        \\
    );
}

test "zig fmt: comments before error set decl" {
    try testCanonical(
        \\const UnexpectedError = error{
        \\    /// The Operating System returned an undocumented error code.
        \\    Unexpected,
        \\    // another
        \\    Another,
        \\
        \\    // in between
        \\
        \\    // at end
        \\};
        \\
    );
}

test "zig fmt: comments before switch prong" {
    try testCanonical(
        \\test "" {
        \\    switch (err) {
        \\        error.PathAlreadyExists => continue,
        \\
        \\        // comment 1
        \\
        \\        // comment 2
        \\        else => return err,
        \\        // at end
        \\    }
        \\}
        \\
    );
}

test "zig fmt: comments before var decl in struct" {
    try testCanonical(
        \\pub const vfs_cap_data = extern struct {
        \\    // All of these are mandated as little endian
        \\    // when on disk.
        \\    const Data = struct {
        \\        permitted: u32,
        \\        inheritable: u32,
        \\    };
        \\
        \\    // in between
        \\
        \\    /// All of these are mandated as little endian
        \\    /// when on disk.
        \\    const Data = struct {
        \\        permitted: u32,
        \\        inheritable: u32,
        \\    };
        \\
        \\    // at end
        \\};
        \\
    );
}

test "zig fmt: array literal with 1 item on 1 line" {
    try testCanonical(
        \\var s = []const u64{0} ** 25;
        \\
    );
}

test "zig fmt: comments before global variables" {
    try testCanonical(
        \\/// Foo copies keys and values before they go into the map, and
        \\/// frees them when they get removed.
        \\pub const Foo = struct {};
        \\
    );
}

test "zig fmt: comments in statements" {
    try testCanonical(
        \\test "std" {
        \\    // statement comment
        \\    _ = @import("foo/bar.zig");
        \\
        \\    // middle
        \\    // middle2
        \\
        \\    // end
        \\}
        \\
    );
}

test "zig fmt: comments before test decl" {
    try testCanonical(
        \\// top level normal comment
        \\test "hi" {}
        \\
        \\// middle
        \\
        \\// end
        \\
    );
}

test "zig fmt: preserve spacing" {
    try testCanonical(
        \\const std = @import("std");
        \\
        \\pub fn main() !void {
        \\    var stdout_file = std.io.getStdOut;
        \\    var stdout_file = std.io.getStdOut;
        \\
        \\    var stdout_file = std.io.getStdOut;
        \\    var stdout_file = std.io.getStdOut;
        \\}
        \\
    );
}

test "zig fmt: return types" {
    try testCanonical(
        \\pub fn main() !void {}
        \\pub fn main() FooBar {}
        \\pub fn main() i32 {}
        \\
    );
}

test "zig fmt: imports" {
    try testCanonical(
        \\const std = @import("std");
        \\const std = @import();
        \\
    );
}

test "zig fmt: global declarations" {
    try testCanonical(
        \\const a = b;
        \\pub const a = b;
        \\var a = b;
        \\pub var a = b;
        \\const a: i32 = b;
        \\pub const a: i32 = b;
        \\var a: i32 = b;
        \\pub var a: i32 = b;
        \\extern const a: i32 = b;
        \\pub extern const a: i32 = b;
        \\extern var a: i32 = b;
        \\pub extern var a: i32 = b;
        \\extern "a" const a: i32 = b;
        \\pub extern "a" const a: i32 = b;
        \\extern "a" var a: i32 = b;
        \\pub extern "a" var a: i32 = b;
        \\
    );
}

test "zig fmt: extern declaration" {
    try testCanonical(
        \\extern var foo: c_int;
        \\
    );
}

test "zig fmt: alignment" {
    try testCanonical(
        \\var foo: c_int align(1);
        \\
    );
}

test "zig fmt: C main" {
    try testCanonical(
        \\fn main(argc: c_int, argv: **u8) c_int {
        \\    const a = b;
        \\}
        \\
    );
}

test "zig fmt: return" {
    try testCanonical(
        \\fn foo(argc: c_int, argv: **u8) c_int {
        \\    return 0;
        \\}
        \\
        \\fn bar() void {
        \\    return;
        \\}
        \\
    );
}

test "zig fmt: function attributes" {
    try testCanonical(
        \\export fn foo() void {}
        \\pub export fn foo() void {}
        \\extern fn foo() void;
        \\pub extern fn foo() void;
        \\extern "c" fn foo() void;
        \\pub extern "c" fn foo() void;
        \\noinline fn foo() void {}
        \\pub noinline fn foo() void {}
        \\
    );
}

test "zig fmt: nested pointers with ** tokens" {
    try testCanonical(
        \\const x: *u32 = undefined;
        \\const x: **u32 = undefined;
        \\const x: ***u32 = undefined;
        \\const x: ****u32 = undefined;
        \\const x: *****u32 = undefined;
        \\const x: ******u32 = undefined;
        \\const x: *******u32 = undefined;
        \\
    );
}

test "zig fmt: pointer attributes" {
    try testCanonical(
        \\extern fn f1(s: *align(*u8) u8) c_int;
        \\extern fn f2(s: **align(1) *const *volatile u8) c_int;
        \\extern fn f3(s: *align(1) const *align(1) volatile *const volatile u8) c_int;
        \\extern fn f4(s: *align(1) const volatile u8) c_int;
        \\extern fn f5(s: [*:0]align(1) const volatile u8) c_int;
        \\
    );
}

test "zig fmt: slice attributes" {
    try testCanonical(
        \\extern fn f1(s: []align(*u8) u8) c_int;
        \\extern fn f2(s: []align(1) []const []volatile u8) c_int;
        \\extern fn f3(s: []align(1) const [:0]align(1) volatile []const volatile u8) c_int;
        \\extern fn f4(s: []align(1) const volatile u8) c_int;
        \\extern fn f5(s: [:0]align(1) const volatile u8) c_int;
        \\
    );
}

test "zig fmt: test declaration" {
    try testCanonical(
        \\test "test name" {
        \\    const a = 1;
        \\    var b = 1;
        \\}
        \\
    );
}

test "zig fmt: destructure" {
    try testCanonical(
        \\comptime {
        \\    var w: u8, var x: u8 = .{ 1, 2 };
        \\    w, var y: u8 = .{ 3, 4 };
        \\    var z: u8, x = .{ 5, 6 };
        \\    y, z = .{ 7, 8 };
        \\}
        \\
        \\comptime {
        \\    comptime var w, var x = .{ 1, 2 };
        \\    comptime w, var y = .{ 3, 4 };
        \\    comptime var z, x = .{ 5, 6 };
        \\    comptime y, z = .{ 7, 8 };
        \\}
        \\
    );
}

test "zig fmt: infix operators" {
    try testCanonical(
        \\test {
        \\    var i = undefined;
        \\    i = 2;
        \\    i *= 2;
        \\    i |= 2;
        \\    i ^= 2;
        \\    i <<= 2;
        \\    i >>= 2;
        \\    i &= 2;
        \\    i *= 2;
        \\    i *%= 2;
        \\    i -= 2;
        \\    i -%= 2;
        \\    i += 2;
        \\    i +%= 2;
        \\    i /= 2;
        \\    i %= 2;
        \\    _ = i == i;
        \\    _ = i != i;
        \\    _ = i != i;
        \\    _ = i.i;
        \\    _ = i || i;
        \\    _ = i!i;
        \\    _ = i ** i;
        \\    _ = i ++ i;
        \\    _ = i orelse i;
        \\    _ = i % i;
        \\    _ = i / i;
        \\    _ = i *% i;
        \\    _ = i * i;
        \\    _ = i -% i;
        \\    _ = i - i;
        \\    _ = i +% i;
        \\    _ = i + i;
        \\    _ = i << i;
        \\    _ = i >> i;
        \\    _ = i & i;
        \\    _ = i ^ i;
        \\    _ = i | i;
        \\    _ = i >= i;
        \\    _ = i <= i;
        \\    _ = i > i;
        \\    _ = i < i;
        \\    _ = i and i;
        \\    _ = i or i;
        \\}
        \\
    );
}

test "zig fmt: precedence" {
    try testCanonical(
        \\test "precedence" {
        \\    a!b();
        \\    (a!b)();
        \\    !a!b;
        \\    !(a!b);
        \\    !a{};
        \\    !(a{});
        \\    a + b{};
        \\    (a + b){};
        \\    a << b + c;
        \\    (a << b) + c;
        \\    a & b << c;
        \\    (a & b) << c;
        \\    a ^ b & c;
        \\    (a ^ b) & c;
        \\    a | b ^ c;
        \\    (a | b) ^ c;
        \\    a == b | c;
        \\    (a == b) | c;
        \\    a and b == c;
        \\    (a and b) == c;
        \\    a or b and c;
        \\    (a or b) and c;
        \\    (a or b) and c;
        \\    a == b and c == d;
        \\}
        \\
    );
}

test "zig fmt: prefix operators" {
    try testCanonical(
        \\test "prefix operators" {
        \\    try return --%~!&0;
        \\}
        \\
    );
}

test "zig fmt: call expression" {
    try testCanonical(
        \\test "test calls" {
        \\    a();
        \\    a(1);
        \\    a(1, 2);
        \\    a(1, 2) + a(1, 2);
        \\}
        \\
    );
}

test "zig fmt: anytype type" {
    try testCanonical(
        \\fn print(args: anytype) @This() {}
        \\
    );
}

test "zig fmt: functions" {
    try testCanonical(
        \\extern fn puts(s: *const u8) c_int;
        \\extern "c" fn puts(s: *const u8) c_int;
        \\export fn puts(s: *const u8) c_int;
        \\inline fn puts(s: *const u8) c_int;
        \\noinline fn puts(s: *const u8) c_int;
        \\pub extern fn puts(s: *const u8) c_int;
        \\pub extern "c" fn puts(s: *const u8) c_int;
        \\pub export fn puts(s: *const u8) c_int;
        \\pub inline fn puts(s: *const u8) c_int;
        \\pub noinline fn puts(s: *const u8) c_int;
        \\pub extern fn puts(s: *const u8) align(2 + 2) c_int;
        \\pub extern "c" fn puts(s: *const u8) align(2 + 2) c_int;
        \\pub export fn puts(s: *const u8) align(2 + 2) c_int;
        \\pub inline fn puts(s: *const u8) align(2 + 2) c_int;
        \\pub noinline fn puts(s: *const u8) align(2 + 2) c_int;
        \\pub fn callInlineFn(func: fn () callconv(.@"inline") void) void {
        \\    func();
        \\}
        \\
    );
}

test "zig fmt: multiline string" {
    try testCanonical(
        \\test "" {
        \\    const s1 =
        \\        \\one
        \\        \\two)
        \\        \\three
        \\    ;
        \\    const s3 = // hi
        \\        \\one
        \\        \\two)
        \\        \\three
        \\    ;
        \\}
        \\
    );
}

test "zig fmt: multiline string with CRLF line endings" {
    try testTransform("" ++
        "const s =\r\n" ++
        "    \\\\one\r\n" ++
        "    \\\\two)\r\n" ++
        "    \\\\three\r\n" ++
        ";\r\n",
        \\const s =
        \\    \\one
        \\    \\two)
        \\    \\three
        \\;
        \\
    );
}

test "zig fmt: values" {
    try testCanonical(
        \\test "values" {
        \\    1;
        \\    1.0;
        \\    "string";
        \\    'c';
        \\    true;
        \\    false;
        \\    null;
        \\    undefined;
        \\    anyerror;
        \\    this;
        \\    unreachable;
        \\}
        \\
    );
}

test "zig fmt: indexing" {
    try testCanonical(
        \\test "test index" {
        \\    a[0];
        \\    a[0 + 5];
        \\    a[0..];
        \\    a[0..5];
        \\    a[a[0]];
        \\    a[a[0..]];
        \\    a[a[0..5]];
        \\    a[a[0]..];
        \\    a[a[0..5]..];
        \\    a[a[0]..a[0]];
        \\    a[a[0..5]..a[0]];
        \\    a[a[0..5]..a[0..5]];
        \\}
        \\
    );
}

test "zig fmt: struct declaration" {
    try testCanonical(
        \\const S = struct {
        \\    const Self = @This();
        \\    f1: u8,
        \\    f3: u8,
        \\
        \\    f2: u8,
        \\
        \\    fn method(self: *Self) Self {
        \\        return self.*;
        \\    }
        \\};
        \\
        \\const Ps = packed struct {
        \\    a: u8,
        \\    b: u8,
        \\
        \\    c: u8,
        \\};
        \\
        \\const Ps = packed struct(u32) {
        \\    a: u1,
        \\    b: u2,
        \\
        \\    c: u29,
        \\};
        \\
        \\const Es = extern struct {
        \\    a: u8,
        \\    b: u8,
        \\
        \\    c: u8,
        \\};
        \\
    );
}

test "zig fmt: enum declaration" {
    try testCanonical(
        \\const E = enum {
        \\    Ok,
        \\    SomethingElse = 0,
        \\};
        \\
        \\const E2 = enum(u8) {
        \\    Ok,
        \\    SomethingElse = 255,
        \\    SomethingThird,
        \\};
        \\
        \\const Ee = extern enum {
        \\    Ok,
        \\    SomethingElse,
        \\    SomethingThird,
        \\};
        \\
        \\const Ep = packed enum {
        \\    Ok,
        \\    SomethingElse,
        \\    SomethingThird,
        \\};
        \\
    );
}

test "zig fmt: union declaration" {
    try testCanonical(
        \\const U = union {
        \\    Int: u8,
        \\    Float: f32,
        \\    None,
        \\    Bool: bool,
        \\};
        \\
        \\const Ue = union(enum) {
        \\    Int: u8,
        \\    Float: f32,
        \\    None,
        \\    Bool: bool,
        \\};
        \\
        \\const E = enum {
        \\    Int,
        \\    Float,
        \\    None,
        \\    Bool,
        \\};
        \\
        \\const Ue2 = union(E) {
        \\    Int: u8,
        \\    Float: f32,
        \\    None,
        \\    Bool: bool,
        \\};
        \\
        \\const Eu = extern union {
        \\    Int: u8,
        \\    Float: f32,
        \\    None,
        \\    Bool: bool,
        \\};
        \\
    );
}

test "zig fmt: arrays" {
    try testCanonical(
        \\test "test array" {
        \\    const a: [2]u8 = [2]u8{
        \\        1,
        \\        2,
        \\    };
        \\    const a: [2]u8 = []u8{
        \\        1,
        \\        2,
        \\    };
        \\    const a: [0]u8 = []u8{};
        \\    const x: [4:0]u8 = undefined;
        \\}
        \\
    );
}

test "zig fmt: container initializers" {
    try testCanonical(
        \\const a0 = []u8{};
        \\const a1 = []u8{1};
        \\const a2 = []u8{
        \\    1,
        \\    2,
        \\    3,
        \\    4,
        \\};
        \\const s0 = S{};
        \\const s1 = S{ .a = 1 };
        \\const s2 = S{
        \\    .a = 1,
        \\    .b = 2,
        \\};
        \\
    );
}

test "zig fmt: catch" {
    try testCanonical(
        \\test "catch" {
        \\    const a: anyerror!u8 = 0;
        \\    _ = a catch return;
        \\    _ = a catch
        \\        return;
        \\    _ = a catch |err| return;
        \\    _ = a catch |err|
        \\        return;
        \\}
        \\
    );
}

test "zig fmt: blocks" {
    try testCanonical(
        \\test "blocks" {
        \\    {
        \\        const a = 0;
        \\        const b = 0;
        \\    }
        \\
        \\    blk: {
        \\        const a = 0;
        \\        const b = 0;
        \\    }
        \\
        \\    const r = blk: {
        \\        const a = 0;
        \\        const b = 0;
        \\    };
        \\}
        \\
    );
}

test "zig fmt: switch" {
    try testCanonical(
        \\test "switch" {
        \\    switch (0) {
        \\        0 => {},
        \\        1 => unreachable,
        \\        2, 3 => {},
        \\        4...7 => {},
        \\        1 + 4 * 3 + 22 => {},
        \\        else => {
        \\            const a = 1;
        \\            const b = a;
        \\        },
        \\    }
        \\
        \\    const res = switch (0) {
        \\        0 => 0,
        \\        1 => 2,
        \\        1 => a = 4,
        \\        else => 4,
        \\    };
        \\
        \\    const Union = union(enum) {
        \\        Int: i64,
        \\        Float: f64,
        \\    };
        \\
        \\    switch (u) {
        \\        Union.Int => |int| {},
        \\        Union.Float => |*float| unreachable,
        \\        1 => |a, b| unreachable,
        \\        2 => |*a, b| unreachable,
        \\    }
        \\}
        \\
    );

    try testTransform(
        \\test {
        \\    switch (x) {
        \\        foo =>
        \\            "bar",
        \\    }
        \\}
        \\
    ,
        \\test {
        \\    switch (x) {
        \\        foo => "bar",
        \\    }
        \\}
        \\
    );
}

test "zig fmt: switch multiline string" {
    try testCanonical(
        \\test "switch multiline string" {
        \\    const x: u32 = 0;
        \\    const str = switch (x) {
        \\        1 => "one",
        \\        2 =>
        \\        \\ Comma after the multiline string
        \\        \\ is needed
        \\        ,
        \\        3 => "three",
        \\        else => "else",
        \\    };
        \\
        \\    const Union = union(enum) {
        \\        Int: i64,
        \\        Float: f64,
        \\    };
        \\
        \\    const str = switch (u) {
        \\        Union.Int => |int|
        \\        \\ Comma after the multiline string
        \\        \\ is needed
        \\        ,
        \\        Union.Float => |*float| unreachable,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: while" {
    try testCanonical(
        \\test "while" {
        \\    while (10 < 1) unreachable;
        \\
        \\    while (10 < 1) unreachable else unreachable;
        \\
        \\    while (10 < 1) {
        \\        unreachable;
        \\    }
        \\
        \\    while (10 < 1)
        \\        unreachable;
        \\
        \\    var i: usize = 0;
        \\    while (i < 10) : (i += 1) {
        \\        continue;
        \\    }
        \\
        \\    i = 0;
        \\    while (i < 10) : (i += 1)
        \\        continue;
        \\
        \\    i = 0;
        \\    var j: usize = 0;
        \\    while (i < 10) : ({
        \\        i += 1;
        \\        j += 1;
        \\    }) continue;
        \\
        \\    while (i < 10) : ({
        \\        i += 1;
        \\        j += 1;
        \\    }) {
        \\        continue;
        \\    }
        \\
        \\    var a: ?u8 = 2;
        \\    while (a) |v| : (a = null) {
        \\        continue;
        \\    }
        \\
        \\    while (a) |v| : (a = null)
        \\        unreachable;
        \\
        \\    label: while (10 < 0) {
        \\        unreachable;
        \\    }
        \\
        \\    const res = while (0 < 10) {
        \\        break 7;
        \\    } else {
        \\        unreachable;
        \\    };
        \\
        \\    const res = while (0 < 10)
        \\        break 7
        \\    else
        \\        unreachable;
        \\
        \\    var a: anyerror!u8 = 0;
        \\    while (a) |v| {
        \\        a = error.Err;
        \\    } else |err| {
        \\        i = 1;
        \\    }
        \\
        \\    comptime var k: usize = 0;
        \\    inline while (i < 10) : (i += 1)
        \\        j += 2;
        \\}
        \\
    );
}

test "zig fmt: for" {
    try testCanonical(
        \\test "for" {
        \\    for (a) |v| {
        \\        continue;
        \\    }
        \\
        \\    for (a) |v| continue;
        \\
        \\    for (a) |v| continue else return;
        \\
        \\    for (a) |v| {
        \\        continue;
        \\    } else return;
        \\
        \\    for (a) |v| continue else {
        \\        return;
        \\    }
        \\
        \\    for (a) |v|
        \\        continue
        \\    else
        \\        return;
        \\
        \\    for (a) |v|
        \\        continue;
        \\
        \\    for (a) |*v|
        \\        continue;
        \\
        \\    for (a, 0..) |v, i| {
        \\        continue;
        \\    }
        \\
        \\    for (a, 0..) |v, i|
        \\        continue;
        \\
        \\    for (a) |b| switch (b) {
        \\        c => {},
        \\        d => {},
        \\    };
        \\
        \\    const res = for (a, 0..) |v, i| {
        \\        break v;
        \\    } else {
        \\        unreachable;
        \\    };
        \\
        \\    var num: usize = 0;
        \\    inline for (a, 0..1) |v, i| {
        \\        num += v;
        \\        num += i;
        \\    }
        \\
        \\    for (a, b) |
        \\        long_name,
        \\        another_long_name,
        \\    | {
        \\        continue;
        \\    }
        \\}
        \\
    );

    try testTransform(
        \\test "fix for" {
        \\    for (a) |x|
        \\        f(x) else continue;
        \\}
        \\
    ,
        \\test "fix for" {
        \\    for (a) |x|
        \\        f(x)
        \\    else
        \\        continue;
        \\}
        \\
    );

    try testTransform(
        \\test "fix for" {
        \\    for (a, b, c,) |long, another, third,| {}
        \\}
        \\
    ,
        \\test "fix for" {
        \\    for (
        \\        a,
        \\        b,
        \\        c,
        \\    ) |
        \\        long,
        \\        another,
        \\        third,
        \\    | {}
        \\}
        \\
    );
}

test "zig fmt: for if" {
    try testCanonical(
        \\test {
        \\    for (a) |x| if (x) f(x);
        \\
        \\    for (a) |x| if (x)
        \\        f(x);
        \\
        \\    for (a) |x| if (x) {
        \\        f(x);
        \\    };
        \\
        \\    for (a) |x|
        \\        if (x)
        \\            f(x);
        \\
        \\    for (a) |x|
        \\        if (x) {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: if for" {
    try testCanonical(
        \\test {
        \\    if (a) for (x) |x| f(x);
        \\
        \\    if (a) for (x) |x|
        \\        f(x);
        \\
        \\    if (a) for (x) |x| {
        \\        f(x);
        \\    };
        \\
        \\    if (a)
        \\        for (x) |x|
        \\            f(x);
        \\
        \\    if (a)
        \\        for (x) |x| {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: while if" {
    try testCanonical(
        \\test {
        \\    while (a) if (x) f(x);
        \\
        \\    while (a) if (x)
        \\        f(x);
        \\
        \\    while (a) if (x) {
        \\        f(x);
        \\    };
        \\
        \\    while (a)
        \\        if (x)
        \\            f(x);
        \\
        \\    while (a)
        \\        if (x) {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: if while" {
    try testCanonical(
        \\test {
        \\    if (a) while (x) : (cont) f(x);
        \\
        \\    if (a) while (x) : (cont)
        \\        f(x);
        \\
        \\    if (a) while (x) : (cont) {
        \\        f(x);
        \\    };
        \\
        \\    if (a)
        \\        while (x) : (cont)
        \\            f(x);
        \\
        \\    if (a)
        \\        while (x) : (cont) {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: while for" {
    try testCanonical(
        \\test {
        \\    while (a) for (x) |x| f(x);
        \\
        \\    while (a) for (x) |x|
        \\        f(x);
        \\
        \\    while (a) for (x) |x| {
        \\        f(x);
        \\    };
        \\
        \\    while (a)
        \\        for (x) |x|
        \\            f(x);
        \\
        \\    while (a)
        \\        for (x) |x| {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: for while" {
    try testCanonical(
        \\test {
        \\    for (a) |a| while (x) |x| f(x);
        \\
        \\    for (a) |a| while (x) |x|
        \\        f(x);
        \\
        \\    for (a) |a| while (x) |x| {
        \\        f(x);
        \\    };
        \\
        \\    for (a) |a|
        \\        while (x) |x|
        \\            f(x);
        \\
        \\    for (a) |a|
        \\        while (x) |x| {
        \\            f(x);
        \\        };
        \\}
        \\
    );
}

test "zig fmt: if" {
    try testCanonical(
        \\test "if" {
        \\    if (10 < 0) {
        \\        unreachable;
        \\    }
        \\
        \\    if (10 < 0) unreachable;
        \\
        \\    if (10 < 0) {
        \\        unreachable;
        \\    } else {
        \\        const a = 20;
        \\    }
        \\
        \\    if (10 < 0) {
        \\        unreachable;
        \\    } else if (5 < 0) {
        \\        unreachable;
        \\    } else {
        \\        const a = 20;
        \\    }
        \\
        \\    const is_world_broken = if (10 < 0) true else false;
        \\    const some_number = 1 + if (10 < 0) 2 else 3;
        \\
        \\    const a: ?u8 = 10;
        \\    const b: ?u8 = null;
        \\    if (a) |v| {
        \\        const some = v;
        \\    } else if (b) |*v| {
        \\        unreachable;
        \\    } else {
        \\        const some = 10;
        \\    }
        \\
        \\    const non_null_a = if (a) |v| v else 0;
        \\
        \\    const a_err: anyerror!u8 = 0;
        \\    if (a_err) |v| {
        \\        const p = v;
        \\    } else |err| {
        \\        unreachable;
        \\    }
        \\}
        \\
    );
}

test "zig fmt: fix single statement if/for/while line breaks" {
    try testTransform(
        \\test {
        \\    if (cond) a
        \\    else b;
        \\
        \\    if (cond)
        \\        a
        \\    else b;
        \\
        \\    for (xs) |x| foo()
        \\    else bar();
        \\
        \\    for (xs) |x|
        \\        foo()
        \\    else bar();
        \\
        \\    while (a) : (b) foo()
        \\    else bar();
        \\
        \\    while (a) : (b)
        \\        foo()
        \\    else bar();
        \\}
        \\
    ,
        \\test {
        \\    if (cond) a else b;
        \\
        \\    if (cond)
        \\        a
        \\    else
        \\        b;
        \\
        \\    for (xs) |x| foo() else bar();
        \\
        \\    for (xs) |x|
        \\        foo()
        \\    else
        \\        bar();
        \\
        \\    while (a) : (b) foo() else bar();
        \\
        \\    while (a) : (b)
        \\        foo()
        \\    else
        \\        bar();
        \\}
        \\
    );
}

test "zig fmt: anon struct/array literal in if" {
    try testCanonical(
        \\test {
        \\    const a = if (cond) .{
        \\        1, 2,
        \\        3, 4,
        \\    } else .{
        \\        1,
        \\        2,
        \\        3,
        \\    };
        \\
        \\    const rl_and_tag: struct { rl: ResultLoc, tag: zir.Inst.Tag } = if (any_payload_is_ref) .{
        \\        .rl = .ref,
        \\        .tag = .switchbr_ref,
        \\    } else .{
        \\        .rl = .none,
        \\        .tag = .switchbr,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: defer" {
    try testCanonical(
        \\test "defer" {
        \\    var i: usize = 0;
        \\    defer i = 1;
        \\    defer {
        \\        i += 2;
        \\        i *= i;
        \\    }
        \\
        \\    errdefer i += 3;
        \\    errdefer {
        \\        i += 2;
        \\        i /= i;
        \\    }
        \\}
        \\
    );
}

test "zig fmt: comptime" {
    try testCanonical(
        \\fn a() u8 {
        \\    return 5;
        \\}
        \\
        \\fn b(comptime i: u8) u8 {
        \\    return i;
        \\}
        \\
        \\const av = comptime a();
        \\const av2 = comptime blk: {
        \\    var res = a();
        \\    res *= b(2);
        \\    break :blk res;
        \\};
        \\
        \\comptime {
        \\    _ = a();
        \\}
        \\
        \\test "comptime" {
        \\    const av3 = comptime a();
        \\    const av4 = comptime blk: {
        \\        var res = a();
        \\        res *= a();
        \\        break :blk res;
        \\    };
        \\
        \\    comptime var i = 0;
        \\    comptime {
        \\        i = a();
        \\        i += b(i);
        \\    }
        \\}
        \\
    );
}

test "zig fmt: fn type" {
    try testCanonical(
        \\fn a(i: u8) u8 {
        \\    return i + 1;
        \\}
        \\
        \\const a: fn (u8) u8 = undefined;
        \\const b: fn (u8) callconv(.naked) u8 = undefined;
        \\const ap: fn (u8) u8 = a;
        \\
    );
}

test "zig fmt: inline asm" {
    try testCanonical(
        \\pub fn syscall1(number: usize, arg1: usize) usize {
        \\    return asm volatile ("syscall"
        \\        : [ret] "={rax}" (-> usize),
        \\        : [number] "{rax}" (number),
        \\          [arg1] "{rdi}" (arg1),
        \\        : "rcx", "r11"
        \\    );
        \\}
        \\
    );
}

test "zig fmt: async functions" {
    try testCanonical(
        \\fn simpleAsyncFn() void {
        \\    const a = async a.b();
        \\    x += 1;
        \\    suspend {}
        \\    x += 1;
        \\    suspend {}
        \\    const p: anyframe->void = async simpleAsyncFn() catch unreachable;
        \\    await p;
        \\}
        \\
        \\test "suspend, resume, await" {
        \\    const p: anyframe = async testAsyncSeq();
        \\    resume p;
        \\    await p;
        \\}
        \\
    );
}

test "zig fmt: nosuspend" {
    try testCanonical(
        \\const a = nosuspend foo();
        \\
    );
}

test "zig fmt: Block after if" {
    try testCanonical(
        \\test {
        \\    if (true) {
        \\        const a = 0;
        \\    }
        \\
        \\    {
        \\        const a = 0;
        \\    }
        \\}
        \\
    );
}

test "zig fmt: usingnamespace" {
    try testCanonical(
        \\usingnamespace @import("std");
        \\pub usingnamespace @import("std");
        \\
    );
}

test "zig fmt: string identifier" {
    try testCanonical(
        \\const @"a b" = @"c d".@"e f";
        \\fn @"g h"() void {}
        \\
    );
}

test "zig fmt: error return" {
    try testCanonical(
        \\fn err() anyerror {
        \\    call();
        \\    return error.InvalidArgs;
        \\}
        \\
    );
}

test "zig fmt: comptime block in container" {
    try testCanonical(
        \\pub fn container() type {
        \\    return struct {
        \\        comptime {
        \\            if (false) {
        \\                unreachable;
        \\            }
        \\        }
        \\    };
        \\}
        \\
    );
}

test "zig fmt: inline asm parameter alignment" {
    try testCanonical(
        \\pub fn main() void {
        \\    asm volatile (
        \\        \\ foo
        \\        \\ bar
        \\    );
        \\    asm volatile (
        \\        \\ foo
        \\        \\ bar
        \\        : [_] "" (-> usize),
        \\          [_] "" (-> usize),
        \\    );
        \\    asm volatile (
        \\        \\ foo
        \\        \\ bar
        \\        :
        \\        : [_] "" (0),
        \\          [_] "" (0),
        \\    );
        \\    asm volatile (
        \\        \\ foo
        \\        \\ bar
        \\        ::: "", "");
        \\    asm volatile (
        \\        \\ foo
        \\        \\ bar
        \\        : [_] "" (-> usize),
        \\          [_] "" (-> usize),
        \\        : [_] "" (0),
        \\          [_] "" (0),
        \\        : "", ""
        \\    );
        \\}
        \\
    );
}

test "zig fmt: multiline string in array" {
    try testCanonical(
        \\const Foo = [][]const u8{
        \\    \\aaa
        \\    ,
        \\    \\bbb
        \\};
        \\
        \\fn bar() void {
        \\    const Foo = [][]const u8{
        \\        \\aaa
        \\        ,
        \\        \\bbb
        \\    };
        \\    const Bar = [][]const u8{ // comment here
        \\        \\aaa
        \\        \\
        \\        , // and another comment can go here
        \\        \\bbb
        \\    };
        \\}
        \\
    );
}

test "zig fmt: if type expr" {
    try testCanonical(
        \\const mycond = true;
        \\pub fn foo() if (mycond) i32 else void {
        \\    if (mycond) {
        \\        return 42;
        \\    }
        \\}
        \\
    );
}
test "zig fmt: file ends with struct field" {
    try testCanonical(
        \\a: bool
        \\
    );
}

test "zig fmt: comment after empty comment" {
    try testCanonical(
        \\const x = true; //
        \\//
        \\//
        \\//a
        \\
    );
}

test "zig fmt: line comment in array" {
    try testTransform(
        \\test "a" {
        \\    var arr = [_]u32{
        \\        0
        \\        // 1,
        \\        // 2,
        \\    };
        \\}
        \\
    ,
        \\test "a" {
        \\    var arr = [_]u32{
        \\        0,
        \\        // 1,
        \\        // 2,
        \\    };
        \\}
        \\
    );
    try testCanonical(
        \\test "a" {
        \\    var arr = [_]u32{
        \\        0,
        \\        // 1,
        \\        // 2,
        \\    };
        \\}
        \\
    );
}

test "zig fmt: comment after params" {
    try testTransform(
        \\fn a(
        \\    b: u32
        \\    // c: u32,
        \\    // d: u32,
        \\) void {}
        \\
    ,
        \\fn a(
        \\    b: u32,
        \\    // c: u32,
        \\    // d: u32,
        \\) void {}
        \\
    );
    try testCanonical(
        \\fn a(
        \\    b: u32,
        \\    // c: u32,
        \\    // d: u32,
        \\) void {}
        \\
    );
}

test "zig fmt: comment in array initializer/access" {
    try testCanonical(
        \\test "a" {
        \\    var a = x{ //aa
        \\        //bb
        \\    };
        \\    var a = []x{ //aa
        \\        //bb
        \\    };
        \\    var b = [ //aa
        \\        _
        \\    ]x{ //aa
        \\        //bb
        \\        9,
        \\    };
        \\    var c = b[ //aa
        \\        0
        \\    ];
        \\    var d = [
        \\        _
        \\        //aa
        \\        :
        \\        0
        \\    ]x{ //aa
        \\        //bb
        \\        9,
        \\    };
        \\    var e = d[
        \\        0
        \\        //aa
        \\    ];
        \\}
        \\
    );
}

test "zig fmt: comments at several places in struct init" {
    try testTransform(
        \\var bar = Bar{
        \\    .x = 10, // test
        \\    .y = "test"
        \\    // test
        \\};
        \\
    ,
        \\var bar = Bar{
        \\    .x = 10, // test
        \\    .y = "test",
        \\    // test
        \\};
        \\
    );

    try testCanonical(
        \\var bar = Bar{ // test
        \\    .x = 10, // test
        \\    .y = "test",
        \\    // test
        \\};
        \\
    );
}

test "zig fmt: container doc comments" {
    try testCanonical(
        \\//! tld 1
        \\//! tld 2
        \\//! tld 3
        \\
        \\// comment
        \\
        \\/// A doc
        \\const A = struct {
        \\    //! A tld 1
        \\    //! A tld 2
        \\    //! A tld 3
        \\};
        \\
        \\/// B doc
        \\const B = struct {
        \\    //! B tld 1
        \\    //! B tld 2
        \\    //! B tld 3
        \\
        \\    /// B doc
        \\    b: u32,
        \\};
        \\
        \\/// C doc
        \\const C = union(enum) { // comment
        \\    //! C tld 1
        \\    //! C tld 2
        \\    //! C tld 3
        \\};
        \\
        \\/// D doc
        \\const D = union(Foo) {
        \\    //! D tld 1
        \\    //! D tld 2
        \\    //! D tld 3
        \\
        \\    /// D doc
        \\    b: u32,
        \\};
        \\
    );
    try testCanonical(
        \\//! Top-level documentation.
        \\
        \\/// This is A
        \\pub const A = usize;
        \\
    );
    try testCanonical(
        \\//! Nothing here
        \\
    );
}

test "zig fmt: remove newlines surrounding doc comment" {
    try testTransform(
        \\
        \\
        \\
        \\/// doc comment
        \\
        \\fn foo() void {}
        \\
    ,
        \\/// doc comment
        \\fn foo() void {}
        \\
    );
}

test "zig fmt: remove newlines surrounding doc comment between members" {
    try testTransform(
        \\f1: i32,
        \\
        \\
        \\/// doc comment
        \\
        \\f2: i32,
        \\
    ,
        \\f1: i32,
        \\
        \\/// doc comment
        \\f2: i32,
        \\
    );
}

test "zig fmt: remove newlines surrounding doc comment between members within container decl (1)" {
    try testTransform(
        \\const Foo = struct {
        \\    fn foo() void {}
        \\
        \\
        \\    /// doc comment
        \\
        \\
        \\    fn bar() void {}
        \\};
        \\
    ,
        \\const Foo = struct {
        \\    fn foo() void {}
        \\
        \\    /// doc comment
        \\    fn bar() void {}
        \\};
        \\
    );
}

test "zig fmt: remove newlines surrounding doc comment between members within container decl (2)" {
    try testTransform(
        \\const Foo = struct {
        \\    fn foo() void {}
        \\    /// doc comment 1
        \\
        \\    /// doc comment 2
        \\
        \\    fn bar() void {}
        \\};
        \\
    ,
        \\const Foo = struct {
        \\    fn foo() void {}
        \\    /// doc comment 1
        \\    /// doc comment 2
        \\    fn bar() void {}
        \\};
        \\
    );
}

test "zig fmt: remove newlines surrounding doc comment within container decl" {
    try testTransform(
        \\const Foo = struct {
        \\
        \\
        \\    /// doc comment
        \\
        \\    fn foo() void {}
        \\};
        \\
    ,
        \\const Foo = struct {
        \\    /// doc comment
        \\    fn foo() void {}
        \\};
        \\
    );
}

test "zig fmt: comptime before comptime field" {
    try testError(
        \\const Foo = struct {
        \\    a: i32,
        \\    comptime comptime b: i32 = 1234,
        \\};
        \\
    , &[_]Error{
        .expected_comma_after_field,
    });
}

test "zig fmt: invalid doc comments on comptime and test blocks" {
    try testError(
        \\/// This is a doc comment for a comptime block.
        \\comptime {}
        \\/// This is a doc comment for a test
        \\test "This is my test" {}
    , &[_]Error{
        .comptime_doc_comment,
        .test_doc_comment,
    });
}

test "zig fmt: comments with CRLF line endings" {
    try testTransform("" ++
        "//! Top-level doc comment\r\n" ++
        "//! Continuing to another line\r\n" ++
        "\r\n" ++
        "/// Regular doc comment\r\n" ++
        "const S = struct {\r\n" ++
        "    // Regular comment\r\n" ++
        "    // More content\r\n" ++
        "};\r\n",
        \\//! Top-level doc comment
        \\//! Continuing to another line
        \\
        \\/// Regular doc comment
        \\const S = struct {
        \\    // Regular comment
        \\    // More content
        \\};
        \\
    );
}

test "zig fmt: else comptime expr" {
    try testCanonical(
        \\comptime {
        \\    if (true) {} else comptime foo();
        \\}
        \\comptime {
        \\    while (true) {} else comptime foo();
        \\}
        \\comptime {
        \\    for ("") |_| {} else comptime foo();
        \\}
        \\
    );
}

test "zig fmt: invalid else branch statement" {
    try testError(
        \\comptime {
        \\    if (true) {} else var a = 0;
        \\    if (true) {} else defer {}
        \\}
        \\comptime {
        \\    while (true) {} else var a = 0;
        \\    while (true) {} else defer {}
        \\}
        \\comptime {
        \\    for ("") |_| {} else var a = 0;
        \\    for ("") |_| {} else defer {}
        \\}
    , &[_]Error{
        .expected_expr_or_assignment,
        .expected_expr_or_assignment,
        .expected_expr_or_assignment,
        .expected_expr_or_assignment,
        .expected_expr_or_assignment,
        .expected_expr_or_assignment,
    });
}

test "zig fmt: anytype struct field" {
    try testError(
        \\pub const Pointer = struct {
        \\    sentinel: anytype,
        \\};
        \\
    , &[_]Error{
        .expected_type_expr,
    });
}

test "zig fmt: extern without container keyword returns error" {
    try testError(
        \\const container = extern {};
        \\
    , &[_]Error{
        .expected_container,
    });
}

test "zig fmt: same line doc comment returns error" {
    try testError(
        \\const Foo = struct{
        \\    bar: u32, /// comment
        \\    foo: u32, /// comment
        \\    /// comment
        \\};
        \\
        \\const a = 42; /// comment
        \\
        \\extern fn foo() void; /// comment
        \\
        \\/// comment
        \\
    , &[_]Error{
        .same_line_doc_comment,
        .same_line_doc_comment,
        .unattached_doc_comment,
        .same_line_doc_comment,
        .same_line_doc_comment,
        .unattached_doc_comment,
    });
}

test "zig fmt: integer literals with underscore separators" {
    try testTransform(
        \\const
        \\ x     =
        \\ 1_234_567
        \\ + (0b0_1-0o7_0+0xff_FF ) +  1_0;
    ,
        \\const x =
        \\    1_234_567 + (0b0_1 - 0o7_0 + 0xff_FF) + 1_0;
        \\
    );
}

test "zig fmt: hex literals with underscore separators" {
    try testTransform(
        \\pub fn orMask(a: [ 1_000 ]u64, b: [  1_000]  u64) [1_000]u64 {
        \\    var c: [1_000]u64 =  [1]u64{ 0xFFFF_FFFF_FFFF_FFFF}**1_000;
        \\    for (c [ 1_0 .. ], 0..) |_, i| {
        \\        c[i] = (a[i] | b[i]) & 0xCCAA_CCAA_CCAA_CCAA;
        \\    }
        \\    return c;
        \\}
        \\
        \\
    ,
        \\pub fn orMask(a: [1_000]u64, b: [1_000]u64) [1_000]u64 {
        \\    var c: [1_000]u64 = [1]u64{0xFFFF_FFFF_FFFF_FFFF} ** 1_000;
        \\    for (c[1_0..], 0..) |_, i| {
        \\        c[i] = (a[i] | b[i]) & 0xCCAA_CCAA_CCAA_CCAA;
        \\    }
        \\    return c;
        \\}
        \\
    );
}

test "zig fmt: decimal float literals with underscore separators" {
    try testTransform(
        \\pub fn main() void {
        \\    const a:f64=(10.0e-0+(10.0e+0))+10_00.00_00e-2+20_00.00_10e+4;
        \\    const b:f64=1_0.0--10_10.0+1_0_0.0_0+1e2;
        \\    std.debug.warn("a: {}, b: {} -> a+b: {}\n", .{ a, b, a + b });
        \\}
    ,
        \\pub fn main() void {
        \\    const a: f64 = (10.0e-0 + (10.0e+0)) + 10_00.00_00e-2 + 20_00.00_10e+4;
        \\    const b: f64 = 1_0.0 - -10_10.0 + 1_0_0.0_0 + 1e2;
        \\    std.debug.warn("a: {}, b: {} -> a+b: {}\n", .{ a, b, a + b });
        \\}
        \\
    );
}

test "zig fmt: hexadecimal float literals with underscore separators" {
    try testTransform(
        \\pub fn main() void {
        \\    const a: f64 = (0x10.0p-0+(0x10.0p+0))+0x10_00.00_00p-8+0x00_00.00_10p+16;
        \\    const b: f64 = 0x0010.0--0x00_10.0+0x10.00+0x1p4;
        \\    std.debug.warn("a: {}, b: {} -> a+b: {}\n", .{ a, b, a + b });
        \\}
    ,
        \\pub fn main() void {
        \\    const a: f64 = (0x10.0p-0 + (0x10.0p+0)) + 0x10_00.00_00p-8 + 0x00_00.00_10p+16;
        \\    const b: f64 = 0x0010.0 - -0x00_10.0 + 0x10.00 + 0x1p4;
        \\    std.debug.warn("a: {}, b: {} -> a+b: {}\n", .{ a, b, a + b });
        \\}
        \\
    );
}

test "zig fmt: C var args" {
    try testCanonical(
        \\pub extern "c" fn printf(format: [*:0]const u8, ...) c_int;
        \\
    );
}

test "zig fmt: Only indent multiline string literals in function calls" {
    try testCanonical(
        \\test "zig fmt:" {
        \\    try testTransform(
        \\        \\const X = struct {
        \\        \\    foo: i32, bar: i8 };
        \\    ,
        \\        \\const X = struct {
        \\        \\    foo: i32, bar: i8
        \\        \\};
        \\        \\
        \\    );
        \\}
        \\
    );
}

test "zig fmt: Don't add extra newline after if" {
    try testCanonical(
        \\pub fn atomicSymLink(allocator: Allocator, existing_path: []const u8, new_path: []const u8) !void {
        \\    if (cwd().symLink(existing_path, new_path, .{})) {
        \\        return;
        \\    }
        \\}
        \\
    );
}

test "zig fmt: comments in ternary ifs" {
    try testCanonical(
        \\const x = if (true) {
        \\    1;
        \\} else if (false)
        \\    // Comment
        \\    0;
        \\const y = if (true)
        \\    // Comment
        \\    1
        \\else
        \\    // Comment
        \\    0;
        \\
        \\pub extern "c" fn printf(format: [*:0]const u8, ...) c_int;
        \\
    );
}

test "zig fmt: while statement in blockless if" {
    try testCanonical(
        \\pub fn main() void {
        \\    const zoom_node = if (focused_node == layout_first)
        \\        while (it.next()) |node| {
        \\            if (!node.view.pending.float and !node.view.pending.fullscreen) break node;
        \\        } else null
        \\    else
        \\        focused_node;
        \\}
        \\
    );
}

test "zig fmt: test comments in field access chain" {
    try testCanonical(
        \\pub const str = struct {
        \\    pub const Thing = more.more //
        \\        .more() //
        \\        .more().more() //
        \\        .more() //
        \\        // .more() //
        \\        .more() //
        \\        .more();
        \\    data: Data,
        \\};
        \\
        \\pub const str = struct {
        \\    pub const Thing = more.more //
        \\        .more() //
        \\        // .more() //
        \\        // .more() //
        \\        // .more() //
        \\        .more() //
        \\        .more();
        \\    data: Data,
        \\};
        \\
        \\pub const str = struct {
        \\    pub const Thing = more //
        \\        .more //
        \\        .more() //
        \\        .more();
        \\    data: Data,
        \\};
        \\
    );
}

test "zig fmt: allow line break before field access" {
    try testCanonical(
        \\test {
        \\    const w = foo.bar().zippy(zag).iguessthisisok();
        \\
        \\    const x = foo
        \\        .bar()
        \\        . // comment
        \\        // comment
        \\        swooop().zippy(zag)
        \\        .iguessthisisok();
        \\
        \\    const y = view.output.root.server.input_manager.default_seat.wlr_seat.name;
        \\
        \\    const z = view.output.root.server
        \\        .input_manager //
        \\        .default_seat
        \\        . // comment
        \\        // another comment
        \\        wlr_seat.name;
        \\}
        \\
    );
    try testTransform(
        \\test {
        \\    const x = foo.
        \\        bar()
        \\        .zippy(zag).iguessthisisok();
        \\
        \\    const z = view.output.root.server.
        \\        input_manager.
        \\        default_seat.wlr_seat.name;
        \\}
        \\
    ,
        \\test {
        \\    const x = foo
        \\        .bar()
        \\        .zippy(zag).iguessthisisok();
        \\
        \\    const z = view.output.root.server
        \\        .input_manager
        \\        .default_seat.wlr_seat.name;
        \\}
        \\
    );
}

test "zig fmt: Indent comma correctly after multiline string literals in arg list (trailing comma)" {
    try testCanonical(
        \\fn foo() void {
        \\    z.display_message_dialog(
        \\        *const [323:0]u8,
        \\        \\Message Text
        \\        \\------------
        \\        \\xxxxxxxxxxxx
        \\        \\xxxxxxxxxxxx
        \\    ,
        \\        g.GtkMessageType.GTK_MESSAGE_WARNING,
        \\        null,
        \\    );
        \\
        \\    z.display_message_dialog(*const [323:0]u8,
        \\        \\Message Text
        \\        \\------------
        \\        \\xxxxxxxxxxxx
        \\        \\xxxxxxxxxxxx
        \\    , g.GtkMessageType.GTK_MESSAGE_WARNING, null);
        \\}
        \\
    );
}

test "zig fmt: Control flow statement as body of blockless if" {
    try testCanonical(
        \\pub fn main() void {
        \\    const zoom_node = if (focused_node == layout_first)
        \\        if (it.next()) {
        \\            if (!node.view.pending.float and !node.view.pending.fullscreen) break node;
        \\        } else null
        \\    else
        \\        focused_node;
        \\
        \\    const zoom_node = if (focused_node == layout_first) while (it.next()) |node| {
        \\        if (!node.view.pending.float and !node.view.pending.fullscreen) break node;
        \\    } else null else focused_node;
        \\
        \\    const zoom_node = if (focused_node == layout_first)
        \\        if (it.next()) {
        \\            if (!node.view.pending.float and !node.view.pending.fullscreen) break node;
        \\        } else null;
        \\
        \\    const zoom_node = if (focused_node == layout_first) while (it.next()) |node| {
        \\        if (!node.view.pending.float and !node.view.pending.fullscreen) break node;
        \\    };
        \\
        \\    const zoom_node = if (focused_node == layout_first) for (nodes) |node| {
        \\        break node;
        \\    };
        \\
        \\    const zoom_node = if (focused_node == layout_first) switch (nodes) {
        \\        0 => 0,
        \\    } else focused_node;
        \\}
        \\
    );
}

test "zig fmt: regression test for #5722" {
    try testCanonical(
        \\pub fn sendViewTags(self: Self) void {
        \\    var it = ViewStack(View).iterator(self.output.views.first, std.math.maxInt(u32));
        \\    while (it.next()) |node|
        \\        view_tags.append(node.view.current_tags) catch {
        \\            c.wl_resource_post_no_memory(self.wl_resource);
        \\            log.err(.river_status, "out of memory", .{});
        \\            return;
        \\        };
        \\}
        \\
    );
}

test "zig fmt: regression test for #8974" {
    try testCanonical(
        \\pub const VARIABLE;
        \\
    );
}

test "zig fmt: allow trailing line comments to do manual array formatting" {
    try testCanonical(
        \\fn foo() void {
        \\    self.code.appendSliceAssumeCapacity(&[_]u8{
        \\        0x55, // push rbp
        \\        0x48, 0x89, 0xe5, // mov rbp, rsp
        \\        0x48, 0x81, 0xec, // sub rsp, imm32 (with reloc)
        \\    });
        \\
        \\    di_buf.appendAssumeCapacity(&[_]u8{
        \\        1, DW.TAG_compile_unit, DW.CHILDREN_no, // header
        \\        DW.AT_stmt_list, DW_FORM_data4, // form value pairs
        \\        DW.AT_low_pc,    DW_FORM_addr,
        \\        DW.AT_high_pc,   DW_FORM_addr,
        \\        DW.AT_name,      DW_FORM_strp,
        \\        DW.AT_comp_dir,  DW_FORM_strp,
        \\        DW.AT_producer,  DW_FORM_strp,
        \\        DW.AT_language,  DW_FORM_data2,
        \\        0, 0, // sentinel
        \\    });
        \\
        \\    self.code.appendSliceAssumeCapacity(&[_]u8{
        \\        0x55, // push rbp
        \\        0x48, 0x89, 0xe5, // mov rbp, rsp
        \\        // How do we handle this?
        \\        //0x48, 0x81, 0xec, // sub rsp, imm32 (with reloc)
        \\        // Here's a blank line, should that be allowed?
        \\
        \\        0x48, 0x89, 0xe5,
        \\        0x33, 0x45,
        \\        // Now the comment breaks a single line -- how do we handle this?
        \\        0x88,
        \\    });
        \\}
        \\
    );
}

test "zig fmt: multiline string literals should play nice with array initializers" {
    try testCanonical(
        \\fn main() void {
        \\    var a = .{.{.{.{.{.{.{.{
        \\        0,
        \\    }}}}}}}};
        \\    myFunc(.{
        \\        "aaaaaaa",                           "bbbbbb", "ccccc",
        \\        "dddd",                              ("eee"),  ("fff"),
        \\        ("gggg"),
        \\        // Line comment
        \\        \\Multiline String Literals can be quite long
        \\        ,
        \\        \\Multiline String Literals can be quite long
        \\        \\Multiline String Literals can be quite long
        \\        ,
        \\        \\Multiline String Literals can be quite long
        \\        \\Multiline String Literals can be quite long
        \\        \\Multiline String Literals can be quite long
        \\        \\Multiline String Literals can be quite long
        \\        ,
        \\        (
        \\            \\Multiline String Literals can be quite long
        \\        ),
        \\        .{
        \\            \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\            \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\            \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\        },
        \\        .{(
        \\            \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\        )},
        \\        .{
        \\            "xxxxxxx", "xxx",
        \\            (
        \\                \\ xxx
        \\            ),
        \\            "xxx",
        \\            "xxx",
        \\        },
        \\        .{ "xxxxxxx", "xxx", "xxx", "xxx" },
        \\        .{ "xxxxxxx", "xxx", "xxx", "xxx" },
        \\        "aaaaaaa", "bbbbbb", "ccccc", // -
        \\        "dddd",    ("eee"),  ("fff"),
        \\        .{
        \\            "xxx",            "xxx",
        \\            (
        \\                \\ xxx
        \\            ),
        \\            "xxxxxxxxxxxxxx",
        \\            "xxx",
        \\        },
        \\        .{
        \\            (
        \\                \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\            ),
        \\            \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\        },
        \\        \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\        \\xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        \\    });
        \\}
        \\
    );
}

test "zig fmt: use of comments and multiline string literals may force the parameters over multiple lines" {
    try testCanonical(
        \\pub fn makeMemUndefined(qzz: []u8) i1 {
        \\    cases.add( // fixed bug foo
        \\        "compile diagnostic string for top level decl type",
        \\        \\export fn entry() void {
        \\        \\    var foo: u32 = @This(){};
        \\        \\}
        \\    , &[_][]const u8{
        \\        "tmp.zig:2:27: error: type 'u32' does not support array initialization",
        \\    });
        \\    @compileError(
        \\        \\ unknown-length pointers and C pointers cannot be hashed deeply.
        \\        \\ Consider providing your own hash function.
        \\        \\ unknown-length pointers and C pointers cannot be hashed deeply.
        \\        \\ Consider providing your own hash function.
        \\    );
        \\    return @intCast(doMemCheckClientRequestExpr(0, // default return
        \\        .MakeMemUndefined, @intFromPtr(qzz.ptr), qzz.len, 0, 0, 0));
        \\}
        \\
        \\// This looks like garbage don't do this
        \\const rparen = tree.prevToken(
        \\    // the first token for the annotation expressions is the left
        \\    // parenthesis, hence the need for two prevToken
        \\    if (fn_proto.getAlignExpr()) |align_expr|
        \\        tree.prevToken(tree.prevToken(align_expr.firstToken()))
        \\    else if (fn_proto.getSectionExpr()) |section_expr|
        \\        tree.prevToken(tree.prevToken(section_expr.firstToken()))
        \\    else if (fn_proto.getCallconvExpr()) |callconv_expr|
        \\        tree.prevToken(tree.prevToken(callconv_expr.firstToken()))
        \\    else switch (fn_proto.return_type) {
        \\        .Explicit => |node| node.firstToken(),
        \\        .InferErrorSet => |node| tree.prevToken(node.firstToken()),
        \\        .Invalid => unreachable,
        \\    });
        \\
    );
}

test "zig fmt: single argument trailing commas in @builtins()" {
    try testCanonical(
        \\pub fn foo(qzz: []u8) i1 {
        \\    @panic(
        \\        foo,
        \\    );
        \\    panic(
        \\        foo,
        \\    );
        \\    @panic(
        \\        foo,
        \\        bar,
        \\    );
        \\}
        \\
    );
}

test "zig fmt: trailing comma should force multiline 1 column" {
    try testTransform(
        \\pub const UUID_NULL: uuid_t = [16]u8{0,0,0,0,};
        \\
    ,
        \\pub const UUID_NULL: uuid_t = [16]u8{
        \\    0,
        \\    0,
        \\    0,
        \\    0,
        \\};
        \\
    );
}

test "zig fmt: function params should align nicely" {
    try testCanonical(
        \\pub fn foo() void {
        \\    cases.addRuntimeSafety("slicing operator with sentinel",
        \\        \\const std = @import("std");
        \\    ++ check_panic_msg ++
        \\        \\pub fn main() void {
        \\        \\    var buf = [4]u8{'a','b','c',0};
        \\        \\    const slice = buf[0..:0];
        \\        \\}
        \\    );
        \\}
        \\
    );
}

test "zig fmt: fn proto end with anytype and comma" {
    try testCanonical(
        \\pub fn format(
        \\    out_stream: anytype,
        \\) !void {}
        \\
    );
}

test "zig fmt: space after top level doc comment" {
    try testCanonical(
        \\//! top level doc comment
        \\
        \\field: i32,
        \\
    );
}

test "zig fmt: remove trailing whitespace after container doc comment" {
    try testTransform(
        \\//! top level doc comment 
        \\
    ,
        \\//! top level doc comment
        \\
    );
}

test "zig fmt: remove trailing whitespace after doc comment" {
    try testTransform(
        \\/// doc comment 
        \\a = 0,
        \\
    ,
        \\/// doc comment
        \\a = 0,
        \\
    );
}

test "zig fmt: for loop with ptr payload and index" {
    try testCanonical(
        \\test {
        \\    for (self.entries.items, 0..) |*item, i| {}
        \\    for (self.entries.items, 0..) |*item, i|
        \\        a = b;
        \\    for (self.entries.items, 0..) |*item, i| a = b;
        \\}
        \\
    );
}

test "zig fmt: proper indent line comment after multi-line single expr while loop" {
    try testCanonical(
        \\test {
        \\    while (a) : (b)
        \\        foo();
        \\
        \\    // bar
        \\    baz();
        \\}
        \\
    );
}

test "zig fmt: function with labeled block as return type" {
    try testCanonical(
        \\fn foo() t: {
        \\    break :t bar;
        \\} {
        \\    baz();
        \\}
        \\
    );
}

test "zig fmt: extern function with missing param name" {
    try testCanonical(
        \\extern fn a(
        \\    *b,
        \\    c: *d,
        \\) e;
        \\extern fn f(*g, h: *i) j;
        \\
    );
}

test "zig fmt: line comment after multiline single expr if statement with multiline string" {
    try testCanonical(
        \\test {
        \\    if (foo)
        \\        x =
        \\            \\hello
        \\            \\hello
        \\            \\
        \\        ;
        \\
        \\    // bar
        \\    baz();
        \\
        \\    if (foo)
        \\        x =
        \\            \\hello
        \\            \\hello
        \\            \\
        \\    else
        \\        y =
        \\            \\hello
        \\            \\hello
        \\            \\
        \\        ;
        \\
        \\    // bar
        \\    baz();
        \\}
        \\
    );
}

test "zig fmt: respect extra newline between fn and pub usingnamespace" {
    try testCanonical(
        \\fn foo() void {
        \\    bar();
        \\}
        \\
        \\pub usingnamespace baz;
        \\
    );
}

test "zig fmt: respect extra newline between switch items" {
    try testCanonical(
        \\const a = switch (b) {
        \\    .c => {},
        \\
        \\    .d,
        \\    .e,
        \\    => f,
        \\};
        \\
    );
}

test "zig fmt: assignment with inline for and inline while" {
    try testCanonical(
        \\const tmp = inline for (items) |item| {};
        \\
    );

    try testCanonical(
        \\const tmp2 = inline while (true) {};
        \\
    );
}

test "zig fmt: saturating arithmetic" {
    try testCanonical(
        \\test {
        \\    const actual = switch (op) {
        \\        .add => a +| b,
        \\        .sub => a -| b,
        \\        .mul => a *| b,
        \\        .shl => a <<| b,
        \\    };
        \\    switch (op) {
        \\        .add => actual +|= b,
        \\        .sub => actual -|= b,
        \\        .mul => actual *|= b,
        \\        .shl => actual <<|= b,
        \\    }
        \\}
        \\
    );
}

test "zig fmt: insert trailing comma if there are comments between switch values" {
    try testTransform(
        \\const a = switch (b) {
        \\    .c => {},
        \\
        \\    .d, // foobar
        \\    .e
        \\    => f,
        \\
        \\    .g, .h
        \\    // comment
        \\    => i,
        \\};
        \\
    ,
        \\const a = switch (b) {
        \\    .c => {},
        \\
        \\    .d, // foobar
        \\    .e,
        \\    => f,
        \\
        \\    .g,
        \\    .h,
        \\    // comment
        \\    => i,
        \\};
        \\
    );
}

test "zig fmt: insert trailing comma if comments in array init" {
    try testTransform(
        \\var a = .{
        \\    "foo", //
        \\    "bar"
        \\};
        \\var a = .{
        \\    "foo",
        \\    "bar" //
        \\};
        \\var a = .{
        \\    "foo",
        \\    "//"
        \\};
        \\var a = .{
        \\    "foo",
        \\    "//" //
        \\};
        \\
    ,
        \\var a = .{
        \\    "foo", //
        \\    "bar",
        \\};
        \\var a = .{
        \\    "foo",
        \\    "bar", //
        \\};
        \\var a = .{ "foo", "//" };
        \\var a = .{
        \\    "foo",
        \\    "//", //
        \\};
        \\
    );
}

test "zig fmt: make single-line if no trailing comma" {
    try testTransform(
        \\test "function call no trailing comma" {
        \\    foo(
        \\        1,
        \\        2
        \\    );
        \\}
        \\
    ,
        \\test "function call no trailing comma" {
        \\    foo(1, 2);
        \\}
        \\
    );

    try testTransform(
        \\test "struct no trailing comma" {
        \\    const a = .{
        \\        .foo = 1,
        \\        .bar = 2
        \\    };
        \\}
        \\
    ,
        \\test "struct no trailing comma" {
        \\    const a = .{ .foo = 1, .bar = 2 };
        \\}
        \\
    );

    try testTransform(
        \\test "array no trailing comma" {
        \\    var stream = multiOutStream(.{
        \\        fbs1.outStream(),
        \\        fbs2.outStream()
        \\    });
        \\}
        \\
    ,
        \\test "array no trailing comma" {
        \\    var stream = multiOutStream(.{ fbs1.outStream(), fbs2.outStream() });
        \\}
        \\
    );
}

test "zig fmt: preserve container doc comment in container without trailing comma" {
    try testTransform(
        \\const A = enum(u32) {
        \\//! comment
        \\_ };
        \\
    ,
        \\const A = enum(u32) {
        \\    //! comment
        \\    _,
        \\};
        \\
    );
}

test "zig fmt: make single-line if no trailing comma, fmt: off" {
    try testCanonical(
        \\// Test trailing comma syntax
        \\// zig fmt: off
        \\
        \\extern var a: c_int;
        \\extern "c" var b: c_int;
        \\export var c: c_int = 0;
        \\threadlocal var d: c_int = 0;
        \\extern threadlocal var e: c_int;
        \\extern "c" threadlocal var f: c_int;
        \\export threadlocal var g: c_int = 0;
        \\
        \\const struct_trailing_comma = struct { x: i32, y: i32, };
        \\const struct_no_comma = struct { x: i32, y: i32 };
        \\const struct_fn_no_comma = struct { fn m() void {} y: i32 };
        \\
        \\const enum_no_comma = enum { A, B };
        \\
        \\fn container_init() void {
        \\    const S = struct { x: i32, y: i32 };
        \\    _ = S { .x = 1, .y = 2 };
        \\    _ = S { .x = 1, .y = 2, };
        \\}
        \\
        \\fn type_expr_return1() if (true) A {}
        \\fn type_expr_return2() for (true) |_| A {}
        \\fn type_expr_return3() while (true) A {}
        \\
        \\fn switch_cases(x: i32) void {
        \\    switch (x) {
        \\        1,2,3 => {},
        \\        4,5, => {},
        \\        6...8, => {},
        \\        else => {},
        \\    }
        \\}
        \\
        \\fn switch_prongs(x: i32) void {
        \\    switch (x) {
        \\        0 => {},
        \\        else => {},
        \\    }
        \\    switch (x) {
        \\        0 => {},
        \\        else => {}
        \\    }
        \\}
        \\
        \\const fn_no_comma = fn (i32, i32) void;
        \\const fn_trailing_comma = fn (i32, i32,) void;
        \\
        \\fn fn_calls() void {
        \\    fn add(x: i32, y: i32,) i32 { x + y };
        \\    _ = add(1, 2);
        \\    _ = add(1, 2,);
        \\}
        \\
        \\fn asm_lists() void {
        \\    if (false) { // Build AST but don't analyze
        \\        asm ("not real assembly"
        \\            :[a] "x" (x),);
        \\        asm ("not real assembly"
        \\            :[a] "x" (->i32),:[a] "x" (1),);
        \\        asm volatile ("still not real assembly"
        \\            :::"a","b",);
        \\    }
        \\}
    );
}

test "zig fmt: variable initialized with ==" {
    try testError(
        \\comptime {
        \\    var z: u32 == 12 + 1;
        \\}
    , &.{.wrong_equal_var_decl});
}

test "zig fmt: missing const/var before local variable in comptime block" {
    try testError(
        \\comptime {
        \\    z: u32;
        \\}
        \\comptime {
        \\    z: u32 align(1);
        \\}
        \\comptime {
        \\    z: u32 addrspace(.generic);
        \\}
        \\comptime {
        \\    z: u32 linksection("foo");
        \\}
        \\comptime {
        \\    z: u32 = 1;
        \\}
    , &.{
        .expected_labelable,
        .expected_var_const,
        .expected_var_const,
        .expected_var_const,
        .expected_var_const,
    });
}

test "zig fmt: missing const/var before local variable" {
    try testError(
        \\std = foo,
        \\std = foo;
        \\*u32 = foo;
    , &.{
        .expected_comma_after_field,
        .var_const_decl,
        .expected_comma_after_field,
    });
}

test "zig fmt: while continue expr" {
    try testCanonical(
        \\test {
        \\    while (i > 0)
        \\        (i * 2);
        \\}
        \\
    );
    try testError(
        \\test {
        \\    while (i > 0) (i -= 1) {
        \\        print("test123", .{});
        \\    }
        \\}
    , &[_]Error{
        .expected_continue_expr,
    });
}

test "zig fmt: canonicalize symbols (simple)" {
    try testTransform(
        \\const val_normal: Normal = .{};
        \\const @"val_unesc_me": @"UnescMe" = .{};
        \\const @"val_esc!": @"Esc!" = .{};
        \\
        \\fn fnNormal() void {}
        \\fn @"fnUnescMe"() void {}
        \\fn @"fnEsc!"() void {}
        \\
        \\extern fn protoNormal() void;
        \\extern fn @"protoUnescMe"() void;
        \\extern fn @"protoEsc!"() void;
        \\
        \\fn fnWithArgs(normal: Normal, @"unesc_me": @"UnescMe", @"esc!": @"Esc!") void {
        \\    _ = normal;
        \\    _ = @"unesc_me";
        \\    _ = @"esc!";
        \\}
        \\
        \\const Normal = struct {};
        \\const @"UnescMe" = struct {
        \\    @"x": @"X",
        \\    const X = union(@"EnumUnesc") {
        \\        normal,
        \\        @"unesc_me",
        \\        @"esc!",
        \\    };
        \\    const @"EnumUnesc" = enum {
        \\        normal,
        \\        @"unesc_me",
        \\        @"esc!",
        \\    };
        \\};
        \\const @"Esc!" = struct {
        \\    normal: bool = false,
        \\    @"unesc_me": bool = false,
        \\    @"esc!": bool = false,
        \\};
        \\
        \\pub fn main() void {
        \\    _ = val_normal;
        \\    _ = @"val_normal";
        \\    _ = val_unesc_me;
        \\    _ = @"val_unesc_me";
        \\    _ = @"val_esc!";
        \\
        \\    fnNormal();
        \\    @"fnNormal"();
        \\    fnUnescMe();
        \\    @"fnUnescMe"();
        \\    @"fnEsc!"();
        \\
        \\    fnWithArgs(1, Normal{}, UnescMe{}, @"Esc!"{});
        \\    fnWithArgs(1, @"Normal"{}, @"UnescMe"{}, @"Esc!"{});
        \\    fnWithArgs(1, @"Normal"{}, @"Normal"{}, @"Esc!"{});
        \\
        \\    const local_val1: @"Normal" = .{};
        \\    const @"local_val2": UnescMe = .{
        \\        .@"x" = .@"unesc_me",
        \\    };
        \\    fnWithArgs(@"local_val1", @"local_val2", .{ .@"normal" = true, .@"unesc_me" = true, .@"esc!" = true });
        \\    fnWithArgs(local_val1, local_val2, .{ .normal = true, .unesc_me = true, .@"esc!" = true });
        \\
        \\    var x: u8 = 'x';
        \\    switch (@"x") {
        \\        @"x" => {},
        \\    }
        \\
        \\    _ = @import("std"); // Don't mess with @builtins
        \\    // @"comment"
        \\}
        \\
    ,
        \\const val_normal: Normal = .{};
        \\const val_unesc_me: UnescMe = .{};
        \\const @"val_esc!": @"Esc!" = .{};
        \\
        \\fn fnNormal() void {}
        \\fn fnUnescMe() void {}
        \\fn @"fnEsc!"() void {}
        \\
        \\extern fn protoNormal() void;
        \\extern fn protoUnescMe() void;
        \\extern fn @"protoEsc!"() void;
        \\
        \\fn fnWithArgs(normal: Normal, unesc_me: UnescMe, @"esc!": @"Esc!") void {
        \\    _ = normal;
        \\    _ = unesc_me;
        \\    _ = @"esc!";
        \\}
        \\
        \\const Normal = struct {};
        \\const UnescMe = struct {
        \\    x: X,
        \\    const X = union(EnumUnesc) {
        \\        normal,
        \\        unesc_me,
        \\        @"esc!",
        \\    };
        \\    const EnumUnesc = enum {
        \\        normal,
        \\        unesc_me,
        \\        @"esc!",
        \\    };
        \\};
        \\const @"Esc!" = struct {
        \\    normal: bool = false,
        \\    unesc_me: bool = false,
        \\    @"esc!": bool = false,
        \\};
        \\
        \\pub fn main() void {
        \\    _ = val_normal;
        \\    _ = val_normal;
        \\    _ = val_unesc_me;
        \\    _ = val_unesc_me;
        \\    _ = @"val_esc!";
        \\
        \\    fnNormal();
        \\    fnNormal();
        \\    fnUnescMe();
        \\    fnUnescMe();
        \\    @"fnEsc!"();
        \\
        \\    fnWithArgs(1, Normal{}, UnescMe{}, @"Esc!"{});
        \\    fnWithArgs(1, Normal{}, UnescMe{}, @"Esc!"{});
        \\    fnWithArgs(1, Normal{}, Normal{}, @"Esc!"{});
        \\
        \\    const local_val1: Normal = .{};
        \\    const local_val2: UnescMe = .{
        \\        .x = .unesc_me,
        \\    };
        \\    fnWithArgs(local_val1, local_val2, .{ .normal = true, .unesc_me = true, .@"esc!" = true });
        \\    fnWithArgs(local_val1, local_val2, .{ .normal = true, .unesc_me = true, .@"esc!" = true });
        \\
        \\    var x: u8 = 'x';
        \\    switch (x) {
        \\        x => {},
        \\    }
        \\
        \\    _ = @import("std"); // Don't mess with @builtins
        \\    // @"comment"
        \\}
        \\
    );
}

// Contextually unescape when shadowing primitive types and values.
test "zig fmt: canonicalize symbols (primitive types)" {
    try testTransform(
        \\const @"anyopaque" = struct {
        \\    @"u8": @"type" = true,
        \\    @"_": @"false" = @"true",
        \\    const @"type" = bool;
        \\    const @"false" = bool;
        \\    const @"true" = false;
        \\};
        \\
        \\const U = union(@"null") {
        \\    @"type",
        \\    const @"null" = enum {
        \\        @"type",
        \\    };
        \\};
        \\
        \\test {
        \\    const E = enum { @"anyopaque" };
        \\    _ = U{ .@"type" = {} };
        \\    _ = U.@"type";
        \\    _ = E.@"anyopaque";
        \\}
        \\
        \\fn @"i10"(@"void": @"anyopaque", @"type": @"anyopaque".@"type") error{@"null"}!void {
        \\    var @"f32" = @"void";
        \\    @"f32".@"u8" = false;
        \\    _ = @"type";
        \\    _ = type;
        \\    if (@"f32".@"u8") {
        \\        return @"i10"(.{ .@"u8" = true, .@"_" = false }, false);
        \\    } else {
        \\        return error.@"null";
        \\    }
        \\}
        \\
        \\test @"i10" {
        \\    try @"i10"(.{}, true);
        \\    _ = @"void": while (null) |@"u3"| {
        \\        break :@"void" @"u3";
        \\    };
        \\    _ = @"void": {
        \\        break :@"void";
        \\    };
        \\    for ("hi", 0..) |@"u3", @"i4"| {
        \\        _ = @"u3";
        \\        _ = @"i4";
        \\    }
        \\    if (false) {} else |@"bool"| {
        \\        _ = @"bool";
        \\    }
        \\}
        \\
    ,
        \\const @"anyopaque" = struct {
        \\    u8: @"type" = true,
        \\    _: @"false" = @"true",
        \\    const @"type" = bool;
        \\    const @"false" = bool;
        \\    const @"true" = false;
        \\};
        \\
        \\const U = union(@"null") {
        \\    type,
        \\    const @"null" = enum {
        \\        type,
        \\    };
        \\};
        \\
        \\test {
        \\    const E = enum { anyopaque };
        \\    _ = U{ .type = {} };
        \\    _ = U.type;
        \\    _ = E.anyopaque;
        \\}
        \\
        \\fn @"i10"(@"void": @"anyopaque", @"type": @"anyopaque".type) error{null}!void {
        \\    var @"f32" = @"void";
        \\    @"f32".u8 = false;
        \\    _ = @"type";
        \\    _ = type;
        \\    if (@"f32".u8) {
        \\        return @"i10"(.{ .u8 = true, ._ = false }, false);
        \\    } else {
        \\        return error.null;
        \\    }
        \\}
        \\
        \\test @"i10" {
        \\    try @"i10"(.{}, true);
        \\    _ = void: while (null) |@"u3"| {
        \\        break :void @"u3";
        \\    };
        \\    _ = void: {
        \\        break :void;
        \\    };
        \\    for ("hi", 0..) |@"u3", @"i4"| {
        \\        _ = @"u3";
        \\        _ = @"i4";
        \\    }
        \\    if (false) {} else |@"bool"| {
        \\        _ = @"bool";
        \\    }
        \\}
        \\
    );
}

// Never unescape names spelled like keywords.
test "zig fmt: canonicalize symbols (keywords)" {
    try testCanonical(
        \\const @"enum" = struct {
        \\    @"error": @"struct" = true,
        \\    const @"struct" = bool;
        \\};
        \\
        \\fn @"usingnamespace"(@"union": @"enum") error{@"try"}!void {
        \\    var @"struct" = @"union";
        \\    @"struct".@"error" = false;
        \\    if (@"struct".@"error") {
        \\        return @"usingnamespace"(.{ .@"error" = false });
        \\    } else {
        \\        return error.@"try";
        \\    }
        \\}
        \\
        \\test @"usingnamespace" {
        \\    try @"usingnamespace"(.{});
        \\    _ = @"return": {
        \\        break :@"return" 4;
        \\    };
        \\}
        \\
    );
}

test "zig fmt: no space before newline before multiline string" {
    try testCanonical(
        \\const S = struct {
        \\    text: []const u8,
        \\    comment: []const u8,
        \\};
        \\
        \\test {
        \\    const s1 = .{
        \\        .text =
        \\        \\hello
        \\        \\world
        \\        ,
        \\        .comment = "test",
        \\    };
        \\    _ = s1;
        \\    const s2 = .{
        \\        .comment = "test",
        \\        .text =
        \\        \\hello
        \\        \\world
        \\        ,
        \\    };
        \\    _ = s2;
        \\}
        \\
    );
}

// Normalize \xNN and \u{NN} escapes and unicode inside @"" escapes.
test "zig fmt: canonicalize symbols (character escapes)" {
    try testTransform(
        \\const @"\x46\x6f\x6f\x64" = struct {
        \\    @"\x62\x61\x72\x6E": @"\x43\x72\x61\x62" = false,
        \\    @"\u{67}\u{6C}o\u{70}\xFF": @"Cra\x62" = false,
        \\    @"\x65\x72\x72\x6F\x72": Crab = true,
        \\    @"\x74\x72\x79": Crab = true,
        \\    @"\u{74}\u{79}\u{70}\u{65}": @"any\u{6F}\u{70}\u{61}\u{71}\u{75}\u{65}",
        \\
        \\    const @"\x43\x72\x61\x62" = bool;
        \\    const @"\x61\x6E\x79\x6F\x70\x61que" = void;
        \\};
        \\
        \\test "unicode" {
        \\    const @"cąbbäge ⚡" = 2;
        \\    _ = @"cąbbäge ⚡";
        \\    const @"\u{01f422} friend\u{f6}" = 4;
        \\    _ = @"🐢 friendö";
        \\}
        \\
    ,
        \\const Food = struct {
        \\    barn: Crab = false,
        \\    @"glop\xFF": Crab = false,
        \\    @"error": Crab = true,
        \\    @"try": Crab = true,
        \\    type: @"anyopaque",
        \\
        \\    const Crab = bool;
        \\    const @"anyopaque" = void;
        \\};
        \\
        \\test "unicode" {
        \\    const @"cąbbäge ⚡" = 2;
        \\    _ = @"cąbbäge ⚡";
        \\    const @"\u{01f422} friend\u{f6}" = 4;
        \\    _ = @"🐢 friendö";
        \\}
        \\
    );
}

test "zig fmt: canonicalize symbols (asm)" {
    try testTransform(
        \\test "asm" {
        \\    const @"null" = usize;
        \\    const @"try": usize = 808;
        \\    const arg: usize = 2;
        \\    _ = asm volatile ("syscall"
        \\        : [@"void"] "={rax}" (-> @"null"),
        \\        : [@"error"] "{rax}" (@"try"),
        \\          [@"arg1"] "{rdi}" (arg),
        \\          [arg2] "{rsi}" (arg),
        \\          [arg3] "{rdx}" (arg),
        \\        : "rcx", "r11"
        \\    );
        \\
        \\    const @"false": usize = 10;
        \\    const @"true" = "explode";
        \\    _ = asm volatile (@"true"
        \\        : [one] "={rax}" (@"false"),
        \\        : [two] "{rax}" (@"false"),
        \\    );
        \\}
        \\
    ,
        \\test "asm" {
        \\    const @"null" = usize;
        \\    const @"try": usize = 808;
        \\    const arg: usize = 2;
        \\    _ = asm volatile ("syscall"
        \\        : [void] "={rax}" (-> @"null"),
        \\        : [@"error"] "{rax}" (@"try"),
        \\          [arg1] "{rdi}" (arg),
        \\          [arg2] "{rsi}" (arg),
        \\          [arg3] "{rdx}" (arg),
        \\        : "rcx", "r11"
        \\    );
        \\
        \\    const @"false": usize = 10;
        \\    const @"true" = "explode";
        \\    _ = asm volatile (@"true"
        \\        : [one] "={rax}" (false),
        \\        : [two] "{rax}" (@"false"),
        \\    );
        \\}
        \\
    );
}

test "zig fmt: don't canonicalize _ in enums" {
    try testTransform(
        \\const A = enum {
        \\    first,
        \\    second,
        \\    third,
        \\    _,
        \\};
        \\const B = enum {
        \\    @"_",
        \\    @"__",
        \\    @"___",
        \\    @"____",
        \\};
        \\const C = struct {
        \\    @"_": u8,
        \\    @"__": u8,
        \\    @"___": u8,
        \\    @"____": u8,
        \\};
        \\const D = union {
        \\    @"_": u8,
        \\    @"__": u8,
        \\    @"___": u8,
        \\    @"____": u8,
        \\};
        \\
    ,
        \\const A = enum {
        \\    first,
        \\    second,
        \\    third,
        \\    _,
        \\};
        \\const B = enum {
        \\    @"_",
        \\    __,
        \\    ___,
        \\    ____,
        \\};
        \\const C = struct {
        \\    _: u8,
        \\    __: u8,
        \\    ___: u8,
        \\    ____: u8,
        \\};
        \\const D = union {
        \\    _: u8,
        \\    __: u8,
        \\    ___: u8,
        \\    ____: u8,
        \\};
        \\
    );
}

test "zig fmt: error for missing sentinel value in sentinel slice" {
    try testError(
        \\const foo = foo[0..:];
    , &[_]Error{
        .expected_expr,
    });
}

test "zig fmt: error for invalid bit range" {
    try testError(
        \\var x: []align(0:0:0)u8 = bar;
    , &[_]Error{
        .invalid_bit_range,
    });
}

test "zig fmt: error for ptr mod on array child type" {
    try testError(
        \\var a: [10]align(10) u8 = e;
        \\var b: [10]const u8 = f;
        \\var c: [10]volatile u8 = g;
        \\var d: [10]allowzero u8 = h;
    , &[_]Error{
        .ptr_mod_on_array_child_type,
        .ptr_mod_on_array_child_type,
        .ptr_mod_on_array_child_type,
        .ptr_mod_on_array_child_type,
    });
}

test "zig fmt: pointer type syntax to index" {
    try testCanonical(
        \\test {
        \\    _ = .{}[*0];
        \\}
        \\
    );
}

test "zig fmt: binop indentation in if statement" {
    try testCanonical(
        \\test {
        \\    if (first_param_type.isGenericPoison() or
        \\        (first_param_type.zigTypeTag(zcu) == .pointer and
        \\            (first_param_type.ptrSize(zcu) == .One or
        \\                first_param_type.ptrSize(zcu) == .C) and
        \\            first_param_type.childType(zcu).eql(concrete_ty, zcu)))
        \\    {
        \\        f(x);
        \\    }
        \\}
        \\
    );
}

test "zig fmt: test indentation after equals sign" {
    try testCanonical(
        \\test {
        \\    const foo =
        \\        if (1 == 2)
        \\            1
        \\        else if (3 > 4)
        \\            2
        \\        else
        \\            0;
        \\
        \\    const foo, const bar =
        \\        if (1 == 2)
        \\            .{ 0, 0 }
        \\        else if (3 > 4)
        \\            .{ 1, 1 }
        \\        else
        \\            .{ 2, 2 };
        \\
        \\    while (foo) if (bar)
        \\        f(x);
        \\
        \\    foobar =
        \\        if (true)
        \\            1
        \\        else
        \\            0;
        \\
        \\    const foo = if (1 == 2)
        \\        1
        \\    else if (3 > 4)
        \\        2
        \\    else
        \\        0;
        \\
        \\    const foo, const bar = if (1 == 2)
        \\        .{ 0, 0 }
        \\    else if (3 > 4)
        \\        .{ 1, 1 }
        \\    else
        \\        .{ 2, 2 };
        \\
        \\    foobar = if (true)
        \\        1
        \\    else
        \\        0;
        \\
        \\    const is_alphanum =
        \\        (ch >= 'a' and ch <= 'z') or
        \\        (ch >= 'A' and ch <= 'Z') or
        \\        (ch >= '0' and ch <= '9');
        \\
        \\    const bar = 100 + calculate(
        \\        200,
        \\        300,
        \\    );
        \\
        \\    const gcc_pragma = std.meta.stringToEnum(Directive, pp.expandedSlice(directive_tok)) orelse
        \\        return pp.comp.addDiagnostic(.{
        \\            .tag = .unknown_gcc_pragma,
        \\            .loc = directive_tok.loc,
        \\        }, pp.expansionSlice(start_idx + 1));
        \\
        \\    const vec4s =
        \\        [_][4]i32{
        \\            [_]i32{ 0, 1, 0, 0 },
        \\            [_]i32{ 0, -1, 0, 0 },
        \\            [_]i32{ 2, 1, 2, 0 },
        \\        };
        \\}
        \\
    );
}

test "zig fmt: test indentation of if expressions" {
    try testCanonical(
        \\test {
        \\    const foo = 1 +
        \\        if (1 == 2)
        \\            2
        \\        else
        \\            0;
        \\
        \\    const foo = 1 + if (1 == 2)
        \\        2
        \\    else
        \\        0;
        \\
        \\    errval catch |e|
        \\        if (e == error.Meow)
        \\            return 0x1F408
        \\        else
        \\            unreachable;
        \\
        \\    errval catch |e| if (e == error.Meow)
        \\        return 0x1F408
        \\    else
        \\        unreachable;
        \\
        \\    return if (1 == 2)
        \\        1
        \\    else if (3 > 4)
        \\        2
        \\    else
        \\        0;
        \\}
        \\
    );
}

test "zig fmt: indentation of comments within catch, else, orelse" {
    try testCanonical(
        \\comptime {
        \\    _ = foo() catch
        \\        //
        \\        bar();
        \\
        \\    _ = if (foo) bar() else
        \\        //
        \\        qux();
        \\
        \\    _ = foo() orelse
        \\        //
        \\        qu```
