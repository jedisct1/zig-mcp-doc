```
hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@log2](#toc-log2) [§](#log2){.hdr}

    @log2(value: anytype) @TypeOf(value)

Returns the logarithm to the base 2 of a floating point number. Uses a
dedicated hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@log10](#toc-log10) [§](#log10){.hdr}

    @log10(value: anytype) @TypeOf(value)

Returns the logarithm to the base 10 of a floating point number. Uses a
dedicated hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@abs](#toc-abs) [§](#abs){.hdr}

    @abs(value: anytype) anytype

Returns the absolute value of an integer or a floating point number.
Uses a dedicated hardware instruction when available. The return type is
always an unsigned integer of the same bit width as the operand if the
operand is an integer. Unsigned integer operands are supported. The
builtin cannot overflow for signed integer operands.

Supports [Floats](#Floats), [Integers](#Integers) and
[Vectors](#Vectors) of floats or integers.

### [\@floor](#toc-floor) [§](#floor){.hdr}

    @floor(value: anytype) @TypeOf(value)

Returns the largest integral value not greater than the given floating
point number. Uses a dedicated hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@ceil](#toc-ceil) [§](#ceil){.hdr}

    @ceil(value: anytype) @TypeOf(value)

Returns the smallest integral value not less than the given floating
point number. Uses a dedicated hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@trunc](#toc-trunc) [§](#trunc){.hdr}

    @trunc(value: anytype) @TypeOf(value)

Rounds the given floating point number to an integer, towards zero. Uses
a dedicated hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@round](#toc-round) [§](#round){.hdr}

    @round(value: anytype) @TypeOf(value)

Rounds the given floating point number to the nearest integer. If two
integers are equally close, rounds away from zero. Uses a dedicated
hardware instruction when available.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;@round&quot; {
    try expect(@round(1.4) == 1);
    try expect(@round(1.5) == 2);
    try expect(@round(-1.4) == -1);
    try expect(@round(-2.5) == -3);
}</code></pre>
<figcaption>test_round_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_round_builtin.zig
1/1 test_round_builtin.test.@round...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@subWithOverflow](#toc-subWithOverflow) [§](#subWithOverflow){.hdr} {#subWithOverflow}

    @subWithOverflow(a: anytype, b: anytype) struct { @TypeOf(a, b), u1 }

Performs `a - b` and returns a tuple with the result and a possible
overflow bit.

### [\@tagName](#toc-tagName) [§](#tagName){.hdr} {#tagName}

    @tagName(value: anytype) [:0]const u8

Converts an enum value or union value to a string literal representing
the name.

If the enum is non-exhaustive and the tag value does not map to a name,
it invokes safety-checked [Illegal Behavior](#Illegal-Behavior).

### [\@This](#toc-This) [§](#This){.hdr} {#This}

    @This() type

Returns the innermost struct, enum, or union that this function call is
inside. This can be useful for an anonymous struct that needs to refer
to itself:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;@This()&quot; {
    var items = [_]i32{ 1, 2, 3, 4 };
    const list = List(i32){ .items = items[0..] };
    try expect(list.length() == 4);
}

fn List(comptime T: type) type {
    return struct {
        const Self = @This();

        items: []T,

        fn length(self: Self) usize {
            return self.items.len;
        }
    };
}</code></pre>
<figcaption>test_this_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_this_builtin.zig
1/1 test_this_builtin.test.@This()...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

When [`@This`]{.tok-builtin}`()` is used at file scope, it returns a
reference to the struct that corresponds to the current file.

### [\@trap](#toc-trap) [§](#trap){.hdr}

    @trap() noreturn

This function inserts a platform-specific trap/jam instruction which can
be used to exit the program abnormally. This may be implemented by
explicitly emitting an invalid instruction which may cause an illegal
instruction exception of some sort. Unlike for
[`@breakpoint`]{.tok-builtin}`()`, execution does not continue after
this point.

Outside function scope, this builtin causes a compile error.

See also:

- [\@breakpoint](#breakpoint)

### [\@truncate](#toc-truncate) [§](#truncate){.hdr}

    @truncate(integer: anytype) anytype

This function truncates bits from an integer type, resulting in a
smaller or same-sized integer type. The return type is the inferred
result type.

This function always truncates the significant bits of the integer,
regardless of endianness on the target platform.

Calling [`@truncate`]{.tok-builtin} on a number out of range of the
destination type is well defined and working code:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;integer truncation&quot; {
    const a: u16 = 0xabcd;
    const b: u8 = @truncate(a);
    try expect(b == 0xcd);
}</code></pre>
<figcaption>test_truncate_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_truncate_builtin.zig
1/1 test_truncate_builtin.test.integer truncation...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Use [\@intCast](#intCast) to convert numbers guaranteed to fit the
destination type.

### [\@Type](#toc-Type) [§](#Type){.hdr} {#Type}

    @Type(comptime info: std.builtin.Type) type

This function is the inverse of [\@typeInfo](#typeInfo). It reifies type
information into a [`type`]{.tok-type}.

It is available for the following types:

- [`type`]{.tok-type}
- [`noreturn`]{.tok-type}
- [`void`]{.tok-type}
- [`bool`]{.tok-type}
- [Integers](#Integers) - The maximum bit count for an integer type is
  [`65535`]{.tok-number}.
- [Floats](#Floats)
- [Pointers](#Pointers)
- [`comptime_int`]{.tok-type}
- [`comptime_float`]{.tok-type}
- [`@TypeOf`]{.tok-builtin}`(`[`undefined`]{.tok-null}`)`
- [`@TypeOf`]{.tok-builtin}`(`[`null`]{.tok-null}`)`
- [Arrays](#Arrays)
- [Optionals](#Optionals)
- [Error Set Type](#Error-Set-Type)
- [Error Union Type](#Error-Union-Type)
- [Vectors](#Vectors)
- [opaque](#opaque)
- [`anyframe`]{.tok-kw}
- [struct](#struct)
- [enum](#enum)
- [Enum Literals](#Enum-Literals)
- [union](#union)
- [Functions](#Functions)

### [\@typeInfo](#toc-typeInfo) [§](#typeInfo){.hdr} {#typeInfo}

    @typeInfo(comptime T: type) std.builtin.Type

Provides type reflection.

Type information of [structs](#struct), [unions](#union),
[enums](#enum), and [error sets](#Error-Set-Type) has fields which are
guaranteed to be in the same order as appearance in the source file.

Type information of [structs](#struct), [unions](#union),
[enums](#enum), and [opaques](#opaque) has declarations, which are also
guaranteed to be in the same order as appearance in the source file.

### [\@typeName](#toc-typeName) [§](#typeName){.hdr} {#typeName}

    @typeName(T: type) *const [N:0]u8

This function returns the string representation of a type, as an array.
It is equivalent to a string literal of the type name. The returned type
name is fully qualified with the parent namespace included as part of
the type name with a series of dots.

### [\@TypeOf](#toc-TypeOf) [§](#TypeOf){.hdr} {#TypeOf}

    @TypeOf(...) type

[`@TypeOf`]{.tok-builtin} is a special builtin function that takes any
(non-zero) number of expressions as parameters and returns the type of
the result, using [Peer Type Resolution](#Peer-Type-Resolution).

The expressions are evaluated, however they are guaranteed to have no
*runtime* side-effects:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;no runtime side effects&quot; {
    var data: i32 = 0;
    const T = @TypeOf(foo(i32, &amp;data));
    try comptime expect(T == i32);
    try expect(data == 0);
}

fn foo(comptime T: type, ptr: *T) T {
    ptr.* += 1;
    return ptr.*;
}</code></pre>
<figcaption>test_TypeOf_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_TypeOf_builtin.zig
1/1 test_TypeOf_builtin.test.no runtime side effects...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [\@unionInit](#toc-unionInit) [§](#unionInit){.hdr} {#unionInit}

    @unionInit(comptime Union: type, comptime active_field_name: []const u8, init_expr) Union

This is the same thing as [union](#union) initialization syntax, except
that the field name is a [comptime](#comptime)-known value rather than
an identifier token.

[`@unionInit`]{.tok-builtin} forwards its [result
location](#Result-Location-Semantics) to `init_expr`.

### [\@Vector](#toc-Vector) [§](#Vector){.hdr} {#Vector}

    @Vector(len: comptime_int, Element: type) type

Creates [Vectors](#Vectors).

### [\@volatileCast](#toc-volatileCast) [§](#volatileCast){.hdr} {#volatileCast}

    @volatileCast(value: anytype) DestType

Remove [`volatile`]{.tok-kw} qualifier from a pointer.

### [\@workGroupId](#toc-workGroupId) [§](#workGroupId){.hdr} {#workGroupId}

    @workGroupId(comptime dimension: u32) u32

Returns the index of the work group in the current kernel invocation in
dimension `dimension`.

### [\@workGroupSize](#toc-workGroupSize) [§](#workGroupSize){.hdr} {#workGroupSize}

    @workGroupSize(comptime dimension: u32) u32

Returns the number of work items that a work group has in dimension
`dimension`.

### [\@workItemId](#toc-workItemId) [§](#workItemId){.hdr} {#workItemId}

    @workItemId(comptime dimension: u32) u32

Returns the index of the work item in the work group in dimension
`dimension`. This function returns values between [`0`]{.tok-number}
(inclusive) and [`@workGroupSize`]{.tok-builtin}`(dimension)`
(exclusive).

## [Build Mode](#toc-Build-Mode) [§](#Build-Mode){.hdr} {#Build-Mode}

Zig has four build modes:

- [Debug](#Debug) (default)
- [ReleaseFast](#ReleaseFast)
- [ReleaseSafe](#ReleaseSafe)
- [ReleaseSmall](#ReleaseSmall)

To add standard build options to a `build.zig`{.file} file:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const exe = b.addExecutable(.{
        .name = &quot;example&quot;,
        .root_source_file = b.path(&quot;example.zig&quot;),
        .optimize = optimize,
    });
    b.default_step.dependOn(&amp;exe.step);
}</code></pre>
<figcaption>build.zig</figcaption>
</figure>

This causes these options to be available:

[-Doptimize=Debug]{.kbd}
:   Optimizations off and safety on (default)

[-Doptimize=ReleaseSafe]{.kbd}
:   Optimizations on and safety on

[-Doptimize=ReleaseFast]{.kbd}
:   Optimizations on and safety off

[-Doptimize=ReleaseSmall]{.kbd}
:   Size optimizations on and safety off

### [Debug](#toc-Debug) [§](#Debug){.hdr} {#Debug}

<figure>
<pre><code>$ zig build-exe example.zig</code></pre>
<figcaption>Shell</figcaption>
</figure>

- Fast compilation speed
- Safety checks enabled
- Slow runtime performance
- Large binary size
- No reproducible build requirement

### [ReleaseFast](#toc-ReleaseFast) [§](#ReleaseFast){.hdr} {#ReleaseFast}

<figure>
<pre><code>$ zig build-exe example.zig -O ReleaseFast</code></pre>
<figcaption>Shell</figcaption>
</figure>

- Fast runtime performance
- Safety checks disabled
- Slow compilation speed
- Large binary size
- Reproducible build

### [ReleaseSafe](#toc-ReleaseSafe) [§](#ReleaseSafe){.hdr} {#ReleaseSafe}

<figure>
<pre><code>$ zig build-exe example.zig -O ReleaseSafe</code></pre>
<figcaption>Shell</figcaption>
</figure>

- Medium runtime performance
- Safety checks enabled
- Slow compilation speed
- Large binary size
- Reproducible build

### [ReleaseSmall](#toc-ReleaseSmall) [§](#ReleaseSmall){.hdr} {#ReleaseSmall}

<figure>
<pre><code>$ zig build-exe example.zig -O ReleaseSmall</code></pre>
<figcaption>Shell</figcaption>
</figure>

- Medium runtime performance
- Safety checks disabled
- Slow compilation speed
- Small binary size
- Reproducible build

See also:

- [Compile Variables](#Compile-Variables)
- [Zig Build System](#Zig-Build-System)
- [Illegal Behavior](#Illegal-Behavior)

## [Single Threaded Builds](#toc-Single-Threaded-Builds) [§](#Single-Threaded-Builds){.hdr} {#Single-Threaded-Builds}

Zig has a compile option [-fsingle-threaded]{.kbd} which has the
following effects:

- All [Thread Local Variables](#Thread-Local-Variables) are treated as
  regular [Container Level Variables](#Container-Level-Variables).
- The overhead of [Async Functions](#Async-Functions) becomes equivalent
  to function call overhead.
- The
  [`@import`]{.tok-builtin}`(`[`"builtin"`]{.tok-str}`).single_threaded`
  becomes [`true`]{.tok-null} and therefore various userland APIs which
  read this variable become more efficient. For example `std.Mutex`
  becomes an empty data structure and all of its functions become
  no-ops.

## [Illegal Behavior](#toc-Illegal-Behavior) [§](#Illegal-Behavior){.hdr} {#Illegal-Behavior}

Many operations in Zig trigger what is known as \"Illegal Behavior\"
(IB). If Illegal Behavior is detected at compile-time, Zig emits a
compile error and refuses to continue. Otherwise, when Illegal Behavior
is not caught at compile-time, it falls into one of two categories.

Some Illegal Behavior is *safety-checked*: this means that the compiler
will insert \"safety checks\" anywhere that the Illegal Behavior may
occur at runtime, to determine whether it is about to happen. If it is,
the safety check \"fails\", which triggers a panic.

All other Illegal Behavior is *unchecked*, meaning the compiler is
unable to insert safety checks for it. If Unchecked Illegal Behavior is
invoked at runtime, anything can happen: usually that will be some kind
of crash, but the optimizer is free to make Unchecked Illegal Behavior
do anything, such as calling arbitrary functions or clobbering arbitrary
data. This is similar to the concept of \"undefined behavior\" in some
other languages. Note that Unchecked Illegal Behavior still always
results in a compile error if evaluated at [comptime](#comptime),
because the Zig compiler is able to perform more sophisticated checks at
compile-time than at runtime.

Most Illegal Behavior is safety-checked. However, to facilitate
optimizations, safety checks are disabled by default in the
[ReleaseFast](#ReleaseFast) and [ReleaseSmall](#ReleaseSmall)
optimization modes. Safety checks can also be enabled or disabled on a
per-block basis, overriding the default for the current optimization
mode, using [\@setRuntimeSafety](#setRuntimeSafety). When safety checks
are disabled, Safety-Checked Illegal Behavior behaves like Unchecked
Illegal Behavior; that is, any behavior may result from invoking it.

When a safety check fails, Zig\'s default panic handler crashes with a
stack trace, like this:

<figure>
<pre><code>test &quot;safety check&quot; {
    unreachable;
}</code></pre>
<figcaption>test_illegal_behavior.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_illegal_behavior.zig
1/1 test_illegal_behavior.test.safety check...thread 210560 panic: reached unreachable code
/home/andy/src/zig/doc/langref/test_illegal_behavior.zig:2:5: 0x1048948 in test.safety check (test)
    unreachable;
    ^
/home/andy/src/zig/lib/compiler/test_runner.zig:214:25: 0x10eed75 in mainTerminal (test)
        if (test_fn.func()) |_| {
                        ^
/home/andy/src/zig/lib/compiler/test_runner.zig:62:28: 0x10e730d in main (test)
        return mainTerminal();
                           ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10e6892 in posixCallMainAndExit (test)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10e646d in _start (test)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
error: the following test command crashed:
/home/andy/src/zig/.zig-cache/o/ad5fcf79fd9ccd7e0493595fe81df80a/test --seed=0x4cb0f272</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Reaching Unreachable Code](#toc-Reaching-Unreachable-Code) [§](#Reaching-Unreachable-Code){.hdr} {#Reaching-Unreachable-Code}

At compile-time:

<figure>
<pre><code>comptime {
    assert(false);
}
fn assert(ok: bool) void {
    if (!ok) unreachable; // assertion failure
}</code></pre>
<figcaption>test_comptime_reaching_unreachable.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_reaching_unreachable.zig
doc/langref/test_comptime_reaching_unreachable.zig:5:14: error: reached unreachable code
    if (!ok) unreachable; // assertion failure
             ^~~~~~~~~~~
doc/langref/test_comptime_reaching_unreachable.zig:2:11: note: called from here
    assert(false);
    ~~~~~~^~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    std.debug.assert(false);
}</code></pre>
<figcaption>runtime_reaching_unreachable.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_reaching_unreachable.zig
$ ./runtime_reaching_unreachable
thread 217396 panic: reached unreachable code
/home/andy/src/zig/lib/std/debug.zig:522:14: 0x1048a9d in assert (runtime_reaching_unreachable)
    if (!ok) unreachable; // assertion failure
             ^
/home/andy/src/zig/doc/langref/runtime_reaching_unreachable.zig:4:21: 0x10de72a in main (runtime_reaching_unreachable)
    std.debug.assert(false);
                    ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de232 in posixCallMainAndExit (runtime_reaching_unreachable)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10dde0d in _start (runtime_reaching_unreachable)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Index out of Bounds](#toc-Index-out-of-Bounds) [§](#Index-out-of-Bounds){.hdr} {#Index-out-of-Bounds}

At compile-time:

<figure>
<pre><code>comptime {
    const array: [5]u8 = &quot;hello&quot;.*;
    const garbage = array[5];
    _ = garbage;
}</code></pre>
<figcaption>test_comptime_index_out_of_bounds.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_index_out_of_bounds.zig
doc/langref/test_comptime_index_out_of_bounds.zig:3:27: error: index 5 outside array of length 5
    const garbage = array[5];
                          ^
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>pub fn main() void {
    const x = foo(&quot;hello&quot;);
    _ = x;
}

fn foo(x: []const u8) u8 {
    return x[5];
}</code></pre>
<figcaption>runtime_index_out_of_bounds.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_index_out_of_bounds.zig
$ ./runtime_index_out_of_bounds
thread 219134 panic: index out of bounds: index 5, len 5
/home/andy/src/zig/doc/langref/runtime_index_out_of_bounds.zig:7:13: 0x10df001 in foo (runtime_index_out_of_bounds)
    return x[5];
            ^
/home/andy/src/zig/doc/langref/runtime_index_out_of_bounds.zig:2:18: 0x10de766 in main (runtime_index_out_of_bounds)
    const x = foo(&quot;hello&quot;);
                 ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de262 in posixCallMainAndExit (runtime_index_out_of_bounds)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10dde3d in _start (runtime_index_out_of_bounds)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Cast Negative Number to Unsigned Integer](#toc-Cast-Negative-Number-to-Unsigned-Integer) [§](#Cast-Negative-Number-to-Unsigned-Integer){.hdr} {#Cast-Negative-Number-to-Unsigned-Integer}

At compile-time:

<figure>
<pre><code>comptime {
    const value: i32 = -1;
    const unsigned: u32 = @intCast(value);
    _ = unsigned;
}</code></pre>
<figcaption>test_comptime_invalid_cast.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_invalid_cast.zig
doc/langref/test_comptime_invalid_cast.zig:3:36: error: type &#39;u32&#39; cannot represent integer value &#39;-1&#39;
    const unsigned: u32 = @intCast(value);
                                   ^~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    var value: i32 = -1; // runtime-known
    _ = &amp;value;
    const unsigned: u32 = @intCast(value);
    std.debug.print(&quot;value: {}\n&quot;, .{unsigned});
}</code></pre>
<figcaption>runtime_invalid_cast.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_invalid_cast.zig
$ ./runtime_invalid_cast
thread 212398 panic: attempt to cast negative value to unsigned integer
/home/andy/src/zig/doc/langref/runtime_invalid_cast.zig:6:27: 0x10de866 in main (runtime_invalid_cast)
    const unsigned: u32 = @intCast(value);
                          ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de352 in posixCallMainAndExit (runtime_invalid_cast)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddf2d in _start (runtime_invalid_cast)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

To obtain the maximum value of an unsigned integer, use
`std.math.maxInt`.

### [Cast Truncates Data](#toc-Cast-Truncates-Data) [§](#Cast-Truncates-Data){.hdr} {#Cast-Truncates-Data}

At compile-time:

<figure>
<pre><code>comptime {
    const spartan_count: u16 = 300;
    const byte: u8 = @intCast(spartan_count);
    _ = byte;
}</code></pre>
<figcaption>test_comptime_invalid_cast_truncate.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_invalid_cast_truncate.zig
doc/langref/test_comptime_invalid_cast_truncate.zig:3:31: error: type &#39;u8&#39; cannot represent integer value &#39;300&#39;
    const byte: u8 = @intCast(spartan_count);
                              ^~~~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    var spartan_count: u16 = 300; // runtime-known
    _ = &amp;spartan_count;
    const byte: u8 = @intCast(spartan_count);
    std.debug.print(&quot;value: {}\n&quot;, .{byte});
}</code></pre>
<figcaption>runtime_invalid_cast_truncate.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_invalid_cast_truncate.zig
$ ./runtime_invalid_cast_truncate
thread 212601 panic: integer cast truncated bits
/home/andy/src/zig/doc/langref/runtime_invalid_cast_truncate.zig:6:22: 0x10de8f8 in main (runtime_invalid_cast_truncate)
    const byte: u8 = @intCast(spartan_count);
                     ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de3e2 in posixCallMainAndExit (runtime_invalid_cast_truncate)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddfbd in _start (runtime_invalid_cast_truncate)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

To truncate bits, use [\@truncate](#truncate).

### [Integer Overflow](#toc-Integer-Overflow) [§](#Integer-Overflow){.hdr} {#Integer-Overflow}

#### [Default Operations](#toc-Default-Operations) [§](#Default-Operations){.hdr} {#Default-Operations}

The following operators can cause integer overflow:

- `+` (addition)
- `-` (subtraction)
- `-` (negation)
- `*` (multiplication)
- `/` (division)
- [\@divTrunc](#divTrunc) (division)
- [\@divFloor](#divFloor) (division)
- [\@divExact](#divExact) (division)

Example with addition at compile-time:

<figure>
<pre><code>comptime {
    var byte: u8 = 255;
    byte += 1;
}</code></pre>
<figcaption>test_comptime_overflow.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_overflow.zig
doc/langref/test_comptime_overflow.zig:3:10: error: overflow of integer type &#39;u8&#39; with value &#39;256&#39;
    byte += 1;
    ~~~~~^~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    var byte: u8 = 255;
    byte += 1;
    std.debug.print(&quot;value: {}\n&quot;, .{byte});
}</code></pre>
<figcaption>runtime_overflow.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_overflow.zig
$ ./runtime_overflow
thread 217657 panic: integer overflow
/home/andy/src/zig/doc/langref/runtime_overflow.zig:5:10: 0x10de8f9 in main (runtime_overflow)
    byte += 1;
         ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de3e2 in posixCallMainAndExit (runtime_overflow)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddfbd in _start (runtime_overflow)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Standard Library Math Functions](#toc-Standard-Library-Math-Functions) [§](#Standard-Library-Math-Functions){.hdr} {#Standard-Library-Math-Functions}

These functions provided by the standard library return possible errors.

- [`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.add`
- [`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.sub`
- [`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.mul`
- [`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.divTrunc`
- [`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.divFloor`
- [`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.divExact`
- [`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.shl`

Example of catching an overflow for addition:

<figure>
<pre><code>const math = @import(&quot;std&quot;).math;
const print = @import(&quot;std&quot;).debug.print;
pub fn main() !void {
    var byte: u8 = 255;

    byte = if (math.add(u8, byte, 1)) |result| result else |err| {
        print(&quot;unable to add one: {s}\n&quot;, .{@errorName(err)});
        return err;
    };

    print(&quot;result: {}\n&quot;, .{byte});
}</code></pre>
<figcaption>math_add.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe math_add.zig
$ ./math_add
unable to add one: Overflow
error: Overflow
/home/andy/src/zig/lib/std/math.zig:565:21: 0x10dea25 in add__anon_24023 (math_add)
    if (ov[1] != 0) return error.Overflow;
                    ^
/home/andy/src/zig/doc/langref/math_add.zig:8:9: 0x10de9bb in main (math_add)
        return err;
        ^</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Builtin Overflow Functions](#toc-Builtin-Overflow-Functions) [§](#Builtin-Overflow-Functions){.hdr} {#Builtin-Overflow-Functions}

These builtins return a tuple containing whether there was an overflow
(as a [`u1`]{.tok-type}) and the possibly overflowed bits of the
operation:

- [\@addWithOverflow](#addWithOverflow)
- [\@subWithOverflow](#subWithOverflow)
- [\@mulWithOverflow](#mulWithOverflow)
- [\@shlWithOverflow](#shlWithOverflow)

Example of [\@addWithOverflow](#addWithOverflow):

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;
pub fn main() void {
    const byte: u8 = 255;

    const ov = @addWithOverflow(byte, 10);
    if (ov[1] != 0) {
        print(&quot;overflowed result: {}\n&quot;, .{ov[0]});
    } else {
        print(&quot;result: {}\n&quot;, .{ov[0]});
    }
}</code></pre>
<figcaption>addWithOverflow_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe addWithOverflow_builtin.zig
$ ./addWithOverflow_builtin
overflowed result: 9</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Wrapping Operations](#toc-Wrapping-Operations) [§](#Wrapping-Operations){.hdr} {#Wrapping-Operations}

These operations have guaranteed wraparound semantics.

- `+%` (wraparound addition)
- `-%` (wraparound subtraction)
- `-%` (wraparound negation)
- `*%` (wraparound multiplication)

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;
const minInt = std.math.minInt;
const maxInt = std.math.maxInt;

test &quot;wraparound addition and subtraction&quot; {
    const x: i32 = maxInt(i32);
    const min_val = x +% 1;
    try expect(min_val == minInt(i32));
    const max_val = min_val -% 1;
    try expect(max_val == maxInt(i32));
}</code></pre>
<figcaption>test_wraparound_semantics.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_wraparound_semantics.zig
1/1 test_wraparound_semantics.test.wraparound addition and subtraction...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Exact Left Shift Overflow](#toc-Exact-Left-Shift-Overflow) [§](#Exact-Left-Shift-Overflow){.hdr} {#Exact-Left-Shift-Overflow}

At compile-time:

<figure>
<pre><code>comptime {
    const x = @shlExact(@as(u8, 0b01010101), 2);
    _ = x;
}</code></pre>
<figcaption>test_comptime_shlExact_overwlow.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_shlExact_overwlow.zig
doc/langref/test_comptime_shlExact_overwlow.zig:2:15: error: operation caused overflow
    const x = @shlExact(@as(u8, 0b01010101), 2);
              ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    var x: u8 = 0b01010101; // runtime-known
    _ = &amp;x;
    const y = @shlExact(x, 2);
    std.debug.print(&quot;value: {}\n&quot;, .{y});
}</code></pre>
<figcaption>runtime_shlExact_overflow.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_shlExact_overflow.zig
$ ./runtime_shlExact_overflow
thread 222268 panic: left shift overflowed bits
/home/andy/src/zig/doc/langref/runtime_shlExact_overflow.zig:6:5: 0x10de981 in main (runtime_shlExact_overflow)
    const y = @shlExact(x, 2);
    ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de442 in posixCallMainAndExit (runtime_shlExact_overflow)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10de01d in _start (runtime_shlExact_overflow)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Exact Right Shift Overflow](#toc-Exact-Right-Shift-Overflow) [§](#Exact-Right-Shift-Overflow){.hdr} {#Exact-Right-Shift-Overflow}

At compile-time:

<figure>
<pre><code>comptime {
    const x = @shrExact(@as(u8, 0b10101010), 2);
    _ = x;
}</code></pre>
<figcaption>test_comptime_shrExact_overflow.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_shrExact_overflow.zig
doc/langref/test_comptime_shrExact_overflow.zig:2:15: error: exact shift shifted out 1 bits
    const x = @shrExact(@as(u8, 0b10101010), 2);
              ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    var x: u8 = 0b10101010; // runtime-known
    _ = &amp;x;
    const y = @shrExact(x, 2);
    std.debug.print(&quot;value: {}\n&quot;, .{y});
}</code></pre>
<figcaption>runtime_shrExact_overflow.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_shrExact_overflow.zig
$ ./runtime_shrExact_overflow
thread 215275 panic: right shift overflowed bits
/home/andy/src/zig/doc/langref/runtime_shrExact_overflow.zig:6:5: 0x10de97d in main (runtime_shrExact_overflow)
    const y = @shrExact(x, 2);
    ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de442 in posixCallMainAndExit (runtime_shrExact_overflow)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10de01d in _start (runtime_shrExact_overflow)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Division by Zero](#toc-Division-by-Zero) [§](#Division-by-Zero){.hdr} {#Division-by-Zero}

At compile-time:

<figure>
<pre><code>comptime {
    const a: i32 = 1;
    const b: i32 = 0;
    const c = a / b;
    _ = c;
}</code></pre>
<figcaption>test_comptime_division_by_zero.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_division_by_zero.zig
doc/langref/test_comptime_division_by_zero.zig:4:19: error: division by zero here causes undefined behavior
    const c = a / b;
                  ^
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    var a: u32 = 1;
    var b: u32 = 0;
    _ = .{ &amp;a, &amp;b };
    const c = a / b;
    std.debug.print(&quot;value: {}\n&quot;, .{c});
}</code></pre>
<figcaption>runtime_division_by_zero.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_division_by_zero.zig
$ ./runtime_division_by_zero
thread 213940 panic: division by zero
/home/andy/src/zig/doc/langref/runtime_division_by_zero.zig:7:17: 0x10de89a in main (runtime_division_by_zero)
    const c = a / b;
                ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de352 in posixCallMainAndExit (runtime_division_by_zero)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddf2d in _start (runtime_division_by_zero)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Remainder Division by Zero](#toc-Remainder-Division-by-Zero) [§](#Remainder-Division-by-Zero){.hdr} {#Remainder-Division-by-Zero}

At compile-time:

<figure>
<pre><code>comptime {
    const a: i32 = 10;
    const b: i32 = 0;
    const c = a % b;
    _ = c;
}</code></pre>
<figcaption>test_comptime_remainder_division_by_zero.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_remainder_division_by_zero.zig
doc/langref/test_comptime_remainder_division_by_zero.zig:4:19: error: division by zero here causes undefined behavior
    const c = a % b;
                  ^
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    var a: u32 = 10;
    var b: u32 = 0;
    _ = .{ &amp;a, &amp;b };
    const c = a % b;
    std.debug.print(&quot;value: {}\n&quot;, .{c});
}</code></pre>
<figcaption>runtime_remainder_division_by_zero.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_remainder_division_by_zero.zig
$ ./runtime_remainder_division_by_zero
thread 209979 panic: division by zero
/home/andy/src/zig/doc/langref/runtime_remainder_division_by_zero.zig:7:17: 0x10de89a in main (runtime_remainder_division_by_zero)
    const c = a % b;
                ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de352 in posixCallMainAndExit (runtime_remainder_division_by_zero)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddf2d in _start (runtime_remainder_division_by_zero)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Exact Division Remainder](#toc-Exact-Division-Remainder) [§](#Exact-Division-Remainder){.hdr} {#Exact-Division-Remainder}

At compile-time:

<figure>
<pre><code>comptime {
    const a: u32 = 10;
    const b: u32 = 3;
    const c = @divExact(a, b);
    _ = c;
}</code></pre>
<figcaption>test_comptime_divExact_remainder.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_divExact_remainder.zig
doc/langref/test_comptime_divExact_remainder.zig:4:15: error: exact division produced remainder
    const c = @divExact(a, b);
              ^~~~~~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    var a: u32 = 10;
    var b: u32 = 3;
    _ = .{ &amp;a, &amp;b };
    const c = @divExact(a, b);
    std.debug.print(&quot;value: {}\n&quot;, .{c});
}</code></pre>
<figcaption>runtime_divExact_remainder.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_divExact_remainder.zig
$ ./runtime_divExact_remainder
thread 212495 panic: exact division produced remainder
/home/andy/src/zig/doc/langref/runtime_divExact_remainder.zig:7:15: 0x10de8bb in main (runtime_divExact_remainder)
    const c = @divExact(a, b);
              ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de352 in posixCallMainAndExit (runtime_divExact_remainder)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddf2d in _start (runtime_divExact_remainder)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Attempt to Unwrap Null](#toc-Attempt-to-Unwrap-Null) [§](#Attempt-to-Unwrap-Null){.hdr} {#Attempt-to-Unwrap-Null}

At compile-time:

<figure>
<pre><code>comptime {
    const optional_number: ?i32 = null;
    const number = optional_number.?;
    _ = number;
}</code></pre>
<figcaption>test_comptime_unwrap_null.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_unwrap_null.zig
doc/langref/test_comptime_unwrap_null.zig:3:35: error: unable to unwrap null
    const number = optional_number.?;
                   ~~~~~~~~~~~~~~~^~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    var optional_number: ?i32 = null;
    _ = &amp;optional_number;
    const number = optional_number.?;
    std.debug.print(&quot;value: {}\n&quot;, .{number});
}</code></pre>
<figcaption>runtime_unwrap_null.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_unwrap_null.zig
$ ./runtime_unwrap_null
thread 212451 panic: attempt to use null value
/home/andy/src/zig/doc/langref/runtime_unwrap_null.zig:6:35: 0x10de886 in main (runtime_unwrap_null)
    const number = optional_number.?;
                                  ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de352 in posixCallMainAndExit (runtime_unwrap_null)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddf2d in _start (runtime_unwrap_null)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

One way to avoid this crash is to test for null instead of assuming
non-null, with the [`if`]{.tok-kw} expression:

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;
pub fn main() void {
    const optional_number: ?i32 = null;

    if (optional_number) |number| {
        print(&quot;got number: {}\n&quot;, .{number});
    } else {
        print(&quot;it&#39;s null\n&quot;, .{});
    }
}</code></pre>
<figcaption>testing_null_with_if.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe testing_null_with_if.zig
$ ./testing_null_with_if
it&#39;s null</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Optionals](#Optionals)

### [Attempt to Unwrap Error](#toc-Attempt-to-Unwrap-Error) [§](#Attempt-to-Unwrap-Error){.hdr} {#Attempt-to-Unwrap-Error}

At compile-time:

<figure>
<pre><code>comptime {
    const number = getNumberOrFail() catch unreachable;
    _ = number;
}

fn getNumberOrFail() !i32 {
    return error.UnableToReturnNumber;
}</code></pre>
<figcaption>test_comptime_unwrap_error.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_unwrap_error.zig
doc/langref/test_comptime_unwrap_error.zig:2:44: error: caught unexpected error &#39;UnableToReturnNumber&#39;
    const number = getNumberOrFail() catch unreachable;
                                           ^~~~~~~~~~~
doc/langref/test_comptime_unwrap_error.zig:7:18: note: error returned here
    return error.UnableToReturnNumber;
                 ^~~~~~~~~~~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    const number = getNumberOrFail() catch unreachable;
    std.debug.print(&quot;value: {}\n&quot;, .{number});
}

fn getNumberOrFail() !i32 {
    return error.UnableToReturnNumber;
}</code></pre>
<figcaption>runtime_unwrap_error.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_unwrap_error.zig
$ ./runtime_unwrap_error
thread 214943 panic: attempt to unwrap error: UnableToReturnNumber
/home/andy/src/zig/doc/langref/runtime_unwrap_error.zig:9:5: 0x10df16f in getNumberOrFail (runtime_unwrap_error)
    return error.UnableToReturnNumber;
    ^
/home/andy/src/zig/doc/langref/runtime_unwrap_error.zig:4:44: 0x10de901 in main (runtime_unwrap_error)
    const number = getNumberOrFail() catch unreachable;
                                           ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de3c2 in posixCallMainAndExit (runtime_unwrap_error)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddf9d in _start (runtime_unwrap_error)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

One way to avoid this crash is to test for an error instead of assuming
a successful result, with the [`if`]{.tok-kw} expression:

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

pub fn main() void {
    const result = getNumberOrFail();

    if (result) |number| {
        print(&quot;got number: {}\n&quot;, .{number});
    } else |err| {
        print(&quot;got error: {s}\n&quot;, .{@errorName(err)});
    }
}

fn getNumberOrFail() !i32 {
    return error.UnableToReturnNumber;
}</code></pre>
<figcaption>testing_error_with_if.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe testing_error_with_if.zig
$ ./testing_error_with_if
got error: UnableToReturnNumber</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Errors](#Errors)

### [Invalid Error Code](#toc-Invalid-Error-Code) [§](#Invalid-Error-Code){.hdr} {#Invalid-Error-Code}

At compile-time:

<figure>
<pre><code>comptime {
    const err = error.AnError;
    const number = @intFromError(err) + 10;
    const invalid_err = @errorFromInt(number);
    _ = invalid_err;
}</code></pre>
<figcaption>test_comptime_invalid_error_code.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_invalid_error_code.zig
doc/langref/test_comptime_invalid_error_code.zig:4:39: error: integer value &#39;11&#39; represents no error
    const invalid_err = @errorFromInt(number);
                                      ^~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    const err = error.AnError;
    var number = @intFromError(err) + 500;
    _ = &amp;number;
    const invalid_err = @errorFromInt(number);
    std.debug.print(&quot;value: {}\n&quot;, .{invalid_err});
}</code></pre>
<figcaption>runtime_invalid_error_code.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_invalid_error_code.zig
$ ./runtime_invalid_error_code
thread 222506 panic: invalid error code
/home/andy/src/zig/doc/langref/runtime_invalid_error_code.zig:7:5: 0x10de916 in main (runtime_invalid_error_code)
    const invalid_err = @errorFromInt(number);
    ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de3b2 in posixCallMainAndExit (runtime_invalid_error_code)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddf8d in _start (runtime_invalid_error_code)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Invalid Enum Cast](#toc-Invalid-Enum-Cast) [§](#Invalid-Enum-Cast){.hdr} {#Invalid-Enum-Cast}

At compile-time:

<figure>
<pre><code>const Foo = enum {
    a,
    b,
    c,
};
comptime {
    const a: u2 = 3;
    const b: Foo = @enumFromInt(a);
    _ = b;
}</code></pre>
<figcaption>test_comptime_invalid_enum_cast.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_invalid_enum_cast.zig
doc/langref/test_comptime_invalid_enum_cast.zig:8:20: error: enum &#39;test_comptime_invalid_enum_cast.Foo&#39; has no tag with value &#39;3&#39;
    const b: Foo = @enumFromInt(a);
                   ^~~~~~~~~~~~~~~
doc/langref/test_comptime_invalid_enum_cast.zig:1:13: note: enum declared here
const Foo = enum {
            ^~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

const Foo = enum {
    a,
    b,
    c,
};

pub fn main() void {
    var a: u2 = 3;
    _ = &amp;a;
    const b: Foo = @enumFromInt(a);
    std.debug.print(&quot;value: {s}\n&quot;, .{@tagName(b)});
}</code></pre>
<figcaption>runtime_invalid_enum_cast.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_invalid_enum_cast.zig
$ ./runtime_invalid_enum_cast
thread 220434 panic: invalid enum value
/home/andy/src/zig/doc/langref/runtime_invalid_enum_cast.zig:12:20: 0x10de8da in main (runtime_invalid_enum_cast)
    const b: Foo = @enumFromInt(a);
                   ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de3c2 in posixCallMainAndExit (runtime_invalid_enum_cast)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddf9d in _start (runtime_invalid_enum_cast)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Invalid Error Set Cast](#toc-Invalid-Error-Set-Cast) [§](#Invalid-Error-Set-Cast){.hdr} {#Invalid-Error-Set-Cast}

At compile-time:

<figure>
<pre><code>const Set1 = error{
    A,
    B,
};
const Set2 = error{
    A,
    C,
};
comptime {
    _ = @as(Set2, @errorCast(Set1.B));
}</code></pre>
<figcaption>test_comptime_invalid_error_set_cast.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_invalid_error_set_cast.zig
doc/langref/test_comptime_invalid_error_set_cast.zig:10:19: error: &#39;error.B&#39; not a member of error set &#39;error{A,C}&#39;
    _ = @as(Set2, @errorCast(Set1.B));
                  ^~~~~~~~~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

const Set1 = error{
    A,
    B,
};
const Set2 = error{
    A,
    C,
};
pub fn main() void {
    foo(Set1.B);
}
fn foo(set1: Set1) void {
    const x: Set2 = @errorCast(set1);
    std.debug.print(&quot;value: {}\n&quot;, .{x});
}</code></pre>
<figcaption>runtime_invalid_error_set_cast.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_invalid_error_set_cast.zig
$ ./runtime_invalid_error_set_cast
thread 217676 panic: invalid error code
/home/andy/src/zig/doc/langref/runtime_invalid_error_set_cast.zig:15:21: 0x10df1cd in foo (runtime_invalid_error_set_cast)
    const x: Set2 = @errorCast(set1);
                    ^
/home/andy/src/zig/doc/langref/runtime_invalid_error_set_cast.zig:12:8: 0x10de8fc in main (runtime_invalid_error_set_cast)
    foo(Set1.B);
       ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de3f2 in posixCallMainAndExit (runtime_invalid_error_set_cast)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddfcd in _start (runtime_invalid_error_set_cast)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Incorrect Pointer Alignment](#toc-Incorrect-Pointer-Alignment) [§](#Incorrect-Pointer-Alignment){.hdr} {#Incorrect-Pointer-Alignment}

At compile-time:

<figure>
<pre><code>comptime {
    const ptr: *align(1) i32 = @ptrFromInt(0x1);
    const aligned: *align(4) i32 = @alignCast(ptr);
    _ = aligned;
}</code></pre>
<figcaption>test_comptime_incorrect_pointer_alignment.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_incorrect_pointer_alignment.zig
doc/langref/test_comptime_incorrect_pointer_alignment.zig:3:47: error: pointer address 0x1 is not aligned to 4 bytes
    const aligned: *align(4) i32 = @alignCast(ptr);
                                              ^~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const mem = @import(&quot;std&quot;).mem;
pub fn main() !void {
    var array align(4) = [_]u32{ 0x11111111, 0x11111111 };
    const bytes = mem.sliceAsBytes(array[0..]);
    if (foo(bytes) != 0x11111111) return error.Wrong;
}
fn foo(bytes: []u8) u32 {
    const slice4 = bytes[1..5];
    const int_slice = mem.bytesAsSlice(u32, @as([]align(4) u8, @alignCast(slice4)));
    return int_slice[0];
}</code></pre>
<figcaption>runtime_incorrect_pointer_alignment.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_incorrect_pointer_alignment.zig
$ ./runtime_incorrect_pointer_alignment
thread 222554 panic: incorrect alignment
/home/andy/src/zig/doc/langref/runtime_incorrect_pointer_alignment.zig:9:64: 0x10de7c2 in foo (runtime_incorrect_pointer_alignment)
    const int_slice = mem.bytesAsSlice(u32, @as([]align(4) u8, @alignCast(slice4)));
                                                               ^
/home/andy/src/zig/doc/langref/runtime_incorrect_pointer_alignment.zig:5:12: 0x10de6bf in main (runtime_incorrect_pointer_alignment)
    if (foo(bytes) != 0x11111111) return error.Wrong;
           ^
/home/andy/src/zig/lib/std/start.zig:656:37: 0x10de5aa in posixCallMainAndExit (runtime_incorrect_pointer_alignment)
            const result = root.main() catch |err| {
                                    ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10de15d in _start (runtime_incorrect_pointer_alignment)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Wrong Union Field Access](#toc-Wrong-Union-Field-Access) [§](#Wrong-Union-Field-Access){.hdr} {#Wrong-Union-Field-Access}

At compile-time:

<figure>
<pre><code>comptime {
    var f = Foo{ .int = 42 };
    f.float = 12.34;
}

const Foo = union {
    float: f32,
    int: u32,
};</code></pre>
<figcaption>test_comptime_wrong_union_field_access.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_wrong_union_field_access.zig
doc/langref/test_comptime_wrong_union_field_access.zig:3:6: error: access of union field &#39;float&#39; while field &#39;int&#39; is active
    f.float = 12.34;
    ~^~~~~~
doc/langref/test_comptime_wrong_union_field_access.zig:6:13: note: union declared here
const Foo = union {
            ^~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

const Foo = union {
    float: f32,
    int: u32,
};

pub fn main() void {
    var f = Foo{ .int = 42 };
    bar(&amp;f);
}

fn bar(f: *Foo) void {
    f.float = 12.34;
    std.debug.print(&quot;value: {}\n&quot;, .{f.float});
}</code></pre>
<figcaption>runtime_wrong_union_field_access.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_wrong_union_field_access.zig
$ ./runtime_wrong_union_field_access
thread 215740 panic: access of union field &#39;float&#39; while field &#39;int&#39; is active
/home/andy/src/zig/doc/langref/runtime_wrong_union_field_access.zig:14:6: 0x10e49e8 in bar (runtime_wrong_union_field_access)
    f.float = 12.34;
     ^
/home/andy/src/zig/doc/langref/runtime_wrong_union_field_access.zig:10:8: 0x10e413c in main (runtime_wrong_union_field_access)
    bar(&amp;f);
       ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10e3c32 in posixCallMainAndExit (runtime_wrong_union_field_access)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10e380d in _start (runtime_wrong_union_field_access)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

This safety is not available for [`extern`]{.tok-kw} or
[`packed`]{.tok-kw} unions.

To change the active field of a union, assign the entire union, like
this:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

const Foo = union {
    float: f32,
    int: u32,
};

pub fn main() void {
    var f = Foo{ .int = 42 };
    bar(&amp;f);
}

fn bar(f: *Foo) void {
    f.* = Foo{ .float = 12.34 };
    std.debug.print(&quot;value: {}\n&quot;, .{f.float});
}</code></pre>
<figcaption>change_active_union_field.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe change_active_union_field.zig
$ ./change_active_union_field
value: 1.234e1</code></pre>
<figcaption>Shell</figcaption>
</figure>

To change the active field of a union when a meaningful value for the
field is not known, use [undefined](#undefined), like this:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

const Foo = union {
    float: f32,
    int: u32,
};

pub fn main() void {
    var f = Foo{ .int = 42 };
    f = Foo{ .float = undefined };
    bar(&amp;f);
    std.debug.print(&quot;value: {}\n&quot;, .{f.float});
}

fn bar(f: *Foo) void {
    f.float = 12.34;
}</code></pre>
<figcaption>undefined_active_union_field.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe undefined_active_union_field.zig
$ ./undefined_active_union_field
value: 1.234e1</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [union](#union)
- [extern union](#extern-union)

### [Out of Bounds Float to Integer Cast](#toc-Out-of-Bounds-Float-to-Integer-Cast) [§](#Out-of-Bounds-Float-to-Integer-Cast){.hdr} {#Out-of-Bounds-Float-to-Integer-Cast}

This happens when casting a float to an integer where the float has a
value outside the integer type\'s range.

At compile-time:

<figure>
<pre><code>comptime {
    const float: f32 = 4294967296;
    const int: i32 = @intFromFloat(float);
    _ = int;
}</code></pre>
<figcaption>test_comptime_out_of_bounds_float_to_integer_cast.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_out_of_bounds_float_to_integer_cast.zig
doc/langref/test_comptime_out_of_bounds_float_to_integer_cast.zig:3:36: error: float value &#39;4294967296&#39; cannot be stored in integer type &#39;i32&#39;
    const int: i32 = @intFromFloat(float);
                                   ^~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>pub fn main() void {
    var float: f32 = 4294967296; // runtime-known
    _ = &amp;float;
    const int: i32 = @intFromFloat(float);
    _ = int;
}</code></pre>
<figcaption>runtime_out_of_bounds_float_to_integer_cast.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_out_of_bounds_float_to_integer_cast.zig
$ ./runtime_out_of_bounds_float_to_integer_cast
thread 215812 panic: integer part of floating point value out of bounds
/home/andy/src/zig/doc/langref/runtime_out_of_bounds_float_to_integer_cast.zig:4:22: 0x10de7a9 in main (runtime_out_of_bounds_float_to_integer_cast)
    const int: i32 = @intFromFloat(float);
                     ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de252 in posixCallMainAndExit (runtime_out_of_bounds_float_to_integer_cast)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10dde2d in _start (runtime_out_of_bounds_float_to_integer_cast)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Pointer Cast Invalid Null](#toc-Pointer-Cast-Invalid-Null) [§](#Pointer-Cast-Invalid-Null){.hdr} {#Pointer-Cast-Invalid-Null}

This happens when casting a pointer with the address 0 to a pointer
which may not have the address 0. For example, [C
Pointers](#C-Pointers), [Optional Pointers](#Optional-Pointers), and
[allowzero](#allowzero) pointers allow address zero, but normal
[Pointers](#Pointers) do not.

At compile-time:

<figure>
<pre><code>comptime {
    const opt_ptr: ?*i32 = null;
    const ptr: *i32 = @ptrCast(opt_ptr);
    _ = ptr;
}</code></pre>
<figcaption>test_comptime_invalid_null_pointer_cast.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_invalid_null_pointer_cast.zig
doc/langref/test_comptime_invalid_null_pointer_cast.zig:3:32: error: null pointer casted to type &#39;*i32&#39;
    const ptr: *i32 = @ptrCast(opt_ptr);
                               ^~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At runtime:

<figure>
<pre><code>pub fn main() void {
    var opt_ptr: ?*i32 = null;
    _ = &amp;opt_ptr;
    const ptr: *i32 = @ptrCast(opt_ptr);
    _ = ptr;
}</code></pre>
<figcaption>runtime_invalid_null_pointer_cast.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe runtime_invalid_null_pointer_cast.zig
$ ./runtime_invalid_null_pointer_cast
thread 214922 panic: cast causes pointer to be null
/home/andy/src/zig/doc/langref/runtime_invalid_null_pointer_cast.zig:4:23: 0x10de75c in main (runtime_invalid_null_pointer_cast)
    const ptr: *i32 = @ptrCast(opt_ptr);
                      ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de232 in posixCallMainAndExit (runtime_invalid_null_pointer_cast)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10dde0d in _start (runtime_invalid_null_pointer_cast)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [Memory](#toc-Memory) [§](#Memory){.hdr} {#Memory}

The Zig language performs no memory management on behalf of the
programmer. This is why Zig has no runtime, and why Zig code works
seamlessly in so many environments, including real-time software,
operating system kernels, embedded devices, and low latency servers. As
a consequence, Zig programmers must always be able to answer the
question:

[Where are the bytes?](#Where-are-the-bytes)

Like Zig, the C programming language has manual memory management.
However, unlike Zig, C has a default allocator - `malloc`, `realloc`,
and `free`. When linking against libc, Zig exposes this allocator with
`std.heap.c_allocator`. However, by convention, there is no default
allocator in Zig. Instead, functions which need to allocate accept an
`Allocator` parameter. Likewise, data structures such as `std.ArrayList`
accept an `Allocator` parameter in their initialization functions:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const Allocator = std.mem.Allocator;
const expect = std.testing.expect;

test &quot;using an allocator&quot; {
    var buffer: [100]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&amp;buffer);
    const allocator = fba.allocator();
    const result = try concat(allocator, &quot;foo&quot;, &quot;bar&quot;);
    try expect(std.mem.eql(u8, &quot;foobar&quot;, result));
}

fn concat(allocator: Allocator, a: []const u8, b: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, a.len + b.len);
    @memcpy(result[0..a.len], a);
    @memcpy(result[a.len..], b);
    return result;
}</code></pre>
<figcaption>test_allocator.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_allocator.zig
1/1 test_allocator.test.using an allocator...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

In the above example, 100 bytes of stack memory are used to initialize a
`FixedBufferAllocator`, which is then passed to a function. As a
convenience there is a global `FixedBufferAllocator` available for quick
tests at `std.testing.allocator`, which will also perform basic leak
detection.

Zig has a general purpose allocator available to be imported with
`std.heap.GeneralPurposeAllocator`. However, it is still recommended to
follow the [Choosing an Allocator](#Choosing-an-Allocator) guide.

### [Choosing an Allocator](#toc-Choosing-an-Allocator) [§](#Choosing-an-Allocator){.hdr} {#Choosing-an-Allocator}

What allocator to use depends on a number of factors. Here is a flow
chart to help you decide:

1.  Are you making a library? In this case, best to accept an
    `Allocator` as a parameter and allow your library\'s users to decide
    what allocator to use.
2.  Are you linking libc? In this case, `std.heap.c_allocator` is likely
    the right choice, at least for your main allocator.
3.  Need to use the same allocator in multiple threads? Use one of your
    choice wrapped around `std.heap.ThreadSafeAllocator`
4.  Is the maximum number of bytes that you will need bounded by a
    number known at [comptime](#comptime)? In this case, use
    `std.heap.FixedBufferAllocator`.
5.  Is your program a command line application which runs from start to
    end without any fundamental cyclical pattern (such as a video game
    main loop, or a web server request handler), such that it would make
    sense to free everything at once at the end? In this case, it is
    recommended to follow this pattern:
    <figure>
    <pre><code>const std = @import(&quot;std&quot;);

    pub fn main() !void {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();

        const allocator = arena.allocator();

        const ptr = try allocator.create(i32);
        std.debug.print(&quot;ptr={*}\n&quot;, .{ptr});
    }</code></pre>
    <figcaption>cli_allocation.zig</figcaption>
    </figure>

    <figure>
    <pre><code>$ zig build-exe cli_allocation.zig
    $ ./cli_allocation
    ptr=i32@7f23d195f010</code></pre>
    <figcaption>Shell</figcaption>
    </figure>

    When using this kind of allocator, there is no need to free anything
    manually. Everything gets freed at once with the call to
    `arena.deinit()`.
6.  Are the allocations part of a cyclical pattern such as a video game
    main loop, or a web server request handler? If the allocations can
    all be freed at once, at the end of the cycle, for example once the
    video game frame has been fully rendered, or the web server request
    has been served, then `std.heap.ArenaAllocator` is a great
    candidate. As demonstrated in the previous bullet point, this allows
    you to free entire arenas at once. Note also that if an upper bound
    of memory can be established, then `std.heap.FixedBufferAllocator`
    can be used as a further optimization.
7.  Are you writing a test, and you want to make sure
    [`error`]{.tok-kw}`.OutOfMemory` is handled correctly? In this case,
    use `std.testing.FailingAllocator`.
8.  Are you writing a test? In this case, use `std.testing.allocator`.
9.  Finally, if none of the above apply, you need a general purpose
    allocator. Zig\'s general purpose allocator is available as a
    function that takes a [comptime](#comptime) [struct](#struct) of
    configuration options and returns a type. Generally, you will set up
    one `std.heap.GeneralPurposeAllocator` in your main function, and
    then pass it or sub-allocators around to various parts of your
    application.
10. You can also consider [Implementing an
    Allocator](#Implementing-an-Allocator).

### [Where are the bytes?](#toc-Where-are-the-bytes) [§](#Where-are-the-bytes){.hdr} {#Where-are-the-bytes}

String literals such as [`"hello"`]{.tok-str} are in the global constant
data section. This is why it is an error to pass a string literal to a
mutable slice, like this:

<figure>
<pre><code>fn foo(s: []u8) void {
    _ = s;
}

test &quot;string literal to mutable slice&quot; {
    foo(&quot;hello&quot;);
}</code></pre>
<figcaption>test_string_literal_to_slice.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_string_literal_to_slice.zig
doc/langref/test_string_literal_to_slice.zig:6:9: error: expected type &#39;[]u8&#39;, found &#39;*const [5:0]u8&#39;
    foo(&quot;hello&quot;);
        ^~~~~~~
doc/langref/test_string_literal_to_slice.zig:6:9: note: cast discards const qualifier
doc/langref/test_string_literal_to_slice.zig:1:11: note: parameter type declared here
fn foo(s: []u8) void {
          ^~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

However if you make the slice constant, then it works:

<figure>
<pre><code>fn foo(s: []const u8) void {
    _ = s;
}

test &quot;string literal to constant slice&quot; {
    foo(&quot;hello&quot;);
}</code></pre>
<figcaption>test_string_literal_to_const_slice.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_string_literal_to_const_slice.zig
1/1 test_string_literal_to_const_slice.test.string literal to constant slice...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Just like string literals, [`const`]{.tok-kw} declarations, when the
value is known at [comptime](#comptime), are stored in the global
constant data section. Also [Compile Time
Variables](#Compile-Time-Variables) are stored in the global constant
data section.

[`var`]{.tok-kw} declarations inside functions are stored in the
function\'s stack frame. Once a function returns, any
[Pointers](#Pointers) to variables in the function\'s stack frame become
invalid references, and dereferencing them becomes unchecked [Illegal
Behavior](#Illegal-Behavior).

[`var`]{.tok-kw} declarations at the top level or in [struct](#struct)
declarations are stored in the global data section.

The location of memory allocated with `allocator.alloc` or
`allocator.create` is determined by the allocator\'s implementation.

TODO: thread local variables

### [Implementing an Allocator](#toc-Implementing-an-Allocator) [§](#Implementing-an-Allocator){.hdr} {#Implementing-an-Allocator}

Zig programmers can implement their own allocators by fulfilling the
Allocator interface. In order to do this one must read carefully the
documentation comments in std/mem.zig and then supply a `allocFn` and a
`resizeFn`.

There are many example allocators to look at for inspiration. Look at
std/heap.zig and `std.heap.GeneralPurposeAllocator`.

### [Heap Allocation Failure](#toc-Heap-Allocation-Failure) [§](#Heap-Allocation-Failure){.hdr} {#Heap-Allocation-Failure}

Many programming languages choose to handle the possibility of heap
allocation failure by unconditionally crashing. By convention, Zig
programmers do not consider this to be a satisfactory solution. Instead,
[`error`]{.tok-kw}`.OutOfMemory` represents heap allocation failure, and
Zig libraries return this error code whenever heap allocation failure
prevented an operation from completing successfully.

Some have argued that because some operating systems such as Linux have
memory overcommit enabled by default, it is pointless to handle heap
allocation failure. There are many problems with this reasoning:

- Only some operating systems have an overcommit feature.
  - Linux has it enabled by default, but it is configurable.
  - Windows does not overcommit.
  - Embedded systems do not have overcommit.
  - Hobby operating systems may or may not have overcommit.
- For real-time systems, not only is there no overcommit, but typically
  the maximum amount of memory per application is determined ahead of
  time.
- When writing a library, one of the main goals is code reuse. By making
  code handle allocation failure correctly, a library becomes eligible
  to be reused in more contexts.
- Although some software has grown to depend on overcommit being
  enabled, its existence is the source of countless user experience
  disasters. When a system with overcommit enabled, such as Linux on
  default settings, comes close to memory exhaustion, the system locks
  up and becomes unusable. At this point, the OOM Killer selects an
  application to kill based on heuristics. This non-deterministic
  decision often results in an important process being killed, and often
  fails to return the system back to working order.

### [Recursion](#toc-Recursion) [§](#Recursion){.hdr} {#Recursion}

Recursion is a fundamental tool in modeling software. However it has an
often-overlooked problem: unbounded memory allocation.

Recursion is an area of active experimentation in Zig and so the
documentation here is not final. You can read a [summary of recursion
status in the 0.3.0 release
notes](https://ziglang.org/download/0.3.0/release-notes.html#recursion).

The short summary is that currently recursion works normally as you
would expect. Although Zig code is not yet protected from stack
overflow, it is planned that a future version of Zig will provide such
protection, with some degree of cooperation from Zig code required.

### [Lifetime and Ownership](#toc-Lifetime-and-Ownership) [§](#Lifetime-and-Ownership){.hdr} {#Lifetime-and-Ownership}

It is the Zig programmer\'s responsibility to ensure that a
[pointer](#Pointers) is not accessed when the memory pointed to is no
longer available. Note that a [slice](#Slices) is a form of pointer, in
that it references other memory.

In order to prevent bugs, there are some helpful conventions to follow
when dealing with pointers. In general, when a function returns a
pointer, the documentation for the function should explain who \"owns\"
the pointer. This concept helps the programmer decide when it is
appropriate, if ever, to free the pointer.

For example, the function\'s documentation may say \"caller owns the
returned memory\", in which case the code that calls the function must
have a plan for when to free that memory. Probably in this situation,
the function will accept an `Allocator` parameter.

Sometimes the lifetime of a pointer may be more complicated. For
example, the `std.ArrayList(T).items` slice has a lifetime that remains
valid until the next time the list is resized, such as by appending new
elements.

The API documentation for functions and data structures should take
great care to explain the ownership and lifetime semantics of pointers.
Ownership determines whose responsibility it is to free the memory
referenced by the pointer, and lifetime determines the point at which
the memory becomes inaccessible (lest [Illegal
Behavior](#Illegal-Behavior) occur).

## [Compile Variables](#toc-Compile-Variables) [§](#Compile-Variables){.hdr} {#Compile-Variables}

Compile variables are accessible by importing the
[`"builtin"`]{.tok-str} package, which the compiler makes available to
every Zig source file. It contains compile-time constants such as the
current target, endianness, and release mode.

<figure>
<pre><code>const builtin = @import(&quot;builtin&quot;);
const separator = if (builtin.os.tag == .windows) &#39;\\&#39; else &#39;/&#39;;</code></pre>
<figcaption>compile_variables.zig</figcaption>
</figure>

Example of what is imported with
[`@import`]{.tok-builtin}`(`[`"builtin"`]{.tok-str}`)`:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
/// Zig version. When writing code that supports multiple versions of Zig, prefer
/// feature detection (i.e. with `@hasDecl` or `@hasField`) over version checks.
pub const zig_version = std.SemanticVersion.parse(zig_version_string) catch unreachable;
pub const zig_version_string = &quot;0.14.0-dev.3451+d8d2aa9af&quot;;
pub const zig_backend = std.builtin.CompilerBackend.stage2_llvm;

pub const output_mode: std.builtin.OutputMode = .Exe;
pub const link_mode: std.builtin.LinkMode = .static;
pub const unwind_tables: std.builtin.UnwindTables = .@&quot;async&quot;;
pub const is_test = false;
pub const single_threaded = false;
pub const abi: std.Target.Abi = .gnu;
pub const cpu: std.Target.Cpu = .{
    .arch = .x86_64,
    .model = &amp;std.Target.x86.cpu.znver4,
    .features = std.Target.x86.featureSet(&amp;.{
        .@&quot;64bit&quot;,
        .adx,
        .aes,
        .allow_light_256_bit,
        .avx,
        .avx2,
        .avx512bf16,
        .avx512bitalg,
        .avx512bw,
        .avx512cd,
        .avx512dq,
        .avx512f,
        .avx512ifma,
        .avx512vbmi,
        .avx512vbmi2,
        .avx512vl,
        .avx512vnni,
        .avx512vpopcntdq,
        .bmi,
        .bmi2,
        .branchfusion,
        .clflushopt,
        .clwb,
        .clzero,
        .cmov,
        .crc32,
        .cx16,
        .cx8,
        .evex512,
        .f16c,
        .fast_15bytenop,
        .fast_bextr,
        .fast_dpwssd,
        .fast_imm16,
        .fast_lzcnt,
        .fast_movbe,
        .fast_scalar_fsqrt,
        .fast_scalar_shift_masks,
        .fast_variable_perlane_shuffle,
        .fast_vector_fsqrt,
        .fma,
        .fsgsbase,
        .fsrm,
        .fxsr,
        .gfni,
        .idivq_to_divl,
        .invpcid,
        .lzcnt,
        .macrofusion,
        .mmx,
        .movbe,
        .mwaitx,
        .nopl,
        .pclmul,
        .pku,
        .popcnt,
        .prfchw,
        .rdpid,
        .rdpru,
        .rdrnd,
        .rdseed,
        .sahf,
        .sbb_dep_breaking,
        .sha,
        .shstk,
        .slow_shld,
        .smap,
        .smep,
        .sse,
        .sse2,
        .sse3,
        .sse4_1,
        .sse4_2,
        .sse4a,
        .ssse3,
        .vaes,
        .vpclmulqdq,
        .vzeroupper,
        .wbnoinvd,
        .x87,
        .xsave,
        .xsavec,
        .xsaveopt,
        .xsaves,
    }),
};
pub const os: std.Target.Os = .{
    .tag = .linux,
    .version_range = .{ .linux = .{
        .range = .{
            .min = .{
                .major = 6,
                .minor = 13,
                .patch = 2,
            },
            .max = .{
                .major = 6,
                .minor = 13,
                .patch = 2,
            },
        },
        .glibc = .{
            .major = 2,
            .minor = 39,
            .patch = 0,
        },
        .android = 14,
    }},
};
pub const target: std.Target = .{
    .cpu = cpu,
    .os = os,
    .abi = abi,
    .ofmt = object_format,
    .dynamic_linker = .init(&quot;/nix/store/nqb2ns2d1lahnd5ncwmn6k84qfd7vx2k-glibc-2.40-36/lib/ld-linux-x86-64.so.2&quot;),
};
pub const object_format: std.Target.ObjectFormat = .elf;
pub const mode: std.builtin.OptimizeMode = .Debug;
pub const link_libc = false;
pub const link_libcpp = false;
pub const have_error_return_tracing = true;
pub const valgrind_support = true;
pub const sanitize_thread = false;
pub const fuzz = false;
pub const position_independent_code = false;
pub const position_independent_executable = false;
pub const strip_debug_info = false;
pub const code_model: std.builtin.CodeModel = .default;
pub const omit_frame_pointer = false;</code></pre>
<figcaption>@import("builtin")</figcaption>
</figure>

See also:

- [Build Mode](#Build-Mode)

## [Compilation Model](#toc-Compilation-Model) [§](#Compilation-Model){.hdr} {#Compilation-Model}

A Zig compilation is separated into *modules*. Each module is a
collection of Zig source files, one of which is the module\'s *root
source file*. Each module can *depend* on any number of other modules,
forming a directed graph (dependency loops between modules are allowed).
If module A depends on module B, then any Zig source file in module A
can import the *root source file* of module B using
[`@import`]{.tok-builtin} with the module\'s name. In essence, a module
acts as an alias to import a Zig source file (which might exist in a
completely separate part of the filesystem).

A simple Zig program compiled with `zig build-exe` has two key modules:
the one containing your code, known as the \"main\" or \"root\" module,
and the standard library. Your module *depends on* the standard library
module under the name \"std\", which is what allows you to write
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`)`! In fact, every
single module in a Zig compilation --- including the standard library
itself --- implicitly depends on the standard library module under the
name \"std\".

The \"root module\" (the one provided by you in the `zig build-exe`
example) has a special property. Like the standard library, it is
implicitly made available to all modules (including itself), this time
under the name \"root\". So,
[`@import`]{.tok-builtin}`(`[`"root"`]{.tok-str}`)` will always be
equivalent to [`@import`]{.tok-builtin} of your \"main\" source file
(often, but not necessarily, named `main.zig`).

### [Source File Structs](#toc-Source-File-Structs) [§](#Source-File-Structs){.hdr} {#Source-File-Structs}

Every Zig source file is implicitly a [`struct`]{.tok-kw} declaration;
you can imagine that the file\'s contents are literally surrounded by
[`struct`]{.tok-kw}` { ... }`. This means that as well as declarations,
the top level of a file is permitted to contain fields:

<figure>
<pre><code>//! Because this file contains fields, it is a type which is intended to be instantiated, and so
//! is named in TitleCase instead of snake_case by convention.

foo: u32,
bar: u64,

/// `@This()` can be used to refer to this struct type. In files with fields, it is quite common to
/// name the type here, so it can be easily referenced by other declarations in this file.
const TopLevelFields = @This();

pub fn init(val: u32) TopLevelFields {
    return .{
        .foo = val,
        .bar = val * 10,
    };
}</code></pre>
<figcaption>TopLevelFields.zig</figcaption>
</figure>

Such files can be instantiated just like any other [`struct`]{.tok-kw}
type. A file\'s \"root struct type\" can be referred to within that file
using [\@This](#This).

### [File and Declaration Discovery](#toc-File-and-Declaration-Discovery) [§](#File-and-Declaration-Discovery){.hdr} {#File-and-Declaration-Discovery}

Zig places importance on the concept of whether any piece of code is
*semantically analyzed*; in essence, whether the compiler \"looks at\"
it. What code is analyzed is based on what files and declarations are
\"discovered\" from a certain point. This process of \"discovery\" is
based on a simple set of recursive rules:

- If a call to [`@import`]{.tok-builtin} is analyzed, the file being
  imported is analyzed.
- If a type (including a file) is analyzed, all [`comptime`]{.tok-kw},
  [`usingnamespace`]{.tok-kw}, and [`export`]{.tok-kw} declarations
  within it are analyzed.
- If a type (including a file) is analyzed, and the compilation is for a
  [test](#Zig-Test), and the module the type is within is the root
  module of the compilation, then all [`test`]{.tok-kw} declarations
  within it are also analyzed.
- If a reference to a named declaration (i.e. a usage of it) is
  analyzed, the declaration being referenced is analyzed. Declarations
  are order-independent, so this reference may be above or below the
  declaration being referenced, or even in another file entirely.

That\'s it! Those rules define how Zig files and declarations are
discovered. All that remains is to understand where this process
*starts*.

The answer to that is the root of the standard library: every Zig
compilation begins by analyzing the file `lib/std/std.zig`. This file
contains a [`comptime`]{.tok-kw} declaration which imports
`lib/std/start.zig`, and that file in turn uses
[`@import`]{.tok-builtin}`(`[`"root"`]{.tok-str}`)` to reference the
\"root module\"; so, the file you provide as your main module\'s root
source file is effectively also a root, because the standard library
will always reference it.

It is often desirable to make sure that certain declarations ---
particularly [`test`]{.tok-kw} or [`export`]{.tok-kw} declarations ---
are discovered. Based on the above rules, a common strategy for this is
to use [`@import`]{.tok-builtin} within a [`comptime`]{.tok-kw} or
[`test`]{.tok-kw} block:

<figure>
<pre><code>comptime {
    // This will ensure that the file &#39;api.zig&#39; is always discovered (as long as this file is discovered).
    // It is useful if &#39;api.zig&#39; contains important exported declarations.
    _ = @import(&quot;api.zig&quot;);

    // We could also have a file which contains declarations we only want to export depending on a comptime
    // condition. In that case, we can use an `if` statement here:
    if (builtin.os.tag == .windows) {
        _ = @import(&quot;windows_api.zig&quot;);
    }
}

test {
    // This will ensure that the file &#39;tests.zig&#39; is always discovered (as long as this file is discovered),
    // if this compilation is a test. It is useful if &#39;tests.zig&#39; contains tests we want to ensure are run.
    _ = @import(&quot;tests.zig&quot;);

    // We could also have a file which contains tests we only want to run depending on a comptime condition.
    // In that case, we can use an `if` statement here:
    if (builtin.os.tag == .windows) {
        _ = @import(&quot;windows_tests.zig&quot;);
    }
}

const builtin = @import(&quot;builtin&quot;);</code></pre>
<figcaption>force_file_discovery.zig</figcaption>
</figure>

### [Special Root Declarations](#toc-Special-Root-Declarations) [§](#Special-Root-Declarations){.hdr} {#Special-Root-Declarations}

Because the root module\'s root source file is always accessible using
[`@import`]{.tok-builtin}`(`[`"root"`]{.tok-str}`)`, is is sometimes
used by libraries --- including the Zig Standard Library --- as a place
for the program to expose some \"global\" information to that library.
The Zig Standard Library will look for several declarations in this
file.

#### [Entry Point](#toc-Entry-Point) [§](#Entry-Point){.hdr} {#Entry-Point}

When building an executable, the most important thing to be looked up in
this file is the program\'s *entry point*. Most commonly, this is a
function named `main`, which `std.start` will call just after performing
important initialization work.

Alternatively, the presence of a declaration named `_start` (for
instance, [`pub`]{.tok-kw}` `[`const`]{.tok-kw}` _start = {};`) will
disable the default `std.start` logic, allowing your root source file to
export a low-level entry point as needed.

<figure>
<pre><code>/// `std.start` imports this file using `@import(&quot;root&quot;)`, and uses this declaration as the program&#39;s
/// user-provided entry point. It can return any of the following types:
/// * `void`
/// * `E!void`, for any error set `E`
/// * `u8`
/// * `E!u8`, for any error set `E`
/// Returning a `void` value from this function will exit with code 0.
/// Returning a `u8` value from this function will exit with the given status code.
/// Returning an error value from this function will print an Error Return Trace and exit with code 1.
pub fn main() void {
    std.debug.print(&quot;Hello, World!\n&quot;, .{});
}

// If uncommented, this declaration would suppress the usual std.start logic, causing
// the `main` declaration above to be ignored.
//pub const _start = {};

const std = @import(&quot;std&quot;);</code></pre>
<figcaption>entry_point.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe entry_point.zig
$ ./entry_point
Hello, World!</code></pre>
<figcaption>Shell</figcaption>
</figure>

If the Zig compilation links libc, the `main` function can optionally be
an [`export`]{.tok-kw}` `[`fn`]{.tok-kw} which matches the signature of
the C `main` function:

<figure>
<pre><code>pub export fn main(argc: c_int, argv: [*]const [*:0]const u8) c_int {
    const args = argv[0..@intCast(argc)];
    std.debug.print(&quot;Hello! argv[0] is &#39;{s}&#39;\n&quot;, .{args[0]});
    return 0;
}

const std = @import(&quot;std&quot;);</code></pre>
<figcaption>libc_export_entry_point.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe libc_export_entry_point.zig -lc
$ ./libc_export_entry_point
Hello! argv[0] is &#39;./libc_export_entry_point&#39;</code></pre>
<figcaption>Shell</figcaption>
</figure>

`std.start` may also use other entry point declarations in certain
situations, such as `wWinMain` or `EfiMain`. Refer to the
`lib/std/start.zig` logic for details of these declarations.

#### [Standard Library Options](#toc-Standard-Library-Options) [§](#Standard-Library-Options){.hdr} {#Standard-Library-Options}

The standard library also looks for a declaration in the root module\'s
root source file named `std_options`. If present, this declaration is
expected to be a struct of type `std.Options`, and allows the program to
customize some standard library functionality, such as the `std.log`
implementation.

<figure>
<pre><code>/// The presence of this declaration allows the program to override certain behaviors of the standard library.
/// For a full list of available options, see the documentation for `std.Options`.
pub const std_options: std.Options = .{
    // By default, in safe build modes, the standard library will attach a segfault handler to the program to
    // print a helpful stack trace if a segmentation fault occurs. Here, we can disable this, or even enable
    // it in unsafe build modes.
    .enable_segfault_handler = true,
    // This is the logging function used by `std.log`.
    .logFn = myLogFn,
};

fn myLogFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    // We could do anything we want here!
    // ...but actually, let&#39;s just call the default implementation.
    std.log.defaultLog(level, scope, format, args);
}

const std = @import(&quot;std&quot;);</code></pre>
<figcaption>std_options.zig</figcaption>
</figure>

#### [Panic Handler](#toc-Panic-Handler) [§](#Panic-Handler){.hdr} {#Panic-Handler}

The Zig Standard Library looks for a declaration named `panic` in the
root module\'s root source file. If present, it is expected to be a
namespace (container type) with declarations providing different panic
handlers.

See `std.debug.simple_panic` for a basic implementation of this
namespace.

Overriding how the panic handler actually outputs messages, but keeping
the formatted safety panics which are enabled by default, can be easily
achieved with `std.debug.FullPanic`:

<figure>
<pre><code>pub fn main() void {
    @setRuntimeSafety(true);
    var x: u8 = 255;
    // Let&#39;s overflow this integer!
    x += 1;
}

pub const panic = std.debug.FullPanic(myPanic);

fn myPanic(msg: []const u8, first_trace_addr: ?usize) noreturn {
    _ = first_trace_addr;
    std.debug.print(&quot;Panic! {s}\n&quot;, .{msg});
    std.process.exit(1);
}

const std = @import(&quot;std&quot;);</code></pre>
<figcaption>panic_handler.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe panic_handler.zig
$ ./panic_handler
Panic! integer overflow</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [Zig Build System](#toc-Zig-Build-System) [§](#Zig-Build-System){.hdr} {#Zig-Build-System}

The Zig Build System provides a cross-platform, dependency-free way to
declare the logic required to build a project. With this system, the
logic to build a project is written in a build.zig file, using the Zig
Build System API to declare and configure build artifacts and other
tasks.

Some examples of tasks the build system can help with:

- Performing tasks in parallel and caching the results.
- Depending on other projects.
- Providing a package for other projects to depend on.
- Creating build artifacts by executing the Zig compiler. This includes
  building Zig source code as well as C and C++ source code.
- Capturing user-configured options and using those options to configure
  the build.
- Surfacing build configuration as [comptime](#comptime) values by
  providing a file that can be [imported](#import) by Zig code.
- Caching build artifacts to avoid unnecessarily repeating steps.
- Executing build artifacts or system-installed tools.
- Running tests and verifying the output of executing a build artifact
  matches the expected value.
- Running `zig fmt` on a codebase or a subset of it.
- Custom tasks.

To use the build system, run [zig build \--help]{.kbd} to see a
command-line usage help menu. This will include project-specific options
that were declared in the build.zig script.

For the time being, the build system documentation is hosted externally:
[Build System Documentation](https://ziglang.org/learn/build-system/)

## [C](#toc-C) [§](#C){.hdr} {#C}

Although Zig is independent of C, and, unlike most other languages, does
not depend on libc, Zig acknowledges the importance of interacting with
existing C code.

There are a few ways that Zig facilitates C interop.

### [C Type Primitives](#toc-C-Type-Primitives) [§](#C-Type-Primitives){.hdr} {#C-Type-Primitives}

These have guaranteed C ABI compatibility and can be used like any other
type.

- [`c_char`]{.tok-type}
- [`c_short`]{.tok-type}
- [`c_ushort`]{.tok-type}
- [`c_int`]{.tok-type}
- [`c_uint`]{.tok-type}
- [`c_long`]{.tok-type}
- [`c_ulong`]{.tok-type}
- [`c_longlong`]{.tok-type}
- [`c_ulonglong`]{.tok-type}
- [`c_longdouble`]{.tok-type}

To interop with the C [`void`]{.tok-type} type, use
[`anyopaque`]{.tok-type}.

See also:

- [Primitive Types](#Primitive-Types)

### [Import from C Header File](#toc-Import-from-C-Header-File) [§](#Import-from-C-Header-File){.hdr} {#Import-from-C-Header-File}

The [`@cImport`]{.tok-builtin} builtin function can be used to directly
import symbols from `.h`{.file} files:

<figure>
<pre><code>const c = @cImport({
    // See https://github.com/ziglang/zig/issues/515
    @cDefine(&quot;_NO_CRT_STDIO_INLINE&quot;, &quot;1&quot;);
    @cInclude(&quot;stdio.h&quot;);
});
pub fn main() void {
    _ = c.printf(&quot;hello\n&quot;);
}</code></pre>
<figcaption>cImport_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe cImport_builtin.zig -lc
$ ./cImport_builtin
hello</code></pre>
<figcaption>Shell</figcaption>
</figure>

The [`@cImport`]{.tok-builtin} function takes an expression as a
parameter. This expression is evaluated at compile-time and is used to
control preprocessor directives and include multiple `.h`{.file} files:

<figure>
<pre><code>const builtin = @import(&quot;builtin&quot;);

const c = @cImport({
    @cDefine(&quot;NDEBUG&quot;, builtin.mode == .ReleaseFast);
    if (something) {
        @cDefine(&quot;_GNU_SOURCE&quot;, {});
    }
    @cInclude(&quot;stdlib.h&quot;);
    if (something) {
        @cUndef(&quot;_GNU_SOURCE&quot;);
    }
    @cInclude(&quot;soundio.h&quot;);
});</code></pre>
<figcaption>@cImport Expression</figcaption>
</figure>

See also:

- [\@cImport](#cImport)
- [\@cInclude](#cInclude)
- [\@cDefine](#cDefine)
- [\@cUndef](#cUndef)
- [\@import](#import)

### [C Translation CLI](#toc-C-Translation-CLI) [§](#C-Translation-CLI){.hdr} {#C-Translation-CLI}

Zig\'s C translation capability is available as a CLI tool via [zig
translate-c]{.kbd}. It requires a single filename as an argument. It may
also take a set of optional flags that are forwarded to clang. It writes
the translated file to stdout.

#### [Command line flags](#toc-Command-line-flags) [§](#Command-line-flags){.hdr} {#Command-line-flags}

- [-I]{.kbd}: Specify a search directory for include files. May be used
  multiple times. Equivalent to [clang\'s [-I]{.kbd}
  flag](https://releases.llvm.org/12.0.0/tools/clang/docs/ClangCommandLineReference.html#cmdoption-clang-i-dir).
  The current directory is *not* included by default; use [-I.]{.kbd} to
  include it.
- [-D]{.kbd}: Define a preprocessor macro. Equivalent to [clang\'s
  [-D]{.kbd}
  flag](https://releases.llvm.org/12.0.0/tools/clang/docs/ClangCommandLineReference.html#cmdoption-clang-d-macro).
- [-cflags \[flags\] \--]{.kbd}: Pass arbitrary additional [command line
  flags](https://releases.llvm.org/12.0.0/tools/clang/docs/ClangCommandLineReference.html)
  to clang. Note: the list of flags must end with [\--]{.kbd}
- [-target]{.kbd}: The [target triple](#Targets) for the translated Zig
  code. If no target is specified, the current host target will be used.

#### [Using -target and -cflags](#toc-Using--target-and--cflags) [§](#Using--target-and--cflags){.hdr} {#Using--target-and--cflags}

**Important!** When translating C code with [zig translate-c]{.kbd}, you
**must** use the same [-target]{.kbd} triple that you will use when
compiling the translated code. In addition, you **must** ensure that the
[-cflags]{.kbd} used, if any, match the cflags used by code on the
target system. Using the incorrect [-target]{.kbd} or [-cflags]{.kbd}
could result in clang or Zig parse failures, or subtle ABI
incompatibilities when linking with C code.

<figure>
<pre><code>long FOO = __LONG_MAX__;</code></pre>
<figcaption>varytarget.h</figcaption>
</figure>

<figure>
<pre><code>$ zig translate-c -target thumb-freestanding-gnueabihf varytarget.h|grep FOO
pub export var FOO: c_long = 2147483647;
$ zig translate-c -target x86_64-macos-gnu varytarget.h|grep FOO
pub export var FOO: c_long = 9223372036854775807;</code></pre>
<figcaption>Shell</figcaption>
</figure>

<figure>
<pre><code>enum FOO { BAR };
int do_something(enum FOO foo);</code></pre>
<figcaption>varycflags.h</figcaption>
</figure>

<figure>
<pre><code>$ zig translate-c varycflags.h|grep -B1 do_something
pub const enum_FOO = c_uint;
pub extern fn do_something(foo: enum_FOO) c_int;
$ zig translate-c -cflags -fshort-enums -- varycflags.h|grep -B1 do_something
pub const enum_FOO = u8;
pub extern fn do_something(foo: enum_FOO) c_int;</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [\@cImport vs translate-c](#toc-cImport-vs-translate-c) [§](#cImport-vs-translate-c){.hdr} {#cImport-vs-translate-c}

[`@cImport`]{.tok-builtin} and [zig translate-c]{.kbd} use the same
underlying C translation functionality, so on a technical level they are
equivalent. In practice, [`@cImport`]{.tok-builtin} is useful as a way
to quickly and easily access numeric constants, typedefs, and record
types without needing any extra setup. If you need to pass
[cflags](#Using--target-and--cflags) to clang, or if you would like to
edit the translated code, it is recommended to use [zig
translate-c]{.kbd} and save the results to a file. Common reasons for
editing the generated code include: changing [`anytype`]{.tok-kw}
parameters in function-like macros to more specific types; changing
`[*c]T` pointers to `[*]T` or `*T` pointers for improved type safety;
and [enabling or disabling runtime safety](#setRuntimeSafety) within
specific functions.

See also:

- [Targets](#Targets)
- [C Type Primitives](#C-Type-Primitives)
- [Pointers](#Pointers)
- [C Pointers](#C-Pointers)
- [Import from C Header File](#Import-from-C-Header-File)
- [\@cInclude](#cInclude)
- [\@cImport](#cImport)
- [\@setRuntimeSafety](#setRuntimeSafety)

### [C Translation Caching](#toc-C-Translation-Caching) [§](#C-Translation-Caching){.hdr} {#C-Translation-Caching}

The C translation feature (whether used via [zig translate-c]{.kbd} or
[`@cImport`]{.tok-builtin}) integrates with the Zig caching system.
Subsequent runs with the same source file, target, and cflags will use
the cache instead of repeatedly translating the same code.

To see where the cached files are stored when compiling code that uses
[`@cImport`]{.tok-builtin}, use the [\--verbose-cimport]{.kbd} flag:

<figure>
<pre><code>const c = @cImport({
    @cDefine(&quot;_NO_CRT_STDIO_INLINE&quot;, &quot;1&quot;);
    @cInclude(&quot;stdio.h&quot;);
});
pub fn main() void {
    _ = c;
}</code></pre>
<figcaption>verbose_cimport_flag.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe verbose_cimport_flag.zig -lc --verbose-cimport
info(compilation): C import source: /home/andy/src/zig/.zig-cache/o/d5beb8c0b08d3a28e44bf4f197b53bae/cimport.h
info(compilation): C import .d file: /home/andy/src/zig/.zig-cache/o/d5beb8c0b08d3a28e44bf4f197b53bae/cimport.h.d
$ ./verbose_cimport_flag</code></pre>
<figcaption>Shell</figcaption>
</figure>

`cimport.h`{.file} contains the file to translate (constructed from
calls to [`@cInclude`]{.tok-builtin}, [`@cDefine`]{.tok-builtin}, and
[`@cUndef`]{.tok-builtin}), `cimport.h.d`{.file} is the list of file
dependencies, and `cimport.zig`{.file} contains the translated output.

See also:

- [Import from C Header File](#Import-from-C-Header-File)
- [C Translation CLI](#C-Translation-CLI)
- [\@cInclude](#cInclude)
- [\@cImport](#cImport)

### [Translation failures](#toc-Translation-failures) [§](#Translation-failures){.hdr} {#Translation-failures}

Some C constructs cannot be translated to Zig - for example, *goto*,
structs with bitfields, and token-pasting macros. Zig employs *demotion*
to allow translation to continue in the face of non-translatable
entities.

Demotion comes in three varieties - [opaque](#opaque), *extern*, and
[`@compileError`]{.tok-builtin}. C structs and unions that cannot be
translated correctly will be translated as [`opaque`]{.tok-kw}`{}`.
Functions that contain opaque types or code constructs that cannot be
translated will be demoted to [`extern`]{.tok-kw} declarations. Thus,
non-translatable types can still be used as pointers, and
non-translatable functions can be called so long as the linker is aware
of the compiled function.

[`@compileError`]{.tok-builtin} is used when top-level definitions
(global variables, function prototypes, macros) cannot be translated or
demoted. Since Zig uses lazy analysis for top-level declarations,
untranslatable entities will not cause a compile error in your code
unless you actually use them.

See also:

- [opaque](#opaque)
- [extern](#extern)
- [\@compileError](#compileError)

### [C Macros](#toc-C-Macros) [§](#C-Macros){.hdr} {#C-Macros}

C Translation makes a best-effort attempt to translate function-like
macros into equivalent Zig functions. Since C macros operate at the
level of lexical tokens, not all C macros can be translated to Zig.
Macros that cannot be translated will be demoted to
[`@compileError`]{.tok-builtin}. Note that C code which *uses* macros
will be translated without any additional issues (since Zig operates on
the pre-processed source with macros expanded). It is merely the macros
themselves which may not be translatable to Zig.

Consider the following example:

<figure>
<pre><code>#define MAKELOCAL(NAME, INIT) int NAME = INIT
int foo(void) {
   MAKELOCAL(a, 1);
   MAKELOCAL(b, 2);
   return a + b;
}</code></pre>
<figcaption>macro.c</figcaption>
</figure>

<figure>
<pre><code>$ zig translate-c macro.c &gt; macro.zig</code></pre>
<figcaption>Shell</figcaption>
</figure>

<figure>
<pre><code>pub export fn foo() c_int {
    var a: c_int = 1;
    _ = &amp;a;
    var b: c_int = 2;
    _ = &amp;b;
    return a + b;
}
pub const MAKELOCAL = @compileError(&quot;unable to translate C expr: unexpected token .Equal&quot;); // macro.c:1:9</code></pre>
<figcaption>macro.zig</figcaption>
</figure>

Note that `foo` was translated correctly despite using a
non-translatable macro. `MAKELOCAL` was demoted to
[`@compileError`]{.tok-builtin} since it cannot be expressed as a Zig
function; this simply means that you cannot directly use `MAKELOCAL`
from Zig.

See also:

- [\@compileError](#compileError)

### [C Pointers](#toc-C-Pointers) [§](#C-Pointers){.hdr} {#C-Pointers}

This type is to be avoided whenever possible. The only valid reason for
using a C pointer is in auto-generated code from translating C code.

When importing C header files, it is ambi```
