```
 try expect(fancy_array[4].y == 8);
}

// call a function to initialize an array
var more_points = [_]Point{makePoint(3)} ** 10;
fn makePoint(x: i32) Point {
    return Point{
        .x = x,
        .y = x * 2,
    };
}
test &quot;array initialization with function calls&quot; {
    try expect(more_points[4].x == 3);
    try expect(more_points[4].y == 6);
    try expect(more_points.len == 10);
}</code></pre>
<figcaption>test_arrays.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_arrays.zig
1/4 test_arrays.test.iterate over an array...OK
2/4 test_arrays.test.modify an array...OK
3/4 test_arrays.test.compile-time array initialization...OK
4/4 test_arrays.test.array initialization with function calls...OK
All 4 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [for](#for)
- [Slices](#Slices)

### [Multidimensional Arrays](#toc-Multidimensional-Arrays) [§](#Multidimensional-Arrays){.hdr} {#Multidimensional-Arrays}

Multidimensional arrays can be created by nesting arrays:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const mat4x4 = [4][4]f32{
    [_]f32{ 1.0, 0.0, 0.0, 0.0 },
    [_]f32{ 0.0, 1.0, 0.0, 1.0 },
    [_]f32{ 0.0, 0.0, 1.0, 0.0 },
    [_]f32{ 0.0, 0.0, 0.0, 1.0 },
};
test &quot;multidimensional arrays&quot; {
    // Access the 2D array by indexing the outer array, and then the inner array.
    try expect(mat4x4[1][1] == 1.0);

    // Here we iterate with for loops.
    for (mat4x4, 0..) |row, row_index| {
        for (row, 0..) |cell, column_index| {
            if (row_index == column_index) {
                try expect(cell == 1.0);
            }
        }
    }

    // initialize a multidimensional array to zeros
    const all_zero: [4][4]f32 = .{.{0} ** 4} ** 4;
    try expect(all_zero[0][0] == 0);
}</code></pre>
<figcaption>test_multidimensional_arrays.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_multidimensional_arrays.zig
1/1 test_multidimensional_arrays.test.multidimensional arrays...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Sentinel-Terminated Arrays](#toc-Sentinel-Terminated-Arrays) [§](#Sentinel-Terminated-Arrays){.hdr} {#Sentinel-Terminated-Arrays}

The syntax `[N:x]T` describes an array which has a sentinel element of
value `x` at the index corresponding to the length `N`.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;0-terminated sentinel array&quot; {
    const array = [_:0]u8{ 1, 2, 3, 4 };

    try expect(@TypeOf(array) == [4:0]u8);
    try expect(array.len == 4);
    try expect(array[4] == 0);
}

test &quot;extra 0s in 0-terminated sentinel array&quot; {
    // The sentinel value may appear earlier, but does not influence the compile-time &#39;len&#39;.
    const array = [_:0]u8{ 1, 0, 0, 4 };

    try expect(@TypeOf(array) == [4:0]u8);
    try expect(array.len == 4);
    try expect(array[4] == 0);
}</code></pre>
<figcaption>test_null_terminated_array.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_null_terminated_array.zig
1/2 test_null_terminated_array.test.0-terminated sentinel array...OK
2/2 test_null_terminated_array.test.extra 0s in 0-terminated sentinel array...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Sentinel-Terminated Pointers](#Sentinel-Terminated-Pointers)
- [Sentinel-Terminated Slices](#Sentinel-Terminated-Slices)

### [Destructuring Arrays](#toc-Destructuring-Arrays) [§](#Destructuring-Arrays){.hdr} {#Destructuring-Arrays}

Arrays can be destructured:

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

fn swizzleRgbaToBgra(rgba: [4]u8) [4]u8 {
    // readable swizzling by destructuring
    const r, const g, const b, const a = rgba;
    return .{ b, g, r, a };
}

pub fn main() void {
    const pos = [_]i32{ 1, 2 };
    const x, const y = pos;
    print(&quot;x = {}, y = {}\n&quot;, .{x, y});

    const orange: [4]u8 = .{ 255, 165, 0, 255 };
    print(&quot;{any}\n&quot;, .{swizzleRgbaToBgra(orange)});
}</code></pre>
<figcaption>destructuring_arrays.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe destructuring_arrays.zig
$ ./destructuring_arrays
x = 1, y = 2
{ 0, 165, 255, 255 }</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Destructuring](#Destructuring)
- [Destructuring Tuples](#Destructuring-Tuples)
- [Destructuring Vectors](#Destructuring-Vectors)

## [Vectors](#toc-Vectors) [§](#Vectors){.hdr} {#Vectors}

A vector is a group of booleans, [Integers](#Integers),
[Floats](#Floats), or [Pointers](#Pointers) which are operated on in
parallel, using SIMD instructions if possible. Vector types are created
with the builtin function [\@Vector](#Vector).

Vectors support the same builtin operators as their underlying base
types. These operations are performed element-wise, and return a vector
of the same length as the input vectors. This includes:

- Arithmetic (`+`, `-`, `/`, `*`, [`@divFloor`]{.tok-builtin},
  [`@sqrt`]{.tok-builtin}, [`@ceil`]{.tok-builtin},
  [`@log`]{.tok-builtin}, etc.)
- Bitwise operators (`>>`, `<<`, `&`, `|`, `~`, etc.)
- Comparison operators (`<`, `>`, `==`, etc.)

It is prohibited to use a math operator on a mixture of scalars
(individual numbers) and vectors. Zig provides the [\@splat](#splat)
builtin to easily convert from scalars to vectors, and it supports
[\@reduce](#reduce) and array indexing syntax to convert from vectors to
scalars. Vectors also support assignment to and from fixed-length arrays
with comptime-known length.

For rearranging elements within and between vectors, Zig provides the
[\@shuffle](#shuffle) and [\@select](#select) functions.

Operations on vectors shorter than the target machine\'s native SIMD
size will typically compile to single SIMD instructions, while vectors
longer than the target machine\'s native SIMD size will compile to
multiple SIMD instructions. If a given operation doesn\'t have SIMD
support on the target architecture, the compiler will default to
operating on each vector element one at a time. Zig supports any
comptime-known vector length up to 2\^32-1, although small powers of two
(2-64) are most typical. Note that excessively long vector lengths (e.g.
2\^20) may result in compiler crashes on current versions of Zig.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expectEqual = std.testing.expectEqual;

test &quot;Basic vector usage&quot; {
    // Vectors have a compile-time known length and base type.
    const a = @Vector(4, i32){ 1, 2, 3, 4 };
    const b = @Vector(4, i32){ 5, 6, 7, 8 };

    // Math operations take place element-wise.
    const c = a + b;

    // Individual vector elements can be accessed using array indexing syntax.
    try expectEqual(6, c[0]);
    try expectEqual(8, c[1]);
    try expectEqual(10, c[2]);
    try expectEqual(12, c[3]);
}

test &quot;Conversion between vectors, arrays, and slices&quot; {
    // Vectors and fixed-length arrays can be automatically assigned back and forth
    const arr1: [4]f32 = [_]f32{ 1.1, 3.2, 4.5, 5.6 };
    const vec: @Vector(4, f32) = arr1;
    const arr2: [4]f32 = vec;
    try expectEqual(arr1, arr2);

    // You can also assign from a slice with comptime-known length to a vector using .*
    const vec2: @Vector(2, f32) = arr1[1..3].*;

    const slice: []const f32 = &amp;arr1;
    var offset: u32 = 1; // var to make it runtime-known
    _ = &amp;offset; // suppress &#39;var is never mutated&#39; error
    // To extract a comptime-known length from a runtime-known offset,
    // first extract a new slice from the starting offset, then an array of
    // comptime-known length
    const vec3: @Vector(2, f32) = slice[offset..][0..2].*;
    try expectEqual(slice[offset], vec2[0]);
    try expectEqual(slice[offset + 1], vec2[1]);
    try expectEqual(vec2, vec3);
}</code></pre>
<figcaption>test_vector.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_vector.zig
1/2 test_vector.test.Basic vector usage...OK
2/2 test_vector.test.Conversion between vectors, arrays, and slices...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

TODO talk about C ABI interop\
TODO consider suggesting std.MultiArrayList

See also:

- [\@splat](#splat)
- [\@shuffle](#shuffle)
- [\@select](#select)
- [\@reduce](#reduce)

### [Destructuring Vectors](#toc-Destructuring-Vectors) [§](#Destructuring-Vectors){.hdr} {#Destructuring-Vectors}

Vectors can be destructured:

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

// emulate punpckldq
pub fn unpack(x: @Vector(4, f32), y: @Vector(4, f32)) @Vector(4, f32) {
    const a, const c, _, _ = x;
    const b, const d, _, _ = y;
    return .{ a, b, c, d };
}

pub fn main() void {
    const x: @Vector(4, f32) = .{ 1.0, 2.0, 3.0, 4.0 };
    const y: @Vector(4, f32) = .{ 5.0, 6.0, 7.0, 8.0 };
    print(&quot;{}&quot;, .{unpack(x, y)});
}</code></pre>
<figcaption>destructuring_vectors.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe destructuring_vectors.zig
$ ./destructuring_vectors
{ 1e0, 5e0, 2e0, 6e0 }</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Destructuring](#Destructuring)
- [Destructuring Tuples](#Destructuring-Tuples)
- [Destructuring Arrays](#Destructuring-Arrays)

## [Pointers](#toc-Pointers) [§](#Pointers){.hdr} {#Pointers}

Zig has two kinds of pointers: single-item and many-item.

- `*T` - single-item pointer to exactly one item.
  - Supports deref syntax: `ptr.*`
  - Supports slice syntax:
    `ptr[`[`0`]{.tok-number}`..`[`1`]{.tok-number}`]`
  - Supports pointer subtraction: `ptr - ptr`
- `[*]T` - many-item pointer to unknown number of items.
  - Supports index syntax: `ptr[i]`
  - Supports slice syntax: `ptr[start..end]` and `ptr[start..]`
  - Supports pointer-integer arithmetic: `ptr + int`, `ptr - int`
  - Supports pointer subtraction: `ptr - ptr`

  `T` must have a known size, which means that it cannot be
  [`anyopaque`]{.tok-type} or any other [opaque type](#opaque).

These types are closely related to [Arrays](#Arrays) and
[Slices](#Slices):

- `*[N]T` - pointer to N items, same as single-item pointer to an array.
  - Supports index syntax: `array_ptr[i]`
  - Supports slice syntax: `array_ptr[start..end]`
  - Supports len property: `array_ptr.len`
  - Supports pointer subtraction: `array_ptr - array_ptr`

<!-- -->

- `[]T` - is a slice (a fat pointer, which contains a pointer of type
  `[*]T` and a length).
  - Supports index syntax: `slice[i]`
  - Supports slice syntax: `slice[start..end]`
  - Supports len property: `slice.len`

Use `&x` to obtain a single-item pointer:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;address of syntax&quot; {
    // Get the address of a variable:
    const x: i32 = 1234;
    const x_ptr = &amp;x;

    // Dereference a pointer:
    try expect(x_ptr.* == 1234);

    // When you get the address of a const variable, you get a const single-item pointer.
    try expect(@TypeOf(x_ptr) == *const i32);

    // If you want to mutate the value, you&#39;d need an address of a mutable variable:
    var y: i32 = 5678;
    const y_ptr = &amp;y;
    try expect(@TypeOf(y_ptr) == *i32);
    y_ptr.* += 1;
    try expect(y_ptr.* == 5679);
}

test &quot;pointer array access&quot; {
    // Taking an address of an individual element gives a
    // single-item pointer. This kind of pointer
    // does not support pointer arithmetic.
    var array = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    const ptr = &amp;array[2];
    try expect(@TypeOf(ptr) == *u8);

    try expect(array[2] == 3);
    ptr.* += 1;
    try expect(array[2] == 4);
}

test &quot;slice syntax&quot; {
    // Get a pointer to a variable:
    var x: i32 = 1234;
    const x_ptr = &amp;x;

    // Convert to array pointer using slice syntax:
    const x_array_ptr = x_ptr[0..1];
    try expect(@TypeOf(x_array_ptr) == *[1]i32);

    // Coerce to many-item pointer:
    const x_many_ptr: [*]i32 = x_array_ptr;
    try expect(x_many_ptr[0] == 1234);
}</code></pre>
<figcaption>test_single_item_pointer.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_single_item_pointer.zig
1/3 test_single_item_pointer.test.address of syntax...OK
2/3 test_single_item_pointer.test.pointer array access...OK
3/3 test_single_item_pointer.test.slice syntax...OK
All 3 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Zig supports pointer arithmetic. It\'s better to assign the pointer to
`[*]T` and increment that variable. For example, directly incrementing
the pointer from a slice will corrupt it.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;pointer arithmetic with many-item pointer&quot; {
    const array = [_]i32{ 1, 2, 3, 4 };
    var ptr: [*]const i32 = &amp;array;

    try expect(ptr[0] == 1);
    ptr += 1;
    try expect(ptr[0] == 2);

    // slicing a many-item pointer without an end is equivalent to
    // pointer arithmetic: `ptr[start..] == ptr + start`
    try expect(ptr[1..] == ptr + 1);

    // subtraction between any two pointers except slices based on element size is supported
    try expect(&amp;ptr[1] - &amp;ptr[0] == 1);
}

test &quot;pointer arithmetic with slices&quot; {
    var array = [_]i32{ 1, 2, 3, 4 };
    var length: usize = 0; // var to make it runtime-known
    _ = &amp;length; // suppress &#39;var is never mutated&#39; error
    var slice = array[length..array.len];

    try expect(slice[0] == 1);
    try expect(slice.len == 4);

    slice.ptr += 1;
    // now the slice is in an bad state since len has not been updated

    try expect(slice[0] == 2);
    try expect(slice.len == 4);
}</code></pre>
<figcaption>test_pointer_arithmetic.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_pointer_arithmetic.zig
1/2 test_pointer_arithmetic.test.pointer arithmetic with many-item pointer...OK
2/2 test_pointer_arithmetic.test.pointer arithmetic with slices...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

In Zig, we generally prefer [Slices](#Slices) rather than
[Sentinel-Terminated Pointers](#Sentinel-Terminated-Pointers). You can
turn an array or pointer into a slice using slice syntax.

Slices have bounds checking and are therefore protected against this
kind of Illegal Behavior. This is one reason we prefer slices to
pointers.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;pointer slicing&quot; {
    var array = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    var start: usize = 2; // var to make it runtime-known
    _ = &amp;start; // suppress &#39;var is never mutated&#39; error
    const slice = array[start..4];
    try expect(slice.len == 2);

    try expect(array[3] == 4);
    slice[1] += 1;
    try expect(array[3] == 5);
}</code></pre>
<figcaption>test_slice_bounds.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_slice_bounds.zig
1/1 test_slice_bounds.test.pointer slicing...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Pointers work at compile-time too, as long as the code does not depend
on an undefined memory layout:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;comptime pointers&quot; {
    comptime {
        var x: i32 = 1;
        const ptr = &amp;x;
        ptr.* += 1;
        x += 1;
        try expect(ptr.* == 3);
    }
}</code></pre>
<figcaption>test_comptime_pointers.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_pointers.zig
1/1 test_comptime_pointers.test.comptime pointers...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

To convert an integer address into a pointer, use
[`@ptrFromInt`]{.tok-builtin}. To convert a pointer to an integer, use
[`@intFromPtr`]{.tok-builtin}:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;@intFromPtr and @ptrFromInt&quot; {
    const ptr: *i32 = @ptrFromInt(0xdeadbee0);
    const addr = @intFromPtr(ptr);
    try expect(@TypeOf(addr) == usize);
    try expect(addr == 0xdeadbee0);
}</code></pre>
<figcaption>test_integer_pointer_conversion.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_integer_pointer_conversion.zig
1/1 test_integer_pointer_conversion.test.@intFromPtr and @ptrFromInt...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Zig is able to preserve memory addresses in comptime code, as long as
the pointer is never dereferenced:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;comptime @ptrFromInt&quot; {
    comptime {
        // Zig is able to do this at compile-time, as long as
        // ptr is never dereferenced.
        const ptr: *i32 = @ptrFromInt(0xdeadbee0);
        const addr = @intFromPtr(ptr);
        try expect(@TypeOf(addr) == usize);
        try expect(addr == 0xdeadbee0);
    }
}</code></pre>
<figcaption>test_comptime_pointer_conversion.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_pointer_conversion.zig
1/1 test_comptime_pointer_conversion.test.comptime @ptrFromInt...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

[\@ptrCast](#ptrCast) converts a pointer\'s element type to another.
This creates a new pointer that can cause undetectable Illegal Behavior
depending on the loads and stores that pass through it. Generally, other
kinds of type conversions are preferable to [`@ptrCast`]{.tok-builtin}
if possible.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;pointer casting&quot; {
    const bytes align(@alignOf(u32)) = [_]u8{ 0x12, 0x12, 0x12, 0x12 };
    const u32_ptr: *const u32 = @ptrCast(&amp;bytes);
    try expect(u32_ptr.* == 0x12121212);

    // Even this example is contrived - there are better ways to do the above than
    // pointer casting. For example, using a slice narrowing cast:
    const u32_value = std.mem.bytesAsSlice(u32, bytes[0..])[0];
    try expect(u32_value == 0x12121212);

    // And even another way, the most straightforward way to do it:
    try expect(@as(u32, @bitCast(bytes)) == 0x12121212);
}

test &quot;pointer child type&quot; {
    // pointer types have a `child` field which tells you the type they point to.
    try expect(@typeInfo(*u32).pointer.child == u32);
}</code></pre>
<figcaption>test_pointer_casting.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_pointer_casting.zig
1/2 test_pointer_casting.test.pointer casting...OK
2/2 test_pointer_casting.test.pointer child type...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Optional Pointers](#Optional-Pointers)
- [\@ptrFromInt](#ptrFromInt)
- [\@intFromPtr](#intFromPtr)
- [C Pointers](#C-Pointers)

### [volatile](#toc-volatile) [§](#volatile){.hdr}

Loads and stores are assumed to not have side effects. If a given load
or store should have side effects, such as Memory Mapped Input/Output
(MMIO), use [`volatile`]{.tok-kw}. In the following code, loads and
stores with `mmio_ptr` are guaranteed to all happen and in the same
order as in source code:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;volatile&quot; {
    const mmio_ptr: *volatile u8 = @ptrFromInt(0x12345678);
    try expect(@TypeOf(mmio_ptr) == *volatile u8);
}</code></pre>
<figcaption>test_volatile.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_volatile.zig
1/1 test_volatile.test.volatile...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Note that [`volatile`]{.tok-kw} is unrelated to concurrency and
[Atomics](#Atomics). If you see code that is using [`volatile`]{.tok-kw}
for something other than Memory Mapped Input/Output, it is probably a
bug.

### [Alignment](#toc-Alignment) [§](#Alignment){.hdr} {#Alignment}

Each type has an **alignment** - a number of bytes such that, when a
value of the type is loaded from or stored to memory, the memory address
must be evenly divisible by this number. You can use
[\@alignOf](#alignOf) to find out this value for any type.

Alignment depends on the CPU architecture, but is always a power of two,
and less than [`1`]{.tok-number}` << `[`29`]{.tok-number}.

In Zig, a pointer type has an alignment value. If the value is equal to
the alignment of the underlying type, it can be omitted from the type:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const builtin = @import(&quot;builtin&quot;);
const expect = std.testing.expect;

test &quot;variable alignment&quot; {
    var x: i32 = 1234;
    const align_of_i32 = @alignOf(@TypeOf(x));
    try expect(@TypeOf(&amp;x) == *i32);
    try expect(*i32 == *align(align_of_i32) i32);
    if (builtin.target.cpu.arch == .x86_64) {
        try expect(@typeInfo(*i32).pointer.alignment == 4);
    }
}</code></pre>
<figcaption>test_variable_alignment.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_variable_alignment.zig
1/1 test_variable_alignment.test.variable alignment...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

In the same way that a `*`[`i32`]{.tok-type} can be
[coerced](#Type-Coercion) to a
`*`[`const`]{.tok-kw}` `[`i32`]{.tok-type}, a pointer with a larger
alignment can be implicitly cast to a pointer with a smaller alignment,
but not vice versa.

You can specify alignment on variables and functions. If you do this,
then pointers to them get the specified alignment:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

var foo: u8 align(4) = 100;

test &quot;global variable alignment&quot; {
    try expect(@typeInfo(@TypeOf(&amp;foo)).pointer.alignment == 4);
    try expect(@TypeOf(&amp;foo) == *align(4) u8);
    const as_pointer_to_array: *align(4) [1]u8 = &amp;foo;
    const as_slice: []align(4) u8 = as_pointer_to_array;
    const as_unaligned_slice: []u8 = as_slice;
    try expect(as_unaligned_slice[0] == 100);
}

fn derp() align(@sizeOf(usize) * 2) i32 {
    return 1234;
}
fn noop1() align(1) void {}
fn noop4() align(4) void {}

test &quot;function alignment&quot; {
    try expect(derp() == 1234);
    try expect(@TypeOf(derp) == fn () i32);
    try expect(@TypeOf(&amp;derp) == *align(@sizeOf(usize) * 2) const fn () i32);

    noop1();
    try expect(@TypeOf(noop1) == fn () void);
    try expect(@TypeOf(&amp;noop1) == *align(1) const fn () void);

    noop4();
    try expect(@TypeOf(noop4) == fn () void);
    try expect(@TypeOf(&amp;noop4) == *align(4) const fn () void);
}</code></pre>
<figcaption>test_variable_func_alignment.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_variable_func_alignment.zig
1/2 test_variable_func_alignment.test.global variable alignment...OK
2/2 test_variable_func_alignment.test.function alignment...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

If you have a pointer or a slice that has a small alignment, but you
know that it actually has a bigger alignment, use
[\@alignCast](#alignCast) to change the pointer into a more aligned
pointer. This is a no-op at runtime, but inserts a [safety
check](#Incorrect-Pointer-Alignment):

<figure>
<pre><code>const std = @import(&quot;std&quot;);

test &quot;pointer alignment safety&quot; {
    var array align(4) = [_]u32{ 0x11111111, 0x11111111 };
    const bytes = std.mem.sliceAsBytes(array[0..]);
    try std.testing.expect(foo(bytes) == 0x11111111);
}
fn foo(bytes: []u8) u32 {
    const slice4 = bytes[1..5];
    const int_slice = std.mem.bytesAsSlice(u32, @as([]align(4) u8, @alignCast(slice4)));
    return int_slice[0];
}</code></pre>
<figcaption>test_incorrect_pointer_alignment.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_incorrect_pointer_alignment.zig
1/1 test_incorrect_pointer_alignment.test.pointer alignment safety...thread 211638 panic: incorrect alignment
/home/andy/src/zig/doc/langref/test_incorrect_pointer_alignment.zig:10:68: 0x1048c12 in foo (test)
    const int_slice = std.mem.bytesAsSlice(u32, @as([]align(4) u8, @alignCast(slice4)));
                                                                   ^
/home/andy/src/zig/doc/langref/test_incorrect_pointer_alignment.zig:6:31: 0x1048abf in test.pointer alignment safety (test)
    try std.testing.expect(foo(bytes) == 0x11111111);
                              ^
/home/andy/src/zig/lib/compiler/test_runner.zig:214:25: 0x10ef185 in mainTerminal (test)
        if (test_fn.func()) |_| {
                        ^
/home/andy/src/zig/lib/compiler/test_runner.zig:62:28: 0x10e771d in main (test)
        return mainTerminal();
                           ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10e6ca2 in posixCallMainAndExit (test)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10e687d in _start (test)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
error: the following test command crashed:
/home/andy/src/zig/.zig-cache/o/08ad046baf4e682f3eb12b3ecaa07a72/test --seed=0xaf095082</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [allowzero](#toc-allowzero) [§](#allowzero){.hdr}

This pointer attribute allows a pointer to have address zero. This is
only ever needed on the freestanding OS target, where the address zero
is mappable. If you want to represent null pointers, use [Optional
Pointers](#Optional-Pointers) instead. [Optional
Pointers](#Optional-Pointers) with [`allowzero`]{.tok-kw} are not the
same size as pointers. In this code example, if the pointer did not have
the [`allowzero`]{.tok-kw} attribute, this would be a [Pointer Cast
Invalid Null](#Pointer-Cast-Invalid-Null) panic:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;allowzero&quot; {
    var zero: usize = 0; // var to make to runtime-known
    _ = &amp;zero; // suppress &#39;var is never mutated&#39; error
    const ptr: *allowzero i32 = @ptrFromInt(zero);
    try expect(@intFromPtr(ptr) == 0);
}</code></pre>
<figcaption>test_allowzero.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_allowzero.zig
1/1 test_allowzero.test.allowzero...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Sentinel-Terminated Pointers](#toc-Sentinel-Terminated-Pointers) [§](#Sentinel-Terminated-Pointers){.hdr} {#Sentinel-Terminated-Pointers}

The syntax `[*:x]T` describes a pointer that has a length determined by
a sentinel value. This provides protection against buffer overflow and
overreads.

<figure>
<pre><code>const std = @import(&quot;std&quot;);

// This is also available as `std.c.printf`.
pub extern &quot;c&quot; fn printf(format: [*:0]const u8, ...) c_int;

pub fn main() anyerror!void {
    _ = printf(&quot;Hello, world!\n&quot;); // OK

    const msg = &quot;Hello, world!\n&quot;;
    const non_null_terminated_msg: [msg.len]u8 = msg.*;
    _ = printf(&amp;non_null_terminated_msg);
}</code></pre>
<figcaption>sentinel-terminated_pointer.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe sentinel-terminated_pointer.zig -lc
/home/andy/src/zig/doc/langref/sentinel-terminated_pointer.zig:11:16: error: expected type &#39;[*:0]const u8&#39;, found &#39;*const [14]u8&#39;
    _ = printf(&amp;non_null_terminated_msg);
               ^~~~~~~~~~~~~~~~~~~~~~~~
/home/andy/src/zig/doc/langref/sentinel-terminated_pointer.zig:11:16: note: destination pointer requires &#39;0&#39; sentinel
/home/andy/src/zig/doc/langref/sentinel-terminated_pointer.zig:4:34: note: parameter type declared here
pub extern &quot;c&quot; fn printf(format: [*:0]const u8, ...) c_int;
                                 ^~~~~~~~~~~~~
referenced by:
    main: /home/andy/src/zig/lib/std/start.zig:656:37
    comptime: /home/andy/src/zig/lib/std/start.zig:58:30
    2 reference(s) hidden; use &#39;-freference-trace=4&#39; to see all references
</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Sentinel-Terminated Slices](#Sentinel-Terminated-Slices)
- [Sentinel-Terminated Arrays](#Sentinel-Terminated-Arrays)

## [Slices](#toc-Slices) [§](#Slices){.hdr} {#Slices}

A slice is a pointer and a length. The difference between an array and a
slice is that the array\'s length is part of the type and known at
compile-time, whereas the slice\'s length is known at runtime. Both can
be accessed with the `len` field.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;
const expectEqualSlices = @import(&quot;std&quot;).testing.expectEqualSlices;

test &quot;basic slices&quot; {
    var array = [_]i32{ 1, 2, 3, 4 };
    var known_at_runtime_zero: usize = 0;
    _ = &amp;known_at_runtime_zero;
    const slice = array[known_at_runtime_zero..array.len];

    // alternative initialization using result location
    const alt_slice: []const i32 = &amp;.{ 1, 2, 3, 4 };

    try expectEqualSlices(i32, slice, alt_slice);

    try expect(@TypeOf(slice) == []i32);
    try expect(&amp;slice[0] == &amp;array[0]);
    try expect(slice.len == array.len);

    // If you slice with comptime-known start and end positions, the result is
    // a pointer to an array, rather than a slice.
    const array_ptr = array[0..array.len];
    try expect(@TypeOf(array_ptr) == *[array.len]i32);

    // You can perform a slice-by-length by slicing twice. This allows the compiler
    // to perform some optimisations like recognising a comptime-known length when
    // the start position is only known at runtime.
    var runtime_start: usize = 1;
    _ = &amp;runtime_start;
    const length = 2;
    const array_ptr_len = array[runtime_start..][0..length];
    try expect(@TypeOf(array_ptr_len) == *[length]i32);

    // Using the address-of operator on a slice gives a single-item pointer.
    try expect(@TypeOf(&amp;slice[0]) == *i32);
    // Using the `ptr` field gives a many-item pointer.
    try expect(@TypeOf(slice.ptr) == [*]i32);
    try expect(@intFromPtr(slice.ptr) == @intFromPtr(&amp;slice[0]));

    // Slices have array bounds checking. If you try to access something out
    // of bounds, you&#39;ll get a safety check failure:
    slice[10] += 1;

    // Note that `slice.ptr` does not invoke safety checking, while `&amp;slice[0]`
    // asserts that the slice has len &gt; 0.

    // Empty slices can be created like this:
    const empty1 = &amp;[0]u8{};
    // If the type is known you can use this short hand:
    const empty2: []u8 = &amp;.{};
    try expect(empty1.len == 0);
    try expect(empty2.len == 0);

    // A zero-length initialization can always be used to create an empty slice, even if the slice is mutable.
    // This is because the pointed-to data is zero bits long, so its immutability is irrelevant.
}</code></pre>
<figcaption>test_basic_slices.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_basic_slices.zig
1/1 test_basic_slices.test.basic slices...thread 222617 panic: index out of bounds: index 10, len 4
/home/andy/src/zig/doc/langref/test_basic_slices.zig:41:10: 0x104b5a1 in test.basic slices (test)
    slice[10] += 1;
         ^
/home/andy/src/zig/lib/compiler/test_runner.zig:214:25: 0x10f2645 in mainTerminal (test)
        if (test_fn.func()) |_| {
                        ^
/home/andy/src/zig/lib/compiler/test_runner.zig:62:28: 0x10eabdd in main (test)
        return mainTerminal();
                           ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10ea162 in posixCallMainAndExit (test)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10e9d3d in _start (test)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
error: the following test command crashed:
/home/andy/src/zig/.zig-cache/o/d7a037b9b130e4363980ed7df085d9dc/test --seed=0x830cf24c</code></pre>
<figcaption>Shell</figcaption>
</figure>

This is one reason we prefer slices to pointers.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;
const mem = std.mem;
const fmt = std.fmt;

test &quot;using slices for strings&quot; {
    // Zig has no concept of strings. String literals are const pointers
    // to null-terminated arrays of u8, and by convention parameters
    // that are &quot;strings&quot; are expected to be UTF-8 encoded slices of u8.
    // Here we coerce *const [5:0]u8 and *const [6:0]u8 to []const u8
    const hello: []const u8 = &quot;hello&quot;;
    const world: []const u8 = &quot;世界&quot;;

    var all_together: [100]u8 = undefined;
    // You can use slice syntax with at least one runtime-known index on an
    // array to convert an array into a slice.
    var start: usize = 0;
    _ = &amp;start;
    const all_together_slice = all_together[start..];
    // String concatenation example.
    const hello_world = try fmt.bufPrint(all_together_slice, &quot;{s} {s}&quot;, .{ hello, world });

    // Generally, you can use UTF-8 and not worry about whether something is a
    // string. If you don&#39;t need to deal with individual characters, no need
    // to decode.
    try expect(mem.eql(u8, hello_world, &quot;hello 世界&quot;));
}

test &quot;slice pointer&quot; {
    var array: [10]u8 = undefined;
    const ptr = &amp;array;
    try expect(@TypeOf(ptr) == *[10]u8);

    // A pointer to an array can be sliced just like an array:
    var start: usize = 0;
    var end: usize = 5;
    _ = .{ &amp;start, &amp;end };
    const slice = ptr[start..end];
    // The slice is mutable because we sliced a mutable pointer.
    try expect(@TypeOf(slice) == []u8);
    slice[2] = 3;
    try expect(array[2] == 3);

    // Again, slicing with comptime-known indexes will produce another pointer
    // to an array:
    const ptr2 = slice[2..3];
    try expect(ptr2.len == 1);
    try expect(ptr2[0] == 3);
    try expect(@TypeOf(ptr2) == *[1]u8);
}</code></pre>
<figcaption>test_slices.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_slices.zig
1/2 test_slices.test.using slices for strings...OK
2/2 test_slices.test.slice pointer...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Pointers](#Pointers)
- [for](#for)
- [Arrays](#Arrays)

### [Sentinel-Terminated Slices](#toc-Sentinel-Terminated-Slices) [§](#Sentinel-Terminated-Slices){.hdr} {#Sentinel-Terminated-Slices}

The syntax `[:x]T` is a slice which has a runtime-known length and also
guarantees a sentinel value at the element indexed by the length. The
type does not guarantee that there are no sentinel elements before that.
Sentinel-terminated slices allow element access to the `len` index.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;0-terminated slice&quot; {
    const slice: [:0]const u8 = &quot;hello&quot;;

    try expect(slice.len == 5);
    try expect(slice[5] == 0);
}</code></pre>
<figcaption>test_null_terminated_slice.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_null_terminated_slice.zig
1/1 test_null_terminated_slice.test.0-terminated slice...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Sentinel-terminated slices can also be created using a variation of the
slice syntax `data[start..end :x]`, where `data` is a many-item pointer,
array or slice and `x` is the sentinel value.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;0-terminated slicing&quot; {
    var array = [_]u8{ 3, 2, 1, 0, 3, 2, 1, 0 };
    var runtime_length: usize = 3;
    _ = &amp;runtime_length;
    const slice = array[0..runtime_length :0];

    try expect(@TypeOf(slice) == [:0]u8);
    try expect(slice.len == 3);
}</code></pre>
<figcaption>test_null_terminated_slicing.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_null_terminated_slicing.zig
1/1 test_null_terminated_slicing.test.0-terminated slicing...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Sentinel-terminated slicing asserts that the element in the sentinel
position of the backing data is actually the sentinel value. If this is
not the case, safety-checked [Illegal Behavior](#Illegal-Behavior)
results.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;sentinel mismatch&quot; {
    var array = [_]u8{ 3, 2, 1, 0 };

    // Creating a sentinel-terminated slice from the array with a length of 2
    // will result in the value `1` occupying the sentinel element position.
    // This does not match the indicated sentinel value of `0` and will lead
    // to a runtime panic.
    var runtime_length: usize = 2;
    _ = &amp;runtime_length;
    const slice = array[0..runtime_length :0];

    _ = slice;
}</code></pre>
<figcaption>test_sentinel_mismatch.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_sentinel_mismatch.zig
1/1 test_sentinel_mismatch.test.sentinel mismatch...thread 212416 panic: sentinel mismatch: expected 0, found 1
/home/andy/src/zig/doc/langref/test_sentinel_mismatch.zig:13:24: 0x1048af1 in test.sentinel mismatch (test)
    const slice = array[0..runtime_length :0];
                       ^
/home/andy/src/zig/lib/compiler/test_runner.zig:214:25: 0x10eeee5 in mainTerminal (test)
        if (test_fn.func()) |_| {
                        ^
/home/andy/src/zig/lib/compiler/test_runner.zig:62:28: 0x10e747d in main (test)
        return mainTerminal();
                           ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10e6a02 in posixCallMainAndExit (test)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10e65dd in _start (test)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
error: the following test command crashed:
/home/andy/src/zig/.zig-cache/o/9dfcdd59e16f1035ebfa67da73c4ad20/test --seed=0xb1e7629e</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Sentinel-Terminated Pointers](#Sentinel-Terminated-Pointers)
- [Sentinel-Terminated Arrays](#Sentinel-Terminated-Arrays)

## [struct](#toc-struct) [§](#struct){.hdr}

<figure>
<pre><code>// Declare a struct.
// Zig gives no guarantees about the order of fields and the size of
// the struct but the fields are guaranteed to be ABI-aligned.
const Point = struct {
    x: f32,
    y: f32,
};

// Declare an instance of a struct.
const p: Point = .{
    .x = 0.12,
    .y = 0.34,
};

// Functions in the struct&#39;s namespace can be called with dot syntax.
const Vec3 = struct {
    x: f32,
    y: f32,
    z: f32,

    pub fn init(x: f32, y: f32, z: f32) Vec3 {
        return Vec3{
            .x = x,
            .y = y,
            .z = z,
        };
    }

    pub fn dot(self: Vec3, other: Vec3) f32 {
        return self.x * other.x + self.y * other.y + self.z * other.z;
    }
};

test &quot;dot product&quot; {
    const v1 = Vec3.init(1.0, 0.0, 0.0);
    const v2 = Vec3.init(0.0, 1.0, 0.0);
    try expect(v1.dot(v2) == 0.0);

    // Other than being available to call with dot syntax, struct methods are
    // not special. You can reference them as any other declaration inside
    // the struct:
    try expect(Vec3.dot(v1, v2) == 0.0);
}

// Structs can have declarations.
// Structs can have 0 fields.
const Empty = struct {
    pub const PI = 3.14;
};
test &quot;struct namespaced variable&quot; {
    try expect(Empty.PI == 3.14);
    try expect(@sizeOf(Empty) == 0);

    // Empty structs can be instantiated the same as usual.
    const does_nothing: Empty = .{};

    _ = does_nothing;
}

// Struct field order is determined by the compiler, however, a base pointer
// can be computed from a field pointer:
fn setYBasedOnX(x: *f32, y: f32) void {
    const point: *Point = @fieldParentPtr(&quot;x&quot;, x);
    point.y = y;
}
test &quot;field parent pointer&quot; {
    var point = Point{
        .x = 0.1234,
        .y = 0.5678,
    };
    setYBasedOnX(&amp;point.x, 0.9);
    try expect(point.y == 0.9);
}

// Structs can be returned from functions.
fn LinkedList(comptime T: type) type {
    return struct {
        pub const Node = struct {
            prev: ?*Node,
            next: ?*Node,
            data: T,
        };

        first: ?*Node,
        last: ?*Node,
        len: usize,
    };
}

test &quot;linked list&quot; {
    // Functions called at compile-time are memoized.
    try expect(LinkedList(i32) == LinkedList(i32));

    const list = LinkedList(i32){
        .first = null,
        .last = null,
        .len = 0,
    };
    try expect(list.len == 0);

    // Since types are first class values you can instantiate the type
    // by assigning it to a variable:
    const ListOfInts = LinkedList(i32);
    try expect(ListOfInts == LinkedList(i32));

    var node = ListOfInts.Node{
        .prev = null,
        .next = null,
        .data = 1234,
    };
    const list2 = LinkedList(i32){
        .first = &amp;node,
        .last = &amp;node,
        .len = 1,
    };

    // When using a pointer to a struct, fields can be accessed directly,
    // without explicitly dereferencing the pointer.
    // So you can do
    try expect(list2.first.?.data == 1234);
    // instead of try expect(list2.first.?.*.data == 1234);
}

const expect = @import(&quot;std&quot;).testing.expect;</code></pre>
<figcaption>test_structs.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_structs.zig
1/4 test_structs.test.dot product...OK
2/4 test_structs.test.struct namespaced variable...OK
3/4 test_structs.test.field parent pointer...OK
4/4 test_structs.test.linked list...OK
All 4 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Default Field Values](#toc-Default-Field-Values) [§](#Default-Field-Values){.hdr} {#Default-Field-Values}

Each struct field may have an expression indicating the default field
value. Such expressions are executed at [comptime](#comptime), and allow
the field to be omitted in a struct literal expression:

<figure>
<pre><code>const Foo = struct {
    a: i32 = 1234,
    b: i32,
};

test &quot;default struct initialization fields&quot; {
    const x: Foo = .{
        .b = 5,
    };
    if (x.a + x.b != 1239) {
        comptime unreachable;
    }
}</code></pre>
<figcaption>struct_default_field_values.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test struct_default_field_values.zig
1/1 struct_default_field_values.test.default struct initialization fields...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Faulty Default Field Values](#toc-Faulty-Default-Field-Values) [§](#Faulty-Default-Field-Values){.hdr} {#Faulty-Default-Field-Values}

Default field values are only appropriate when the data invariants of a
struct cannot be violated by omitting that field from an initialization.

For example, here is an inappropriate use of default struct field
initialization:

<figure>
<pre><code>const Threshold = struct {
    minimum: f32 = 0.25,
    maximum: f32 = 0.75,

    const Category = enum { low, medium, high };

    fn categorize(t: Threshold, value: f32) Category {
        assert(t.maximum &gt;= t.minimum);
        if (value &lt; t.minimum) return .low;
        if (value &gt; t.maximum) return .high;
        return .medium;
    }
};

pub fn main() !void {
    var threshold: Threshold = .{
        .maximum = 0.20,
    };
    const category = threshold.categorize(0.90);
    try std.io.getStdOut().writeAll(@tagName(category));
}

const std = @import(&quot;std&quot;);
const assert = std.debug.assert;</code></pre>
<figcaption>bad_default_value.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe bad_default_value.zig
$ ./bad_default_value
thread 216489 panic: reached unreachable code
/home/andy/src/zig/lib/std/debug.zig:522:14: 0x1048e4d in assert (bad_default_value)
    if (!ok) unreachable; // assertion failure
             ^
/home/andy/src/zig/doc/langref/bad_default_value.zig:8:15: 0x10de7b9 in categorize (bad_default_value)
        assert(t.maximum &gt;= t.minimum);
              ^
/home/andy/src/zig/doc/langref/bad_default_value.zig:19:42: 0x10de6fa in main (bad_default_value)
    const category = threshold.categorize(0.90);
                                         ^
/home/andy/src/zig/lib/std/start.zig:656:37: 0x10de60a in posixCallMainAndExit (bad_default_value)
            const result = root.main() catch |err| {
                                    ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10de1bd in _start (bad_default_value)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

Above you can see the danger of ignoring this principle. The default
field values caused the data invariant to be violated, causing illegal
behavior.

To fix this, remove the default values from all the struct fields, and
provide a named default value:

<figure>
<pre><code>const Threshold = struct {
    minimum: f32,
    maximum: f32,

    const default: Threshold = .{
        .minimum = 0.25,
        .maximum = 0.75,
    };
};</code></pre>
<figcaption>struct_default_value.zig</figcaption>
</figure>

If a struct value requires a runtime-known value in order to be
initialized without violating data invariants, then use an
initialization method that accepts those runtime values, and populates
the remaining fields.

### [extern struct](#toc-extern-struct) [§](#extern-struct){.hdr}

An [`extern`]{.tok-kw}` `[`struct`]{.tok-kw} has in-memory layout
matching the C ABI for the target.

If well-defined in-memory layout is not required, [struct](#struct) is a
better choice because it places fewer restrictions on the compiler.

See [packed struct](#packed-struct) for a struct that has the ABI of its
backing integer, which can be useful for modeling flags.

See also:

- [extern union](#extern-union)
- [extern enum](#extern-enum)

### [packed struct](#toc-packed-struct) [§](#packed-struct){.hdr}

Unlike normal structs, [`packed`]{.tok-kw} structs have guaranteed
in-memory layout:

- Fields remain in the order declared, least to most significant.
- There is no padding between fields.
- Zig supports arbitrary width [Integers](#Integers) and although
  normally, integers with fewer than 8 bits will still use 1 byte of
  memory, in packed structs, they use exactly their bit width.
- [`bool`]{.tok-type} fields use exactly 1 bit.
- An [enum](#enum) field uses exactly the bit width of its integer tag
  type.
- A [packed union](#packed-union) field uses exactly the bit width of
  the union field with the largest bit width.
- Packed structs support equality operators.

This means that a [`packed`]{.tok-kw}` `[`struct`]{.tok-kw} can
participate in a [\@bitCast](#bitCast) or a [\@ptrCast](#ptrCast) to
reinterpret memory. This even works at [comptime](#comptime):

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const native_endian = @import(&quot;builtin&quot;).target.cpu.arch.endian();
const expect = std.testing.expect;

const Full = packed struct {
    number: u16,
};
const Divided = packed struct {
    half1: u8,
    quarter3: u4,
    quarter4: u4,
};

test &quot;@bitCast between packed structs&quot; {
    try doTheTest();
    try comptime doTheTest();
}

fn doTheTest() !void {
    try expect(@sizeOf(Full) == 2);
    try expect(@sizeOf(Divided) == 2);
    const full = Full{ .number = 0x1234 };
    const divided: Divided = @bitCast(full);
    try expect(divided.half1 == 0x34);
    try expect(divided.quarter3 == 0x2);
    try expect(divided.quarter4 == 0x1);

    const ordered: [2]u8 = @bitCast(full);
    switch (native_endian) {
        .big =&gt; {
            try expect(ordered[0] == 0x12);
            try expect(ordered[1] == 0x34);
        },
        .little =&gt; {
            try expect(ordered[0] == 0x34);
            try expect(ordered[1] == 0x12);
        },
    }
}</code></pre>
<figcaption>test_packed_structs.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_packed_structs.zig
1/1 test_packed_structs.test.@bitCast between packed structs...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

The backing integer is inferred from the fields\' total bit width.
Optionally, it can be explicitly provided and enforced at compile time:

<figure>
<pre><code>test &quot;missized packed struct&quot; {
    const S = packed struct(u32) { a: u16, b: u8 };
    _ = S{ .a = 4, .b = 2 };
}</code></pre>
<figcaption>test_missized_packed_struct.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_missized_packed_struct.zig
doc/langref/test_missized_packed_struct.zig:2:29: error: backing integer type &#39;u32&#39; has bit size 32 but the struct fields have a total bit size of 24
    const S = packed struct(u32) { a: u16, b: u8 };
                            ^~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

Zig allows the address to be taken of a non-byte-aligned field:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const BitField = packed struct {
    a: u3,
    b: u3,
    c: u2,
};

var foo = BitField{
    .a = 1,
    .b = 2,
    .c = 3,
};

test &quot;pointer to non-byte-aligned field&quot; {
    const ptr = &amp;foo.b;
    try expect(ptr.* == 2);
}</code></pre>
<figcaption>test_pointer_to_non-byte_aligned_field.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_pointer_to_non-byte_aligned_field.zig
1/1 test_pointer_to_non-byte_aligned_field.test.pointer to non-byte-aligned field...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

However, the pointer to a non-byte-aligned field has special properties
and cannot be passed when a normal pointer is expected:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const BitField = packed struct {
    a: u3,
    b: u3,
    c: u2,
};

var bit_field = BitField{
    .a = 1,
    .b = 2,
    .c = 3,
};

test &quot;pointer to non-byte-aligned field&quot; {
    try expect(bar(&amp;bit_field.b) == 2);
}

fn bar(x: *const u3) u3 {
    return x.*;
}</code></pre>
<figcaption>test_misaligned_pointer.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_misaligned_pointer.zig
doc/langref/test_misaligned_pointer.zig:17:20: error: expected type &#39;*const u3&#39;, found &#39;*align(1:3:1) u3&#39;
    try expect(bar(&amp;bit_field.b) == 2);
                   ^~~~~~~~~~~~
doc/langref/test_misaligned_pointer.zig:17:20: note: pointer host size &#39;1&#39; cannot cast into pointer host size &#39;0&#39;
doc/langref/test_misaligned_pointer.zig:17:20: note: pointer bit offset &#39;3&#39; cannot cast into pointer bit offset &#39;0&#39;
doc/langref/test_misaligned_pointer.zig:20:11: note: parameter type declared here
fn bar(x: *const u3) u3 {
          ^~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

In this case, the function `bar` cannot be called because the pointer to
the non-ABI-aligned field mentions the bit offset, but the function
expects an ABI-aligned pointer.

Pointers to non-ABI-aligned fields share the same address as the other
fields within their host integer:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const BitField = packed struct {
    a: u3,
    b: u3,
    c: u2,
};

var bit_field = BitField{
    .a = 1,
    .b = 2,
    .c = 3,
};

test &quot;pointers of sub-byte-aligned fields share addresses&quot; {
    try expect(@intFromPtr(&amp;bit_field.a) == @intFromPtr(&amp;bit_field.b));
    try expect(@intFromPtr(&amp;bit_field.a) == @intFromPtr(&amp;bit_field.c));
}</code></pre>
<figcaption>test_packed_struct_field_address.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_packed_struct_field_address.zig
1/1 test_packed_struct_field_address.test.pointers of sub-byte-aligned fields share addresses...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

This can be observed with [\@bitOffsetOf](#bitOffsetOf) and
[offsetOf](#offsetOf):

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const BitField = packed struct {
    a: u3,
    b: u3,
    c: u2,
};

test &quot;offsets of non-byte-aligned fields&quot; {
    comptime {
        try expect(@bitOffsetOf(BitField, &quot;a&quot;) == 0);
        try expect(@bitOffsetOf(BitField, &quot;b&quot;) == 3);
        try expect(@bitOffsetOf(BitField, &quot;c&quot;) == 6);

        try expect(@offsetOf(BitField, &quot;a&quot;) == 0);
        try expect(@offsetOf(BitField, &quot;b&quot;) == 0);
        try expect(@offsetOf(BitField, &quot;c&quot;) == 0);
    }
}</code></pre>
<figcaption>test_bitOffsetOf_offsetOf.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_bitOffsetOf_offsetOf.zig
1/1 test_bitOffsetOf_offsetOf.test.offsets of non-byte-aligned fields...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Packed structs have the same alignment as their backing integer,
however, overaligned pointers to packed structs can override this:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const S = packed struct {
    a: u32,
    b: u32,
};
test &quot;overaligned pointer to packed struct&quot; {
    var foo: S align(4) = .{ .a = 1, .b = 2 };
    const ptr: *align(4) S = &amp;foo;
    const ptr_to_b: *u32 = &amp;ptr.b;
    try expect(ptr_to_b.* == 2);
}</code></pre>
<figcaption>test_overaligned_packed_struct.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_overaligned_packed_struct.zig
1/1 test_overaligned_packed_struct.test.overaligned pointer to packed struct...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

It\'s also possible to set alignment of struct fields:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expectEqual = std.testing.expectEqual;

test &quot;aligned struct fields&quot; {
    const S = struct {
        a: u32 align(2),
        b: u32 align(64),
    };
    var foo = S{ .a = 1, .b = 2 };

    try expectEqual(64, @alignOf(S));
    try expectEqual(*align(2) u32, @TypeOf(&amp;foo.a));
    try expectEqual(*align(64) u32, @TypeOf(&amp;foo.b));
}</code></pre>
<figcaption>test_aligned_struct_fields.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_aligned_struct_fields.zig
1/1 test_aligned_struct_fields.test.aligned struct fields...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Equating packed structs results in a comparison of the backing integer,
and only works for the \`==\` and \`!=\` operators.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;packed struct equality&quot; {
    const S = packed struct {
        a: u4,
        b: u4,
    };
    const x: S = .{ .a = 1, .b = 2 };
    const y: S = .{ .b = 2, .a = 1 };
    try expect(x == y);
}</code></pre>
<figcaption>test_packed_struct_equality.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_packed_struct_equality.zig
1/1 test_packed_struct_equality.test.packed struct equality...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Using packed structs with [volatile](#volatile) is problematic, and may
be a compile error in the future. For details on this subscribe to [this
issue](https://github.com/ziglang/zig/issues/1761). TODO update these
docs with a recommendation on how to use packed structs with MMIO (the
use case for volatile packed structs) once this issue is resolved.
Don\'t worry, there will be a good solution for this use case in zig.

### [Struct Naming](#toc-Struct-Naming) [§](#Struct-Naming){.hdr} {#Struct-Naming}

Since all structs are anonymous, Zig infers the type name based on a few
rules.

- If the struct is in the initialization expression of a variable, it
  gets named after that variable.
- If the struct is in the [`return`]{.tok-kw} expression, it gets named
  after the function it is returning from, with the parameter values
  serialized.
- Otherwise, the struct gets a name such as
  `(filename.funcname__struct_ID)`.
- If the struct is declared inside another struct, it gets named after
  both the parent struct and the name inferred by the previous rules,
  separated by a dot.

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    const Foo = struct {};
    std.debug.print(&quot;variable: {s}\n&quot;, .{@typeName(Foo)});
    std.debug.print(&quot;anonymous: {s}\n&quot;, .{@typeName(struct {})});
    std.debug.print(&quot;function: {s}\n&quot;, .{@typeName(List(i32))});
}

fn List(comptime T: type) type {
    return struct {
        x: T,
    };
}</code></pre>
<figcaption>struct_name.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe struct_name.zig
$ ./struct_name
variable: struct_name.main.Foo
anonymous: struct_name.main__struct_24143
function: struct_name.List(i32)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Anonymous Struct Literals](#toc-Anonymous-Struct-Literals) [§](#Anonymous-Struct-Literals){.hdr} {#Anonymous-Struct-Literals}

Zig allows omitting the struct type of a literal. When the result is
[coerced](#Type-Coercion), the struct literal will directly instantiate
the [result location](#Result-Location-Semantics), with no copy:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const Point = struct { x: i32, y: i32 };

test &quot;anonymous struct literal&quot; {
    const pt: Point = .{
        .x = 13,
        .y = 67,
    };
    try expect(pt.x == 13);
    try expect(pt.y == 67);
}</code></pre>
<figcaption>test_struct_result.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_struct_result.zig
1/1 test_struct_result.test.anonymous struct literal...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

The struct type can be inferred. Here the [result
location](#Result-Location-Semantics) does not include a type, and so
Zig infers the type:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;fully anonymous struct&quot; {
    try check(.{
        .int = @as(u32, 1234),
        .float = @as(f64, 12.34),
        .b = true,
        .s = &quot;hi&quot;,
    });
}

fn check(args: anytype) !void {
    try expect(args.int == 1234);
    try expect(args.float == 12.34);
    try expect(args.b);
    try expect(args.s[0] == &#39;h&#39;);
    try expect(args.s[1] == &#39;i&#39;);
}</code></pre>
<figcaption>test_anonymous_struct.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_anonymous_struct.zig
1/1 test_anonymous_struct.test.fully anonymous struct...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Tuples](#toc-Tuples) [§](#Tuples){.hdr} {#Tuples}

Anonymous structs can be created without specifying field names, and are
referred to as \"tuples\". An empty tuple looks like `.{}` and can be
seen in one of the [Hello World examples](#Hello-World).

The fields are implicitly named using numbers starting from 0. Because
their names are integers, they cannot be accessed with `.` syntax
without also wrapping them in `@""`. Names inside `@""` are always
recognised as [identifiers](#Identifiers).

Like arrays, tuples have a .len field, can be indexed (provided the
index is comptime-known) and work with the ++ and \*\* operators. They
can also be iterated over with [inline for](#inline-for).

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;tuple&quot; {
    const values = .{
        @as(u32, 1234),
        @as(f64, 12.34),
        true,
        &quot;hi&quot;,
    } ++ .{false} ** 2;
    try expect(values[0] == 1234);
    try expect(values[4] == false);
    inline for (values, 0..) |v, i| {
        if (i != 2) continue;
        try expect(v);
    }
    try expect(values.len == 6);
    try expect(values.@&quot;3&quot;[0] == &#39;h&#39;);
}</code></pre>
<figcaption>test_tuples.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_tuples.zig
1/1 test_tuples.test.tuple...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Destructuring Tuples](#toc-Destructuring-Tuples) [§](#Destructuring-Tuples){.hdr} {#Destructuring-Tuples}

Tuples can be [destructured](#Destructuring).

Tuple destructuring is helpful for returning multiple values from a
block:

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

pub fn main() void {
    const digits = [_]i8 { 3, 8, 9, 0, 7, 4, 1 };

    const min, const max = blk: {
        var min: i8 = 127;
        var max: i8 = -128;

        for (digits) |digit| {
            if (digit &lt; min) min = digit;
            if (digit &gt; max) max = digit;
        }

        break :blk .{ min, max };
    };

    print(&quot;min = {}&quot;, .{ min });
    print(&quot;max = {}&quot;, .{ max });
}</code></pre>
<figcaption>destructuring_block.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe destructuring_block.zig
$ ./destructuring_block
min = 0max = 9</code></pre>
<figcaption>Shell</figcaption>
</figure>

Tuple destructuring is helpful for dealing with functions and built-ins
that return multiple values as a tuple:

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

fn divmod(numerator: u32, denominator: u32) struct { u32, u32 } {
    return .{ numerator / denominator, numerator % denominator };
}

pub fn main() void {
    const div, const mod = divmod(10, 3);

    print(&quot;10 / 3 = {}\n&quot;, .{div});
    print(&quot;10 % 3 = {}\n&quot;, .{mod});
}</code></pre>
<figcaption>destructuring_return_value.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe destructuring_return_value.zig
$ ./destructuring_return_value
10 / 3 = 3
10 % 3 = 1</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Destructuring](#Destructuring)
- [Destructuring Arrays](#Destructuring-Arrays)
- [Destructuring Vectors](#Destructuring-Vectors)

See also:

- [comptime](#comptime)
- [\@fieldParentPtr](#fieldParentPtr)

## [enum](#toc-enum) [§](#enum){.hdr}

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;
const mem = @import(&quot;std&quot;).mem;

// Declare an enum.
const Type = enum {
    ok,
    not_ok,
};

// Declare a specific enum field.
const c = Type.ok;

// If you want access to the ordinal value of an enum, you
// can specify the tag type.
const Value = enum(u2) {
    zero,
    one,
    two,
};
// Now you can cast between u2 and Value.
// The ordinal value starts from 0, counting up by 1 from the previous member.
test &quot;enum ordinal value&quot; {
    try expect(@intFromEnum(Value.zero) == 0);
    try expect(@intFromEnum(Value.one) == 1);
    try expect(@intFromEnum(Value.two) == 2);
}

// You can override the ordinal value for an enum.
const Value2 = enum(u32) {
    hundred = 100,
    thousand = 1000,
    million = 1000000,
};
test &quot;set enum ordinal value&quot; {
    try expect(@intFromEnum(Value2.hundred) == 100);
    try expect(@intFromEnum(Value2.thousand) == 1000);
    try expect(@intFromEnum(Value2.million) == 1000000);
}

// You can also override only some values.
const Value3 = enum(u4) {
    a,
    b = 8,
    c,
    d = 4,
    e,
};
test &quot;enum implicit ordinal values and overridden values&quot; {
    try expect(@intFromEnum(Value3.a) == 0);
    try expect(@intFromEnum(Value3.b) == 8);
    try expect(@intFromEnum(Value3.c) == 9);
    try expect(@intFromEnum(Value3.d) == 4);
    try expect(@intFromEnum(Value3.e) == 5);
}

// Enums can have methods, the same as structs and unions.
// Enum methods are not special, they are only namespaced
// functions that you can call with dot syntax.
const Suit = enum {
    clubs,
    spades,
    diamonds,
    hearts,

    pub fn isClubs(self: Suit) bool {
        return self == Suit.clubs;
    }
};
test &quot;enum method&quot; {
    const p = Suit.spades;
    try expect(!p.isClubs());
}

// An enum can be switched upon.
const Foo = enum {
    string,
    number,
    none,
};
test &quot;enum switch&quot; {
    const p = Foo.number;
    const what_is_it = switch (p) {
        Foo.string =&gt; &quot;this is a string&quot;,
        Foo.number =&gt; &quot;this is a number&quot;,
        Foo.none =&gt; &quot;this is a none&quot;,
    };
    try expect(mem.eql(u8, what_is_it, &quot;this is a number&quot;));
}

// @typeInfo can be used to access the integer tag type of an enum.
const Small = enum {
    one,
    two,
    three,
    four,
};
test &quot;std.meta.Tag&quot; {
    try expect(@typeInfo(Small).@&quot;enum&quot;.tag_type == u2);
}

// @typeInfo tells us the field count and the fields names:
test &quot;@typeInfo&quot; {
    try expect(@typeInfo(Small).@&quot;enum&quot;.fields.len == 4);
    try expect(mem.eql(u8, @typeInfo(Small).@&quot;enum&quot;.fields[1].name, &quot;two&quot;));
}

// @tagName gives a [:0]const u8 representation of an enum value:
test &quot;@tagName&quot; {
    try expect(mem.eql(u8, @tagName(Small.three), &quot;three&quot;));
}</code></pre>
<figcaption>test_enums.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_enums.zig
1/8 test_enums.test.enum ordinal value...OK
2/8 test_enums.test.set enum ordinal value...OK
3/8 test_enums.test.enum implicit ordinal values and overridden values...OK
4/8 test_enums.test.enum method...OK
5/8 test_enums.test.enum switch...OK
6/8 test_enums.test.std.meta.Tag...OK
7/8 test_enums.test.@typeInfo...OK
8/8 test_enums.test.@tagName...OK
All 8 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [\@typeInfo](#typeInfo)
- [\@tagName](#tagName)
- [\@sizeOf](#sizeOf)

### [extern enum](#toc-extern-enum) [§](#extern-enum){.hdr}

By default, enums are not guaranteed to be compatible with the C ABI:

<figure>
<pre><code>const Foo = enum { a, b, c };
export fn entry(foo: Foo) void {
    _ = foo;
}</code></pre>
<figcaption>enum_export_error.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-obj enum_export_error.zig -target x86_64-linux
doc/langref/enum_export_error.zig:2:17: error: parameter of type &#39;enum_export_error.Foo&#39; not allowed in function with calling convention &#39;x86_64_sysv&#39;
export fn entry(foo: Foo) void {
                ^~~~~~~~
doc/langref/enum_export_error.zig:2:17: note: enum tag type &#39;u2&#39; is not extern compatible
doc/langref/enum_export_error.zig:2:17: note: only integers with 0, 8, 16, 32, 64 and 128 bits are extern compatible
doc/langref/enum_export_error.zig:1:13: note: enum declared here
const Foo = enum { a, b, c };
            ^~~~~~~~~~~~~~~~
referenced by:
    root: lib/std/start.zig:3:22
    comptime: lib/std/start.zig:27:9
    2 reference(s) hidden; use &#39;-freference-trace=4&#39; to see all references
</code></pre>
<figcaption>Shell</figcaption>
</figure>

For a C-ABI-compatible enum, provide an explicit tag type to the enum:

<figure>
<pre><code>const Foo = enum(c_int) { a, b, c };
export fn entry(foo: Foo) void {
    _ = foo;
}</code></pre>
<figcaption>enum_export.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-obj enum_export.zig</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Enum Literals](#toc-Enum-Literals) [§](#Enum-Literals){.hdr} {#Enum-Literals}

Enum literals allow specifying the name of an enum field without
specifying the enum type:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const Color = enum {
    auto,
    off,
    on,
};

test &quot;enum literals&quot; {
    const color1: Color = .auto;
    const color2 = Color.auto;
    try expect(color1 == color2);
}

test &quot;switch using enum literals&quot; {
    const color = Color.on;
    const result = switch (color) {
        .auto =&gt; false,
        .on =&gt; true,
        .off =&gt; false,
    };
    try expect(result);
}</code></pre>
<figcaption>test_enum_literals.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_enum_literals.zig
1/2 test_enum_literals.test.enum literals...OK
2/2 test_enum_literals.test.switch using enum literals...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Non-exhaustive enum](#toc-Non-exhaustive-enum) [§](#Non-exhaustive-enum){.hdr} {#Non-exhaustive-enum}

A non-exhaustive enum can be created by adding a trailing `_` field. The
enum must specify a tag type and cannot consume every enumeration value.

[\@enumFromInt](#enumFromInt) on a non-exhaustive enum involves the
safety semantics of [\@intCast](#intCast) to the integer tag type, but
beyond that always results in a well-defined enum value.

A switch on a non-exhaustive enum can include a `_` prong as an
alternative to an [`else`]{.tok-kw} prong. With a `_` prong the compiler
errors if all the known tag names are not handled by the switch.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const Number = enum(u8) {
    one,
    two,
    three,
    _,
};

test &quot;switch on non-exhaustive enum&quot; {
    const number = Number.one;
    const result = switch (number) {
        .one =&gt; true,
        .two, .three =&gt; false,
        _ =&gt; false,
    };
    try expect(result);
    const is_one = switch (number) {
        .one =&gt; true,
        else =&gt; false,
    };
    try expect(is_one);
}</code></pre>
<figcaption>test_switch_non-exhaustive.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_switch_non-exhaustive.zig
1/1 test_switch_non-exhaustive.test.switch on non-exhaustive enum...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [union](#toc-union) [§](#union){.hdr}

A bare [`union`]{.tok-kw} defines a set of possible types that a value
can be as a list of fields. Only one field can be active at a time. The
in-memory representation of bare unions is not guaranteed. Bare unions
cannot be used to reinterpret memory. For that, use
[\@ptrCast](#ptrCast), or use an [extern union](#extern-union) or a
[packed union](#packed-union) which have guaranteed in-memory layout.
[Accessing the non-active field](#Wrong-Union-Field-Access) is
safety-checked [Illegal Behavior](#Illegal-Behavior):

<figure>
<pre><code>const Payload = union {
    int: i64,
    float: f64,
    boolean: bool,
};
test &quot;simple union&quot; {
    var payload = Payload{ .int = 1234 };
    payload.float = 12.34;
}</code></pre>
<figcaption>test_wrong_union_access.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_wrong_union_access.zig
1/1 test_wrong_union_access.test.simple union...thread 221884 panic: access of union field &#39;float&#39; while field &#39;int&#39; is active
/home/andy/src/zig/doc/langref/test_wrong_union_access.zig:8:12: 0x1048aef in test.simple union (test)
    payload.float = 12.34;
           ^
/home/andy/src/zig/lib/compiler/test_runner.zig:214:25: 0x10ef005 in mainTerminal (test)
        if (test_fn.func()) |_| {
                        ^
/home/andy/src/zig/lib/compiler/test_runner.zig:62:28: 0x10e759d in main (test)
        return mainTerminal();
                           ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10e6b22 in posixCallMainAndExit (test)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10e66fd in _start (test)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
error: the following test command crashed:
/home/andy/src/zig/.zig-cache/o/cc43f9aad019d16b70a651087b598133/test --seed=0x94ba4c6a</code></pre>
<figcaption>Shell</figcaption>
</figure>

You can activate another field by assigning the entire union:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const Payload = union {
    int: i64,
    float: f64,
    boolean: bool,
};
test &quot;simple union&quot; {
    var payload = Payload{ .int = 1234 };
    try expect(payload.int == 1234);
    payload = Payload{ .float = 12.34 };
    try expect(payload.float == 12.34);
}</code></pre>
<figcaption>test_simple_union.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_simple_union.zig
1/1 test_simple_union.test.simple union...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

In order to use [switch](#switch) with a union, it must be a [Tagged
union](#Tagged-union).

To initialize a union when the tag is a [comptime](#comptime)-known
name, see [\@unionInit](#unionInit).

### [Tagged union](#toc-Tagged-union) [§](#Tagged-union){.hdr} {#Tagged-union}

Unions can be declared with an enum tag type. This turns the union into
a *tagged* union, which makes it eligible to use with [switch](#switch)
expressions. Tagged unions coerce to their tag type: [Type Coercion:
Unions and Enums](#Type-Coercion-Unions-and-Enums).

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const ComplexTypeTag = enum {
    ok,
    not_ok,
};
const ComplexType = union(ComplexTypeTag) {
    ok: u8,
    not_ok: void,
};

test &quot;switch on tagged union&quot; {
    const c = ComplexType{ .ok = 42 };
    try expect(@as(ComplexTypeTag, c) == ComplexTypeTag.ok);

    switch (c) {
        .ok =&gt; |value| try expect(value == 42),
        .not_ok =&gt; unreachable,
    }
}

test &quot;get tag type&quot; {
    try expect(std.meta.Tag(ComplexType) == ComplexTypeTag);
}</code></pre>
<figcaption>test_tagged_union.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_tagged_union.zig
1/2 test_tagged_union.test.switch on tagged union...OK
2/2 test_tagged_union.test.get tag type...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

In order to modify the payload of a tagged union in a switch expression,
place a `*` before the variable name to make it a pointer:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const ComplexTypeTag = enum {
    ok,
    not_ok,
};
const ComplexType = union(ComplexTypeTag) {
    ok: u8,
    not_ok: void,
};

test &quot;modify tagged union in switch&quot; {
    var c = ComplexType{ .ok = 42 };

    switch (c) {
        ComplexTypeTag.ok =&gt; |*value| value.* += 1,
        ComplexTypeTag.not_ok =&gt; unreachable,
    }

    try expect(c.ok == 43);
}</code></pre>
<figcaption>test_switch_modify_tagged_union.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_switch_modify_tagged_union.zig
1/1 test_switch_modify_tagged_union.test.modify tagged union in switch...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Unions can be made to infer the enum tag type. Further, unions can have
methods just like structs and enums.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const Variant = union(enum) {
    int: i32,
    boolean: bool,

    // void can be omitted when inferring enum tag type.
    none,

    fn truthy(self: Variant) bool {
        return switch (self) {
            Variant.int =&gt; |x_int| x_int != 0,
            Variant.boolean =&gt; |x_bool| x_bool,
            Variant.none =&gt; false,
        };
    }
};

test &quot;union method&quot; {
    var v1: Variant = .{ .int = 1 };
    var v2: Variant = .{ .boolean = false };
    var v3: Variant = .none;

    try expect(v1.truthy());
    try expect(!v2.truthy());
    try expect(!v3.truthy());
}</code></pre>
<figcaption>test_union_method.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_union_method.zig
1/1 test_union_method.test.union method...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

[\@tagName](#tagName) can be used to return a [comptime](#comptime)
`[:`[`0`]{.tok-number}`]`[`const`]{.tok-kw}` `[`u8`]{.tok-type} value
representing the field name:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const Small2 = union(enum) {
    a: i32,
    b: bool,
    c: u8,
};
test &quot;@tagName&quot; {
    try expect(std.mem.eql(u8, @tagName(Small2.a), &quot;a&quot;));
}</code></pre>
<figcaption>test_tagName.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_tagName.zig
1/1 test_tagName.test.@tagName...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [extern union](#toc-extern-union) [§](#extern-union){.hdr}

An [`extern`]{.tok-kw}` `[`union`]{.tok-kw} has memory layout guaranteed
to be compatible with the target C ABI.

See also:

- [extern struct](#extern-struct)

### [packed union](#toc-packed-union) [§](#packed-union){.hdr}

A [`packed`]{.tok-kw}` `[`union`]{.tok-kw} has well-defined in-memory
layout and is eligible to be in a [packed struct](#packed-struct).

### [Anonymous Union Literals](#toc-Anonymous-Union-Literals) [§](#Anonymous-Union-Literals){.hdr} {#Anonymous-Union-Literals}

[Anonymous Struct Literals](#Anonymous-Struct-Literals) syntax can be
used to initialize unions without specifying the type:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const Number = union {
    int: i32,
    float: f64,
};

test &quot;anonymous union literal syntax&quot; {
    const i: Number = .{ .int = 42 };
    const f = makeNumber();
    try expect(i.int == 42);
    try expect(f.float == 12.34);
}

fn makeNumber() Number {
    return .{ .float = 12.34 };
}</code></pre>
<figcaption>test_anonymous_union.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_anonymous_union.zig
1/1 test_anonymous_union.test.anonymous union literal syntax...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [opaque](#toc-opaque) [§](#opaque){.hdr}

[`opaque`]{.tok-kw}` {}` declares a new type with an unknown (but
non-zero) size and alignment. It can contain declarations the same as
[structs](#struct), [unions](#union), and [enums](#enum).

This is typically used for type safety when interacting with C code that
does not expose struct details. Example:

<figure>
<pre><code>const Derp = opaque {};
const Wat = opaque {};

extern fn bar(d: *Derp) void;
fn foo(w: *Wat) callconv(.C) void {
    bar(w);
}

test &quot;call foo&quot; {
    foo(undefined);
}</code></pre>
<figcaption>test_opaque.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_opaque.zig
doc/langref/test_opaque.zig:6:9: error: expected type &#39;*test_opaque.Derp&#39;, found &#39;*test_opaque.Wat&#39;
    bar(w);
        ^
doc/langref/test_opaque.zig:6:9: note: pointer type child &#39;test_opaque.Wat&#39; cannot cast into pointer type child &#39;test_opaque.Derp&#39;
doc/langref/test_opaque.zig:2:13: note: opaque declared here
const Wat = opaque {};
            ^~~~~~~~~
doc/langref/test_opaque.zig:1:14: note: opaque declared here
const Derp = opaque {};
             ^~~~~~~~~
doc/langref/test_opaque.zig:4:18: note: parameter type declared here
extern fn bar(d: *Derp) void;
                 ^~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [Blocks](#toc-Blocks) [§](#Blocks){.hdr} {#Blocks}

Blocks are used to limit the scope of variable declarations:

<figure>
<pre><code>test &quot;access variable after block scope&quot; {
    {
        var x: i32 = 1;
        _ = &amp;x;
    }
    x += 1;
}</code></pre>
<figcaption>test_blocks.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_blocks.zig
doc/langref/test_blocks.zig:6:5: error: use of undeclared identifier &#39;x&#39;
    x += 1;
    ^
</code></pre>
<figcaption>Shell</figcaption>
</figure>

Blocks are expressions. When labeled, [`break`]{.tok-kw} can be used to
return a value from the block:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;labeled break from labeled block expression&quot; {
    var y: i32 = 123;

    const x = blk: {
        y += 1;
        break :blk y;
    };
    try expect(x == 124);
    try expect(y == 124);
}</code></pre>
<figcaption>test_labeled_break.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_labeled_break.zig
1/1 test_labeled_break.test.labeled break from labeled block expression...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Here, `blk` can be any name.

See also:

- [Labeled while](#Labeled-while)
- [Labeled for](#Labeled-for)

### [Shadowing](#toc-Shadowing) [§](#Shadowing){.hdr} {#Shadowing}

[Identifiers](#Identifiers) are never allowed to \"hide\" other
identifiers by using the same name:

<figure>
<pre><code>const pi = 3.14;

test &quot;inside test block&quot; {
    // Let&#39;s even go inside another block
    {
        var pi: i32 = 1234;
    }
}</code></pre>
<figcaption>test_shadowing.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_shadowing.zig
doc/langref/test_shadowing.zig:6:13: error: local variable shadows declaration of &#39;pi&#39;
        var pi: i32 = 1234;
            ^~
doc/langref/test_shadowing.zig:1:1: note: declared here
const pi = 3.14;
^~~~~~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

Because of this, when you read Zig code you can always rely on an
identifier to consistently mean the same thing within the scope it is
defined. Note that you can, however, use the same name if the scopes are
separate:

<figure>
<pre><code>test &quot;separate scopes&quot; {
    {
        const pi = 3.14;
        _ = pi;
    }
    {
        var pi: bool = true;
        _ = &amp;pi;
    }
}</code></pre>
<figcaption>test_scopes.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_scopes.zig
1/1 test_scopes.test.separate scopes...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Empty Blocks](#toc-Empty-Blocks) [§](#Empty-Blocks){.hdr} {#Empty-Blocks}

An empty block is equivalent to [`void`]{.tok-type}`{}`:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test {
    const a = {};
    const b = void{};
    try expect(@TypeOf(a) == void);
    try expect(@TypeOf(b) == void);
    try expect(a == b);
}</code></pre>
<figcaption>test_empty_block.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_empty_block.zig
1/1 test_empty_block.test_0...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [switch](#toc-switch) [§](#switch){.hdr}

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const builtin = @import(&quot;builtin&quot;);
const expect = std.testing.expect;

test &quot;switch simple&quot; {
    const a: u64 = 10;
    const zz: u64 = 103;

    // All branches of a switch expression must be able to be coerced to a
    // common type.
    //
    // Branches cannot fallthrough. If fallthrough behavior is desired, combine
    // the cases and use an if.
    const b = switch (a) {
        // Multiple cases can be combined via a &#39;,&#39;
        1, 2, 3 =&gt; 0,

        // Ranges can be specified using the ... syntax. These are inclusive
        // of both ends.
        5...100 =&gt; 1,

        // Branches can be arbitrarily complex.
        101 =&gt; blk: {
            const c: u64 = 5;
            break :blk c * 2 + 1;
        },

        // Switching on arbitrary expressions is allowed as long as the
        // expression is known at compile-time.
        zz =&gt; zz,
        blk: {
            const d: u32 = 5;
            const e: u32 = 100;
            break :blk d + e;
        } =&gt; 107,

        // The else branch catches everything not already captured.
        // Else branches are mandatory unless the entire range of values
        // is handled.
        else =&gt; 9,
    };

    try expect(b == 1);
}

// Switch expressions can be used outside a function:
const os_msg = switch (builtin.target.os.tag) {
    .linux =&gt; &quot;we found a linux user&quot;,
    else =&gt; &quot;not a linux user&quot;,
};

// Inside a function, switch statements implicitly are compile-time
// evaluated if the target expression is compile-time known.
test &quot;switch inside function&quot; {
    switch (builtin.target.os.tag) {
        .fuchsia =&gt; {
            // On an OS other than fuchsia, block is not even analyzed,
            // so this compile error is not triggered.
            // On fuchsia this compile error would be triggered.
            @compileError(&quot;fuchsia not supported&quot;);
        },
        else =&gt; {},
    }
}</code></pre>
<figcaption>test_switch.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_switch.zig
1/2 test_switch.test.switch simple...OK
2/2 test_switch.test.switch inside function...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

[`switch`]{.tok-kw} can be used to capture the field values of a [Tagged
union](#Tagged-union). Modifications to the field values can be done by
placing a `*` before the capture variable name, turning it into a
pointer.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;switch on tagged union&quot; {
    const Point = struct {
        x: u8,
        y: u8,
    };
    const Item = union(enum) {
        a: u32,
        c: Point,
        d,
        e: u32,
    };

    var a = Item{ .c = Point{ .x = 1, .y = 2 } };

    // Switching on more complex enums is allowed.
    const b = switch (a) {
        // A capture group is allowed on a match, and will return the enum
        // value matched. If the payload types of both cases are the same
        // they can be put into the same switch prong.
        Item.a, Item.e =&gt; |item| item,

        // A reference to the matched value can be obtained using `*` syntax.
        Item.c =&gt; |*item| blk: {
            item.*.x += 1;
            break :blk 6;
        },

        // No else is required if the types cases was exhaustively handled
        Item.d =&gt; 8,
    };

    try expect(b == 6);
    try expect(a.c.x == 2);
}</code></pre>
<figcaption>test_switch_tagged_union.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_switch_tagged_union.zig
1/1 test_switch_tagged_union.test.switch on tagged union...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [comptime](#comptime)
- [enum](#enum)
- [\@compileError](#compileError)
- [Compile Variables](#Compile-Variables)

### [Exhaustive Switching](#toc-Exhaustive-Switching) [§](#Exhaustive-Switching){.hdr} {#Exhaustive-Switching}

When a [`switch`]{.tok-kw} expression does not have an [`else`]{.tok-kw}
clause, it must exhaustively list all the possible values. Failure to do
so is a compile error:

<figure>
<pre><code>const Color = enum {
    auto,
    off,
    on,
};

test &quot;exhaustive switching&quot; {
    const color = Color.off;
    switch (color) {
        Color.auto =&gt; {},
        Color.on =&gt; {},
    }
}</code></pre>
<figcaption>test_unhandled_enumeration_value.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_unhandled_enumeration_value.zig
doc/langref/test_unhandled_enumeration_value.zig:9:5: error: switch must handle all possibilities
    switch (color) {
    ^~~~~~
doc/langref/test_unhandled_enumeration_value.zig:3:5: note: unhandled enumeration value: &#39;off&#39;
    off,
    ^~~
doc/langref/test_unhandled_enumeration_value.zig:1:15: note: enum &#39;test_unhandled_enumeration_value.Color&#39; declared here
const Color = enum {
              ^~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Switching with Enum Literals](#toc-Switching-with-Enum-Literals) [§](#Switching-with-Enum-Literals){.hdr} {#Switching-with-Enum-Literals}

[Enum Literals](#Enum-Literals) can be useful to use with
[`switch`]{.tok-kw} to avoid repetitively specifying [enum](#enum) or
[union](#union) types:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const Color = enum {
    auto,
    off,
    on,
};

test &quot;enum literals with switch&quot; {
    const color = Color.off;
    const result = switch (color) {
        .auto =&gt; false,
        .on =&gt; false,
        .off =&gt; true,
    };
    try expect(result);
}</code></pre>
<figcaption>test_exhaustive_switch.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_exhaustive_switch.zig
1/1 test_exhaustive_switch.test.enum literals with switch...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Labeled switch](#toc-Labeled-switch) [§](#Labeled-switch){.hdr} {#Labeled-switch}

When a switch statement is labeled, it can be referenced from a
[`break`]{.tok-kw} or [`continue`]{.tok-kw}. [`break`]{.tok-kw} will
return a value from the [`switch`]{.tok-kw}.

A [`continue`]{.tok-kw} targeting a switch must have an operand. When
executed, it will jump to the matching prong, as if the
[`switch`]{.tok-kw} were executed again with the
[`continue`]{.tok-kw}\'s operand replacing the initial switch value.

<figure>
<pre><code>const std = @import(&quot;std&quot;);

test &quot;switch continue&quot; {
    sw: switch (@as(i32, 5)) {
        5 =&gt; continue :sw 4,

        // `continue` can occur multiple times within a single switch prong.
        2...4 =&gt; |v| {
            if (v &gt; 3) {
                continue :sw 2;
            } else if (v == 3) {

                // `break` can target labeled loops.
                break :sw;
            }

            continue :sw 1;
        },

        1 =&gt; return,

        else =&gt; unreachable,
    }
}</code></pre>
<figcaption>test_switch_continue.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_switch_continue.zig
1/1 test_switch_continue.test.switch continue...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Semantically, this is equivalent to the following loop:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

test &quot;switch continue, equivalent loop&quot; {
    var sw: i32 = 5;
    while (true) {
        switch (sw) {
            5 =&gt; {
                sw = 4;
                continue;
            },
            2...4 =&gt; |v| {
                if (v &gt; 3) {
                    sw = 2;
                    continue;
                } else if (v == 3) {
                    break;
                }

                sw = 1;
                continue;
            },
            1 =&gt; return,
            else =&gt; unreachable,
        }
    }
}</code></pre>
<figcaption>test_switch_continue_equivalent.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_switch_continue_equivalent.zig
1/1 test_switch_continue_equivalent.test.switch continue, equivalent loop...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

This can improve clarity of (for example) state machines, where the
syntax [`continue`]{.tok-kw}` :sw .next_state` is unambiguous, explicit,
and immediately understandable.

However, the motivating example is a switch on each element of an array,
where using a single switch can improve clarity and performance:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expectEqual = std.testing.expectEqual;

const Instruction = enum {
    add,
    mul,
    end,
};

fn evaluate(initial_stack: []const i32, code: []const Instruction) !i32 {
    var stack = try std.BoundedArray(i32, 8).fromSlice(initial_stack);
    var ip: usize = 0;

    return vm: switch (code[ip]) {
        // Because all code after `continue` is unreachable, this branch does
        // not provide a result.
        .add =&gt; {
            try stack.append(stack.pop().? + stack.pop().?);

            ip += 1;
            continue :vm code[ip];
        },
        .mul =&gt; {
            try stack.append(stack.pop().? * stack.pop().?);

            ip += 1;
            continue :vm code[ip];
        },
        .end =&gt; stack.pop().?,
    };
}

test &quot;evaluate&quot; {
    const result = try evaluate(&amp;.{ 7, 2, -3 }, &amp;.{ .mul, .add, .end });
    try expectEqual(1, result);
}</code></pre>
<figcaption>test_switch_dispatch_loop.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_switch_dispatch_loop.zig
1/1 test_switch_dispatch_loop.test.evaluate...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

If the operand to [`continue`]{.tok-kw} is [comptime](#comptime)-known,
then it can be lowered to an unconditional branch to the relevant case.
Such a branch is perfectly predicted, and hence typically very fast to
execute.

If the operand is runtime-known, each [`continue`]{.tok-kw} can embed a
conditional branch inline (ideally through a jump table), which allows a
CPU to predict its target independently of any other prong. A loop-based
lowering would force every branch through the same dispatch point,
hindering branch prediction.

### [Inline Switch Prongs](#toc-Inline-Switch-Prongs) [§](#Inline-Switch-Prongs){.hdr} {#Inline-Switch-Prongs}

Switch prongs can be marked as [`inline`]{.tok-kw} to generate the
prong\'s body for each possible value it could have, making the captured
value [comptime](#comptime).

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;
const expectError = std.testing.expectError;

fn isFieldOptional(comptime T: type, field_index: usize) !bool {
    const fields = @typeInfo(T).@&quot;struct&quot;.fields;
    return switch (field_index) {
        // This prong is analyzed twice with `idx` being a
        // comptime-known value each time.
        inline 0, 1 =&gt; |idx| @typeInfo(fields[idx].type) == .optional,
        else =&gt; return error.IndexOutOfBounds,
    };
}

const Struct1 = struct { a: u32, b: ?u32 };

test &quot;using @typeInfo with runtime values&quot; {
    var index: usize = 0;
    try expect(!try isFieldOptional(Struct1, index));
    index += 1;
    try expect(try isFieldOptional(Struct1, index));
    index += 1;
    try expectError(error.IndexOutOfBounds, isFieldOptional(Struct1, index));
}

// Calls to `isFieldOptional` on `Struct1` get unrolled to an equivalent
// of this function:
fn isFieldOptionalUnrolled(field_index: usize) !bool {
    return switch (field_index) {
        0 =&gt; false,
        1 =&gt; true,
        else =&gt; return error.IndexOutOfBounds,
    };
}</code></pre>
<figcaption>test_inline_switch.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_inline_switch.zig
1/1 test_inline_switch.test.using @typeInfo with runtime values...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

The [`inline`]{.tok-kw} keyword may also be combined with ranges:

<figure>
<pre><code>fn isFieldOptional(comptime T: type, field_index: usize) !bool {
    const fields = @typeInfo(T).@&quot;struct&quot;.fields;
    return switch (field_index) {
        inline 0...fields.len - 1 =&gt; |idx| @typeInfo(fields[idx].type) == .optional,
        else =&gt; return error.IndexOutOfBounds,
    };
}</code></pre>
<figcaption>inline_prong_range.zig</figcaption>
</figure>

[`inline`]{.tok-kw}` `[`else`]{.tok-kw} prongs can be used as a type
safe alternative to [`inline`]{.tok-kw}` `[`for`]{.tok-kw} loops:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const SliceTypeA = extern struct {
    len: usize,
    ptr: [*]u32,
};
const SliceTypeB = extern struct {
    ptr: [*]SliceTypeA,
    len: usize,
};
const AnySlice = union(enum) {
    a: SliceTypeA,
    b: SliceTypeB,
    c: []const u8,
    d: []AnySlice,
};

fn withFor(any: AnySlice) usize {
    const Tag = @typeInfo(AnySlice).@&quot;union&quot;.tag_type.?;
    inline for (@typeInfo(Tag).@&quot;enum&quot;.fields) |field| {
        // With `inline for` the function gets generated as
        // a series of `if` statements relying on the optimizer
        // to convert it to a switch.
        if (field.value == @intFromEnum(any)) {
            return @field(any, field.name).len;
        }
    }
    // When using `inline for` the compiler doesn&#39;t know that every
    // possible case has been handled requiring an explicit `unreachable`.
    unreachable;
}

fn withSwitch(any: AnySlice) usize {
    return switch (any) {
        // With `inline else` the function is explicitly generated
        // as the desired switch and the compiler can check that
        // every possible case is handled.
        inline else =&gt; |slice| slice.len,
    };
}

test &quot;inline for and inline else similarity&quot; {
    const any = AnySlice{ .c = &quot;hello&quot; };
    try expect(withFor(any) == 5);
    try expect(withSwitch(any) == 5);
}</code></pre>
<figcaption>test_inline_else.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_inline_else.zig
1/1 test_inline_else.test.inline for and inline else similarity...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

When using an inline prong switching on an union an additional capture
can be used to obtain the union\'s enum tag value.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const U = union(enum) {
    a: u32,
    b: f32,
};

fn getNum(u: U) u32 {
    switch (u) {
        // Here `num` is a runtime-known value that is either
        // `u.a` or `u.b` and `tag` is `u`&#39;s comptime-known tag value.
        inline else =&gt; |num, tag| {
            if (tag == .b) {
                return @intFromFloat(num);
            }
            return num;
        },
    }
}

test &quot;test&quot; {
    const u = U{ .b = 42 };
    try expect(getNum(u) == 42);
}</code></pre>
<figcaption>test_inline_switch_union_tag.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_inline_switch_union_tag.zig
1/1 test_inline_switch_union_tag.test.test...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [inline while](#inline-while)
- [inline for](#inline-for)

## [while](#toc-while) [§](#while){.hdr}

A while loop is used to repeatedly execute an expression until some
condition is no longer true.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;while basic&quot; {
    var i: usize = 0;
    while (i &lt; 10) {
        i += 1;
    }
    try expect(i == 10);
}</code></pre>
<figcaption>test_while.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_while.zig
1/1 test_while.test.while basic...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Use [`break`]{.tok-kw} to exit a while loop early.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;while break&quot; {
    var i: usize = 0;
    while (true) {
        if (i == 10)
            break;
        i += 1;
    }
    try expect(i == 10);
}</code></pre>
<figcaption>test_while_break.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_while_break.zig
1/1 test_while_break.test.while break...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Use [`continue`]{.tok-kw} to jump back to the beginning of the loop.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;while continue&quot; {
    var i: usize = 0;
    while (true) {
        i += 1;
        if (i &lt; 10)
            continue;
        break;
    }
    try expect(i == 10);
}</code></pre>
<figcaption>test_while_continue.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_while_continue.zig
1/1 test_while_continue.test.while continue...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

While loops support a continue expression which is executed when the
loop is continued. The [`continue`]{.tok-kw} keyword respects this
expression.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;while loop continue expression&quot; {
    var i: usize = 0;
    while (i &lt; 10) : (i += 1) {}
    ```
