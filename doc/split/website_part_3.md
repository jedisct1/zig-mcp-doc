```
try expect(i == 10);
}

test &quot;while loop continue expression, more complicated&quot; {
    var i: usize = 1;
    var j: usize = 1;
    while (i * j &lt; 2000) : ({
        i *= 2;
        j *= 3;
    }) {
        const my_ij = i * j;
        try expect(my_ij &lt; 2000);
    }
}</code></pre>
<figcaption>test_while_continue_expression.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_while_continue_expression.zig
1/2 test_while_continue_expression.test.while loop continue expression...OK
2/2 test_while_continue_expression.test.while loop continue expression, more complicated...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

While loops are expressions. The result of the expression is the result
of the [`else`]{.tok-kw} clause of a while loop, which is executed when
the condition of the while loop is tested as false.

[`break`]{.tok-kw}, like [`return`]{.tok-kw}, accepts a value parameter.
This is the result of the [`while`]{.tok-kw} expression. When you
[`break`]{.tok-kw} from a while loop, the [`else`]{.tok-kw} branch is
not evaluated.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;while else&quot; {
    try expect(rangeHasNumber(0, 10, 5));
    try expect(!rangeHasNumber(0, 10, 15));
}

fn rangeHasNumber(begin: usize, end: usize, number: usize) bool {
    var i = begin;
    return while (i &lt; end) : (i += 1) {
        if (i == number) {
            break true;
        }
    } else false;
}</code></pre>
<figcaption>test_while_else.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_while_else.zig
1/1 test_while_else.test.while else...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Labeled while](#toc-Labeled-while) [§](#Labeled-while){.hdr} {#Labeled-while}

When a [`while`]{.tok-kw} loop is labeled, it can be referenced from a
[`break`]{.tok-kw} or [`continue`]{.tok-kw} from within a nested loop:

<figure>
<pre><code>test &quot;nested break&quot; {
    outer: while (true) {
        while (true) {
            break :outer;
        }
    }
}

test &quot;nested continue&quot; {
    var i: usize = 0;
    outer: while (i &lt; 10) : (i += 1) {
        while (true) {
            continue :outer;
        }
    }
}</code></pre>
<figcaption>test_while_nested_break.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_while_nested_break.zig
1/2 test_while_nested_break.test.nested break...OK
2/2 test_while_nested_break.test.nested continue...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [while with Optionals](#toc-while-with-Optionals) [§](#while-with-Optionals){.hdr} {#while-with-Optionals}

Just like [if](#if) expressions, while loops can take an optional as the
condition and capture the payload. When [null](#null) is encountered the
loop exits.

When the `|x|` syntax is present on a [`while`]{.tok-kw} expression, the
while condition must have an [Optional Type](#Optional-Type).

The [`else`]{.tok-kw} branch is allowed on optional iteration. In this
case, it will be executed on the first null value encountered.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;while null capture&quot; {
    var sum1: u32 = 0;
    numbers_left = 3;
    while (eventuallyNullSequence()) |value| {
        sum1 += value;
    }
    try expect(sum1 == 3);

    // null capture with an else block
    var sum2: u32 = 0;
    numbers_left = 3;
    while (eventuallyNullSequence()) |value| {
        sum2 += value;
    } else {
        try expect(sum2 == 3);
    }

    // null capture with a continue expression
    var i: u32 = 0;
    var sum3: u32 = 0;
    numbers_left = 3;
    while (eventuallyNullSequence()) |value| : (i += 1) {
        sum3 += value;
    }
    try expect(i == 3);
}

var numbers_left: u32 = undefined;
fn eventuallyNullSequence() ?u32 {
    return if (numbers_left == 0) null else blk: {
        numbers_left -= 1;
        break :blk numbers_left;
    };
}</code></pre>
<figcaption>test_while_null_capture.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_while_null_capture.zig
1/1 test_while_null_capture.test.while null capture...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [while with Error Unions](#toc-while-with-Error-Unions) [§](#while-with-Error-Unions){.hdr} {#while-with-Error-Unions}

Just like [if](#if) expressions, while loops can take an error union as
the condition and capture the payload or the error code. When the
condition results in an error code the else branch is evaluated and the
loop is finished.

When the [`else`]{.tok-kw}` |x|` syntax is present on a
[`while`]{.tok-kw} expression, the while condition must have an [Error
Union Type](#Error-Union-Type).

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;while error union capture&quot; {
    var sum1: u32 = 0;
    numbers_left = 3;
    while (eventuallyErrorSequence()) |value| {
        sum1 += value;
    } else |err| {
        try expect(err == error.ReachedZero);
    }
}

var numbers_left: u32 = undefined;

fn eventuallyErrorSequence() anyerror!u32 {
    return if (numbers_left == 0) error.ReachedZero else blk: {
        numbers_left -= 1;
        break :blk numbers_left;
    };
}</code></pre>
<figcaption>test_while_error_capture.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_while_error_capture.zig
1/1 test_while_error_capture.test.while error union capture...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [inline while](#toc-inline-while) [§](#inline-while){.hdr}

While loops can be inlined. This causes the loop to be unrolled, which
allows the code to do some things which only work at compile time, such
as use types as first class values.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;inline while loop&quot; {
    comptime var i = 0;
    var sum: usize = 0;
    inline while (i &lt; 3) : (i += 1) {
        const T = switch (i) {
            0 =&gt; f32,
            1 =&gt; i8,
            2 =&gt; bool,
            else =&gt; unreachable,
        };
        sum += typeNameLength(T);
    }
    try expect(sum == 9);
}

fn typeNameLength(comptime T: type) usize {
    return @typeName(T).len;
}</code></pre>
<figcaption>test_inline_while.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_inline_while.zig
1/1 test_inline_while.test.inline while loop...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

It is recommended to use [`inline`]{.tok-kw} loops only for one of these
reasons:

- You need the loop to execute at [comptime](#comptime) for the
  semantics to work.
- You have a benchmark to prove that forcibly unrolling the loop in this
  way is measurably faster.

See also:

- [if](#if)
- [Optionals](#Optionals)
- [Errors](#Errors)
- [comptime](#comptime)
- [unreachable](#unreachable)

## [for](#toc-for) [§](#for){.hdr}

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;for basics&quot; {
    const items = [_]i32{ 4, 5, 3, 4, 0 };
    var sum: i32 = 0;

    // For loops iterate over slices and arrays.
    for (items) |value| {
        // Break and continue are supported.
        if (value == 0) {
            continue;
        }
        sum += value;
    }
    try expect(sum == 16);

    // To iterate over a portion of a slice, reslice.
    for (items[0..1]) |value| {
        sum += value;
    }
    try expect(sum == 20);

    // To access the index of iteration, specify a second condition as well
    // as a second capture value.
    var sum2: i32 = 0;
    for (items, 0..) |_, i| {
        try expect(@TypeOf(i) == usize);
        sum2 += @as(i32, @intCast(i));
    }
    try expect(sum2 == 10);

    // To iterate over consecutive integers, use the range syntax.
    // Unbounded range is always a compile error.
    var sum3: usize = 0;
    for (0..5) |i| {
        sum3 += i;
    }
    try expect(sum3 == 10);
}

test &quot;multi object for&quot; {
    const items = [_]usize{ 1, 2, 3 };
    const items2 = [_]usize{ 4, 5, 6 };
    var count: usize = 0;

    // Iterate over multiple objects.
    // All lengths must be equal at the start of the loop, otherwise detectable
    // illegal behavior occurs.
    for (items, items2) |i, j| {
        count += i + j;
    }

    try expect(count == 21);
}

test &quot;for reference&quot; {
    var items = [_]i32{ 3, 4, 2 };

    // Iterate over the slice by reference by
    // specifying that the capture value is a pointer.
    for (&amp;items) |*value| {
        value.* += 1;
    }

    try expect(items[0] == 4);
    try expect(items[1] == 5);
    try expect(items[2] == 3);
}

test &quot;for else&quot; {
    // For allows an else attached to it, the same as a while loop.
    const items = [_]?i32{ 3, 4, null, 5 };

    // For loops can also be used as expressions.
    // Similar to while loops, when you break from a for loop, the else branch is not evaluated.
    var sum: i32 = 0;
    const result = for (items) |value| {
        if (value != null) {
            sum += value.?;
        }
    } else blk: {
        try expect(sum == 12);
        break :blk sum;
    };
    try expect(result == 12);
}</code></pre>
<figcaption>test_for.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_for.zig
1/4 test_for.test.for basics...OK
2/4 test_for.test.multi object for...OK
3/4 test_for.test.for reference...OK
4/4 test_for.test.for else...OK
All 4 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Labeled for](#toc-Labeled-for) [§](#Labeled-for){.hdr} {#Labeled-for}

When a [`for`]{.tok-kw} loop is labeled, it can be referenced from a
[`break`]{.tok-kw} or [`continue`]{.tok-kw} from within a nested loop:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;nested break&quot; {
    var count: usize = 0;
    outer: for (1..6) |_| {
        for (1..6) |_| {
            count += 1;
            break :outer;
        }
    }
    try expect(count == 1);
}

test &quot;nested continue&quot; {
    var count: usize = 0;
    outer: for (1..9) |_| {
        for (1..6) |_| {
            count += 1;
            continue :outer;
        }
    }

    try expect(count == 8);
}</code></pre>
<figcaption>test_for_nested_break.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_for_nested_break.zig
1/2 test_for_nested_break.test.nested break...OK
2/2 test_for_nested_break.test.nested continue...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [inline for](#toc-inline-for) [§](#inline-for){.hdr}

For loops can be inlined. This causes the loop to be unrolled, which
allows the code to do some things which only work at compile time, such
as use types as first class values. The capture value and iterator value
of inlined for loops are compile-time known.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;inline for loop&quot; {
    const nums = [_]i32{ 2, 4, 6 };
    var sum: usize = 0;
    inline for (nums) |i| {
        const T = switch (i) {
            2 =&gt; f32,
            4 =&gt; i8,
            6 =&gt; bool,
            else =&gt; unreachable,
        };
        sum += typeNameLength(T);
    }
    try expect(sum == 9);
}

fn typeNameLength(comptime T: type) usize {
    return @typeName(T).len;
}</code></pre>
<figcaption>test_inline_for.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_inline_for.zig
1/1 test_inline_for.test.inline for loop...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

It is recommended to use [`inline`]{.tok-kw} loops only for one of these
reasons:

- You need the loop to execute at [comptime](#comptime) for the
  semantics to work.
- You have a benchmark to prove that forcibly unrolling the loop in this
  way is measurably faster.

See also:

- [while](#while)
- [comptime](#comptime)
- [Arrays](#Arrays)
- [Slices](#Slices)

## [if](#toc-if) [§](#if){.hdr}

<figure>
<pre><code>// If expressions have three uses, corresponding to the three types:
// * bool
// * ?T
// * anyerror!T

const expect = @import(&quot;std&quot;).testing.expect;

test &quot;if expression&quot; {
    // If expressions are used instead of a ternary expression.
    const a: u32 = 5;
    const b: u32 = 4;
    const result = if (a != b) 47 else 3089;
    try expect(result == 47);
}

test &quot;if boolean&quot; {
    // If expressions test boolean conditions.
    const a: u32 = 5;
    const b: u32 = 4;
    if (a != b) {
        try expect(true);
    } else if (a == 9) {
        unreachable;
    } else {
        unreachable;
    }
}

test &quot;if error union&quot; {
    // If expressions test for errors.
    // Note the |err| capture on the else.

    const a: anyerror!u32 = 0;
    if (a) |value| {
        try expect(value == 0);
    } else |err| {
        _ = err;
        unreachable;
    }

    const b: anyerror!u32 = error.BadValue;
    if (b) |value| {
        _ = value;
        unreachable;
    } else |err| {
        try expect(err == error.BadValue);
    }

    // The else and |err| capture is strictly required.
    if (a) |value| {
        try expect(value == 0);
    } else |_| {}

    // To check only the error value, use an empty block expression.
    if (b) |_| {} else |err| {
        try expect(err == error.BadValue);
    }

    // Access the value by reference using a pointer capture.
    var c: anyerror!u32 = 3;
    if (c) |*value| {
        value.* = 9;
    } else |_| {
        unreachable;
    }

    if (c) |value| {
        try expect(value == 9);
    } else |_| {
        unreachable;
    }
}</code></pre>
<figcaption>test_if.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_if.zig
1/3 test_if.test.if expression...OK
2/3 test_if.test.if boolean...OK
3/3 test_if.test.if error union...OK
All 3 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [if with Optionals](#toc-if-with-Optionals) [§](#if-with-Optionals){.hdr} {#if-with-Optionals}

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;if optional&quot; {
    // If expressions test for null.

    const a: ?u32 = 0;
    if (a) |value| {
        try expect(value == 0);
    } else {
        unreachable;
    }

    const b: ?u32 = null;
    if (b) |_| {
        unreachable;
    } else {
        try expect(true);
    }

    // The else is not required.
    if (a) |value| {
        try expect(value == 0);
    }

    // To test against null only, use the binary equality operator.
    if (b == null) {
        try expect(true);
    }

    // Access the value by reference using a pointer capture.
    var c: ?u32 = 3;
    if (c) |*value| {
        value.* = 2;
    }

    if (c) |value| {
        try expect(value == 2);
    } else {
        unreachable;
    }
}

test &quot;if error union with optional&quot; {
    // If expressions test for errors before unwrapping optionals.
    // The |optional_value| capture&#39;s type is ?u32.

    const a: anyerror!?u32 = 0;
    if (a) |optional_value| {
        try expect(optional_value.? == 0);
    } else |err| {
        _ = err;
        unreachable;
    }

    const b: anyerror!?u32 = null;
    if (b) |optional_value| {
        try expect(optional_value == null);
    } else |_| {
        unreachable;
    }

    const c: anyerror!?u32 = error.BadValue;
    if (c) |optional_value| {
        _ = optional_value;
        unreachable;
    } else |err| {
        try expect(err == error.BadValue);
    }

    // Access the value by reference by using a pointer capture each time.
    var d: anyerror!?u32 = 3;
    if (d) |*optional_value| {
        if (optional_value.*) |*value| {
            value.* = 9;
        }
    } else |_| {
        unreachable;
    }

    if (d) |optional_value| {
        try expect(optional_value.? == 9);
    } else |_| {
        unreachable;
    }
}</code></pre>
<figcaption>test_if_optionals.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_if_optionals.zig
1/2 test_if_optionals.test.if optional...OK
2/2 test_if_optionals.test.if error union with optional...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Optionals](#Optionals)
- [Errors](#Errors)

## [defer](#toc-defer) [§](#defer){.hdr}

Executes an expression unconditionally at scope exit.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;
const print = std.debug.print;

fn deferExample() !usize {
    var a: usize = 1;

    {
        defer a = 2;
        a = 1;
    }
    try expect(a == 2);

    a = 5;
    return a;
}

test &quot;defer basics&quot; {
    try expect((try deferExample()) == 5);
}</code></pre>
<figcaption>test_defer.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_defer.zig
1/1 test_defer.test.defer basics...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Defer expressions are evaluated in reverse order.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;
const print = std.debug.print;

test &quot;defer unwinding&quot; {
    print(&quot;\n&quot;, .{});

    defer {
        print(&quot;1 &quot;, .{});
    }
    defer {
        print(&quot;2 &quot;, .{});
    }
    if (false) {
        // defers are not run if they are never executed.
        defer {
            print(&quot;3 &quot;, .{});
        }
    }
}</code></pre>
<figcaption>defer_unwind.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test defer_unwind.zig
1/1 defer_unwind.test.defer unwinding...
2 1 OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Inside a defer expression the return statement is not allowed.

<figure>
<pre><code>fn deferInvalidExample() !void {
    defer {
        return error.DeferError;
    }

    return error.DeferError;
}</code></pre>
<figcaption>test_invalid_defer.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_invalid_defer.zig
doc/langref/test_invalid_defer.zig:3:9: error: cannot return from defer expression
        return error.DeferError;
        ^~~~~~~~~~~~~~~~~~~~~~~
doc/langref/test_invalid_defer.zig:2:5: note: defer expression here
    defer {
    ^~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Errors](#Errors)

## [unreachable](#toc-unreachable) [§](#unreachable){.hdr}

In [Debug](#Debug) and [ReleaseSafe](#ReleaseSafe) mode
[`unreachable`]{.tok-kw} emits a call to `panic` with the message
`reached unreachable code`.

In [ReleaseFast](#ReleaseFast) and [ReleaseSmall](#ReleaseSmall) mode,
the optimizer uses the assumption that [`unreachable`]{.tok-kw} code
will never be hit to perform optimizations.

### [Basics](#toc-Basics) [§](#Basics){.hdr} {#Basics}

<figure>
<pre><code>// unreachable is used to assert that control flow will never reach a
// particular location:
test &quot;basic math&quot; {
    const x = 1;
    const y = 2;
    if (x + y != 3) {
        unreachable;
    }
}</code></pre>
<figcaption>test_unreachable.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_unreachable.zig
1/1 test_unreachable.test.basic math...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

In fact, this is how `std.debug.assert` is implemented:

<figure>
<pre><code>// This is how std.debug.assert is implemented
fn assert(ok: bool) void {
    if (!ok) unreachable; // assertion failure
}

// This test will fail because we hit unreachable.
test &quot;this will fail&quot; {
    assert(false);
}</code></pre>
<figcaption>test_assertion_failure.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_assertion_failure.zig
1/1 test_assertion_failure.test.this will fail...thread 220435 panic: reached unreachable code
/home/andy/src/zig/doc/langref/test_assertion_failure.zig:3:14: 0x10489ad in assert (test)
    if (!ok) unreachable; // assertion failure
             ^
/home/andy/src/zig/doc/langref/test_assertion_failure.zig:8:11: 0x104897a in test.this will fail (test)
    assert(false);
          ^
/home/andy/src/zig/lib/compiler/test_runner.zig:214:25: 0x10eedd5 in mainTerminal (test)
        if (test_fn.func()) |_| {
                        ^
/home/andy/src/zig/lib/compiler/test_runner.zig:62:28: 0x10e736d in main (test)
        return mainTerminal();
                           ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10e68f2 in posixCallMainAndExit (test)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10e64cd in _start (test)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
error: the following test command crashed:
/home/andy/src/zig/.zig-cache/o/51c9599b1e9a8f93217f914df57d48a3/test --seed=0xcd3102a8</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [At Compile-Time](#toc-At-Compile-Time) [§](#At-Compile-Time){.hdr} {#At-Compile-Time}

<figure>
<pre><code>const assert = @import(&quot;std&quot;).debug.assert;

test &quot;type of unreachable&quot; {
    comptime {
        // The type of unreachable is noreturn.

        // However this assertion will still fail to compile because
        // unreachable expressions are compile errors.

        assert(@TypeOf(unreachable) == noreturn);
    }
}</code></pre>
<figcaption>test_comptime_unreachable.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_unreachable.zig
doc/langref/test_comptime_unreachable.zig:10:16: error: unreachable code
        assert(@TypeOf(unreachable) == noreturn);
               ^~~~~~~~~~~~~~~~~~~~
doc/langref/test_comptime_unreachable.zig:10:24: note: control flow is diverted here
        assert(@TypeOf(unreachable) == noreturn);
                       ^~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Zig Test](#Zig-Test)
- [Build Mode](#Build-Mode)
- [comptime](#comptime)

## [noreturn](#toc-noreturn) [§](#noreturn){.hdr}

[`noreturn`]{.tok-type} is the type of:

- [`break`]{.tok-kw}
- [`continue`]{.tok-kw}
- [`return`]{.tok-kw}
- [`unreachable`]{.tok-kw}
- [`while`]{.tok-kw}` (`[`true`]{.tok-null}`) {}`

When resolving types together, such as [`if`]{.tok-kw} clauses or
[`switch`]{.tok-kw} prongs, the [`noreturn`]{.tok-type} type is
compatible with every other type. Consider:

<figure>
<pre><code>fn foo(condition: bool, b: u32) void {
    const a = if (condition) b else return;
    _ = a;
    @panic(&quot;do something with a&quot;);
}
test &quot;noreturn&quot; {
    foo(false, 1);
}</code></pre>
<figcaption>test_noreturn.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_noreturn.zig
1/1 test_noreturn.test.noreturn...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Another use case for [`noreturn`]{.tok-type} is the `exit` function:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const builtin = @import(&quot;builtin&quot;);
const native_arch = builtin.cpu.arch;
const expect = std.testing.expect;

const WINAPI: std.builtin.CallingConvention = if (native_arch == .x86) .Stdcall else .C;
extern &quot;kernel32&quot; fn ExitProcess(exit_code: c_uint) callconv(WINAPI) noreturn;

test &quot;foo&quot; {
    const value = bar() catch ExitProcess(1);
    try expect(value == 1234);
}

fn bar() anyerror!u32 {
    return 1234;
}</code></pre>
<figcaption>test_noreturn_from_exit.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_noreturn_from_exit.zig -target x86_64-windows --test-no-exec</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [Functions](#toc-Functions) [§](#Functions){.hdr} {#Functions}

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const builtin = @import(&quot;builtin&quot;);
const native_arch = builtin.cpu.arch;
const expect = std.testing.expect;

// Functions are declared like this
fn add(a: i8, b: i8) i8 {
    if (a == 0) {
        return b;
    }

    return a + b;
}

// The export specifier makes a function externally visible in the generated
// object file, and makes it use the C ABI.
export fn sub(a: i8, b: i8) i8 {
    return a - b;
}

// The extern specifier is used to declare a function that will be resolved
// at link time, when linking statically, or at runtime, when linking
// dynamically. The quoted identifier after the extern keyword specifies
// the library that has the function. (e.g. &quot;c&quot; -&gt; libc.so)
// The callconv specifier changes the calling convention of the function.
const WINAPI: std.builtin.CallingConvention = if (native_arch == .x86) .Stdcall else .C;
extern &quot;kernel32&quot; fn ExitProcess(exit_code: u32) callconv(WINAPI) noreturn;
extern &quot;c&quot; fn atan2(a: f64, b: f64) f64;

// The @branchHint builtin can be used to tell the optimizer that a function is rarely called (&quot;cold&quot;).
fn abort() noreturn {
    @branchHint(.cold);
    while (true) {}
}

// The naked calling convention makes a function not have any function prologue or epilogue.
// This can be useful when integrating with assembly.
fn _start() callconv(.Naked) noreturn {
    abort();
}

// The inline calling convention forces a function to be inlined at all call sites.
// If the function cannot be inlined, it is a compile-time error.
inline fn shiftLeftOne(a: u32) u32 {
    return a &lt;&lt; 1;
}

// The pub specifier allows the function to be visible when importing.
// Another file can use @import and call sub2
pub fn sub2(a: i8, b: i8) i8 {
    return a - b;
}

// Function pointers are prefixed with `*const `.
const Call2Op = *const fn (a: i8, b: i8) i8;
fn doOp(fnCall: Call2Op, op1: i8, op2: i8) i8 {
    return fnCall(op1, op2);
}

test &quot;function&quot; {
    try expect(doOp(add, 5, 6) == 11);
    try expect(doOp(sub2, 5, 6) == -1);
}</code></pre>
<figcaption>test_functions.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_functions.zig
1/1 test_functions.test.function...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

There is a difference between a function *body* and a function
*pointer*. Function bodies are [comptime](#comptime)-only types while
function [Pointers](#Pointers) may be runtime-known.

### [Pass-by-value Parameters](#toc-Pass-by-value-Parameters) [§](#Pass-by-value-Parameters){.hdr} {#Pass-by-value-Parameters}

Primitive types such as [Integers](#Integers) and [Floats](#Floats)
passed as parameters are copied, and then the copy is available in the
function body. This is called \"passing by value\". Copying a primitive
type is essentially free and typically involves nothing more than
setting a register.

Structs, unions, and arrays can sometimes be more efficiently passed as
a reference, since a copy could be arbitrarily expensive depending on
the size. When these types are passed as parameters, Zig may choose to
copy and pass by value, or pass by reference, whichever way Zig decides
will be faster. This is made possible, in part, by the fact that
parameters are immutable.

<figure>
<pre><code>const Point = struct {
    x: i32,
    y: i32,
};

fn foo(point: Point) i32 {
    // Here, `point` could be a reference, or a copy. The function body
    // can ignore the difference and treat it as a value. Be very careful
    // taking the address of the parameter - it should be treated as if
    // the address will become invalid when the function returns.
    return point.x + point.y;
}

const expect = @import(&quot;std&quot;).testing.expect;

test &quot;pass struct to function&quot; {
    try expect(foo(Point{ .x = 1, .y = 2 }) == 3);
}</code></pre>
<figcaption>test_pass_by_reference_or_value.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_pass_by_reference_or_value.zig
1/1 test_pass_by_reference_or_value.test.pass struct to function...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

For extern functions, Zig follows the C ABI for passing structs and
unions by value.

### [Function Parameter Type Inference](#toc-Function-Parameter-Type-Inference) [§](#Function-Parameter-Type-Inference){.hdr} {#Function-Parameter-Type-Inference}

Function parameters can be declared with [`anytype`]{.tok-kw} in place
of the type. In this case the parameter types will be inferred when the
function is called. Use [\@TypeOf](#TypeOf) and [\@typeInfo](#typeInfo)
to get information about the inferred type.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

fn addFortyTwo(x: anytype) @TypeOf(x) {
    return x + 42;
}

test &quot;fn type inference&quot; {
    try expect(addFortyTwo(1) == 43);
    try expect(@TypeOf(addFortyTwo(1)) == comptime_int);
    const y: i64 = 2;
    try expect(addFortyTwo(y) == 44);
    try expect(@TypeOf(addFortyTwo(y)) == i64);
}</code></pre>
<figcaption>test_fn_type_inference.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_fn_type_inference.zig
1/1 test_fn_type_inference.test.fn type inference...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [inline fn](#toc-inline-fn) [§](#inline-fn){.hdr}

Adding the [`inline`]{.tok-kw} keyword to a function definition makes
that function become *semantically inlined* at the callsite. This is not
a hint to be possibly observed by optimization passes, but has
implications on the types and values involved in the function call.

Unlike normal function calls, arguments at an inline function callsite
which are compile-time known are treated as [Compile Time
Parameters](#Compile-Time-Parameters). This can potentially propagate
all the way to the return value:

<figure>
<pre><code>test &quot;inline function call&quot; {
    if (foo(1200, 34) != 1234) {
        @compileError(&quot;bad&quot;);
    }
}

inline fn foo(a: i32, b: i32) i32 {
    return a + b;
}</code></pre>
<figcaption>inline_call.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test inline_call.zig
1/1 inline_call.test.inline function call...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

If [`inline`]{.tok-kw} is removed, the test fails with the compile error
instead of passing.

It is generally better to let the compiler decide when to inline a
function, except for these scenarios:

- To change how many stack frames are in the call stack, for debugging
  purposes.
- To force comptime-ness of the arguments to propagate to the return
  value of the function, as in the above example.
- Real world performance measurements demand it.

Note that [`inline`]{.tok-kw} actually *restricts* what the compiler is
allowed to do. This can harm binary size, compilation speed, and even
runtime performance.

### [Function Reflection](#toc-Function-Reflection) [§](#Function-Reflection){.hdr} {#Function-Reflection}

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const math = std.math;
const testing = std.testing;

test &quot;fn reflection&quot; {
    try testing.expect(@typeInfo(@TypeOf(testing.expect)).@&quot;fn&quot;.params[0].type.? == bool);
    try testing.expect(@typeInfo(@TypeOf(testing.tmpDir)).@&quot;fn&quot;.return_type.? == testing.TmpDir);

    try testing.expect(@typeInfo(@TypeOf(math.Log2Int)).@&quot;fn&quot;.is_generic);
}</code></pre>
<figcaption>test_fn_reflection.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_fn_reflection.zig
1/1 test_fn_reflection.test.fn reflection...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [Errors](#toc-Errors) [§](#Errors){.hdr} {#Errors}

### [Error Set Type](#toc-Error-Set-Type) [§](#Error-Set-Type){.hdr} {#Error-Set-Type}

An error set is like an [enum](#enum). However, each error name across
the entire compilation gets assigned an unsigned integer greater than 0.
You are allowed to declare the same error name more than once, and if
you do, it gets assigned the same integer value.

The error set type defaults to a [`u16`]{.tok-type}, though if the
maximum number of distinct error values is provided via the
[\--error-limit \[num\]]{.kbd} command line parameter an integer type
with the minimum number of bits required to represent all of the error
values will be used.

You can [coerce](#Type-Coercion) an error from a subset to a superset:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

const FileOpenError = error{
    AccessDenied,
    OutOfMemory,
    FileNotFound,
};

const AllocationError = error{
    OutOfMemory,
};

test &quot;coerce subset to superset&quot; {
    const err = foo(AllocationError.OutOfMemory);
    try std.testing.expect(err == FileOpenError.OutOfMemory);
}

fn foo(err: AllocationError) FileOpenError {
    return err;
}</code></pre>
<figcaption>test_coerce_error_subset_to_superset.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_coerce_error_subset_to_superset.zig
1/1 test_coerce_error_subset_to_superset.test.coerce subset to superset...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

But you cannot [coerce](#Type-Coercion) an error from a superset to a
subset:

<figure>
<pre><code>const FileOpenError = error{
    AccessDenied,
    OutOfMemory,
    FileNotFound,
};

const AllocationError = error{
    OutOfMemory,
};

test &quot;coerce superset to subset&quot; {
    foo(FileOpenError.OutOfMemory) catch {};
}

fn foo(err: FileOpenError) AllocationError {
    return err;
}</code></pre>
<figcaption>test_coerce_error_superset_to_subset.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_coerce_error_superset_to_subset.zig
doc/langref/test_coerce_error_superset_to_subset.zig:16:12: error: expected type &#39;error{OutOfMemory}&#39;, found &#39;error{AccessDenied,OutOfMemory,FileNotFound}&#39;
    return err;
           ^~~
doc/langref/test_coerce_error_superset_to_subset.zig:16:12: note: &#39;error.AccessDenied&#39; not a member of destination error set
doc/langref/test_coerce_error_superset_to_subset.zig:16:12: note: &#39;error.FileNotFound&#39; not a member of destination error set
doc/langref/test_coerce_error_superset_to_subset.zig:15:28: note: function return type declared here
fn foo(err: FileOpenError) AllocationError {
                           ^~~~~~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

There is a shortcut for declaring an error set with only 1 value, and
then getting that value:

<figure>
<pre><code>const err = error.FileNotFound;</code></pre>
<figcaption>single_value_error_set_shortcut.zig</figcaption>
</figure>

This is equivalent to:

<figure>
<pre><code>const err = (error{FileNotFound}).FileNotFound;</code></pre>
<figcaption>single_value_error_set.zig</figcaption>
</figure>

This becomes useful when using [Inferred Error
Sets](#Inferred-Error-Sets).

#### [The Global Error Set](#toc-The-Global-Error-Set) [§](#The-Global-Error-Set){.hdr} {#The-Global-Error-Set}

[`anyerror`]{.tok-type} refers to the global error set. This is the
error set that contains all errors in the entire compilation unit, i.e.
it is the union of all other error sets.

You can [coerce](#Type-Coercion) any error set to the global one, and
you can explicitly cast an error of the global error set to a non-global
one. This inserts a language-level assert to make sure the error value
is in fact in the destination error set.

The global error set should generally be avoided because it prevents the
compiler from knowing what errors are possible at compile-time. Knowing
the error set at compile-time is better for generated documentation and
helpful error messages, such as forgetting a possible error value in a
[switch](#switch).

### [Error Union Type](#toc-Error-Union-Type) [§](#Error-Union-Type){.hdr} {#Error-Union-Type}

An error set type and normal type can be combined with the `!` binary
operator to form an error union type. You are likely to use an error
union type more often than an error set type by itself.

Here is a function to parse a string into a 64-bit integer:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const maxInt = std.math.maxInt;

pub fn parseU64(buf: []const u8, radix: u8) !u64 {
    var x: u64 = 0;

    for (buf) |c| {
        const digit = charToDigit(c);

        if (digit &gt;= radix) {
            return error.InvalidChar;
        }

        // x *= radix
        var ov = @mulWithOverflow(x, radix);
        if (ov[1] != 0) return error.OverFlow;

        // x += digit
        ov = @addWithOverflow(ov[0], digit);
        if (ov[1] != 0) return error.OverFlow;
        x = ov[0];
    }

    return x;
}

fn charToDigit(c: u8) u8 {
    return switch (c) {
        &#39;0&#39;...&#39;9&#39; =&gt; c - &#39;0&#39;,
        &#39;A&#39;...&#39;Z&#39; =&gt; c - &#39;A&#39; + 10,
        &#39;a&#39;...&#39;z&#39; =&gt; c - &#39;a&#39; + 10,
        else =&gt; maxInt(u8),
    };
}

test &quot;parse u64&quot; {
    const result = try parseU64(&quot;1234&quot;, 10);
    try std.testing.expect(result == 1234);
}</code></pre>
<figcaption>error_union_parsing_u64.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test error_union_parsing_u64.zig
1/1 error_union_parsing_u64.test.parse u64...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Notice the return type is `!`[`u64`]{.tok-type}. This means that the
function either returns an unsigned 64 bit integer, or an error. We left
off the error set to the left of the `!`, so the error set is inferred.

Within the function definition, you can see some return statements that
return an error, and at the bottom a return statement that returns a
[`u64`]{.tok-type}. Both types [coerce](#Type-Coercion) to
[`anyerror`]{.tok-type}`!`[`u64`]{.tok-type}.

What it looks like to use this function varies depending on what you\'re
trying to do. One of the following:

- You want to provide a default value if it returned an error.
- If it returned an error then you want to return the same error.
- You know with complete certainty it will not return an error, so want
  to unconditionally unwrap it.
- You want to take a different action for each possible error.

#### [catch](#toc-catch) [§](#catch){.hdr}

If you want to provide a default value, you can use the
[`catch`]{.tok-kw} binary operator:

<figure>
<pre><code>const parseU64 = @import(&quot;error_union_parsing_u64.zig&quot;).parseU64;

fn doAThing(str: []u8) void {
    const number = parseU64(str, 10) catch 13;
    _ = number; // ...
}</code></pre>
<figcaption>catch.zig</figcaption>
</figure>

In this code, `number` will be equal to the successfully parsed string,
or a default value of 13. The type of the right hand side of the binary
[`catch`]{.tok-kw} operator must match the unwrapped error union type,
or be of type [`noreturn`]{.tok-type}.

If you want to provide a default value with [`catch`]{.tok-kw} after
performing some logic, you can combine [`catch`]{.tok-kw} with named
[Blocks](#Blocks):

<figure>
<pre><code>const parseU64 = @import(&quot;error_union_parsing_u64.zig&quot;).parseU64;

fn doAThing(str: []u8) void {
    const number = parseU64(str, 10) catch blk: {
        // do things
        break :blk 13;
    };
    _ = number; // number is now initialized
}</code></pre>
<figcaption>handle_error_with_catch_block.zig.zig</figcaption>
</figure>

#### [try](#toc-try) [§](#try){.hdr}

Let\'s say you wanted to return the error if you got one, otherwise
continue with the function logic:

<figure>
<pre><code>const parseU64 = @import(&quot;error_union_parsing_u64.zig&quot;).parseU64;

fn doAThing(str: []u8) !void {
    const number = parseU64(str, 10) catch |err| return err;
    _ = number; // ...
}</code></pre>
<figcaption>catch_err_return.zig</figcaption>
</figure>

There is a shortcut for this. The [`try`]{.tok-kw} expression:

<figure>
<pre><code>const parseU64 = @import(&quot;error_union_parsing_u64.zig&quot;).parseU64;

fn doAThing(str: []u8) !void {
    const number = try parseU64(str, 10);
    _ = number; // ...
}</code></pre>
<figcaption>try.zig</figcaption>
</figure>

[`try`]{.tok-kw} evaluates an error union expression. If it is an error,
it returns from the current function with the same error. Otherwise, the
expression results in the unwrapped value.

Maybe you know with complete certainty that an expression will never be
an error. In this case you can do this:

[`const`]{.tok-kw}` number = parseU64(`[`"1234"`]{.tok-str}`, `[`10`]{.tok-number}`) `[`catch`]{.tok-kw}` `[`unreachable`]{.tok-kw}`;`

Here we know for sure that \"1234\" will parse successfully. So we put
the [`unreachable`]{.tok-kw} value on the right hand side.
[`unreachable`]{.tok-kw} invokes safety-checked [Illegal
Behavior](#Illegal-Behavior), so in [Debug](#Debug) and
[ReleaseSafe](#ReleaseSafe), triggers a safety panic by default. So,
while we\'re debugging the application, if there *was* a surprise error
here, the application would crash appropriately.

You may want to take a different action for every situation. For that,
we combine the [if](#if) and [switch](#switch) expression:

<figure>
<pre><code>fn doAThing(str: []u8) void {
    if (parseU64(str, 10)) |number| {
        doSomethingWithNumber(number);
    } else |err| switch (err) {
        error.Overflow =&gt; {
            // handle overflow...
        },
        // we promise that InvalidChar won&#39;t happen (or crash in debug mode if it does)
        error.InvalidChar =&gt; unreachable,
    }
}</code></pre>
<figcaption>handle_all_error_scenarios.zig</figcaption>
</figure>

Finally, you may want to handle only some errors. For that, you can
capture the unhandled errors in the [`else`]{.tok-kw} case, which now
contains a narrower error set:

<figure>
<pre><code>fn doAnotherThing(str: []u8) error{InvalidChar}!void {
    if (parseU64(str, 10)) |number| {
        doSomethingWithNumber(number);
    } else |err| switch (err) {
        error.Overflow =&gt; {
            // handle overflow...
        },
        else =&gt; |leftover_err| return leftover_err,
    }
}</code></pre>
<figcaption>handle_some_error_scenarios.zig</figcaption>
</figure>

You must use the variable capture syntax. If you don\'t need the
variable, you can capture with `_` and avoid the [`switch`]{.tok-kw}.

<figure>
<pre><code>fn doADifferentThing(str: []u8) void {
    if (parseU64(str, 10)) |number| {
        doSomethingWithNumber(number);
    } else |_| {
        // do as you&#39;d like
    }
}</code></pre>
<figcaption>handle_no_error_scenarios.zig</figcaption>
</figure>

#### [errdefer](#toc-errdefer) [§](#errdefer){.hdr}

The other component to error handling is defer statements. In addition
to an unconditional [defer](#defer), Zig has [`errdefer`]{.tok-kw},
which evaluates the deferred expression on block exit path if and only
if the function returned with an error from the block.

Example:

<figure>
<pre><code>fn createFoo(param: i32) !Foo {
    const foo = try tryToAllocateFoo();
    // now we have allocated foo. we need to free it if the function fails.
    // but we want to return it if the function succeeds.
    errdefer deallocateFoo(foo);

    const tmp_buf = allocateTmpBuffer() orelse return error.OutOfMemory;
    // tmp_buf is truly a temporary resource, and we for sure want to clean it up
    // before this block leaves scope
    defer deallocateTmpBuffer(tmp_buf);

    if (param &gt; 1337) return error.InvalidParam;

    // here the errdefer will not run since we&#39;re returning success from the function.
    // but the defer will run!
    return foo;
}</code></pre>
<figcaption>errdefer_example.zig</figcaption>
</figure>

The neat thing about this is that you get robust error handling without
the verbosity and cognitive overhead of trying to make sure every exit
path is covered. The deallocation code is always directly following the
allocation code.

The [`errdefer`]{.tok-kw} statement can optionally capture the error:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

fn captureError(captured: *?anyerror) !void {
    errdefer |err| {
        captured.* = err;
    }
    return error.GeneralFailure;
}

test &quot;errdefer capture&quot; {
    var captured: ?anyerror = null;

    if (captureError(&amp;captured)) unreachable else |err| {
        try std.testing.expectEqual(error.GeneralFailure, captured.?);
        try std.testing.expectEqual(error.GeneralFailure, err);
    }
}</code></pre>
<figcaption>test_errdefer_capture.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_errdefer_capture.zig
1/1 test_errdefer_capture.test.errdefer capture...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

A couple of other tidbits about error handling:

- These primitives give enough expressiveness that it\'s completely
  practical to have failing to check for an error be a compile error. If
  you really want to ignore the error, you can add
  [`catch`]{.tok-kw}` `[`unreachable`]{.tok-kw} and get the added
  benefit of crashing in Debug and ReleaseSafe modes if your assumption
  was wrong.
- Since Zig understands error types, it can pre-weight branches in favor
  of errors not occurring. Just a small optimization benefit that is not
  available in other languages.

See also:

- [defer](#defer)
- [if](#if)
- [switch](#switch)

An error union is created with the `!` binary operator. You can use
compile-time reflection to access the child type of an error union:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;error union&quot; {
    var foo: anyerror!i32 = undefined;

    // Coerce from child type of an error union:
    foo = 1234;

    // Coerce from an error set:
    foo = error.SomeError;

    // Use compile-time reflection to access the payload type of an error union:
    try comptime expect(@typeInfo(@TypeOf(foo)).error_union.payload == i32);

    // Use compile-time reflection to access the error set type of an error union:
    try comptime expect(@typeInfo(@TypeOf(foo)).error_union.error_set == anyerror);
}</code></pre>
<figcaption>test_error_union.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_error_union.zig
1/1 test_error_union.test.error union...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Merging Error Sets](#toc-Merging-Error-Sets) [§](#Merging-Error-Sets){.hdr} {#Merging-Error-Sets}

Use the `||` operator to merge two error sets together. The resulting
error set contains the errors of both error sets. Doc comments from the
left-hand side override doc comments from the right-hand side. In this
example, the doc comments for `C.PathNotFound` is `A doc comment`.

This is especially useful for functions which return different error
sets depending on [comptime](#comptime) branches. For example, the Zig
standard library uses `LinuxFileOpenError || WindowsFileOpenError` for
the error set of opening files.

<figure>
<pre><code>const A = error{
    NotDir,

    /// A doc comment
    PathNotFound,
};
const B = error{
    OutOfMemory,

    /// B doc comment
    PathNotFound,
};

const C = A || B;

fn foo() C!void {
    return error.NotDir;
}

test &quot;merge error sets&quot; {
    if (foo()) {
        @panic(&quot;unexpected&quot;);
    } else |err| switch (err) {
        error.OutOfMemory =&gt; @panic(&quot;unexpected&quot;),
        error.PathNotFound =&gt; @panic(&quot;unexpected&quot;),
        error.NotDir =&gt; {},
    }
}</code></pre>
<figcaption>test_merging_error_sets.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_merging_error_sets.zig
1/1 test_merging_error_sets.test.merge error sets...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Inferred Error Sets](#toc-Inferred-Error-Sets) [§](#Inferred-Error-Sets){.hdr} {#Inferred-Error-Sets}

Because many functions in Zig return a possible error, Zig supports
inferring the error set. To infer the error set for a function, prepend
the `!` operator to the function's return type, like `!T`:

<figure>
<pre><code>// With an inferred error set
pub fn add_inferred(comptime T: type, a: T, b: T) !T {
    const ov = @addWithOverflow(a, b);
    if (ov[1] != 0) return error.Overflow;
    return ov[0];
}

// With an explicit error set
pub fn add_explicit(comptime T: type, a: T, b: T) Error!T {
    const ov = @addWithOverflow(a, b);
    if (ov[1] != 0) return error.Overflow;
    return ov[0];
}

const Error = error{
    Overflow,
};

const std = @import(&quot;std&quot;);

test &quot;inferred error set&quot; {
    if (add_inferred(u8, 255, 1)) |_| unreachable else |err| switch (err) {
        error.Overflow =&gt; {}, // ok
    }
}</code></pre>
<figcaption>test_inferred_error_sets.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_inferred_error_sets.zig
1/1 test_inferred_error_sets.test.inferred error set...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

When a function has an inferred error set, that function becomes generic
and thus it becomes trickier to do certain things with it, such as
obtain a function pointer, or have an error set that is consistent
across different build targets. Additionally, inferred error sets are
incompatible with recursion.

In these situations, it is recommended to use an explicit error set. You
can generally start with an empty error set and let compile errors guide
you toward completing the set.

These limitations may be overcome in a future version of Zig.

### [Error Return Traces](#toc-Error-Return-Traces) [§](#Error-Return-Traces){.hdr} {#Error-Return-Traces}

Error Return Traces show all the points in the code that an error was
returned to the calling function. This makes it practical to use
[try](#try) everywhere and then still be able to know what happened if
an error ends up bubbling all the way out of your application.

<figure>
<pre><code>pub fn main() !void {
    try foo(12);
}

fn foo(x: i32) !void {
    if (x &gt;= 5) {
        try bar();
    } else {
        try bang2();
    }
}

fn bar() !void {
    if (baz()) {
        try quux();
    } else |err| switch (err) {
        error.FileNotFound =&gt; try hello(),
    }
}

fn baz() !void {
    try bang1();
}

fn quux() !void {
    try bang2();
}

fn hello() !void {
    try bang2();
}

fn bang1() !void {
    return error.FileNotFound;
}

fn bang2() !void {
    return error.PermissionDenied;
}</code></pre>
<figcaption>error_return_trace.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe error_return_trace.zig
$ ./error_return_trace
error: PermissionDenied
/home/andy/src/zig/doc/langref/error_return_trace.zig:34:5: 0x10de6f8 in bang1 (error_return_trace)
    return error.FileNotFound;
    ^
/home/andy/src/zig/doc/langref/error_return_trace.zig:22:5: 0x10de723 in baz (error_return_trace)
    try bang1();
    ^
/home/andy/src/zig/doc/langref/error_return_trace.zig:38:5: 0x10de748 in bang2 (error_return_trace)
    return error.PermissionDenied;
    ^
/home/andy/src/zig/doc/langref/error_return_trace.zig:30:5: 0x10de7b3 in hello (error_return_trace)
    try bang2();
    ^
/home/andy/src/zig/doc/langref/error_return_trace.zig:17:31: 0x10de858 in bar (error_return_trace)
        error.FileNotFound =&gt; try hello(),
                              ^
/home/andy/src/zig/doc/langref/error_return_trace.zig:7:9: 0x10de8c0 in foo (error_return_trace)
        try bar();
        ^
/home/andy/src/zig/doc/langref/error_return_trace.zig:2:5: 0x10de918 in main (error_return_trace)
    try foo(12);
    ^</code></pre>
<figcaption>Shell</figcaption>
</figure>

Look closely at this example. This is no stack trace.

You can see that the final error bubbled up was `PermissionDenied`, but
the original error that started this whole thing was `FileNotFound`. In
the `bar` function, the code handles the original error code, and then
returns another one, from the switch statement. Error Return Traces make
this clear, whereas a stack trace would look like this:

<figure>
<pre><code>pub fn main() void {
    foo(12);
}

fn foo(x: i32) void {
    if (x &gt;= 5) {
        bar();
    } else {
        bang2();
    }
}

fn bar() void {
    if (baz()) {
        quux();
    } else {
        hello();
    }
}

fn baz() bool {
    return bang1();
}

fn quux() void {
    bang2();
}

fn hello() void {
    bang2();
}

fn bang1() bool {
    return false;
}

fn bang2() void {
    @panic(&quot;PermissionDenied&quot;);
}</code></pre>
<figcaption>stack_trace.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe stack_trace.zig
$ ./stack_trace
thread 216810 panic: PermissionDenied
/home/andy/src/zig/doc/langref/stack_trace.zig:38:5: 0x10df2bc in bang2 (stack_trace)
    @panic(&quot;PermissionDenied&quot;);
    ^
/home/andy/src/zig/doc/langref/stack_trace.zig:30:10: 0x10dfb38 in hello (stack_trace)
    bang2();
         ^
/home/andy/src/zig/doc/langref/stack_trace.zig:17:14: 0x10df290 in bar (stack_trace)
        hello();
             ^
/home/andy/src/zig/doc/langref/stack_trace.zig:7:12: 0x10df0b4 in foo (stack_trace)
        bar();
           ^
/home/andy/src/zig/doc/langref/stack_trace.zig:2:8: 0x10de84d in main (stack_trace)
    foo(12);
       ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10de352 in posixCallMainAndExit (stack_trace)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10ddf2d in _start (stack_trace)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
(process terminated by signal)</code></pre>
<figcaption>Shell</figcaption>
</figure>

Here, the stack trace does not explain how the control flow in `bar` got
to the `hello()` call. One would have to open a debugger or further
instrument the application in order to find out. The error return trace,
on the other hand, shows exactly how the error bubbled up.

This debugging feature makes it easier to iterate quickly on code that
robustly handles all error conditions. This means that Zig developers
will naturally find themselves writing correct, robust code in order to
increase their development pace.

Error Return Traces are enabled by default in [Debug](#Debug) and
[ReleaseSafe](#ReleaseSafe) builds and disabled by default in
[ReleaseFast](#ReleaseFast) and [ReleaseSmall](#ReleaseSmall) builds.

There are a few ways to activate this error return tracing feature:

- Return an error from main
- An error makes its way to
  [`catch`]{.tok-kw}` `[`unreachable`]{.tok-kw} and you have not
  overridden the default panic handler
- Use [errorReturnTrace](#errorReturnTrace) to access the current return
  trace. You can use `std.debug.dumpStackTrace` to print it. This
  function returns comptime-known [null](#null) when building without
  error return tracing support.

#### [Implementation Details](#toc-Implementation-Details) [§](#Implementation-Details){.hdr} {#Implementation-Details}

To analyze performance cost, there are two cases:

- when no errors are returned
- when returning errors

For the case when no errors are returned, the cost is a single memory
write operation, only in the first non-failable function in the call
graph that calls a failable function, i.e. when a function returning
[`void`]{.tok-type} calls a function returning [`error`]{.tok-kw}. This
is to initialize this struct in the stack memory:

<figure>
<pre><code>pub const StackTrace = struct {
    index: usize,
    instruction_addresses: [N]usize,
};</code></pre>
<figcaption>stack_trace_struct.zig</figcaption>
</figure>

Here, N is the maximum function call depth as determined by call graph
analysis. Recursion is ignored and counts for 2.

A pointer to `StackTrace` is passed as a secret parameter to every
function that can return an error, but it\'s always the first parameter,
so it can likely sit in a register and stay there.

That\'s it for the path when no errors occur. It\'s practically free in
terms of performance.

When generating the code for a function that returns an error, just
before the [`return`]{.tok-kw} statement (only for the
[`return`]{.tok-kw} statements that return errors), Zig generates a call
to this function:

<figure>
<pre><code>// marked as &quot;no-inline&quot; in LLVM IR
fn __zig_return_error(stack_trace: *StackTrace) void {
    stack_trace.instruction_addresses[stack_trace.index] = @returnAddress();
    stack_trace.index = (stack_trace.index + 1) % N;
}</code></pre>
<figcaption>zig_return_error_fn.zig</figcaption>
</figure>

The cost is 2 math operations plus some memory reads and writes. The
memory accessed is constrained and should remain cached for the duration
of the error return bubbling.

As for code size cost, 1 function call before a return statement is no
big deal. Even so, I have [a
plan](https://github.com/ziglang/zig/issues/690) to make the call to
`__zig_return_error` a tail call, which brings the code size cost down
to actually zero. What is a return statement in code without error
return tracing can become a jump instruction in code with error return
tracing.

## [Optionals](#toc-Optionals) [§](#Optionals){.hdr} {#Optionals}

One area that Zig provides safety without compromising efficiency or
readability is with the optional type.

The question mark symbolizes the optional type. You can convert a type
to an optional type by putting a question mark in front of it, like
this:

<figure>
<pre><code>// normal integer
const normal_int: i32 = 1234;

// optional integer
const optional_int: ?i32 = 5678;</code></pre>
<figcaption>optional_integer.zig</figcaption>
</figure>

Now the variable `optional_int` could be an [`i32`]{.tok-type}, or
[`null`]{.tok-null}.

Instead of integers, let\'s talk about pointers. Null references are the
source of many runtime exceptions, and even stand accused of being [the
worst mistake of computer
science](https://www.lucidchart.com/techblog/2015/08/31/the-worst-mistake-of-computer-science/).

Zig does not have them.

Instead, you can use an optional pointer. This secretly compiles down to
a normal pointer, since we know we can use 0 as the null value for the
optional type. But the compiler can check your work and make sure you
don\'t assign null to something that can\'t be null.

Typically the downside of not having null is that it makes the code more
verbose to write. But, let\'s compare some equivalent C code and Zig
code.

Task: call malloc, if the result is null, return null.

C code

<figure>
<pre><code>// malloc prototype included for reference
void *malloc(size_t size);

struct Foo *do_a_thing(void) {
    char *ptr = malloc(1234);
    if (!ptr) return NULL;
    // ...
}</code></pre>
<figcaption>call_malloc_in_c.c</figcaption>
</figure>

Zig code

<figure>
<pre><code>// malloc prototype included for reference
extern fn malloc(size: usize) ?[*]u8;

fn doAThing() ?*Foo {
    const ptr = malloc(1234) orelse return null;
    _ = ptr; // ...
}</code></pre>
<figcaption>call_malloc_from_zig.zig</figcaption>
</figure>

Here, Zig is at least as convenient, if not more, than C. And, the type
of \"ptr\" is `[*]`[`u8`]{.tok-type} *not* `?[*]`[`u8`]{.tok-type}. The
[`orelse`]{.tok-kw} keyword unwrapped the optional type and therefore
`ptr` is guaranteed to be non-null everywhere it is used in the
function.

The other form of checking against NULL you might see looks like this:

<figure>
<pre><code>void do_a_thing(struct Foo *foo) {
    // do some stuff

    if (foo) {
        do_something_with_foo(foo);
    }

    // do some stuff
}</code></pre>
<figcaption>checking_null_in_c.c</figcaption>
</figure>

In Zig you can accomplish the same thing:

<figure>
<pre><code>const Foo = struct {};
fn doSomethingWithFoo(foo: *Foo) void {
    _ = foo;
}

fn doAThing(optional_foo: ?*Foo) void {
    // do some stuff

    if (optional_foo) |foo| {
        doSomethingWithFoo(foo);
    }

    // do some stuff
}</code></pre>
<figcaption>checking_null_in_zig.zig</figcaption>
</figure>

Once again, the notable thing here is that inside the if block, `foo` is
no longer an optional pointer, it is a pointer, which cannot be null.

One benefit to this is that functions which take pointers as arguments
can be annotated with the \"nonnull\" attribute -
`__attribute__((nonnull))` in
[GCC](https://gcc.gnu.org/onlinedocs/gcc-4.0.0/gcc/Function-Attributes.html).
The optimizer can sometimes make better decisions knowing that pointer
arguments cannot be null.

### [Optional Type](#toc-Optional-Type) [§](#Optional-Type){.hdr} {#Optional-Type}

An optional is created by putting `?` in front of a type. You can use
compile-time reflection to access the child type of an optional:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;optional type&quot; {
    // Declare an optional and coerce from null:
    var foo: ?i32 = null;

    // Coerce from child type of an optional
    foo = 1234;

    // Use compile-time reflection to access the child type of the optional:
    try comptime expect(@typeInfo(@TypeOf(foo)).optional.child == i32);
}</code></pre>
<figcaption>test_optional_type.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_optional_type.zig
1/1 test_optional_type.test.optional type...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [null](#toc-null) [§](#null){.hdr}

Just like [undefined](#undefined), [`null`]{.tok-null} has its own type,
and the only way to use it is to cast it to a different type:

<figure>
<pre><code>const optional_value: ?i32 = null;</code></pre>
<figcaption>null.zig</figcaption>
</figure>

### [Optional Pointers](#toc-Optional-Pointers) [§](#Optional-Pointers){.hdr} {#Optional-Pointers}

An optional pointer is guaranteed to be the same size as a pointer. The
[`null`]{.tok-null} of the optional is guaranteed to be address 0.

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;optional pointers&quot; {
    // Pointers cannot be null. If you want a null pointer, use the optional
    // prefix `?` to make the pointer type optional.
    var ptr: ?*i32 = null;

    var x: i32 = 1;
    ptr = &amp;x;

    try expect(ptr.?.* == 1);

    // Optional pointers are the same size as normal pointers, because pointer
    // value 0 is used as the null value.
    try expect(@sizeOf(?*i32) == @sizeOf(*i32));
}</code></pre>
<figcaption>test_optional_pointer.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_optional_pointer.zig
1/1 test_optional_pointer.test.optional pointers...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [while with Optionals](#while-with-Optionals)
- [if with Optionals](#if-with-Optionals)

## [Casting](#toc-Casting) [§](#Casting){.hdr} {#Casting}

A **type cast** converts a value of one type to another. Zig has [Type
Coercion](#Type-Coercion) for conversions that are known to be
completely safe and unambiguous, and [Explicit Casts](#Explicit-Casts)
for conversions that one would not want to happen on accident. There is
also a third kind of type conversion called [Peer Type
Resolution](#Peer-Type-Resolution) for the case when a result type must
be decided given multiple operand types.

### [Type Coercion](#toc-Type-Coercion) [§](#Type-Coercion){.hdr} {#Type-Coercion}

Type coercion occurs when one type is expected, but different type is
provided:

<figure>
<pre><code>test &quot;type coercion - variable declaration&quot; {
    const a: u8 = 1;
    const b: u16 = a;
    _ = b;
}

test &quot;type coercion - function call&quot; {
    const a: u8 = 1;
    foo(a);
}

fn foo(b: u16) void {
    _ = b;
}

test &quot;type coercion - @as builtin&quot; {
    const a: u8 = 1;
    const b = @as(u16, a);
    _ = b;
}</code></pre>
<figcaption>test_type_coercion.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_type_coercion.zig
1/3 test_type_coercion.test.type coercion - variable declaration...OK
2/3 test_type_coercion.test.type coercion - function call...OK
3/3 test_type_coercion.test.type coercion - @as builtin...OK
All 3 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Type coercions are only allowed when it is completely unambiguous how to
get from one type to another, and the transformation is guaranteed to be
safe. There is one exception, which is [C Pointers](#C-Pointers).

#### [Type Coercion: Stricter Qualification](#toc-Type-Coercion-Stricter-Qualification) [§](#Type-Coercion-Stricter-Qualification){.hdr} {#Type-Coercion-Stricter-Qualification}

Values which have the same representation at runtime can be cast to
increase the strictness of the qualifiers, no matter how nested the
qualifiers are:

- [`const`]{.tok-kw} - non-const to const is allowed
- [`volatile`]{.tok-kw} - non-volatile to volatile is allowed
- [`align`]{.tok-kw} - bigger to smaller alignment is allowed
- [error sets](#Error-Set-Type) to supersets is allowed

These casts are no-ops at runtime since the value representation does
not change.

<figure>
<pre><code>test &quot;type coercion - const qualification&quot; {
    var a: i32 = 1;
    const b: *i32 = &amp;a;
    foo(b);
}

fn foo(_: *const i32) void {}</code></pre>
<figcaption>test_no_op_casts.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_no_op_casts.zig
1/1 test_no_op_casts.test.type coercion - const qualification...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

In addition, pointers coerce to const optional pointers:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;
const mem = std.mem;

test &quot;cast *[1][*:0]const u8 to []const ?[*:0]const u8&quot; {
    const window_name = [1][*:0]const u8{&quot;window name&quot;};
    const x: []const ?[*:0]const u8 = &amp;window_name;
    try expect(mem.eql(u8, mem.span(x[0].?), &quot;window name&quot;));
}</code></pre>
<figcaption>test_pointer_coerce_const_optional.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_pointer_coerce_const_optional.zig
1/1 test_pointer_coerce_const_optional.test.cast *[1][*:0]const u8 to []const ?[*:0]const u8...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Type Coercion: Integer and Float Widening](#toc-Type-Coercion-Integer-and-Float-Widening) [§](#Type-Coercion-Integer-and-Float-Widening){.hdr} {#Type-Coercion-Integer-and-Float-Widening}

[Integers](#Integers) coerce to integer types which can represent every
value of the old type, and likewise [Floats](#Floats) coerce to float
types which can represent every value of the old type.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const builtin = @import(&quot;builtin&quot;);
const expect = std.testing.expect;
const mem = std.mem;

test &quot;integer widening&quot; {
    const a: u8 = 250;
    const b: u16 = a;
    const c: u32 = b;
    const d: u64 = c;
    const e: u64 = d;
    const f: u128 = e;
    try expect(f == a);
}

test &quot;implicit unsigned integer to signed integer&quot; {
    const a: u8 = 250;
    const b: i16 = a;
    try expect(b == 250);
}

test &quot;float widening&quot; {
    const a: f16 = 12.34;
    const b: f32 = a;
    const c: f64 = b;
    const d: f128 = c;
    try expect(d == a);
}</code></pre>
<figcaption>test_integer_widening.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_integer_widening.zig
1/3 test_integer_widening.test.integer widening...OK
2/3 test_integer_widening.test.implicit unsigned integer to signed integer...OK
3/3 test_integer_widening.test.float widening...OK
All 3 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Type Coercion: Float to Int](#toc-Type-Coercion-Float-to-Int) [§](#Type-Coercion-Float-to-Int){.hdr} {#Type-Coercion-Float-to-Int}

A compiler error is appropriate because this ambiguous expression leaves
the compiler two choices about the coercion.

- Cast [`54.0`]{.tok-number} to [`comptime_int`]{.tok-type} resulting in
  [`@as`]{.tok-builtin}`(`[`comptime_int`]{.tok-type}`, `[`10`]{.tok-number}`)`,
  which is casted to
  [`@as`]{.tok-builtin}`(`[`f32`]{.tok-type}`, `[`10`]{.tok-number}`)`
- Cast [`5`]{.tok-number} to [`comptime_float`]{.tok-type} resulting in
  [`@as`]{.tok-builtin}`(`[`comptime_float`]{.tok-type}`, `[`10.8`]{.tok-number}`)`,
  which is casted to
  [`@as`]{.tok-builtin}`(`[`f32`]{.tok-type}`, `[`10.8`]{.tok-number}`)`

<figure>
<pre><code>// Compile time coercion of float to int
test &quot;implicit cast to comptime_int&quot; {
    const f: f32 = 54.0 / 5;
    _ = f;
}</code></pre>
<figcaption>test_ambiguous_coercion.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_ambiguous_coercion.zig
doc/langref/test_ambiguous_coercion.zig:3:25: error: ambiguous coercion of division operands &#39;comptime_float&#39; and &#39;comptime_int&#39;; non-zero remainder &#39;4&#39;
    const f: f32 = 54.0 / 5;
                   ~~~~~^~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Type Coercion: Slices, Arrays and Pointers](#toc-Type-Coercion-Slices-Arrays-and-Pointers) [§](#Type-Coercion-Slices-Arrays-and-Pointers){.hdr} {#Type-Coercion-Slices-Arrays-and-Pointers}

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

// You can assign constant pointers to arrays to a slice with
// const modifier on the element type. Useful in particular for
// String literals.
test &quot;*const [N]T to []const T&quot; {
    const x1: []const u8 = &quot;hello&quot;;
    const x2: []const u8 = &amp;[5]u8{ &#39;h&#39;, &#39;e&#39;, &#39;l&#39;, &#39;l&#39;, 111 };
    try expect(std.mem.eql(u8, x1, x2));

    const y: []const f32 = &amp;[2]f32{ 1.2, 3.4 };
    try expect(y[0] == 1.2);
}

// Likewise, it works when the destination type is an error union.
test &quot;*const [N]T to E![]const T&quot; {
    const x1: anyerror![]const u8 = &quot;hello&quot;;
    const x2: anyerror![]const u8 = &amp;[5]u8{ &#39;h&#39;, &#39;e&#39;, &#39;l&#39;, &#39;l&#39;, 111 };
    try expect(std.mem.eql(u8, try x1, try x2));

    const y: anyerror![]const f32 = &amp;[2]f32{ 1.2, 3.4 };
    try expect((try y)[0] == 1.2);
}

// Likewise, it works when the destination type is an optional.
test &quot;*const [N]T to ?[]const T&quot; {
    const x1: ?[]const u8 = &quot;hello&quot;;
    const x2: ?[]const u8 = &amp;[5]u8{ &#39;h&#39;, &#39;e&#39;, &#39;l&#39;, &#39;l&#39;, 111 };
    try expect(std.mem.eql(u8, x1.?, x2.?));

    const y: ?[]const f32 = &amp;[2]f32{ 1.2, 3.4 };
    try expect(y.?[0] == 1.2);
}

// In this cast, the array length becomes the slice length.
test &quot;*[N]T to []T&quot; {
    var buf: [5]u8 = &quot;hello&quot;.*;
    const x: []u8 = &amp;buf;
    try expect(std.mem.eql(u8, x, &quot;hello&quot;));

    const buf2 = [2]f32{ 1.2, 3.4 };
    const x2: []const f32 = &amp;buf2;
    try expect(std.mem.eql(f32, x2, &amp;[2]f32{ 1.2, 3.4 }));
}

// Single-item pointers to arrays can be coerced to many-item pointers.
test &quot;*[N]T to [*]T&quot; {
    var buf: [5]u8 = &quot;hello&quot;.*;
    const x: [*]u8 = &amp;buf;
    try expect(x[4] == &#39;o&#39;);
    // x[5] would be an uncaught out of bounds pointer dereference!
}

// Likewise, it works when the destination type is an optional.
test &quot;*[N]T to ?[*]T&quot; {
    var buf: [5]u8 = &quot;hello&quot;.*;
    const x: ?[*]u8 = &amp;buf;
    try expect(x.?[4] == &#39;o&#39;);
}

// Single-item pointers can be cast to len-1 single-item arrays.
test &quot;*T to *[1]T&quot; {
    var x: i32 = 1234;
    const y: *[1]i32 = &amp;x;
    const z: [*]i32 = y;
    try expect(z[0] == 1234);
}</code></pre>
<figcaption>test_coerce_slices_arrays_and_pointers.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_coerce_slices_arrays_and_pointers.zig
1/7 test_coerce_slices_arrays_and_pointers.test.*const [N]T to []const T...OK
2/7 test_coerce_slices_arrays_and_pointers.test.*const [N]T to E![]const T...OK
3/7 test_coerce_slices_arrays_and_pointers.test.*const [N]T to ?[]const T...OK
4/7 test_coerce_slices_arrays_and_pointers.test.*[N]T to []T...OK
5/7 test_coerce_slices_arrays_and_pointers.test.*[N]T to [*]T...OK
6/7 test_coerce_slices_arrays_and_pointers.test.*[N]T to ?[*]T...OK
7/7 test_coerce_slices_arrays_and_pointers.test.*T to *[1]T...OK
All 7 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [C Pointers](#C-Pointers)

#### [Type Coercion: Optionals](#toc-Type-Coercion-Optionals) [§](#Type-Coercion-Optionals){.hdr} {#Type-Coercion-Optionals}

The payload type of [Optionals](#Optionals), as well as [null](#null),
coerce to the optional type.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;coerce to optionals&quot; {
    const x: ?i32 = 1234;
    const y: ?i32 = null;

    try expect(x.? == 1234);
    try expect(y == null);
}</code></pre>
<figcaption>test_coerce_optionals.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_coerce_optionals.zig
1/1 test_coerce_optionals.test.coerce to optionals...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Optionals work nested inside the [Error Union Type](#Error-Union-Type),
too:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;coerce to optionals wrapped in error union&quot; {
    const x: anyerror!?i32 = 1234;
    const y: anyerror!?i32 = null;

    try expect((try x).? == 1234);
    try expect((try y) == null);
}</code></pre>
<figcaption>test_coerce_optional_wrapped_error_union.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_coerce_optional_wrapped_error_union.zig
1/1 test_coerce_optional_wrapped_error_union.test.coerce to optionals wrapped in error union...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Type Coercion: Error Unions](#toc-Type-Coercion-Error-Unions) [§](#Type-Coercion-Error-Unions){.hdr} {#Type-Coercion-Error-Unions}

The payload type of an [Error Union Type](#Error-Union-Type) as well as
the [Error Set Type](#Error-Set-Type) coerce to the error union type:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;coercion to error unions&quot; {
    const x: anyerror!i32 = 1234;
    const y: anyerror!i32 = error.Failure;

    try expect((try x) == 1234);
    try std.testing.expectError(error.Failure, y);
}</code></pre>
<figcaption>test_coerce_to_error_union.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_coerce_to_error_union.zig
1/1 test_coerce_to_error_union.test.coercion to error unions...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Type Coercion: Compile-Time Known Numbers](#toc-Type-Coercion-Compile-Time-Known-Numbers) [§](#Type-Coercion-Compile-Time-Known-Numbers){.hdr} {#Type-Coercion-Compile-Time-Known-Numbers}

When a number is [comptime](#comptime)-known to be representable in the
destination type, it may be coerced:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;coercing large integer type to smaller one when value is comptime-known to fit&quot; {
    const x: u64 = 255;
    const y: u8 = x;
    try expect(y == 255);
}</code></pre>
<figcaption>test_coerce_large_to_small.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_coerce_large_to_small.zig
1/1 test_coerce_large_to_small.test.coercing large integer type to smaller one when value is comptime-known to fit...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [Type Coercion: Unions and Enums](#toc-Type-Coercion-Unions-and-Enums) [§](#Type-Coercion-Unions-and-Enums){.hdr} {#Type-Coercion-Unions-and-Enums}

Tagged unions can be coerced to enums, and enums can be coerced to
tagged unions when they are [comptime](#comptime)-known to be a field of
the union that has only one possible value, such as [void](#void):

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const E = enum {
    one,
    two,
    three,
};

const U = union(E) {
    one: i32,
    two: f32,
    three,
};

const U2 = union(enum) {
    a: void,
    b: f32,

    fn tag(self: U2) usize {
        switch (self) {
            .a =&gt; return 1,
            .b =&gt; return 2,
        }
    }
};

test &quot;coercion between unions and enums&quot; {
    const u = U{ .two = 12.34 };
    const e: E = u; // coerce union to enum
    try expect(e == E.two);

    const three = E.three;
    const u_2: U = three; // coerce enum to union
    try expect(u_2 == E.three);

    const u_3: U = .three; // coerce enum literal to union
    try expect(u_3 == E.three);

    const u_4: U2 = .a; // coerce enum literal to union with inferred enum tag type.
    try expect(u_4.tag() == 1);

    // The following example is invalid.
    // error: coercion from enum &#39;@TypeOf(.enum_literal)&#39; to union &#39;test_coerce_unions_enum.U2&#39; must initialize &#39;f32&#39; field &#39;b&#39;
    //var u_5: U2 = .b;
    //try expect(u_5.tag() == 2);
}</code></pre>
<figcaption>test_coerce_unions_enums.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_coerce_unions_enums.zig
1/1 test_coerce_unions_enums.test.coercion between unions and enums...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [union](#union)
- [enum](#enum)

#### [Type Coercion: undefined](#toc-Type-Coercion-undefined) [§](#Type-Coercion-undefined){.hdr} {#Type-Coercion-undefined}

[undefined](#undefined) can be coerced to any type.

#### [Type Coercion: Tuples to Arrays](#toc-Type-Coercion-Tuples-to-Arrays) [§](#Type-Coercion-Tuples-to-Arrays){.hdr} {#Type-Coercion-Tuples-to-Arrays}

[Tuples](#Tuples) can be coerced to arrays, if all of the fields have
the same type.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const Tuple = struct { u8, u8 };
test &quot;coercion from homogeneous tuple to array&quot; {
    const tuple: Tuple = .{ 5, 6 };
    const array: [2]u8 = tuple;
    _ = array;
}</code></pre>
<figcaption>test_coerce_tuples_arrays.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_coerce_tuples_arrays.zig
1/1 test_coerce_tuples_arrays.test.coercion from homogeneous tuple to array...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Explicit Casts](#toc-Explicit-Casts) [§](#Explicit-Casts){.hdr} {#Explicit-Casts}

Explicit casts are performed via [Builtin
Functions](#Builtin-Functions). Some explicit casts are safe; some are
not. Some explicit casts perform language-level assertions; some do not.
Some explicit casts are no-ops at runtime; some are not.

- [\@bitCast](#bitCast) - change type but maintain bit representation
- [\@alignCast](#alignCast) - make a pointer have more alignment
- [\@enumFromInt](#enumFromInt) - obtain an enum value based on its
  integer tag value
- [\@errorFromInt](#errorFromInt) - obtain an error code based on its
  integer value
- [\@errorCast](#errorCast) - convert to a smaller error set
- [\@floatCast](#floatCast) - convert a larger float to a smaller float
- [\@floatFromInt](#floatFromInt) - convert an integer to a float value
- [\@intCast](#intCast) - convert between integer types
- [\@intFromBool](#intFromBool) - convert true to 1 and false to 0
- [\@intFromEnum](#intFromEnum) - obtain the integer tag value of an
  enum or tagged union
- [\@intFromError](#intFromError) - obtain the integer value of an error
  code
- [\@intFromFloat](#intFromFloat) - obtain the integer part of a float
  value
- [\@intFromPtr](#intFromPtr) - obtain the address of a pointer
- [\@ptrFromInt](#ptrFromInt) - convert an address to a pointer
- [\@ptrCast](#ptrCast) - convert between pointer types
- [\@truncate](#truncate) - convert between integer types, chopping off
  bits

### [Peer Type Resolution](#toc-Peer-Type-Resolution) [§](#Peer-Type-Resolution){.hdr} {#Peer-Type-Resolution}

Peer Type Resolution occurs in these places:

- [switch](#switch) expressions
- [if](#if) expressions
- [while](#while) expressions
- [for](#for) expressions
- Multiple break statements in a block
- Some [binary operations](#Table-of-Operators)

This kind of type resolution chooses a type that all peer types can
coerce into. Here are some examples:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;
const mem = std.mem;

test &quot;peer resolve int widening&quot; {
    const a: i8 = 12;
    const b: i16 = 34;
    const c = a + b;
    try expect(c == 46);
    try expect(@TypeOf(c) == i16);
}

test &quot;peer resolve arrays of different size to const slice&quot; {
    try expect(mem.eql(u8, boolToStr(true), &quot;true&quot;));
    try expect(mem.eql(u8, boolToStr(false), &quot;false&quot;));
    try comptime expect(mem.eql(u8, boolToStr(true), &quot;true&quot;));
    try comptime expect(mem.eql(u8, boolToStr(false), &quot;false&quot;));
}
fn boolToStr(b: bool) []const u8 {
    return if (b) &quot;true&quot; else &quot;false&quot;;
}

test &quot;peer resolve array and const slice&quot; {
    try testPeerResolveArrayConstSlice(true);
    try comptime testPeerResolveArrayConstSlice(true);
}
fn testPeerResolveArrayConstSlice(b: bool) !void {
    const value1 = if (b) &quot;aoeu&quot; else @as([]const u8, &quot;zz&quot;);
    const value2 = if (b) @as([]const u8, &quot;zz&quot;) else &quot;aoeu&quot;;
    try expect(mem.eql(u8, value1, &quot;aoeu&quot;));
    try expect(mem.eql(u8, value2, &quot;zz&quot;));
}

test &quot;peer type resolution: ?T and T&quot; {
    try expect(peerTypeTAndOptionalT(true, false).? == 0);
    try expect(peerTypeTAndOptionalT(false, false).? == 3);
    comptime {
        try expect(peerTypeTAndOptionalT(true, false).? == 0);
        try expect(peerTypeTAndOptionalT(false, false).? == 3);
    }
}
fn peerTypeTAndOptionalT(c: bool, b: bool) ?usize {
    if (c) {
        return if (b) null else @as(usize, 0);
    }

    return @as(usize, 3);
}

test &quot;peer type resolution: *[0]u8 and []const u8&quot; {
    try expect(peerTypeEmptyArrayAndSlice(true, &quot;hi&quot;).len == 0);
    try expect(peerTypeEmptyArrayAndSlice(false, &quot;hi&quot;).len == 1);
    comptime {
        try expect(peerTypeEmptyArrayAndSlice(true, &quot;hi&quot;).len == 0);
        try expect(peerTypeEmptyArrayAndSlice(false, &quot;hi&quot;).len == 1);
    }
}
fn peerTypeEmptyArrayAndSlice(a: bool, slice: []const u8) []const u8 {
    if (a) {
        return &amp;[_]u8{};
    }

    return slice[0..1];
}
test &quot;peer type resolution: *[0]u8, []const u8, and anyerror![]u8&quot; {
    {
        var data = &quot;hi&quot;.*;
        const slice = data[0..];
        try expect((try peerTypeEmptyArrayAndSliceAndError(true, slice)).len == 0);
        try expect((try peerTypeEmptyArrayAndSliceAndError(false, slice)).len == 1);
    }
    comptime {
        var data = &quot;hi&quot;.*;
        const slice = data[0..];
        try expect((try peerTypeEmptyArrayAndSliceAndError(true, slice)).len == 0);
        try expect((try peerTypeEmptyArrayAndSliceAndError(false, slice)).len == 1);
    }
}
fn peerTypeEmptyArrayAndSliceAndError(a: bool, slice: []u8) anyerror![]u8 {
    if (a) {
        return &amp;[_]u8{};
    }

    return slice[0..1];
}

test &quot;peer type resolution: *const T and ?*T&quot; {
    const a: *const usize = @ptrFromInt(0x123456780);
    const b: ?*usize = @ptrFromInt(0x123456780);
    try expect(a == b);
    try expect(b == a);
}

test &quot;peer type resolution: error union switch&quot; {
    // The non-error and error cases are only peers if the error case is just a switch expression;
    // the pattern `if (x) {...} else |err| blk: { switch (err) {...} }` does not consider the
    // non-error and error case to be peers.
    var a: error{ A, B, C }!u32 = 0;
    _ = &amp;a;
    const b = if (a) |x|
        x + 3
    else |err| switch (err) {
        error.A =&gt; 0,
        error.B =&gt; 1,
        error.C =&gt; null,
    };
    try expect(@TypeOf(b) == ?u32);

    // The non-error and error cases are only peers if the error case is just a switch expression;
    // the pattern `x catch |err| blk: { switch (err) {...} }` does not consider the unwrapped `x`
    // and error case to be peers.
    const c = a catch |err| switch (err) {
        error.A =&gt; 0,
        error.B =&gt; 1,
        error.C =&gt; null,
    };
    try expect(@TypeOf(c) == ?u32);
}</code></pre>
<figcaption>test_peer_type_resolution.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_peer_type_resolution.zig
1/8 test_peer_type_resolution.test.peer resolve int widening...OK
2/8 test_peer_type_resolution.test.peer resolve arrays of different size to const slice...OK
3/8 test_peer_type_resolution.test.peer resolve array and const slice...OK
4/8 test_peer_type_resolution.test.peer type resolution: ?T and T...OK
5/8 test_peer_type_resolution.test.peer type resolution: *[0]u8 and []const u8...OK
6/8 test_peer_type_resolution.test.peer type resolution: *[0]u8, []const u8, and anyerror![]u8...OK
7/8 test_peer_type_resolution.test.peer type resolution: *const T and ?*T...OK
8/8 test_peer_type_resolution.test.peer type resolution: error union switch...OK
All 8 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [Zero Bit Types](#toc-Zero-Bit-Types) [§](#Zero-Bit-Types){.hdr} {#Zero-Bit-Types}

For some types, [\@sizeOf](#sizeOf) is 0:

- [void](#void)
- The [Integers](#Integers) [`u0`]{.tok-type} and [`i0`]{.tok-type}.
- [Arrays](#Arrays) and [Vectors](#Vectors) with len 0, or with an
  element type that is a zero bit type.
- An [enum](#enum) with only 1 tag.
- A [struct](#struct) with all fields being zero bit types.
- A [union](#union) with only 1 field which is a zero bit type.

These types can only ever have one possible value, and thus require 0
bits to represent. Code that makes use of these types is not included in
the final generated code:

<figure>
<pre><code>export fn entry() void {
    var x: void = {};
    var y: void = {};
    x = y;
    y = x;
}</code></pre>
<figcaption>zero_bit_types.zig</figcaption>
</figure>

When this turns into machine code, there is no code generated in the
body of `entry`, even in [Debug](#Debug) mode. For example, on x86_64:

    0000000000000010 <entry>:
      10:   55                      push   %rbp
      11:   48 89 e5                mov    %rsp,%rbp
      14:   5d                      pop    %rbp
      15:   c3                      retq   

These assembly instructions do not have any code associated with the
void values - they only perform the function call prologue and epilogue.

### [void](#toc-void) [§](#void){.hdr}

[`void`]{.tok-type} can be useful for instantiating generic types. For
example, given a `Map(Key, Value)`, one can pass [`void`]{.tok-type} for
the `Value` type to make it into a `Set`:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;turn HashMap into a set with void&quot; {
    var map = std.AutoHashMap(i32, void).init(std.testing.allocator);
    defer map.deinit();

    try map.put(1, {});
    try map.put(2, {});

    try expect(map.contains(2));
    try expect(!map.contains(3));

    _ = map.remove(2);
    try expect(!map.contains(2));
}</code></pre>
<figcaption>test_void_in_hashmap.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_void_in_hashmap.zig
1/1 test_void_in_hashmap.test.turn HashMap into a set with void...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Note that this is different from using a dummy value for the hash map
value. By using [`void`]{.tok-type} as the type of the value, the hash
map entry type has no value field, and thus the hash map takes up less
space. Further, all the code that deals with storing and loading the
value is deleted, as seen above.

[`void`]{.tok-type} is distinct from [`anyopaque`]{.tok-type}.
[`void`]{.tok-type} has a known size of 0 bytes, and
[`anyopaque`]{.tok-type} has an unknown, but non-zero, size.

Expressions of type [`void`]{.tok-type} are the only ones whose value
can be ignored. For example, ignoring a non-[`void`]{.tok-type}
expression is a compile error:

<figure>
<pre><code>test &quot;ignoring expression value&quot; {
    foo();
}

fn foo() i32 {
    return 1234;
}</code></pre>
<figcaption>test_expression_ignored.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_expression_ignored.zig
doc/langref/test_expression_ignored.zig:2:8: error: value of type &#39;i32&#39; ignored
    foo();
    ~~~^~
doc/langref/test_expression_ignored.zig:2:8: note: all non-void values must be used
doc/langref/test_expression_ignored.zig:2:8: note: to discard the value, assign it to &#39;_&#39;
</code></pre>
<figcaption>Shell</figcaption>
</figure>

However, if the expression has type [`void`]{.tok-type}, there will be
no error. Expression results can be explicitly ignored by assigning them
to `_`.

<figure>
<pre><code>test &quot;void is ignored&quot; {
    returnsVoid();
}

test &quot;explicitly ignoring expression value&quot; {
    _ = foo();
}

fn returnsVoid() void {}

fn foo() i32 {
    return 1234;
}</code></pre>
<figcaption>test_void_ignored.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_void_ignored.zig
1/2 test_void_ignored.test.void is ignored...OK
2/2 test_void_ignored.test.explicitly ignoring expression value...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [Result Location Semantics](#toc-Result-Location-Semantics) [§](#Result-Location-Semantics){.hdr} {#Result-Location-Semantics}

During compilation, every Zig expression and sub-expression is assigned
optional result location information. This information dictates what
type the expression should have (its result type), and where the
resulting value should be placed in memory (its result location). The
information is optional in the sense that not every expression has this
information: assignment to `_`, for instance, does not provide any
information about the type of an expression, nor does it provide a
concrete memory location to place it in.

As a motivating example, consider the statement
[`const`]{.tok-kw}` x: `[`u32`]{.tok-type}` = `[`42`]{.tok-number}`;`.
The type annotation here provides a result type of [`u32`]{.tok-type} to
the initialization expression [`42`]{.tok-number}, instructing the
compiler to coerce this integer (initially of type
[`comptime_int`]{.tok-type}) to this type. We will see more examples
shortly.

This is not an implementation detail: the logic outlined above is
codified into the Zig language specification, and is the primary
mechanism of type inference in the language. This system is collectively
referred to as \"Result Location Semantics\".

### [Result Types](#toc-Result-Types) [§](#Result-Types){.hdr} {#Result-Types}

Result types are propagated recursively through expressions where
possible. For instance, if the expression `&e` has result type
`*`[`u32`]{.tok-type}, then `e` is given a result type of
[`u32`]{.tok-type}, allowing the language to perform this coercion
before taking a reference.

The result type mechanism is utilized by casting builtins such as
[`@intCast`]{.tok-builtin}. Rather than taking as an argument the type
to cast to, these builtins use their result type to determine this
information. The result type is often known from context; where it is
not, the [`@as`]{.tok-builtin} builtin can be used to explicitly provide
a result type.

We can break down the result types for each component of a simple
expression as follows:

<figure>
<pre><code>const expectEqual = @import(&quot;std&quot;).testing.expectEqual;
test &quot;result type propagates through struct initializer&quot; {
    const S = struct { x: u32 };
    const val: u64 = 123;
    const s: S = .{ .x = @intCast(val) };
    // .{ .x = @intCast(val) }   has result type `S` due to the type annotation
    //         @intCast(val)     has result type `u32` due to the type of the field `S.x`
    //                  val      has no result type, as it is permitted to be any integer type
    try expectEqual(@as(u32, 123), s.x);
}</code></pre>
<figcaption>result_type_propagation.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test result_type_propagation.zig
1/1 result_type_propagation.test.result type propagates through struct initializer...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

This result type information is useful for the aforementioned cast
builtins, as well as to avoid the construction of pre-coercion values,
and to avoid the need for explicit type coercions in some cases. The
following table details how some common expressions propagate result
types, where `x` and `y` are arbitrary sub-expressions.

::: table-wrapper
  Expression                         Parent Result Type   Sub-expression Result Type
  ---------------------------------- -------------------- -----------------------------------------------------------------
  [`const`]{.tok-kw}` val: T = x`    \-                   `x` is a `T`
  [`var`]{.tok-kw}` val: T = x`      \-                   `x` is a `T`
  `val = x`                          \-                   `x` is a [`@TypeOf`]{.tok-builtin}`(val)`
  [`@as`]{.tok-builtin}`(T, x)`      \-                   `x` is a `T`
  `&x`                               `*T`                 `x` is a `T`
  `&x`                               `[]T`                `x` is some array of `T`
  `f(x)`                             \-                   `x` has the type of the first parameter of `f`
  `.{x}`                             `T`                  `x` is a `std.meta.FieldType(T, .@"0")`
  `.{ .a = x }`                      `T`                  `x` is a `std.meta.FieldType(T, .a)`
  `T{x}`                             \-                   `x` is a `std.meta.FieldType(T, .@"0")`
  `T{ .a = x }`                      \-                   `x` is a `std.meta.FieldType(T, .a)`
  [`@Type`]{.tok-builtin}`(x)`       \-                   `x` is a `std.builtin.Type`
  [`@typeInfo`]{.tok-builtin}`(x)`   \-                   `x` is a [`type`]{.tok-type}
  `x << y`                           \-                   `y` is a `std.math.Log2IntCeil(`[`@TypeOf`]{.tok-builtin}`(x))`
:::

### [Result Locations](#toc-Result-Locations) [§](#Result-Locations){.hdr} {#Result-Locations}

In addition to result type information, every expression may be
optionally assigned a result location: a pointer to which the value must
be directly written. This system can be used to prevent intermediate
copies when initializing data structures, which can be important for
types which must have a fixed memory address (\"pinned\" types).

When compiling the simple assignment expression `x = e`, many languages
would create the temporary value `e` on the stack, and then assign it to
`x`, potentially performing a type coercion in the process. Zig
approaches this differently. The expression `e` is given a result type
matching the type of `x`, and a result location of `&x`. For many
syntactic forms of `e`, this has no practical impact. However, it can
have important semantic effects when working with more complex syntax
forms.

For instance, if the expression `.{ .a = x, .b = y }` has a result
location of `ptr`, then `x` is given a result location of `&ptr.a`, and
`y` a result location of `&ptr.b`. Without this system, this expression
would construct a temporary struct value entirely on the stack, and only
then copy it to the destination address. In essence, Zig desugars the
assignment `foo = .{ .a = x, .b = y }` to the two statements
`foo.a = x; foo.b = y;`.

This can sometimes be important when assigning an aggregate value where
the initialization expression depends on the previous value of the
aggregate. The easiest way to demonstrate this is by attempting to swap
fields of a struct or array - the following logic looks sound, but in
fact is not:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;
test &quot;attempt to swap array elements with array initializer&quot; {
    var arr: [2]u32 = .{ 1, 2 };
    arr = .{ arr[1], arr[0] };
    // The previous line is equivalent to the following two lines:
    //   arr[0] = arr[1];
    //   arr[1] = arr[0];
    // So this fails!
    try expect(arr[0] == 2); // succeeds
    try expect(arr[1] == 1); // fails
}</code></pre>
<figcaption>result_location_interfering_with_swap.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test result_location_interfering_with_swap.zig
1/1 result_location_interfering_with_swap.test.attempt to swap array elements with array initializer...FAIL (TestUnexpectedResult)
/home/andy/src/zig/lib/std/testing.zig:580:14: 0x104896f in expect (test)
    if (!ok) return error.TestUnexpectedResult;
             ^
/home/andy/src/zig/doc/langref/result_location_interfering_with_swap.zig:10:5: 0x1048a55 in test.attempt to swap array elements with array initializer (test)
    try expect(arr[1] == 1); // fails
    ^
0 passed; 0 skipped; 1 failed.
error: the following test command failed with exit code 1:
/home/andy/src/zig/.zig-cache/o/1ab5fe7528c3fb20f26dc032b4e272d9/test --seed=0x35f0babc</code></pre>
<figcaption>Shell</figcaption>
</figure>

The following table details how some common expressions propagate result
locations, where `x` and `y` are arbitrary sub-expressions. Note that
some expressions cannot provide meaningful result locations to
sub-expressions, even if they themselves have a result location.

::: table-wrapper
  Expression                         Result Location   Sub-expression Result Locations
  ---------------------------------- ----------------- -----------------------------------------------------------------------------------
  [`const`]{.tok-kw}` val: T = x`    \-                `x` has result location `&val`
  [`var`]{.tok-kw}` val: T = x`      \-                `x` has result location `&val`
  `val = x`                          \-                `x` has result location `&val`
  [`@as`]{.tok-builtin}`(T, x)`      `ptr`             `x` has no result location
  `&x`                               `ptr`             `x` has no result location
  `f(x)`                             `ptr`             `x` has no result location
  `.{x}`                             `ptr`             `x` has result location `&ptr[`[`0`]{.tok-number}`]`
  `.{ .a = x }`                      `ptr`             `x` has result location `&ptr.a`
  `T{x}`                             `ptr`             `x` has no result location (typed initializers do not propagate result locations)
  `T{ .a = x }`                      `ptr`             `x` has no result location (typed initializers do not propagate result locations)
  [`@Type`]{.tok-builtin}`(x)`       `ptr`             `x` has no result location
  [`@typeInfo`]{.tok-builtin}`(x)`   `ptr`             `x` has no result location
  `x << y`                           `ptr`             `x` and `y` do not have result locations
:::

## [usingnamespace](#toc-usingnamespace) [§](#usingnamespace){.hdr}

[`usingnamespace`]{.tok-kw} is a declaration that mixes all the public
declarations of the operand, which must be a [struct](#struct),
[union](#union), [enum](#enum), or [opaque](#opaque), into the
namespace:

<figure>
<pre><code>test &quot;using std namespace&quot; {
    const S = struct {
        usingnamespace @import(&quot;std&quot;);
    };
    try S.testing.expect(true);
}</code></pre>
<figcaption>test_usingnamespace.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_usingnamespace.zig
1/1 test_usingnamespace.test.using std namespace...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

[`usingnamespace`]{.tok-kw} has an important use case when organizing
the public API of a file or package. For example, one might have
`c.zig`{.file} with all of the [C imports](#Import-from-C-Header-File):

<figure>
<pre><code>pub usingnamespace @cImport({
    @cInclude(&quot;epoxy/gl.h&quot;);
    @cInclude(&quot;GLFW/glfw3.h&quot;);
    @cDefine(&quot;ST```
