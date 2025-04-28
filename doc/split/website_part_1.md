```
:::::::::: {#contents role="main"}
## [Introduction](#toc-Introduction) [§](#Introduction){.hdr} {#Introduction}

[Zig](https://ziglang.org) is a general-purpose programming language and
toolchain for maintaining **robust**, **optimal**, and **reusable**
software.

Robust
:   Behavior is correct even for edge cases such as out of memory.

Optimal
:   Write programs the best way they can behave and perform.

Reusable
:   The same code works in many environments which have different
    constraints.

Maintainable
:   Precisely communicate intent to the compiler and other programmers.
    The language imposes a low overhead to reading code and is resilient
    to changing requirements and environments.

Often the most efficient way to learn something new is to see examples,
so this documentation shows how to use each of Zig\'s features. It is
all on one page so you can search with your browser\'s search tool.

The code samples in this document are compiled and tested as part of the
main test suite of Zig.

This HTML document depends on no external files, so you can use it
offline.

## [Zig Standard Library](#toc-Zig-Standard-Library) [§](#Zig-Standard-Library){.hdr} {#Zig-Standard-Library}

The [Zig Standard
Library](https://ziglang.org/documentation/0.14.0/std/) has its own
documentation.

Zig\'s Standard Library contains commonly used algorithms, data
structures, and definitions to help you build programs or libraries. You
will see many examples of Zig\'s Standard Library used in this
documentation. To learn more about the Zig Standard Library, visit the
link above.

Alternatively, the Zig Standard Library documentation is provided with
each Zig distribution. It can be rendered via a local webserver with:

<figure>
<pre><code>zig std</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [Hello World](#toc-Hello-World) [§](#Hello-World){.hdr} {#Hello-World}

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print(&quot;Hello, {s}!\n&quot;, .{&quot;world&quot;});
}</code></pre>
<figcaption>hello.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe hello.zig
$ ./hello
Hello, world!</code></pre>
<figcaption>Shell</figcaption>
</figure>

Most of the time, it is more appropriate to write to stderr rather than
stdout, and whether or not the message is successfully written to the
stream is irrelevant. For this common case, there is a simpler API:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

pub fn main() void {
    std.debug.print(&quot;Hello, world!\n&quot;, .{});
}</code></pre>
<figcaption>hello_again.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe hello_again.zig
$ ./hello_again
Hello, world!</code></pre>
<figcaption>Shell</figcaption>
</figure>

In this case, the `!` may be omitted from the return type of `main`
because no errors are returned from the function.

See also:

- [Values](#Values)
- [Tuples](#Tuples)
- [\@import](#import)
- [Errors](#Errors)
- [Entry Point](#Entry-Point)
- [Source Encoding](#Source-Encoding)
- [try](#try)

## [Comments](#toc-Comments) [§](#Comments){.hdr} {#Comments}

Zig supports 3 types of comments. Normal comments are ignored, but doc
comments and top-level doc comments are used by the compiler to generate
the package documentation.

The generated documentation is still experimental, and can be produced
with:

<figure>
<pre><code>zig test -femit-docs main.zig</code></pre>
<figcaption>Shell</figcaption>
</figure>

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

pub fn main() void {
    // Comments in Zig start with &quot;//&quot; and end at the next LF byte (end of line).
    // The line below is a comment and won&#39;t be executed.

    //print(&quot;Hello?&quot;, .{});

    print(&quot;Hello, world!\n&quot;, .{}); // another comment
}</code></pre>
<figcaption>comments.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe comments.zig
$ ./comments
Hello, world!</code></pre>
<figcaption>Shell</figcaption>
</figure>

There are no multiline comments in Zig (e.g. like `/* */`{.c} comments
in C). This allows Zig to have the property that each line of code can
be tokenized out of context.

### [Doc Comments](#toc-Doc-Comments) [§](#Doc-Comments){.hdr} {#Doc-Comments}

A doc comment is one that begins with exactly three slashes (i.e.
[`///`]{.tok-comment} but not [`////`]{.tok-comment}); multiple doc
comments in a row are merged together to form a multiline doc comment.
The doc comment documents whatever immediately follows it.

<figure>
<pre><code>/// A structure for storing a timestamp, with nanosecond precision (this is a
/// multiline doc comment).
const Timestamp = struct {
    /// The number of seconds since the epoch (this is also a doc comment).
    seconds: i64, // signed so we can represent pre-1970 (not a doc comment)
    /// The number of nanoseconds past the second (doc comment again).
    nanos: u32,

    /// Returns a `Timestamp` struct representing the Unix epoch; that is, the
    /// moment of 1970 Jan 1 00:00:00 UTC (this is a doc comment too).
    pub fn unixEpoch() Timestamp {
        return Timestamp{
            .seconds = 0,
            .nanos = 0,
        };
    }
};</code></pre>
<figcaption>doc_comments.zig</figcaption>
</figure>

Doc comments are only allowed in certain places; it is a compile error
to have a doc comment in an unexpected place, such as in the middle of
an expression, or just before a non-doc comment.

<figure>
<pre><code>/// doc-comment
//! top-level doc-comment
const std = @import(&quot;std&quot;);</code></pre>
<figcaption>invalid_doc-comment.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-obj invalid_doc-comment.zig
doc/langref/invalid_doc-comment.zig:1:16: error: expected type expression, found &#39;a document comment&#39;
/// doc-comment
               ^
</code></pre>
<figcaption>Shell</figcaption>
</figure>

<figure>
<pre><code>pub fn main() void {}

/// End of file</code></pre>
<figcaption>unattached_doc-comment.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-obj unattached_doc-comment.zig
doc/langref/unattached_doc-comment.zig:3:1: error: unattached documentation comment
/// End of file
^~~~~~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

Doc comments can be interleaved with normal comments. Currently, when
producing the package documentation, normal comments are merged with doc
comments.

### [Top-Level Doc Comments](#toc-Top-Level-Doc-Comments) [§](#Top-Level-Doc-Comments){.hdr} {#Top-Level-Doc-Comments}

A top-level doc comment is one that begins with two slashes and an
exclamation point: [`//!`]{.tok-comment}; it documents the current
module.

It is a compile error if a top-level doc comment is not placed at the
start of a [container](#Containers), before any expressions.

<figure>
<pre><code>//! This module provides functions for retrieving the current date and
//! time with varying degrees of precision and accuracy. It does not
//! depend on libc, but will use functions from it if available.

const S = struct {
    //! Top level comments are allowed inside a container other than a module,
    //! but it is not very useful.  Currently, when producing the package
    //! documentation, these comments are ignored.
};</code></pre>
<figcaption>tldoc_comments.zig</figcaption>
</figure>

## [Values](#toc-Values) [§](#Values){.hdr} {#Values}

<figure>
<pre><code>// Top-level declarations are order-independent:
const print = std.debug.print;
const std = @import(&quot;std&quot;);
const os = std.os;
const assert = std.debug.assert;

pub fn main() void {
    // integers
    const one_plus_one: i32 = 1 + 1;
    print(&quot;1 + 1 = {}\n&quot;, .{one_plus_one});

    // floats
    const seven_div_three: f32 = 7.0 / 3.0;
    print(&quot;7.0 / 3.0 = {}\n&quot;, .{seven_div_three});

    // boolean
    print(&quot;{}\n{}\n{}\n&quot;, .{
        true and false,
        true or false,
        !true,
    });

    // optional
    var optional_value: ?[]const u8 = null;
    assert(optional_value == null);

    print(&quot;\noptional 1\ntype: {}\nvalue: {?s}\n&quot;, .{
        @TypeOf(optional_value), optional_value,
    });

    optional_value = &quot;hi&quot;;
    assert(optional_value != null);

    print(&quot;\noptional 2\ntype: {}\nvalue: {?s}\n&quot;, .{
        @TypeOf(optional_value), optional_value,
    });

    // error union
    var number_or_error: anyerror!i32 = error.ArgNotFound;

    print(&quot;\nerror union 1\ntype: {}\nvalue: {!}\n&quot;, .{
        @TypeOf(number_or_error),
        number_or_error,
    });

    number_or_error = 1234;

    print(&quot;\nerror union 2\ntype: {}\nvalue: {!}\n&quot;, .{
        @TypeOf(number_or_error), number_or_error,
    });
}</code></pre>
<figcaption>values.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe values.zig
$ ./values
1 + 1 = 2
7.0 / 3.0 = 2.3333333e0
false
true
false

optional 1
type: ?[]const u8
value: null

optional 2
type: ?[]const u8
value: hi

error union 1
type: anyerror!i32
value: error.ArgNotFound

error union 2
type: anyerror!i32
value: 1234</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Primitive Types](#toc-Primitive-Types) [§](#Primitive-Types){.hdr} {#Primitive-Types}

::: table-wrapper
  Type                            C Equivalent                    Description
  ------------------------------- ------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------
  [`i8`]{.tok-type}               `int8_t`{.c}                    signed 8-bit integer
  [`u8`]{.tok-type}               `uint8_t`{.c}                   unsigned 8-bit integer
  [`i16`]{.tok-type}              `int16_t`{.c}                   signed 16-bit integer
  [`u16`]{.tok-type}              `uint16_t`{.c}                  unsigned 16-bit integer
  [`i32`]{.tok-type}              `int32_t`{.c}                   signed 32-bit integer
  [`u32`]{.tok-type}              `uint32_t`{.c}                  unsigned 32-bit integer
  [`i64`]{.tok-type}              `int64_t`{.c}                   signed 64-bit integer
  [`u64`]{.tok-type}              `uint64_t`{.c}                  unsigned 64-bit integer
  [`i128`]{.tok-type}             `__int128`{.c}                  signed 128-bit integer
  [`u128`]{.tok-type}             `unsigned __int128`{.c}         unsigned 128-bit integer
  [`isize`]{.tok-type}            `intptr_t`{.c}                  signed pointer sized integer
  [`usize`]{.tok-type}            `uintptr_t`{.c}, `size_t`{.c}   unsigned pointer sized integer. Also see [#5185](https://github.com/ziglang/zig/issues/5185)
  [`c_char`]{.tok-type}           `char`{.c}                      for ABI compatibility with C
  [`c_short`]{.tok-type}          `short`{.c}                     for ABI compatibility with C
  [`c_ushort`]{.tok-type}         `unsigned short`{.c}            for ABI compatibility with C
  [`c_int`]{.tok-type}            `int`{.c}                       for ABI compatibility with C
  [`c_uint`]{.tok-type}           `unsigned int`{.c}              for ABI compatibility with C
  [`c_long`]{.tok-type}           `long`{.c}                      for ABI compatibility with C
  [`c_ulong`]{.tok-type}          `unsigned long`{.c}             for ABI compatibility with C
  [`c_longlong`]{.tok-type}       `long long`{.c}                 for ABI compatibility with C
  [`c_ulonglong`]{.tok-type}      `unsigned long long`{.c}        for ABI compatibility with C
  [`c_longdouble`]{.tok-type}     `long double`{.c}               for ABI compatibility with C
  [`f16`]{.tok-type}              `_Float16`{.c}                  16-bit floating point (10-bit mantissa) IEEE-754-2008 binary16
  [`f32`]{.tok-type}              `float`{.c}                     32-bit floating point (23-bit mantissa) IEEE-754-2008 binary32
  [`f64`]{.tok-type}              `double`{.c}                    64-bit floating point (52-bit mantissa) IEEE-754-2008 binary64
  [`f80`]{.tok-type}              `long double`{.c}               80-bit floating point (64-bit mantissa) IEEE-754-2008 80-bit extended precision
  [`f128`]{.tok-type}             `_Float128`{.c}                 128-bit floating point (112-bit mantissa) IEEE-754-2008 binary128
  [`bool`]{.tok-type}             `bool`{.c}                      [`true`]{.tok-null} or [`false`]{.tok-null}
  [`anyopaque`]{.tok-type}        `void`{.c}                      Used for type-erased pointers.
  [`void`]{.tok-type}             (none)                          Always the value [`void`]{.tok-type}`{}`
  [`noreturn`]{.tok-type}         (none)                          the type of [`break`]{.tok-kw}, [`continue`]{.tok-kw}, [`return`]{.tok-kw}, [`unreachable`]{.tok-kw}, and [`while`]{.tok-kw}` (`[`true`]{.tok-null}`) {}`
  [`type`]{.tok-type}             (none)                          the type of types
  [`anyerror`]{.tok-type}         (none)                          an error code
  [`comptime_int`]{.tok-type}     (none)                          Only allowed for [comptime](#comptime)-known values. The type of integer literals.
  [`comptime_float`]{.tok-type}   (none)                          Only allowed for [comptime](#comptime)-known values. The type of float literals.

  : Primitive Types
:::

In addition to the integer types above, arbitrary bit-width integers can
be referenced by using an identifier of `i` or `u` followed by digits.
For example, the identifier [`i7`]{.tok-type} refers to a signed 7-bit
integer. The maximum allowed bit-width of an integer type is
[`65535`]{.tok-number}.

See also:

- [Integers](#Integers)
- [Floats](#Floats)
- [void](#void)
- [Errors](#Errors)
- [\@Type](#Type)

### [Primitive Values](#toc-Primitive-Values) [§](#Primitive-Values){.hdr} {#Primitive-Values}

::: table-wrapper
  Name                                           Description
  ---------------------------------------------- -----------------------------------------------------
  [`true`]{.tok-null} and [`false`]{.tok-null}   [`bool`]{.tok-type} values
  [`null`]{.tok-null}                            used to set an optional type to [`null`]{.tok-null}
  [`undefined`]{.tok-null}                       used to leave a value unspecified

  : Primitive Values
:::

See also:

- [Optionals](#Optionals)
- [undefined](#undefined)

### [String Literals and Unicode Code Point Literals](#toc-String-Literals-and-Unicode-Code-Point-Literals) [§](#String-Literals-and-Unicode-Code-Point-Literals){.hdr} {#String-Literals-and-Unicode-Code-Point-Literals}

String literals are constant single-item [Pointers](#Pointers) to
null-terminated byte arrays. The type of string literals encodes both
the length, and the fact that they are null-terminated, and thus they
can be [coerced](#Type-Coercion) to both [Slices](#Slices) and
[Null-Terminated Pointers](#Sentinel-Terminated-Pointers). Dereferencing
string literals converts them to [Arrays](#Arrays).

Because Zig source code is [UTF-8 encoded](#Source-Encoding), any
non-ASCII bytes appearing within a string literal in source code carry
their UTF-8 meaning into the content of the string in the Zig program;
the bytes are not modified by the compiler. It is possible to embed
non-UTF-8 bytes into a string literal using `\xNN` notation.

Indexing into a string containing non-ASCII bytes returns individual
bytes, whether valid UTF-8 or not.

Unicode code point literals have type [`comptime_int`]{.tok-type}, the
same as [Integer Literals](#Integer-Literals). All [Escape
Sequences](#Escape-Sequences) are valid in both string literals and
Unicode code point literals.

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;
const mem = @import(&quot;std&quot;).mem; // will be used to compare bytes

pub fn main() void {
    const bytes = &quot;hello&quot;;
    print(&quot;{}\n&quot;, .{@TypeOf(bytes)}); // *const [5:0]u8
    print(&quot;{d}\n&quot;, .{bytes.len}); // 5
    print(&quot;{c}\n&quot;, .{bytes[1]}); // &#39;e&#39;
    print(&quot;{d}\n&quot;, .{bytes[5]}); // 0
    print(&quot;{}\n&quot;, .{&#39;e&#39; == &#39;\x65&#39;}); // true
    print(&quot;{d}\n&quot;, .{&#39;\u{1f4a9}&#39;}); // 128169
    print(&quot;{d}\n&quot;, .{&#39;💯&#39;}); // 128175
    print(&quot;{u}\n&quot;, .{&#39;⚡&#39;});
    print(&quot;{}\n&quot;, .{mem.eql(u8, &quot;hello&quot;, &quot;h\x65llo&quot;)}); // true
    print(&quot;{}\n&quot;, .{mem.eql(u8, &quot;💯&quot;, &quot;\xf0\x9f\x92\xaf&quot;)}); // also true
    const invalid_utf8 = &quot;\xff\xfe&quot;; // non-UTF-8 strings are possible with \xNN notation.
    print(&quot;0x{x}\n&quot;, .{invalid_utf8[1]}); // indexing them returns individual bytes...
    print(&quot;0x{x}\n&quot;, .{&quot;💯&quot;[1]}); // ...as does indexing part-way through non-ASCII characters
}</code></pre>
<figcaption>string_literals.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe string_literals.zig
$ ./string_literals
*const [5:0]u8
5
e
0
true
128169
128175
⚡
true
true
0xfe
0x9f</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Arrays](#Arrays)
- [Source Encoding](#Source-Encoding)

#### [Escape Sequences](#toc-Escape-Sequences) [§](#Escape-Sequences){.hdr} {#Escape-Sequences}

::: table-wrapper
  Escape Sequence   Name
  ----------------- -------------------------------------------------------------------
  `\n`              Newline
  `\r`              Carriage Return
  `\t`              Tab
  `\\`              Backslash
  `\'`              Single Quote
  `\"`              Double Quote
  `\xNN`            hexadecimal 8-bit byte value (2 digits)
  `\u{NNNNNN}`      hexadecimal Unicode scalar value UTF-8 encoded (1 or more digits)

  : Escape Sequences
:::

Note that the maximum valid Unicode scalar value is
[`0x10ffff`]{.tok-number}.

#### [Multiline String Literals](#toc-Multiline-String-Literals) [§](#Multiline-String-Literals){.hdr} {#Multiline-String-Literals}

Multiline string literals have no escapes and can span across multiple
lines. To start a multiline string literal, use the [`\\`]{.tok-str}
token. Just like a comment, the string literal goes until the end of the
line. The end of the line is not included in the string literal.
However, if the next line begins with [`\\`]{.tok-str} then a newline is
appended and the string literal continues.

<figure>
<pre><code>const hello_world_in_c =
    \\#include &lt;stdio.h&gt;
    \\
    \\int main(int argc, char **argv) {
    \\    printf(&quot;hello world\n&quot;);
    \\    return 0;
    \\}
;</code></pre>
<figcaption>multiline_string_literals.zig</figcaption>
</figure>

See also:

- [\@embedFile](#embedFile)

### [Assignment](#toc-Assignment) [§](#Assignment){.hdr} {#Assignment}

Use the [`const`]{.tok-kw} keyword to assign a value to an identifier:

<figure>
<pre><code>const x = 1234;

fn foo() void {
    // It works at file scope as well as inside functions.
    const y = 5678;

    // Once assigned, an identifier cannot be changed.
    y += 1;
}

pub fn main() void {
    foo();
}</code></pre>
<figcaption>constant_identifier_cannot_change.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe constant_identifier_cannot_change.zig
/home/andy/src/zig/doc/langref/constant_identifier_cannot_change.zig:8:7: error: cannot assign to constant
    y += 1;
    ~~^~~~
referenced by:
    main: /home/andy/src/zig/doc/langref/constant_identifier_cannot_change.zig:12:8
    posixCallMainAndExit: /home/andy/src/zig/lib/std/start.zig:647:22
    4 reference(s) hidden; use &#39;-freference-trace=6&#39; to see all references
</code></pre>
<figcaption>Shell</figcaption>
</figure>

[`const`]{.tok-kw} applies to all of the bytes that the identifier
immediately addresses. [Pointers](#Pointers) have their own const-ness.

If you need a variable that you can modify, use the [`var`]{.tok-kw}
keyword:

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

pub fn main() void {
    var y: i32 = 5678;

    y += 1;

    print(&quot;{d}&quot;, .{y});
}</code></pre>
<figcaption>mutable_var.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe mutable_var.zig
$ ./mutable_var
5679</code></pre>
<figcaption>Shell</figcaption>
</figure>

Variables must be initialized:

<figure>
<pre><code>pub fn main() void {
    var x: i32;

    x = 1;
}</code></pre>
<figcaption>var_must_be_initialized.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe var_must_be_initialized.zig
/home/andy/src/zig/doc/langref/var_must_be_initialized.zig:2:15: error: expected &#39;=&#39;, found &#39;;&#39;
    var x: i32;
              ^
</code></pre>
<figcaption>Shell</figcaption>
</figure>

#### [undefined](#toc-undefined) [§](#undefined){.hdr}

Use [`undefined`]{.tok-null} to leave variables uninitialized:

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

pub fn main() void {
    var x: i32 = undefined;
    x = 1;
    print(&quot;{d}&quot;, .{x});
}</code></pre>
<figcaption>assign_undefined.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe assign_undefined.zig
$ ./assign_undefined
1</code></pre>
<figcaption>Shell</figcaption>
</figure>

[`undefined`]{.tok-null} can be [coerced](#Type-Coercion) to any type.
Once this happens, it is no longer possible to detect that the value is
[`undefined`]{.tok-null}. [`undefined`]{.tok-null} means the value could
be anything, even something that is nonsense according to the type.
Translated into English, [`undefined`]{.tok-null} means \"Not a
meaningful value. Using this value would be a bug. The value will be
unused, or overwritten before being used.\"

In [Debug](#Debug) mode, Zig writes [`0xaa`]{.tok-number} bytes to
undefined memory. This is to catch bugs early, and to help detect use of
undefined memory in a debugger. However, this behavior is only an
implementation feature, not a language semantic, so it is not guaranteed
to be observable to code.

#### [Destructuring](#toc-Destructuring) [§](#Destructuring){.hdr} {#Destructuring}

A destructuring assignment can separate elements of indexable aggregate
types ([Tuples](#Tuples), [Arrays](#Arrays), [Vectors](#Vectors)):

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

pub fn main() void {
    var x: u32 = undefined;
    var y: u32 = undefined;
    var z: u32 = undefined;

    const tuple = .{ 1, 2, 3 };

    x, y, z = tuple;

    print(&quot;tuple: x = {}, y = {}, z = {}\n&quot;, .{x, y, z});

    const array = [_]u32{ 4, 5, 6 };

    x, y, z = array;

    print(&quot;array: x = {}, y = {}, z = {}\n&quot;, .{x, y, z});

    const vector: @Vector(3, u32) = .{ 7, 8, 9 };

    x, y, z = vector;

    print(&quot;vector: x = {}, y = {}, z = {}\n&quot;, .{x, y, z});
}</code></pre>
<figcaption>destructuring_to_existing.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe destructuring_to_existing.zig
$ ./destructuring_to_existing
tuple: x = 1, y = 2, z = 3
array: x = 4, y = 5, z = 6
vector: x = 7, y = 8, z = 9</code></pre>
<figcaption>Shell</figcaption>
</figure>

A destructuring expression may only appear within a block (i.e. not at
container scope). The left hand side of the assignment must consist of a
comma separated list, each element of which may be either an lvalue (for
instance, an existing \`var\`) or a variable declaration:

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

pub fn main() void {
    var x: u32 = undefined;

    const tuple = .{ 1, 2, 3 };

    x, var y : u32, const z = tuple;

    print(&quot;x = {}, y = {}, z = {}\n&quot;, .{x, y, z});

    // y is mutable
    y = 100;

    // You can use _ to throw away unwanted values.
    _, x, _ = tuple;

    print(&quot;x = {}&quot;, .{x});
}</code></pre>
<figcaption>destructuring_mixed.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe destructuring_mixed.zig
$ ./destructuring_mixed
x = 1, y = 2, z = 3
x = 2</code></pre>
<figcaption>Shell</figcaption>
</figure>

A destructure may be prefixed with the [`comptime`]{.tok-kw} keyword, in
which case the entire destructure expression is evaluated at
[comptime](#comptime). All [`var`]{.tok-kw}s declared would be
[`comptime`]{.tok-kw}` `[`var`]{.tok-kw}s and all expressions (both
result locations and the assignee expression) are evaluated at
[comptime](#comptime).

See also:

- [Destructuring Tuples](#Destructuring-Tuples)
- [Destructuring Arrays](#Destructuring-Arrays)
- [Destructuring Vectors](#Destructuring-Vectors)

## [Zig Test](#toc-Zig-Test) [§](#Zig-Test){.hdr} {#Zig-Test}

Code written within one or more [`test`]{.tok-kw} declarations can be
used to ensure behavior meets expectations:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

test &quot;expect addOne adds one to 41&quot; {

    // The Standard Library contains useful functions to help create tests.
    // `expect` is a function that verifies its argument is true.
    // It will return an error if its argument is false to indicate a failure.
    // `try` is used to return an error to the test runner to notify it that the test failed.
    try std.testing.expect(addOne(41) == 42);
}

test addOne {
    // A test name can also be written using an identifier.
    // This is a doctest, and serves as documentation for `addOne`.
    try std.testing.expect(addOne(41) == 42);
}

/// The function `addOne` adds one to the number given as its argument.
fn addOne(number: i32) i32 {
    return number + 1;
}</code></pre>
<figcaption>testing_introduction.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test testing_introduction.zig
1/2 testing_introduction.test.expect addOne adds one to 41...OK
2/2 testing_introduction.decltest.addOne...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

The `testing_introduction.zig`{.file} code sample tests the
[function](#Functions) `addOne` to ensure that it returns
[`42`]{.tok-number} given the input [`41`]{.tok-number}. From this
test\'s perspective, the `addOne` function is said to be *code under
test*.

[zig test]{.kbd} is a tool that creates and runs a test build. By
default, it builds and runs an executable program using the *default
test runner* provided by the [Zig Standard
Library](#Zig-Standard-Library) as its main entry point. During the
build, [`test`]{.tok-kw} declarations found while
[resolving](#File-and-Declaration-Discovery) the given Zig source file
are included for the default test runner to run and report on.

This documentation discusses the features of the default test runner as
provided by the Zig Standard Library. Its source code is located in
`lib/compiler/test_runner.zig`{.file}.

The shell output shown above displays two lines after the [zig
test]{.kbd} command. These lines are printed to standard error by the
default test runner:

`1/2 testing_introduction.test.expect addOne adds one to 41...`{.sample}
:   Lines like this indicate which test, out of the total number of
    tests, is being run. In this case, `1/2`{.sample} indicates that the
    first test, out of a total of two tests, is being run. Note that,
    when the test runner program\'s standard error is output to the
    terminal, these lines are cleared when a test succeeds.

`2/2 testing_introduction.decltest.addOne...`{.sample}
:   When the test name is an identifier, the default test runner uses
    the text decltest instead of test.

`All 2 tests passed.`{.sample}
:   This line indicates the total number of tests that have passed.

### [Test Declarations](#toc-Test-Declarations) [§](#Test-Declarations){.hdr} {#Test-Declarations}

Test declarations contain the [keyword](#Keyword-Reference)
[`test`]{.tok-kw}, followed by an optional name written as a [string
literal](#String-Literals-and-Unicode-Code-Point-Literals) or an
[identifier](#Identifiers), followed by a [block](#Blocks) containing
any valid Zig code that is allowed in a [function](#Functions).

Non-named test blocks always run during test builds and are exempt from
[Skip Tests](#Skip-Tests).

Test declarations are similar to [Functions](#Functions): they have a
return type and a block of code. The implicit return type of
[`test`]{.tok-kw} is the [Error Union Type](#Error-Union-Type)
[`anyerror`]{.tok-type}`!`[`void`]{.tok-type}, and it cannot be changed.
When a Zig source file is not built using the [zig test]{.kbd} tool, the
test declarations are omitted from the build.

Test declarations can be written in the same file, where code under test
is written, or in a separate Zig source file. Since test declarations
are top-level declarations, they are order-independent and can be
written before or after the code under test.

See also:

- [The Global Error Set](#The-Global-Error-Set)
- [Grammar](#Grammar)

#### [Doctests](#toc-Doctests) [§](#Doctests){.hdr} {#Doctests}

Test declarations named using an identifier are *doctests*. The
identifier must refer to another declaration in scope. A doctest, like a
[doc comment](#Doc-Comments), serves as documentation for the associated
declaration, and will appear in the generated documentation for the
declaration.

An effective doctest should be self-contained and focused on the
declaration being tested, answering questions a new user might have
about its interface or intended usage, while avoiding unnecessary or
confusing details. A doctest is not a substitute for a doc comment, but
rather a supplement and companion providing a testable, code-driven
example, verified by [zig test]{.kbd}.

### [Test Failure](#toc-Test-Failure) [§](#Test-Failure){.hdr} {#Test-Failure}

The default test runner checks for an [error](#Errors) returned from a
test. When a test returns an error, the test is considered a failure and
its [error return trace](#Error-Return-Traces) is output to standard
error. The total number of failures will be reported after all tests
have run.

<figure>
<pre><code>const std = @import(&quot;std&quot;);

test &quot;expect this to fail&quot; {
    try std.testing.expect(false);
}

test &quot;expect this to succeed&quot; {
    try std.testing.expect(true);
}</code></pre>
<figcaption>testing_failure.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test testing_failure.zig
1/2 testing_failure.test.expect this to fail...FAIL (TestUnexpectedResult)
/home/andy/src/zig/lib/std/testing.zig:580:14: 0x104899f in expect (test)
    if (!ok) return error.TestUnexpectedResult;
             ^
/home/andy/src/zig/doc/langref/testing_failure.zig:4:5: 0x1048a35 in test.expect this to fail (test)
    try std.testing.expect(false);
    ^
2/2 testing_failure.test.expect this to succeed...OK
1 passed; 0 skipped; 1 failed.
error: the following test command failed with exit code 1:
/home/andy/src/zig/.zig-cache/o/4b55be885f04d4406910bf905e0a160c/test --seed=0x5dd97878</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Skip Tests](#toc-Skip-Tests) [§](#Skip-Tests){.hdr} {#Skip-Tests}

One way to skip tests is to filter them out by using the [zig
test]{.kbd} command line parameter [\--test-filter \[text\]]{.kbd}. This
makes the test build only include tests whose name contains the supplied
filter text. Note that non-named tests are run even when using the
[\--test-filter \[text\]]{.kbd} command line parameter.

To programmatically skip a test, make a [`test`]{.tok-kw} return the
error [`error`]{.tok-kw}`.SkipZigTest` and the default test runner will
consider the test as being skipped. The total number of skipped tests
will be reported after all tests have run.

<figure>
<pre><code>test &quot;this will be skipped&quot; {
    return error.SkipZigTest;
}</code></pre>
<figcaption>testing_skip.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test testing_skip.zig
1/1 testing_skip.test.this will be skipped...SKIP
0 passed; 1 skipped; 0 failed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Report Memory Leaks](#toc-Report-Memory-Leaks) [§](#Report-Memory-Leaks){.hdr} {#Report-Memory-Leaks}

When code allocates [Memory](#Memory) using the [Zig Standard
Library](#Zig-Standard-Library)\'s testing allocator,
`std.testing.allocator`, the default test runner will report any leaks
that are found from using the testing allocator:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

test &quot;detect leak&quot; {
    var list = std.ArrayList(u21).init(std.testing.allocator);
    // missing `defer list.deinit();`
    try list.append(&#39;☔&#39;);

    try std.testing.expect(list.items.len == 1);
}</code></pre>
<figcaption>testing_detect_leak.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test testing_detect_leak.zig
1/1 testing_detect_leak.test.detect leak...OK
[gpa] (err): memory address 0x7f7537720000 leaked:
/home/andy/src/zig/lib/std/array_list.zig:474:67: 0x10695a2 in ensureTotalCapacityPrecise (test)
                const new_memory = try self.allocator.alignedAlloc(T, alignment, new_capacity);
                                                                  ^
/home/andy/src/zig/lib/std/array_list.zig:450:51: 0x104ea80 in ensureTotalCapacity (test)
            return self.ensureTotalCapacityPrecise(better_capacity);
                                                  ^
/home/andy/src/zig/lib/std/array_list.zig:500:41: 0x104cdaf in addOne (test)
            try self.ensureTotalCapacity(newlen);
                                        ^
/home/andy/src/zig/lib/std/array_list.zig:261:49: 0x104a8cd in append (test)
            const new_item_ptr = try self.addOne();
                                                ^
/home/andy/src/zig/doc/langref/testing_detect_leak.zig:6:20: 0x1048d05 in test.detect leak (test)
    try list.append(&#39;☔&#39;);
                   ^
/home/andy/src/zig/lib/compiler/test_runner.zig:214:25: 0x10f7c35 in mainTerminal (test)
        if (test_fn.func()) |_| {
                        ^
/home/andy/src/zig/lib/compiler/test_runner.zig:62:28: 0x10f1c8d in main (test)
        return mainTerminal();
                           ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10f1212 in posixCallMainAndExit (test)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10f0ded in _start (test)
    asm volatile (switch (native_arch) {
    ^

All 1 tests passed.
1 errors were logged.
1 tests leaked memory.
error: the following test command failed with exit code 1:
/home/andy/src/zig/.zig-cache/o/9073e84ae632f507d6f6e265f9c82f56/test --seed=0xe9497de3</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [defer](#defer)
- [Memory](#Memory)

### [Detecting Test Build](#toc-Detecting-Test-Build) [§](#Detecting-Test-Build){.hdr} {#Detecting-Test-Build}

Use the [compile variable](#Compile-Variables)
[`@import`]{.tok-builtin}`(`[`"builtin"`]{.tok-str}`).is_test` to detect
a test build:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const builtin = @import(&quot;builtin&quot;);
const expect = std.testing.expect;

test &quot;builtin.is_test&quot; {
    try expect(isATest());
}

fn isATest() bool {
    return builtin.is_test;
}</code></pre>
<figcaption>testing_detect_test.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test testing_detect_test.zig
1/1 testing_detect_test.test.builtin.is_test...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Test Output and Logging](#toc-Test-Output-and-Logging) [§](#Test-Output-and-Logging){.hdr} {#Test-Output-and-Logging}

The default test runner and the Zig Standard Library\'s testing
namespace output messages to standard error.

### [The Testing Namespace](#toc-The-Testing-Namespace) [§](#The-Testing-Namespace){.hdr} {#The-Testing-Namespace}

The Zig Standard Library\'s `testing` namespace contains useful
functions to help you create tests. In addition to the `expect`
function, this document uses a couple of more functions as exemplified
here:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

test &quot;expectEqual demo&quot; {
    const expected: i32 = 42;
    const actual = 42;

    // The first argument to `expectEqual` is the known, expected, result.
    // The second argument is the result of some expression.
    // The actual&#39;s type is casted to the type of expected.
    try std.testing.expectEqual(expected, actual);
}

test &quot;expectError demo&quot; {
    const expected_error = error.DemoError;
    const actual_error_union: anyerror!void = error.DemoError;

    // `expectError` will fail when the actual error is different than
    // the expected error.
    try std.testing.expectError(expected_error, actual_error_union);
}</code></pre>
<figcaption>testing_namespace.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test testing_namespace.zig
1/2 testing_namespace.test.expectEqual demo...OK
2/2 testing_namespace.test.expectError demo...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

The Zig Standard Library also contains functions to compare
[Slices](#Slices), strings, and more. See the rest of the `std.testing`
namespace in the [Zig Standard Library](#Zig-Standard-Library) for more
available functions.

### [Test Tool Documentation](#toc-Test-Tool-Documentation) [§](#Test-Tool-Documentation){.hdr} {#Test-Tool-Documentation}

[zig test]{.kbd} has a few command line parameters which affect the
compilation. See [zig test \--help]{.kbd} for a full list.

## [Variables](#toc-Variables) [§](#Variables){.hdr} {#Variables}

A variable is a unit of [Memory](#Memory) storage.

It is generally preferable to use [`const`]{.tok-kw} rather than
[`var`]{.tok-kw} when declaring a variable. This causes less work for
both humans and computers to do when reading code, and creates more
optimization opportunities.

The [`extern`]{.tok-kw} keyword or [\@extern](#extern) builtin function
can be used to link against a variable that is exported from another
object. The [`export`]{.tok-kw} keyword or [\@export](#export) builtin
function can be used to make a variable available to other objects at
link time. In both cases, the type of the variable must be C ABI
compatible.

See also:

- [Exporting a C Library](#Exporting-a-C-Library)

### [Identifiers](#toc-Identifiers) [§](#Identifiers){.hdr} {#Identifiers}

Variable identifiers are never allowed to shadow identifiers from an
outer scope.

Identifiers must start with an alphabetic character or underscore and
may be followed by any number of alphanumeric characters or underscores.
They must not overlap with any keywords. See [Keyword
Reference](#Keyword-Reference).

If a name that does not fit these requirements is needed, such as for
linking with external libraries, the `@""` syntax may be used.

<figure>
<pre><code>const @&quot;identifier with spaces in it&quot; = 0xff;
const @&quot;1SmallStep4Man&quot; = 112358;

const c = @import(&quot;std&quot;).c;
pub extern &quot;c&quot; fn @&quot;error&quot;() void;
pub extern &quot;c&quot; fn @&quot;fstat$INODE64&quot;(fd: c.fd_t, buf: *c.Stat) c_int;

const Color = enum {
    red,
    @&quot;really red&quot;,
};
const color: Color = .@&quot;really red&quot;;</code></pre>
<figcaption>identifiers.zig</figcaption>
</figure>

### [Container Level Variables](#toc-Container-Level-Variables) [§](#Container-Level-Variables){.hdr} {#Container-Level-Variables}

[Container](#Containers) level variables have static lifetime and are
order-independent and lazily analyzed. The initialization value of
container level variables is implicitly [comptime](#comptime). If a
container level variable is [`const`]{.tok-kw} then its value is
[`comptime`]{.tok-kw}-known, otherwise it is runtime-known.

<figure>
<pre><code>var y: i32 = add(10, x);
const x: i32 = add(12, 34);

test &quot;container level variables&quot; {
    try expect(x == 46);
    try expect(y == 56);
}

fn add(a: i32, b: i32) i32 {
    return a + b;
}

const std = @import(&quot;std&quot;);
const expect = std.testing.expect;</code></pre>
<figcaption>test_container_level_variables.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_container_level_variables.zig
1/1 test_container_level_variables.test.container level variables...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Container level variables may be declared inside a [struct](#struct),
[union](#union), [enum](#enum), or [opaque](#opaque):

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;namespaced container level variable&quot; {
    try expect(foo() == 1235);
    try expect(foo() == 1236);
}

const S = struct {
    var x: i32 = 1234;
};

fn foo() i32 {
    S.x += 1;
    return S.x;
}</code></pre>
<figcaption>test_namespaced_container_level_variable.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_namespaced_container_level_variable.zig
1/1 test_namespaced_container_level_variable.test.namespaced container level variable...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Static Local Variables](#toc-Static-Local-Variables) [§](#Static-Local-Variables){.hdr} {#Static-Local-Variables}

It is also possible to have local variables with static lifetime by
using containers inside functions.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;static local variable&quot; {
    try expect(foo() == 1235);
    try expect(foo() == 1236);
}

fn foo() i32 {
    const S = struct {
        var x: i32 = 1234;
    };
    S.x += 1;
    return S.x;
}</code></pre>
<figcaption>test_static_local_variable.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_static_local_variable.zig
1/1 test_static_local_variable.test.static local variable...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [Thread Local Variables](#toc-Thread-Local-Variables) [§](#Thread-Local-Variables){.hdr} {#Thread-Local-Variables}

A variable may be specified to be a thread-local variable using the
[`threadlocal`]{.tok-kw} keyword, which makes each thread work with a
separate instance of the variable:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const assert = std.debug.assert;

threadlocal var x: i32 = 1234;

test &quot;thread local storage&quot; {
    const thread1 = try std.Thread.spawn(.{}, testTls, .{});
    const thread2 = try std.Thread.spawn(.{}, testTls, .{});
    testTls();
    thread1.join();
    thread2.join();
}

fn testTls() void {
    assert(x == 1234);
    x += 1;
    assert(x == 1235);
}</code></pre>
<figcaption>test_thread_local_variables.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_thread_local_variables.zig
1/1 test_thread_local_variables.test.thread local storage...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

For [Single Threaded Builds](#Single-Threaded-Builds), all thread local
variables are treated as regular [Container Level
Variables](#Container-Level-Variables).

Thread local variables may not be [`const`]{.tok-kw}.

### [Local Variables](#toc-Local-Variables) [§](#Local-Variables){.hdr} {#Local-Variables}

Local variables occur inside [Functions](#Functions),
[comptime](#comptime) blocks, and [\@cImport](#cImport) blocks.

When a local variable is [`const`]{.tok-kw}, it means that after
initialization, the variable\'s value will not change. If the
initialization value of a [`const`]{.tok-kw} variable is
[comptime](#comptime)-known, then the variable is also
[`comptime`]{.tok-kw}-known.

A local variable may be qualified with the [`comptime`]{.tok-kw}
keyword. This causes the variable\'s value to be
[`comptime`]{.tok-kw}-known, and all loads and stores of the variable to
happen during semantic analysis of the program, rather than at runtime.
All variables declared in a [`comptime`]{.tok-kw} expression are
implicitly [`comptime`]{.tok-kw} variables.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;comptime vars&quot; {
    var x: i32 = 1;
    comptime var y: i32 = 1;

    x += 1;
    y += 1;

    try expect(x == 2);
    try expect(y == 2);

    if (y != 2) {
        // This compile error never triggers because y is a comptime variable,
        // and so `y != 2` is a comptime value, and this if is statically evaluated.
        @compileError(&quot;wrong y value&quot;);
    }
}</code></pre>
<figcaption>test_comptime_variables.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_variables.zig
1/1 test_comptime_variables.test.comptime vars...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [Integers](#toc-Integers) [§](#Integers){.hdr} {#Integers}

### [Integer Literals](#toc-Integer-Literals) [§](#Integer-Literals){.hdr} {#Integer-Literals}

<figure>
<pre><code>const decimal_int = 98222;
const hex_int = 0xff;
const another_hex_int = 0xFF;
const octal_int = 0o755;
const binary_int = 0b11110000;

// underscores may be placed between two digits as a visual separator
const one_billion = 1_000_000_000;
const binary_mask = 0b1_1111_1111;
const permissions = 0o7_5_5;
const big_address = 0xFF80_0000_0000_0000;</code></pre>
<figcaption>integer_literals.zig</figcaption>
</figure>

### [Runtime Integer Values](#toc-Runtime-Integer-Values) [§](#Runtime-Integer-Values){.hdr} {#Runtime-Integer-Values}

Integer literals have no size limitation, and if any Illegal Behavior
occurs, the compiler catches it.

However, once an integer value is no longer known at compile-time, it
must have a known size, and is vulnerable to safety-checked [Illegal
Behavior](#Illegal-Behavior).

<figure>
<pre><code>fn divide(a: i32, b: i32) i32 {
    return a / b;
}</code></pre>
<figcaption>runtime_vs_comptime.zig</figcaption>
</figure>

In this function, values `a` and `b` are known only at runtime, and thus
this division operation is vulnerable to both [Integer
Overflow](#Integer-Overflow) and [Division by Zero](#Division-by-Zero).

Operators such as `+` and `-` cause [Illegal
Behavior](#Illegal-Behavior) on integer overflow. Alternative operators
are provided for wrapping and saturating arithmetic on all targets. `+%`
and `-%` perform wrapping arithmetic while `+|` and `-|` perform
saturating arithmetic.

Zig supports arbitrary bit-width integers, referenced by using an
identifier of `i` or `u` followed by digits. For example, the identifier
[`i7`]{.tok-type} refers to a signed 7-bit integer. The maximum allowed
bit-width of an integer type is [`65535`]{.tok-number}. For signed
integer types, Zig uses a [two\'s
complement](https://en.wikipedia.org/wiki/Two's_complement)
representation.

See also:

- [Wrapping Operations](#Wrapping-Operations)

## [Floats](#toc-Floats) [§](#Floats){.hdr} {#Floats}

Zig has the following floating point types:

- [`f16`]{.tok-type} - IEEE-754-2008 binary16
- [`f32`]{.tok-type} - IEEE-754-2008 binary32
- [`f64`]{.tok-type} - IEEE-754-2008 binary64
- [`f80`]{.tok-type} - IEEE-754-2008 80-bit extended precision
- [`f128`]{.tok-type} - IEEE-754-2008 binary128
- [`c_longdouble`]{.tok-type} - matches `long double`{.c} for the target
  C ABI

### [Float Literals](#toc-Float-Literals) [§](#Float-Literals){.hdr} {#Float-Literals}

Float literals have type [`comptime_float`]{.tok-type} which is
guaranteed to have the same precision and operations of the largest
other floating point type, which is [`f128`]{.tok-type}.

Float literals [coerce](#Type-Coercion) to any floating point type, and
to any [integer](#Integers) type when there is no fractional component.

<figure>
<pre><code>const floating_point = 123.0E+77;
const another_float = 123.0;
const yet_another = 123.0e+77;

const hex_floating_point = 0x103.70p-5;
const another_hex_float = 0x103.70;
const yet_another_hex_float = 0x103.70P-5;

// underscores may be placed between two digits as a visual separator
const lightspeed = 299_792_458.000_000;
const nanosecond = 0.000_000_001;
const more_hex = 0x1234_5678.9ABC_CDEFp-10;</code></pre>
<figcaption>float_literals.zig</figcaption>
</figure>

There is no syntax for NaN, infinity, or negative infinity. For these
special values, one must use the standard library:

<figure>
<pre><code>const std = @import(&quot;std&quot;);

const inf = std.math.inf(f32);
const negative_inf = -std.math.inf(f64);
const nan = std.math.nan(f128);</code></pre>
<figcaption>float_special_values.zig</figcaption>
</figure>

### [Floating Point Operations](#toc-Floating-Point-Operations) [§](#Floating-Point-Operations){.hdr} {#Floating-Point-Operations}

By default floating point operations use `Strict` mode, but you can
switch to `Optimized` mode on a per-block basis:

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const big = @as(f64, 1 &lt;&lt; 40);

export fn foo_strict(x: f64) f64 {
    return x + big - big;
}

export fn foo_optimized(x: f64) f64 {
    @setFloatMode(.optimized);
    return x + big - big;
}</code></pre>
<figcaption>float_mode_obj.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-obj float_mode_obj.zig -O ReleaseFast</code></pre>
<figcaption>Shell</figcaption>
</figure>

For this test we have to separate code into two object files - otherwise
the optimizer figures out all the values at compile-time, which operates
in strict mode.

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

extern fn foo_strict(x: f64) f64;
extern fn foo_optimized(x: f64) f64;

pub fn main() void {
    const x = 0.001;
    print(&quot;optimized = {}\n&quot;, .{foo_optimized(x)});
    print(&quot;strict = {}\n&quot;, .{foo_strict(x)});
}</code></pre>
<figcaption>float_mode_exe.zig</figcaption>
</figure>

See also:

- [\@setFloatMode](#setFloatMode)
- [Division by Zero](#Division-by-Zero)

## [Operators](#toc-Operators) [§](#Operators){.hdr} {#Operators}

There is no operator overloading. When you see an operator in Zig, you
know that it is doing something from this table, and nothing else.

### [Table of Operators](#toc-Table-of-Operators) [§](#Table-of-Operators){.hdr} {#Table-of-Operators}

::: table-wrapper
+-------------+-------------+-------------+-------------+-------------+
| Name        | Syntax      | Types       | Remarks     | Example     |
+=============+=============+=============+=============+=============+
| Addition    |     a + b   | -           | - Can cause |             |
|             |     a += b  |  [Integers] |   [overflow |  2 + 5 == 7 |
|             |             | (#Integers) | ](#Default- |             |
|             |             | - [Float    | Operations) |             |
|             |             | s](#Floats) |   for       |             |
|             |             |             |   integers. |             |
|             |             |             | - Invokes   |             |
|             |             |             |   [Peer     |             |
|             |             |             |   Type      |             |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
|             |             |             | - See also  |             |
|             |             |             |   [\@ad     |             |
|             |             |             | dWithOverfl |             |
|             |             |             | ow](#addWit |             |
|             |             |             | hOverflow). |             |
+-------------+-------------+-------------+-------------+-------------+
| Wrapping    |     a +% b  | -           | - Twos      |             |
| Addition    |     a +%= b |  [Integers] | -complement |    @as(u32, |
|             |             | (#Integers) |   wrapping  |  0xffffffff |
|             |             |             |   behavior. | ) +% 1 == 0 |
|             |             |             | - Invokes   |             |
|             |             |             |   [Peer     |             |
|             |             |             |   Type      |             |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
|             |             |             | - See also  |             |
|             |             |             |   [\@ad     |             |
|             |             |             | dWithOverfl |             |
|             |             |             | ow](#addWit |             |
|             |             |             | hOverflow). |             |
+-------------+-------------+-------------+-------------+-------------+
| Saturating  |     a +| b  | -           | - Invokes   |             |
| Addition    |     a +|= b |  [Integers] |   [Peer     | @as(u8, 255 |
|             |             | (#Integers) |   Type      | ) +| 1 == @ |
|             |             |             |   R         | as(u8, 255) |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
+-------------+-------------+-------------+-------------+-------------+
| Subtraction |     a - b   | -           | - Can cause |             |
|             |     a -= b  |  [Integers] |   [overflow | 2 - 5 == -3 |
|             |             | (#Integers) | ](#Default- |             |
|             |             | - [Float    | Operations) |             |
|             |             | s](#Floats) |   for       |             |
|             |             |             |   integers. |             |
|             |             |             | - Invokes   |             |
|             |             |             |   [Peer     |             |
|             |             |             |   Type      |             |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
|             |             |             | - See also  |             |
|             |             |             |   [\@su     |             |
|             |             |             | bWithOverfl |             |
|             |             |             | ow](#subWit |             |
|             |             |             | hOverflow). |             |
+-------------+-------------+-------------+-------------+-------------+
| Wrapping    |     a -% b  | -           | - Twos      |             |
| Subtraction |     a -%= b |  [Integers] | -complement | @as(u8, 0)  |
|             |             | (#Integers) |   wrapping  | -% 1 == 255 |
|             |             |             |   behavior. |             |
|             |             |             | - Invokes   |             |
|             |             |             |   [Peer     |             |
|             |             |             |   Type      |             |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
|             |             |             | - See also  |             |
|             |             |             |   [\@su     |             |
|             |             |             | bWithOverfl |             |
|             |             |             | ow](#subWit |             |
|             |             |             | hOverflow). |             |
+-------------+-------------+-------------+-------------+-------------+
| Saturating  |     a -| b  | -           | - Invokes   |             |
| Subtraction |     a -|= b |  [Integers] |   [Peer     |  @as(u32, 0 |
|             |             | (#Integers) |   Type      | ) -| 1 == 0 |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
+-------------+-------------+-------------+-------------+-------------+
| Negation    |     -a      | -           | - Can cause |             |
|             |             |  [Integers] |   [overflow | -1 == 0 - 1 |
|             |             | (#Integers) | ](#Default- |             |
|             |             | - [Float    | Operations) |             |
|             |             | s](#Floats) |   for       |             |
|             |             |             |   integers. |             |
+-------------+-------------+-------------+-------------+-------------+
| Wrapping    |     -%a     | -           | - Twos      |     -       |
| Negation    |             |  [Integers] | -complement | %@as(i8, -1 |
|             |             | (#Integers) |   wrapping  | 28) == -128 |
|             |             |             |   behavior. |             |
+-------------+-------------+-------------+-------------+-------------+
| Mul         |     a * b   | -           | - Can cause |             |
| tiplication |     a *= b  |  [Integers] |   [overflow | 2 * 5 == 10 |
|             |             | (#Integers) | ](#Default- |             |
|             |             | - [Float    | Operations) |             |
|             |             | s](#Floats) |   for       |             |
|             |             |             |   integers. |             |
|             |             |             | - Invokes   |             |
|             |             |             |   [Peer     |             |
|             |             |             |   Type      |             |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
|             |             |             | - See also  |             |
|             |             |             |   [\@mu     |             |
|             |             |             | lWithOverfl |             |
|             |             |             | ow](#mulWit |             |
|             |             |             | hOverflow). |             |
+-------------+-------------+-------------+-------------+-------------+
| Wrapping    |     a *% b  | -           | - Twos      |     @a      |
| Mul         |     a *%= b |  [Integers] | -complement | s(u8, 200)  |
| tiplication |             | (#Integers) |   wrapping  | *% 2 == 144 |
|             |             |             |   behavior. |             |
|             |             |             | - Invokes   |             |
|             |             |             |   [Peer     |             |
|             |             |             |   Type      |             |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
|             |             |             | - See also  |             |
|             |             |             |   [\@mu     |             |
|             |             |             | lWithOverfl |             |
|             |             |             | ow](#mulWit |             |
|             |             |             | hOverflow). |             |
+-------------+-------------+-------------+-------------+-------------+
| Saturating  |     a *| b  | -           | - Invokes   |     @a      |
| Mul         |     a *|= b |  [Integers] |   [Peer     | s(u8, 200)  |
| tiplication |             | (#Integers) |   Type      | *| 2 == 255 |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
+-------------+-------------+-------------+-------------+-------------+
| Division    |     a / b   | -           | - Can cause |             |
|             |     a /= b  |  [Integers] |   [overflow | 10 / 5 == 2 |
|             |             | (#Integers) | ](#Default- |             |
|             |             | - [Float    | Operations) |             |
|             |             | s](#Floats) |   for       |             |
|             |             |             |   integers. |             |
|             |             |             | - Can cause |             |
|             |             |             |   [Division |             |
|             |             |             |   by        |             |
|             |             |             |   Ze        |             |
|             |             |             | ro](#Divisi |             |
|             |             |             | on-by-Zero) |             |
|             |             |             |   for       |             |
|             |             |             |   integers. |             |
|             |             |             | - Can cause |             |
|             |             |             |   [Division |             |
|             |             |             |   by        |             |
|             |             |             |   Ze        |             |
|             |             |             | ro](#Divisi |             |
|             |             |             | on-by-Zero) |             |
|             |             |             |   for       |             |
|             |             |             |   floats in |             |
|             |             |             |   [FloatMod |             |
|             |             |             | e.Optimized |             |
|             |             |             |   M         |             |
|             |             |             | ode](#Float |             |
|             |             |             | ing-Point-O |             |
|             |             |             | perations). |             |
|             |             |             | - Signed    |             |
|             |             |             |   integer   |             |
|             |             |             |   operands  |             |
|             |             |             |   must be   |             |
|             |             |             |   com       |             |
|             |             |             | ptime-known |             |
|             |             |             |   and       |             |
|             |             |             |   positive. |             |
|             |             |             |   In other  |             |
|             |             |             |   cases,    |             |
|             |             |             |   use       |             |
|             |             |             |   [\        |             |
|             |             |             | @divTrunc]( |             |
|             |             |             | #divTrunc), |             |
|             |             |             |   [\        |             |
|             |             |             | @divFloor]( |             |
|             |             |             | #divFloor), |             |
|             |             |             |   or        |             |
|             |             |             |   [         |             |
|             |             |             | \@divExact] |             |
|             |             |             | (#divExact) |             |
|             |             |             |   instead.  |             |
|             |             |             | - Invokes   |             |
|             |             |             |   [Peer     |             |
|             |             |             |   Type      |             |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
+-------------+-------------+-------------+-------------+-------------+
| Remainder   |     a % b   | -           | - Can cause |             |
| Division    |     a %= b  |  [Integers] |   [Division | 10 % 3 == 1 |
|             |             | (#Integers) |   by        |             |
|             |             | - [Float    |   Ze        |             |
|             |             | s](#Floats) | ro](#Divisi |             |
|             |             |             | on-by-Zero) |             |
|             |             |             |   for       |             |
|             |             |             |   integers. |             |
|             |             |             | - Can cause |             |
|             |             |             |   [Division |             |
|             |             |             |   by        |             |
|             |             |             |   Ze        |             |
|             |             |             | ro](#Divisi |             |
|             |             |             | on-by-Zero) |             |
|             |             |             |   for       |             |
|             |             |             |   floats in |             |
|             |             |             |   [FloatMod |             |
|             |             |             | e.Optimized |             |
|             |             |             |   M         |             |
|             |             |             | ode](#Float |             |
|             |             |             | ing-Point-O |             |
|             |             |             | perations). |             |
|             |             |             | - Signed or |             |
|             |             |             |   flo       |             |
|             |             |             | ating-point |             |
|             |             |             |   operands  |             |
|             |             |             |   must be   |             |
|             |             |             |   com       |             |
|             |             |             | ptime-known |             |
|             |             |             |   and       |             |
|             |             |             |   positive. |             |
|             |             |             |   In other  |             |
|             |             |             |   cases,    |             |
|             |             |             |   use       |             |
|             |             |             |   [\        |             |
|             |             |             | @rem](#rem) |             |
|             |             |             |   or        |             |
|             |             |             |   [\        |             |
|             |             |             | @mod](#mod) |             |
|             |             |             |   instead.  |             |
|             |             |             | - Invokes   |             |
|             |             |             |   [Peer     |             |
|             |             |             |   Type      |             |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
+-------------+-------------+-------------+-------------+-------------+
| Bit Shift   |     a << b  | -           | - Moves all |     0       |
| Left        |     a <<= b |  [Integers] |   bits to   | b1 << 8 ==  |
|             |             | (#Integers) |   the left, | 0b100000000 |
|             |             |             |   inserting |             |
|             |             |             |   new       |             |
|             |             |             |   zeroes at |             |
|             |             |             |   the       |             |
|             |             |             |   least-    |             |
|             |             |             | significant |             |
|             |             |             |   bit.      |             |
|             |             |             | - `b` must  |             |
|             |             |             |   be        |             |
|             |             |             |   [comp     |             |
|             |             |             | time-known] |             |
|             |             |             | (#comptime) |             |
|             |             |             |   or have a |             |
|             |             |             |   type with |             |
|             |             |             |   log2      |             |
|             |             |             |   number of |             |
|             |             |             |   bits as   |             |
|             |             |             |   `a`.      |             |
|             |             |             | - See also  |             |
|             |             |             |   [\        |             |
|             |             |             | @shlExact]( |             |
|             |             |             | #shlExact). |             |
|             |             |             | - See also  |             |
|             |             |             |   [\@sh     |             |
|             |             |             | lWithOverfl |             |
|             |             |             | ow](#shlWit |             |
|             |             |             | hOverflow). |             |
+-------------+-------------+-------------+-------------+-------------+
| Saturating  |     a <<| b | -           | - See also  |     @       |
| Bit Shift   |             |  [Integers] |   [\        | as(u8, 1) < |
| Left        |    a <<|= b | (#Integers) | @shlExact]( | <| 8 == 255 |
|             |             |             | #shlExact). |             |
|             |             |             | - See also  |             |
|             |             |             |   [\@sh     |             |
|             |             |             | lWithOverfl |             |
|             |             |             | ow](#shlWit |             |
|             |             |             | hOverflow). |             |
+-------------+-------------+-------------+-------------+-------------+
| Bit Shift   |     a >> b  | -           | - Moves all |             |
| Right       |     a >>= b |  [Integers] |   bits to   |   0b1010 >> |
|             |             | (#Integers) |   the       |  1 == 0b101 |
|             |             |             |   right,    |             |
|             |             |             |   inserting |             |
|             |             |             |   zeroes at |             |
|             |             |             |   the       |             |
|             |             |             |   most-     |             |
|             |             |             | significant |             |
|             |             |             |   bit.      |             |
|             |             |             | - `b` must  |             |
|             |             |             |   be        |             |
|             |             |             |   [comp     |             |
|             |             |             | time-known] |             |
|             |             |             | (#comptime) |             |
|             |             |             |   or have a |             |
|             |             |             |   type with |             |
|             |             |             |   log2      |             |
|             |             |             |   number of |             |
|             |             |             |   bits as   |             |
|             |             |             |   `a`.      |             |
|             |             |             | - See also  |             |
|             |             |             |   [\        |             |
|             |             |             | @shrExact]( |             |
|             |             |             | #shrExact). |             |
+-------------+-------------+-------------+-------------+-------------+
| Bitwise And |     a & b   | -           | - Invokes   |             |
|             |     a &= b  |  [Integers] |   [Peer     | 0b011 & 0b1 |
|             |             | (#Integers) |   Type      | 01 == 0b001 |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
+-------------+-------------+-------------+-------------+-------------+
| Bitwise Or  |     a | b   | -           | - Invokes   |             |
|             |     a |= b  |  [Integers] |   [Peer     | 0b010 | 0b1 |
|             |             | (#Integers) |   Type      | 00 == 0b110 |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
+-------------+-------------+-------------+-------------+-------------+
| Bitwise Xor |     a ^ b   | -           | - Invokes   |             |
|             |     a ^= b  |  [Integers] |   [Peer     | 0b011 ^ 0b1 |
|             |             | (#Integers) |   Type      | 01 == 0b110 |
|             |             |             |   R         |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             |   for the   |             |
|             |             |             |   operands. |             |
+-------------+-------------+-------------+-------------+-------------+
| Bitwise Not |     ~a      | -           |             |     ~       |
|             |             |  [Integers] |             | @as(u8, 0b1 |
|             |             | (#Integers) |             | 0101111) == |
|             |             |             |             |  0b01010000 |
+-------------+-------------+-------------+-------------+-------------+
| Defaulting  |             | - [         | If `a` is   |     con     |
| Optional    |  a orelse b | Optionals]( | [`null`]{   | st value: ? |
| Unwrap      |             | #Optionals) | .tok-null}, | u32 = null; |
|             |             |             | returns `b` |     con     |
|             |             |             | (\"default  | st unwrappe |
|             |             |             | value\"),   | d = value o |
|             |             |             | otherwise   | relse 1234; |
|             |             |             | returns the |     unwrap  |
|             |             |             | unwrapped   | ped == 1234 |
|             |             |             | value of    |             |
|             |             |             | `a`. Note   |             |
|             |             |             | that `b`    |             |
|             |             |             | may be a    |             |
|             |             |             | value of    |             |
|             |             |             | type        |             |
|             |             |             | [noreturn]( |             |
|             |             |             | #noreturn). |             |
+-------------+-------------+-------------+-------------+-------------+
| Optional    |     a.?     | - [         | Equivalent  |     con     |
| Unwrap      |             | Optionals]( | to:         | st value: ? |
|             |             | #Optionals) |             | u32 = 5678; |
|             |             |             |             |     valu    |
|             |             |             |   a orelse  | e.? == 5678 |
|             |             |             | unreachable |             |
+-------------+-------------+-------------+-------------+-------------+
| Defaulting  |             | - [Error    | If `a` is   |             |
| Error       |   a catch b |   Union     | an          |    const va |
| Unwrap      |     a ca    | s](#Errors) | [`error`    | lue: anyerr |
|             | tch |err| b |             | ]{.tok-kw}, | or!u32 = er |
|             |             |             | returns `b` | ror.Broken; |
|             |             |             | (\"default  |     co      |
|             |             |             | value\"),   | nst unwrapp |
|             |             |             | otherwise   | ed = value  |
|             |             |             | returns the | catch 1234; |
|             |             |             | unwrapped   |     unwrap  |
|             |             |             | value of    | ped == 1234 |
|             |             |             | `a`. Note   |             |
|             |             |             | that `b`    |             |
|             |             |             | may be a    |             |
|             |             |             | value of    |             |
|             |             |             | type        |             |
|             |             |             | [noreturn]( |             |
|             |             |             | #noreturn). |             |
|             |             |             | `err` is    |             |
|             |             |             | the         |             |
|             |             |             | [`error     |             |
|             |             |             | `]{.tok-kw} |             |
|             |             |             | and is in   |             |
|             |             |             | scope of    |             |
|             |             |             | the         |             |
|             |             |             | expression  |             |
|             |             |             | `b`.        |             |
+-------------+-------------+-------------+-------------+-------------+
| Logical And |     a and b | - [b        | If `a` is   |     (fa     |
|             |             | ool](#Primi | [`false`]{  | lse and tru |
|             |             | tive-Types) | .tok-null}, | e) == false |
|             |             |             | returns     |             |
|             |             |             | [`false`]   |             |
|             |             |             | {.tok-null} |             |
|             |             |             | without     |             |
|             |             |             | evaluating  |             |
|             |             |             | `b`.        |             |
|             |             |             | Otherwise,  |             |
|             |             |             | returns     |             |
|             |             |             | `b`.        |             |
+-------------+-------------+-------------+-------------+-------------+
| Logical Or  |     a or b  | - [b        | If `a` is   |     (       |
|             |             | ool](#Primi | [`true`]{   | false or tr |
|             |             | tive-Types) | .tok-null}, | ue) == true |
|             |             |             | returns     |             |
|             |             |             | [`true`]    |             |
|             |             |             | {.tok-null} |             |
|             |             |             | without     |             |
|             |             |             | evaluating  |             |
|             |             |             | `b`.        |             |
|             |             |             | Otherwise,  |             |
|             |             |             | returns     |             |
|             |             |             | `b`.        |             |
+-------------+-------------+-------------+-------------+-------------+
| Boolean Not |     !a      | - [b        |             |     !fa     |
|             |             | ool](#Primi |             | lse == true |
|             |             | tive-Types) |             |             |
+-------------+-------------+-------------+-------------+-------------+
| Equality    |     a == b  | -           | Returns     |     (1 ==   |
|             |             |  [Integers] | [`true`]    |  1) == true |
|             |             | (#Integers) | {.tok-null} |             |
|             |             | - [Float    | if a and b  |             |
|             |             | s](#Floats) | are equal,  |             |
|             |             | - [b        | otherwise   |             |
|             |             | ool](#Primi | returns     |             |
|             |             | tive-Types) | [`false`]{  |             |
|             |             | - [t        | .tok-null}. |             |
|             |             | ype](#Primi | Invokes     |             |
|             |             | tive-Types) | [Peer Type  |             |
|             |             |             | R           |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             | for the     |             |
|             |             |             | operands.   |             |
+-------------+-------------+-------------+-------------+-------------+
| Null Check  |             | - [         | Returns     |     con     |
|             |   a == null | Optionals]( | [`true`]    | st value: ? |
|             |             | #Optionals) | {.tok-null} | u32 = null; |
|             |             |             | if a is     |     (       |
|             |             |             | [`null`]{   | value == nu |
|             |             |             | .tok-null}, | ll) == true |
|             |             |             | otherwise   |             |
|             |             |             | returns     |             |
|             |             |             | [`false`]{  |             |
|             |             |             | .tok-null}. |             |
+-------------+-------------+-------------+-------------+-------------+
| Inequality  |     a != b  | -           | Returns     |     (1 !=   |
|             |             |  [Integers] | [`false`]   | 1) == false |
|             |             | (#Integers) | {.tok-null} |             |
|             |             | - [Float    | if a and b  |             |
|             |             | s](#Floats) | are equal,  |             |
|             |             | - [b        | otherwise   |             |
|             |             | ool](#Primi | returns     |             |
|             |             | tive-Types) | [`true`]{   |             |
|             |             | - [t        | .tok-null}. |             |
|             |             | ype](#Primi | Invokes     |             |
|             |             | tive-Types) | [Peer Type  |             |
|             |             |             | R           |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             | for the     |             |
|             |             |             | operands.   |             |
+-------------+-------------+-------------+-------------+-------------+
| Non-Null    |             | - [         | Returns     |     con     |
| Check       |   a != null | Optionals]( | [`false`]   | st value: ? |
|             |             | #Optionals) | {.tok-null} | u32 = null; |
|             |             |             | if a is     |     (v      |
|             |             |             | [`null`]{   | alue != nul |
|             |             |             | .tok-null}, | l) == false |
|             |             |             | otherwise   |             |
|             |             |             | returns     |             |
|             |             |             | [`true`]{   |             |
|             |             |             | .tok-null}. |             |
+-------------+-------------+-------------+-------------+-------------+
| Greater     |     a > b   | -           | Returns     |     (2 >    |
| Than        |             |  [Integers] | [`true`]    |  1) == true |
|             |             | (#Integers) | {.tok-null} |             |
|             |             | - [Float    | if a is     |             |
|             |             | s](#Floats) | greater     |             |
|             |             |             | than b,     |             |
|             |             |             | otherwise   |             |
|             |             |             | returns     |             |
|             |             |             | [`false`]{  |             |
|             |             |             | .tok-null}. |             |
|             |             |             | Invokes     |             |
|             |             |             | [Peer Type  |             |
|             |             |             | R           |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             | for the     |             |
|             |             |             | operands.   |             |
+-------------+-------------+-------------+-------------+-------------+
| Greater or  |     a >= b  | -           | Returns     |     (2 >=   |
| Equal       |             |  [Integers] | [`true`]    |  1) == true |
|             |             | (#Integers) | {.tok-null} |             |
|             |             | - [Float    | if a is     |             |
|             |             | s](#Floats) | greater     |             |
|             |             |             | than or     |             |
|             |             |             | equal to b, |             |
|             |             |             | otherwise   |             |
|             |             |             | returns     |             |
|             |             |             | [`false`]{  |             |
|             |             |             | .tok-null}. |             |
|             |             |             | Invokes     |             |
|             |             |             | [Peer Type  |             |
|             |             |             | R           |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             | for the     |             |
|             |             |             | operands.   |             |
+-------------+-------------+-------------+-------------+-------------+
| Less Than   |     a < b   | -           | Returns     |     (1 <    |
|             |             |  [Integers] | [`true`]    |  2) == true |
|             |             | (#Integers) | {.tok-null} |             |
|             |             | - [Float    | if a is     |             |
|             |             | s](#Floats) | less than   |             |
|             |             |             | b,          |             |
|             |             |             | otherwise   |             |
|             |             |             | returns     |             |
|             |             |             | [`false`]{  |             |
|             |             |             | .tok-null}. |             |
|             |             |             | Invokes     |             |
|             |             |             | [Peer Type  |             |
|             |             |             | R           |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             | for the     |             |
|             |             |             | operands.   |             |
+-------------+-------------+-------------+-------------+-------------+
| Lesser or   |     a <= b  | -           | Returns     |     (1 <=   |
| Equal       |             |  [Integers] | [`true`]    |  2) == true |
|             |             | (#Integers) | {.tok-null} |             |
|             |             | - [Float    | if a is     |             |
|             |             | s](#Floats) | less than   |             |
|             |             |             | or equal to |             |
|             |             |             | b,          |             |
|             |             |             | otherwise   |             |
|             |             |             | returns     |             |
|             |             |             | [`false`]{  |             |
|             |             |             | .tok-null}. |             |
|             |             |             | Invokes     |             |
|             |             |             | [Peer Type  |             |
|             |             |             | R           |             |
|             |             |             | esolution]( |             |
|             |             |             | #Peer-Type- |             |
|             |             |             | Resolution) |             |
|             |             |             | for the     |             |
|             |             |             | operands.   |             |
+-------------+-------------+-------------+-------------+-------------+
| Array       |     a ++ b  | - [Array    | - Only      |             |
| Co          |             | s](#Arrays) |   available |   const mem |
| ncatenation |             |             |   when the  |  = @import( |
|             |             |             |   lengths   | "std").mem; |
|             |             |             |   of both   |     const   |
|             |             |             |   `a` and   |  array1 = [ |
|             |             |             |   `b` are   | _]u32{1,2}; |
|             |             |             |   [c        |     const   |
|             |             |             | ompile-time |  array2 = [ |
|             |             |             |   known](   | _]u32{3,4}; |
|             |             |             | #comptime). |     c       |
|             |             |             |             | onst togeth |
|             |             |             |             | er = array1 |
|             |             |             |             |  ++ array2; |
|             |             |             |             |             |
|             |             |             |             |    mem.eql( |
|             |             |             |             | u32, &toget |
|             |             |             |             | her, &[_]u3 |
|             |             |             |             | 2{1,2,3,4}) |
+-------------+-------------+-------------+-------------+-------------+
| Array       |     a ** b  | - [Array    | - Only      |             |
| Mul         |             | s](#Arrays) |   available |   const mem |
| tiplication |             |             |   when the  |  = @import( |
|             |             |             |   length of | "std").mem; |
|             |             |             |   `a` and   |     cons    |
|             |             |             |   `b` are   | t pattern = |
|             |             |             |   [c        |  "ab" ** 3; |
|             |             |             | ompile-time |             |
|             |             |             |   known](   |    mem.eql( |
|             |             |             | #comptime). | u8, pattern |
|             |             |             |             | , "ababab") |
+-------------+-------------+-------------+-------------+-------------+
| Pointer     |     a.*     | -           | Pointer     |             |
| Dereference |             |  [Pointers] | d           |   const x:  |
|             |             | (#Pointers) | ereference. | u32 = 1234; |
|             |             |             |             |     cons    |
|             |             |             |             | t ptr = &x; |
|             |             |             |             |     pt      |
|             |             |             |             | r.* == 1234 |
+-------------+-------------+-------------+-------------+-------------+
| Address Of  |     &a      | All types   |             |             |
|             |             |             |             |   const x:  |
|             |             |             |             | u32 = 1234; |
|             |             |             |             |     cons    |
|             |             |             |             | t ptr = &x; |
|             |             |             |             |     pt      |
|             |             |             |             | r.* == 1234 |
+-------------+-------------+-------------+-------------+-------------+
| Error Set   |     a || b  | - [Error    | [Merging    |             |
| Merge       |             |   Set       | Error       |  const A =  |
|             |             |             | Sets        | error{One}; |
|             |             | Type](#Erro | ](#Merging- |             |
|             |             | r-Set-Type) | Error-Sets) |  const B =  |
|             |             |             |             | error{Two}; |
|             |             |             |             |     (A ||   |
|             |             |             |             |  B) == erro |
|             |             |             |             | r{One, Two} |
+-------------+-------------+-------------+-------------+-------------+
:::

### [Precedence](#toc-Precedence) [§](#Precedence){.hdr} {#Precedence}

    x() x[] x.y x.* x.?
    a!b
    x{}
    !x -x -%x ~x &x ?x
    * / % ** *% *| ||
    + - ++ +% -% +| -|
    << >> <<|
    & ^ | orelse catch
    == != < > <= >=
    and
    or
    = *= *%= *|= /= %= += +%= +|= -= -%= -|= <<= <<|= >>= &= ^= |=

## [Arrays](#toc-Arrays) [§](#Arrays){.hdr} {#Arrays}

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;
const assert = @import(&quot;std&quot;).debug.assert;
const mem = @import(&quot;std&quot;).mem;

// array literal
const message = [_]u8{ &#39;h&#39;, &#39;e&#39;, &#39;l&#39;, &#39;l&#39;, &#39;o&#39; };

// alternative initialization using result location
const alt_message: [5]u8 = .{ &#39;h&#39;, &#39;e&#39;, &#39;l&#39;, &#39;l&#39;, &#39;o&#39; };

comptime {
    assert(mem.eql(u8, &amp;message, &amp;alt_message));
}

// get the size of an array
comptime {
    assert(message.len == 5);
}

// A string literal is a single-item pointer to an array.
const same_message = &quot;hello&quot;;

comptime {
    assert(mem.eql(u8, &amp;message, same_message));
}

test &quot;iterate over an array&quot; {
    var sum: usize = 0;
    for (message) |byte| {
        sum += byte;
    }
    try expect(sum == &#39;h&#39; + &#39;e&#39; + &#39;l&#39; * 2 + &#39;o&#39;);
}

// modifiable array
var some_integers: [100]i32 = undefined;

test &quot;modify an array&quot; {
    for (&amp;some_integers, 0..) |*item, i| {
        item.* = @intCast(i);
    }
    try expect(some_integers[10] == 10);
    try expect(some_integers[99] == 99);
}

// array concatenation works if the values are known
// at compile time
const part_one = [_]i32{ 1, 2, 3, 4 };
const part_two = [_]i32{ 5, 6, 7, 8 };
const all_of_it = part_one ++ part_two;
comptime {
    assert(mem.eql(i32, &amp;all_of_it, &amp;[_]i32{ 1, 2, 3, 4, 5, 6, 7, 8 }));
}

// remember that string literals are arrays
const hello = &quot;hello&quot;;
const world = &quot;world&quot;;
const hello_world = hello ++ &quot; &quot; ++ world;
comptime {
    assert(mem.eql(u8, hello_world, &quot;hello world&quot;));
}

// ** does repeating patterns
const pattern = &quot;ab&quot; ** 3;
comptime {
    assert(mem.eql(u8, pattern, &quot;ababab&quot;));
}

// initialize an array to zero
const all_zero = [_]u16{0} ** 10;

comptime {
    assert(all_zero.len == 10);
    assert(all_zero[5] == 0);
}

// use compile-time code to initialize an array
var fancy_array = init: {
    var initial_value: [10]Point = undefined;
    for (&amp;initial_value, 0..) |*pt, i| {
        pt.* = Point{
            .x = @intCast(i),
            .y = @intCast(i * 2),
        };
    }
    break :init initial_value;
};
const Point = struct {
    x: i32,
    y: i32,
};

test &quot;compile-time array initialization&quot; {
    try expect(fancy_array[4].x == 4);
   ```
