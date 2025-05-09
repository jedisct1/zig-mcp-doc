```
BI_ONLY_PNG&quot;, &quot;&quot;);
    @cDefine(&quot;STBI_NO_STDIO&quot;, &quot;&quot;);
    @cInclude(&quot;stb_image.h&quot;);
});</code></pre>
<figcaption>c.zig</figcaption>
</figure>

The above example demonstrates using [`pub`]{.tok-kw} to qualify the
[`usingnamespace`]{.tok-kw} additionally makes the imported declarations
[`pub`]{.tok-kw}. This can be used to forward declarations, giving
precise control over what declarations a given file exposes.

## [comptime](#toc-comptime) [§](#comptime){.hdr}

Zig places importance on the concept of whether an expression is known
at compile-time. There are a few different places this concept is used,
and these building blocks are used to keep the language small, readable,
and powerful.

### [Introducing the Compile-Time Concept](#toc-Introducing-the-Compile-Time-Concept) [§](#Introducing-the-Compile-Time-Concept){.hdr} {#Introducing-the-Compile-Time-Concept}

#### [Compile-Time Parameters](#toc-Compile-Time-Parameters) [§](#Compile-Time-Parameters){.hdr} {#Compile-Time-Parameters}

Compile-time parameters is how Zig implements generics. It is
compile-time duck typing.

<figure>
<pre><code>fn max(comptime T: type, a: T, b: T) T {
    return if (a &gt; b) a else b;
}
fn gimmeTheBiggerFloat(a: f32, b: f32) f32 {
    return max(f32, a, b);
}
fn gimmeTheBiggerInteger(a: u64, b: u64) u64 {
    return max(u64, a, b);
}</code></pre>
<figcaption>compile-time_duck_typing.zig</figcaption>
</figure>

In Zig, types are first-class citizens. They can be assigned to
variables, passed as parameters to functions, and returned from
functions. However, they can only be used in expressions which are known
at *compile-time*, which is why the parameter `T` in the above snippet
must be marked with [`comptime`]{.tok-kw}.

A [`comptime`]{.tok-kw} parameter means that:

- At the callsite, the value must be known at compile-time, or it is a
  compile error.
- In the function definition, the value is known at compile-time.

For example, if we were to introduce another function to the above
snippet:

<figure>
<pre><code>fn max(comptime T: type, a: T, b: T) T {
    return if (a &gt; b) a else b;
}
test &quot;try to pass a runtime type&quot; {
    foo(false);
}
fn foo(condition: bool) void {
    const result = max(if (condition) f32 else u64, 1234, 5678);
    _ = result;
}</code></pre>
<figcaption>test_unresolved_comptime_value.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_unresolved_comptime_value.zig
doc/langref/test_unresolved_comptime_value.zig:8:28: error: unable to resolve comptime value
    const result = max(if (condition) f32 else u64, 1234, 5678);
                           ^~~~~~~~~
doc/langref/test_unresolved_comptime_value.zig:8:24: note: argument to comptime parameter must be comptime-known
    const result = max(if (condition) f32 else u64, 1234, 5678);
                       ^~~~~~~~~~~~~~~~~~~~~~~~~~~
doc/langref/test_unresolved_comptime_value.zig:1:8: note: parameter declared comptime here
fn max(comptime T: type, a: T, b: T) T {
       ^~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

This is an error because the programmer attempted to pass a value only
known at run-time to a function which expects a value known at
compile-time.

Another way to get an error is if we pass a type that violates the type
checker when the function is analyzed. This is what it means to have
*compile-time duck typing*.

For example:

<figure>
<pre><code>fn max(comptime T: type, a: T, b: T) T {
    return if (a &gt; b) a else b;
}
test &quot;try to compare bools&quot; {
    _ = max(bool, true, false);
}</code></pre>
<figcaption>test_comptime_mismatched_type.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_mismatched_type.zig
doc/langref/test_comptime_mismatched_type.zig:2:18: error: operator &gt; not allowed for type &#39;bool&#39;
    return if (a &gt; b) a else b;
               ~~^~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

On the flip side, inside the function definition with the
[`comptime`]{.tok-kw} parameter, the value is known at compile-time.
This means that we actually could make this work for the bool type if we
wanted to:

<figure>
<pre><code>fn max(comptime T: type, a: T, b: T) T {
    if (T == bool) {
        return a or b;
    } else if (a &gt; b) {
        return a;
    } else {
        return b;
    }
}
test &quot;try to compare bools&quot; {
    try @import(&quot;std&quot;).testing.expect(max(bool, false, true) == true);
}</code></pre>
<figcaption>test_comptime_max_with_bool.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_max_with_bool.zig
1/1 test_comptime_max_with_bool.test.try to compare bools...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

This works because Zig implicitly inlines [`if`]{.tok-kw} expressions
when the condition is known at compile-time, and the compiler guarantees
that it will skip analysis of the branch not taken.

This means that the actual function generated for `max` in this
situation looks like this:

<figure>
<pre><code>fn max(a: bool, b: bool) bool {
    {
        return a or b;
    }
}</code></pre>
<figcaption>compiler_generated_function.zig</figcaption>
</figure>

All the code that dealt with compile-time known values is eliminated and
we are left with only the necessary run-time code to accomplish the
task.

This works the same way for [`switch`]{.tok-kw} expressions - they are
implicitly inlined when the target expression is compile-time known.

#### [Compile-Time Variables](#toc-Compile-Time-Variables) [§](#Compile-Time-Variables){.hdr} {#Compile-Time-Variables}

In Zig, the programmer can label variables as [`comptime`]{.tok-kw}.
This guarantees to the compiler that every load and store of the
variable is performed at compile-time. Any violation of this results in
a compile error.

This combined with the fact that we can [`inline`]{.tok-kw} loops allows
us to write a function which is partially evaluated at compile-time and
partially at run-time.

For example:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

const CmdFn = struct {
    name: []const u8,
    func: fn (i32) i32,
};

const cmd_fns = [_]CmdFn{
    CmdFn{ .name = &quot;one&quot;, .func = one },
    CmdFn{ .name = &quot;two&quot;, .func = two },
    CmdFn{ .name = &quot;three&quot;, .func = three },
};
fn one(value: i32) i32 {
    return value + 1;
}
fn two(value: i32) i32 {
    return value + 2;
}
fn three(value: i32) i32 {
    return value + 3;
}

fn performFn(comptime prefix_char: u8, start_value: i32) i32 {
    var result: i32 = start_value;
    comptime var i = 0;
    inline while (i &lt; cmd_fns.len) : (i += 1) {
        if (cmd_fns[i].name[0] == prefix_char) {
            result = cmd_fns[i].func(result);
        }
    }
    return result;
}

test &quot;perform fn&quot; {
    try expect(performFn(&#39;t&#39;, 1) == 6);
    try expect(performFn(&#39;o&#39;, 0) == 1);
    try expect(performFn(&#39;w&#39;, 99) == 99);
}</code></pre>
<figcaption>test_comptime_evaluation.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_evaluation.zig
1/1 test_comptime_evaluation.test.perform fn...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

This example is a bit contrived, because the compile-time evaluation
component is unnecessary; this code would work fine if it was all done
at run-time. But it does end up generating different code. In this
example, the function `performFn` is generated three different times,
for the different values of `prefix_char` provided:

<figure>
<pre><code>// From the line:
// expect(performFn(&#39;t&#39;, 1) == 6);
fn performFn(start_value: i32) i32 {
    var result: i32 = start_value;
    result = two(result);
    result = three(result);
    return result;
}</code></pre>
<figcaption>performFn_1</figcaption>
</figure>

<figure>
<pre><code>// From the line:
// expect(performFn(&#39;o&#39;, 0) == 1);
fn performFn(start_value: i32) i32 {
    var result: i32 = start_value;
    result = one(result);
    return result;
}</code></pre>
<figcaption>performFn_2</figcaption>
</figure>

<figure>
<pre><code>// From the line:
// expect(performFn(&#39;w&#39;, 99) == 99);
fn performFn(start_value: i32) i32 {
    var result: i32 = start_value;
    _ = &amp;result;
    return result;
}</code></pre>
<figcaption>performFn_3</figcaption>
</figure>

Note that this happens even in a debug build. This is not a way to write
more optimized code, but it is a way to make sure that what *should*
happen at compile-time, *does* happen at compile-time. This catches more
errors and allows expressiveness that in other languages requires using
macros, generated code, or a preprocessor to accomplish.

#### [Compile-Time Expressions](#toc-Compile-Time-Expressions) [§](#Compile-Time-Expressions){.hdr} {#Compile-Time-Expressions}

In Zig, it matters whether a given expression is known at compile-time
or run-time. A programmer can use a [`comptime`]{.tok-kw} expression to
guarantee that the expression will be evaluated at compile-time. If this
cannot be accomplished, the compiler will emit an error. For example:

<figure>
<pre><code>extern fn exit() noreturn;

test &quot;foo&quot; {
    comptime {
        exit();
    }
}</code></pre>
<figcaption>test_comptime_call_extern_function.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_comptime_call_extern_function.zig
doc/langref/test_comptime_call_extern_function.zig:5:13: error: comptime call of extern function
        exit();
        ~~~~^~
doc/langref/test_comptime_call_extern_function.zig:4:5: note: &#39;comptime&#39; keyword forces comptime evaluation
    comptime {
    ^~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

It doesn\'t make sense that a program could call `exit()` (or any other
external function) at compile-time, so this is a compile error. However,
a [`comptime`]{.tok-kw} expression does much more than sometimes cause a
compile error.

Within a [`comptime`]{.tok-kw} expression:

- All variables are [`comptime`]{.tok-kw} variables.
- All [`if`]{.tok-kw}, [`while`]{.tok-kw}, [`for`]{.tok-kw}, and
  [`switch`]{.tok-kw} expressions are evaluated at compile-time, or emit
  a compile error if this is not possible.
- All [`return`]{.tok-kw} and [`try`]{.tok-kw} expressions are invalid
  (unless the function itself is called at compile-time).
- All code with runtime side effects or depending on runtime values
  emits a compile error.
- All function calls cause the compiler to interpret the function at
  compile-time, emitting a compile error if the function tries to do
  something that has global runtime side effects.

This means that a programmer can create a function which is called both
at compile-time and run-time, with no modification to the function
required.

Let\'s look at an example:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

fn fibonacci(index: u32) u32 {
    if (index &lt; 2) return index;
    return fibonacci(index - 1) + fibonacci(index - 2);
}

test &quot;fibonacci&quot; {
    // test fibonacci at run-time
    try expect(fibonacci(7) == 13);

    // test fibonacci at compile-time
    try comptime expect(fibonacci(7) == 13);
}</code></pre>
<figcaption>test_fibonacci_recursion.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_fibonacci_recursion.zig
1/1 test_fibonacci_recursion.test.fibonacci...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

Imagine if we had forgotten the base case of the recursive function and
tried to run the tests:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

fn fibonacci(index: u32) u32 {
    //if (index &lt; 2) return index;
    return fibonacci(index - 1) + fibonacci(index - 2);
}

test &quot;fibonacci&quot; {
    try comptime expect(fibonacci(7) == 13);
}</code></pre>
<figcaption>test_fibonacci_comptime_overflow.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_fibonacci_comptime_overflow.zig
doc/langref/test_fibonacci_comptime_overflow.zig:5:28: error: overflow of integer type &#39;u32&#39; with value &#39;-1&#39;
    return fibonacci(index - 1) + fibonacci(index - 2);
                     ~~~~~~^~~
doc/langref/test_fibonacci_comptime_overflow.zig:5:21: note: called from here (7 times)
    return fibonacci(index - 1) + fibonacci(index - 2);
           ~~~~~~~~~^~~~~~~~~~~
doc/langref/test_fibonacci_comptime_overflow.zig:9:34: note: called from here
    try comptime expect(fibonacci(7) == 13);
                        ~~~~~~~~~^~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

The compiler produces an error which is a stack trace from trying to
evaluate the function at compile-time.

Luckily, we used an unsigned integer, and so when we tried to subtract 1
from 0, it triggered [Illegal Behavior](#Illegal-Behavior), which is
always a compile error if the compiler knows it happened. But what would
have happened if we used a signed integer?

<figure>
<pre><code>const assert = @import(&quot;std&quot;).debug.assert;

fn fibonacci(index: i32) i32 {
    //if (index &lt; 2) return index;
    return fibonacci(index - 1) + fibonacci(index - 2);
}

test &quot;fibonacci&quot; {
    try comptime assert(fibonacci(7) == 13);
}</code></pre>
<figcaption>fibonacci_comptime_infinite_recursion.zig</figcaption>
</figure>

The compiler is supposed to notice that evaluating this function at
compile-time took more than 1000 branches, and thus emits an error and
gives up. If the programmer wants to increase the budget for
compile-time computation, they can use a built-in function called
[\@setEvalBranchQuota](#setEvalBranchQuota) to change the default number
1000 to something else.

However, there is a [design flaw in the
compiler](https://github.com/ziglang/zig/issues/13724) causing it to
stack overflow instead of having the proper behavior here. I\'m terribly
sorry about that. I hope to get this resolved before the next release.

What if we fix the base case, but put the wrong value in the `expect`
line?

<figure>
<pre><code>const assert = @import(&quot;std&quot;).debug.assert;

fn fibonacci(index: i32) i32 {
    if (index &lt; 2) return index;
    return fibonacci(index - 1) + fibonacci(index - 2);
}

test &quot;fibonacci&quot; {
    try comptime assert(fibonacci(7) == 99999);
}</code></pre>
<figcaption>test_fibonacci_comptime_unreachable.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_fibonacci_comptime_unreachable.zig
lib/std/debug.zig:522:14: error: reached unreachable code
    if (!ok) unreachable; // assertion failure
             ^~~~~~~~~~~
doc/langref/test_fibonacci_comptime_unreachable.zig:9:24: note: called from here
    try comptime assert(fibonacci(7) == 99999);
                 ~~~~~~^~~~~~~~~~~~~~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

At [container](#Containers) level (outside of any function), all
expressions are implicitly [`comptime`]{.tok-kw} expressions. This means
that we can use functions to initialize complex static data. For
example:

<figure>
<pre><code>const first_25_primes = firstNPrimes(25);
const sum_of_first_25_primes = sum(&amp;first_25_primes);

fn firstNPrimes(comptime n: usize) [n]i32 {
    var prime_list: [n]i32 = undefined;
    var next_index: usize = 0;
    var test_number: i32 = 2;
    while (next_index &lt; prime_list.len) : (test_number += 1) {
        var test_prime_index: usize = 0;
        var is_prime = true;
        while (test_prime_index &lt; next_index) : (test_prime_index += 1) {
            if (test_number % prime_list[test_prime_index] == 0) {
                is_prime = false;
                break;
            }
        }
        if (is_prime) {
            prime_list[next_index] = test_number;
            next_index += 1;
        }
    }
    return prime_list;
}

fn sum(numbers: []const i32) i32 {
    var result: i32 = 0;
    for (numbers) |x| {
        result += x;
    }
    return result;
}

test &quot;variable values&quot; {
    try @import(&quot;std&quot;).testing.expect(sum_of_first_25_primes == 1060);
}</code></pre>
<figcaption>test_container-level_comptime_expressions.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_container-level_comptime_expressions.zig
1/1 test_container-level_comptime_expressions.test.variable values...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

When we compile this program, Zig generates the constants with the
answer pre-computed. Here are the lines from the generated LLVM IR:

``` llvm
@0 = internal unnamed_addr constant [25 x i32] [i32 2, i32 3, i32 5, i32 7, i32 11, i32 13, i32 17, i32 19, i32 23, i32 29, i32 31, i32 37, i32 41, i32 43, i32 47, i32 53, i32 59, i32 61, i32 67, i32 71, i32 73, i32 79, i32 83, i32 89, i32 97]
@1 = internal unnamed_addr constant i32 1060
```

Note that we did not have to do anything special with the syntax of
these functions. For example, we could call the `sum` function as is
with a slice of numbers whose length and values were only known at
run-time.

### [Generic Data Structures](#toc-Generic-Data-Structures) [§](#Generic-Data-Structures){.hdr} {#Generic-Data-Structures}

Zig uses comptime capabilities to implement generic data structures
without introducing any special-case syntax.

Here is an example of a generic `List` data structure.

<figure>
<pre><code>fn List(comptime T: type) type {
    return struct {
        items: []T,
        len: usize,
    };
}

// The generic List data structure can be instantiated by passing in a type:
var buffer: [10]i32 = undefined;
var list = List(i32){
    .items = &amp;buffer,
    .len = 0,
};</code></pre>
<figcaption>generic_data_structure.zig</figcaption>
</figure>

That\'s it. It\'s a function that returns an anonymous
[`struct`]{.tok-kw}. For the purposes of error messages and debugging,
Zig infers the name [`"List(i32)"`]{.tok-str} from the function name and
parameters invoked when creating the anonymous struct.

To explicitly give a type a name, we assign it to a constant.

<figure>
<pre><code>const Node = struct {
    next: ?*Node,
    name: []const u8,
};

var node_a = Node{
    .next = null,
    .name = &quot;Node A&quot;,
};

var node_b = Node{
    .next = &amp;node_a,
    .name = &quot;Node B&quot;,
};</code></pre>
<figcaption>anonymous_struct_name.zig</figcaption>
</figure>

In this example, the `Node` struct refers to itself. This works because
all top level declarations are order-independent. As long as the
compiler can determine the size of the struct, it is free to refer to
itself. In this case, `Node` refers to itself as a pointer, which has a
well-defined size at compile time, so it works fine.

### [Case Study: print in Zig](#toc-Case-Study-print-in-Zig) [§](#Case-Study-print-in-Zig){.hdr} {#Case-Study-print-in-Zig}

Putting all of this together, let\'s see how `print` works in Zig.

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

const a_number: i32 = 1234;
const a_string = &quot;foobar&quot;;

pub fn main() void {
    print(&quot;here is a string: &#39;{s}&#39; here is a number: {}\n&quot;, .{ a_string, a_number });
}</code></pre>
<figcaption>print.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe print.zig
$ ./print
here is a string: &#39;foobar&#39; here is a number: 1234</code></pre>
<figcaption>Shell</figcaption>
</figure>

Let\'s crack open the implementation of this and see how it works:

<figure>
<pre><code>const Writer = struct {
    /// Calls print and then flushes the buffer.
    pub fn print(self: *Writer, comptime format: []const u8, args: anytype) anyerror!void {
        const State = enum {
            start,
            open_brace,
            close_brace,
        };

        comptime var start_index: usize = 0;
        comptime var state = State.start;
        comptime var next_arg: usize = 0;

        inline for (format, 0..) |c, i| {
            switch (state) {
                State.start =&gt; switch (c) {
                    &#39;{&#39; =&gt; {
                        if (start_index &lt; i) try self.write(format[start_index..i]);
                        state = State.open_brace;
                    },
                    &#39;}&#39; =&gt; {
                        if (start_index &lt; i) try self.write(format[start_index..i]);
                        state = State.close_brace;
                    },
                    else =&gt; {},
                },
                State.open_brace =&gt; switch (c) {
                    &#39;{&#39; =&gt; {
                        state = State.start;
                        start_index = i;
                    },
                    &#39;}&#39; =&gt; {
                        try self.printValue(args[next_arg]);
                        next_arg += 1;
                        state = State.start;
                        start_index = i + 1;
                    },
                    &#39;s&#39; =&gt; {
                        continue;
                    },
                    else =&gt; @compileError(&quot;Unknown format character: &quot; ++ [1]u8{c}),
                },
                State.close_brace =&gt; switch (c) {
                    &#39;}&#39; =&gt; {
                        state = State.start;
                        start_index = i;
                    },
                    else =&gt; @compileError(&quot;Single &#39;}&#39; encountered in format string&quot;),
                },
            }
        }
        comptime {
            if (args.len != next_arg) {
                @compileError(&quot;Unused arguments&quot;);
            }
            if (state != State.start) {
                @compileError(&quot;Incomplete format string: &quot; ++ format);
            }
        }
        if (start_index &lt; format.len) {
            try self.write(format[start_index..format.len]);
        }
        try self.flush();
    }

    fn write(self: *Writer, value: []const u8) !void {
        _ = self;
        _ = value;
    }
    pub fn printValue(self: *Writer, value: anytype) !void {
        _ = self;
        _ = value;
    }
    fn flush(self: *Writer) !void {
        _ = self;
    }
};</code></pre>
<figcaption>poc_print_fn.zig</figcaption>
</figure>

This is a proof of concept implementation; the actual function in the
standard library has more formatting capabilities.

Note that this is not hard-coded into the Zig compiler; this is userland
code in the standard library.

When this function is analyzed from our example code above, Zig
partially evaluates the function and emits a function that actually
looks like this:

<figure>
<pre><code>pub fn print(self: *Writer, arg0: []const u8, arg1: i32) !void {
    try self.write(&quot;here is a string: &#39;&quot;);
    try self.printValue(arg0);
    try self.write(&quot;&#39; here is a number: &quot;);
    try self.printValue(arg1);
    try self.write(&quot;\n&quot;);
    try self.flush();
}</code></pre>
<figcaption>Emitted print Function</figcaption>
</figure>

`printValue` is a function that takes a parameter of any type, and does
different things depending on the type:

<figure>
<pre><code>const Writer = struct {
    pub fn printValue(self: *Writer, value: anytype) !void {
        switch (@typeInfo(@TypeOf(value))) {
            .int =&gt; {
                return self.writeInt(value);
            },
            .float =&gt; {
                return self.writeFloat(value);
            },
            .pointer =&gt; {
                return self.write(value);
            },
            else =&gt; {
                @compileError(&quot;Unable to print type &#39;&quot; ++ @typeName(@TypeOf(value)) ++ &quot;&#39;&quot;);
            },
        }
    }

    fn write(self: *Writer, value: []const u8) !void {
        _ = self;
        _ = value;
    }
    fn writeInt(self: *Writer, value: anytype) !void {
        _ = self;
        _ = value;
    }
    fn writeFloat(self: *Writer, value: anytype) !void {
        _ = self;
        _ = value;
    }
};</code></pre>
<figcaption>poc_printValue_fn.zig</figcaption>
</figure>

And now, what happens if we give too many arguments to `print`?

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

const a_number: i32 = 1234;
const a_string = &quot;foobar&quot;;

test &quot;print too many arguments&quot; {
    print(&quot;here is a string: &#39;{s}&#39; here is a number: {}\n&quot;, .{
        a_string,
        a_number,
        a_number,
    });
}</code></pre>
<figcaption>test_print_too_many_args.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_print_too_many_args.zig
lib/std/fmt.zig:211:18: error: unused argument in &#39;here is a string: &#39;{s}&#39; here is a number: {}
                               &#39;
            1 =&gt; @compileError(&quot;unused argument in &#39;&quot; ++ fmt ++ &quot;&#39;&quot;),
                 ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
</code></pre>
<figcaption>Shell</figcaption>
</figure>

Zig gives programmers the tools needed to protect themselves against
their own mistakes.

Zig doesn\'t care whether the format argument is a string literal, only
that it is a compile-time known value that can be coerced to a
`[]`[`const`]{.tok-kw}` `[`u8`]{.tok-type}:

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

const a_number: i32 = 1234;
const a_string = &quot;foobar&quot;;
const fmt = &quot;here is a string: &#39;{s}&#39; here is a number: {}\n&quot;;

pub fn main() void {
    print(fmt, .{ a_string, a_number });
}</code></pre>
<figcaption>print_comptime-known_format.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe print_comptime-known_format.zig
$ ./print_comptime-known_format
here is a string: &#39;foobar&#39; here is a number: 1234</code></pre>
<figcaption>Shell</figcaption>
</figure>

This works fine.

Zig does not special case string formatting in the compiler and instead
exposes enough power to accomplish this task in userland. It does so
without introducing another language on top of Zig, such as a macro
language or a preprocessor language. It\'s Zig all the way down.

See also:

- [inline while](#inline-while)
- [inline for](#inline-for)

## [Assembly](#toc-Assembly) [§](#Assembly){.hdr} {#Assembly}

For some use cases, it may be necessary to directly control the machine
code generated by Zig programs, rather than relying on Zig\'s code
generation. For these cases, one can use inline assembly. Here is an
example of implementing Hello, World on x86_64 Linux using inline
assembly:

<figure>
<pre><code>pub fn main() noreturn {
    const msg = &quot;hello world\n&quot;;
    _ = syscall3(SYS_write, STDOUT_FILENO, @intFromPtr(msg), msg.len);
    _ = syscall1(SYS_exit, 0);
    unreachable;
}

pub const SYS_write = 1;
pub const SYS_exit = 60;

pub const STDOUT_FILENO = 1;

pub fn syscall1(number: usize, arg1: usize) usize {
    return asm volatile (&quot;syscall&quot;
        : [ret] &quot;={rax}&quot; (-&gt; usize),
        : [number] &quot;{rax}&quot; (number),
          [arg1] &quot;{rdi}&quot; (arg1),
        : &quot;rcx&quot;, &quot;r11&quot;
    );
}

pub fn syscall3(number: usize, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile (&quot;syscall&quot;
        : [ret] &quot;={rax}&quot; (-&gt; usize),
        : [number] &quot;{rax}&quot; (number),
          [arg1] &quot;{rdi}&quot; (arg1),
          [arg2] &quot;{rsi}&quot; (arg2),
          [arg3] &quot;{rdx}&quot; (arg3),
        : &quot;rcx&quot;, &quot;r11&quot;
    );
}</code></pre>
<figcaption>inline_assembly.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-exe inline_assembly.zig -target x86_64-linux
$ ./inline_assembly
hello world</code></pre>
<figcaption>Shell</figcaption>
</figure>

Dissecting the syntax:

<figure>
<pre><code>pub fn syscall1(number: usize, arg1: usize) usize {
    // Inline assembly is an expression which returns a value.
    // the `asm` keyword begins the expression.
    return asm
    // `volatile` is an optional modifier that tells Zig this
    // inline assembly expression has side-effects. Without
    // `volatile`, Zig is allowed to delete the inline assembly
    // code if the result is unused.
    volatile (
    // Next is a comptime string which is the assembly code.
    // Inside this string one may use `%[ret]`, `%[number]`,
    // or `%[arg1]` where a register is expected, to specify
    // the register that Zig uses for the argument or return value,
    // if the register constraint strings are used. However in
    // the below code, this is not used. A literal `%` can be
    // obtained by escaping it with a double percent: `%%`.
    // Often multiline string syntax comes in handy here.
        \\syscall
        // Next is the output. It is possible in the future Zig will
        // support multiple outputs, depending on how
        // https://github.com/ziglang/zig/issues/215 is resolved.
        // It is allowed for there to be no outputs, in which case
        // this colon would be directly followed by the colon for the inputs.
        :
        // This specifies the name to be used in `%[ret]` syntax in
        // the above assembly string. This example does not use it,
        // but the syntax is mandatory.
          [ret]
          // Next is the output constraint string. This feature is still
          // considered unstable in Zig, and so LLVM/GCC documentation
          // must be used to understand the semantics.
          // http://releases.llvm.org/10.0.0/docs/LangRef.html#inline-asm-constraint-string
          // https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
          // In this example, the constraint string means &quot;the result value of
          // this inline assembly instruction is whatever is in $rax&quot;.
          &quot;={rax}&quot;
          // Next is either a value binding, or `-&gt;` and then a type. The
          // type is the result type of the inline assembly expression.
          // If it is a value binding, then `%[ret]` syntax would be used
          // to refer to the register bound to the value.
          (-&gt; usize),
          // Next is the list of inputs.
          // The constraint for these inputs means, &quot;when the assembly code is
          // executed, $rax shall have the value of `number` and $rdi shall have
          // the value of `arg1`&quot;. Any number of input parameters is allowed,
          // including none.
        : [number] &quot;{rax}&quot; (number),
          [arg1] &quot;{rdi}&quot; (arg1),
          // Next is the list of clobbers. These declare a set of registers whose
          // values will not be preserved by the execution of this assembly code.
          // These do not include output or input registers. The special clobber
          // value of &quot;memory&quot; means that the assembly writes to arbitrary undeclared
          // memory locations - not only the memory pointed to by a declared indirect
          // output. In this example we list $rcx and $r11 because it is known the
          // kernel syscall does not preserve these registers.
        : &quot;rcx&quot;, &quot;r11&quot;
    );
}</code></pre>
<figcaption>Assembly Syntax Explained.zig</figcaption>
</figure>

For x86 and x86_64 targets, the syntax is AT&T syntax, rather than the
more popular Intel syntax. This is due to technical constraints;
assembly parsing is provided by LLVM and its support for Intel syntax is
buggy and not well tested.

Some day Zig may have its own assembler. This would allow it to
integrate more seamlessly into the language, as well as be compatible
with the popular NASM syntax. This documentation section will be updated
before 1.0.0 is released, with a conclusive statement about the status
of AT&T vs Intel/NASM syntax.

### [Output Constraints](#toc-Output-Constraints) [§](#Output-Constraints){.hdr} {#Output-Constraints}

Output constraints are still considered to be unstable in Zig, and so
[LLVM
documentation](http://releases.llvm.org/10.0.0/docs/LangRef.html#inline-asm-constraint-string)
and [GCC
documentation](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html)
must be used to understand the semantics.

Note that some breaking changes to output constraints are planned with
[issue #215](https://github.com/ziglang/zig/issues/215).

### [Input Constraints](#toc-Input-Constraints) [§](#Input-Constraints){.hdr} {#Input-Constraints}

Input constraints are still considered to be unstable in Zig, and so
[LLVM
documentation](http://releases.llvm.org/10.0.0/docs/LangRef.html#inline-asm-constraint-string)
and [GCC
documentation](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html)
must be used to understand the semantics.

Note that some breaking changes to input constraints are planned with
[issue #215](https://github.com/ziglang/zig/issues/215).

### [Clobbers](#toc-Clobbers) [§](#Clobbers){.hdr} {#Clobbers}

Clobbers are the set of registers whose values will not be preserved by
the execution of the assembly code. These do not include output or input
registers. The special clobber value of [`"memory"`]{.tok-str} means
that the assembly causes writes to arbitrary undeclared memory
locations - not only the memory pointed to by a declared indirect
output.

Failure to declare the full set of clobbers for a given inline assembly
expression is unchecked [Illegal Behavior](#Illegal-Behavior).

### [Global Assembly](#toc-Global-Assembly) [§](#Global-Assembly){.hdr} {#Global-Assembly}

When an assembly expression occurs in a [container](#Containers) level
[comptime](#comptime) block, this is **global assembly**.

This kind of assembly has different rules than inline assembly. First,
[`volatile`]{.tok-kw} is not valid because all global assembly is
unconditionally included. Second, there are no inputs, outputs, or
clobbers. All global assembly is concatenated verbatim into one long
string and assembled together. There are no template substitution rules
regarding `%` as there are in inline assembly expressions.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

comptime {
    asm (
        \\.global my_func;
        \\.type my_func, @function;
        \\my_func:
        \\  lea (%rdi,%rsi,1),%eax
        \\  retq
    );
}

extern fn my_func(a: i32, b: i32) i32;

test &quot;global assembly&quot; {
    try expect(my_func(12, 34) == 46);
}</code></pre>
<figcaption>test_global_assembly.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_global_assembly.zig -target x86_64-linux
1/1 test_global_assembly.test.global assembly...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

## [Atomics](#toc-Atomics) [§](#Atomics){.hdr} {#Atomics}

TODO: \@atomic rmw

TODO: builtin atomic memory ordering enum

See also:

- [\@atomicLoad](#atomicLoad)
- [\@atomicStore](#atomicStore)
- [\@atomicRmw](#atomicRmw)
- [\@cmpxchgWeak](#cmpxchgWeak)
- [\@cmpxchgStrong](#cmpxchgStrong)

## [Async Functions](#toc-Async-Functions) [§](#Async-Functions){.hdr} {#Async-Functions}

Async functions regressed with the release of 0.11.0. Their future in
the Zig language is unclear due to multiple unsolved problems:

- LLVM\'s lack of ability to optimize them.
- Third-party debuggers\' lack of ability to debug them.
- [The cancellation
  problem](https://github.com/ziglang/zig/issues/5913).
- Async function pointers preventing the stack size from being known.

These problems are surmountable, but it will take time. The Zig team is
currently focused on other priorities.

## [Builtin Functions](#toc-Builtin-Functions) [§](#Builtin-Functions){.hdr} {#Builtin-Functions}

Builtin functions are provided by the compiler and are prefixed with
`@`. The [`comptime`]{.tok-kw} keyword on a parameter means that the
parameter must be known at compile time.

### [\@addrSpaceCast](#toc-addrSpaceCast) [§](#addrSpaceCast){.hdr} {#addrSpaceCast}

    @addrSpaceCast(ptr: anytype) anytype

Converts a pointer from one address space to another. The new address
space is inferred based on the result type. Depending on the current
target and address spaces, this cast may be a no-op, a complex
operation, or illegal. If the cast is legal, then the resulting pointer
points to the same memory location as the pointer operand. It is always
valid to cast a pointer between the same address spaces.

### [\@addWithOverflow](#toc-addWithOverflow) [§](#addWithOverflow){.hdr} {#addWithOverflow}

    @addWithOverflow(a: anytype, b: anytype) struct { @TypeOf(a, b), u1 }

Performs `a + b` and returns a tuple with the result and a possible
overflow bit.

### [\@alignCast](#toc-alignCast) [§](#alignCast){.hdr} {#alignCast}

    @alignCast(ptr: anytype) anytype

`ptr` can be `*T`, `?*T`, or `[]T`. Changes the alignment of a pointer.
The alignment to use is inferred based on the result type.

A [pointer alignment safety check](#Incorrect-Pointer-Alignment) is
added to the generated code to make sure the pointer is aligned as
promised.

### [\@alignOf](#toc-alignOf) [§](#alignOf){.hdr} {#alignOf}

    @alignOf(comptime T: type) comptime_int

This function returns the number of bytes that this type should be
aligned to for the current target to match the C ABI. When the child
type of a pointer has this alignment, the alignment can be omitted from
the type.

    const assert = @import("std").debug.assert;
    comptime {
        assert(*u32 == *align(@alignOf(u32)) u32);
    }

The result is a target-specific compile time constant. It is guaranteed
to be less than or equal to [\@sizeOf(T)](#sizeOf).

See also:

- [Alignment](#Alignment)

### [\@as](#toc-as) [§](#as){.hdr}

    @as(comptime T: type, expression) T

Performs [Type Coercion](#Type-Coercion). This cast is allowed when the
conversion is unambiguous and safe, and is the preferred way to convert
between types, whenever possible.

### [\@atomicLoad](#toc-atomicLoad) [§](#atomicLoad){.hdr} {#atomicLoad}

    @atomicLoad(comptime T: type, ptr: *const T, comptime ordering: AtomicOrder) T

This builtin function atomically dereferences a pointer to a `T` and
returns the value.

`T` must be a pointer, a [`bool`]{.tok-type}, a float, an integer or an
enum.

`AtomicOrder` can be found with
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).builtin.AtomicOrder`.

See also:

- [\@atomicStore](#atomicStore)
- [\@atomicRmw](#atomicRmw)
- [\@cmpxchgWeak](#cmpxchgWeak)
- [\@cmpxchgStrong](#cmpxchgStrong)

### [\@atomicRmw](#toc-atomicRmw) [§](#atomicRmw){.hdr} {#atomicRmw}

    @atomicRmw(comptime T: type, ptr: *T, comptime op: AtomicRmwOp, operand: T, comptime ordering: AtomicOrder) T

This builtin function dereferences a pointer to a `T` and atomically
modifies the value and returns the previous value.

`T` must be a pointer, a [`bool`]{.tok-type}, a float, an integer or an
enum.

`AtomicOrder` can be found with
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).builtin.AtomicOrder`.

`AtomicRmwOp` can be found with
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).builtin.AtomicRmwOp`.

See also:

- [\@atomicStore](#atomicStore)
- [\@atomicLoad](#atomicLoad)
- [\@cmpxchgWeak](#cmpxchgWeak)
- [\@cmpxchgStrong](#cmpxchgStrong)

### [\@atomicStore](#toc-atomicStore) [§](#atomicStore){.hdr} {#atomicStore}

    @atomicStore(comptime T: type, ptr: *T, value: T, comptime ordering: AtomicOrder) void

This builtin function dereferences a pointer to a `T` and atomically
stores the given value.

`T` must be a pointer, a [`bool`]{.tok-type}, a float, an integer or an
enum.

`AtomicOrder` can be found with
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).builtin.AtomicOrder`.

See also:

- [\@atomicLoad](#atomicLoad)
- [\@atomicRmw](#atomicRmw)
- [\@cmpxchgWeak](#cmpxchgWeak)
- [\@cmpxchgStrong](#cmpxchgStrong)

### [\@bitCast](#toc-bitCast) [§](#bitCast){.hdr} {#bitCast}

    @bitCast(value: anytype) anytype

Converts a value of one type to another type. The return type is the
inferred result type.

Asserts that
[`@sizeOf`]{.tok-builtin}`(`[`@TypeOf`]{.tok-builtin}`(value)) == `[`@sizeOf`]{.tok-builtin}`(DestType)`.

Asserts that [`@typeInfo`]{.tok-builtin}`(DestType) != .pointer`. Use
[`@ptrCast`]{.tok-builtin} or [`@ptrFromInt`]{.tok-builtin} if you need
this.

Can be used for these things for example:

- Convert [`f32`]{.tok-type} to [`u32`]{.tok-type} bits
- Convert [`i32`]{.tok-type} to [`u32`]{.tok-type} preserving twos
  complement

Works at compile-time if `value` is known at compile time. It\'s a
compile error to bitcast a value of undefined layout; this means that,
besides the restriction from types which possess dedicated casting
builtins (enums, pointers, error sets), bare structs, error unions,
slices, optionals, and any other type without a well-defined memory
layout, also cannot be used in this operation.

### [\@bitOffsetOf](#toc-bitOffsetOf) [§](#bitOffsetOf){.hdr} {#bitOffsetOf}

    @bitOffsetOf(comptime T: type, comptime field_name: []const u8) comptime_int

Returns the bit offset of a field relative to its containing struct.

For non [packed structs](#packed-struct), this will always be divisible
by [`8`]{.tok-number}. For packed structs, non-byte-aligned fields will
share a byte offset, but they will have different bit offsets.

See also:

- [\@offsetOf](#offsetOf)

### [\@bitSizeOf](#toc-bitSizeOf) [§](#bitSizeOf){.hdr} {#bitSizeOf}

    @bitSizeOf(comptime T: type) comptime_int

This function returns the number of bits it takes to store `T` in memory
if the type were a field in a packed struct/union. The result is a
target-specific compile time constant.

This function measures the size at runtime. For types that are
disallowed at runtime, such as [`comptime_int`]{.tok-type} and
[`type`]{.tok-type}, the result is [`0`]{.tok-number}.

See also:

- [\@sizeOf](#sizeOf)
- [\@typeInfo](#typeInfo)

### [\@branchHint](#toc-branchHint) [§](#branchHint){.hdr} {#branchHint}

    @branchHint(hint: BranchHint) void

Hints to the optimizer how likely a given branch of control flow is to
be reached.

`BranchHint` can be found with
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).builtin.BranchHint`.

This function is only valid as the first statement in a control flow
branch, or the first statement in a function.

### [\@breakpoint](#toc-breakpoint) [§](#breakpoint){.hdr}

    @breakpoint() void

This function inserts a platform-specific debug trap instruction which
causes debuggers to break there. Unlike for [`@trap`]{.tok-builtin}`()`,
execution may continue after this point if the program is resumed.

This function is only valid within function scope.

See also:

- [\@trap](#trap)

### [\@mulAdd](#toc-mulAdd) [§](#mulAdd){.hdr} {#mulAdd}

    @mulAdd(comptime T: type, a: T, b: T, c: T) T

Fused multiply-add, similar to `(a * b) + c`, except only rounds once,
and is thus more accurate.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@byteSwap](#toc-byteSwap) [§](#byteSwap){.hdr} {#byteSwap}

    @byteSwap(operand: anytype) T

[`@TypeOf`]{.tok-builtin}`(operand)` must be an integer type or an
integer vector type with bit count evenly divisible by 8.

`operand` may be an [integer](#Integers) or [vector](#Vectors).

Swaps the byte order of the integer. This converts a big endian integer
to a little endian integer, and converts a little endian integer to a
big endian integer.

Note that for the purposes of memory layout with respect to endianness,
the integer type should be related to the number of bytes reported by
[\@sizeOf](#sizeOf) bytes. This is demonstrated with [`u24`]{.tok-type}.
[`@sizeOf`]{.tok-builtin}`(`[`u24`]{.tok-type}`) == `[`4`]{.tok-number},
which means that a [`u24`]{.tok-type} stored in memory takes 4 bytes,
and those 4 bytes are what are swapped on a little vs big endian system.
On the other hand, if `T` is specified to be [`u24`]{.tok-type}, then
only 3 bytes are reversed.

### [\@bitReverse](#toc-bitReverse) [§](#bitReverse){.hdr} {#bitReverse}

    @bitReverse(integer: anytype) T

[`@TypeOf`]{.tok-builtin}`(`[`anytype`]{.tok-kw}`)` accepts any integer
type or integer vector type.

Reverses the bitpattern of an integer value, including the sign bit if
applicable.

For example 0b10110110 ([`u8`]{.tok-type}` = `[`182`]{.tok-number},
[`i8`]{.tok-type}` = -`[`74`]{.tok-number}) becomes 0b01101101
([`u8`]{.tok-type}` = `[`109`]{.tok-number},
[`i8`]{.tok-type}` = `[`109`]{.tok-number}).

### [\@offsetOf](#toc-offsetOf) [§](#offsetOf){.hdr} {#offsetOf}

    @offsetOf(comptime T: type, comptime field_name: []const u8) comptime_int

Returns the byte offset of a field relative to its containing struct.

See also:

- [\@bitOffsetOf](#bitOffsetOf)

### [\@call](#toc-call) [§](#call){.hdr}

    @call(modifier: std.builtin.CallModifier, function: anytype, args: anytype) anytype

Calls a function, in the same way that invoking an expression with
parentheses does:

<figure>
<pre><code>const expect = @import(&quot;std&quot;).testing.expect;

test &quot;noinline function call&quot; {
    try expect(@call(.auto, add, .{ 3, 9 }) == 12);
}

fn add(a: i32, b: i32) i32 {
    return a + b;
}</code></pre>
<figcaption>test_call_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_call_builtin.zig
1/1 test_call_builtin.test.noinline function call...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

[`@call`]{.tok-builtin} allows more flexibility than normal function
call syntax does. The `CallModifier` enum is reproduced here:

<figure>
<pre><code>pub const CallModifier = enum {
    /// Equivalent to function call syntax.
    auto,

    /// Equivalent to async keyword used with function call syntax.
    async_kw,

    /// Prevents tail call optimization. This guarantees that the return
    /// address will point to the callsite, as opposed to the callsite&#39;s
    /// callsite. If the call is otherwise required to be tail-called
    /// or inlined, a compile error is emitted instead.
    never_tail,

    /// Guarantees that the call will not be inlined. If the call is
    /// otherwise required to be inlined, a compile error is emitted instead.
    never_inline,

    /// Asserts that the function call will not suspend. This allows a
    /// non-async function to call an async function.
    no_async,

    /// Guarantees that the call will be generated with tail call optimization.
    /// If this is not possible, a compile error is emitted instead.
    always_tail,

    /// Guarantees that the call will be inlined at the callsite.
    /// If this is not possible, a compile error is emitted instead.
    always_inline,

    /// Evaluates the call at compile-time. If the call cannot be completed at
    /// compile-time, a compile error is emitted instead.
    compile_time,
};</code></pre>
<figcaption>builtin.CallModifier struct.zig</figcaption>
</figure>

### [\@cDefine](#toc-cDefine) [§](#cDefine){.hdr} {#cDefine}

    @cDefine(comptime name: []const u8, value) void

This function can only occur inside [`@cImport`]{.tok-builtin}.

This appends `#define $name $value` to the [`@cImport`]{.tok-builtin}
temporary buffer.

To define without a value, like this:

``` c
#define _GNU_SOURCE
```

Use the void value, like this:

    @cDefine("_GNU_SOURCE", {})

See also:

- [Import from C Header File](#Import-from-C-Header-File)
- [\@cInclude](#cInclude)
- [\@cImport](#cImport)
- [\@cUndef](#cUndef)
- [void](#void)

### [\@cImport](#toc-cImport) [§](#cImport){.hdr} {#cImport}

    @cImport(expression) type

This function parses C code and imports the functions, types, variables,
and compatible macro definitions into a new empty struct type, and then
returns that type.

`expression` is interpreted at compile time. The builtin functions
[`@cInclude`]{.tok-builtin}, [`@cDefine`]{.tok-builtin}, and
[`@cUndef`]{.tok-builtin} work within this expression, appending to a
temporary buffer which is then parsed as C code.

Usually you should only have one [`@cImport`]{.tok-builtin} in your
entire application, because it saves the compiler from invoking clang
multiple times, and prevents inline functions from being duplicated.

Reasons for having multiple [`@cImport`]{.tok-builtin} expressions would
be:

- To avoid a symbol collision, for example if foo.h and bar.h both
  `#define CONNECTION_COUNT`
- To analyze the C code with different preprocessor defines

See also:

- [Import from C Header File](#Import-from-C-Header-File)
- [\@cInclude](#cInclude)
- [\@cDefine](#cDefine)
- [\@cUndef](#cUndef)

### [\@cInclude](#toc-cInclude) [§](#cInclude){.hdr} {#cInclude}

    @cInclude(comptime path: []const u8) void

This function can only occur inside [`@cImport`]{.tok-builtin}.

This appends `#include <$path>\n` to the `c_import` temporary buffer.

See also:

- [Import from C Header File](#Import-from-C-Header-File)
- [\@cImport](#cImport)
- [\@cDefine](#cDefine)
- [\@cUndef](#cUndef)

### [\@clz](#toc-clz) [§](#clz){.hdr}

    @clz(operand: anytype) anytype

[`@TypeOf`]{.tok-builtin}`(operand)` must be an integer type or an
integer vector type.

`operand` may be an [integer](#Integers) or [vector](#Vectors).

Counts the number of most-significant (leading in a big-endian sense)
zeroes in an integer - \"count leading zeroes\".

The return type is an unsigned integer or vector of unsigned integers
with the minimum number of bits that can represent the bit count of the
integer type.

If `operand` is zero, [`@clz`]{.tok-builtin} returns the bit width of
integer type `T`.

See also:

- [\@ctz](#ctz)
- [\@popCount](#popCount)

### [\@cmpxchgStrong](#toc-cmpxchgStrong) [§](#cmpxchgStrong){.hdr} {#cmpxchgStrong}

    @cmpxchgStrong(comptime T: type, ptr: *T, expected_value: T, new_value: T, success_order: AtomicOrder, fail_order: AtomicOrder) ?T

This function performs a strong atomic compare-and-exchange operation,
returning [`null`]{.tok-null} if the current value is the given expected
value. It\'s the equivalent of this code, except atomic:

<figure>
<pre><code>fn cmpxchgStrongButNotAtomic(comptime T: type, ptr: *T, expected_value: T, new_value: T) ?T {
    const old_value = ptr.*;
    if (old_value == expected_value) {
        ptr.* = new_value;
        return null;
    } else {
        return old_value;
    }
}</code></pre>
<figcaption>not_atomic_cmpxchgStrong.zig</figcaption>
</figure>

If you are using cmpxchg in a retry loop, [\@cmpxchgWeak](#cmpxchgWeak)
is the better choice, because it can be implemented more efficiently in
machine instructions.

`T` must be a pointer, a [`bool`]{.tok-type}, a float, an integer or an
enum.

[`@typeInfo`]{.tok-builtin}`(`[`@TypeOf`]{.tok-builtin}`(ptr)).pointer.alignment`
must be `>= `[`@sizeOf`]{.tok-builtin}`(T).`

`AtomicOrder` can be found with
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).builtin.AtomicOrder`.

See also:

- [\@atomicStore](#atomicStore)
- [\@atomicLoad](#atomicLoad)
- [\@atomicRmw](#atomicRmw)
- [\@cmpxchgWeak](#cmpxchgWeak)

### [\@cmpxchgWeak](#toc-cmpxchgWeak) [§](#cmpxchgWeak){.hdr} {#cmpxchgWeak}

    @cmpxchgWeak(comptime T: type, ptr: *T, expected_value: T, new_value: T, success_order: AtomicOrder, fail_order: AtomicOrder) ?T

This function performs a weak atomic compare-and-exchange operation,
returning [`null`]{.tok-null} if the current value is the given expected
value. It\'s the equivalent of this code, except atomic:

<figure>
<pre><code>fn cmpxchgWeakButNotAtomic(comptime T: type, ptr: *T, expected_value: T, new_value: T) ?T {
    const old_value = ptr.*;
    if (old_value == expected_value and usuallyTrueButSometimesFalse()) {
        ptr.* = new_value;
        return null;
    } else {
        return old_value;
    }
}</code></pre>
<figcaption>cmpxchgWeakButNotAtomic</figcaption>
</figure>

If you are using cmpxchg in a retry loop, the sporadic failure will be
no problem, and `cmpxchgWeak` is the better choice, because it can be
implemented more efficiently in machine instructions. However if you
need a stronger guarantee, use [\@cmpxchgStrong](#cmpxchgStrong).

`T` must be a pointer, a [`bool`]{.tok-type}, a float, an integer or an
enum.

[`@typeInfo`]{.tok-builtin}`(`[`@TypeOf`]{.tok-builtin}`(ptr)).pointer.alignment`
must be `>= `[`@sizeOf`]{.tok-builtin}`(T).`

`AtomicOrder` can be found with
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).builtin.AtomicOrder`.

See also:

- [\@atomicStore](#atomicStore)
- [\@atomicLoad](#atomicLoad)
- [\@atomicRmw](#atomicRmw)
- [\@cmpxchgStrong](#cmpxchgStrong)

### [\@compileError](#toc-compileError) [§](#compileError){.hdr} {#compileError}

    @compileError(comptime msg: []const u8) noreturn

This function, when semantically analyzed, causes a compile error with
the message `msg`.

There are several ways that code avoids being semantically checked, such
as using [`if`]{.tok-kw} or [`switch`]{.tok-kw} with compile time
constants, and [`comptime`]{.tok-kw} functions.

### [\@compileLog](#toc-compileLog) [§](#compileLog){.hdr} {#compileLog}

    @compileLog(...) void

This function prints the arguments passed to it at compile-time.

To prevent accidentally leaving compile log statements in a codebase, a
compilation error is added to the build, pointing to the compile log
statement. This error prevents code from being generated, but does not
otherwise interfere with analysis.

This function can be used to do \"printf debugging\" on compile-time
executing code.

<figure>
<pre><code>const print = @import(&quot;std&quot;).debug.print;

const num1 = blk: {
    var val1: i32 = 99;
    @compileLog(&quot;comptime val1 = &quot;, val1);
    val1 = val1 + 1;
    break :blk val1;
};

test &quot;main&quot; {
    @compileLog(&quot;comptime in main&quot;);

    print(&quot;Runtime in main, num1 = {}.\n&quot;, .{num1});
}</code></pre>
<figcaption>test_compileLog_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_compileLog_builtin.zig
doc/langref/test_compileLog_builtin.zig:11:5: error: found compile log statement
    @compileLog(&quot;comptime in main&quot;);
    ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
doc/langref/test_compileLog_builtin.zig:5:5: note: also here
    @compileLog(&quot;comptime val1 = &quot;, val1);
    ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Compile Log Output:
@as(*const [16:0]u8, &quot;comptime in main&quot;)
@as(*const [16:0]u8, &quot;comptime val1 = &quot;), @as(i32, 99)</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [\@constCast](#toc-constCast) [§](#constCast){.hdr} {#constCast}

    @constCast(value: anytype) DestType

Remove [`const`]{.tok-kw} qualifier from a pointer.

### [\@ctz](#toc-ctz) [§](#ctz){.hdr}

    @ctz(operand: anytype) anytype

[`@TypeOf`]{.tok-builtin}`(operand)` must be an integer type or an
integer vector type.

`operand` may be an [integer](#Integers) or [vector](#Vectors).

Counts the number of least-significant (trailing in a big-endian sense)
zeroes in an integer - \"count trailing zeroes\".

The return type is an unsigned integer or vector of unsigned integers
with the minimum number of bits that can represent the bit count of the
integer type.

If `operand` is zero, [`@ctz`]{.tok-builtin} returns the bit width of
integer type `T`.

See also:

- [\@clz](#clz)
- [\@popCount](#popCount)

### [\@cUndef](#toc-cUndef) [§](#cUndef){.hdr} {#cUndef}

    @cUndef(comptime name: []const u8) void

This function can only occur inside [`@cImport`]{.tok-builtin}.

This appends `#undef $name` to the [`@cImport`]{.tok-builtin} temporary
buffer.

See also:

- [Import from C Header File](#Import-from-C-Header-File)
- [\@cImport](#cImport)
- [\@cDefine](#cDefine)
- [\@cInclude](#cInclude)

### [\@cVaArg](#toc-cVaArg) [§](#cVaArg){.hdr} {#cVaArg}

    @cVaArg(operand: *std.builtin.VaList, comptime T: type) T

Implements the C macro `va_arg`.

See also:

- [\@cVaCopy](#cVaCopy)
- [\@cVaEnd](#cVaEnd)
- [\@cVaStart](#cVaStart)

### [\@cVaCopy](#toc-cVaCopy) [§](#cVaCopy){.hdr} {#cVaCopy}

    @cVaCopy(src: *std.builtin.VaList) std.builtin.VaList

Implements the C macro `va_copy`.

See also:

- [\@cVaArg](#cVaArg)
- [\@cVaEnd](#cVaEnd)
- [\@cVaStart](#cVaStart)

### [\@cVaEnd](#toc-cVaEnd) [§](#cVaEnd){.hdr} {#cVaEnd}

    @cVaEnd(src: *std.builtin.VaList) void

Implements the C macro `va_end`.

See also:

- [\@cVaArg](#cVaArg)
- [\@cVaCopy](#cVaCopy)
- [\@cVaStart](#cVaStart)

### [\@cVaStart](#toc-cVaStart) [§](#cVaStart){.hdr} {#cVaStart}

    @cVaStart() std.builtin.VaList

Implements the C macro `va_start`. Only valid inside a variadic
function.

See also:

- [\@cVaArg](#cVaArg)
- [\@cVaCopy](#cVaCopy)
- [\@cVaEnd](#cVaEnd)

### [\@divExact](#toc-divExact) [§](#divExact){.hdr} {#divExact}

    @divExact(numerator: T, denominator: T) T

Exact division. Caller guarantees `denominator != `[`0`]{.tok-number}
and
[`@divTrunc`]{.tok-builtin}`(numerator, denominator) * denominator == numerator`.

- [`@divExact`]{.tok-builtin}`(`[`6`]{.tok-number}`, `[`3`]{.tok-number}`) == `[`2`]{.tok-number}
- [`@divExact`]{.tok-builtin}`(a, b) * b == a`

For a function that returns a possible error code, use
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.divExact`.

See also:

- [\@divTrunc](#divTrunc)
- [\@divFloor](#divFloor)

### [\@divFloor](#toc-divFloor) [§](#divFloor){.hdr} {#divFloor}

    @divFloor(numerator: T, denominator: T) T

Floored division. Rounds toward negative infinity. For unsigned integers
it is the same as `numerator / denominator`. Caller guarantees
`denominator != `[`0`]{.tok-number} and
`!(`[`@typeInfo`]{.tok-builtin}`(T) == .int `[`and`]{.tok-kw}` T.is_signed `[`and`]{.tok-kw}` numerator == std.math.minInt(T) `[`and`]{.tok-kw}` denominator == -`[`1`]{.tok-number}`)`.

- [`@divFloor`]{.tok-builtin}`(-`[`5`]{.tok-number}`, `[`3`]{.tok-number}`) == -`[`2`]{.tok-number}
- `(`[`@divFloor`]{.tok-builtin}`(a, b) * b) + `[`@mod`]{.tok-builtin}`(a, b) == a`

For a function that returns a possible error code, use
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.divFloor`.

See also:

- [\@divTrunc](#divTrunc)
- [\@divExact](#divExact)

### [\@divTrunc](#toc-divTrunc) [§](#divTrunc){.hdr} {#divTrunc}

    @divTrunc(numerator: T, denominator: T) T

Truncated division. Rounds toward zero. For unsigned integers it is the
same as `numerator / denominator`. Caller guarantees
`denominator != `[`0`]{.tok-number} and
`!(`[`@typeInfo`]{.tok-builtin}`(T) == .int `[`and`]{.tok-kw}` T.is_signed `[`and`]{.tok-kw}` numerator == std.math.minInt(T) `[`and`]{.tok-kw}` denominator == -`[`1`]{.tok-number}`)`.

- [`@divTrunc`]{.tok-builtin}`(-`[`5`]{.tok-number}`, `[`3`]{.tok-number}`) == -`[`1`]{.tok-number}
- `(`[`@divTrunc`]{.tok-builtin}`(a, b) * b) + `[`@rem`]{.tok-builtin}`(a, b) == a`

For a function that returns a possible error code, use
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.divTrunc`.

See also:

- [\@divFloor](#divFloor)
- [\@divExact](#divExact)

### [\@embedFile](#toc-embedFile) [§](#embedFile){.hdr} {#embedFile}

    @embedFile(comptime path: []const u8) *const [N:0]u8

This function returns a compile time constant pointer to
null-terminated, fixed-size array with length equal to the byte count of
the file given by `path`. The contents of the array are the contents of
the file. This is equivalent to a [string
literal](#String-Literals-and-Unicode-Code-Point-Literals) with the file
contents.

`path` is absolute or relative to the current file, just like
[`@import`]{.tok-builtin}.

See also:

- [\@import](#import)

### [\@enumFromInt](#toc-enumFromInt) [§](#enumFromInt){.hdr} {#enumFromInt}

    @enumFromInt(integer: anytype) anytype

Converts an integer into an [enum](#enum) value. The return type is the
inferred result type.

Attempting to convert an integer with no corresponding value in the enum
invokes safety-checked [Illegal Behavior](#Illegal-Behavior). Note that
a [non-exhaustive enum](#Non-exhaustive-enum) has corresponding values
for all integers in the enum\'s integer tag type: the `_` value
represents all the remaining unnamed integers in the enum\'s tag type.

See also:

- [\@intFromEnum](#intFromEnum)

### [\@errorFromInt](#toc-errorFromInt) [§](#errorFromInt){.hdr} {#errorFromInt}

    @errorFromInt(value: std.meta.Int(.unsigned, @bitSizeOf(anyerror))) anyerror

Converts from the integer representation of an error into [The Global
Error Set](#The-Global-Error-Set) type.

It is generally recommended to avoid this cast, as the integer
representation of an error is not stable across source code changes.

Attempting to convert an integer that does not correspond to any error
results in safety-checked [Illegal Behavior](#Illegal-Behavior).

See also:

- [\@intFromError](#intFromError)

### [\@errorName](#toc-errorName) [§](#errorName){.hdr} {#errorName}

    @errorName(err: anyerror) [:0]const u8

This function returns the string representation of an error. The string
representation of [`error`]{.tok-kw}`.OutOfMem` is
[`"OutOfMem"`]{.tok-str}.

If there are no calls to [`@errorName`]{.tok-builtin} in an entire
application, or all calls have a compile-time known value for `err`,
then no error name table will be generated.

### [\@errorReturnTrace](#toc-errorReturnTrace) [§](#errorReturnTrace){.hdr} {#errorReturnTrace}

    @errorReturnTrace() ?*builtin.StackTrace

If the binary is built with error return tracing, and this function is
invoked in a function that calls a function with an error or error union
return type, returns a stack trace object. Otherwise returns
[null](#null).

### [\@errorCast](#toc-errorCast) [§](#errorCast){.hdr} {#errorCast}

    @errorCast(value: anytype) anytype

Converts an error set or error union value from one error set to another
error set. The return type is the inferred result type. Attempting to
convert an error which is not in the destination error set results in
safety-checked [Illegal Behavior](#Illegal-Behavior).

### [\@export](#toc-export) [§](#export){.hdr}

    @export(comptime ptr: *const anyopaque, comptime options: std.builtin.ExportOptions) void

Creates a symbol in the output object file which refers to the target of
`ptr`.

`ptr` must point to a global variable or a comptime-known constant.

This builtin can be called from a [comptime](#comptime) block to
conditionally export symbols. When `ptr` points to a function with the C
calling convention and `options.linkage` is `.Strong`, this is
equivalent to the [`export`]{.tok-kw} keyword used on a function:

<figure>
<pre><code>comptime {
    @export(&amp;internalName, .{ .name = &quot;foo&quot;, .linkage = .strong });
}

fn internalName() callconv(.C) void {}</code></pre>
<figcaption>export_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-obj export_builtin.zig</code></pre>
<figcaption>Shell</figcaption>
</figure>

This is equivalent to:

<figure>
<pre><code>export fn foo() void {}</code></pre>
<figcaption>export_builtin_equivalent_code.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-obj export_builtin_equivalent_code.zig</code></pre>
<figcaption>Shell</figcaption>
</figure>

Note that even when using [`export`]{.tok-kw}, the `@"foo"` syntax for
[identifiers](#Identifiers) can be used to choose any string for the
symbol name:

<figure>
<pre><code>export fn @&quot;A function name that is a complete sentence.&quot;() void {}</code></pre>
<figcaption>export_any_symbol_name.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig build-obj export_any_symbol_name.zig</code></pre>
<figcaption>Shell</figcaption>
</figure>

When looking at the resulting object, you can see the symbol is used
verbatim:

    00000000000001f0 T A function name that is a complete sentence.

See also:

- [Exporting a C Library](#Exporting-a-C-Library)

### [\@extern](#toc-extern) [§](#extern){.hdr}

    @extern(T: type, comptime options: std.builtin.ExternOptions) T

Creates a reference to an external symbol in the output object file. T
must be a pointer type.

See also:

- [\@export](#export)

### [\@field](#toc-field) [§](#field){.hdr}

    @field(lhs: anytype, comptime field_name: []const u8) (field)

Performs field access by a compile-time string. Works on both fields and
declarations.

<figure>
<pre><code>const std = @import(&quot;std&quot;);

const Point = struct {
    x: u32,
    y: u32,

    pub var z: u32 = 1;
};

test &quot;field access by string&quot; {
    const expect = std.testing.expect;
    var p = Point{ .x = 0, .y = 0 };

    @field(p, &quot;x&quot;) = 4;
    @field(p, &quot;y&quot;) = @field(p, &quot;x&quot;) + 1;

    try expect(@field(p, &quot;x&quot;) == 4);
    try expect(@field(p, &quot;y&quot;) == 5);
}

test &quot;decl access by string&quot; {
    const expect = std.testing.expect;

    try expect(@field(Point, &quot;z&quot;) == 1);

    @field(Point, &quot;z&quot;) = 2;
    try expect(@field(Point, &quot;z&quot;) == 2);
}</code></pre>
<figcaption>test_field_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_field_builtin.zig
1/2 test_field_builtin.test.field access by string...OK
2/2 test_field_builtin.test.decl access by string...OK
All 2 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [\@fieldParentPtr](#toc-fieldParentPtr) [§](#fieldParentPtr){.hdr} {#fieldParentPtr}

    @fieldParentPtr(comptime field_name: []const u8, field_ptr: *T) anytype

Given a pointer to a struct field, returns a pointer to the struct
containing that field. The return type (and struct in question) is the
inferred result type.

If `field_ptr` does not point to the `field_name` field of an instance
of the result type, and the result type has ill-defined layout, invokes
unchecked [Illegal Behavior](#Illegal-Behavior).

### [\@FieldType](#toc-FieldType) [§](#FieldType){.hdr} {#FieldType}

    @FieldType(comptime Type: type, comptime field_name: []const u8) type

Given a type and the name of one of its fields, returns the type of that
field.

### [\@floatCast](#toc-floatCast) [§](#floatCast){.hdr} {#floatCast}

    @floatCast(value: anytype) anytype

Convert from one float type to another. This cast is safe, but may cause
the numeric value to lose precision. The return type is the inferred
result type.

### [\@floatFromInt](#toc-floatFromInt) [§](#floatFromInt){.hdr} {#floatFromInt}

    @floatFromInt(int: anytype) anytype

Converts an integer to the closest floating point representation. The
return type is the inferred result type. To convert the other way, use
[\@intFromFloat](#intFromFloat). This operation is legal for all values
of all integer types.

### [\@frameAddress](#toc-frameAddress) [§](#frameAddress){.hdr} {#frameAddress}

    @frameAddress() usize

This function returns the base pointer of the current stack frame.

The implications of this are target-specific and not consistent across
all platforms. The frame address may not be available in release mode
due to aggressive optimizations.

This function is only valid within function scope.

### [\@hasDecl](#toc-hasDecl) [§](#hasDecl){.hdr} {#hasDecl}

    @hasDecl(comptime Container: type, comptime name: []const u8) bool

Returns whether or not a [container](#Containers) has a declaration
matching `name`.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

const Foo = struct {
    nope: i32,

    pub var blah = &quot;xxx&quot;;
    const hi = 1;
};

test &quot;@hasDecl&quot; {
    try expect(@hasDecl(Foo, &quot;blah&quot;));

    // Even though `hi` is private, @hasDecl returns true because this test is
    // in the same file scope as Foo. It would return false if Foo was declared
    // in a different file.
    try expect(@hasDecl(Foo, &quot;hi&quot;));

    // @hasDecl is for declarations; not fields.
    try expect(!@hasDecl(Foo, &quot;nope&quot;));
    try expect(!@hasDecl(Foo, &quot;nope1234&quot;));
}</code></pre>
<figcaption>test_hasDecl_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_hasDecl_builtin.zig
1/1 test_hasDecl_builtin.test.@hasDecl...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [\@hasField](#hasField)

### [\@hasField](#toc-hasField) [§](#hasField){.hdr} {#hasField}

    @hasField(comptime Container: type, comptime name: []const u8) bool

Returns whether the field name of a struct, union, or enum exists.

The result is a compile time constant.

It does not include functions, variables, or constants.

See also:

- [\@hasDecl](#hasDecl)

### [\@import](#toc-import) [§](#import){.hdr}

    @import(comptime path: []const u8) type

This function finds a zig file corresponding to `path` and adds it to
the build, if it is not already added.

Zig source files are implicitly structs, with a name equal to the
file\'s basename with the extension truncated. [`@import`]{.tok-builtin}
returns the struct type corresponding to the file.

Declarations which have the [`pub`]{.tok-kw} keyword may be referenced
from a different source file than the one they are declared in.

`path` can be a relative path or it can be the name of a package. If it
is a relative path, it is relative to the file that contains the
[`@import`]{.tok-builtin} function call.

The following packages are always available:

- [`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`)` - Zig Standard
  Library
- [`@import`]{.tok-builtin}`(`[`"builtin"`]{.tok-str}`)` -
  Target-specific information The command `zig build-exe --show-builtin`
  outputs the source to stdout for reference.
- [`@import`]{.tok-builtin}`(`[`"root"`]{.tok-str}`)` - Root source file
  This is usually `src/main.zig` but depends on what file is built.

See also:

- [Compile Variables](#Compile-Variables)
- [\@embedFile](#embedFile)

### [\@inComptime](#toc-inComptime) [§](#inComptime){.hdr} {#inComptime}

    @inComptime() bool

Returns whether the builtin was run in a [`comptime`]{.tok-kw} context.
The result is a compile-time constant.

This can be used to provide alternative, comptime-friendly
implementations of functions. It should not be used, for instance, to
exclude certain functions from being evaluated at comptime.

See also:

- [comptime](#comptime)

### [\@intCast](#toc-intCast) [§](#intCast){.hdr} {#intCast}

    @intCast(int: anytype) anytype

Converts an integer to another integer while keeping the same numerical
value. The return type is the inferred result type. Attempting to
convert a number which is out of range of the destination type results
in safety-checked [Illegal Behavior](#Illegal-Behavior).

<figure>
<pre><code>test &quot;integer cast panic&quot; {
    var a: u16 = 0xabcd; // runtime-known
    _ = &amp;a;
    const b: u8 = @intCast(a);
    _ = b;
}</code></pre>
<figcaption>test_intCast_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_intCast_builtin.zig
1/1 test_intCast_builtin.test.integer cast panic...thread 222197 panic: integer cast truncated bits
/home/andy/src/zig/doc/langref/test_intCast_builtin.zig:4:19: 0x1048978 in test.integer cast panic (test)
    const b: u8 = @intCast(a);
                  ^
/home/andy/src/zig/lib/compiler/test_runner.zig:214:25: 0x10eedb5 in mainTerminal (test)
        if (test_fn.func()) |_| {
                        ^
/home/andy/src/zig/lib/compiler/test_runner.zig:62:28: 0x10e734d in main (test)
        return mainTerminal();
                           ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10e68d2 in posixCallMainAndExit (test)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10e64ad in _start (test)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
error: the following test command crashed:
/home/andy/src/zig/.zig-cache/o/df39e05f4dd3b2dc748e167908afb941/test --seed=0x9bc4417f</code></pre>
<figcaption>Shell</figcaption>
</figure>

To truncate the significant bits of a number out of range of the
destination type, use [\@truncate](#truncate).

If `T` is [`comptime_int`]{.tok-type}, then this is semantically
equivalent to [Type Coercion](#Type-Coercion).

### [\@intFromBool](#toc-intFromBool) [§](#intFromBool){.hdr} {#intFromBool}

    @intFromBool(value: bool) u1

Converts [`true`]{.tok-null} to
[`@as`]{.tok-builtin}`(`[`u1`]{.tok-type}`, `[`1`]{.tok-number}`)` and
[`false`]{.tok-null} to
[`@as`]{.tok-builtin}`(`[`u1`]{.tok-type}`, `[`0`]{.tok-number}`)`.

### [\@intFromEnum](#toc-intFromEnum) [§](#intFromEnum){.hdr} {#intFromEnum}

    @intFromEnum(enum_or_tagged_union: anytype) anytype

Converts an enumeration value into its integer tag type. When a tagged
union is passed, the tag value is used as the enumeration value.

If there is only one possible enum value, the result is a
[`comptime_int`]{.tok-type} known at [comptime](#comptime).

See also:

- [\@enumFromInt](#enumFromInt)

### [\@intFromError](#toc-intFromError) [§](#intFromError){.hdr} {#intFromError}

    @intFromError(err: anytype) std.meta.Int(.unsigned, @bitSizeOf(anyerror))

Supports the following types:

- [The Global Error Set](#The-Global-Error-Set)
- [Error Set Type](#Error-Set-Type)
- [Error Union Type](#Error-Union-Type)

Converts an error to the integer representation of an error.

It is generally recommended to avoid this cast, as the integer
representation of an error is not stable across source code changes.

See also:

- [\@errorFromInt](#errorFromInt)

### [\@intFromFloat](#toc-intFromFloat) [§](#intFromFloat){.hdr} {#intFromFloat}

    @intFromFloat(float: anytype) anytype

Converts the integer part of a floating point number to the inferred
result type.

If the integer part of the floating point number cannot fit in the
destination type, it invokes safety-checked [Illegal
Behavior](#Illegal-Behavior).

See also:

- [\@floatFromInt](#floatFromInt)

### [\@intFromPtr](#toc-intFromPtr) [§](#intFromPtr){.hdr} {#intFromPtr}

    @intFromPtr(value: anytype) usize

Converts `value` to a [`usize`]{.tok-type} which is the address of the
pointer. `value` can be `*T` or `?*T`.

To convert the other way, use [\@ptrFromInt](#ptrFromInt)

### [\@max](#toc-max) [§](#max){.hdr}

    @max(...) T

Takes two or more arguments and returns the biggest value included (the
maximum). This builtin accepts integers, floats, and vectors of either.
In the latter case, the operation is performed element wise.

NaNs are handled as follows: return the biggest non-NaN value included.
If all operands are NaN, return NaN.

See also:

- [\@min](#min)
- [Vectors](#Vectors)

### [\@memcpy](#toc-memcpy) [§](#memcpy){.hdr}

    @memcpy(noalias dest, noalias source) void

This function copies bytes from one region of memory to another.

`dest` must be a mutable slice, a mutable pointer to an array, or a
mutable many-item [pointer](#Pointers). It may have any alignment, and
it may have any element type.

`source` must be a slice, a pointer to an array, or a many-item
[pointer](#Pointers). It may have any alignment, and it may have any
element type.

The `source` element type must have the same in-memory representation as
the `dest` element type.

Similar to [for](#for) loops, at least one of `source` and `dest` must
provide a length, and if two lengths are provided, they must be equal.

Finally, the two memory regions must not overlap.

### [\@memset](#toc-memset) [§](#memset){.hdr}

    @memset(dest, elem) void

This function sets all the elements of a memory region to `elem`.

`dest` must be a mutable slice or a mutable pointer to an array. It may
have any alignment, and it may have any element type.

`elem` is coerced to the element type of `dest`.

For securely zeroing out sensitive contents from memory, you should use
`std.crypto.secureZero`

### [\@min](#toc-min) [§](#min){.hdr}

    @min(...) T

Takes two or more arguments and returns the smallest value included (the
minimum). This builtin accepts integers, floats, and vectors of either.
In the latter case, the operation is performed element wise.

NaNs are handled as follows: return the smallest non-NaN value included.
If all operands are NaN, return NaN.

See also:

- [\@max](#max)
- [Vectors](#Vectors)

### [\@wasmMemorySize](#toc-wasmMemorySize) [§](#wasmMemorySize){.hdr} {#wasmMemorySize}

    @wasmMemorySize(index: u32) usize

This function returns the size of the Wasm memory identified by `index`
as an unsigned value in units of Wasm pages. Note that each Wasm page is
64KB in size.

This function is a low level intrinsic with no safety mechanisms usually
useful for allocator designers targeting Wasm. So unless you are writing
a new allocator from scratch, you should use something like
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).heap.WasmPageAllocator`.

See also:

- [\@wasmMemoryGrow](#wasmMemoryGrow)

### [\@wasmMemoryGrow](#toc-wasmMemoryGrow) [§](#wasmMemoryGrow){.hdr} {#wasmMemoryGrow}

    @wasmMemoryGrow(index: u32, delta: usize) isize

This function increases the size of the Wasm memory identified by
`index` by `delta` in units of unsigned number of Wasm pages. Note that
each Wasm page is 64KB in size. On success, returns previous memory
size; on failure, if the allocation fails, returns -1.

This function is a low level intrinsic with no safety mechanisms usually
useful for allocator designers targeting Wasm. So unless you are writing
a new allocator from scratch, you should use something like
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).heap.WasmPageAllocator`.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const native_arch = @import(&quot;builtin&quot;).target.cpu.arch;
const expect = std.testing.expect;

test &quot;@wasmMemoryGrow&quot; {
    if (native_arch != .wasm32) return error.SkipZigTest;

    const prev = @wasmMemorySize(0);
    try expect(prev == @wasmMemoryGrow(0, 1));
    try expect(prev + 1 == @wasmMemorySize(0));
}</code></pre>
<figcaption>test_wasmMemoryGrow_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_wasmMemoryGrow_builtin.zig
1/1 test_wasmMemoryGrow_builtin.test.@wasmMemoryGrow...SKIP
0 passed; 1 skipped; 0 failed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [\@wasmMemorySize](#wasmMemorySize)

### [\@mod](#toc-mod) [§](#mod){.hdr}

    @mod(numerator: T, denominator: T) T

Modulus division. For unsigned integers this is the same as
`numerator % denominator`. Caller guarantees
`denominator > `[`0`]{.tok-number}, otherwise the operation will result
in a [Remainder Division by Zero](#Remainder-Division-by-Zero) when
runtime safety checks are enabled.

- [`@mod`]{.tok-builtin}`(-`[`5`]{.tok-number}`, `[`3`]{.tok-number}`) == `[`1`]{.tok-number}
- `(`[`@divFloor`]{.tok-builtin}`(a, b) * b) + `[`@mod`]{.tok-builtin}`(a, b) == a`

For a function that returns an error code, see
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.mod`.

See also:

- [\@rem](#rem)

### [\@mulWithOverflow](#toc-mulWithOverflow) [§](#mulWithOverflow){.hdr} {#mulWithOverflow}

    @mulWithOverflow(a: anytype, b: anytype) struct { @TypeOf(a, b), u1 }

Performs `a * b` and returns a tuple with the result and a possible
overflow bit.

### [\@panic](#toc-panic) [§](#panic){.hdr}

    @panic(message: []const u8) noreturn

Invokes the panic handler function. By default the panic handler
function calls the public `panic` function exposed in the root source
file, or if there is not one specified, the `std.builtin.default_panic`
function from `std/builtin.zig`.

Generally it is better to use
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).debug.panic`. However,
[`@panic`]{.tok-builtin} can be useful for 2 scenarios:

- From library code, calling the programmer\'s panic function if they
  exposed one in the root source file.
- When mixing C and Zig code, calling the canonical panic implementation
  across multiple .o files.

See also:

- [Panic Handler](#Panic-Handler)

### [\@popCount](#toc-popCount) [§](#popCount){.hdr} {#popCount}

    @popCount(operand: anytype) anytype

[`@TypeOf`]{.tok-builtin}`(operand)` must be an integer type.

`operand` may be an [integer](#Integers) or [vector](#Vectors).

Counts the number of bits set in an integer - \"population count\".

The return type is an unsigned integer or vector of unsigned integers
with the minimum number of bits that can represent the bit count of the
integer type.

See also:

- [\@ctz](#ctz)
- [\@clz](#clz)

### [\@prefetch](#toc-prefetch) [§](#prefetch){.hdr}

    @prefetch(ptr: anytype, comptime options: PrefetchOptions) void

This builtin tells the compiler to emit a prefetch instruction if
supported by the target CPU. If the target CPU does not support the
requested prefetch instruction, this builtin is a no-op. This function
has no effect on the behavior of the program, only on the performance
characteristics.

The `ptr` argument may be any pointer type and determines the memory
address to prefetch. This function does not dereference the pointer, it
is perfectly legal to pass a pointer to invalid memory to this function
and no Illegal Behavior will result.

`PrefetchOptions` can be found with
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).builtin.PrefetchOptions`.

### [\@ptrCast](#toc-ptrCast) [§](#ptrCast){.hdr} {#ptrCast}

    @ptrCast(value: anytype) anytype

Converts a pointer of one type to a pointer of another type. The return
type is the inferred result type.

[Optional Pointers](#Optional-Pointers) are allowed. Casting an optional
pointer which is [null](#null) to a non-optional pointer invokes
safety-checked [Illegal Behavior](#Illegal-Behavior).

[`@ptrCast`]{.tok-builtin} cannot be used for:

- Removing [`const`]{.tok-kw} qualifier, use [\@constCast](#constCast).
- Removing [`volatile`]{.tok-kw} qualifier, use
  [\@volatileCast](#volatileCast).
- Changing pointer address space, use [\@addrSpaceCast](#addrSpaceCast).
- Increasing pointer alignment, use [\@alignCast](#alignCast).
- Casting a non-slice pointer to a slice, use slicing syntax
  `ptr[start..end]`.

### [\@ptrFromInt](#toc-ptrFromInt) [§](#ptrFromInt){.hdr} {#ptrFromInt}

    @ptrFromInt(address: usize) anytype

Converts an integer to a [pointer](#Pointers). The return type is the
inferred result type. To convert the other way, use
[\@intFromPtr](#intFromPtr). Casting an address of 0 to a destination
type which in not [optional](#Optional-Pointers) and does not have the
[`allowzero`]{.tok-kw} attribute will result in a [Pointer Cast Invalid
Null](#Pointer-Cast-Invalid-Null) panic when runtime safety checks are
enabled.

If the destination pointer type does not allow address zero and
`address` is zero, this invokes safety-checked [Illegal
Behavior](#Illegal-Behavior).

### [\@rem](#toc-rem) [§](#rem){.hdr}

    @rem(numerator: T, denominator: T) T

Remainder division. For unsigned integers this is the same as
`numerator % denominator`. Caller guarantees
`denominator > `[`0`]{.tok-number}, otherwise the operation will result
in a [Remainder Division by Zero](#Remainder-Division-by-Zero) when
runtime safety checks are enabled.

- [`@rem`]{.tok-builtin}`(-`[`5`]{.tok-number}`, `[`3`]{.tok-number}`) == -`[`2`]{.tok-number}
- `(`[`@divTrunc`]{.tok-builtin}`(a, b) * b) + `[`@rem`]{.tok-builtin}`(a, b) == a`

For a function that returns an error code, see
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).math.rem`.

See also:

- [\@mod](#mod)

### [\@returnAddress](#toc-returnAddress) [§](#returnAddress){.hdr} {#returnAddress}

    @returnAddress() usize

This function returns the address of the next machine code instruction
that will be executed when the current function returns.

The implications of this are target-specific and not consistent across
all platforms.

This function is only valid within function scope. If the function gets
inlined into a calling function, the returned address will apply to the
calling function.

### [\@select](#toc-select) [§](#select){.hdr}

    @select(comptime T: type, pred: @Vector(len, bool), a: @Vector(len, T), b: @Vector(len, T)) @Vector(len, T)

Selects values element-wise from `a` or `b` based on `pred`. If
`pred[i]` is [`true`]{.tok-null}, the corresponding element in the
result will be `a[i]` and otherwise `b[i]`.

See also:

- [Vectors](#Vectors)

### [\@setEvalBranchQuota](#toc-setEvalBranchQuota) [§](#setEvalBranchQuota){.hdr} {#setEvalBranchQuota}

    @setEvalBranchQuota(comptime new_quota: u32) void

Increase the maximum number of backwards branches that compile-time code
execution can use before giving up and making a compile error.

If the `new_quota` is smaller than the default quota
([`1000`]{.tok-number}) or a previously explicitly set quota, it is
ignored.

Example:

<figure>
<pre><code>test &quot;foo&quot; {
    comptime {
        var i = 0;
        while (i &lt; 1001) : (i += 1) {}
    }
}</code></pre>
<figcaption>test_without_setEvalBranchQuota_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_without_setEvalBranchQuota_builtin.zig
doc/langref/test_without_setEvalBranchQuota_builtin.zig:4:9: error: evaluation exceeded 1000 backwards branches
        while (i &lt; 1001) : (i += 1) {}
        ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
doc/langref/test_without_setEvalBranchQuota_builtin.zig:4:9: note: use @setEvalBranchQuota() to raise the branch limit from 1000
</code></pre>
<figcaption>Shell</figcaption>
</figure>

Now we use [`@setEvalBranchQuota`]{.tok-builtin}:

<figure>
<pre><code>test &quot;foo&quot; {
    comptime {
        @setEvalBranchQuota(1001);
        var i = 0;
        while (i &lt; 1001) : (i += 1) {}
    }
}</code></pre>
<figcaption>test_setEvalBranchQuota_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_setEvalBranchQuota_builtin.zig
1/1 test_setEvalBranchQuota_builtin.test.foo...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [comptime](#comptime)

### [\@setFloatMode](#toc-setFloatMode) [§](#setFloatMode){.hdr} {#setFloatMode}

    @setFloatMode(comptime mode: FloatMode) void

Changes the current scope\'s rules about how floating point operations
are defined.

- `Strict` (default) - Floating point operations follow strict IEEE
  compliance.
- `Optimized` - Floating point operations may do all of the following:
  - Assume the arguments and result are not NaN. Optimizations are
    required to retain legal behavior over NaNs, but the value of the
    result is undefined.
  - Assume the arguments and result are not +/-Inf. Optimizations are
    required to retain legal behavior over +/-Inf, but the value of the
    result is undefined.
  - Treat the sign of a zero argument or result as insignificant.
  - Use the reciprocal of an argument rather than perform division.
  - Perform floating-point contraction (e.g. fusing a multiply followed
    by an addition into a fused multiply-add).
  - Perform algebraically equivalent transformations that may change
    results in floating point (e.g. reassociate).

  This is equivalent to `-ffast-math` in GCC.

The floating point mode is inherited by child scopes, and can be
overridden in any scope. You can set the floating point mode in a struct
or module scope by using a comptime block.

`FloatMode` can be found with
[`@import`]{.tok-builtin}`(`[`"std"`]{.tok-str}`).builtin.FloatMode`.

See also:

- [Floating Point Operations](#Floating-Point-Operations)

### [\@setRuntimeSafety](#toc-setRuntimeSafety) [§](#setRuntimeSafety){.hdr} {#setRuntimeSafety}

    @setRuntimeSafety(comptime safety_on: bool) void

Sets whether runtime safety checks are enabled for the scope that
contains the function call.

<figure>
<pre><code>test &quot;@setRuntimeSafety&quot; {
    // The builtin applies to the scope that it is called in. So here, integer overflow
    // will not be caught in ReleaseFast and ReleaseSmall modes:
    // var x: u8 = 255;
    // x += 1; // Unchecked Illegal Behavior in ReleaseFast/ReleaseSmall modes.
    {
        // However this block has safety enabled, so safety checks happen here,
        // even in ReleaseFast and ReleaseSmall modes.
        @setRuntimeSafety(true);
        var x: u8 = 255;
        x += 1;

        {
            // The value can be overridden at any scope. So here integer overflow
            // would not be caught in any build mode.
            @setRuntimeSafety(false);
            // var x: u8 = 255;
            // x += 1; // Unchecked Illegal Behavior in all build modes.
        }
    }
}</code></pre>
<figcaption>test_setRuntimeSafety_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_setRuntimeSafety_builtin.zig -OReleaseFast
1/1 test_setRuntimeSafety_builtin.test.@setRuntimeSafety...thread 222792 panic: integer overflow
/home/andy/src/zig/doc/langref/test_setRuntimeSafety_builtin.zig:11:11: 0x100b1f8 in test.@setRuntimeSafety (test)
        x += 1;
          ^
/home/andy/src/zig/lib/compiler/test_runner.zig:214:25: 0x1033308 in main (test)
        if (test_fn.func()) |_| {
                        ^
/home/andy/src/zig/lib/std/start.zig:647:22: 0x10319ad in posixCallMainAndExit (test)
            root.main();
                     ^
/home/andy/src/zig/lib/std/start.zig:271:5: 0x10314cd in _start (test)
    asm volatile (switch (native_arch) {
    ^
???:?:?: 0x0 in ??? (???)
error: the following test command crashed:
/home/andy/src/zig/.zig-cache/o/fb1876bcfd12bd21ad987d48fd800b31/test --seed=0x3a9b5544</code></pre>
<figcaption>Shell</figcaption>
</figure>

Note: it is [planned](https://github.com/ziglang/zig/issues/978) to
replace [`@setRuntimeSafety`]{.tok-builtin} with `@optimizeFor`

### [\@shlExact](#toc-shlExact) [§](#shlExact){.hdr} {#shlExact}

    @shlExact(value: T, shift_amt: Log2T) T

Performs the left shift operation (`<<`). For unsigned integers, the
result is [undefined](#undefined) if any 1 bits are shifted out. For
signed integers, the result is [undefined](#undefined) if any bits that
disagree with the resultant sign bit are shifted out.

The type of `shift_amt` is an unsigned integer with
`log2(`[`@typeInfo`]{.tok-builtin}`(T).int.bits)` bits. This is because
`shift_amt >= `[`@typeInfo`]{.tok-builtin}`(T).int.bits` triggers
safety-checked [Illegal Behavior](#Illegal-Behavior).

[`comptime_int`]{.tok-type} is modeled as an integer with an infinite
number of bits, meaning that in such case, [`@shlExact`]{.tok-builtin}
always produces a result and cannot produce a compile error.

See also:

- [\@shrExact](#shrExact)
- [\@shlWithOverflow](#shlWithOverflow)

### [\@shlWithOverflow](#toc-shlWithOverflow) [§](#shlWithOverflow){.hdr} {#shlWithOverflow}

    @shlWithOverflow(a: anytype, shift_amt: Log2T) struct { @TypeOf(a), u1 }

Performs `a << b` and returns a tuple with the result and a possible
overflow bit.

The type of `shift_amt` is an unsigned integer with
`log2(`[`@typeInfo`]{.tok-builtin}`(`[`@TypeOf`]{.tok-builtin}`(a)).int.bits)`
bits. This is because
`shift_amt >= `[`@typeInfo`]{.tok-builtin}`(`[`@TypeOf`]{.tok-builtin}`(a)).int.bits`
triggers safety-checked [Illegal Behavior](#Illegal-Behavior).

See also:

- [\@shlExact](#shlExact)
- [\@shrExact](#shrExact)

### [\@shrExact](#toc-shrExact) [§](#shrExact){.hdr} {#shrExact}

    @shrExact(value: T, shift_amt: Log2T) T

Performs the right shift operation (`>>`). Caller guarantees that the
shift will not shift any 1 bits out.

The type of `shift_amt` is an unsigned integer with
`log2(`[`@typeInfo`]{.tok-builtin}`(T).int.bits)` bits. This is because
`shift_amt >= `[`@typeInfo`]{.tok-builtin}`(T).int.bits` triggers
safety-checked [Illegal Behavior](#Illegal-Behavior).

See also:

- [\@shlExact](#shlExact)
- [\@shlWithOverflow](#shlWithOverflow)

### [\@shuffle](#toc-shuffle) [§](#shuffle){.hdr}

    @shuffle(comptime E: type, a: @Vector(a_len, E), b: @Vector(b_len, E), comptime mask: @Vector(mask_len, i32)) @Vector(mask_len, E)

Constructs a new [vector](#Vectors) by selecting elements from `a` and
`b` based on `mask`.

Each element in `mask` selects an element from either `a` or `b`.
Positive numbers select from `a` starting at 0. Negative values select
from `b`, starting at `-`[`1`]{.tok-number} and going down. It is
recommended to use the `~` operator for indexes from `b` so that both
indexes can start from [`0`]{.tok-number} (i.e.
`~`[`@as`]{.tok-builtin}`(`[`i32`]{.tok-type}`, `[`0`]{.tok-number}`)`
is `-`[`1`]{.tok-number}).

For each element of `mask`, if it or the selected value from `a` or `b`
is [`undefined`]{.tok-null}, then the resulting element is
[`undefined`]{.tok-null}.

`a_len` and `b_len` may differ in length. Out-of-bounds element indexes
in `mask` result in compile errors.

If `a` or `b` is [`undefined`]{.tok-null}, it is equivalent to a vector
of all [`undefined`]{.tok-null} with the same length as the other
vector. If both vectors are [`undefined`]{.tok-null},
[`@shuffle`]{.tok-builtin} returns a vector with all elements
[`undefined`]{.tok-null}.

`E` must be an [integer](#Integers), [float](#Floats),
[pointer](#Pointers), or [`bool`]{.tok-type}. The mask may be any vector
length, and its length determines the result length.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;vector @shuffle&quot; {
    const a = @Vector(7, u8){ &#39;o&#39;, &#39;l&#39;, &#39;h&#39;, &#39;e&#39;, &#39;r&#39;, &#39;z&#39;, &#39;w&#39; };
    const b = @Vector(4, u8){ &#39;w&#39;, &#39;d&#39;, &#39;!&#39;, &#39;x&#39; };

    // To shuffle within a single vector, pass undefined as the second argument.
    // Notice that we can re-order, duplicate, or omit elements of the input vector
    const mask1 = @Vector(5, i32){ 2, 3, 1, 1, 0 };
    const res1: @Vector(5, u8) = @shuffle(u8, a, undefined, mask1);
    try expect(std.mem.eql(u8, &amp;@as([5]u8, res1), &quot;hello&quot;));

    // Combining two vectors
    const mask2 = @Vector(6, i32){ -1, 0, 4, 1, -2, -3 };
    const res2: @Vector(6, u8) = @shuffle(u8, a, b, mask2);
    try expect(std.mem.eql(u8, &amp;@as([6]u8, res2), &quot;world!&quot;));
}</code></pre>
<figcaption>test_shuffle_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_shuffle_builtin.zig
1/1 test_shuffle_builtin.test.vector @shuffle...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Vectors](#Vectors)

### [\@sizeOf](#toc-sizeOf) [§](#sizeOf){.hdr} {#sizeOf}

    @sizeOf(comptime T: type) comptime_int

This function returns the number of bytes it takes to store `T` in
memory. The result is a target-specific compile time constant.

This size may contain padding bytes. If there were two consecutive T in
memory, the padding would be the offset in bytes between element at
index 0 and the element at index 1. For [integer](#Integers), consider
whether you want to use [`@sizeOf`]{.tok-builtin}`(T)` or
[`@typeInfo`]{.tok-builtin}`(T).int.bits`.

This function measures the size at runtime. For types that are
disallowed at runtime, such as [`comptime_int`]{.tok-type} and
[`type`]{.tok-type}, the result is [`0`]{.tok-number}.

See also:

- [\@bitSizeOf](#bitSizeOf)
- [\@typeInfo](#typeInfo)

### [\@splat](#toc-splat) [§](#splat){.hdr}

    @splat(scalar: anytype) anytype

Produces a vector where each element is the value `scalar`. The return
type and thus the length of the vector is inferred.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;vector @splat&quot; {
    const scalar: u32 = 5;
    const result: @Vector(4, u32) = @splat(scalar);
    try expect(std.mem.eql(u32, &amp;@as([4]u32, result), &amp;[_]u32{ 5, 5, 5, 5 }));
}</code></pre>
<figcaption>test_splat_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_splat_builtin.zig
1/1 test_splat_builtin.test.vector @splat...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

`scalar` must be an [integer](#Integers), [bool](#Primitive-Types),
[float](#Floats), or [pointer](#Pointers).

See also:

- [Vectors](#Vectors)
- [\@shuffle](#shuffle)

### [\@reduce](#toc-reduce) [§](#reduce){.hdr}

    @reduce(comptime op: std.builtin.ReduceOp, value: anytype) E

Transforms a [vector](#Vectors) into a scalar value (of type `E`) by
performing a sequential horizontal reduction of its elements using the
specified operator `op`.

Not every operator is available for every vector element type:

- Every operator is available for [integer](#Integers) vectors.
- `.And`, `.Or`, `.Xor` are additionally available for
  [`bool`]{.tok-type} vectors,
- `.Min`, `.Max`, `.Add`, `.Mul` are additionally available for
  [floating point](#Floats) vectors,

Note that `.Add` and `.Mul` reductions on integral types are wrapping;
when applied on floating point types the operation associativity is
preserved, unless the float mode is set to `Optimized`.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;vector @reduce&quot; {
    const V = @Vector(4, i32);
    const value = V{ 1, -1, 1, -1 };
    const result = value &gt; @as(V, @splat(0));
    // result is { true, false, true, false };
    try comptime expect(@TypeOf(result) == @Vector(4, bool));
    const is_all_true = @reduce(.And, result);
    try comptime expect(@TypeOf(is_all_true) == bool);
    try expect(is_all_true == false);
}</code></pre>
<figcaption>test_reduce_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_reduce_builtin.zig
1/1 test_reduce_builtin.test.vector @reduce...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

See also:

- [Vectors](#Vectors)
- [\@setFloatMode](#setFloatMode)

### [\@src](#toc-src) [§](#src){.hdr}

    @src() std.builtin.SourceLocation

Returns a `SourceLocation` struct representing the function\'s name and
location in the source code. This must be called in a function.

<figure>
<pre><code>const std = @import(&quot;std&quot;);
const expect = std.testing.expect;

test &quot;@src&quot; {
    try doTheTest();
}

fn doTheTest() !void {
    const src = @src();

    try expect(src.line == 9);
    try expect(src.column == 17);
    try expect(std.mem.endsWith(u8, src.fn_name, &quot;doTheTest&quot;));
    try expect(std.mem.endsWith(u8, src.file, &quot;test_src_builtin.zig&quot;));
}</code></pre>
<figcaption>test_src_builtin.zig</figcaption>
</figure>

<figure>
<pre><code>$ zig test test_src_builtin.zig
1/1 test_src_builtin.test.@src...OK
All 1 tests passed.</code></pre>
<figcaption>Shell</figcaption>
</figure>

### [\@sqrt](#toc-sqrt) [§](#sqrt){.hdr}

    @sqrt(value: anytype) @TypeOf(value)

Performs the square root of a floating point number. Uses a dedicated
hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@sin](#toc-sin) [§](#sin){.hdr}

    @sin(value: anytype) @TypeOf(value)

Sine trigonometric function on a floating point number in radians. Uses
a dedicated hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@cos](#toc-cos) [§](#cos){.hdr}

    @cos(value: anytype) @TypeOf(value)

Cosine trigonometric function on a floating point number in radians.
Uses a dedicated hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@tan](#toc-tan) [§](#tan){.hdr}

    @tan(value: anytype) @TypeOf(value)

Tangent trigonometric function on a floating point number in radians.
Uses a dedicated hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@exp](#toc-exp) [§](#exp){.hdr}

    @exp(value: anytype) @TypeOf(value)

Base-e exponential function on a floating point number. Uses a dedicated
hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@exp2](#toc-exp2) [§](#exp2){.hdr}

    @exp2(value: anytype) @TypeOf(value)

Base-2 exponential function on a floating point number. Uses a dedicated
hardware instruction when available.

Supports [Floats](#Floats) and [Vectors](#Vectors) of floats.

### [\@log](#toc-log) [§](#log){.hdr}

    @log(value: anytype) @TypeOf(value)

Returns the natural logarithm of a floating point number. Uses a
dedicated ```
