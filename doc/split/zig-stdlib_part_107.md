```
 so instead of rotating we can just block swap B to where it belongs
                                    blockSwap(T, items, B_split, blockA.start + block_size - B_remaining, B_remaining);
                                } else {
                                    // we are unable to use the 'buffer2' trick to speed up the rotation operation since buffer2 doesn't exist, so perform a normal rotation
                                    mem.rotate(T, items[B_split .. blockA.start + block_size], blockA.start - B_split);
                                }

                                // update the range for the remaining A blocks, and the range remaining from the B block after it was split
                                lastA = Range.init(blockA.start - B_remaining, blockA.start - B_remaining + block_size);
                                lastB = Range.init(lastA.end, lastA.end + B_remaining);

                                // if there are no more A blocks remaining, this step is finished!
                                blockA.start += block_size;
                                if (blockA.length() == 0) break;
                            } else if (blockB.length() < block_size) {
                                // move the last B block, which is unevenly sized, to before the remaining A blocks, by using a rotation
                                // the cache is disabled here since it might contain the contents of the previous A block
                                mem.rotate(T, items[blockA.start..blockB.end], blockB.start - blockA.start);

                                lastB = Range.init(blockA.start, blockA.start + blockB.length());
                                blockA.start += blockB.length();
                                blockA.end += blockB.length();
                                blockB.end = blockB.start;
                            } else {
                                // roll the leftmost A block to the end by swapping it with the next B block
                                blockSwap(T, items, blockA.start, blockB.start, block_size);
                                lastB = Range.init(blockA.start, blockA.start + block_size);

                                blockA.start += block_size;
                                blockA.end += block_size;
                                blockB.start += block_size;

                                if (blockB.end > B.end - block_size) {
                                    blockB.end = B.end;
                                } else {
                                    blockB.end += block_size;
                                }
                            }
                        }
                    }

                    // merge the last A block with the remaining B values
                    if (lastA.length() <= cache.len) {
                        mergeExternal(T, items, lastA, Range.init(lastA.end, B.end), cache[0..], context, lessThan);
                    } else if (buffer2.length() > 0) {
                        mergeInternal(T, items, lastA, Range.init(lastA.end, B.end), buffer2, context, lessThan);
                    } else {
                        mergeInPlace(T, items, lastA, Range.init(lastA.end, B.end), context, lessThan);
                    }
                }
            }

            // when we're finished with this merge step we should have the one
            // or two internal buffers left over, where the second buffer is all jumbled up
            // insertion sort the second buffer, then redistribute the buffers
            // back into the items using the opposite process used for creating the buffer

            // while an unstable sort like quicksort could be applied here, in benchmarks
            // it was consistently slightly slower than a simple insertion sort,
            // even for tens of millions of items. this may be because insertion
            // sort is quite fast when the data is already somewhat sorted, like it is here
            sort.insertion(T, items[buffer2.start..buffer2.end], context, lessThan);

            pull_index = 0;
            while (pull_index < 2) : (pull_index += 1) {
                var unique = pull[pull_index].count * 2;
                if (pull[pull_index].from > pull[pull_index].to) {
                    // the values were pulled out to the left, so redistribute them back to the right
                    var buffer = Range.init(pull[pull_index].range.start, pull[pull_index].range.start + pull[pull_index].count);
                    while (buffer.length() > 0) {
                        index = findFirstForward(T, items, items[buffer.start], Range.init(buffer.end, pull[pull_index].range.end), unique, context, lessThan);
                        const amount = index - buffer.end;
                        mem.rotate(T, items[buffer.start..index], buffer.length());
                        buffer.start += (amount + 1);
                        buffer.end += amount;
                        unique -= 2;
                    }
                } else if (pull[pull_index].from < pull[pull_index].to) {
                    // the values were pulled out to the right, so redistribute them back to the left
                    var buffer = Range.init(pull[pull_index].range.end - pull[pull_index].count, pull[pull_index].range.end);
                    while (buffer.length() > 0) {
                        index = findLastBackward(T, items, items[buffer.end - 1], Range.init(pull[pull_index].range.start, buffer.start), unique, context, lessThan);
                        const amount = buffer.start - index;
                        mem.rotate(T, items[index..buffer.end], amount);
                        buffer.start -= amount;
                        buffer.end -= (amount + 1);
                        unique -= 2;
                    }
                }
            }
        }

        // double the size of each A and B subarray that will be merged in the next level
        if (!iterator.nextLevel()) break;
    }
}
// merge operation without a buffer
fn mergeInPlace(
    comptime T: type,
    items: []T,
    A_arg: Range,
    B_arg: Range,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    if (A_arg.length() == 0 or B_arg.length() == 0) return;

    // this just repeatedly binary searches into B and rotates A into position.
    // the paper suggests using the 'rotation-based Hwang and Lin algorithm' here,
    // but I decided to stick with this because it had better situational performance
    //
    // (Hwang and Lin is designed for merging subarrays of very different sizes,
    // but WikiSort almost always uses subarrays that are roughly the same size)
    //
    // normally this is incredibly suboptimal, but this function is only called
    // when none of the A or B blocks in any subarray contained 2√A unique values,
    // which places a hard limit on the number of times this will ACTUALLY need
    // to binary search and rotate.
    //
    // according to my analysis the worst case is √A rotations performed on √A items
    // once the constant factors are removed, which ends up being O(n)
    //
    // again, this is NOT a general-purpose solution – it only works well in this case!
    // kind of like how the O(n^2) insertion sort is used in some places

    var A = A_arg;
    var B = B_arg;

    while (true) {
        // find the first place in B where the first item in A needs to be inserted
        const mid = binaryFirst(T, items, items[A.start], B, context, lessThan);

        // rotate A into place
        const amount = mid - A.end;
        mem.rotate(T, items[A.start..mid], A.length());
        if (B.end == mid) break;

        // calculate the new A and B ranges
        B.start = mid;
        A = Range.init(A.start + amount, B.start);
        A.start = binaryLast(T, items, items[A.start], A, context, lessThan);
        if (A.length() == 0) break;
    }
}

// merge operation using an internal buffer
fn mergeInternal(
    comptime T: type,
    items: []T,
    A: Range,
    B: Range,
    buffer: Range,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    // whenever we find a value to add to the final array, swap it with the value that's already in that spot
    // when this algorithm is finished, 'buffer' will contain its original contents, but in a different order
    var A_count: usize = 0;
    var B_count: usize = 0;
    var insert: usize = 0;

    if (B.length() > 0 and A.length() > 0) {
        while (true) {
            if (!lessThan(context, items[B.start + B_count], items[buffer.start + A_count])) {
                mem.swap(T, &items[A.start + insert], &items[buffer.start + A_count]);
                A_count += 1;
                insert += 1;
                if (A_count >= A.length()) break;
            } else {
                mem.swap(T, &items[A.start + insert], &items[B.start + B_count]);
                B_count += 1;
                insert += 1;
                if (B_count >= B.length()) break;
            }
        }
    }

    // swap the remainder of A into the final array
    blockSwap(T, items, buffer.start + A_count, A.start + insert, A.length() - A_count);
}

fn blockSwap(comptime T: type, items: []T, start1: usize, start2: usize, block_size: usize) void {
    var index: usize = 0;
    while (index < block_size) : (index += 1) {
        mem.swap(T, &items[start1 + index], &items[start2 + index]);
    }
}

// combine a linear search with a binary search to reduce the number of comparisons in situations
// where have some idea as to how many unique values there are and where the next value might be
fn findFirstForward(
    comptime T: type,
    items: []T,
    value: T,
    range: Range,
    unique: usize,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) usize {
    if (range.length() == 0) return range.start;
    const skip = @max(range.length() / unique, @as(usize, 1));

    var index = range.start + skip;
    while (lessThan(context, items[index - 1], value)) : (index += skip) {
        if (index >= range.end - skip) {
            return binaryFirst(T, items, value, Range.init(index, range.end), context, lessThan);
        }
    }

    return binaryFirst(T, items, value, Range.init(index - skip, index), context, lessThan);
}

fn findFirstBackward(
    comptime T: type,
    items: []T,
    value: T,
    range: Range,
    unique: usize,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) usize {
    if (range.length() == 0) return range.start;
    const skip = @max(range.length() / unique, @as(usize, 1));

    var index = range.end - skip;
    while (index > range.start and !lessThan(context, items[index - 1], value)) : (index -= skip) {
        if (index < range.start + skip) {
            return binaryFirst(T, items, value, Range.init(range.start, index), context, lessThan);
        }
    }

    return binaryFirst(T, items, value, Range.init(index, index + skip), context, lessThan);
}

fn findLastForward(
    comptime T: type,
    items: []T,
    value: T,
    range: Range,
    unique: usize,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) usize {
    if (range.length() == 0) return range.start;
    const skip = @max(range.length() / unique, @as(usize, 1));

    var index = range.start + skip;
    while (!lessThan(context, value, items[index - 1])) : (index += skip) {
        if (index >= range.end - skip) {
            return binaryLast(T, items, value, Range.init(index, range.end), context, lessThan);
        }
    }

    return binaryLast(T, items, value, Range.init(index - skip, index), context, lessThan);
}

fn findLastBackward(
    comptime T: type,
    items: []T,
    value: T,
    range: Range,
    unique: usize,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) usize {
    if (range.length() == 0) return range.start;
    const skip = @max(range.length() / unique, @as(usize, 1));

    var index = range.end - skip;
    while (index > range.start and lessThan(context, value, items[index - 1])) : (index -= skip) {
        if (index < range.start + skip) {
            return binaryLast(T, items, value, Range.init(range.start, index), context, lessThan);
        }
    }

    return binaryLast(T, items, value, Range.init(index, index + skip), context, lessThan);
}

fn binaryFirst(
    comptime T: type,
    items: []T,
    value: T,
    range: Range,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) usize {
    var curr = range.start;
    var size = range.length();
    if (range.start >= range.end) return range.end;
    while (size > 0) {
        const offset = size % 2;

        size /= 2;
        const mid_item = items[curr + size];
        if (lessThan(context, mid_item, value)) {
            curr += size + offset;
        }
    }
    return curr;
}

fn binaryLast(
    comptime T: type,
    items: []T,
    value: T,
    range: Range,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) usize {
    var curr = range.start;
    var size = range.length();
    if (range.start >= range.end) return range.end;
    while (size > 0) {
        const offset = size % 2;

        size /= 2;
        const mid_item = items[curr + size];
        if (!lessThan(context, value, mid_item)) {
            curr += size + offset;
        }
    }
    return curr;
}

fn mergeInto(
    comptime T: type,
    from: []T,
    A: Range,
    B: Range,
    into: []T,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    var A_index: usize = A.start;
    var B_index: usize = B.start;
    const A_last = A.end;
    const B_last = B.end;
    var insert_index: usize = 0;

    while (true) {
        if (!lessThan(context, from[B_index], from[A_index])) {
            into[insert_index] = from[A_index];
            A_index += 1;
            insert_index += 1;
            if (A_index == A_last) {
                // copy the remainder of B into the final array
                const from_b = from[B_index..B_last];
                @memcpy(into[insert_index..][0..from_b.len], from_b);
                break;
            }
        } else {
            into[insert_index] = from[B_index];
            B_index += 1;
            insert_index += 1;
            if (B_index == B_last) {
                // copy the remainder of A into the final array
                const from_a = from[A_index..A_last];
                @memcpy(into[insert_index..][0..from_a.len], from_a);
                break;
            }
        }
    }
}

fn mergeExternal(
    comptime T: type,
    items: []T,
    A: Range,
    B: Range,
    cache: []T,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    // A fits into the cache, so use that instead of the internal buffer
    var A_index: usize = 0;
    var B_index: usize = B.start;
    var insert_index: usize = A.start;
    const A_last = A.length();
    const B_last = B.end;

    if (B.length() > 0 and A.length() > 0) {
        while (true) {
            if (!lessThan(context, items[B_index], cache[A_index])) {
                items[insert_index] = cache[A_index];
                A_index += 1;
                insert_index += 1;
                if (A_index == A_last) break;
            } else {
                items[insert_index] = items[B_index];
                B_index += 1;
                insert_index += 1;
                if (B_index == B_last) break;
            }
        }
    }

    // copy the remainder of A into the final array
    const cache_a = cache[A_index..A_last];
    @memcpy(items[insert_index..][0..cache_a.len], cache_a);
}

fn swap(
    comptime T: type,
    items: []T,
    order: *[8]u8,
    x: usize,
    y: usize,
    context: anytype,
    comptime lessThan: fn (@TypeOf(context), lhs: T, rhs: T) bool,
) void {
    if (lessThan(context, items[y], items[x]) or ((order.*)[x] > (order.*)[y] and !lessThan(context, items[x], items[y]))) {
        mem.swap(T, &items[x], &items[y]);
        mem.swap(u8, &(order.*)[x], &(order.*)[y]);
    }
}
const std = @import("../std.zig");
const sort = std.sort;
const mem = std.mem;
const math = std.math;
const testing = std.testing;

/// Unstable in-place sort. n best case, n*log(n) worst case and average case.
/// log(n) memory (no allocator required).
///
/// Sorts in ascending order with respect to the given `lessThan` function.
pub fn pdq(
    comptime T: type,
    items: []T,
    context: anytype,
    comptime lessThanFn: fn (context: @TypeOf(context), lhs: T, rhs: T) bool,
) void {
    const Context = struct {
        items: []T,
        sub_ctx: @TypeOf(context),

        pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
            return lessThanFn(ctx.sub_ctx, ctx.items[a], ctx.items[b]);
        }

        pub fn swap(ctx: @This(), a: usize, b: usize) void {
            return mem.swap(T, &ctx.items[a], &ctx.items[b]);
        }
    };
    pdqContext(0, items.len, Context{ .items = items, .sub_ctx = context });
}

const Hint = enum {
    increasing,
    decreasing,
    unknown,
};

/// Unstable in-place sort. O(n) best case, O(n*log(n)) worst case and average case.
/// O(log(n)) memory (no allocator required).
/// `context` must have methods `swap` and `lessThan`,
/// which each take 2 `usize` parameters indicating the index of an item.
/// Sorts in ascending order with respect to `lessThan`.
pub fn pdqContext(a: usize, b: usize, context: anytype) void {
    // slices of up to this length get sorted using insertion sort.
    const max_insertion = 24;
    // number of allowed imbalanced partitions before switching to heap sort.
    const max_limit = std.math.floorPowerOfTwo(usize, b - a) + 1;

    // set upper bound on stack memory usage.
    const Range = struct { a: usize, b: usize, limit: usize };
    const stack_size = math.log2(math.maxInt(usize) + 1);
    var stack: [stack_size]Range = undefined;
    var range = Range{ .a = a, .b = b, .limit = max_limit };
    var top: usize = 0;

    while (true) {
        var was_balanced = true;
        var was_partitioned = true;

        while (true) {
            const len = range.b - range.a;

            // very short slices get sorted using insertion sort.
            if (len <= max_insertion) {
                break sort.insertionContext(range.a, range.b, context);
            }

            // if too many bad pivot choices were made, simply fall back to heapsort in order to
            // guarantee O(n*log(n)) worst-case.
            if (range.limit == 0) {
                break sort.heapContext(range.a, range.b, context);
            }

            // if the last partitioning was imbalanced, try breaking patterns in the slice by shuffling
            // some elements around. Hopefully we'll choose a better pivot this time.
            if (!was_balanced) {
                breakPatterns(range.a, range.b, context);
                range.limit -= 1;
            }

            // choose a pivot and try guessing whether the slice is already sorted.
            var pivot: usize = 0;
            var hint = chosePivot(range.a, range.b, &pivot, context);

            if (hint == .decreasing) {
                // The maximum number of swaps was performed, so items are likely
                // in reverse order. Reverse it to make sorting faster.
                reverseRange(range.a, range.b, context);
                pivot = (range.b - 1) - (pivot - range.a);
                hint = .increasing;
            }

            // if the last partitioning was decently balanced and didn't shuffle elements, and if pivot
            // selection predicts the slice is likely already sorted...
            if (was_balanced and was_partitioned and hint == .increasing) {
                // try identifying several out-of-order elements and shifting them to correct
                // positions. If the slice ends up being completely sorted, we're done.
                if (partialInsertionSort(range.a, range.b, context)) break;
            }

            // if the chosen pivot is equal to the predecessor, then it's the smallest element in the
            // slice. Partition the slice into elements equal to and elements greater than the pivot.
            // This case is usually hit when the slice contains many duplicate elements.
            if (range.a > a and !context.lessThan(range.a - 1, pivot)) {
                range.a = partitionEqual(range.a, range.b, pivot, context);
                continue;
            }

            // partition the slice.
            var mid = pivot;
            was_partitioned = partition(range.a, range.b, &mid, context);

            const left_len = mid - range.a;
            const right_len = range.b - mid;
            const balanced_threshold = len / 8;
            if (left_len < right_len) {
                was_balanced = left_len >= balanced_threshold;
                stack[top] = .{ .a = range.a, .b = mid, .limit = range.limit };
                top += 1;
                range.a = mid + 1;
            } else {
                was_balanced = right_len >= balanced_threshold;
                stack[top] = .{ .a = mid + 1, .b = range.b, .limit = range.limit };
                top += 1;
                range.b = mid;
            }
        }

        top = math.sub(usize, top, 1) catch break;
        range = stack[top];
    }
}

/// partitions `items[a..b]` into elements smaller than `items[pivot]`,
/// followed by elements greater than or equal to `items[pivot]`.
///
/// sets the new pivot.
/// returns `true` if already partitioned.
fn partition(a: usize, b: usize, pivot: *usize, context: anytype) bool {
    // move pivot to the first place
    context.swap(a, pivot.*);

    var i = a + 1;
    var j = b - 1;

    while (i <= j and context.lessThan(i, a)) i += 1;
    while (i <= j and !context.lessThan(j, a)) j -= 1;

    // check if items are already partitioned (no item to swap)
    if (i > j) {
        // put pivot back to the middle
        context.swap(j, a);
        pivot.* = j;
        return true;
    }

    context.swap(i, j);
    i += 1;
    j -= 1;

    while (true) {
        while (i <= j and context.lessThan(i, a)) i += 1;
        while (i <= j and !context.lessThan(j, a)) j -= 1;
        if (i > j) break;

        context.swap(i, j);
        i += 1;
        j -= 1;
    }

    // TODO: Enable the BlockQuicksort optimization

    context.swap(j, a);
    pivot.* = j;
    return false;
}

/// partitions items into elements equal to `items[pivot]`
/// followed by elements greater than `items[pivot]`.
///
/// it assumed that `items[a..b]` does not contain elements smaller than the `items[pivot]`.
fn partitionEqual(a: usize, b: usize, pivot: usize, context: anytype) usize {
    // move pivot to the first place
    context.swap(a, pivot);

    var i = a + 1;
    var j = b - 1;

    while (true) {
        while (i <= j and !context.lessThan(a, i)) i += 1;
        while (i <= j and context.lessThan(a, j)) j -= 1;
        if (i > j) break;

        context.swap(i, j);
        i += 1;
        j -= 1;
    }

    return i;
}

/// partially sorts a slice by shifting several out-of-order elements around.
///
/// returns `true` if the slice is sorted at the end. This function is `O(n)` worst-case.
fn partialInsertionSort(a: usize, b: usize, context: anytype) bool {
    @branchHint(.cold);

    // maximum number of adjacent out-of-order pairs that will get shifted
    const max_steps = 5;
    // if the slice is shorter than this, don't shift any elements
    const shortest_shifting = 50;

    var i = a + 1;
    for (0..max_steps) |_| {
        // find the next pair of adjacent out-of-order elements.
        while (i < b and !context.lessThan(i, i - 1)) i += 1;

        // are we done?
        if (i == b) return true;

        // don't shift elements on short arrays, that has a performance cost.
        if (b - a < shortest_shifting) return false;

        // swap the found pair of elements. This puts them in correct order.
        context.swap(i, i - 1);

        // shift the smaller element to the left.
        if (i - a >= 2) {
            var j = i - 1;
            while (j >= 1) : (j -= 1) {
                if (!context.lessThan(j, j - 1)) break;
                context.swap(j, j - 1);
            }
        }

        // shift the greater element to the right.
        if (b - i >= 2) {
            var j = i + 1;
            while (j < b) : (j += 1) {
                if (!context.lessThan(j, j - 1)) break;
                context.swap(j, j - 1);
            }
        }
    }

    return false;
}

fn breakPatterns(a: usize, b: usize, context: anytype) void {
    @branchHint(.cold);

    const len = b - a;
    if (len < 8) return;

    var rand = @as(u64, @intCast(len));
    const modulus = math.ceilPowerOfTwoAssert(u64, len);

    var i = a + (len / 4) * 2 - 1;
    while (i <= a + (len / 4) * 2 + 1) : (i += 1) {
        // xorshift64
        rand ^= rand << 13;
        rand ^= rand >> 7;
        rand ^= rand << 17;

        var other = @as(usize, @intCast(rand & (modulus - 1)));
        if (other >= len) other -= len;
        context.swap(i, a + other);
    }
}

/// chooses a pivot in `items[a..b]`.
/// swaps likely_sorted when `items[a..b]` seems to be already sorted.
fn chosePivot(a: usize, b: usize, pivot: *usize, context: anytype) Hint {
    // minimum length for using the Tukey's ninther method
    const shortest_ninther = 50;
    // max_swaps is the maximum number of swaps allowed in this function
    const max_swaps = 4 * 3;

    const len = b - a;
    const i = a + len / 4 * 1;
    const j = a + len / 4 * 2;
    const k = a + len / 4 * 3;
    var swaps: usize = 0;

    if (len >= 8) {
        if (len >= shortest_ninther) {
            // find medians in the neighborhoods of `i`, `j` and `k`
            sort3(i - 1, i, i + 1, &swaps, context);
            sort3(j - 1, j, j + 1, &swaps, context);
            sort3(k - 1, k, k + 1, &swaps, context);
        }

        // find the median among `i`, `j` and `k` and stores it in `j`
        sort3(i, j, k, &swaps, context);
    }

    pivot.* = j;
    return switch (swaps) {
        0 => .increasing,
        max_swaps => .decreasing,
        else => .unknown,
    };
}

fn sort3(a: usize, b: usize, c: usize, swaps: *usize, context: anytype) void {
    if (context.lessThan(b, a)) {
        swaps.* += 1;
        context.swap(b, a);
    }

    if (context.lessThan(c, b)) {
        swaps.* += 1;
        context.swap(c, b);
    }

    if (context.lessThan(b, a)) {
        swaps.* += 1;
        context.swap(b, a);
    }
}

fn reverseRange(a: usize, b: usize, context: anytype) void {
    var i = a;
    var j = b - 1;
    while (i < j) {
        context.swap(i, j);
        i += 1;
        j -= 1;
    }
}
// This file is included in the compilation unit when exporting an executable.

const root = @import("root");
const std = @import("std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const uefi = std.os.uefi;
const elf = std.elf;
const native_arch = builtin.cpu.arch;
const native_os = builtin.os.tag;

const start_sym_name = if (native_arch.isMIPS()) "__start" else "_start";

// The self-hosted compiler is not fully capable of handling all of this start.zig file.
// Until then, we have simplified logic here for self-hosted. TODO remove this once
// self-hosted is capable enough to handle all of the real start.zig logic.
pub const simplified_logic =
    builtin.zig_backend == .stage2_x86 or
    builtin.zig_backend == .stage2_aarch64 or
    builtin.zig_backend == .stage2_arm or
    builtin.zig_backend == .stage2_sparc64 or
    builtin.zig_backend == .stage2_spirv64;

comptime {
    // No matter what, we import the root file, so that any export, test, comptime
    // decls there get run.
    _ = root;

    if (simplified_logic) {
        if (builtin.output_mode == .Exe) {
            if ((builtin.link_libc or builtin.object_format == .c) and @hasDecl(root, "main")) {
                if (!@typeInfo(@TypeOf(root.main)).@"fn".calling_convention.eql(.c)) {
                    @export(&main2, .{ .name = "main" });
                }
            } else if (builtin.os.tag == .windows) {
                if (!@hasDecl(root, "wWinMainCRTStartup") and !@hasDecl(root, "mainCRTStartup")) {
                    @export(&wWinMainCRTStartup2, .{ .name = "wWinMainCRTStartup" });
                }
            } else if (builtin.os.tag == .opencl or builtin.os.tag == .vulkan) {
                if (@hasDecl(root, "main"))
                    @export(&spirvMain2, .{ .name = "main" });
            } else {
                if (!@hasDecl(root, "_start")) {
                    @export(&_start2, .{ .name = "_start" });
                }
            }
        }
    } else {
        if (builtin.output_mode == .Lib and builtin.link_mode == .dynamic) {
            if (native_os == .windows and !@hasDecl(root, "_DllMainCRTStartup")) {
                @export(&_DllMainCRTStartup, .{ .name = "_DllMainCRTStartup" });
            }
        } else if (builtin.output_mode == .Exe or @hasDecl(root, "main")) {
            if (builtin.link_libc and @hasDecl(root, "main")) {
                if (native_arch.isWasm()) {
                    @export(&mainWithoutEnv, .{ .name = "main" });
                } else if (!@typeInfo(@TypeOf(root.main)).@"fn".calling_convention.eql(.c)) {
                    @export(&main, .{ .name = "main" });
                }
            } else if (native_os == .windows) {
                if (!@hasDecl(root, "WinMain") and !@hasDecl(root, "WinMainCRTStartup") and
                    !@hasDecl(root, "wWinMain") and !@hasDecl(root, "wWinMainCRTStartup"))
                {
                    @export(&WinStartup, .{ .name = "wWinMainCRTStartup" });
                } else if (@hasDecl(root, "WinMain") and !@hasDecl(root, "WinMainCRTStartup") and
                    !@hasDecl(root, "wWinMain") and !@hasDecl(root, "wWinMainCRTStartup"))
                {
                    @compileError("WinMain not supported; declare wWinMain or main instead");
                } else if (@hasDecl(root, "wWinMain") and !@hasDecl(root, "wWinMainCRTStartup") and
                    !@hasDecl(root, "WinMain") and !@hasDecl(root, "WinMainCRTStartup"))
                {
                    @export(&wWinMainCRTStartup, .{ .name = "wWinMainCRTStartup" });
                }
            } else if (native_os == .uefi) {
                if (!@hasDecl(root, "EfiMain")) @export(&EfiMain, .{ .name = "EfiMain" });
            } else if (native_os == .wasi) {
                const wasm_start_sym = switch (builtin.wasi_exec_model) {
                    .reactor => "_initialize",
                    .command => "_start",
                };
                if (!@hasDecl(root, wasm_start_sym) and @hasDecl(root, "main")) {
                    // Only call main when defined. For WebAssembly it's allowed to pass `-fno-entry` in which
                    // case it's not required to provide an entrypoint such as main.
                    @export(&wasi_start, .{ .name = wasm_start_sym });
                }
            } else if (native_arch.isWasm() and native_os == .freestanding) {
                // Only call main when defined. For WebAssembly it's allowed to pass `-fno-entry` in which
                // case it's not required to provide an entrypoint such as main.
                if (!@hasDecl(root, start_sym_name) and @hasDecl(root, "main")) @export(&wasm_freestanding_start, .{ .name = start_sym_name });
            } else if (native_os != .other and native_os != .freestanding) {
                if (!@hasDecl(root, start_sym_name)) @export(&_start, .{ .name = start_sym_name });
            }
        }
    }
}

// Simplified start code for stage2 until it supports more language features ///

fn main2() callconv(.c) c_int {
    root.main();
    return 0;
}

fn _start2() callconv(.withStackAlign(.c, 1)) noreturn {
    callMain2();
}

fn callMain2() noreturn {
    root.main();
    exit2(0);
}

fn spirvMain2() callconv(.kernel) void {
    root.main();
}

fn wWinMainCRTStartup2() callconv(.c) noreturn {
    root.main();
    exit2(0);
}

fn exit2(code: usize) noreturn {
    switch (native_os) {
        .linux => switch (builtin.cpu.arch) {
            .x86_64 => {
                asm volatile ("syscall"
                    :
                    : [number] "{rax}" (231),
                      [arg1] "{rdi}" (code),
                    : "rcx", "r11", "memory"
                );
            },
            .arm => {
                asm volatile ("svc #0"
                    :
                    : [number] "{r7}" (1),
                      [arg1] "{r0}" (code),
                    : "memory"
                );
            },
            .aarch64 => {
                asm volatile ("svc #0"
                    :
                    : [number] "{x8}" (93),
                      [arg1] "{x0}" (code),
                    : "memory", "cc"
                );
            },
            .sparc64 => {
                asm volatile ("ta 0x6d"
                    :
                    : [number] "{g1}" (1),
                      [arg1] "{o0}" (code),
                    : "o0", "o1", "o2", "o3", "o4", "o5", "o6", "o7", "memory"
                );
            },
            else => @compileError("TODO"),
        },
        // exits(0)
        .plan9 => std.os.plan9.exits(null),
        .windows => {
            std.os.windows.ntdll.RtlExitUserProcess(@as(u32, @truncate(code)));
        },
        else => @compileError("TODO"),
    }
    unreachable;
}

////////////////////////////////////////////////////////////////////////////////

fn _DllMainCRTStartup(
    hinstDLL: std.os.windows.HINSTANCE,
    fdwReason: std.os.windows.DWORD,
    lpReserved: std.os.windows.LPVOID,
) callconv(.winapi) std.os.windows.BOOL {
    if (!builtin.single_threaded and !builtin.link_libc) {
        _ = @import("os/windows/tls.zig");
    }

    if (@hasDecl(root, "DllMain")) {
        return root.DllMain(hinstDLL, fdwReason, lpReserved);
    }

    return std.os.windows.TRUE;
}

fn wasm_freestanding_start() callconv(.c) void {
    // This is marked inline because for some reason LLVM in
    // release mode fails to inline it, and we want fewer call frames in stack traces.
    _ = @call(.always_inline, callMain, .{});
}

fn wasi_start() callconv(.c) void {
    // The function call is marked inline because for some reason LLVM in
    // release mode fails to inline it, and we want fewer call frames in stack traces.
    switch (builtin.wasi_exec_model) {
        .reactor => _ = @call(.always_inline, callMain, .{}),
        .command => std.os.wasi.proc_exit(@call(.always_inline, callMain, .{})),
    }
}

fn EfiMain(handle: uefi.Handle, system_table: *uefi.tables.SystemTable) callconv(.c) usize {
    uefi.handle = handle;
    uefi.system_table = system_table;

    switch (@typeInfo(@TypeOf(root.main)).@"fn".return_type.?) {
        noreturn => {
            root.main();
        },
        void => {
            root.main();
            return 0;
        },
        uefi.Status => {
            return @intFromEnum(root.main());
        },
        uefi.Error!void => {
            root.main() catch |err| switch (err) {
                error.Unexpected => @panic("EfiMain: unexpected error"),
                else => {
                    const status = uefi.Status.fromError(@errorCast(err));
                    return @intFromEnum(status);
                },
            };

            return 0;
        },
        else => @compileError(
            "expected return type of main to be 'void', 'noreturn', " ++
                "'uefi.Status', or 'uefi.Error!void'",
        ),
    }
}

fn _start() callconv(.naked) noreturn {
    // TODO set Top of Stack on non x86_64-plan9
    if (native_os == .plan9 and native_arch == .x86_64) {
        // from /sys/src/libc/amd64/main9.s
        std.os.plan9.tos = asm volatile (""
            : [tos] "={rax}" (-> *std.os.plan9.Tos),
        );
    }

    // This is the first userspace frame. Prevent DWARF-based unwinders from unwinding further. We
    // prevent FP-based unwinders from unwinding further by zeroing the register below.
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (switch (native_arch) {
            .arc => ".cfi_undefined blink",
            .arm, .armeb, .thumb, .thumbeb => "", // https://github.com/llvm/llvm-project/issues/115891
            .aarch64, .aarch64_be => ".cfi_undefined lr",
            .csky => ".cfi_undefined lr",
            .hexagon => ".cfi_undefined r31",
            .loongarch32, .loongarch64 => ".cfi_undefined 1",
            .m68k => ".cfi_undefined %%pc",
            .mips, .mipsel, .mips64, .mips64el => ".cfi_undefined $ra",
            .powerpc, .powerpcle, .powerpc64, .powerpc64le => ".cfi_undefined lr",
            .riscv32, .riscv64 => if (builtin.zig_backend == .stage2_riscv64)
                ""
            else
                ".cfi_undefined ra",
            .s390x => ".cfi_undefined %%r14",
            .sparc, .sparc64 => ".cfi_undefined %%i7",
            .x86 => ".cfi_undefined %%eip",
            .x86_64 => ".cfi_undefined %%rip",
            else => @compileError("unsupported arch"),
        });

    // Move this to the riscv prong below when this is resolved: https://github.com/ziglang/zig/issues/20918
    if (builtin.cpu.arch.isRISCV() and builtin.zig_backend != .stage2_riscv64) asm volatile (
        \\ .weak __global_pointer$
        \\ .hidden __global_pointer$
        \\ .option push
        \\ .option norelax
        \\ lla gp, __global_pointer$
        \\ .option pop
    );

    // Note that we maintain a very low level of trust with regards to ABI guarantees at this point.
    // We will redundantly align the stack, clear the link register, etc. While e.g. the Linux
    // kernel is usually good about upholding the ABI guarantees, the same cannot be said of dynamic
    // linkers; musl's ldso, for example, opts to not align the stack when invoking the dynamic
    // linker explicitly.
    asm volatile (switch (native_arch) {
            .x86_64 =>
            \\ xorl %%ebp, %%ebp
            \\ movq %%rsp, %%rdi
            \\ andq $-16, %%rsp
            \\ callq %[posixCallMainAndExit:P]
            ,
            .x86 =>
            \\ xorl %%ebp, %%ebp
            \\ movl %%esp, %%eax
            \\ andl $-16, %%esp
            \\ subl $12, %%esp
            \\ pushl %%eax
            \\ calll %[posixCallMainAndExit:P]
            ,
            .aarch64, .aarch64_be =>
            \\ mov fp, #0
            \\ mov lr, #0
            \\ mov x0, sp
            \\ and sp, x0, #-16
            \\ b %[posixCallMainAndExit]
            ,
            .arc =>
            // The `arc` tag currently means ARC v1 and v2, which have an unusually low stack
            // alignment requirement. ARC v3 increases it from 4 to 16, but we don't support v3 yet.
            \\ mov fp, 0
            \\ mov blink, 0
            \\ mov r0, sp
            \\ and sp, sp, -4
            \\ b %[posixCallMainAndExit]
            ,
            .arm, .armeb, .thumb, .thumbeb =>
            // Note that this code must work for Thumb-1.
            // r7 = FP (local), r11 = FP (unwind)
            \\ movs v1, #0
            \\ mov r7, v1
            \\ mov r11, v1
            \\ mov lr, v1
            \\ mov a1, sp
            \\ subs v1, #16
            \\ ands v1, a1
            \\ mov sp, v1
            \\ b %[posixCallMainAndExit]
            ,
            .csky =>
            // The CSKY ABI assumes that `gb` is set to the address of the GOT in order for
            // position-independent code to work. We depend on this in `std.os.linux.pie` to locate
            // `_DYNAMIC` as well.
            // r8 = FP
            \\ grs t0, 1f
            \\ 1:
            \\ lrw gb, 1b@GOTPC
            \\ addu gb, t0
            \\ movi r8, 0
            \\ movi lr, 0
            \\ mov a0, sp
            \\ andi sp, sp, -8
            \\ jmpi %[posixCallMainAndExit]
            ,
            .hexagon =>
            // r29 = SP, r30 = FP, r31 = LR
            \\ r30 = #0
            \\ r31 = #0
            \\ r0 = r29
            \\ r29 = and(r29, #-8)
            \\ memw(r29 + #-8) = r29
            \\ r29 = add(r29, #-8)
            \\ call %[posixCallMainAndExit]
            ,
            .loongarch32, .loongarch64 =>
            \\ move $fp, $zero
            \\ move $ra, $zero
            \\ move $a0, $sp
            \\ bstrins.d $sp, $zero, 3, 0
            \\ b %[posixCallMainAndExit]
            ,
            .riscv32, .riscv64 =>
            \\ li fp, 0
            \\ li ra, 0
            \\ mv a0, sp
            \\ andi sp, sp, -16
            \\ tail %[posixCallMainAndExit]@plt
            ,
            .m68k =>
            // Note that the - 8 is needed because pc in the jsr instruction points into the middle
            // of the jsr instruction. (The lea is 6 bytes, the jsr is 4 bytes.)
            \\ suba.l %%fp, %%fp
            \\ move.l %%sp, %%a0
            \\ move.l %%a0, %%d0
            \\ and.l #-4, %%d0
            \\ move.l %%d0, %%sp
            \\ move.l %%a0, -(%%sp)
            \\ lea %[posixCallMainAndExit] - . - 8, %%a0
            \\ jsr (%%pc, %%a0)
            ,
            .mips, .mipsel =>
            \\ move $fp, $0
            \\ bal 1f
            \\ .gpword .
            \\ .gpword %[posixCallMainAndExit]
            \\ 1:
            // The `gp` register on MIPS serves a similar purpose to `r2` (ToC pointer) on PPC64.
            \\ lw $gp, 0($ra)
            \\ subu $gp, $ra, $gp
            \\ lw $25, 4($ra)
            \\ addu $25, $25, $gp
            \\ move $ra, $0
            \\ move $a0, $sp
            \\ and $sp, -8
            \\ subu $sp, $sp, 16
            \\ jalr $25
            ,
            .mips64, .mips64el =>
            \\ move $fp, $0
            // This is needed because early MIPS versions don't support misaligned loads. Without
            // this directive, the hidden `nop` inserted to fill the delay slot after `bal` would
            // cause the two doublewords to be aligned to 4 bytes instead of 8.
            \\ .balign 8
            \\ bal 1f
            \\ .gpdword .
            \\ .gpdword %[posixCallMainAndExit]
            \\ 1:
            // The `gp` register on MIPS serves a similar purpose to `r2` (ToC pointer) on PPC64.
            \\ ld $gp, 0($ra)
            \\ dsubu $gp, $ra, $gp
            \\ ld $25, 8($ra)
            \\ daddu $25, $25, $gp
            \\ move $ra, $0
            \\ move $a0, $sp
            \\ and $sp, -16
            \\ dsubu $sp, $sp, 16
            \\ jalr $25
            ,
            .powerpc, .powerpcle =>
            // Set up the initial stack frame, and clear the back chain pointer.
            // r1 = SP, r31 = FP
            \\ mr 3, 1
            \\ clrrwi 1, 1, 4
            \\ li 0, 0
            \\ stwu 1, -16(1)
            \\ stw 0, 0(1)
            \\ li 31, 0
            \\ mtlr 0
            \\ b %[posixCallMainAndExit]
            ,
            .powerpc64, .powerpc64le =>
            // Set up the ToC and initial stack frame, and clear the back chain pointer.
            // r1 = SP, r2 = ToC, r31 = FP
            \\ addis 2, 12, .TOC. - %[_start]@ha
            \\ addi 2, 2, .TOC. - %[_start]@l
            \\ mr 3, 1
            \\ clrrdi 1, 1, 4
            \\ li 0, 0
            \\ stdu 0, -32(1)
            \\ li 31, 0
            \\ mtlr 0
            \\ b %[posixCallMainAndExit]
            \\ nop
            ,
            .s390x =>
            // Set up the stack frame (register save area and cleared back-chain slot).
            // r11 = FP, r14 = LR, r15 = SP
            \\ lghi %%r11, 0
            \\ lghi %%r14, 0
            \\ lgr %%r2, %%r15
            \\ lghi %%r0, -16
            \\ ngr %%r15, %%r0
            \\ aghi %%r15, -160
            \\ lghi %%r0, 0
            \\ stg  %%r0, 0(%%r15)
            \\ jg %[posixCallMainAndExit]
            ,
            .sparc =>
            // argc is stored after a register window (16 registers * 4 bytes).
            // i7 = LR
            \\ mov %%g0, %%fp
            \\ mov %%g0, %%i7
            \\ add %%sp, 64, %%o0
            \\ and %%sp, -8, %%sp
            \\ ba,a %[posixCallMainAndExit]
            ,
            .sparc64 =>
            // argc is stored after a register window (16 registers * 8 bytes) plus the stack bias
            // (2047 bytes).
            // i7 = LR
            \\ mov %%g0, %%fp
            \\ mov %%g0, %%i7
            \\ add %%sp, 2175, %%o0
            \\ add %%sp, 2047, %%sp
            \\ and %%sp, -16, %%sp
            \\ sub %%sp, 2047, %%sp
            \\ ba,a %[posixCallMainAndExit]
            ,
            else => @compileError("unsupported arch"),
        }
        :
        : [_start] "X" (&_start),
          [posixCallMainAndExit] "X" (&posixCallMainAndExit),
    );
}

fn WinStartup() callconv(.withStackAlign(.c, 1)) noreturn {
    if (!builtin.single_threaded and !builtin.link_libc) {
        _ = @import("os/windows/tls.zig");
    }

    std.debug.maybeEnableSegfaultHandler();

    std.os.windows.ntdll.RtlExitUserProcess(callMain());
}

fn wWinMainCRTStartup() callconv(.withStackAlign(.c, 1)) noreturn {
    if (!builtin.single_threaded and !builtin.link_libc) {
        _ = @import("os/windows/tls.zig");
    }

    std.debug.maybeEnableSegfaultHandler();

    const result: std.os.windows.INT = call_wWinMain();
    std.os.windows.ntdll.RtlExitUserProcess(@as(std.os.windows.UINT, @bitCast(result)));
}

fn posixCallMainAndExit(argc_argv_ptr: [*]usize) callconv(.c) noreturn {
    // We're not ready to panic until thread local storage is initialized.
    @setRuntimeSafety(false);
    // Code coverage instrumentation might try to use thread local variables.
    @disableInstrumentation();
    const argc = argc_argv_ptr[0];
    const argv = @as([*][*:0]u8, @ptrCast(argc_argv_ptr + 1));

    const envp_optional: [*:null]?[*:0]u8 = @ptrCast(@alignCast(argv + argc + 1));
    var envp_count: usize = 0;
    while (envp_optional[envp_count]) |_| : (envp_count += 1) {}
    const envp = @as([*][*:0]u8, @ptrCast(envp_optional))[0..envp_count];

    if (native_os == .linux) {
        // Find the beginning of the auxiliary vector
        const auxv: [*]elf.Auxv = @ptrCast(@alignCast(envp.ptr + envp_count + 1));

        var at_hwcap: usize = 0;
        const phdrs = init: {
            var i: usize = 0;
            var at_phdr: usize = 0;
            var at_phnum: usize = 0;
            while (auxv[i].a_type != elf.AT_NULL) : (i += 1) {
                switch (auxv[i].a_type) {
                    elf.AT_PHNUM => at_phnum = auxv[i].a_un.a_val,
                    elf.AT_PHDR => at_phdr = auxv[i].a_un.a_val,
                    elf.AT_HWCAP => at_hwcap = auxv[i].a_un.a_val,
                    else => continue,
                }
            }
            break :init @as([*]elf.Phdr, @ptrFromInt(at_phdr))[0..at_phnum];
        };

        // Apply the initial relocations as early as possible in the startup process. We cannot
        // make calls yet on some architectures (e.g. MIPS) *because* they haven't been applied yet,
        // so this must be fully inlined.
        if (builtin.position_independent_executable) {
            @call(.always_inline, std.os.linux.pie.relocate, .{phdrs});
        }

        // This must be done after PIE relocations have been applied or we may crash
        // while trying to access the global variable (happens on MIPS at least).
        std.os.linux.elf_aux_maybe = auxv;

        if (!builtin.single_threaded) {
            // ARMv6 targets (and earlier) have no support for TLS in hardware.
            // FIXME: Elide the check for targets >= ARMv7 when the target feature API
            // becomes less verbose (and more usable).
            if (comptime native_arch.isArm()) {
                if (at_hwcap & std.os.linux.HWCAP.TLS == 0) {
                    // FIXME: Make __aeabi_read_tp call the kernel helper kuser_get_tls
                    // For the time being use a simple trap instead of a @panic call to
                    // keep the binary bloat under control.
                    @trap();
                }
            }

            // Initialize the TLS area.
            std.os.linux.tls.initStatic(phdrs);
        }

        // The way Linux executables represent stack size is via the PT_GNU_STACK
        // program header. However the kernel does not recognize it; it always gives 8 MiB.
        // Here we look for the stack size in our program headers and use setrlimit
        // to ask for more stack space.
        expandStackSize(phdrs);

        const opt_init_array_start = @extern([*]*const fn () callconv(.c) void, .{
            .name = "__init_array_start",
            .linkage = .weak,
        });
        const opt_init_array_end = @extern([*]*const fn () callconv(.c) void, .{
            .name = "__init_array_end",
            .linkage = .weak,
        });
        if (opt_init_array_start) |init_array_start| {
            const init_array_end = opt_init_array_end.?;
            const slice = init_array_start[0 .. init_array_end - init_array_start];
            for (slice) |func| func();
        }
    }

    std.posix.exit(callMainWithArgs(argc, argv, envp));
}

fn expandStackSize(phdrs: []elf.Phdr) void {
    for (phdrs) |*phdr| {
        switch (phdr.p_type) {
            elf.PT_GNU_STACK => {
                if (phdr.p_memsz == 0) break;
                assert(phdr.p_memsz % std.heap.page_size_min == 0);

                // Silently fail if we are unable to get limits.
                const limits = std.posix.getrlimit(.STACK) catch break;

                // Clamp to limits.max .
                const wanted_stack_size = @min(phdr.p_memsz, limits.max);

                if (wanted_stack_size > limits.cur) {
                    std.posix.setrlimit(.STACK, .{
                        .cur = wanted_stack_size,
                        .max = limits.max,
                    }) catch {
                        // Because we could not increase the stack size to the upper bound,
                        // depending on what happens at runtime, a stack overflow may occur.
                        // However it would cause a segmentation fault, thanks to stack probing,
                        // so we do not have a memory safety issue here.
                        // This is intentional silent failure.
                        // This logic should be revisited when the following issues are addressed:
                        // https://github.com/ziglang/zig/issues/157
                        // https://github.com/ziglang/zig/issues/1006
                    };
                }
                break;
            },
            else => {},
        }
    }
}

inline fn callMainWithArgs(argc: usize, argv: [*][*:0]u8, envp: [][*:0]u8) u8 {
    std.os.argv = argv[0..argc];
    std.os.environ = envp;

    std.debug.maybeEnableSegfaultHandler();
    maybeIgnoreSigpipe();

    return callMain();
}

fn main(c_argc: c_int, c_argv: [*][*:0]c_char, c_envp: [*:null]?[*:0]c_char) callconv(.c) c_int {
    var env_count: usize = 0;
    while (c_envp[env_count] != null) : (env_count += 1) {}
    const envp = @as([*][*:0]u8, @ptrCast(c_envp))[0..env_count];

    if (builtin.os.tag == .linux) {
        const at_phdr = std.c.getauxval(elf.AT_PHDR);
        const at_phnum = std.c.getauxval(elf.AT_PHNUM);
        const phdrs = (@as([*]elf.Phdr, @ptrFromInt(at_phdr)))[0..at_phnum];
        expandStackSize(phdrs);
    }

    return callMainWithArgs(@as(usize, @intCast(c_argc)), @as([*][*:0]u8, @ptrCast(c_argv)), envp);
}

fn mainWithoutEnv(c_argc: c_int, c_argv: [*][*:0]c_char) callconv(.c) c_int {
    std.os.argv = @as([*][*:0]u8, @ptrCast(c_argv))[0..@as(usize, @intCast(c_argc))];
    return callMain();
}

// General error message for a malformed return type
const bad_main_ret = "expected return type of main to be 'void', '!void', 'noreturn', 'u8', or '!u8'";

pub inline fn callMain() u8 {
    const ReturnType = @typeInfo(@TypeOf(root.main)).@"fn".return_type.?;

    switch (ReturnType) {
        void => {
            root.main();
            return 0;
        },
        noreturn, u8 => {
            return root.main();
        },
        else => {
            if (@typeInfo(ReturnType) != .error_union) @compileError(bad_main_ret);

            const result = root.main() catch |err| {
                if (builtin.zig_backend == .stage2_riscv64) {
                    std.debug.print("error: failed with error\n", .{});
                    return 1;
                }
                std.log.err("{s}", .{@errorName(err)});
                if (@errorReturnTrace()) |trace| {
                    std.debug.dumpStackTrace(trace.*);
                }
                return 1;
            };

            return switch (@TypeOf(result)) {
                void => 0,
                u8 => result,
                else => @compileError(bad_main_ret),
            };
        },
    }
}

pub fn call_wWinMain() std.os.windows.INT {
    const peb = std.os.windows.peb();
    const MAIN_HINSTANCE = @typeInfo(@TypeOf(root.wWinMain)).@"fn".params[0].type.?;
    const hInstance = @as(MAIN_HINSTANCE, @ptrCast(peb.ImageBaseAddress));
    const lpCmdLine: [*:0]u16 = @ptrCast(peb.ProcessParameters.CommandLine.Buffer);

    // There are various types used for the 'show window' variable through the Win32 APIs:
    // - u16 in STARTUPINFOA.wShowWindow / STARTUPINFOW.wShowWindow
    // - c_int in ShowWindow
    // - u32 in PEB.ProcessParameters.dwShowWindow
    // Since STARTUPINFO is the bottleneck for the allowed values, we use `u16` as the
    // type which can coerce into i32/c_int/u32 depending on how the user defines their wWinMain
    // (the Win32 docs show wWinMain with `int` as the type for nCmdShow).
    const nCmdShow: u16 = nCmdShow: {
        // This makes Zig match the nCmdShow behavior of a C program with a WinMain symbol:
        // - With STARTF_USESHOWWINDOW set in STARTUPINFO.dwFlags of the CreateProcess call:
        //   - Compiled with subsystem:console -> nCmdShow is always SW_SHOWDEFAULT
        //   - Compiled with subsystem:windows -> nCmdShow is STARTUPINFO.wShowWindow from
        //     the parent CreateProcess call
        // - With STARTF_USESHOWWINDOW unset:
        //   - nCmdShow is always SW_SHOWDEFAULT
        const SW_SHOWDEFAULT = 10;
        const STARTF_USESHOWWINDOW = 1;
        // root having a wWinMain means that std.builtin.subsystem will always have a non-null value.
        if (std.builtin.subsystem.? == .Windows and peb.ProcessParameters.dwFlags & STARTF_USESHOWWINDOW != 0) {
            break :nCmdShow @truncate(peb.ProcessParameters.dwShowWindow);
        }
        break :nCmdShow SW_SHOWDEFAULT;
    };

    // second parameter hPrevInstance, MSDN: "This parameter is always NULL"
    return root.wWinMain(hInstance, null, lpCmdLine, nCmdShow);
}

fn maybeIgnoreSigpipe() void {
    const have_sigpipe_support = switch (builtin.os.tag) {
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

    if (have_sigpipe_support and !std.options.keep_sigpipe) {
        const posix = std.posix;
        const act: posix.Sigaction = .{
            // Set handler to a noop function instead of `SIG.IGN` to prevent
            // leaking signal disposition to a child process.
            .handler = .{ .handler = noopSigHandler },
            .mask = posix.empty_sigset,
            .flags = 0,
        };
        posix.sigaction(posix.SIG.PIPE, &act, null);
    }
}

fn noopSigHandler(_: i32) callconv(.c) void {}
const std = @import("std.zig");
const mem = std.mem;

/// Static string map optimized for small sets of disparate string keys.
/// Works by separating the keys by length at initialization and only checking
/// strings of equal length at runtime.
pub fn StaticStringMap(comptime V: type) type {
    return StaticStringMapWithEql(V, defaultEql);
}

/// Like `std.mem.eql`, but takes advantage of the fact that the lengths
/// of `a` and `b` are known to be equal.
pub fn defaultEql(a: []const u8, b: []const u8) bool {
    if (a.ptr == b.ptr) return true;
    for (a, b) |a_elem, b_elem| {
        if (a_elem != b_elem) return false;
    }
    return true;
}

/// Like `std.ascii.eqlIgnoreCase` but takes advantage of the fact that
/// the lengths of `a` and `b` are known to be equal.
pub fn eqlAsciiIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.ptr == b.ptr) return true;
    for (a, b) |a_c, b_c| {
        if (std.ascii.toLower(a_c) != std.ascii.toLower(b_c)) return false;
    }
    return true;
}

/// StaticStringMap, but accepts an equality function (`eql`).
/// The `eql` function is only called to determine the equality
/// of equal length strings. Any strings that are not equal length
/// are never compared using the `eql` function.
pub fn StaticStringMapWithEql(
    comptime V: type,
    comptime eql: fn (a: []const u8, b: []const u8) bool,
) type {
    return struct {
        kvs: *const KVs = &empty_kvs,
        len_indexes: [*]const u32 = &empty_len_indexes,
        len_indexes_len: u32 = 0,
        min_len: u32 = std.math.maxInt(u32),
        max_len: u32 = 0,

        pub const KV = struct {
            key: []const u8,
            value: V,
        };

        const Self = @This();
        const KVs = struct {
            keys: [*]const []const u8,
            values: [*]const V,
            len: u32,
        };
        const empty_kvs = KVs{
            .keys = &empty_keys,
            .values = &empty_vals,
            .len = 0,
        };
        const empty_len_indexes = [0]u32{};
        const empty_keys = [0][]const u8{};
        const empty_vals = [0]V{};

        /// Returns a map backed by static, comptime allocated memory.
        ///
        /// `kvs_list` must be either a list of `struct { []const u8, V }`
        /// (key-value pair) tuples, or a list of `struct { []const u8 }`
        /// (only keys) tuples if `V` is `void`.
        pub inline fn initComptime(comptime kvs_list: anytype) Self {
            comptime {
                var self = Self{};
                if (kvs_list.len == 0)
                    return self;

                // Since the KVs are sorted, a linearly-growing bound will never
                // be sufficient for extreme cases. So we grow proportional to
                // N*log2(N).
                @setEvalBranchQuota(10 * kvs_list.len * std.math.log2_int_ceil(usize, kvs_list.len));

                var sorted_keys: [kvs_list.len][]const u8 = undefined;
                var sorted_vals: [kvs_list.len]V = undefined;

                self.initSortedKVs(kvs_list, &sorted_keys, &sorted_vals);
                const final_keys = sorted_keys;
                const final_vals = sorted_vals;
                self.kvs = &.{
                    .keys = &final_keys,
                    .values = &final_vals,
                    .len = @intCast(kvs_list.len),
                };

                var len_indexes: [self.max_len + 1]u32 = undefined;
                self.initLenIndexes(&len_indexes);
                const final_len_indexes = len_indexes;
                self.len_indexes = &final_len_indexes;
                self.len_indexes_len = @intCast(len_indexes.len);
                return self;
            }
        }

        /// Returns a map backed by memory allocated with `allocator`.
        ///
        /// Handles `kvs_list` the same way as `initComptime()`.
        pub fn init(kvs_list: anytype, allocator: mem.Allocator) !Self {
            var self = Self{};
            if (kvs_list.len == 0)
                return self;

            const sorted_keys = try allocator.alloc([]const u8, kvs_list.len);
            errdefer allocator.free(sorted_keys);
            const sorted_vals = try allocator.alloc(V, kvs_list.len);
            errdefer allocator.free(sorted_vals);
            const kvs = try allocator.create(KVs);
            errdefer allocator.destroy(kvs);

            self.initSortedKVs(kvs_list, sorted_keys, sorted_vals);
            kvs.* = .{
                .keys = sorted_keys.ptr,
                .values = sorted_vals.ptr,
                .len = @intCast(kvs_list.len),
            };
            self.kvs = kvs;

            const len_indexes = try allocator.alloc(u32, self.max_len + 1);
            self.initLenIndexes(len_indexes);
            self.len_indexes = len_indexes.ptr;
            self.len_indexes_len = @intCast(len_indexes.len);
            return self;
        }

        /// this method should only be used with init() and not with initComptime().
        pub fn deinit(self: Self, allocator: mem.Allocator) void {
            allocator.free(self.len_indexes[0..self.len_indexes_len]);
            allocator.free(self.kvs.keys[0..self.kvs.len]);
            allocator.free(self.kvs.values[0..self.kvs.len]);
            allocator.destroy(self.kvs);
        }

        const SortContext = struct {
            keys: [][]const u8,
            vals: []V,

            pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
                return ctx.keys[a].len < ctx.keys[b].len;
            }

            pub fn swap(ctx: @This(), a: usize, b: usize) void {
                std.mem.swap([]const u8, &ctx.keys[a], &ctx.keys[b]);
                std.mem.swap(V, &ctx.vals[a], &ctx.vals[b]);
            }
        };

        fn initSortedKVs(
            self: *Self,
            kvs_list: anytype,
            sorted_keys: [][]const u8,
            sorted_vals: []V,
        ) void {
            for (kvs_list, 0..) |kv, i| {
                sorted_keys[i] = kv.@"0";
                sorted_vals[i] = if (V == void) {} else kv.@"1";
                self.min_len = @intCast(@min(self.min_len, kv.@"0".len));
                self.max_len = @intCast(@max(self.max_len, kv.@"0".len));
            }
            mem.sortUnstableContext(0, sorted_keys.len, SortContext{
                .keys = sorted_keys,
                .vals = sorted_vals,
            });
        }

        fn initLenIndexes(self: Self, len_indexes: []u32) void {
            var len: usize = 0;
            var i: u32 = 0;
            while (len <= self.max_len) : (len += 1) {
                // find the first keyword len == len
                while (len > self.kvs.keys[i].len) {
                    i += 1;
                }
                len_indexes[len] = i;
            }
        }

        /// Checks if the map has a value for the key.
        pub fn has(self: Self, str: []const u8) bool {
            return self.get(str) != null;
        }

        /// Returns the value for the key if any, else null.
        pub fn get(self: Self, str: []const u8) ?V {
            if (self.kvs.len == 0)
                return null;

            return self.kvs.values[self.getIndex(str) orelse return null];
        }

        pub fn getIndex(self: Self, str: []const u8) ?usize {
            const kvs = self.kvs.*;
            if (kvs.len == 0)
                return null;

            if (str.len < self.min_len or str.len > self.max_len)
                return null;

            var i = self.len_indexes[str.len];
            while (true) {
                const key = kvs.keys[i];
                if (key.len != str.len)
                    return null;
                if (eql(key, str))
                    return i;
                i += 1;
                if (i >= kvs.len)
                    return null;
            }
        }

        /// Returns the key-value pair where key is the longest prefix of `str`
        /// else null.
        ///
        /// This is effectively an O(N) algorithm which loops from `max_len` to
        /// `min_len` and calls `getIndex()` to check all keys with the given
        /// len.
        pub fn getLongestPrefix(self: Self, str: []const u8) ?KV {
            if (self.kvs.len == 0)
                return null;
            const i = self.getLongestPrefixIndex(str) orelse return null;
            const kvs = self.kvs.*;
            return .{
                .key = kvs.keys[i],
                .value = kvs.values[i],
            };
        }

        pub fn getLongestPrefixIndex(self: Self, str: []const u8) ?usize {
            if (self.kvs.len == 0)
                return null;

            if (str.len < self.min_len)
                return null;

            var len = @min(self.max_len, str.len);
            while (len >= self.min_len) : (len -= 1) {
                if (self.getIndex(str[0..len])) |i|
                    return i;
            }
            return null;
        }

        pub fn keys(self: Self) []const []const u8 {
            const kvs = self.kvs.*;
            return kvs.keys[0..kvs.len];
        }

        pub fn values(self: Self) []const V {
            const kvs = self.kvs.*;
            return kvs.values[0..kvs.len];
        }
    };
}

const TestEnum = enum { A, B, C, D, E };
const TestMap = StaticStringMap(TestEnum);
const TestKV = struct { []const u8, TestEnum };
const TestMapVoid = StaticStringMap(void);
const TestKVVoid = struct { []const u8 };
const TestMapWithEql = StaticStringMapWithEql(TestEnum, eqlAsciiIgnoreCase);
const testing = std.testing;
const test_alloc = testing.allocator;

test "list literal of list literals" {
    const slice: []const TestKV = &.{
        .{ "these", .D },
        .{ "have", .A },
        .{ "nothing", .B },
        .{ "incommon", .C },
        .{ "samelen", .E },
    };

    const map = TestMap.initComptime(slice);
    try testMap(map);
    // Default comparison is case sensitive
    try testing.expect(null == map.get("NOTHING"));

    // runtime init(), deinit()
    const map_rt = try TestMap.init(slice, test_alloc);
    defer map_rt.deinit(test_alloc);
    try testMap(map_rt);
    // Default comparison is case sensitive
    try testing.expect(null == map_rt.get("NOTHING"));
}

test "array of structs" {
    const slice = [_]TestKV{
        .{ "these", .D },
        .{ "have", .A },
        .{ "nothing", .B },
        .{ "incommon", .C },
        .{ "samelen", .E },
    };

    try testMap(TestMap.initComptime(slice));
}

test "slice of structs" {
    const slice = [_]TestKV{
        .{ "these", .D },
        .{ "have", .A },
        .{ "nothing", .B },
        .{ "incommon", .C },
        .{ "samelen", .E },
    };

    try testMap(TestMap.initComptime(slice));
}

fn testMap(map: anytype) !void {
    try testing.expectEqual(TestEnum.A, map.get("have").?);
    try testing.expectEqual(TestEnum.B, map.get("nothing").?);
    try testing.expect(null == map.get("missing"));
    try testing.expectEqual(TestEnum.D, map.get("these").?);
    try testing.expectEqual(TestEnum.E, map.get("samelen").?);

    try testing.expect(!map.has("missing"));
    try testing.expect(map.has("these"));

    try testing.expect(null == map.get(""));
    try testing.expect(null == map.get("averylongstringthathasnomatches"));
}

test "void value type, slice of structs" {
    const slice = [_]TestKVVoid{
        .{"these"},
        .{"have"},
        .{"nothing"},
        .{"incommon"},
        .{"samelen"},
    };
    const map = TestMapVoid.initComptime(slice);
    try testSet(map);
    // Default comparison is case sensitive
    try testing.expect(null == map.get("NOTHING"));
}

test "void value type, list literal of list literals" {
    const slice = [_]TestKVVoid{
        .{"these"},
        .{"have"},
        .{"nothing"},
        .{"incommon"},
        .{"samelen"},
    };

    try testSet(TestMapVoid.initComptime(slice));
}

fn testSet(map: TestMapVoid) !void {
    try testing.expectEqual({}, map.get("have").?);
    try testing.expectEqual({}, map.get("nothing").?);
    try testing.expect(null == map.get("missing"));
    try testing.expectEqual({}, map.get("these").?);
    try testing.expectEqual({}, map.get("samelen").?);

    try testing.expect(!map.has("missing"));
    try testing.expect(map.has("these"));

    try testing.expect(null == map.get(""));
    try testing.expect(null == map.get("averylongstringthathasnomatches"));
}

fn testStaticStringMapWithEql(map: TestMapWithEql) !void {
    try testMap(map);
    try testing.expectEqual(TestEnum.A, map.get("HAVE").?);
    try testing.expectEqual(TestEnum.E, map.get("SameLen").?);
    try testing.expect(null == map.get("SameLength"));
    try testing.expect(map.has("ThESe"));
}

test "StaticStringMapWithEql" {
    const slice = [_]TestKV{
        .{ "these", .D },
        .{ "have", .A },
        .{ "nothing", .B },
        .{ "incommon", .C },
        .{ "samelen", .E },
    };

    try testStaticStringMapWithEql(TestMapWithEql.initComptime(slice));
}

test "empty" {
    const m1 = StaticStringMap(usize).initComptime(.{});
    try testing.expect(null == m1.get("anything"));

    const m2 = StaticStringMapWithEql(usize, eqlAsciiIgnoreCase).initComptime(.{});
    try testing.expect(null == m2.get("anything"));

    const m3 = try StaticStringMap(usize).init(.{}, test_alloc);
    try testing.expect(null == m3.get("anything"));

    const m4 = try StaticStringMapWithEql(usize, eqlAsciiIgnoreCase).init(.{}, test_alloc);
    try testing.expect(null == m4.get("anything"));
}

test "redundant entries" {
    const slice = [_]TestKV{
        .{ "redundant", .D },
        .{ "theNeedle", .A },
        .{ "redundant", .B },
        .{ "re" ++ "dundant", .C },
        .{ "redun" ++ "dant", .E },
    };
    const map = TestMap.initComptime(slice);

    // No promises about which one you get:
    try testing.expect(null != map.get("redundant"));

    // Default map is not case sensitive:
    try testing.expect(null == map.get("REDUNDANT"));

    try testing.expectEqual(TestEnum.A, map.get("theNeedle").?);
}

test "redundant insensitive" {
    const slice = [_]TestKV{
        .{ "redundant", .D },
        .{ "theNeedle", .A },
        .{ "redundanT", .B },
        .{ "RE" ++ "dundant", .C },
        .{ "redun" ++ "DANT", .E },
    };

    const map = TestMapWithEql.initComptime(slice);

    // No promises about which result you'll get ...
    try testing.expect(null != map.get("REDUNDANT"));
    try testing.expect(null != map.get("ReDuNdAnT"));
    try testing.expectEqual(TestEnum.A, map.get("theNeedle").?);
}

test "comptime-only value" {
    const map = StaticStringMap(type).initComptime(.{
        .{ "a", struct {
            pub const foo = 1;
        } },
        .{ "b", struct {
            pub const foo = 2;
        } },
        .{ "c", struct {
            pub const foo = 3;
        } },
    });

    try testing.expect(map.get("a").?.foo == 1);
    try testing.expect(map.get("b").?.foo == 2);
    try testing.expect(map.get("c").?.foo == 3);
    try testing.expect(map.get("d") == null);
}

test "getLongestPrefix" {
    const slice = [_]TestKV{
        .{ "a", .A },
        .{ "aa", .B },
        .{ "aaa", .C },
        .{ "aaaa", .D },
    };

    const map = TestMap.initComptime(slice);

    try testing.expectEqual(null, map.getLongestPrefix(""));
    try testing.expectEqual(null, map.getLongestPrefix("bar"));
    try testing.expectEqualStrings("aaaa", map.getLongestPrefix("aaaabar").?.key);
    try testing.expectEqualStrings("aaa", map.getLongestPrefix("aaabar").?.key);
}

test "getLongestPrefix2" {
    const slice = [_]struct { []const u8, u8 }{
        .{ "one", 1 },
        .{ "two", 2 },
        .{ "three", 3 },
        .{ "four", 4 },
        .{ "five", 5 },
        .{ "six", 6 },
        .{ "seven", 7 },
        .{ "eight", 8 },
        .{ "nine", 9 },
    };
    const map = StaticStringMap(u8).initComptime(slice);

    try testing.expectEqual(1, map.get("one"));
    try testing.expectEqual(null, map.get("o"));
    try testing.expectEqual(null, map.get("onexxx"));
    try testing.expectEqual(9, map.get("nine"));
    try testing.expectEqual(null, map.get("n"));
    try testing.expectEqual(null, map.get("ninexxx"));
    try testing.expectEqual(null, map.get("xxx"));

    try testing.expectEqual(1, map.getLongestPrefix("one").?.value);
    try testing.expectEqual(1, map.getLongestPrefix("onexxx").?.value);
    try testing.expectEqual(null, map.getLongestPrefix("o"));
    try testing.expectEqual(null, map.getLongestPrefix("on"));
    try testing.expectEqual(9, map.getLongestPrefix("nine").?.value);
    try testing.expectEqual(9, map.getLongestPrefix("ninexxx").?.value);
    try testing.expectEqual(null, map.getLongestPrefix("n"));
    try testing.expectEqual(null, map.getLongestPrefix("xxx"));
}

test "sorting kvs doesn't exceed eval branch quota" {
    // from https://github.com/ziglang/zig/issues/19803
    const TypeToByteSizeLUT = std.StaticStringMap(u32).initComptime(.{
        .{ "bool", 0 },
        .{ "c_int", 0 },
        .{ "c_long", 0 },
        .{ "c_longdouble", 0 },
        .{ "t20", 0 },
        .{ "t19", 0 },
        .{ "t18", 0 },
        .{ "t17", 0 },
        .{ "t16", 0 },
        .{ "t15", 0 },
        .{ "t14", 0 },
        .{ "t13", 0 },
        .{ "t12", 0 },
        .{ "t11", 0 },
        .{ "t10", 0 },
        .{ "t9", 0 },
        .{ "t8", 0 },
        .{ "t7", 0 },
        .{ "t6", 0 },
        .{ "t5", 0 },
        .{ "t4", 0 },
        .{ "t3", 0 },
        .{ "t2", 0 },
        .{ "t1", 1 },
    });
    try testing.expectEqual(1, TypeToByteSizeLUT.get("t1"));
}
pub const ArrayHashMap = array_hash_map.ArrayHashMap;
pub const ArrayHashMapUnmanaged = array_hash_map.ArrayHashMapUnmanaged;
pub const ArrayList = @import("array_list.zig").ArrayList;
pub const ArrayListAligned = @import("array_list.zig").ArrayListAligned;
pub const ArrayListAlignedUnmanaged = @import("array_list.zig").ArrayListAlignedUnmanaged;
pub const ArrayListUnmanaged = @import("array_list.zig").ArrayListUnmanaged;
pub const AutoArrayHashMap = array_hash_map.AutoArrayHashMap;
pub const AutoArrayHashMapUnmanaged = array_hash_map.AutoArrayHashMapUnmanaged;
pub const AutoHashMap = hash_map.AutoHashMap;
pub const AutoHashMapUnmanaged = hash_map.AutoHashMapUnmanaged;
pub const BitStack = @import("BitStack.zig");
pub const BoundedArray = @import("bounded_array.zig").BoundedArray;
pub const BoundedArrayAligned = @import("bounded_array.zig").BoundedArrayAligned;
pub const Build = @import("Build.zig");
pub const BufMap = @import("buf_map.zig").BufMap;
pub const BufSet = @import("buf_set.zig").BufSet;
pub const StaticStringMap = static_string_map.StaticStringMap;
pub const StaticStringMapWithEql = static_string_map.StaticStringMapWithEql;
pub const DoublyLinkedList = @import("DoublyLinkedList.zig");
pub const DynLib = @import("dynamic_library.zig").DynLib;
pub const DynamicBitSet = bit_set.DynamicBitSet;
pub const DynamicBitSetUnmanaged = bit_set.DynamicBitSetUnmanaged;
pub const EnumArray = enums.EnumArray;
pub const EnumMap = enums.EnumMap;
pub const EnumSet = enums.EnumSet;
pub const HashMap = hash_map.HashMap;
pub const HashMapUnmanaged = hash_map.HashMapUnmanaged;
pub const MultiArrayList = @import("multi_array_list.zig").MultiArrayList;
pub const PriorityQueue = @import("priority_queue.zig").PriorityQueue;
pub const PriorityDequeue = @import("priority_dequeue.zig").PriorityDequeue;
pub const Progress = @import("Progress.zig");
pub const Random = @import("Random.zig");
pub const RingBuffer = @import("RingBuffer.zig");
pub const SegmentedList = @import("segmented_list.zig").SegmentedList;
pub const SemanticVersion = @import("SemanticVersion.zig");
pub const SinglyLinkedList = @import("SinglyLinkedList.zig");
pub const StaticBitSet = bit_set.StaticBitSet;
pub const StringHashMap = hash_map.StringHashMap;
pub const StringHashMapUnmanaged = hash_map.StringHashMapUnmanaged;
pub const StringArrayHashMap = array_hash_map.StringArrayHashMap;
pub const StringArrayHashMapUnmanaged = array_hash_map.StringArrayHashMapUnmanaged;
pub const Target = @import("Target.zig");
pub const Thread = @import("Thread.zig");
pub const Treap = @import("treap.zig").Treap;
pub const Tz = tz.Tz;
pub const Uri = @import("Uri.zig");

pub const array_hash_map = @import("array_hash_map.zig");
pub const atomic = @import("atomic.zig");
pub const base64 = @import("base64.zig");
pub const bit_set = @import("bit_set.zig");
pub const builtin = @import("builtin.zig");
pub const c = @import("c.zig");
pub const coff = @import("coff.zig");
pub const compress = @import("compress.zig");
pub const static_string_map = @import("static_string_map.zig");
pub const crypto = @import("crypto.zig");
pub const debug = @import("debug.zig");
pub const dwarf = @import("dwarf.zig");
pub const elf = @import("elf.zig");
pub const enums = @import("enums.zig");
pub const fifo = @import("fifo.zig");
pub const fmt = @import("fmt.zig");
pub const fs = @import("fs.zig");
pub const gpu = @import("gpu.zig");
pub const hash = @import("hash.zig");
pub const hash_map = @import("hash_map.zig");
pub const heap = @import("heap.zig");
pub const http = @import("http.zig");
pub const io = @import("io.zig");
pub const json = @import("json.zig");
pub const leb = @import("leb128.zig");
pub const log = @import("log.zig");
pub const macho = @import("macho.zig");
pub const math = @import("math.zig");
pub const mem = @import("mem.zig");
pub const meta = @import("meta.zig");
pub const net = @import("net.zig");
pub const os = @import("os.zig");
pub const once = @import("once.zig").once;
pub const pdb = @import("pdb.zig");
pub const posix = @import("posix.zig");
pub const process = @import("process.zig");
pub const sort = @import("sort.zig");
pub const simd = @import("simd.zig");
pub const ascii = @import("ascii.zig");
pub const tar = @import("tar.zig");
pub const testing = @import("testing.zig");
pub const time = @import("time.zig");
pub const tz = @import("tz.zig");
pub const unicode = @import("unicode.zig");
pub const valgrind = @import("valgrind.zig");
pub const wasm = @import("wasm.zig");
pub const zig = @import("zig.zig");
pub const zip = @import("zip.zig");
pub const zon = @import("zon.zig");
pub const start = @import("start.zig");

const root = @import("root");

/// Stdlib-wide options that can be overridden by the root file.
pub const options: Options = if (@hasDecl(root, "std_options")) root.std_options else .{};

pub const Options = struct {
    enable_segfault_handler: bool = debug.default_enable_segfault_handler,

    /// Function used to implement `std.fs.cwd` for WASI.
    wasiCwd: fn () os.wasi.fd_t = fs.defaultWasiCwd,

    /// The current log level.
    log_level: log.Level = log.default_level,

    log_scope_levels: []const log.ScopeLevel = &.{},

    logFn: fn (
        comptime message_level: log.Level,
        comptime scope: @TypeOf(.enum_literal),
        comptime format: []const u8,
        args: anytype,
    ) void = log.defaultLog,

    /// Overrides `std.heap.page_size_min`.
    page_size_min: ?usize = null,
    /// Overrides `std.heap.page_size_max`.
    page_size_max: ?usize = null,
    /// Overrides default implementation for determining OS page size at runtime.
    queryPageSize: fn () usize = heap.defaultQueryPageSize,

    fmt_max_depth: usize = fmt.default_max_depth,

    cryptoRandomSeed: fn (buffer: []u8) void = @import("crypto/tlcsprng.zig").defaultRandomSeed,

    crypto_always_getrandom: bool = false,

    crypto_fork_safety: bool = true,

    /// By default Zig disables SIGPIPE by setting a "no-op" handler for it.  Set this option
    /// to `true` to prevent that.
    ///
    /// Note that we use a "no-op" handler instead of SIG_IGN because it will not be inherited by
    /// any child process.
    ///
    /// SIGPIPE is triggered when a process attempts to write to a broken pipe. By default, SIGPIPE
    /// will terminate the process instead of exiting.  It doesn't trigger the panic handler so in many
    /// cases it's unclear why the process was terminated.  By capturing SIGPIPE instead, functions that
    /// write to broken pipes will return the EPIPE error (error.BrokenPipe) and the program can handle
    /// it like any other error.
    keep_sigpipe: bool = false,

    /// By default, std.http.Client will support HTTPS connections.  Set this option to `true` to
    /// disable TLS support.
    ///
    /// This will likely reduce the size of the binary, but it will also make it impossible to
    /// make a HTTPS connection.
    http_disable_tls: bool = false,

    /// This enables `std.http.Client` to log ssl secrets to the file specified by the SSLKEYLOGFILE
    /// env var.  Creating such a log file allows other programs with access to that file to decrypt
    /// all `std.http.Client` traffic made by this program.
    http_enable_ssl_key_log_file: bool = @import("builtin").mode == .Debug,

    side_channels_mitigations: crypto.SideChannelsMitigations = crypto.default_side_channels_mitigations,
};

// This forces the start.zig file to be imported, and the comptime logic inside that
// file decides whether to export any appropriate start symbols, and call main.
comptime {
    _ = start;
}

test {
    testing.refAllDecls(@This());
}

comptime {
    debug.assert(@import("std") == @This()); // std lib tests require --zig-lib-dir
}
//! Tar archive is single ordinary file which can contain many files (or
//! directories, symlinks, ...). It's build by series of blocks each size of 512
//! bytes. First block of each entry is header which defines type, name, size
//! permissions and other attributes. Header is followed by series of blocks of
//! file content, if any that entry has content. Content is padded to the block
//! size, so next header always starts at block boundary.
//!
//! This simple format is extended by GNU and POSIX pax extensions to support
//! file names longer than 256 bytes and additional attributes.
//!
//! This is not comprehensive tar parser. Here we are only file types needed to
//! support Zig package manager; normal file, directory, symbolic link. And
//! subset of attributes: name, size, permissions.
//!
//! GNU tar reference: https://www.gnu.org/software/tar/manual/html_node/Standard.html
//! pax reference: https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html#tag_20_92_13

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub const writer = @import("tar/writer.zig").writer;

/// Provide this to receive detailed error messages.
/// When this is provided, some errors which would otherwise be returned
/// immediately will instead be added to this structure. The API user must check
/// the errors in diagnostics to know whether the operation succeeded or failed.
pub const Diagnostics = struct {
    allocator: std.mem.Allocator,
    errors: std.ArrayListUnmanaged(Error) = .empty,

    entries: usize = 0,
    root_dir: []const u8 = "",

    pub const Error = union(enum) {
        unable_to_create_sym_link: struct {
            code: anyerror,
            file_name: []const u8,
            link_name: []const u8,
        },
        unable_to_create_file: struct {
            code: anyerror,
            file_name: []const u8,
        },
        unsupported_file_type: struct {
            file_name: []const u8,
            file_type: Header.Kind,
        },
        components_outside_stripped_prefix: struct {
            file_name: []const u8,
        },
    };

    fn findRoot(d: *Diagnostics, kind: FileKind, path: []const u8) !void {
        if (path.len == 0) return;

        d.entries += 1;
        const root_dir = rootDir(path, kind);
        if (d.entries == 1) {
            d.root_dir = try d.allocator.dupe(u8, root_dir);
            return;
        }
        if (d.root_dir.len == 0 or std.mem.eql(u8, root_dir, d.root_dir))
            return;
        d.allocator.free(d.root_dir);
        d.root_dir = "";
    }

    // Returns root dir of the path, assumes non empty path.
    fn rootDir(path: []const u8, kind: FileKind) []const u8 {
        const start_index: usize = if (path[0] == '/') 1 else 0;
        const end_index: usize = if (path[path.len - 1] == '/') path.len - 1 else path.len;
        const buf = path[start_index..end_index];
        if (std.mem.indexOfScalarPos(u8, buf, 0, '/')) |idx| {
            return buf[0..idx];
        }

        return switch (kind) {
            .file => "",
            .sym_link => "",
            .directory => buf,
        };
    }

    test rootDir {
        const expectEqualStrings = testing.expectEqualStrings;
        try expectEqualStrings("", rootDir("a", .file));
        try expectEqualStrings("a", rootDir("a", .directory));
        try expectEqualStrings("b", rootDir("b", .directory));
        try expectEqualStrings("c", rootDir("/c", .directory));
        try expectEqualStrings("d", rootDir("/d/", .directory));
        try expectEqualStrings("a", rootDir("a/b", .directory));
        try expectEqualStrings("a", rootDir("a/b", .file));
        try expectEqualStrings("a", rootDir("a/b/c", .directory));
    }

    pub fn deinit(d: *Diagnostics) void {
        for (d.errors.items) |item| {
            switch (item) {
                .unable_to_create_sym_link => |info| {
                    d.allocator.free(info.file_name);
                    d.allocator.free(info.link_name);
                },
                .unable_to_create_file => |info| {
                    d.allocator.free(info.file_name);
                },
                .unsupported_file_type => |info| {
                    d.allocator.free(info.file_name);
                },
                .components_outside_stripped_prefix => |info| {
                    d.allocator.free(info.file_name);
                },
            }
        }
        d.errors.deinit(d.allocator);
        d.allocator.free(d.root_dir);
        d.* = undefined;
    }
};

/// pipeToFileSystem options
pub const PipeOptions = struct {
    /// Number of directory levels to skip when extracting files.
    strip_components: u32 = 0,
    /// How to handle the "mode" property of files from within the tar file.
    mode_mode: ModeMode = .executable_bit_only,
    /// Prevents creation of empty directories.
    exclude_empty_directories: bool = false,
    /// Collects error messages during unpacking
    diagnostics: ?*Diagnostics = null,

    pub const ModeMode = enum {
        /// The mode from the tar file is completely ignored. Files are created
        /// with the default mode when creating files.
        ignore,
        /// The mode from the tar file is inspected for the owner executable bit
        /// only. This bit is copied to the group and other executable bits.
        /// Other bits of the mode are left as the default when creating files.
        executable_bit_only,
    };
};

const Header = struct {
    const SIZE = 512;
    const MAX_NAME_SIZE = 100 + 1 + 155; // name(100) + separator(1) + prefix(155)
    const LINK_NAME_SIZE = 100;

    bytes: *const [SIZE]u8,

    const Kind = enum(u8) {
        normal_alias = 0,
        normal = '0',
        hard_link = '1',
        symbolic_link = '2',
        character_special = '3',
        block_special = '4',
        directory = '5',
        fifo = '6',
        contiguous = '7',
        global_extended_header = 'g',
        extended_header = 'x',
        // Types 'L' and 'K' are used by the GNU format for a meta file
        // used to store the path or link name for the next file.
        gnu_long_name = 'L',
        gnu_long_link = 'K',
        gnu_sparse = 'S',
        solaris_extended_header = 'X',
        _,
    };

    /// Includes prefix concatenated, if any.
    /// TODO: check against "../" and other nefarious things
    pub fn fullName(header: Header, buffer: []u8) ![]const u8 {
        const n = name(header);
        const p = prefix(header);
        if (buffer.len < n.len + p.len + 1) return error.TarInsufficientBuffer;
        if (!is_ustar(header) or p.len == 0) {
            @memcpy(buffer[0..n.len], n);
            return buffer[0..n.len];
        }
        @memcpy(buffer[0..p.len], p);
        buffer[p.len] = '/';
        @memcpy(buffer[p.len + 1 ..][0..n.len], n);
        return buffer[0 .. p.len + 1 + n.len];
    }

    /// When kind is symbolic_link linked-to name (target_path) is specified in
    /// the linkname field.
    pub fn linkName(header: Header, buffer: []u8) ![]const u8 {
        const link_name = header.str(157, 100);
        if (link_name.len == 0) {
            return buffer[0..0];
        }
        if (buffer.len < link_name.len) return error.TarInsufficientBuffer;
        const buf = buffer[0..link_name.len];
        @memcpy(buf, link_name);
        return buf;
    }

    pub fn name(header: Header) []const u8 {
        return header.str(0, 100);
    }

    pub fn mode(header: Header) !u32 {
        return @intCast(try header.octal(100, 8));
    }

    pub fn size(header: Header) !u64 {
        const start = 124;
        const len = 12;
        const raw = header.bytes[start..][0..len];
        //  If the leading byte is 0xff (255), all the bytes of the field
        //  (including the leading byte) are concatenated in big-endian order,
        //  with the result being a negative number expressed in two’s
        //  complement form.
        if (raw[0] == 0xff) return error.TarNumericValueNegative;
        // If the leading byte is 0x80 (128), the non-leading bytes of the
        // field are concatenated in big-endian order.
        if (raw[0] == 0x80) {
            if (raw[1] != 0 or raw[2] != 0 or raw[3] != 0) return error.TarNumericValueTooBig;
            return std.mem.readInt(u64, raw[4..12], .big);
        }
        return try header.octal(start, len);
    }

    pub fn chksum(header: Header) !u64 {
        return header.octal(148, 8);
    }

    pub fn is_ustar(header: Header) bool {
        const magic = header.bytes[257..][0..6];
        return std.mem.eql(u8, magic[0..5], "ustar") and (magic[5] == 0 or magic[5] == ' ');
    }

    pub fn prefix(header: Header) []const u8 {
        return header.str(345, 155);
    }

    pub fn kind(header: Header) Kind {
        const result: Kind = @enumFromInt(header.bytes[156]);
        if (result == .normal_alias) return .normal;
        return result;
    }

    fn str(header: Header, start: usize, len: usize) []const u8 {
        return nullStr(header.bytes[start .. start + len]);
    }

    fn octal(header: Header, start: usize, len: usize) !u64 {
        const raw = header.bytes[start..][0..len];
        // Zero-filled octal number in ASCII. Each numeric field of width w
        // contains w minus 1 digits, and a null
        const ltrimmed = std.mem.trimLeft(u8, raw, "0 ");
        const rtrimmed = std.mem.trimRight(u8, ltrimmed, " \x00");
        if (rtrimmed.len == 0) return 0;
        return std.fmt.parseInt(u64, rtrimmed, 8) catch return error.TarHeader;
    }

    const Chksums = struct {
        unsigned: u64,
        signed: i64,
    };

    // Sum of all bytes in the header block. The chksum field is treated as if
    // it were filled with spaces (ASCII 32).
    fn computeChksum(header: Header) Chksums {
        var cs: Chksums = .{ .signed = 0, .unsigned = 0 };
        for (header.bytes, 0..) |v, i| {
            const b = if (148 <= i and i < 156) 32 else v; // Treating chksum bytes as spaces.
            cs.unsigned += b;
            cs.signed += @as(i8, @bitCast(b));
        }
        return cs;
    }

    // Checks calculated chksum with value of chksum field.
    // Returns error or valid chksum value.
    // Zero value indicates empty block.
    pub fn checkChksum(header: Header) !u64 {
        const field = try header.chksum();
        const cs = header.computeChksum();
        if (field == 0 and cs.unsigned == 256) return 0;
        if (field != cs.unsigned and field != cs.signed) return error.TarHeaderChksum;
        return field;
    }
};

// Breaks string on first null character.
fn nullStr(str: []const u8) []const u8 {
    for (str, 0..) |c, i| {
        if (c == 0) return str[0..i];
    }
    return str;
}

/// Options for iterator.
/// Buffers should be provided by the caller.
pub const IteratorOptions = struct {
    /// Use a buffer with length `std.fs.max_path_bytes` to match file system capabilities.
    file_name_buffer: []u8,
    /// Use a buffer with length `std.fs.max_path_bytes` to match file system capabilities.
    link_name_buffer: []u8,
    /// Collects error messages during unpacking
    diagnostics: ?*Diagnostics = null,
};

/// Iterates over files in tar archive.
/// `next` returns each file in tar archive.
pub fn iterator(reader: anytype, options: IteratorOptions) Iterator(@TypeOf(reader)) {
    return .{
        .reader = reader,
        .diagnostics = options.diagnostics,
        .file_name_buffer = options.file_name_buffer,
        .link_name_buffer = options.link_name_buffer,
    };
}

/// Type of the file returned by iterator `next` method.
pub const FileKind = enum {
    directory,
    sym_link,
    file,
};

/// Iterator over entries in the tar file represented by reader.
pub fn Iterator(comptime ReaderType: type) type {
    return struct {
        reader: ReaderType,
        diagnostics: ?*Diagnostics = null,

        // buffers for heeader and file attributes
        header_buffer: [Header.SIZE]u8 = undefined,
        file_name_buffer: []u8,
        link_name_buffer: []u8,

        // bytes of padding to the end of the block
        padding: usize = 0,
        // not consumed bytes of file from last next iteration
        unread_file_bytes: u64 = 0,

        pub const File = struct {
            name: []const u8, // name of file, symlink or directory
            link_name: []const u8, // target name of symlink
            size: u64 = 0, // size of the file in bytes
            mode: u32 = 0,
            kind: FileKind = .file,

            unread_bytes: *u64,
            parent_reader: ReaderType,

            pub const Reader = std.io.Reader(File, ReaderType.Error, File.read);

            pub fn reader(self: File) Reader {
                return .{ .context = self };
            }

            pub fn read(self: File, dest: []u8) ReaderType.Error!usize {
                const buf = dest[0..@min(dest.len, self.unread_bytes.*)];
                const n = try self.parent_reader.read(buf);
                self.unread_bytes.* -= n;
                return n;
            }

            // Writes file content to writer.
            pub fn writeAll(self: File, out_writer: anytype) !void {
                var buffer: [4096]u8 = undefined;

                while (self.unread_bytes.* > 0) {
                    const buf = buffer[0..@min(buffer.len, self.unread_bytes.*)];
                    try self.parent_reader.readNoEof(buf);
                    try out_writer.writeAll(buf);
                    self.unread_bytes.* -= buf.len;
                }
            }
        };

        const Self = @This();

        fn readHeader(self: *Self) !?Header {
            if (self.padding > 0) {
                try self.reader.skipBytes(self.padding, .{});
            }
            const n = try self.reader.readAll(&self.header_buffer);
            if (n == 0) return null;
            if (n < Header.SIZE) return error.UnexpectedEndOfStream;
            const header = Header{ .bytes = self.header_buffer[0..Header.SIZE] };
            if (try header.checkChksum() == 0) return null;
            return header;
        }

        fn readString(self: *Self, size: usize, buffer: []u8) ![]const u8 {
            if (size > buffer.len) return error.TarInsufficientBuffer;
            const buf = buffer[0..size];
            try self.reader.readNoEof(buf);
            return nullStr(buf);
        }

        fn newFile(self: *Self) File {
            return .{
                .name = self.file_name_buffer[0..0],
                .link_name = self.link_name_buffer[0..0],
                .parent_reader = self.reader,
                .unread_bytes = &self.unread_file_bytes,
            };
        }

        // Number of padding bytes in the last file block.
        fn blockPadding(size: u64) usize {
            const block_rounded = std.mem.alignForward(u64, size, Header.SIZE); // size rounded to te block boundary
            return @intCast(block_rounded - size);
        }

        /// Iterates through the tar archive as if it is a series of files.
        /// Internally, the tar format often uses entries (header with optional
        /// content) to add meta data that describes the next file. These
        /// entries should not normally be visible to the outside. As such, this
        /// loop iterates through one or more entries until it collects a all
        /// file attributes.
        pub fn next(self: *Self) !?File {
            if (self.unread_file_bytes > 0) {
                // If file content was not consumed by caller
                try self.reader.skipBytes(self.unread_file_bytes, .{});
                self.unread_file_bytes = 0;
            }
            var file: File = self.newFile();

            while (try self.readHeader()) |header| {
                const kind = header.kind();
                const size: u64 = try header.size();
                self.padding = blockPadding(size);

                switch (kind) {
                    // File types to return upstream
                    .directory, .normal, .symbolic_link => {
                        file.kind = switch (kind) {
                            .directory => .directory,
                            .normal => .file,
                            .symbolic_link => .sym_link,
                            else => unreachable,
                        };
                        file.mode = try header.mode();

                        // set file attributes if not already set by prefix/extended headers
                        if (file.size == 0) {
                            file.size = size;
                        }
                        if (file.link_name.len == 0) {
                            file.link_name = try header.linkName(self.link_name_buffer);
                        }
                        if (file.name.len == 0) {
                            file.name = try header.fullName(self.file_name_buffer);
                        }

                        self.padding = blockPadding(file.size);
                        self.unread_file_bytes = file.size;
                        return file;
                    },
                    // Prefix header types
                    .gnu_long_name => {
                        file.name = try self.readString(@intCast(size), self.file_name_buffer);
                    },
                    .gnu_long_link => {
                        file.link_name = try self.readString(@intCast(size), self.link_name_buffer);
                    },
                    .extended_header => {
                        // Use just attributes from last extended header.
                        file = self.newFile();

                        var rdr = paxIterator(self.reader, @intCast(size));
                        while (try rdr.next()) |attr| {
                            switch (attr.kind) {
                                .path => {
                                    file.name = try attr.value(self.file_name_buffer);
                                },
                                .linkpath => {
                                    file.link_name = try attr.value(self.link_name_buffer);
                                },
                                .size => {
                                    var buf: [pax_max_size_attr_len]u8 = undefined;
 ```
