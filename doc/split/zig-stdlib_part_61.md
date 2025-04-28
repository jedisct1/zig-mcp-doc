```
st;
        while (it) |node| : (it = node.next) {
            // Compute the actually allocated size excluding the
            // linked list node.
            const buf_node: *BufNode = @fieldParentPtr("node", node);
            size += buf_node.data - @sizeOf(BufNode);
        }
        return size;
    }
    /// Resets the arena allocator and frees all allocated memory.
    ///
    /// `mode` defines how the currently allocated memory is handled.
    /// See the variant documentation for `ResetMode` for the effects of each mode.
    ///
    /// The function will return whether the reset operation was successful or not.
    /// If the reallocation  failed `false` is returned. The arena will still be fully
    /// functional in that case, all memory is released. Future allocations just might
    /// be slower.
    ///
    /// NOTE: If `mode` is `free_all`, the function will always return `true`.
    pub fn reset(self: *ArenaAllocator, mode: ResetMode) bool {
        // Some words on the implementation:
        // The reset function can be implemented with two basic approaches:
        // - Counting how much bytes were allocated since the last reset, and storing that
        //   information in State. This will make reset fast and alloc only a teeny tiny bit
        //   slower.
        // - Counting how much bytes were allocated by iterating the chunk linked list. This
        //   will make reset slower, but alloc() keeps the same speed when reset() as if reset()
        //   would not exist.
        //
        // The second variant was chosen for implementation, as with more and more calls to reset(),
        // the function will get faster and faster. At one point, the complexity of the function
        // will drop to amortized O(1), as we're only ever having a single chunk that will not be
        // reallocated, and we're not even touching the backing allocator anymore.
        //
        // Thus, only the first hand full of calls to reset() will actually need to iterate the linked
        // list, all future calls are just taking the first node, and only resetting the `end_index`
        // value.
        const requested_capacity = switch (mode) {
            .retain_capacity => self.queryCapacity(),
            .retain_with_limit => |limit| @min(limit, self.queryCapacity()),
            .free_all => 0,
        };
        if (requested_capacity == 0) {
            // just reset when we don't have anything to reallocate
            self.deinit();
            self.state = State{};
            return true;
        }
        const total_size = requested_capacity + @sizeOf(BufNode);
        // Free all nodes except for the last one
        var it = self.state.buffer_list.first;
        const maybe_first_node = while (it) |node| {
            // this has to occur before the free because the free frees node
            const next_it = node.next;
            if (next_it == null)
                break node;
            const buf_node: *BufNode = @fieldParentPtr("node", node);
            const alloc_buf = @as([*]u8, @ptrCast(buf_node))[0..buf_node.data];
            self.child_allocator.rawFree(alloc_buf, BufNode_alignment, @returnAddress());
            it = next_it;
        } else null;
        std.debug.assert(maybe_first_node == null or maybe_first_node.?.next == null);
        // reset the state before we try resizing the buffers, so we definitely have reset the arena to 0.
        self.state.end_index = 0;
        if (maybe_first_node) |first_node| {
            self.state.buffer_list.first = first_node;
            // perfect, no need to invoke the child_allocator
            const first_buf_node: *BufNode = @fieldParentPtr("node", first_node);
            if (first_buf_node.data == total_size)
                return true;
            const first_alloc_buf = @as([*]u8, @ptrCast(first_buf_node))[0..first_buf_node.data];
            if (self.child_allocator.rawResize(first_alloc_buf, BufNode_alignment, total_size, @returnAddress())) {
                // successful resize
                first_buf_node.data = total_size;
            } else {
                // manual realloc
                const new_ptr = self.child_allocator.rawAlloc(total_size, BufNode_alignment, @returnAddress()) orelse {
                    // we failed to preheat the arena properly, signal this to the user.
                    return false;
                };
                self.child_allocator.rawFree(first_alloc_buf, BufNode_alignment, @returnAddress());
                const buf_node: *BufNode = @ptrCast(@alignCast(new_ptr));
                buf_node.* = .{ .data = total_size };
                self.state.buffer_list.first = &buf_node.node;
            }
        }
        return true;
    }

    fn createNode(self: *ArenaAllocator, prev_len: usize, minimum_size: usize) ?*BufNode {
        const actual_min_size = minimum_size + (@sizeOf(BufNode) + 16);
        const big_enough_len = prev_len + actual_min_size;
        const len = big_enough_len + big_enough_len / 2;
        const ptr = self.child_allocator.rawAlloc(len, BufNode_alignment, @returnAddress()) orelse
            return null;
        const buf_node: *BufNode = @ptrCast(@alignCast(ptr));
        buf_node.* = .{ .data = len };
        self.state.buffer_list.prepend(&buf_node.node);
        self.state.end_index = 0;
        return buf_node;
    }

    fn alloc(ctx: *anyopaque, n: usize, alignment: Alignment, ra: usize) ?[*]u8 {
        const self: *ArenaAllocator = @ptrCast(@alignCast(ctx));
        _ = ra;

        const ptr_align = alignment.toByteUnits();
        var cur_node: *BufNode = if (self.state.buffer_list.first) |first_node|
            @fieldParentPtr("node", first_node)
        else
            (self.createNode(0, n + ptr_align) orelse return null);
        while (true) {
            const cur_alloc_buf = @as([*]u8, @ptrCast(cur_node))[0..cur_node.data];
            const cur_buf = cur_alloc_buf[@sizeOf(BufNode)..];
            const addr = @intFromPtr(cur_buf.ptr) + self.state.end_index;
            const adjusted_addr = mem.alignForward(usize, addr, ptr_align);
            const adjusted_index = self.state.end_index + (adjusted_addr - addr);
            const new_end_index = adjusted_index + n;

            if (new_end_index <= cur_buf.len) {
                const result = cur_buf[adjusted_index..new_end_index];
                self.state.end_index = new_end_index;
                return result.ptr;
            }

            const bigger_buf_size = @sizeOf(BufNode) + new_end_index;
            if (self.child_allocator.rawResize(cur_alloc_buf, BufNode_alignment, bigger_buf_size, @returnAddress())) {
                cur_node.data = bigger_buf_size;
            } else {
                // Allocate a new node if that's not possible
                cur_node = self.createNode(cur_buf.len, n + ptr_align) orelse return null;
            }
        }
    }

    fn resize(ctx: *anyopaque, buf: []u8, alignment: Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *ArenaAllocator = @ptrCast(@alignCast(ctx));
        _ = alignment;
        _ = ret_addr;

        const cur_node = self.state.buffer_list.first orelse return false;
        const cur_buf_node: *BufNode = @fieldParentPtr("node", cur_node);
        const cur_buf = @as([*]u8, @ptrCast(cur_buf_node))[@sizeOf(BufNode)..cur_buf_node.data];
        if (@intFromPtr(cur_buf.ptr) + self.state.end_index != @intFromPtr(buf.ptr) + buf.len) {
            // It's not the most recent allocation, so it cannot be expanded,
            // but it's fine if they want to make it smaller.
            return new_len <= buf.len;
        }

        if (buf.len >= new_len) {
            self.state.end_index -= buf.len - new_len;
            return true;
        } else if (cur_buf.len - self.state.end_index >= new_len - buf.len) {
            self.state.end_index += new_len - buf.len;
            return true;
        } else {
            return false;
        }
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        return if (resize(context, memory, alignment, new_len, return_address)) memory.ptr else null;
    }

    fn free(ctx: *anyopaque, buf: []u8, alignment: Alignment, ret_addr: usize) void {
        _ = alignment;
        _ = ret_addr;

        const self: *ArenaAllocator = @ptrCast(@alignCast(ctx));

        const cur_node = self.state.buffer_list.first orelse return;
        const cur_buf_node: *BufNode = @fieldParentPtr("node", cur_node);
        const cur_buf = @as([*]u8, @ptrCast(cur_buf_node))[@sizeOf(BufNode)..cur_buf_node.data];

        if (@intFromPtr(cur_buf.ptr) + self.state.end_index == @intFromPtr(buf.ptr) + buf.len) {
            self.state.end_index -= buf.len;
        }
    }
};

test "reset with preheating" {
    var arena_allocator = ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    // provides some variance in the allocated data
    var rng_src = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = rng_src.random();
    var rounds: usize = 25;
    while (rounds > 0) {
        rounds -= 1;
        _ = arena_allocator.reset(.retain_capacity);
        var alloced_bytes: usize = 0;
        const total_size: usize = random.intRangeAtMost(usize, 256, 16384);
        while (alloced_bytes < total_size) {
            const size = random.intRangeAtMost(usize, 16, 256);
            const alignment: Alignment = .@"32";
            const slice = try arena_allocator.allocator().alignedAlloc(u8, alignment, size);
            try std.testing.expect(alignment.check(@intFromPtr(slice.ptr)));
            try std.testing.expectEqual(size, slice.len);
            alloced_bytes += slice.len;
        }
    }
}

test "reset while retaining a buffer" {
    var arena_allocator = ArenaAllocator.init(std.testing.allocator);
    defer arena_allocator.deinit();
    const a = arena_allocator.allocator();

    // Create two internal buffers
    _ = try a.alloc(u8, 1);
    _ = try a.alloc(u8, 1000);

    // Check that we have at least two buffers
    try std.testing.expect(arena_allocator.state.buffer_list.first.?.next != null);

    // This retains the first allocated buffer
    try std.testing.expect(arena_allocator.reset(.{ .retain_with_limit = 1 }));
}
//! An allocator that is intended to be used in Debug mode.
//!
//! ## Features
//!
//! * Captures stack traces on allocation, free, and optionally resize.
//! * Double free detection, which prints all three traces (first alloc, first
//!   free, second free).
//! * Leak detection, with stack traces.
//! * Never reuses memory addresses, making it easier for Zig to detect branch
//!   on undefined values in case of dangling pointers. This relies on
//!   the backing allocator to also not reuse addresses.
//! * Uses a minimum backing allocation size to avoid operating system errors
//!   from having too many active memory mappings.
//! * When a page of memory is no longer needed, give it back to resident
//!   memory as soon as possible, so that it causes page faults when used.
//! * Cross platform. Operates based on a backing allocator which makes it work
//!   everywhere, even freestanding.
//! * Compile-time configuration.
//!
//! These features require the allocator to be quite slow and wasteful. For
//! example, when allocating a single byte, the efficiency is less than 1%;
//! it requires more than 100 bytes of overhead to manage the allocation for
//! one byte. The efficiency gets better with larger allocations.
//!
//! ## Basic Design
//!
//! Allocations are divided into two categories, small and large.
//!
//! Small allocations are divided into buckets based on `page_size`:
//!
//! ```
//! index obj_size
//! 0     1
//! 1     2
//! 2     4
//! 3     8
//! 4     16
//! 5     32
//! 6     64
//! 7     128
//! 8     256
//! 9     512
//! 10    1024
//! 11    2048
//! ...
//! ```
//!
//! This goes on for `small_bucket_count` indexes.
//!
//! Allocations are grouped into an object size based on max(len, alignment),
//! rounded up to the next power of two.
//!
//! The main allocator state has an array of all the "current" buckets for each
//! size class. Each slot in the array can be null, meaning the bucket for that
//! size class is not allocated. When the first object is allocated for a given
//! size class, it makes one `page_size` allocation from the backing allocator.
//! This allocation is divided into "slots" - one per allocated object, leaving
//! room for the allocation metadata (starting with `BucketHeader`), which is
//! located at the very end of the "page".
//!
//! The allocation metadata includes "used bits" - 1 bit per slot representing
//! whether the slot is used. Allocations always take the next available slot
//! from the current bucket, setting the corresponding used bit, as well as
//! incrementing `allocated_count`.
//!
//! Frees recover the allocation metadata based on the address, length, and
//! alignment, relying on the backing allocation's large alignment, combined
//! with the fact that allocations are never moved from small to large, or vice
//! versa.
//!
//! When a bucket is full, a new one is allocated, containing a pointer to the
//! previous one. This singly-linked list is iterated during leak detection.
//!
//! Resizing and remapping work the same on small allocations: if the size
//! class would not change, then the operation succeeds, and the address is
//! unchanged. Otherwise, the request is rejected.
//!
//! Large objects are allocated directly using the backing allocator. Metadata
//! is stored separately in a `std.HashMap` using the backing allocator.
//!
//! Resizing and remapping are forwarded directly to the backing allocator,
//! except where such operations would change the category from large to small.

const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.gpa);
const math = std.math;
const assert = std.debug.assert;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const StackTrace = std.builtin.StackTrace;

const default_page_size: usize = switch (builtin.os.tag) {
    // Makes `std.heap.PageAllocator` take the happy path.
    .windows => 64 * 1024,
    else => switch (builtin.cpu.arch) {
        // Max alignment supported by `std.heap.WasmAllocator`.
        .wasm32, .wasm64 => 64 * 1024,
        // Avoids too many active mappings when `page_size_max` is low.
        else => @max(std.heap.page_size_max, 128 * 1024),
    },
};

const Log2USize = std.math.Log2Int(usize);

const default_sys_stack_trace_frames: usize = if (std.debug.sys_can_stack_trace) 6 else 0;
const default_stack_trace_frames: usize = switch (builtin.mode) {
    .Debug => default_sys_stack_trace_frames,
    else => 0,
};

pub const Config = struct {
    /// Number of stack frames to capture.
    stack_trace_frames: usize = default_stack_trace_frames,

    /// If true, the allocator will have two fields:
    ///  * `total_requested_bytes` which tracks the total allocated bytes of memory requested.
    ///  * `requested_memory_limit` which causes allocations to return `error.OutOfMemory`
    ///    when the `total_requested_bytes` exceeds this limit.
    /// If false, these fields will be `void`.
    enable_memory_limit: bool = false,

    /// Whether to enable safety checks.
    safety: bool = std.debug.runtime_safety,

    /// Whether the allocator may be used simultaneously from multiple threads.
    thread_safe: bool = !builtin.single_threaded,

    /// What type of mutex you'd like to use, for thread safety.
    /// when specified, the mutex type must have the same shape as `std.Thread.Mutex` and
    /// `DummyMutex`, and have no required fields. Specifying this field causes
    /// the `thread_safe` field to be ignored.
    ///
    /// when null (default):
    /// * the mutex type defaults to `std.Thread.Mutex` when thread_safe is enabled.
    /// * the mutex type defaults to `DummyMutex` otherwise.
    MutexType: ?type = null,

    /// This is a temporary debugging trick you can use to turn segfaults into more helpful
    /// logged error messages with stack trace details. The downside is that every allocation
    /// will be leaked, unless used with retain_metadata!
    never_unmap: bool = false,

    /// This is a temporary debugging aid that retains metadata about allocations indefinitely.
    /// This allows a greater range of double frees to be reported. All metadata is freed when
    /// deinit is called. When used with never_unmap, deliberately leaked memory is also freed
    /// during deinit. Currently should be used with never_unmap to avoid segfaults.
    /// TODO https://github.com/ziglang/zig/issues/4298 will allow use without never_unmap
    retain_metadata: bool = false,

    /// Enables emitting info messages with the size and address of every allocation.
    verbose_log: bool = false,

    /// Tell whether the backing allocator returns already-zeroed memory.
    backing_allocator_zeroes: bool = true,

    /// When resizing an allocation, refresh the stack trace with the resize
    /// callsite. Comes with a performance penalty.
    resize_stack_traces: bool = false,

    /// Magic value that distinguishes allocations owned by this allocator from
    /// other regions of memory.
    canary: usize = @truncate(0x9232a6ff85dff10f),

    /// The size of allocations requested from the backing allocator for
    /// subdividing into slots for small allocations.
    ///
    /// Must be a power of two.
    page_size: usize = default_page_size,
};

/// Default initialization of this struct is deprecated; use `.init` instead.
pub fn DebugAllocator(comptime config: Config) type {
    return struct {
        backing_allocator: Allocator = std.heap.page_allocator,
        /// Tracks the active bucket, which is the one that has free slots in it.
        buckets: [small_bucket_count]?*BucketHeader = [1]?*BucketHeader{null} ** small_bucket_count,
        large_allocations: LargeAllocTable = .empty,
        total_requested_bytes: @TypeOf(total_requested_bytes_init) = total_requested_bytes_init,
        requested_memory_limit: @TypeOf(requested_memory_limit_init) = requested_memory_limit_init,
        mutex: @TypeOf(mutex_init) = mutex_init,

        const Self = @This();

        pub const init: Self = .{};

        /// These can be derived from size_class_index but the calculation is nontrivial.
        const slot_counts: [small_bucket_count]SlotIndex = init: {
            @setEvalBranchQuota(10000);
            var result: [small_bucket_count]SlotIndex = undefined;
            for (&result, 0..) |*elem, i| elem.* = calculateSlotCount(i);
            break :init result;
        };

        comptime {
            assert(math.isPowerOfTwo(page_size));
        }

        const page_size = config.page_size;
        const page_align: mem.Alignment = .fromByteUnits(page_size);
        /// Integer type for pointing to slots in a small allocation
        const SlotIndex = std.meta.Int(.unsigned, math.log2(page_size) + 1);

        const total_requested_bytes_init = if (config.enable_memory_limit) @as(usize, 0) else {};
        const requested_memory_limit_init = if (config.enable_memory_limit) @as(usize, math.maxInt(usize)) else {};

        const mutex_init = if (config.MutexType) |T|
            T{}
        else if (config.thread_safe)
            std.Thread.Mutex{}
        else
            DummyMutex{};

        const DummyMutex = struct {
            inline fn lock(_: *DummyMutex) void {}
            inline fn unlock(_: *DummyMutex) void {}
        };

        const stack_n = config.stack_trace_frames;
        const one_trace_size = @sizeOf(usize) * stack_n;
        const traces_per_slot = 2;

        pub const Error = mem.Allocator.Error;

        /// Avoids creating buckets that would only be able to store a small
        /// number of slots. Value of 1 means 2 is the minimum slot count.
        const minimum_slots_per_bucket_log2 = 1;
        const small_bucket_count = math.log2(page_size) - minimum_slots_per_bucket_log2;
        const largest_bucket_object_size = 1 << (small_bucket_count - 1);
        const LargestSizeClassInt = std.math.IntFittingRange(0, largest_bucket_object_size);

        const bucketCompare = struct {
            fn compare(a: *BucketHeader, b: *BucketHeader) std.math.Order {
                return std.math.order(@intFromPtr(a.page), @intFromPtr(b.page));
            }
        }.compare;

        const LargeAlloc = struct {
            bytes: []u8,
            requested_size: if (config.enable_memory_limit) usize else void,
            stack_addresses: [trace_n][stack_n]usize,
            freed: if (config.retain_metadata) bool else void,
            alignment: if (config.never_unmap and config.retain_metadata) mem.Alignment else void,

            const trace_n = if (config.retain_metadata) traces_per_slot else 1;

            fn dumpStackTrace(self: *LargeAlloc, trace_kind: TraceKind) void {
                std.debug.dumpStackTrace(self.getStackTrace(trace_kind));
            }

            fn getStackTrace(self: *LargeAlloc, trace_kind: TraceKind) std.builtin.StackTrace {
                assert(@intFromEnum(trace_kind) < trace_n);
                const stack_addresses = &self.stack_addresses[@intFromEnum(trace_kind)];
                var len: usize = 0;
                while (len < stack_n and stack_addresses[len] != 0) {
                    len += 1;
                }
                return .{
                    .instruction_addresses = stack_addresses,
                    .index = len,
                };
            }

            fn captureStackTrace(self: *LargeAlloc, ret_addr: usize, trace_kind: TraceKind) void {
                assert(@intFromEnum(trace_kind) < trace_n);
                const stack_addresses = &self.stack_addresses[@intFromEnum(trace_kind)];
                collectStackTrace(ret_addr, stack_addresses);
            }
        };
        const LargeAllocTable = std.AutoHashMapUnmanaged(usize, LargeAlloc);

        /// Bucket: In memory, in order:
        /// * BucketHeader
        /// * bucket_used_bits: [N]usize, // 1 bit for every slot
        /// -- below only exists when config.safety is true --
        /// * requested_sizes: [N]LargestSizeClassInt // 1 int for every slot
        /// * log2_ptr_aligns: [N]u8 // 1 byte for every slot
        /// -- above only exists when config.safety is true --
        /// * stack_trace_addresses: [N]usize, // traces_per_slot for every allocation
        const BucketHeader = struct {
            allocated_count: SlotIndex,
            freed_count: SlotIndex,
            prev: ?*BucketHeader,
            next: ?*BucketHeader,
            canary: usize = config.canary,

            fn fromPage(page_addr: usize, slot_count: usize) *BucketHeader {
                const unaligned = page_addr + page_size - bucketSize(slot_count);
                return @ptrFromInt(unaligned & ~(@as(usize, @alignOf(BucketHeader)) - 1));
            }

            fn usedBits(bucket: *BucketHeader, index: usize) *usize {
                const ptr: [*]u8 = @ptrCast(bucket);
                const bits: [*]usize = @alignCast(@ptrCast(ptr + @sizeOf(BucketHeader)));
                return &bits[index];
            }

            fn requestedSizes(bucket: *BucketHeader, slot_count: usize) []LargestSizeClassInt {
                if (!config.safety) @compileError("requested size is only stored when safety is enabled");
                const start_ptr = @as([*]u8, @ptrCast(bucket)) + bucketRequestedSizesStart(slot_count);
                const sizes = @as([*]LargestSizeClassInt, @ptrCast(@alignCast(start_ptr)));
                return sizes[0..slot_count];
            }

            fn log2PtrAligns(bucket: *BucketHeader, slot_count: usize) []mem.Alignment {
                if (!config.safety) @compileError("requested size is only stored when safety is enabled");
                const aligns_ptr = @as([*]u8, @ptrCast(bucket)) + bucketAlignsStart(slot_count);
                return @ptrCast(aligns_ptr[0..slot_count]);
            }

            fn stackTracePtr(
                bucket: *BucketHeader,
                slot_count: usize,
                slot_index: SlotIndex,
                trace_kind: TraceKind,
            ) *[stack_n]usize {
                const start_ptr = @as([*]u8, @ptrCast(bucket)) + bucketStackFramesStart(slot_count);
                const addr = start_ptr + one_trace_size * traces_per_slot * slot_index +
                    @intFromEnum(trace_kind) * @as(usize, one_trace_size);
                return @ptrCast(@alignCast(addr));
            }

            fn captureStackTrace(
                bucket: *BucketHeader,
                ret_addr: usize,
                slot_count: usize,
                slot_index: SlotIndex,
                trace_kind: TraceKind,
            ) void {
                // Initialize them to 0. When determining the count we must look
                // for non zero addresses.
                const stack_addresses = bucket.stackTracePtr(slot_count, slot_index, trace_kind);
                collectStackTrace(ret_addr, stack_addresses);
            }
        };

        pub fn allocator(self: *Self) Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }

        fn bucketStackTrace(
            bucket: *BucketHeader,
            slot_count: usize,
            slot_index: SlotIndex,
            trace_kind: TraceKind,
        ) StackTrace {
            const stack_addresses = bucket.stackTracePtr(slot_count, slot_index, trace_kind);
            var len: usize = 0;
            while (len < stack_n and stack_addresses[len] != 0) {
                len += 1;
            }
            return .{
                .instruction_addresses = stack_addresses,
                .index = len,
            };
        }

        fn bucketRequestedSizesStart(slot_count: usize) usize {
            if (!config.safety) @compileError("requested sizes are not stored unless safety is enabled");
            return mem.alignForward(
                usize,
                @sizeOf(BucketHeader) + usedBitsSize(slot_count),
                @alignOf(LargestSizeClassInt),
            );
        }

        fn bucketAlignsStart(slot_count: usize) usize {
            if (!config.safety) @compileError("requested sizes are not stored unless safety is enabled");
            return bucketRequestedSizesStart(slot_count) + (@sizeOf(LargestSizeClassInt) * slot_count);
        }

        fn bucketStackFramesStart(slot_count: usize) usize {
            const unaligned_start = if (config.safety)
                bucketAlignsStart(slot_count) + slot_count
            else
                @sizeOf(BucketHeader) + usedBitsSize(slot_count);
            return mem.alignForward(usize, unaligned_start, @alignOf(usize));
        }

        fn bucketSize(slot_count: usize) usize {
            return bucketStackFramesStart(slot_count) + one_trace_size * traces_per_slot * slot_count;
        }

        /// This is executed only at compile-time to prepopulate a lookup table.
        fn calculateSlotCount(size_class_index: usize) SlotIndex {
            const size_class = @as(usize, 1) << @as(Log2USize, @intCast(size_class_index));
            var lower: usize = 1 << minimum_slots_per_bucket_log2;
            var upper: usize = (page_size - bucketSize(lower)) / size_class;
            while (upper > lower) {
                const proposed: usize = lower + (upper - lower) / 2;
                if (proposed == lower) return lower;
                const slots_end = proposed * size_class;
                const header_begin = mem.alignForward(usize, slots_end, @alignOf(BucketHeader));
                const end = header_begin + bucketSize(proposed);
                if (end > page_size) {
                    upper = proposed - 1;
                } else {
                    lower = proposed;
                }
            }
            const slots_end = lower * size_class;
            const header_begin = mem.alignForward(usize, slots_end, @alignOf(BucketHeader));
            const end = header_begin + bucketSize(lower);
            assert(end <= page_size);
            return lower;
        }

        fn usedBitsCount(slot_count: usize) usize {
            return (slot_count + (@bitSizeOf(usize) - 1)) / @bitSizeOf(usize);
        }

        fn usedBitsSize(slot_count: usize) usize {
            return usedBitsCount(slot_count) * @sizeOf(usize);
        }

        fn detectLeaksInBucket(bucket: *BucketHeader, size_class_index: usize, used_bits_count: usize) bool {
            const size_class = @as(usize, 1) << @as(Log2USize, @intCast(size_class_index));
            const slot_count = slot_counts[size_class_index];
            var leaks = false;
            for (0..used_bits_count) |used_bits_byte| {
                const used_int = bucket.usedBits(used_bits_byte).*;
                if (used_int != 0) {
                    for (0..@bitSizeOf(usize)) |bit_index_usize| {
                        const bit_index: Log2USize = @intCast(bit_index_usize);
                        const is_used = @as(u1, @truncate(used_int >> bit_index)) != 0;
                        if (is_used) {
                            const slot_index: SlotIndex = @intCast(used_bits_byte * @bitSizeOf(usize) + bit_index);
                            const stack_trace = bucketStackTrace(bucket, slot_count, slot_index, .alloc);
                            const page_addr = @intFromPtr(bucket) & ~(page_size - 1);
                            const addr = page_addr + slot_index * size_class;
                            log.err("memory address 0x{x} leaked: {}", .{ addr, stack_trace });
                            leaks = true;
                        }
                    }
                }
            }
            return leaks;
        }

        /// Emits log messages for leaks and then returns whether there were any leaks.
        pub fn detectLeaks(self: *Self) bool {
            var leaks = false;

            for (self.buckets, 0..) |init_optional_bucket, size_class_index| {
                var optional_bucket = init_optional_bucket;
                const slot_count = slot_counts[size_class_index];
                const used_bits_count = usedBitsCount(slot_count);
                while (optional_bucket) |bucket| {
                    leaks = detectLeaksInBucket(bucket, size_class_index, used_bits_count) or leaks;
                    optional_bucket = bucket.prev;
                }
            }

            var it = self.large_allocations.valueIterator();
            while (it.next()) |large_alloc| {
                if (config.retain_metadata and large_alloc.freed) continue;
                const stack_trace = large_alloc.getStackTrace(.alloc);
                log.err("memory address 0x{x} leaked: {}", .{
                    @intFromPtr(large_alloc.bytes.ptr), stack_trace,
                });
                leaks = true;
            }
            return leaks;
        }

        fn freeRetainedMetadata(self: *Self) void {
            comptime assert(config.retain_metadata);
            if (config.never_unmap) {
                // free large allocations that were intentionally leaked by never_unmap
                var it = self.large_allocations.iterator();
                while (it.next()) |large| {
                    if (large.value_ptr.freed) {
                        self.backing_allocator.rawFree(large.value_ptr.bytes, large.value_ptr.alignment, @returnAddress());
                    }
                }
            }
        }

        pub fn flushRetainedMetadata(self: *Self) void {
            comptime assert(config.retain_metadata);
            self.freeRetainedMetadata();
            // also remove entries from large_allocations
            var it = self.large_allocations.iterator();
            while (it.next()) |large| {
                if (large.value_ptr.freed) {
                    _ = self.large_allocations.remove(@intFromPtr(large.value_ptr.bytes.ptr));
                }
            }
        }

        /// Returns `std.heap.Check.leak` if there were leaks; `std.heap.Check.ok` otherwise.
        pub fn deinit(self: *Self) std.heap.Check {
            const leaks = if (config.safety) self.detectLeaks() else false;
            if (config.retain_metadata) self.freeRetainedMetadata();
            self.large_allocations.deinit(self.backing_allocator);
            self.* = undefined;
            return if (leaks) .leak else .ok;
        }

        fn collectStackTrace(first_trace_addr: usize, addresses: *[stack_n]usize) void {
            if (stack_n == 0) return;
            @memset(addresses, 0);
            var stack_trace: StackTrace = .{
                .instruction_addresses = addresses,
                .index = 0,
            };
            std.debug.captureStackTrace(first_trace_addr, &stack_trace);
        }

        fn reportDoubleFree(ret_addr: usize, alloc_stack_trace: StackTrace, free_stack_trace: StackTrace) void {
            var addresses: [stack_n]usize = @splat(0);
            var second_free_stack_trace: StackTrace = .{
                .instruction_addresses = &addresses,
                .index = 0,
            };
            std.debug.captureStackTrace(ret_addr, &second_free_stack_trace);
            log.err("Double free detected. Allocation: {} First free: {} Second free: {}", .{
                alloc_stack_trace, free_stack_trace, second_free_stack_trace,
            });
        }

        /// This function assumes the object is in the large object storage regardless
        /// of the parameters.
        fn resizeLarge(
            self: *Self,
            old_mem: []u8,
            alignment: mem.Alignment,
            new_size: usize,
            ret_addr: usize,
            may_move: bool,
        ) ?[*]u8 {
            if (config.retain_metadata and may_move) {
                // Before looking up the entry (since this could invalidate
                // it), we must reserve space for the new entry in case the
                // allocation is relocated.
                self.large_allocations.ensureUnusedCapacity(self.backing_allocator, 1) catch return null;
            }

            const entry = self.large_allocations.getEntry(@intFromPtr(old_mem.ptr)) orelse {
                if (config.safety) {
                    @panic("Invalid free");
                } else {
                    unreachable;
                }
            };

            if (config.retain_metadata and entry.value_ptr.freed) {
                if (config.safety) {
                    reportDoubleFree(ret_addr, entry.value_ptr.getStackTrace(.alloc), entry.value_ptr.getStackTrace(.free));
                    @panic("Unrecoverable double free");
                } else {
                    unreachable;
                }
            }

            if (config.safety and old_mem.len != entry.value_ptr.bytes.len) {
                var addresses: [stack_n]usize = [1]usize{0} ** stack_n;
                var free_stack_trace: StackTrace = .{
                    .instruction_addresses = &addresses,
                    .index = 0,
                };
                std.debug.captureStackTrace(ret_addr, &free_stack_trace);
                log.err("Allocation size {d} bytes does not match free size {d}. Allocation: {} Free: {}", .{
                    entry.value_ptr.bytes.len,
                    old_mem.len,
                    entry.value_ptr.getStackTrace(.alloc),
                    free_stack_trace,
                });
            }

            // If this would move the allocation into a small size class,
            // refuse the request, because it would require creating small
            // allocation metadata.
            const new_size_class_index: usize = @max(@bitSizeOf(usize) - @clz(new_size - 1), @intFromEnum(alignment));
            if (new_size_class_index < self.buckets.len) return null;

            // Do memory limit accounting with requested sizes rather than what
            // backing_allocator returns because if we want to return
            // error.OutOfMemory, we have to leave allocation untouched, and
            // that is impossible to guarantee after calling
            // backing_allocator.rawResize.
            const prev_req_bytes = self.total_requested_bytes;
            if (config.enable_memory_limit) {
                const new_req_bytes = prev_req_bytes + new_size - entry.value_ptr.requested_size;
                if (new_req_bytes > prev_req_bytes and new_req_bytes > self.requested_memory_limit) {
                    return null;
                }
                self.total_requested_bytes = new_req_bytes;
            }

            const opt_resized_ptr = if (may_move)
                self.backing_allocator.rawRemap(old_mem, alignment, new_size, ret_addr)
            else if (self.backing_allocator.rawResize(old_mem, alignment, new_size, ret_addr))
                old_mem.ptr
            else
                null;

            const resized_ptr = opt_resized_ptr orelse {
                if (config.enable_memory_limit) {
                    self.total_requested_bytes = prev_req_bytes;
                }
                return null;
            };

            if (config.enable_memory_limit) {
                entry.value_ptr.requested_size = new_size;
            }

            if (config.verbose_log) {
                log.info("large resize {d} bytes at {*} to {d} at {*}", .{
                    old_mem.len, old_mem.ptr, new_size, resized_ptr,
                });
            }
            entry.value_ptr.bytes = resized_ptr[0..new_size];
            if (config.resize_stack_traces)
                entry.value_ptr.captureStackTrace(ret_addr, .alloc);

            // Update the key of the hash map if the memory was relocated.
            if (resized_ptr != old_mem.ptr) {
                const large_alloc = entry.value_ptr.*;
                if (config.retain_metadata) {
                    entry.value_ptr.freed = true;
                    entry.value_ptr.captureStackTrace(ret_addr, .free);
                } else {
                    self.large_allocations.removeByPtr(entry.key_ptr);
                }

                const gop = self.large_allocations.getOrPutAssumeCapacity(@intFromPtr(resized_ptr));
                if (config.retain_metadata and !config.never_unmap) {
                    // Backing allocator may be reusing memory that we're retaining metadata for
                    assert(!gop.found_existing or gop.value_ptr.freed);
                } else {
                    assert(!gop.found_existing); // This would mean the kernel double-mapped pages.
                }
                gop.value_ptr.* = large_alloc;
            }

            return resized_ptr;
        }

        /// This function assumes the object is in the large object storage regardless
        /// of the parameters.
        fn freeLarge(
            self: *Self,
            old_mem: []u8,
            alignment: mem.Alignment,
            ret_addr: usize,
        ) void {
            const entry = self.large_allocations.getEntry(@intFromPtr(old_mem.ptr)) orelse {
                if (config.safety) {
                    @panic("Invalid free");
                } else {
                    unreachable;
                }
            };

            if (config.retain_metadata and entry.value_ptr.freed) {
                if (config.safety) {
                    reportDoubleFree(ret_addr, entry.value_ptr.getStackTrace(.alloc), entry.value_ptr.getStackTrace(.free));
                    return;
                } else {
                    unreachable;
                }
            }

            if (config.safety and old_mem.len != entry.value_ptr.bytes.len) {
                var addresses: [stack_n]usize = [1]usize{0} ** stack_n;
                var free_stack_trace = StackTrace{
                    .instruction_addresses = &addresses,
                    .index = 0,
                };
                std.debug.captureStackTrace(ret_addr, &free_stack_trace);
                log.err("Allocation size {d} bytes does not match free size {d}. Allocation: {} Free: {}", .{
                    entry.value_ptr.bytes.len,
                    old_mem.len,
                    entry.value_ptr.getStackTrace(.alloc),
                    free_stack_trace,
                });
            }

            if (!config.never_unmap) {
                self.backing_allocator.rawFree(old_mem, alignment, ret_addr);
            }

            if (config.enable_memory_limit) {
                self.total_requested_bytes -= entry.value_ptr.requested_size;
            }

            if (config.verbose_log) {
                log.info("large free {d} bytes at {*}", .{ old_mem.len, old_mem.ptr });
            }

            if (!config.retain_metadata) {
                assert(self.large_allocations.remove(@intFromPtr(old_mem.ptr)));
            } else {
                entry.value_ptr.freed = true;
                entry.value_ptr.captureStackTrace(ret_addr, .free);
            }
        }

        fn alloc(context: *anyopaque, len: usize, alignment: mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(context));
            self.mutex.lock();
            defer self.mutex.unlock();

            if (config.enable_memory_limit) {
                const new_req_bytes = self.total_requested_bytes + len;
                if (new_req_bytes > self.requested_memory_limit) return null;
                self.total_requested_bytes = new_req_bytes;
            }

            const size_class_index: usize = @max(@bitSizeOf(usize) - @clz(len - 1), @intFromEnum(alignment));
            if (size_class_index >= self.buckets.len) {
                @branchHint(.unlikely);
                self.large_allocations.ensureUnusedCapacity(self.backing_allocator, 1) catch return null;
                const ptr = self.backing_allocator.rawAlloc(len, alignment, ret_addr) orelse return null;
                const slice = ptr[0..len];

                const gop = self.large_allocations.getOrPutAssumeCapacity(@intFromPtr(slice.ptr));
                if (config.retain_metadata and !config.never_unmap) {
                    // Backing allocator may be reusing memory that we're retaining metadata for
                    assert(!gop.found_existing or gop.value_ptr.freed);
                } else {
                    assert(!gop.found_existing); // This would mean the kernel double-mapped pages.
                }
                gop.value_ptr.bytes = slice;
                if (config.enable_memory_limit)
                    gop.value_ptr.requested_size = len;
                gop.value_ptr.captureStackTrace(ret_addr, .alloc);
                if (config.retain_metadata) {
                    gop.value_ptr.freed = false;
                    if (config.never_unmap) {
                        gop.value_ptr.alignment = alignment;
                    }
                }

                if (config.verbose_log) {
                    log.info("large alloc {d} bytes at {*}", .{ slice.len, slice.ptr });
                }
                return slice.ptr;
            }

            const slot_count = slot_counts[size_class_index];

            if (self.buckets[size_class_index]) |bucket| {
                @branchHint(.likely);
                const slot_index = bucket.allocated_count;
                if (slot_index < slot_count) {
                    @branchHint(.likely);
                    bucket.allocated_count = slot_index + 1;
                    const used_bits_byte = bucket.usedBits(slot_index / @bitSizeOf(usize));
                    const used_bit_index: Log2USize = @intCast(slot_index % @bitSizeOf(usize));
                    used_bits_byte.* |= (@as(usize, 1) << used_bit_index);
                    const size_class = @as(usize, 1) << @as(Log2USize, @intCast(size_class_index));
                    if (config.stack_trace_frames > 0) {
                        bucket.captureStackTrace(ret_addr, slot_count, slot_index, .alloc);
                    }
                    if (config.safety) {
                        bucket.requestedSizes(slot_count)[slot_index] = @intCast(len);
                        bucket.log2PtrAligns(slot_count)[slot_index] = alignment;
                    }
                    const page_addr = @intFromPtr(bucket) & ~(page_size - 1);
                    const addr = page_addr + slot_index * size_class;
                    if (config.verbose_log) {
                        log.info("small alloc {d} bytes at 0x{x}", .{ len, addr });
                    }
                    return @ptrFromInt(addr);
                }
            }

            const page = self.backing_allocator.rawAlloc(page_size, page_align, @returnAddress()) orelse
                return null;
            const bucket: *BucketHeader = .fromPage(@intFromPtr(page), slot_count);
            bucket.* = .{
                .allocated_count = 1,
                .freed_count = 0,
                .prev = self.buckets[size_class_index],
                .next = null,
            };
            if (self.buckets[size_class_index]) |old_head| {
                old_head.next = bucket;
            }
            self.buckets[size_class_index] = bucket;

            if (!config.backing_allocator_zeroes) {
                @memset(@as([*]usize, @as(*[1]usize, bucket.usedBits(0)))[0..usedBitsCount(slot_count)], 0);
                if (config.safety) @memset(bucket.requestedSizes(slot_count), 0);
            }

            bucket.usedBits(0).* = 0b1;

            if (config.stack_trace_frames > 0) {
                bucket.captureStackTrace(ret_addr, slot_count, 0, .alloc);
            }

            if (config.safety) {
                bucket.requestedSizes(slot_count)[0] = @intCast(len);
                bucket.log2PtrAligns(slot_count)[0] = alignment;
            }

            if (config.verbose_log) {
                log.info("small alloc {d} bytes at 0x{x}", .{ len, @intFromPtr(page) });
            }

            return page;
        }

        fn resize(
            context: *anyopaque,
            memory: []u8,
            alignment: mem.Alignment,
            new_len: usize,
            return_address: usize,
        ) bool {
            const self: *Self = @ptrCast(@alignCast(context));
            self.mutex.lock();
            defer self.mutex.unlock();

            const size_class_index: usize = @max(@bitSizeOf(usize) - @clz(memory.len - 1), @intFromEnum(alignment));
            if (size_class_index >= self.buckets.len) {
                return self.resizeLarge(memory, alignment, new_len, return_address, false) != null;
            } else {
                return resizeSmall(self, memory, alignment, new_len, return_address, size_class_index);
            }
        }

        fn remap(
            context: *anyopaque,
            memory: []u8,
            alignment: mem.Alignment,
            new_len: usize,
            return_address: usize,
        ) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(context));
            self.mutex.lock();
            defer self.mutex.unlock();

            const size_class_index: usize = @max(@bitSizeOf(usize) - @clz(memory.len - 1), @intFromEnum(alignment));
            if (size_class_index >= self.buckets.len) {
                return self.resizeLarge(memory, alignment, new_len, return_address, true);
            } else {
                return if (resizeSmall(self, memory, alignment, new_len, return_address, size_class_index)) memory.ptr else null;
            }
        }

        fn free(
            context: *anyopaque,
            old_memory: []u8,
            alignment: mem.Alignment,
            return_address: usize,
        ) void {
            const self: *Self = @ptrCast(@alignCast(context));
            self.mutex.lock();
            defer self.mutex.unlock();

            const size_class_index: usize = @max(@bitSizeOf(usize) - @clz(old_memory.len - 1), @intFromEnum(alignment));
            if (size_class_index >= self.buckets.len) {
                @branchHint(.unlikely);
                self.freeLarge(old_memory, alignment, return_address);
                return;
            }

            const slot_count = slot_counts[size_class_index];
            const freed_addr = @intFromPtr(old_memory.ptr);
            const page_addr = freed_addr & ~(page_size - 1);
            const bucket: *BucketHeader = .fromPage(page_addr, slot_count);
            if (bucket.canary != config.canary) @panic("Invalid free");
            const page_offset = freed_addr - page_addr;
            const size_class = @as(usize, 1) << @as(Log2USize, @intCast(size_class_index));
            const slot_index: SlotIndex = @intCast(page_offset / size_class);
            const used_byte_index = slot_index / @bitSizeOf(usize);
            const used_bit_index: Log2USize = @intCast(slot_index % @bitSizeOf(usize));
            const used_byte = bucket.usedBits(used_byte_index);
            const is_used = @as(u1, @truncate(used_byte.* >> used_bit_index)) != 0;
            if (!is_used) {
                if (config.safety) {
                    reportDoubleFree(
                        return_address,
                        bucketStackTrace(bucket, slot_count, slot_index, .alloc),
                        bucketStackTrace(bucket, slot_count, slot_index, .free),
                    );
                    // Recoverable since this is a free.
                    return;
                } else {
                    unreachable;
                }
            }

            // Definitely an in-use small alloc now.
            if (config.safety) {
                const requested_size = bucket.requestedSizes(slot_count)[slot_index];
                if (requested_size == 0) @panic("Invalid free");
                const slot_alignment = bucket.log2PtrAligns(slot_count)[slot_index];
                if (old_memory.len != requested_size or alignment != slot_alignment) {
                    var addresses: [stack_n]usize = [1]usize{0} ** stack_n;
                    var free_stack_trace: StackTrace = .{
                        .instruction_addresses = &addresses,
                        .index = 0,
                    };
                    std.debug.captureStackTrace(return_address, &free_stack_trace);
                    if (old_memory.len != requested_size) {
                        log.err("Allocation size {d} bytes does not match free size {d}. Allocation: {} Free: {}", .{
                            requested_size,
                            old_memory.len,
                            bucketStackTrace(bucket, slot_count, slot_index, .alloc),
                            free_stack_trace,
                        });
                    }
                    if (alignment != slot_alignment) {
                        log.err("Allocation alignment {d} does not match free alignment {d}. Allocation: {} Free: {}", .{
                            slot_alignment.toByteUnits(),
                            alignment.toByteUnits(),
                            bucketStackTrace(bucket, slot_count, slot_index, .alloc),
                            free_stack_trace,
                        });
                    }
                }
            }

            if (config.enable_memory_limit) {
                self.total_requested_bytes -= old_memory.len;
            }

            if (config.stack_trace_frames > 0) {
                // Capture stack trace to be the "first free", in case a double free happens.
                bucket.captureStackTrace(return_address, slot_count, slot_index, .free);
            }

            used_byte.* &= ~(@as(usize, 1) << used_bit_index);
            if (config.safety) {
                bucket.requestedSizes(slot_count)[slot_index] = 0;
            }
            bucket.freed_count += 1;
            if (bucket.freed_count == bucket.allocated_count) {
                if (bucket.prev) |prev| {
                    prev.next = bucket.next;
                }

                if (bucket.next) |next| {
                    assert(self.buckets[size_class_index] != bucket);
                    next.prev = bucket.prev;
                } else {
                    assert(self.buckets[size_class_index] == bucket);
                    self.buckets[size_class_index] = bucket.prev;
                }

                if (!config.never_unmap) {
                    const page: [*]align(page_size) u8 = @ptrFromInt(page_addr);
                    self.backing_allocator.rawFree(page[0..page_size], page_align, @returnAddress());
                }
            }
            if (config.verbose_log) {
                log.info("small free {d} bytes at {*}", .{ old_memory.len, old_memory.ptr });
            }
        }

        fn resizeSmall(
            self: *Self,
            memory: []u8,
            alignment: mem.Alignment,
            new_len: usize,
            return_address: usize,
            size_class_index: usize,
        ) bool {
            const new_size_class_index: usize = @max(@bitSizeOf(usize) - @clz(new_len - 1), @intFromEnum(alignment));
            if (!config.safety) return new_size_class_index == size_class_index;
            const slot_count = slot_counts[size_class_index];
            const memory_addr = @intFromPtr(memory.ptr);
            const page_addr = memory_addr & ~(page_size - 1);
            const bucket: *BucketHeader = .fromPage(page_addr, slot_count);
            if (bucket.canary != config.canary) @panic("Invalid free");
            const page_offset = memory_addr - page_addr;
            const size_class = @as(usize, 1) << @as(Log2USize, @intCast(size_class_index));
            const slot_index: SlotIndex = @intCast(page_offset / size_class);
            const used_byte_index = slot_index / @bitSizeOf(usize);
            const used_bit_index: Log2USize = @intCast(slot_index % @bitSizeOf(usize));
            const used_byte = bucket.usedBits(used_byte_index);
            const is_used = @as(u1, @truncate(used_byte.* >> used_bit_index)) != 0;
            if (!is_used) {
                reportDoubleFree(
                    return_address,
                    bucketStackTrace(bucket, slot_count, slot_index, .alloc),
                    bucketStackTrace(bucket, slot_count, slot_index, .free),
                );
                // Recoverable since this is a free.
                return false;
            }

            // Definitely an in-use small alloc now.
            const requested_size = bucket.requestedSizes(slot_count)[slot_index];
            if (requested_size == 0) @panic("Invalid free");
            const slot_alignment = bucket.log2PtrAligns(slot_count)[slot_index];
            if (memory.len != requested_size or alignment != slot_alignment) {
                var addresses: [stack_n]usize = [1]usize{0} ** stack_n;
                var free_stack_trace: StackTrace = .{
                    .instruction_addresses = &addresses,
                    .index = 0,
                };
                std.debug.captureStackTrace(return_address, &free_stack_trace);
                if (memory.len != requested_size) {
                    log.err("Allocation size {d} bytes does not match free size {d}. Allocation: {} Free: {}", .{
                        requested_size,
                        memory.len,
                        bucketStackTrace(bucket, slot_count, slot_index, .alloc),
                        free_stack_trace,
                    });
                }
                if (alignment != slot_alignment) {
                    log.err("Allocation alignment {d} does not match free alignment {d}. Allocation: {} Free: {}", .{
                        slot_alignment.toByteUnits(),
                        alignment.toByteUnits(),
                        bucketStackTrace(bucket, slot_count, slot_index, .alloc),
                        free_stack_trace,
                    });
                }
            }

            if (new_size_class_index != size_class_index) return false;

            const prev_req_bytes = self.total_requested_bytes;
            if (config.enable_memory_limit) {
                const new_req_bytes = prev_req_bytes - memory.len + new_len;
                if (new_req_bytes > prev_req_bytes and new_req_bytes > self.requested_memory_limit) {
                    return false;
                }
                self.total_requested_bytes = new_req_bytes;
            }

            if (memory.len > new_len) @memset(memory[new_len..], undefined);
            if (config.verbose_log)
                log.info("small resize {d} bytes at {*} to {d}", .{ memory.len, memory.ptr, new_len });

            if (config.safety)
                bucket.requestedSizes(slot_count)[slot_index] = @intCast(new_len);

            if (config.resize_stack_traces)
                bucket.captureStackTrace(return_address, slot_count, slot_index, .alloc);

            return true;
        }
    };
}

const TraceKind = enum {
    alloc,
    free,
};

const test_config = Config{};

test "small allocations - free in same order" {
    var gpa = DebugAllocator(test_config){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var list = std.ArrayList(*u64).init(std.testing.allocator);
    defer list.deinit();

    var i: usize = 0;
    while (i < 513) : (i += 1) {
        const ptr = try allocator.create(u64);
        try list.append(ptr);
    }

    for (list.items) |ptr| {
        allocator.destroy(ptr);
    }
}

test "small allocations - free in reverse order" {
    var gpa = DebugAllocator(test_config){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var list = std.ArrayList(*u64).init(std.testing.allocator);
    defer list.deinit();

    var i: usize = 0;
    while (i < 513) : (i += 1) {
        const ptr = try allocator.create(u64);
        try list.append(ptr);
    }

    while (list.pop()) |ptr| {
        allocator.destroy(ptr);
    }
}

test "large allocations" {
    var gpa = DebugAllocator(test_config){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const ptr1 = try allocator.alloc(u64, 42768);
    const ptr2 = try allocator.alloc(u64, 52768);
    allocator.free(ptr1);
    const ptr3 = try allocator.alloc(u64, 62768);
    allocator.free(ptr3);
    allocator.free(ptr2);
}

test "very large allocation" {
    var gpa = DebugAllocator(test_config){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, math.maxInt(usize)));
}

test "realloc" {
    var gpa = DebugAllocator(test_config){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var slice = try allocator.alignedAlloc(u8, .of(u32), 1);
    defer allocator.free(slice);
    slice[0] = 0x12;

    // This reallocation should keep its pointer address.
    const old_slice = slice;
    slice = try allocator.realloc(slice, 2);
    try std.testing.expect(old_slice.ptr == slice.ptr);
    try std.testing.expect(slice[0] == 0x12);
    slice[1] = 0x34;

    // This requires upgrading to a larger size class
    slice = try allocator.realloc(slice, 17);
    try std.testing.expect(slice[0] == 0x12);
    try std.testing.expect(slice[1] == 0x34);
}

test "shrink" {
    var gpa: DebugAllocator(test_config) = .{};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var slice = try allocator.alloc(u8, 20);
    defer allocator.free(slice);

    @memset(slice, 0x11);

    try std.testing.expect(allocator.resize(slice, 17));
    slice = slice[0..17];

    for (slice) |b| {
        try std.testing.expect(b == 0x11);
    }

    // Does not cross size class boundaries when shrinking.
    try std.testing.expect(!allocator.resize(slice, 16));
}

test "large object - grow" {
    if (builtin.target.cpu.arch.isWasm()) {
        // Not expected to pass on targets that do not have memory mapping.
        return error.SkipZigTest;
    }
    var gpa: DebugAllocator(test_config) = .{};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var slice1 = try allocator.alloc(u8, default_page_size * 2 - 20);
    defer allocator.free(slice1);

    const old = slice1;
    slice1 = try allocator.realloc(slice1, default_page_size * 2 - 10);
    try std.testing.expect(slice1.ptr == old.ptr);

    slice1 = try allocator.realloc(slice1, default_page_size * 2);
    try std.testing.expect(slice1.ptr == old.ptr);

    slice1 = try allocator.realloc(slice1, default_page_size * 2 + 1);
}

test "realloc small object to large object" {
    var gpa = DebugAllocator(test_config){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var slice = try allocator.alloc(u8, 70);
    defer allocator.free(slice);
    slice[0] = 0x12;
    slice[60] = 0x34;

    // This requires upgrading to a large object
    const large_object_size = default_page_size * 2 + 50;
    slice = try allocator.realloc(slice, large_object_size);
    try std.testing.expect(slice[0] == 0x12);
    try std.testing.expect(slice[60] == 0x34);
}

test "shrink large object to large object" {
    var gpa: DebugAllocator(test_config) = .{};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var slice = try allocator.alloc(u8, default_page_size * 2 + 50);
    defer allocator.free(slice);
    slice[0] = 0x12;
    slice[60] = 0x34;

    if (!allocator.resize(slice, default_page_size * 2 + 1)) return;
    slice = slice.ptr[0 .. default_page_size * 2 + 1];
    try std.testing.expect(slice[0] == 0x12);
    try std.testing.expect(slice[60] == 0x34);

    try std.testing.expect(allocator.resize(slice, default_page_size * 2 + 1));
    slice = slice[0 .. default_page_size * 2 + 1];
    try std.testing.expect(slice[0] == 0x12);
    try std.testing.expect(slice[60] == 0x34);

    slice = try allocator.realloc(slice, default_page_size * 2);
    try std.testing.expect(slice[0] == 0x12);
    try std.testing.expect(slice[60] == 0x34);
}

test "shrink large object to large object with larger alignment" {
    if (!builtin.link_libc and builtin.os.tag == .wasi) return error.SkipZigTest; // https://github.com/ziglang/zig/issues/22731

    var gpa = DebugAllocator(test_config){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var debug_buffer: [1000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&debug_buffer);
    const debug_allocator = fba.allocator();

    const alloc_size = default_page_size * 2 + 50;
    var slice = try allocator.alignedAlloc(u8, .@"16", alloc_size);
    defer allocator.free(slice);

    const big_alignment: usize = default_page_size * 2;
    // This loop allocates until we find a page that is not aligned to the big
    // alignment. Then we shrink the allocation after the loop, but increase the
    // alignment to the higher one, that we know will force it to realloc.
    var stuff_to_free = std.ArrayList([]align(16) u8).init(debug_allocator);
    while (mem.isAligned(@intFromPtr(slice.ptr), big_alignment)) {
        try stuff_to_free.append(slice);
        slice = try allocator.alignedAlloc(u8, .@"16", alloc_size);
    }
    while (stuff_to_free.pop()) |item| {
        allocator.free(item);
    }
    slice[0] = 0x12;
    slice[60] = 0x34;

    slice = try allocator.reallocAdvanced(slice, big_alignment, alloc_size / 2);
    try std.testing.expect(slice[0] == 0x12);
    try std.testing.expect(slice[60] == 0x34);
}

test "realloc large object to small object" {
    var gpa = DebugAllocator(test_config){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var slice = try allocator.alloc(u8, default_page_size * 2 + 50);
    defer allocator.free(slice);
    slice[0] = 0x12;
    slice[16] = 0x34;

    slice = try allocator.realloc(slice, 19);
    try std.testing.expect(slice[0] == 0x12);
    try std.testing.expect(slice[16] == 0x34);
}

test "overridable mutexes" {
    var gpa = DebugAllocator(.{ .MutexType = std.Thread.Mutex }){
        .backing_allocator = std.testing.allocator,
        .mutex = std.Thread.Mutex{},
    };
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const ptr = try allocator.create(i32);
    defer allocator.destroy(ptr);
}

test "non-page-allocator backing allocator" {
    var gpa: DebugAllocator(.{
        .backing_allocator_zeroes = false,
    }) = .{
        .backing_allocator = std.testing.allocator,
    };
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const ptr = try allocator.create(i32);
    defer allocator.destroy(ptr);
}

test "realloc large object to larger alignment" {
    if (!builtin.link_libc and builtin.os.tag == .wasi) return error.SkipZigTest; // https://github.com/ziglang/zig/issues/22731

    var gpa = DebugAllocator(test_config){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var debug_buffer: [1000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&debug_buffer);
    const debug_allocator = fba.allocator();

    var slice = try allocator.alignedAlloc(u8, .@"16", default_page_size * 2 + 50);
    defer allocator.free(slice);

    const big_alignment: usize = default_page_size * 2;
    // This loop allocates until we find a page that is not aligned to the big alignment.
    var stuff_to_free = std.ArrayList([]align(16) u8).init(debug_allocator);
    while (mem.isAligned(@intFromPtr(slice.ptr), big_alignment)) {
        try stuff_to_free.append(slice);
        slice = try allocator.alignedAlloc(u8, .@"16", default_page_size * 2 + 50);
    }
    while (stuff_to_free.pop()) |item| {
        allocator.free(item);
    }
    slice[0] = 0x12;
    slice[16] = 0x34;

    slice = try allocator.reallocAdvanced(slice, 32, default_page_size * 2 + 100);
    try std.testing.expect(slice[0] == 0x12);
    try std.testing.expect(slice[16] == 0x34);

    slice = try allocator.reallocAdvanced(slice, 32, default_page_size * 2 + 25);
    try std.testing.expect(slice[0] == 0x12);
    try std.testing.expect(slice[16] == 0x34);

    slice = try allocator.reallocAdvanced(slice, big_alignment, default_page_size * 2 + 100);
    try std.testing.expect(slice[0] == 0x12);
    try std.testing.expect(slice[16] == 0x34);
}

test "large object rejects shrinking to small" {
    if (builtin.target.cpu.arch.isWasm()) {
        // Not expected to pass on targets that do not have memory mapping.
        return error.SkipZigTest;
    }

    var failing_allocator = std.testing.FailingAllocator.init(std.heap.page_allocator, .{ .fail_index = 3 });
    var gpa: DebugAllocator(.{}) = .{
        .backing_allocator = failing_allocator.allocator(),
    };
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    var slice = try allocator.alloc(u8, default_page_size * 2 + 50);
    defer allocator.free(slice);
    slice[0] = 0x12;
    slice[3] = 0x34;

    try std.testing.expect(!allocator.resize(slice, 4));
    try std.testing.expect(slice[0] == 0x12);
    try std.testing.expect(slice[3] == 0x34);
}

test "objects of size 1024 and 2048" {
    var gpa = DebugAllocator(test_config){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    const slice = try allocator.alloc(u8, 1025);
    const slice2 = try allocator.alloc(u8, 3000);

    allocator.free(slice);
    allocator.free(slice2);
}

test "setting a memory cap" {
    var gpa = DebugAllocator(.{ .enable_memory_limit = true }){};
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();

    gpa.requested_memory_limit = 1010;

    const small = try allocator.create(i32);
    try std.testing.expect(gpa.total_requested_bytes == 4);

    const big = try allocator.alloc(u8, 1000);
    try std.testing.expect(gpa.total_requested_bytes == 1004);

    try std.testing.expectError(error.OutOfMemory, allocator.create(u64));

    allocator.destroy(small);
    try std.testing.expect(gpa.total_requested_bytes == 1000);

    allocator.free(big);
    try std.testing.expect(gpa.total_requested_bytes == 0);

    const exact = try allocator.alloc(u8, 1010);
    try std.testing.expect(gpa.total_requested_bytes == 1010);
    allocator.free(exact);
}

test "large allocations count requested size not backing size" {
    var gpa: DebugAllocator(.{ .enable_memory_limit = true }) = .{};
    const allocator = gpa.allocator();

    var buf = try allocator.alignedAlloc(u8, .@"1", default_page_size + 1);
    try std.testing.expectEqual(default_page_size + 1, gpa.total_requested_bytes);
    buf = try allocator.realloc(buf, 1);
    try std.testing.expectEqual(1, gpa.total_requested_bytes);
    buf = try allocator.realloc(buf, 2);
    try std.testing.expectEqual(2, gpa.total_requested_bytes);
}

test "retain metadata and never unmap" {
    var gpa = std.heap.DebugAllocator(.{
        .safety = true,
        .never_unmap = true,
        .retain_metadata = true,
    }){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    const alloc = try allocator.alloc(u8, 8);
    allocator.free(alloc);

    const alloc2 = try allocator.alloc(u8, 8);
    allocator.free(alloc2);
}
const std = @import("../std.zig");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const mem = std.mem;

const FixedBufferAllocator = @This();

end_index: usize,
buffer: []u8,

pub fn init(buffer: []u8) FixedBufferAllocator {
    return .{
        .buffer = buffer,
        .end_index = 0,
    };
}

/// Using this at the same time as the interface returned by `threadSafeAllocator` is not thread safe.
pub fn allocator(self: *FixedBufferAllocator) Allocator {
    return .{
        .ptr = self,
        .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        },
    };
}

/// Provides a lock free thread safe `Allocator` interface to the underlying `FixedBufferAllocator`
///
/// Using this at the same time as the interface returned by `allocator` is not thread safe.
pub fn threadSafeAllocator(self: *FixedBufferAllocator) Allocator {
    return .{
        .ptr = self,
        .vtable = &.{
            .alloc = threadSafeAlloc,
            .resize = Allocator.noResize,
            .remap = Allocator.noRemap,
            .free = Allocator.noFree,
        },
    };
}

pub fn ownsPtr(self: *FixedBufferAllocator, ptr: [*]u8) bool {
    return sliceContainsPtr(self.buffer, ptr);
}

pub fn ownsSlice(self: *FixedBufferAllocator, slice: []u8) bool {
    return sliceContainsSlice(self.buffer, slice);
}

/// This has false negatives when the last allocation had an
/// adjusted_index. In such case we won't be able to determine what the
/// last allocation was because the alignForward operation done in alloc is
/// not reversible.
pub fn isLastAllocation(self: *FixedBufferAllocator, buf: []u8) bool {
    return buf.ptr + buf.len == self.buffer.ptr + self.end_index;
}

pub fn alloc(ctx: *anyopaque, n: usize, alignment: mem.Alignment, ra: usize) ?[*]u8 {
    const self: *FixedBufferAllocator = @ptrCast(@alignCast(ctx));
    _ = ra;
    const ptr_align = alignment.toByteUnits();
    const adjust_off = mem.alignPointerOffset(self.buffer.ptr + self.end_index, ptr_align) orelse return null;
    const adjusted_index = self.end_index + adjust_off;
    const new_end_index = adjusted_index + n;
    if (new_end_index > self.buffer.len) return null;
    self.end_index = new_end_index;
    return self.buffer.ptr + adjusted_index;
}

pub fn resize(
    ctx: *anyopaque,
    buf: []u8,
    alignment: mem.Alignment,
    new_size: usize,
    return_address: usize,
) bool {
    const self: *FixedBufferAllocator = @ptrCast(@alignCast(ctx));
    _ = alignment;
    _ = return_address;
    assert(@inComptime() or self.ownsSlice(buf));

    if (!self.isLastAllocation(buf)) {
        if (new_size > buf.len) return false;
        return true;
    }

    if (new_size <= buf.len) {
        const sub = buf.len - new_size;
        self.end_index -= sub;
        return true;
    }

    const add = new_size - buf.len;
    if (add + self.end_index > self.buffer.len) return false;

    self.end_index += add;
    return true;
}

pub fn remap(
    context: *anyopaque,
    memory: []u8,
    alignment: mem.Alignment,
    new_len: usize,
    return_address: usize,
) ?[*]u8 {
    return if (resize(context, memory, alignment, new_len, return_address)) memory.ptr else null;
}

pub fn free(
    ctx: *anyopaque,
    buf: []u8,
    alignment: mem.Alignment,
    return_address: usize,
) void {
    const self: *FixedBufferAllocator = @ptrCast(@alignCast(ctx));
    _ = alignment;
    _ = return_address;
    assert(@inComptime() or self.ownsSlice(buf));

    if (self.isLastAllocation(buf)) {
        self.end_index -= buf.len;
    }
}

fn threadSafeAlloc(ctx: *anyopaque, n: usize, alignment: mem.Alignment, ra: usize) ?[*]u8 {
    const self: *FixedBufferAllocator = @ptrCast(@alignCast(ctx));
    _ = ra;
    const ptr_align = alignment.toByteUnits();
    var end_index = @atomicLoad(usize, &self.end_index, .seq_cst);
    while (true) {
        const adjust_off = mem.alignPointerOffset(self.buffer.ptr + end_index, ptr_align) orelse return null;
        const adjusted_index = end_index + adjust_off;
        const new_end_index = adjusted_index + n;
        if (new_end_index > self.buffer.len) return null;
        end_index = @cmpxchgWeak(usize, &self.end_index, end_index, new_end_index, .seq_cst, .seq_cst) orelse
            return self.buffer[adjusted_index..new_end_index].ptr;
    }
}

pub fn reset(self: *FixedBufferAllocator) void {
    self.end_index = 0;
}

fn sliceContainsPtr(container: []u8, ptr: [*]u8) bool {
    return @intFromPtr(ptr) >= @intFromPtr(container.ptr) and
        @intFromPtr(ptr) < (@intFromPtr(container.ptr) + container.len);
}

fn sliceContainsSlice(container: []u8, slice: []u8) bool {
    return @intFromPtr(slice.ptr) >= @intFromPtr(container.ptr) and
        (@intFromPtr(slice.ptr) + slice.len) <= (@intFromPtr(container.ptr) + container.len);
}

var test_fixed_buffer_allocator_memory: [800000 * @sizeOf(u64)]u8 = undefined;

test FixedBufferAllocator {
    var fixed_buffer_allocator = mem.validationWrap(FixedBufferAllocator.init(test_fixed_buffer_allocator_memory[0..]));
    const a = fixed_buffer_allocator.allocator();

    try std.heap.testAllocator(a);
    try std.heap.testAllocatorAligned(a);
    try std.heap.testAllocatorLargeAlignment(a);
    try std.heap.testAllocatorAlignedShrink(a);
}

test reset {
    var buf: [8]u8 align(@alignOf(u64)) = undefined;
    var fba = FixedBufferAllocator.init(buf[0..]);
    const a = fba.allocator();

    const X = 0xeeeeeeeeeeeeeeee;
    const Y = 0xffffffffffffffff;

    const x = try a.create(u64);
    x.* = X;
    try std.testing.expectError(error.OutOfMemory, a.create(u64));

    fba.reset();
    const y = try a.create(u64);
    y.* = Y;

    // we expect Y to have overwritten X.
    try std.testing.expect(x.* == y.*);
    try std.testing.expect(y.* == Y);
}

test "reuse memory on realloc" {
    var small_fixed_buffer: [10]u8 = undefined;
    // check if we re-use the memory
    {
        var fixed_buffer_allocator = FixedBufferAllocator.init(small_fixed_buffer[0..]);
        const a = fixed_buffer_allocator.allocator();

        const slice0 = try a.alloc(u8, 5);
        try std.testing.expect(slice0.len == 5);
        const slice1 = try a.realloc(slice0, 10);
        try std.testing.expect(slice1.ptr == slice0.ptr);
        try std.testing.expect(slice1.len == 10);
        try std.testing.expectError(error.OutOfMemory, a.realloc(slice1, 11));
    }
    // check that we don't re-use the memory if it's not the most recent block
    {
        var fixed_buffer_allocator = FixedBufferAllocator.init(small_fixed_buffer[0..]);
        const a = fixed_buffer_allocator.allocator();

        var slice0 = try a.alloc(u8, 2);
        slice0[0] = 1;
        slice0[1] = 2;
        const slice1 = try a.alloc(u8, 2);
        const slice2 = try a.realloc(slice0, 4);
        try std.testing.expect(slice0.ptr != slice2.ptr);
        try std.testing.expect(slice1.ptr != slice2.ptr);
        try std.testing.expect(slice2[0] == 1);
        try std.testing.expect(slice2[1] == 2);
    }
}

test "thread safe version" {
    var fixed_buffer_allocator = FixedBufferAllocator.init(test_fixed_buffer_allocator_memory[0..]);

    try std.heap.testAllocator(fixed_buffer_allocator.threadSafeAllocator());
    try std.heap.testAllocatorAligned(fixed_buffer_allocator.threadSafeAllocator());
    try std.heap.testAllocatorLargeAlignment(fixed_buffer_allocator.threadSafeAllocator());
    try std.heap.testAllocatorAlignedShrink(fixed_buffer_allocator.threadSafeAllocator());
}
const std = @import("../std.zig");
const Alignment = std.mem.Alignment;

const debug_mode = @import("builtin").mode == .Debug;

pub const MemoryPoolError = error{OutOfMemory};

/// A memory pool that can allocate objects of a single type very quickly.
/// Use this when you need to allocate a lot of objects of the same type,
/// because It outperforms general purpose allocators.
pub fn MemoryPool(comptime Item: type) type {
    return MemoryPoolAligned(Item, .of(Item));
}

/// A memory pool that can allocate objects of a single type very quickly.
/// Use this when you need to allocate a lot of objects of the same type,
/// because It outperforms general purpose allocators.
pub fn MemoryPoolAligned(comptime Item: type, comptime alignment: Alignment) type {
    if (@alignOf(Item) == comptime alignment.toByteUnits()) {
        return MemoryPoolExtra(Item, .{});
    } else {
        return MemoryPoolExtra(Item, .{ .alignment = alignment });
    }
}

pub const Options = struct {
    /// The alignment of the memory pool items. Use `null` for natural alignment.
    alignment: ?Alignment = null,

    /// If `true`, the memory pool can allocate additional items after a initial setup.
    /// If `false`, the memory pool will not allocate further after a call to `initPreheated`.
    growable: bool = true,
};

/// A memory pool that can allocate objects of a single type very quickly.
/// Use this when you need to allocate a lot of objects of the same type,
/// because It outperforms general purpose allocators.
pub fn MemoryPoolExtra(comptime Item: type, comptime pool_options: Options) type {
    return struct {
        const Pool = @This();

        /// Size of the memory pool items. This is not necessarily the same
        /// as `@sizeOf(Item)` as the pool also uses the items for internal means.
        pub const item_size = @max(@sizeOf(Node), @sizeOf(Item));

        // This needs to be kept in sync with Node.
        const node_alignment: Alignment = .of(*anyopaque);

        /// Alignment of the memory pool items. This is not necessarily the same
        /// as `@alignOf(Item)` as the pool also uses the items for internal means.
        pub const item_alignment: Alignment = node_alignment.max(pool_options.alignment orelse .of(Item));

        const Node = struct {
            next: ?*align(item_alignment.toByteUnits()) @This(),
        };
        const NodePtr = *align(item_alignment.toByteUnits()) Node;
        const ItemPtr = *align(item_alignment.toByteUnits()) Item;

        arena: std.heap.ArenaAllocator,
        free_list: ?NodePtr = null,

        /// Creates a new memory pool.
        pub fn init(allocator: std.mem.Allocator) Pool {
            return .{ .arena = std.heap.ArenaAllocator.init(allocator) };
        }

        /// Creates a new memory pool and pre-allocates `initial_size` items.
        /// This allows the up to `initial_size` active allocations before a
        /// `OutOfMemory` error happens when calling `create()`.
        pub fn initPreheated(allocator: std.mem.Allocator, initial_size: usize) MemoryPoolError!Pool {
            var pool = init(allocator);
            errdefer pool.deinit();
            try pool.preheat(initial_size);
            return pool;
        }

        /// Destroys the memory pool and frees all allocated memory.
        pub fn deinit(pool: *Pool) void {
            pool.arena.deinit();
            pool.* = undefined;
        }

        /// Preheats the memory pool by pre-allocating `size` items.
        /// This allows up to `size` active allocations before an
        /// `OutOfMemory` error might happen when calling `create()`.
        pub fn preheat(pool: *Pool, size: usize) MemoryPoolError!void {
            var i: usize = 0;
            while (i < size) : (i += 1) {
                const raw_mem = try pool.allocNew();
                const free_node = @as(NodePtr, @ptrCast(raw_mem));
                free_node.* = Node{
                    .next = pool.free_list,
                };
                pool.free_list = free_node;
            }
        }

        pub const ResetMode = std.heap.ArenaAllocator.ResetMode;

        /// Resets the memory pool and destroys all allocated items.
        /// This can be used to batch-destroy all objects without invalidating the memory pool.
        ///
        /// The function will return whether the reset operation was successful or not.
        /// If the reallocation  failed `false` is returned. The pool will still be fully
        /// functional in that case, all memory is released. Future allocations just might
        /// be slower.
        ///
        /// NOTE: If `mode` is `free_all`, the function will always return `true`.
        pub fn reset(pool: *Pool, mode: ResetMode) bool {
            // TODO: Potentially store all allocated objects in a list as well, allowing to
            //       just move them into the free list instead of actually releasing the memory.

            const reset_successful = pool.arena.reset(mode);

            pool.free_list = null;

            return reset_successful;
        }

        /// Creates a new item and adds it to the memory pool.
        pub fn create(pool: *Pool) !ItemPtr {
            const node = if (pool.free_list) |item| blk: {
                pool.free_list = item.next;
                break :blk item;
            } else if (pool_options.growable)
                @as(NodePtr, @ptrCast(try pool.allocNew()))
            else
                return error.OutOfMemory;

            const ptr = @as(ItemPtr, @ptrCast(node));
            ptr.* = undefined;
            return ptr;
        }

        /// Destroys a previously created item.
        /// Only pass items to `ptr` that were previously created with `create()` of the same memory pool!
        pub fn destroy(pool: *Pool, ptr: ItemPtr) void {
            ptr.* = undefined;

            const node = @as(NodePtr, @ptrCast(ptr));
            node.* = Node{
                .next = pool.free_list,
            };
            pool.free_list = node;
        }

        fn allocNew(pool: *Pool) MemoryPoolError!*align(item_alignment.toByteUnits()) [item_size]u8 {
            const mem = try pool.arena.allocator().alignedAlloc(u8, item_alignment, item_size);
            return mem[0..item_size]; // coerce slice to array pointer
        }
    };
}

test "basic" {
    var pool = MemoryPool(u32).init(std.testing.allocator);
    defer pool.deinit();

    const p1 = try pool.create();
    const p2 = try pool.create();
    const p3 = try pool.create();

    // Assert uniqueness
    try std.testing.expect(p1 != p2);
    try std.testing.expect(p1 != p3);
    try std.testing.expect(p2 != p3);

    pool.destroy(p2);
    const p4 = try pool.create();

    // Assert memory reuse
    try std.testing.expect(p2 == p4);
}

test "preheating (success)" {
    var pool = try MemoryPool(u32).initPreheated(std.testing.allocator, 4);
    defer pool.deinit();

    _ = try pool.create();
    _ = try pool.create();
    _ = try pool.create();
}

test "preheating (failure)" {
    const failer = std.testing.failing_allocator;
    try std.testing.expectError(error.OutOfMemory, MemoryPool(u32).initPreheated(failer, 5));
}

test "growable" {
    var pool = try MemoryPoolExtra(u32, .{ .growable = false }).initPreheated(std.testing.allocator, 4);
    defer pool.deinit();

    _ = try pool.create();
    _ = try pool.create();
    _ = try pool.create();
    _ = try pool.create();

    try std.testing.expectError(error.OutOfMemory, pool.create());
}

test "greater than pointer default alignment" {
    const Foo = struct {
        data: u64 align(16),
    };

    var pool = MemoryPool(Foo).init(std.testing.allocator);
    defer pool.deinit();

    const foo: *Foo = try pool.create();
    _ = foo;
}

test "greater than pointer manual alignment" {
    const Foo = struct {
        data: u64,
    };

    var pool = MemoryPoolAligned(Foo, .@"16").init(std.testing.allocator);
    defer pool.deinit();

    const foo: *align(16) Foo = try pool.create();
    _ = foo;
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const mem = std.mem;
const maxInt = std.math.maxInt;
const assert = std.debug.assert;
const native_os = builtin.os.tag;
const windows = std.os.windows;
const ntdll = windows.ntdll;
const posix = std.posix;
const page_size_min = std.heap.page_size_min;

const SUCCESS = @import("../os/windows/ntstatus.zig").NTSTATUS.SUCCESS;
const MEM_RESERVE_PLACEHOLDER = windows.MEM_RESERVE_PLACEHOLDER;
const MEM_PRESERVE_PLACEHOLDER = windows.MEM_PRESERVE_PLACEHOLDER;

pub const vtable: Allocator.VTable = .{
    .alloc = alloc,
    .resize = resize,
    .remap = remap,
    .free = free,
};

pub fn map(n: usize, alignment: mem.Alignment) ?[*]u8 {
    const page_size = std.heap.pageSize();
    if (n >= maxInt(usize) - page_size) return null;
    const alignment_bytes = alignment.toByteUnits();

    if (native_os == .windows) {
        var base_addr: ?*anyopaque = null;
        var size: windows.SIZE_T = n;

        var status = ntdll.NtAllocateVirtualMemory(windows.GetCurrentProcess(), @ptrCast(&base_addr), 0, &size, windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_READWRITE);

        if (status == SUCCESS and mem.isAligned(@intFromPtr(base_addr), alignment_bytes)) {
            return @ptrCast(base_addr);
        }

        if (status == SUCCESS) {
            var region_size: windows.SIZE_T = 0;
            _ = ntdll.NtFreeVirtualMemory(windows.GetCurrentProcess(), @ptrCast(&base_addr), &region_size, windows.MEM_RELEASE);
        }

        const overalloc_len = n + alignment_bytes - page_size;
        const aligned_len = mem.alignForward(usize, n, page_size);

        base_addr = null;
        size = overalloc_len;

        status = ntdll.NtAllocateVirtualMemory(windows.GetCurrentProcess(), @ptrCast(&base_addr), 0, &size, windows.MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, windows.PAGE_NOACCESS);

        if (status != SUCCESS) return null;

        const placeholder_addr = @intFromPtr(base_addr);
        const aligned_addr = mem.alignForward(usize, placeholder_addr, alignment_bytes);
        const prefix_size = aligned_addr - placeholder_addr;

        if (prefix_size > 0) {
            var prefix_base = base_addr;
            var prefix_size_param: windows.SIZE_T = prefix_size;
            _ = ntdll.NtFreeVirtualMemory(windows.GetCurrentProcess(), @ptrCast(&prefix_base), &prefix_size_param, windows.MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
        }

        const suffix_start = aligned_addr + aligned_len;
        const suffix_size = (placeholder_addr + overalloc_len) - suffix_start;
        if (suffix_size > 0) {
            var suffix_base = @as(?*anyopaque, @ptrFromInt(suffix_start));
            var suffix_size_param: windows.SIZE_T = suffix_size;
            _ = ntdll.NtFreeVirtualMemory(windows.GetCurrentProcess(), @ptrCast(&suffix_base), &suffix_size_param, windows.MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER);
        }

        base_addr = @ptrFromInt(aligned_addr);
        size = aligned_len;

        status = ntdll.NtAllocateVirtualMemory(windows.GetCurrentProcess(), @ptrCast(&base_addr), 0, &size, windows.MEM_COMMIT | MEM_PRESERVE_PLACEHOLDER, windows.PAGE_READWRITE);

        if (status == SUCCESS) {
            return @ptrCast(base_addr);
        }

        base_addr = @as(?*anyopaque, @ptrFromInt(aligned_addr));
        size = aligned_len;
        _ = ntdll.NtFreeVirtualMemory(windows.GetCurrentProcess(), @ptrCast(&base_addr), &size, windows.MEM_RELEASE);

        return null;
    }

    const aligned_len = mem.alignForward(usize, n, page_size);
    const max_drop_len = alignment_bytes - @min(alignment_bytes, page_size);
    const overalloc_len = if (max_drop_len <= aligned_len - n)
        aligned_len
    else
        mem.alignForward(usize, aligned_len + max_drop_len, page_size);
    const hint = @atomicLoad(@TypeOf(std.heap.next_mmap_addr_hint), &std.heap.next_mmap_addr_hint, .unordered);
    const slice = posix.mmap(
        hint,
        overalloc_len,
        posix.PROT.READ | posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    ) catch return null;
    const result_ptr = mem.alignPointer(slice.ptr, alignment_bytes) orelse return null;
    // Unmap the extra bytes that were only requested in order to guarantee
    // that the range of memory we were provided had a proper alignment in it
    // somewhere. The extra bytes could be at the beginning, or end, or both.
    const drop_len = result_ptr - slice.ptr;
    if (drop_len != 0) posix.munmap(slice[0..drop_len]);
    const remaining_len = overalloc_len - drop_len;
    if (remaining_len > aligned_len) posix.munmap(@alignCast(result_ptr[aligned_len..remaining_len]));
    const new_hint: [*]align(page_size_min) u8 = @alignCast(result_ptr + aligned_len);
    _ = @cmpxchgStrong(@TypeOf(std.heap.next_mmap_addr_hint), &std.heap.next_mmap_addr_hint, hint, new_hint, .monotonic, .monotonic);
    return result_ptr;
}

fn alloc(context: *anyopaque, n: usize, alignment: mem.Alignment, ra: usize) ?[*]u8 {
    _ = context;
    _ = ra;
    assert(n > 0);
    return map(n, alignment);
}

fn resize(context: *anyopaque, memory: []u8, alignment: mem.Alignment, new_len: usize, return_address: usize) bool {
    _ = context;
    _ = alignment;
    _ = return_address;
    return realloc(memory, new_len, false) != null;
}

fn remap(context: *anyopaque, memory: []u8, alignment: mem.Alignment, new_len: usize, return_address: usize) ?[*]u8 {
    _ = context;
    _ = alignment;
    _ = return_address;
    return realloc(memory, new_len, true);
}

fn free(context: *anyopaque, memory: []u8, alignment: mem.Alignment, return_address: usize) void {
    _ = context;
    _ = alignment;
    _ = return_address;
    return unmap(@alignCast(memory));
}

pub fn unmap(memory: []align(page_size_min) u8) void {
    if (native_os == .windows) {
        var base_addr: ?*anyopaque = memory.ptr;
        var region_size: windows.SIZE_T = 0;
        _ = ntdll.NtFreeVirtualMemory(windows.GetCurrentProcess(), @ptrCast(&base_addr), &region_size, windows.MEM_RELEASE);
    } else {
        const page_aligned_len = mem.alignForward(usize, memory.len, std.heap.pageSize());
        posix.munmap(memory.ptr[0..page_aligned_len]);
    }
}

pub fn realloc(uncasted_memory: []u8, new_len: usize, may_move: bool) ?[*]u8 {
    const memory: []align(page_size_min) u8 = @alignCast(uncasted_memory);
    const page_size = std.heap.pageSize();
    const new_size_aligned = mem.alignForward(usize, new_len, page_size);

    if (native_os == .windows) {
        if (new_len <= memory.len) {
            const base_addr = @intFromPtr(memory.ptr);
            const old_addr_end = base_addr + memory.len;
            const new_addr_end = mem.alignForward(usize, base_addr + new_len, page_size);
            if (old_addr_end > new_addr_end) {
                var decommit_addr: ?*anyopaque = @ptrFromInt(new_addr_end);
                var decommit_size: windows.SIZE_T = old_addr_end - new_addr_end;

                _ = ntdll.NtAllocateVirtualMemory(windows.GetCurrentProcess(), @ptrCast(&decommit_addr), 0, &decommit_size, windows.MEM_RESET, windows.PAGE_NOACCESS);
            }
            return memory.ptr;
        }
        const old_size_aligned = mem.alignForward(usize, memory.len, page_size);
        if (new_size_aligned <= old_size_aligned) {
            return memory.ptr;
        }
        return null;
    }

    const page_aligned_len = mem.alignForward(usize, memory.len, page_size);
    if (new_size_aligned == page_aligned_len)
        return memory.ptr;

    if (posix.MREMAP != void) {
        // TODO: if the next_mmap_addr_hint is within the remapped range, update it
        const new_memory = posix.mremap(memory.ptr, memory.len, new_len, .{ .MAYMOVE = may_move }, null) catch return null;
        return new_memory.ptr;
    }

    if (new_size_aligned < page_aligned_len) {
        const ptr = memory.ptr + new_size_aligned;
        // TODO: if the next_mmap_addr_hint is within the unmapped range, update it
        posix.munmap(@alignCast(ptr[0 .. page_aligned_len - new_size_aligned]));
        return memory.ptr;
    }

    return null;
}
const std = @import("../std.zig");
const builtin = @import("builtin");
const math = std.math;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const heap = std.heap;
const assert = std.debug.assert;

pub fn SbrkAllocator(comptime sbrk: *const fn (n: usize) usize) type {
    return struct {
        pub const vtable: Allocator.VTable = .{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        };

        pub const Error = Allocator.Error;

        const max_usize = math.maxInt(usize);
        const ushift = math.Log2Int(usize);
        const bigpage_size = 64 * 1024;
        const pages_per_bigpage = bigpage_size / heap.pageSize();
        const bigpage_count = max_usize / bigpage_size;

        /// Because of storing free list pointers, the minimum size class is 3.
        const min_class = math.log2(math.ceilPowerOfTwoAssert(usize, 1 + @sizeOf(usize)));
        const size_class_count = math.log2(bigpage_size) - min_class;
        /// 0 - 1 bigpage
        /// 1 - 2 bigpages
        /// 2 - 4 bigpages
        /// etc.
        const big_size_class_count = math.log2(bigpage_count);

        var next_addrs = [1]usize{0} ** size_class_count;
        /// For each size class, points to the freed pointer.
        var frees = [1]usize{0} ** size_class_count;
        /// For each big size class, points to the freed pointer.
        var big_frees = [1]usize{0} ** big_size_class_count;

        // TODO don't do the naive locking strategy
        var lock: std.Thread.Mutex = .{};
        fn alloc(ctx: *anyopaque, len: usize, alignment: mem.Alignment, return_address: usize) ?[*]u8 {
            _ = ctx;
            _ = return_address;
            lock.lock();
            defer lock.unlock();
            // Make room for the freelist next pointer.
            const actual_len = @max(len +| @sizeOf(usize), alignment.toByteUnits());
            const slot_size = math.ceilPowerOfTwo(usize, actual_len) catch return null;
            const class = math.log2(slot_size) - min_class;
            if (class < size_class_count) {
                const addr = a: {
                    const top_free_ptr = frees[class];
                    if (top_free_ptr != 0) {
                        const node = @as(*usize, @ptrFromInt(top_free_ptr + (slot_size - @sizeOf(usize))));
                        frees[class] = node.*;
                        break :a top_free_ptr;
                    }

                    const next_addr = next_addrs[class];
                    if (next_addr % heap.pageSize() == 0) {
                        const addr = allocBigPages(1);
                        if (addr == 0) return null;
                        //std.debug.print("allocated fresh slot_size={d} class={d} addr=0x{x}\n", .{
                        //    slot_size, class, addr,
                        //});
                        next_addrs[class] = addr + slot_size;
                        break :a addr;
                    } else {
                        next_addrs[class] = next_addr + slot_size;
                        break :a next_addr;
                    }
                };
                return @as([*]u8, @ptrFromInt(addr));
            }
            const bigpages_needed = bigPagesNeeded(actual_len);
            const addr = allocBigPages(bigpages_needed);
            return @as([*]u8, @ptrFromInt(addr));
        }

        fn resize(
            ctx: *anyopaque,
            buf: []u8,
            alignment: mem.Alignment,
            new_len: usize,
            return_address: usize,
        ) bool {
            _ = ctx;
            _ = return_address;
            lock.lock();
            defer lock.unlock();
            // We don't want to move anything from one size class to another, but we
            // can recover bytes in between powers of two.
            const buf_align = alignment.toByteUnits();
            const old_actual_len = @max(buf.len + @sizeOf(usize), buf_align);
            const new_actual_len = @max(new_len +| @sizeOf(usize), buf_align);
            const old_small_slot_size = math.ceilPowerOfTwoAssert(usize, old_actual_len);
            const old_small_class = math.log2(old_small_slot_size) - min_class;
            if (old_small_class < size_class_count) {
                const new_small_slot_size = math.ceilPowerOfTwo(usize, new_actual_len) catch return false;
                return old_small_slot_size == new_small_slot_size;
            } else {
                const old_bigpages_needed = bigPagesNeeded(old_actual_len);
                const old_big_slot_pages = math.ceilPowerOfTwoAssert(usize, old_bigpages_needed);
                const new_bigpages_needed = bigPagesNeeded(new_actual_len);
                const new_big_slot_pages = math.ceilPowerOfTwo(usize, new_bigpages_needed) catch return false;
                return old_big_slot_pages == new_big_slot_pages;
            }
        }

        fn remap(
            context: *anyopaque,
            memory: []u8,
            alignment: mem.Alignment,
            new_len: usize,
            return_address: usize,
        ) ?[*]u8 {
            return if (resize(context, memory, alignment, new_len, return_address)) memory.ptr else null;
        }

        fn free(
            ctx: *anyopaque,
            buf: []u8,
            alignment: mem.Alignment,
            return_address: usize,
        ) void {
            _ = ctx;
            _ = return_address;
            lock.lock();
            defer lock.unlock();
            const buf_align = alignment.toByteUnits();
            const actual_len = @max(buf.len + @sizeOf(usize), buf_align);
            const slot_size = math.ceilPowerOfTwoAssert(usize, actual_len);
            const class = math.log2(slot_size) - min_class;
            const addr = @intFromPtr(buf.ptr);
            if (class < size_class_count```
