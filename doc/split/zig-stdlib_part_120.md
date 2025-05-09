```
being bad (e.g. for Semaphore.post() where Semaphore.wait() frees the Semaphore)
        const addr = @as(*const volatile c_int, @ptrCast(&ptr.raw));
        _ = c.umtx_wakeup(addr, to_wake);
    }
};

const WasmImpl = struct {
    fn wait(ptr: *const atomic.Value(u32), expect: u32, timeout: ?u64) error{Timeout}!void {
        if (!comptime std.Target.wasm.featureSetHas(builtin.target.cpu.features, .atomics)) {
            @compileError("WASI target missing cpu feature 'atomics'");
        }
        const to: i64 = if (timeout) |to| @intCast(to) else -1;
        const result = asm volatile (
            \\local.get %[ptr]
            \\local.get %[expected]
            \\local.get %[timeout]
            \\memory.atomic.wait32 0
            \\local.set %[ret]
            : [ret] "=r" (-> u32),
            : [ptr] "r" (&ptr.raw),
              [expected] "r" (@as(i32, @bitCast(expect))),
              [timeout] "r" (to),
        );
        switch (result) {
            0 => {}, // ok
            1 => {}, // expected =! loaded
            2 => return error.Timeout,
            else => unreachable,
        }
    }

    fn wake(ptr: *const atomic.Value(u32), max_waiters: u32) void {
        if (!comptime std.Target.wasm.featureSetHas(builtin.target.cpu.features, .atomics)) {
            @compileError("WASI target missing cpu feature 'atomics'");
        }
        assert(max_waiters != 0);
        const woken_count = asm volatile (
            \\local.get %[ptr]
            \\local.get %[waiters]
            \\memory.atomic.notify 0
            \\local.set %[ret]
            : [ret] "=r" (-> u32),
            : [ptr] "r" (&ptr.raw),
              [waiters] "r" (max_waiters),
        );
        _ = woken_count; // can be 0 when linker flag 'shared-memory' is not enabled
    }
};

/// Modified version of linux's futex and Go's sema to implement userspace wait queues with pthread:
/// https://code.woboq.org/linux/linux/kernel/futex.c.html
/// https://go.dev/src/runtime/sema.go
const PosixImpl = struct {
    const Event = struct {
        cond: c.pthread_cond_t,
        mutex: c.pthread_mutex_t,
        state: enum { empty, waiting, notified },

        fn init(self: *Event) void {
            // Use static init instead of pthread_cond/mutex_init() since this is generally faster.
            self.cond = .{};
            self.mutex = .{};
            self.state = .empty;
        }

        fn deinit(self: *Event) void {
            // Some platforms reportedly give EINVAL for statically initialized pthread types.
            const rc = c.pthread_cond_destroy(&self.cond);
            assert(rc == .SUCCESS or rc == .INVAL);

            const rm = c.pthread_mutex_destroy(&self.mutex);
            assert(rm == .SUCCESS or rm == .INVAL);

            self.* = undefined;
        }

        fn wait(self: *Event, timeout: ?u64) error{Timeout}!void {
            assert(c.pthread_mutex_lock(&self.mutex) == .SUCCESS);
            defer assert(c.pthread_mutex_unlock(&self.mutex) == .SUCCESS);

            // Early return if the event was already set.
            if (self.state == .notified) {
                return;
            }

            // Compute the absolute timeout if one was specified.
            // POSIX requires that REALTIME is used by default for the pthread timedwait functions.
            // This can be changed with pthread_condattr_setclock, but it's an extension and may not be available everywhere.
            var ts: c.timespec = undefined;
            if (timeout) |timeout_ns| {
                ts = std.posix.clock_gettime(c.CLOCK.REALTIME) catch unreachable;
                ts.sec +|= @as(@TypeOf(ts.sec), @intCast(timeout_ns / std.time.ns_per_s));
                ts.nsec += @as(@TypeOf(ts.nsec), @intCast(timeout_ns % std.time.ns_per_s));

                if (ts.nsec >= std.time.ns_per_s) {
                    ts.sec +|= 1;
                    ts.nsec -= std.time.ns_per_s;
                }
            }

            // Start waiting on the event - there can be only one thread waiting.
            assert(self.state == .empty);
            self.state = .waiting;

            while (true) {
                // Block using either pthread_cond_wait or pthread_cond_timewait if there's an absolute timeout.
                const rc = blk: {
                    if (timeout == null) break :blk c.pthread_cond_wait(&self.cond, &self.mutex);
                    break :blk c.pthread_cond_timedwait(&self.cond, &self.mutex, &ts);
                };

                // After waking up, check if the event was set.
                if (self.state == .notified) {
                    return;
                }

                assert(self.state == .waiting);
                switch (rc) {
                    .SUCCESS => {},
                    .TIMEDOUT => {
                        // If timed out, reset the event to avoid the set() thread doing an unnecessary signal().
                        self.state = .empty;
                        return error.Timeout;
                    },
                    .INVAL => unreachable, // cond, mutex, and potentially ts should all be valid
                    .PERM => unreachable, // mutex is locked when cond_*wait() functions are called
                    else => unreachable,
                }
            }
        }

        fn set(self: *Event) void {
            assert(c.pthread_mutex_lock(&self.mutex) == .SUCCESS);
            defer assert(c.pthread_mutex_unlock(&self.mutex) == .SUCCESS);

            // Make sure that multiple calls to set() were not done on the same Event.
            const old_state = self.state;
            assert(old_state != .notified);

            // Mark the event as set and wake up the waiting thread if there was one.
            // This must be done while the mutex as the wait() thread could deallocate
            // the condition variable once it observes the new state, potentially causing a UAF if done unlocked.
            self.state = .notified;
            if (old_state == .waiting) {
                assert(c.pthread_cond_signal(&self.cond) == .SUCCESS);
            }
        }
    };

    const Treap = std.Treap(usize, std.math.order);
    const Waiter = struct {
        node: Treap.Node,
        prev: ?*Waiter,
        next: ?*Waiter,
        tail: ?*Waiter,
        is_queued: bool,
        event: Event,
    };

    // An unordered set of Waiters
    const WaitList = struct {
        top: ?*Waiter = null,
        len: usize = 0,

        fn push(self: *WaitList, waiter: *Waiter) void {
            waiter.next = self.top;
            self.top = waiter;
            self.len += 1;
        }

        fn pop(self: *WaitList) ?*Waiter {
            const waiter = self.top orelse return null;
            self.top = waiter.next;
            self.len -= 1;
            return waiter;
        }
    };

    const WaitQueue = struct {
        fn insert(treap: *Treap, address: usize, waiter: *Waiter) void {
            // prepare the waiter to be inserted.
            waiter.next = null;
            waiter.is_queued = true;

            // Find the wait queue entry associated with the address.
            // If there isn't a wait queue on the address, this waiter creates the queue.
            var entry = treap.getEntryFor(address);
            const entry_node = entry.node orelse {
                waiter.prev = null;
                waiter.tail = waiter;
                entry.set(&waiter.node);
                return;
            };

            // There's a wait queue on the address; get the queue head and tail.
            const head: *Waiter = @fieldParentPtr("node", entry_node);
            const tail = head.tail orelse unreachable;

            // Push the waiter to the tail by replacing it and linking to the previous tail.
            head.tail = waiter;
            tail.next = waiter;
            waiter.prev = tail;
        }

        fn remove(treap: *Treap, address: usize, max_waiters: usize) WaitList {
            // Find the wait queue associated with this address and get the head/tail if any.
            var entry = treap.getEntryFor(address);
            var queue_head: ?*Waiter = if (entry.node) |node| @fieldParentPtr("node", node) else null;
            const queue_tail = if (queue_head) |head| head.tail else null;

            // Once we're done updating the head, fix it's tail pointer and update the treap's queue head as well.
            defer entry.set(blk: {
                const new_head = queue_head orelse break :blk null;
                new_head.tail = queue_tail;
                break :blk &new_head.node;
            });

            var removed = WaitList{};
            while (removed.len < max_waiters) {
                // dequeue and collect waiters from their wait queue.
                const waiter = queue_head orelse break;
                queue_head = waiter.next;
                removed.push(waiter);

                // When dequeueing, we must mark is_queued as false.
                // This ensures that a waiter which calls tryRemove() returns false.
                assert(waiter.is_queued);
                waiter.is_queued = false;
            }

            return removed;
        }

        fn tryRemove(treap: *Treap, address: usize, waiter: *Waiter) bool {
            if (!waiter.is_queued) {
                return false;
            }

            queue_remove: {
                // Find the wait queue associated with the address.
                var entry = blk: {
                    // A waiter without a previous link means it's the queue head that's in the treap so we can avoid lookup.
                    if (waiter.prev == null) {
                        assert(waiter.node.key == address);
                        break :blk treap.getEntryForExisting(&waiter.node);
                    }
                    break :blk treap.getEntryFor(address);
                };

                // The queue head and tail must exist if we're removing a queued waiter.
                const head: *Waiter = @fieldParentPtr("node", entry.node orelse unreachable);
                const tail = head.tail orelse unreachable;

                // A waiter with a previous link is never the head of the queue.
                if (waiter.prev) |prev| {
                    assert(waiter != head);
                    prev.next = waiter.next;

                    // A waiter with both a previous and next link is in the middle.
                    // We only need to update the surrounding waiter's links to remove it.
                    if (waiter.next) |next| {
                        assert(waiter != tail);
                        next.prev = waiter.prev;
                        break :queue_remove;
                    }

                    // A waiter with a previous but no next link means it's the tail of the queue.
                    // In that case, we need to update the head's tail reference.
                    assert(waiter == tail);
                    head.tail = waiter.prev;
                    break :queue_remove;
                }

                // A waiter with no previous link means it's the queue head of queue.
                // We must replace (or remove) the head waiter reference in the treap.
                assert(waiter == head);
                entry.set(blk: {
                    const new_head = waiter.next orelse break :blk null;
                    new_head.tail = head.tail;
                    break :blk &new_head.node;
                });
            }

            // Mark the waiter as successfully removed.
            waiter.is_queued = false;
            return true;
        }
    };

    const Bucket = struct {
        mutex: c.pthread_mutex_t align(atomic.cache_line) = .{},
        pending: atomic.Value(usize) = atomic.Value(usize).init(0),
        treap: Treap = .{},

        // Global array of buckets that addresses map to.
        // Bucket array size is pretty much arbitrary here, but it must be a power of two for fibonacci hashing.
        var buckets = [_]Bucket{.{}} ** @bitSizeOf(usize);

        // https://github.com/Amanieu/parking_lot/blob/1cf12744d097233316afa6c8b7d37389e4211756/core/src/parking_lot.rs#L343-L353
        fn from(address: usize) *Bucket {
            // The upper `@bitSizeOf(usize)` bits of the fibonacci golden ratio.
            // Hashing this via (h * k) >> (64 - b) where k=golden-ration and b=bitsize-of-array
            // evenly lays out h=hash values over the bit range even when the hash has poor entropy (identity-hash for pointers).
            const max_multiplier_bits = @bitSizeOf(usize);
            const fibonacci_multiplier = 0x9E3779B97F4A7C15 >> (64 - max_multiplier_bits);

            const max_bucket_bits = @ctz(buckets.len);
            comptime assert(std.math.isPowerOfTwo(buckets.len));

            const index = (address *% fibonacci_multiplier) >> (max_multiplier_bits - max_bucket_bits);
            return &buckets[index];
        }
    };

    const Address = struct {
        fn from(ptr: *const atomic.Value(u32)) usize {
            // Get the alignment of the pointer.
            const alignment = @alignOf(atomic.Value(u32));
            comptime assert(std.math.isPowerOfTwo(alignment));

            // Make sure the pointer is aligned,
            // then cut off the zero bits from the alignment to get the unique address.
            const addr = @intFromPtr(ptr);
            assert(addr & (alignment - 1) == 0);
            return addr >> @ctz(@as(usize, alignment));
        }
    };

    fn wait(ptr: *const atomic.Value(u32), expect: u32, timeout: ?u64) error{Timeout}!void {
        const address = Address.from(ptr);
        const bucket = Bucket.from(address);

        // Announce that there's a waiter in the bucket before checking the ptr/expect condition.
        // If the announcement is reordered after the ptr check, the waiter could deadlock:
        //
        // - T1: checks ptr == expect which is true
        // - T2: updates ptr to != expect
        // - T2: does Futex.wake(), sees no pending waiters, exits
        // - T1: bumps pending waiters (was reordered after the ptr == expect check)
        // - T1: goes to sleep and misses both the ptr change and T2's wake up
        //
        // acquire barrier to ensure the announcement happens before the ptr check below.
        var pending = bucket.pending.fetchAdd(1, .acquire);
        assert(pending < std.math.maxInt(usize));

        // If the wait gets cancelled, remove the pending count we previously added.
        // This is done outside the mutex lock to keep the critical section short in case of contention.
        var cancelled = false;
        defer if (cancelled) {
            pending = bucket.pending.fetchSub(1, .monotonic);
            assert(pending > 0);
        };

        var waiter: Waiter = undefined;
        {
            assert(c.pthread_mutex_lock(&bucket.mutex) == .SUCCESS);
            defer assert(c.pthread_mutex_unlock(&bucket.mutex) == .SUCCESS);

            cancelled = ptr.load(.monotonic) != expect;
            if (cancelled) {
                return;
            }

            waiter.event.init();
            WaitQueue.insert(&bucket.treap, address, &waiter);
        }

        defer {
            assert(!waiter.is_queued);
            waiter.event.deinit();
        }

        waiter.event.wait(timeout) catch {
            // If we fail to cancel after a timeout, it means a wake() thread dequeued us and will wake us up.
            // We must wait until the event is set as that's a signal that the wake() thread won't access the waiter memory anymore.
            // If we return early without waiting, the waiter on the stack would be invalidated and the wake() thread risks a UAF.
            defer if (!cancelled) waiter.event.wait(null) catch unreachable;

            assert(c.pthread_mutex_lock(&bucket.mutex) == .SUCCESS);
            defer assert(c.pthread_mutex_unlock(&bucket.mutex) == .SUCCESS);

            cancelled = WaitQueue.tryRemove(&bucket.treap, address, &waiter);
            if (cancelled) {
                return error.Timeout;
            }
        };
    }

    fn wake(ptr: *const atomic.Value(u32), max_waiters: u32) void {
        const address = Address.from(ptr);
        const bucket = Bucket.from(address);

        // Quick check if there's even anything to wake up.
        // The change to the ptr's value must happen before we check for pending waiters.
        // If not, the wake() thread could miss a sleeping waiter and have it deadlock:
        //
        // - T2: p = has pending waiters (reordered before the ptr update)
        // - T1: bump pending waiters
        // - T1: if ptr == expected: sleep()
        // - T2: update ptr != expected
        // - T2: p is false from earlier so doesn't wake (T1 missed ptr update and T2 missed T1 sleeping)
        //
        // What we really want here is a Release load, but that doesn't exist under the C11 memory model.
        // We could instead do `bucket.pending.fetchAdd(0, Release) == 0` which achieves effectively the same thing,
        // LLVM lowers the fetchAdd(0, .release) into an mfence+load which avoids gaining ownership of the cache-line.
        if (bucket.pending.fetchAdd(0, .release) == 0) {
            return;
        }

        // Keep a list of all the waiters notified and wake then up outside the mutex critical section.
        var notified = WaitList{};
        defer if (notified.len > 0) {
            const pending = bucket.pending.fetchSub(notified.len, .monotonic);
            assert(pending >= notified.len);

            while (notified.pop()) |waiter| {
                assert(!waiter.is_queued);
                waiter.event.set();
            }
        };

        assert(c.pthread_mutex_lock(&bucket.mutex) == .SUCCESS);
        defer assert(c.pthread_mutex_unlock(&bucket.mutex) == .SUCCESS);

        // Another pending check again to avoid the WaitQueue lookup if not necessary.
        if (bucket.pending.load(.monotonic) > 0) {
            notified = WaitQueue.remove(&bucket.treap, address, max_waiters);
        }
    }
};

test "smoke test" {
    var value = atomic.Value(u32).init(0);

    // Try waits with invalid values.
    Futex.wait(&value, 0xdeadbeef);
    Futex.timedWait(&value, 0xdeadbeef, 0) catch {};

    // Try timeout waits.
    try testing.expectError(error.Timeout, Futex.timedWait(&value, 0, 0));
    try testing.expectError(error.Timeout, Futex.timedWait(&value, 0, std.time.ns_per_ms));

    // Try wakes
    Futex.wake(&value, 0);
    Futex.wake(&value, 1);
    Futex.wake(&value, std.math.maxInt(u32));
}

test "signaling" {
    // This test requires spawning threads
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    const num_threads = 4;
    const num_iterations = 4;

    const Paddle = struct {
        value: atomic.Value(u32) = atomic.Value(u32).init(0),
        current: u32 = 0,

        fn hit(self: *@This()) void {
            _ = self.value.fetchAdd(1, .release);
            Futex.wake(&self.value, 1);
        }

        fn run(self: *@This(), hit_to: *@This()) !void {
            while (self.current < num_iterations) {
                // Wait for the value to change from hit()
                var new_value: u32 = undefined;
                while (true) {
                    new_value = self.value.load(.acquire);
                    if (new_value != self.current) break;
                    Futex.wait(&self.value, self.current);
                }

                // change the internal "current" value
                try testing.expectEqual(new_value, self.current + 1);
                self.current = new_value;

                // hit the next paddle
                hit_to.hit();
            }
        }
    };

    var paddles = [_]Paddle{.{}} ** num_threads;
    var threads = [_]std.Thread{undefined} ** num_threads;

    // Create a circle of paddles which hit each other
    for (&threads, 0..) |*t, i| {
        const paddle = &paddles[i];
        const hit_to = &paddles[(i + 1) % paddles.len];
        t.* = try std.Thread.spawn(.{}, Paddle.run, .{ paddle, hit_to });
    }

    // Hit the first paddle and wait for them all to complete by hitting each other for num_iterations.
    paddles[0].hit();
    for (threads) |t| t.join();
    for (paddles) |p| try testing.expectEqual(p.current, num_iterations);
}

test "broadcasting" {
    // This test requires spawning threads
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    const num_threads = 4;
    const num_iterations = 4;

    const Barrier = struct {
        count: atomic.Value(u32) = atomic.Value(u32).init(num_threads),
        futex: atomic.Value(u32) = atomic.Value(u32).init(0),

        fn wait(self: *@This()) !void {
            // Decrement the counter.
            // Release ensures stuff before this barrier.wait() happens before the last one.
            // Acquire for the last counter ensures stuff before previous barrier.wait()s happened before it.
            const count = self.count.fetchSub(1, .acq_rel);
            try testing.expect(count <= num_threads);
            try testing.expect(count > 0);

            // First counter to reach zero wakes all other threads.
            // Release on futex update ensures stuff before all barrier.wait()'s happens before they all return.
            if (count - 1 == 0) {
                self.futex.store(1, .release);
                Futex.wake(&self.futex, num_threads - 1);
                return;
            }

            // Other threads wait until last counter wakes them up.
            // Acquire on futex synchronizes with last barrier count to ensure stuff before all barrier.wait()'s happen before us.
            while (self.futex.load(.acquire) == 0) {
                Futex.wait(&self.futex, 0);
            }
        }
    };

    const Broadcast = struct {
        barriers: [num_iterations]Barrier = [_]Barrier{.{}} ** num_iterations,
        threads: [num_threads]std.Thread = undefined,

        fn run(self: *@This()) !void {
            for (&self.barriers) |*barrier| {
                try barrier.wait();
            }
        }
    };

    var broadcast = Broadcast{};
    for (&broadcast.threads) |*t| t.* = try std.Thread.spawn(.{}, Broadcast.run, .{&broadcast});
    for (broadcast.threads) |t| t.join();
}

/// Deadline is used to wait efficiently for a pointer's value to change using Futex and a fixed timeout.
///
/// Futex's timedWait() api uses a relative duration which suffers from over-waiting
/// when used in a loop which is often required due to the possibility of spurious wakeups.
///
/// Deadline instead converts the relative timeout to an absolute one so that multiple calls
/// to Futex timedWait() can block for and report more accurate error.Timeouts.
pub const Deadline = struct {
    timeout: ?u64,
    started: std.time.Timer,

    /// Create the deadline to expire after the given amount of time in nanoseconds passes.
    /// Pass in `null` to have the deadline call `Futex.wait()` and never expire.
    pub fn init(expires_in_ns: ?u64) Deadline {
        var deadline: Deadline = undefined;
        deadline.timeout = expires_in_ns;

        // std.time.Timer is required to be supported for somewhat accurate reportings of error.Timeout.
        if (deadline.timeout != null) {
            deadline.started = std.time.Timer.start() catch unreachable;
        }

        return deadline;
    }

    /// Wait until either:
    /// - the `ptr`'s value changes from `expect`.
    /// - `Futex.wake()` is called on the `ptr`.
    /// - A spurious wake occurs.
    /// - The deadline expires; In which case `error.Timeout` is returned.
    pub fn wait(self: *Deadline, ptr: *const atomic.Value(u32), expect: u32) error{Timeout}!void {
        @branchHint(.cold);

        // Check if we actually have a timeout to wait until.
        // If not just wait "forever".
        const timeout_ns = self.timeout orelse {
            return Futex.wait(ptr, expect);
        };

        // Get how much time has passed since we started waiting
        // then subtract that from the init() timeout to get how much longer to wait.
        // Use overflow to detect when we've been waiting longer than the init() timeout.
        const elapsed_ns = self.started.read();
        const until_timeout_ns = std.math.sub(u64, timeout_ns, elapsed_ns) catch 0;
        return Futex.timedWait(ptr, expect, until_timeout_ns);
    }
};

test "Deadline" {
    var deadline = Deadline.init(100 * std.time.ns_per_ms);
    var futex_word = atomic.Value(u32).init(0);

    while (true) {
        deadline.wait(&futex_word, 0) catch break;
    }
}
//! Mutex is a synchronization primitive which enforces atomic access to a
//! shared region of code known as the "critical section".
//!
//! It does this by blocking ensuring only one thread is in the critical
//! section at any given point in time by blocking the others.
//!
//! Mutex can be statically initialized and is at most `@sizeOf(u64)` large.
//! Use `lock()` or `tryLock()` to enter the critical section and `unlock()` to leave it.

const std = @import("../std.zig");
const builtin = @import("builtin");
const Mutex = @This();

const assert = std.debug.assert;
const testing = std.testing;
const Thread = std.Thread;
const Futex = Thread.Futex;

impl: Impl = .{},

pub const Recursive = @import("Mutex/Recursive.zig");

/// Tries to acquire the mutex without blocking the caller's thread.
/// Returns `false` if the calling thread would have to block to acquire it.
/// Otherwise, returns `true` and the caller should `unlock()` the Mutex to release it.
pub fn tryLock(self: *Mutex) bool {
    return self.impl.tryLock();
}

/// Acquires the mutex, blocking the caller's thread until it can.
/// It is undefined behavior if the mutex is already held by the caller's thread.
/// Once acquired, call `unlock()` on the Mutex to release it.
pub fn lock(self: *Mutex) void {
    self.impl.lock();
}

/// Releases the mutex which was previously acquired with `lock()` or `tryLock()`.
/// It is undefined behavior if the mutex is unlocked from a different thread that it was locked from.
pub fn unlock(self: *Mutex) void {
    self.impl.unlock();
}

const Impl = if (builtin.mode == .Debug and !builtin.single_threaded)
    DebugImpl
else
    ReleaseImpl;

const ReleaseImpl = if (builtin.single_threaded)
    SingleThreadedImpl
else if (builtin.os.tag == .windows)
    WindowsImpl
else if (builtin.os.tag.isDarwin())
    DarwinImpl
else
    FutexImpl;

const DebugImpl = struct {
    locking_thread: std.atomic.Value(Thread.Id) = std.atomic.Value(Thread.Id).init(0), // 0 means it's not locked.
    impl: ReleaseImpl = .{},

    inline fn tryLock(self: *@This()) bool {
        const locking = self.impl.tryLock();
        if (locking) {
            self.locking_thread.store(Thread.getCurrentId(), .unordered);
        }
        return locking;
    }

    inline fn lock(self: *@This()) void {
        const current_id = Thread.getCurrentId();
        if (self.locking_thread.load(.unordered) == current_id and current_id != 0) {
            @panic("Deadlock detected");
        }
        self.impl.lock();
        self.locking_thread.store(current_id, .unordered);
    }

    inline fn unlock(self: *@This()) void {
        assert(self.locking_thread.load(.unordered) == Thread.getCurrentId());
        self.locking_thread.store(0, .unordered);
        self.impl.unlock();
    }
};

const SingleThreadedImpl = struct {
    is_locked: bool = false,

    fn tryLock(self: *@This()) bool {
        if (self.is_locked) return false;
        self.is_locked = true;
        return true;
    }

    fn lock(self: *@This()) void {
        if (!self.tryLock()) {
            unreachable; // deadlock detected
        }
    }

    fn unlock(self: *@This()) void {
        assert(self.is_locked);
        self.is_locked = false;
    }
};

/// SRWLOCK on windows is almost always faster than Futex solution.
/// It also implements an efficient Condition with requeue support for us.
const WindowsImpl = struct {
    srwlock: windows.SRWLOCK = .{},

    fn tryLock(self: *@This()) bool {
        return windows.kernel32.TryAcquireSRWLockExclusive(&self.srwlock) != windows.FALSE;
    }

    fn lock(self: *@This()) void {
        windows.kernel32.AcquireSRWLockExclusive(&self.srwlock);
    }

    fn unlock(self: *@This()) void {
        windows.kernel32.ReleaseSRWLockExclusive(&self.srwlock);
    }

    const windows = std.os.windows;
};

/// os_unfair_lock on darwin supports priority inheritance and is generally faster than Futex solutions.
const DarwinImpl = struct {
    oul: c.os_unfair_lock = .{},

    fn tryLock(self: *@This()) bool {
        return c.os_unfair_lock_trylock(&self.oul);
    }

    fn lock(self: *@This()) void {
        c.os_unfair_lock_lock(&self.oul);
    }

    fn unlock(self: *@This()) void {
        c.os_unfair_lock_unlock(&self.oul);
    }

    const c = std.c;
};

const FutexImpl = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(unlocked),

    const unlocked: u32 = 0b00;
    const locked: u32 = 0b01;
    const contended: u32 = 0b11; // must contain the `locked` bit for x86 optimization below

    fn lock(self: *@This()) void {
        if (!self.tryLock())
            self.lockSlow();
    }

    fn tryLock(self: *@This()) bool {
        // On x86, use `lock bts` instead of `lock cmpxchg` as:
        // - they both seem to mark the cache-line as modified regardless: https://stackoverflow.com/a/63350048
        // - `lock bts` is smaller instruction-wise which makes it better for inlining
        if (builtin.target.cpu.arch.isX86()) {
            const locked_bit = @ctz(locked);
            return self.state.bitSet(locked_bit, .acquire) == 0;
        }

        // Acquire barrier ensures grabbing the lock happens before the critical section
        // and that the previous lock holder's critical section happens before we grab the lock.
        return self.state.cmpxchgWeak(unlocked, locked, .acquire, .monotonic) == null;
    }

    fn lockSlow(self: *@This()) void {
        @branchHint(.cold);

        // Avoid doing an atomic swap below if we already know the state is contended.
        // An atomic swap unconditionally stores which marks the cache-line as modified unnecessarily.
        if (self.state.load(.monotonic) == contended) {
            Futex.wait(&self.state, contended);
        }

        // Try to acquire the lock while also telling the existing lock holder that there are threads waiting.
        //
        // Once we sleep on the Futex, we must acquire the mutex using `contended` rather than `locked`.
        // If not, threads sleeping on the Futex wouldn't see the state change in unlock and potentially deadlock.
        // The downside is that the last mutex unlocker will see `contended` and do an unnecessary Futex wake
        // but this is better than having to wake all waiting threads on mutex unlock.
        //
        // Acquire barrier ensures grabbing the lock happens before the critical section
        // and that the previous lock holder's critical section happens before we grab the lock.
        while (self.state.swap(contended, .acquire) != unlocked) {
            Futex.wait(&self.state, contended);
        }
    }

    fn unlock(self: *@This()) void {
        // Unlock the mutex and wake up a waiting thread if any.
        //
        // A waiting thread will acquire with `contended` instead of `locked`
        // which ensures that it wakes up another thread on the next unlock().
        //
        // Release barrier ensures the critical section happens before we let go of the lock
        // and that our critical section happens before the next lock holder grabs the lock.
        const state = self.state.swap(unlocked, .release);
        assert(state != unlocked);

        if (state == contended) {
            Futex.wake(&self.state, 1);
        }
    }
};

test "smoke test" {
    var mutex = Mutex{};

    try testing.expect(mutex.tryLock());
    try testing.expect(!mutex.tryLock());
    mutex.unlock();

    mutex.lock();
    try testing.expect(!mutex.tryLock());
    mutex.unlock();
}

// A counter which is incremented without atomic instructions
const NonAtomicCounter = struct {
    // direct u128 could maybe use xmm ops on x86 which are atomic
    value: [2]u64 = [_]u64{ 0, 0 },

    fn get(self: NonAtomicCounter) u128 {
        return @as(u128, @bitCast(self.value));
    }

    fn inc(self: *NonAtomicCounter) void {
        for (@as([2]u64, @bitCast(self.get() + 1)), 0..) |v, i| {
            @as(*volatile u64, @ptrCast(&self.value[i])).* = v;
        }
    }
};

test "many uncontended" {
    // This test requires spawning threads.
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    const num_threads = 4;
    const num_increments = 1000;

    const Runner = struct {
        mutex: Mutex = .{},
        thread: Thread = undefined,
        counter: NonAtomicCounter = .{},

        fn run(self: *@This()) void {
            var i: usize = num_increments;
            while (i > 0) : (i -= 1) {
                self.mutex.lock();
                defer self.mutex.unlock();

                self.counter.inc();
            }
        }
    };

    var runners = [_]Runner{.{}} ** num_threads;
    for (&runners) |*r| r.thread = try Thread.spawn(.{}, Runner.run, .{r});
    for (runners) |r| r.thread.join();
    for (runners) |r| try testing.expectEqual(r.counter.get(), num_increments);
}

test "many contended" {
    // This test requires spawning threads.
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    const num_threads = 4;
    const num_increments = 1000;

    const Runner = struct {
        mutex: Mutex = .{},
        counter: NonAtomicCounter = .{},

        fn run(self: *@This()) void {
            var i: usize = num_increments;
            while (i > 0) : (i -= 1) {
                // Occasionally hint to let another thread run.
                defer if (i % 100 == 0) Thread.yield() catch {};

                self.mutex.lock();
                defer self.mutex.unlock();

                self.counter.inc();
            }
        }
    };

    var runner = Runner{};

    var threads: [num_threads]Thread = undefined;
    for (&threads) |*t| t.* = try Thread.spawn(.{}, Runner.run, .{&runner});
    for (threads) |t| t.join();

    try testing.expectEqual(runner.counter.get(), num_increments * num_threads);
}

// https://github.com/ziglang/zig/issues/19295
//test @This() {
//    var m: Mutex = .{};
//
//    {
//        m.lock();
//        defer m.unlock();
//        // ... critical section code
//    }
//
//    if (m.tryLock()) {
//        defer m.unlock();
//        // ... critical section code
//    }
//}
//! A synchronization primitive enforcing atomic access to a shared region of
//! code known as the "critical section".
//!
//! Equivalent to `std.Mutex` except it allows the same thread to obtain the
//! lock multiple times.
//!
//! A recursive mutex is an abstraction layer on top of a regular mutex;
//! therefore it is recommended to use instead `std.Mutex` unless there is a
//! specific reason a recursive mutex is warranted.

const std = @import("../../std.zig");
const Recursive = @This();
const Mutex = std.Thread.Mutex;
const assert = std.debug.assert;

mutex: Mutex,
thread_id: std.Thread.Id,
lock_count: usize,

pub const init: Recursive = .{
    .mutex = .{},
    .thread_id = invalid_thread_id,
    .lock_count = 0,
};

/// Acquires the `Mutex` without blocking the caller's thread.
///
/// Returns `false` if the calling thread would have to block to acquire it.
///
/// Otherwise, returns `true` and the caller should `unlock()` the Mutex to release it.
pub fn tryLock(r: *Recursive) bool {
    const current_thread_id = std.Thread.getCurrentId();
    if (@atomicLoad(std.Thread.Id, &r.thread_id, .unordered) != current_thread_id) {
        if (!r.mutex.tryLock()) return false;
        assert(r.lock_count == 0);
        @atomicStore(std.Thread.Id, &r.thread_id, current_thread_id, .unordered);
    }
    r.lock_count += 1;
    return true;
}

/// Acquires the `Mutex`, blocking the current thread while the mutex is
/// already held by another thread.
///
/// The `Mutex` can be held multiple times by the same thread.
///
/// Once acquired, call `unlock` on the `Mutex` to release it, regardless
/// of whether the lock was already held by the same thread.
pub fn lock(r: *Recursive) void {
    const current_thread_id = std.Thread.getCurrentId();
    if (@atomicLoad(std.Thread.Id, &r.thread_id, .unordered) != current_thread_id) {
        r.mutex.lock();
        assert(r.lock_count == 0);
        @atomicStore(std.Thread.Id, &r.thread_id, current_thread_id, .unordered);
    }
    r.lock_count += 1;
}

/// Releases the `Mutex` which was previously acquired with `lock` or `tryLock`.
///
/// It is undefined behavior to unlock from a different thread that it was
/// locked from.
pub fn unlock(r: *Recursive) void {
    r.lock_count -= 1;
    if (r.lock_count == 0) {
        @atomicStore(std.Thread.Id, &r.thread_id, invalid_thread_id, .unordered);
        r.mutex.unlock();
    }
}

/// A value that does not alias any other thread id.
const invalid_thread_id: std.Thread.Id = std.math.maxInt(std.Thread.Id);
const std = @import("std");
const builtin = @import("builtin");
const Pool = @This();
const WaitGroup = @import("WaitGroup.zig");

mutex: std.Thread.Mutex = .{},
cond: std.Thread.Condition = .{},
run_queue: std.SinglyLinkedList = .{},
is_running: bool = true,
allocator: std.mem.Allocator,
threads: if (builtin.single_threaded) [0]std.Thread else []std.Thread,
ids: if (builtin.single_threaded) struct {
    inline fn deinit(_: @This(), _: std.mem.Allocator) void {}
    fn getIndex(_: @This(), _: std.Thread.Id) usize {
        return 0;
    }
} else std.AutoArrayHashMapUnmanaged(std.Thread.Id, void),

const Runnable = struct {
    runFn: RunProto,
    node: std.SinglyLinkedList.Node = .{},
};

const RunProto = *const fn (*Runnable, id: ?usize) void;

pub const Options = struct {
    allocator: std.mem.Allocator,
    n_jobs: ?usize = null,
    track_ids: bool = false,
    stack_size: usize = std.Thread.SpawnConfig.default_stack_size,
};

pub fn init(pool: *Pool, options: Options) !void {
    const allocator = options.allocator;

    pool.* = .{
        .allocator = allocator,
        .threads = if (builtin.single_threaded) .{} else &.{},
        .ids = .{},
    };

    if (builtin.single_threaded) {
        return;
    }

    const thread_count = options.n_jobs orelse @max(1, std.Thread.getCpuCount() catch 1);
    if (options.track_ids) {
        try pool.ids.ensureTotalCapacity(allocator, 1 + thread_count);
        pool.ids.putAssumeCapacityNoClobber(std.Thread.getCurrentId(), {});
    }

    // kill and join any threads we spawned and free memory on error.
    pool.threads = try allocator.alloc(std.Thread, thread_count);
    var spawned: usize = 0;
    errdefer pool.join(spawned);

    for (pool.threads) |*thread| {
        thread.* = try std.Thread.spawn(.{
            .stack_size = options.stack_size,
            .allocator = allocator,
        }, worker, .{pool});
        spawned += 1;
    }
}

pub fn deinit(pool: *Pool) void {
    pool.join(pool.threads.len); // kill and join all threads.
    pool.ids.deinit(pool.allocator);
    pool.* = undefined;
}

fn join(pool: *Pool, spawned: usize) void {
    if (builtin.single_threaded) {
        return;
    }

    {
        pool.mutex.lock();
        defer pool.mutex.unlock();

        // ensure future worker threads exit the dequeue loop
        pool.is_running = false;
    }

    // wake up any sleeping threads (this can be done outside the mutex)
    // then wait for all the threads we know are spawned to complete.
    pool.cond.broadcast();
    for (pool.threads[0..spawned]) |thread| {
        thread.join();
    }

    pool.allocator.free(pool.threads);
}

/// Runs `func` in the thread pool, calling `WaitGroup.start` beforehand, and
/// `WaitGroup.finish` after it returns.
///
/// In the case that queuing the function call fails to allocate memory, or the
/// target is single-threaded, the function is called directly.
pub fn spawnWg(pool: *Pool, wait_group: *WaitGroup, comptime func: anytype, args: anytype) void {
    wait_group.start();

    if (builtin.single_threaded) {
        @call(.auto, func, args);
        wait_group.finish();
        return;
    }

    const Args = @TypeOf(args);
    const Closure = struct {
        arguments: Args,
        pool: *Pool,
        runnable: Runnable = .{ .runFn = runFn },
        wait_group: *WaitGroup,

        fn runFn(runnable: *Runnable, _: ?usize) void {
            const closure: *@This() = @alignCast(@fieldParentPtr("runnable", runnable));
            @call(.auto, func, closure.arguments);
            closure.wait_group.finish();

            // The thread pool's allocator is protected by the mutex.
            const mutex = &closure.pool.mutex;
            mutex.lock();
            defer mutex.unlock();

            closure.pool.allocator.destroy(closure);
        }
    };

    {
        pool.mutex.lock();

        const closure = pool.allocator.create(Closure) catch {
            pool.mutex.unlock();
            @call(.auto, func, args);
            wait_group.finish();
            return;
        };
        closure.* = .{
            .arguments = args,
            .pool = pool,
            .wait_group = wait_group,
        };

        pool.run_queue.prepend(&closure.runnable.node);
        pool.mutex.unlock();
    }

    // Notify waiting threads outside the lock to try and keep the critical section small.
    pool.cond.signal();
}

/// Runs `func` in the thread pool, calling `WaitGroup.start` beforehand, and
/// `WaitGroup.finish` after it returns.
///
/// The first argument passed to `func` is a dense `usize` thread id, the rest
/// of the arguments are passed from `args`. Requires the pool to have been
/// initialized with `.track_ids = true`.
///
/// In the case that queuing the function call fails to allocate memory, or the
/// target is single-threaded, the function is called directly.
pub fn spawnWgId(pool: *Pool, wait_group: *WaitGroup, comptime func: anytype, args: anytype) void {
    wait_group.start();

    if (builtin.single_threaded) {
        @call(.auto, func, .{0} ++ args);
        wait_group.finish();
        return;
    }

    const Args = @TypeOf(args);
    const Closure = struct {
        arguments: Args,
        pool: *Pool,
        runnable: Runnable = .{ .runFn = runFn },
        wait_group: *WaitGroup,

        fn runFn(runnable: *Runnable, id: ?usize) void {
            const closure: *@This() = @alignCast(@fieldParentPtr("runnable", runnable));
            @call(.auto, func, .{id.?} ++ closure.arguments);
            closure.wait_group.finish();

            // The thread pool's allocator is protected by the mutex.
            const mutex = &closure.pool.mutex;
            mutex.lock();
            defer mutex.unlock();

            closure.pool.allocator.destroy(closure);
        }
    };

    {
        pool.mutex.lock();

        const closure = pool.allocator.create(Closure) catch {
            const id: ?usize = pool.ids.getIndex(std.Thread.getCurrentId());
            pool.mutex.unlock();
            @call(.auto, func, .{id.?} ++ args);
            wait_group.finish();
            return;
        };
        closure.* = .{
            .arguments = args,
            .pool = pool,
            .wait_group = wait_group,
        };

        pool.run_queue.prepend(&closure.runnable.node);
        pool.mutex.unlock();
    }

    // Notify waiting threads outside the lock to try and keep the critical section small.
    pool.cond.signal();
}

pub fn spawn(pool: *Pool, comptime func: anytype, args: anytype) !void {
    if (builtin.single_threaded) {
        @call(.auto, func, args);
        return;
    }

    const Args = @TypeOf(args);
    const Closure = struct {
        arguments: Args,
        pool: *Pool,
        runnable: Runnable = .{ .runFn = runFn },

        fn runFn(runnable: *Runnable, _: ?usize) void {
            const closure: *@This() = @alignCast(@fieldParentPtr("runnable", runnable));
            @call(.auto, func, closure.arguments);

            // The thread pool's allocator is protected by the mutex.
            const mutex = &closure.pool.mutex;
            mutex.lock();
            defer mutex.unlock();

            closure.pool.allocator.destroy(closure);
        }
    };

    {
        pool.mutex.lock();
        defer pool.mutex.unlock();

        const closure = try pool.allocator.create(Closure);
        closure.* = .{
            .arguments = args,
            .pool = pool,
        };

        pool.run_queue.prepend(&closure.runnable.node);
    }

    // Notify waiting threads outside the lock to try and keep the critical section small.
    pool.cond.signal();
}

test spawn {
    const TestFn = struct {
        fn checkRun(completed: *bool) void {
            completed.* = true;
        }
    };

    var completed: bool = false;

    {
        var pool: Pool = undefined;
        try pool.init(.{
            .allocator = std.testing.allocator,
        });
        defer pool.deinit();
        try pool.spawn(TestFn.checkRun, .{&completed});
    }

    try std.testing.expectEqual(true, completed);
}

fn worker(pool: *Pool) void {
    pool.mutex.lock();
    defer pool.mutex.unlock();

    const id: ?usize = if (pool.ids.count() > 0) @intCast(pool.ids.count()) else null;
    if (id) |_| pool.ids.putAssumeCapacityNoClobber(std.Thread.getCurrentId(), {});

    while (true) {
        while (pool.run_queue.popFirst()) |run_node| {
            // Temporarily unlock the mutex in order to execute the run_node
            pool.mutex.unlock();
            defer pool.mutex.lock();

            const runnable: *Runnable = @fieldParentPtr("node", run_node);
            runnable.runFn(runnable, id);
        }

        // Stop executing instead of waiting if the thread pool is no longer running.
        if (pool.is_running) {
            pool.cond.wait(&pool.mutex);
        } else {
            break;
        }
    }
}

pub fn waitAndWork(pool: *Pool, wait_group: *WaitGroup) void {
    var id: ?usize = null;

    while (!wait_group.isDone()) {
        pool.mutex.lock();
        if (pool.run_queue.popFirst()) |run_node| {
            id = id orelse pool.ids.getIndex(std.Thread.getCurrentId());
            pool.mutex.unlock();
            const runnable: *Runnable = @fieldParentPtr("node", run_node);
            runnable.runFn(runnable, id);
            continue;
        }

        pool.mutex.unlock();
        wait_group.wait();
        return;
    }
}

pub fn getIdCount(pool: *Pool) usize {
    return @intCast(1 + pool.threads.len);
}
//! ResetEvent is a thread-safe bool which can be set to true/false ("set"/"unset").
//! It can also block threads until the "bool" is set with cancellation via timed waits.
//! ResetEvent can be statically initialized and is at most `@sizeOf(u64)` large.

const std = @import("../std.zig");
const builtin = @import("builtin");
const ResetEvent = @This();

const os = std.os;
const assert = std.debug.assert;
const testing = std.testing;
const Futex = std.Thread.Futex;

impl: Impl = .{},

/// Returns if the ResetEvent was set().
/// Once reset() is called, this returns false until the next set().
/// The memory accesses before the set() can be said to happen before isSet() returns true.
pub fn isSet(self: *const ResetEvent) bool {
    return self.impl.isSet();
}

/// Block's the callers thread until the ResetEvent is set().
/// This is effectively a more efficient version of `while (!isSet()) {}`.
/// The memory accesses before the set() can be said to happen before wait() returns.
pub fn wait(self: *ResetEvent) void {
    self.impl.wait(null) catch |err| switch (err) {
        error.Timeout => unreachable, // no timeout provided so we shouldn't have timed-out
    };
}

/// Block's the callers thread until the ResetEvent is set(), or until the corresponding timeout expires.
/// If the timeout expires before the ResetEvent is set, `error.Timeout` is returned.
/// This is effectively a more efficient version of `while (!isSet()) {}`.
/// The memory accesses before the set() can be said to happen before timedWait() returns without error.
pub fn timedWait(self: *ResetEvent, timeout_ns: u64) error{Timeout}!void {
    return self.impl.wait(timeout_ns);
}

/// Marks the ResetEvent as "set" and unblocks any threads in `wait()` or `timedWait()` to observe the new state.
/// The ResetEvent says "set" until reset() is called, making future set() calls do nothing semantically.
/// The memory accesses before set() can be said to happen before isSet() returns true or wait()/timedWait() return successfully.
pub fn set(self: *ResetEvent) void {
    self.impl.set();
}

/// Unmarks the ResetEvent from its "set" state if set() was called previously.
/// It is undefined behavior is reset() is called while threads are blocked in wait() or timedWait().
/// Concurrent calls to set(), isSet() and reset() are allowed.
pub fn reset(self: *ResetEvent) void {
    self.impl.reset();
}

const Impl = if (builtin.single_threaded)
    SingleThreadedImpl
else
    FutexImpl;

const SingleThreadedImpl = struct {
    is_set: bool = false,

    fn isSet(self: *const Impl) bool {
        return self.is_set;
    }

    fn wait(self: *Impl, timeout: ?u64) error{Timeout}!void {
        if (self.isSet()) {
            return;
        }

        // There are no other threads to wake us up.
        // So if we wait without a timeout we would never wake up.
        const timeout_ns = timeout orelse {
            unreachable; // deadlock detected
        };

        std.time.sleep(timeout_ns);
        return error.Timeout;
    }

    fn set(self: *Impl) void {
        self.is_set = true;
    }

    fn reset(self: *Impl) void {
        self.is_set = false;
    }
};

const FutexImpl = struct {
    state: std.atomic.Value(u32) = std.atomic.Value(u32).init(unset),

    const unset = 0;
    const waiting = 1;
    const is_set = 2;

    fn isSet(self: *const Impl) bool {
        // Acquire barrier ensures memory accesses before set() happen before we return true.
        return self.state.load(.acquire) == is_set;
    }

    fn wait(self: *Impl, timeout: ?u64) error{Timeout}!void {
        // Outline the slow path to allow isSet() to be inlined
        if (!self.isSet()) {
            return self.waitUntilSet(timeout);
        }
    }

    fn waitUntilSet(self: *Impl, timeout: ?u64) error{Timeout}!void {
        @branchHint(.cold);

        // Try to set the state from `unset` to `waiting` to indicate
        // to the set() thread that others are blocked on the ResetEvent.
        // We avoid using any strict barriers until the end when we know the ResetEvent is set.
        var state = self.state.load(.acquire);
        if (state == unset) {
            state = self.state.cmpxchgStrong(state, waiting, .acquire, .acquire) orelse waiting;
        }

        // Wait until the ResetEvent is set since the state is waiting.
        if (state == waiting) {
            var futex_deadline = Futex.Deadline.init(timeout);
            while (true) {
                const wait_result = futex_deadline.wait(&self.state, waiting);

                // Check if the ResetEvent was set before possibly reporting error.Timeout below.
                state = self.state.load(.acquire);
                if (state != waiting) {
                    break;
                }

                try wait_result;
            }
        }

        assert(state == is_set);
    }

    fn set(self: *Impl) void {
        // Quick check if the ResetEvent is already set before doing the atomic swap below.
        // set() could be getting called quite often and multiple threads calling swap() increases contention unnecessarily.
        if (self.state.load(.monotonic) == is_set) {
            return;
        }

        // Mark the ResetEvent as set and unblock all waiters waiting on it if any.
        // Release barrier ensures memory accesses before set() happen before the ResetEvent is observed to be "set".
        if (self.state.swap(is_set, .release) == waiting) {
            Futex.wake(&self.state, std.math.maxInt(u32));
        }
    }

    fn reset(self: *Impl) void {
        self.state.store(unset, .monotonic);
    }
};

test "smoke test" {
    // make sure the event is unset
    var event = ResetEvent{};
    try testing.expectEqual(false, event.isSet());

    // make sure the event gets set
    event.set();
    try testing.expectEqual(true, event.isSet());

    // make sure the event gets unset again
    event.reset();
    try testing.expectEqual(false, event.isSet());

    // waits should timeout as there's no other thread to set the event
    try testing.expectError(error.Timeout, event.timedWait(0));
    try testing.expectError(error.Timeout, event.timedWait(std.time.ns_per_ms));

    // set the event again and make sure waits complete
    event.set();
    event.wait();
    try event.timedWait(std.time.ns_per_ms);
    try testing.expectEqual(true, event.isSet());
}

test "signaling" {
    // This test requires spawning threads
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    const Context = struct {
        in: ResetEvent = .{},
        out: ResetEvent = .{},
        value: usize = 0,

        fn input(self: *@This()) !void {
            // wait for the value to become 1
            self.in.wait();
            self.in.reset();
            try testing.expectEqual(self.value, 1);

            // bump the value and wake up output()
            self.value = 2;
            self.out.set();

            // wait for output to receive 2, bump the value and wake us up with 3
            self.in.wait();
            self.in.reset();
            try testing.expectEqual(self.value, 3);

            // bump the value and wake up output() for it to see 4
            self.value = 4;
            self.out.set();
        }

        fn output(self: *@This()) !void {
            // start with 0 and bump the value for input to see 1
            try testing.expectEqual(self.value, 0);
            self.value = 1;
            self.in.set();

            // wait for input to receive 1, bump the value to 2 and wake us up
            self.out.wait();
            self.out.reset();
            try testing.expectEqual(self.value, 2);

            // bump the value to 3 for input to see (rhymes)
            self.value = 3;
            self.in.set();

            // wait for input to bump the value to 4 and receive no more (rhymes)
            self.out.wait();
            self.out.reset();
            try testing.expectEqual(self.value, 4);
        }
    };

    var ctx = Context{};

    const thread = try std.Thread.spawn(.{}, Context.output, .{&ctx});
    defer thread.join();

    try ctx.input();
}

test "broadcast" {
    // This test requires spawning threads
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    const num_threads = 10;
    const Barrier = struct {
        event: ResetEvent = .{},
        counter: std.atomic.Value(usize) = std.atomic.Value(usize).init(num_threads),

        fn wait(self: *@This()) void {
            if (self.counter.fetchSub(1, .acq_rel) == 1) {
                self.event.set();
            }
        }
    };

    const Context = struct {
        start_barrier: Barrier = .{},
        finish_barrier: Barrier = .{},

        fn run(self: *@This()) void {
            self.start_barrier.wait();
            self.finish_barrier.wait();
        }
    };

    var ctx = Context{};
    var threads: [num_threads - 1]std.Thread = undefined;

    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Context.run, .{&ctx});
    defer for (threads) |t| t.join();

    ctx.run();
}
//! A lock that supports one writer or many readers.
//! This API is for kernel threads, not evented I/O.
//! This API requires being initialized at runtime, and initialization
//! can fail. Once initialized, the core operations cannot fail.

impl: Impl = .{},

const RwLock = @This();
const std = @import("../std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;

pub const Impl = if (builtin.single_threaded)
    SingleThreadedRwLock
else if (std.Thread.use_pthreads)
    PthreadRwLock
else
    DefaultRwLock;

/// Attempts to obtain exclusive lock ownership.
/// Returns `true` if the lock is obtained, `false` otherwise.
pub fn tryLock(rwl: *RwLock) bool {
    return rwl.impl.tryLock();
}

/// Blocks until exclusive lock ownership is acquired.
pub fn lock(rwl: *RwLock) void {
    return rwl.impl.lock();
}

/// Releases a held exclusive lock.
/// Asserts the lock is held exclusively.
pub fn unlock(rwl: *RwLock) void {
    return rwl.impl.unlock();
}

/// Attempts to obtain shared lock ownership.
/// Returns `true` if the lock is obtained, `false` otherwise.
pub fn tryLockShared(rwl: *RwLock) bool {
    return rwl.impl.tryLockShared();
}

/// Obtains shared lock ownership.
/// Blocks if another thread has exclusive ownership.
/// May block if another thread is attempting to get exclusive ownership.
pub fn lockShared(rwl: *RwLock) void {
    return rwl.impl.lockShared();
}

/// Releases a held shared lock.
pub fn unlockShared(rwl: *RwLock) void {
    return rwl.impl.unlockShared();
}

/// Single-threaded applications use this for deadlock checks in
/// debug mode, and no-ops in release modes.
pub const SingleThreadedRwLock = struct {
    state: enum { unlocked, locked_exclusive, locked_shared } = .unlocked,
    shared_count: usize = 0,

    /// Attempts to obtain exclusive lock ownership.
    /// Returns `true` if the lock is obtained, `false` otherwise.
    pub fn tryLock(rwl: *SingleThreadedRwLock) bool {
        switch (rwl.state) {
            .unlocked => {
                assert(rwl.shared_count == 0);
                rwl.state = .locked_exclusive;
                return true;
            },
            .locked_exclusive, .locked_shared => return false,
        }
    }

    /// Blocks until exclusive lock ownership is acquired.
    pub fn lock(rwl: *SingleThreadedRwLock) void {
        assert(rwl.state == .unlocked); // deadlock detected
        assert(rwl.shared_count == 0); // corrupted state detected
        rwl.state = .locked_exclusive;
    }

    /// Releases a held exclusive lock.
    /// Asserts the lock is held exclusively.
    pub fn unlock(rwl: *SingleThreadedRwLock) void {
        assert(rwl.state == .locked_exclusive);
        assert(rwl.shared_count == 0); // corrupted state detected
        rwl.state = .unlocked;
    }

    /// Attempts to obtain shared lock ownership.
    /// Returns `true` if the lock is obtained, `false` otherwise.
    pub fn tryLockShared(rwl: *SingleThreadedRwLock) bool {
        switch (rwl.state) {
            .unlocked => {
                rwl.state = .locked_shared;
                assert(rwl.shared_count == 0);
                rwl.shared_count = 1;
                return true;
            },
            .locked_shared => {
                rwl.shared_count += 1;
                return true;
            },
            .locked_exclusive => return false,
        }
    }

    /// Blocks until shared lock ownership is acquired.
    pub fn lockShared(rwl: *SingleThreadedRwLock) void {
        switch (rwl.state) {
            .unlocked => {
                rwl.state = .locked_shared;
                assert(rwl.shared_count == 0);
                rwl.shared_count = 1;
            },
            .locked_shared => {
                rwl.shared_count += 1;
            },
            .locked_exclusive => unreachable, // deadlock detected
        }
    }

    /// Releases a held shared lock.
    pub fn unlockShared(rwl: *SingleThreadedRwLock) void {
        switch (rwl.state) {
            .unlocked => unreachable, // too many calls to `unlockShared`
            .locked_exclusive => unreachable, // exclusively held lock
            .locked_shared => {
                rwl.shared_count -= 1;
                if (rwl.shared_count == 0) {
                    rwl.state = .unlocked;
                }
            },
        }
    }
};

pub const PthreadRwLock = struct {
    rwlock: std.c.pthread_rwlock_t = .{},

    pub fn tryLock(rwl: *PthreadRwLock) bool {
        return std.c.pthread_rwlock_trywrlock(&rwl.rwlock) == .SUCCESS;
    }

    pub fn lock(rwl: *PthreadRwLock) void {
        const rc = std.c.pthread_rwlock_wrlock(&rwl.rwlock);
        assert(rc == .SUCCESS);
    }

    pub fn unlock(rwl: *PthreadRwLock) void {
        const rc = std.c.pthread_rwlock_unlock(&rwl.rwlock);
        assert(rc == .SUCCESS);
    }

    pub fn tryLockShared(rwl: *PthreadRwLock) bool {
        return std.c.pthread_rwlock_tryrdlock(&rwl.rwlock) == .SUCCESS;
    }

    pub fn lockShared(rwl: *PthreadRwLock) void {
        const rc = std.c.pthread_rwlock_rdlock(&rwl.rwlock);
        assert(rc == .SUCCESS);
    }

    pub fn unlockShared(rwl: *PthreadRwLock) void {
        const rc = std.c.pthread_rwlock_unlock(&rwl.rwlock);
        assert(rc == .SUCCESS);
    }
};

pub const DefaultRwLock = struct {
    state: usize = 0,
    mutex: std.Thread.Mutex = .{},
    semaphore: std.Thread.Semaphore = .{},

    const IS_WRITING: usize = 1;
    const WRITER: usize = 1 << 1;
    const READER: usize = 1 << (1 + @bitSizeOf(Count));
    const WRITER_MASK: usize = std.math.maxInt(Count) << @ctz(WRITER);
    const READER_MASK: usize = std.math.maxInt(Count) << @ctz(READER);
    const Count = std.meta.Int(.unsigned, @divFloor(@bitSizeOf(usize) - 1, 2));

    pub fn tryLock(rwl: *DefaultRwLock) bool {
        if (rwl.mutex.tryLock()) {
            const state = @atomicLoad(usize, &rwl.state, .seq_cst);
            if (state & READER_MASK == 0) {
                _ = @atomicRmw(usize, &rwl.state, .Or, IS_WRITING, .seq_cst);
                return true;
            }

            rwl.mutex.unlock();
        }

        return false;
    }

    pub fn lock(rwl: *DefaultRwLock) void {
        _ = @atomicRmw(usize, &rwl.state, .Add, WRITER, .seq_cst);
        rwl.mutex.lock();

        const state = @atomicRmw(usize, &rwl.state, .Add, IS_WRITING -% WRITER, .seq_cst);
        if (state & READER_MASK != 0)
            rwl.semaphore.wait();
    }

    pub fn unlock(rwl: *DefaultRwLock) void {
        _ = @atomicRmw(usize, &rwl.state, .And, ~IS_WRITING, .seq_cst);
        rwl.mutex.unlock();
    }

    pub fn tryLockShared(rwl: *DefaultRwLock) bool {
        const state = @atomicLoad(usize, &rwl.state, .seq_cst);
        if (state & (IS_WRITING | WRITER_MASK) == 0) {
            _ = @cmpxchgStrong(
                usize,
                &rwl.state,
                state,
                state + READER,
                .seq_cst,
                .seq_cst,
            ) orelse return true;
        }

        if (rwl.mutex.tryLock()) {
            _ = @atomicRmw(usize, &rwl.state, .Add, READER, .seq_cst);
            rwl.mutex.unlock();
            return true;
        }

        return false;
    }

    pub fn lockShared(rwl: *DefaultRwLock) void {
        var state = @atomicLoad(usize, &rwl.state, .seq_cst);
        while (state & (IS_WRITING | WRITER_MASK) == 0) {
            state = @cmpxchgWeak(
                usize,
                &rwl.state,
                state,
                state + READER,
                .seq_cst,
                .seq_cst,
            ) orelse return;
        }

        rwl.mutex.lock();
        _ = @atomicRmw(usize, &rwl.state, .Add, READER, .seq_cst);
        rwl.mutex.unlock();
    }

    pub fn unlockShared(rwl: *DefaultRwLock) void {
        const state = @atomicRmw(usize, &rwl.state, .Sub, READER, .seq_cst);

        if ((state & READER_MASK == READER) and (state & IS_WRITING != 0))
            rwl.semaphore.post();
    }
};

test "DefaultRwLock - internal state" {
    var rwl = DefaultRwLock{};

    // The following failed prior to the fix for Issue #13163,
    // where the WRITER flag was subtracted by the lock method.

    rwl.lock();
    rwl.unlock();
    try testing.expectEqual(rwl, DefaultRwLock{});
}

test "smoke test" {
    var rwl = RwLock{};

    rwl.lock();
    try testing.expect(!rwl.tryLock());
    try testing.expect(!rwl.tryLockShared());
    rwl.unlock();

    try testing.expect(rwl.tryLock());
    try testing.expect(!rwl.tryLock());
    try testing.expect(!rwl.tryLockShared());
    rwl.unlock();

    rwl.lockShared();
    try testing.expect(!rwl.tryLock());
    try testing.expect(rwl.tryLockShared());
    rwl.unlockShared();
    rwl.unlockShared();

    try testing.expect(rwl.tryLockShared());
    try testing.expect(!rwl.tryLock());
    try testing.expect(rwl.tryLockShared());
    rwl.unlockShared();
    rwl.unlockShared();

    rwl.lock();
    rwl.unlock();
}

test "concurrent access" {
    if (builtin.single_threaded)
        return;

    const num_writers: usize = 2;
    const num_readers: usize = 4;
    const num_writes: usize = 10000;
    const num_reads: usize = num_writes * 2;

    const Runner = struct {
        const Self = @This();

        rwl: RwLock = .{},
        writes: usize = 0,
        reads: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

        term1: usize = 0,
        term2: usize = 0,
        term_sum: usize = 0,

        fn reader(self: *Self) !void {
            while (true) {
                self.rwl.lockShared();
                defer self.rwl.unlockShared();

                if (self.writes >= num_writes or self.reads.load(.unordered) >= num_reads)
                    break;

                try self.check();

                _ = self.reads.fetchAdd(1, .monotonic);
            }
        }

        fn writer(self: *Self, thread_idx: usize) !void {
            var prng = std.Random.DefaultPrng.init(thread_idx);
            var rnd = prng.random();

            while (true) {
                self.rwl.lock();
                defer self.rwl.unlock();

                if (self.writes >= num_writes)
                    break;

                try self.check();

                const term1 = rnd.int(usize);
                self.term1 = term1;
                try std.Thread.yield();

                const term2 = rnd.int(usize);
                self.term2 = term2;
                try std.Thread.yield();

                self.term_sum = term1 +% term2;
                self.writes += 1;
            }
        }

        fn check(self: *const Self) !void {
            const term_sum = self.term_sum;
            try std.Thread.yield();

            const term2 = self.term2;
            try std.Thread.yield();

            const term1 = self.term1;
            try testing.expectEqual(term_sum, term1 +% term2);
        }
    };

    var runner = Runner{};
    var threads: [num_writers + num_readers]std.Thread = undefined;

    for (threads[0..num_writers], 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Runner.writer, .{ &runner, i });
    for (threads[num_writers..]) |*t| t.* = try std.Thread.spawn(.{}, Runner.reader, .{&runner});

    for (threads) |t| t.join();

    try testing.expectEqual(num_writes, runner.writes);

    //std.debug.print("reads={}\n", .{ runner.reads.load(.unordered)});
}
//! A semaphore is an unsigned integer that blocks the kernel thread if
//! the number would become negative.
//! This API supports static initialization and does not require deinitialization.
//!
//! Example:
//! ```
//! var s = Semaphore{};
//!
//! fn consumer() void {
//!     s.wait();
//! }
//!
//! fn producer() void {
//!     s.post();
//! }
//!
//! const thread = try std.Thread.spawn(.{}, producer, .{});
//! consumer();
//! thread.join();
//! ```

mutex: Mutex = .{},
cond: Condition = .{},
/// It is OK to initialize this field to any value.
permits: usize = 0,

const Semaphore = @This();
const std = @import("../std.zig");
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;
const builtin = @import("builtin");
const testing = std.testing;

pub fn wait(sem: *Semaphore) void {
    sem.mutex.lock();
    defer sem.mutex.unlock();

    while (sem.permits == 0)
        sem.cond.wait(&sem.mutex);

    sem.permits -= 1;
    if (sem.permits > 0)
        sem.cond.signal();
}

pub fn timedWait(sem: *Semaphore, timeout_ns: u64) error{Timeout}!void {
    var timeout_timer = std.time.Timer.start() catch unreachable;

    sem.mutex.lock();
    defer sem.mutex.unlock();

    while (sem.permits == 0) {
        const elapsed = timeout_timer.read();
        if (elapsed > timeout_ns)
            return error.Timeout;

        const local_timeout_ns = timeout_ns - elapsed;
        try sem.cond.timedWait(&sem.mutex, local_timeout_ns);
    }

    sem.permits -= 1;
    if (sem.permits > 0)
        sem.cond.signal();
}

pub fn post(sem: *Semaphore) void {
    sem.mutex.lock();
    defer sem.mutex.unlock();

    sem.permits += 1;
    sem.cond.signal();
}

test Semaphore {
    if (builtin.single_threaded) {
        return error.SkipZigTest;
    }

    const TestContext = struct {
        sem: *Semaphore,
        n: *i32,
        fn worker(ctx: *@This()) void {
            ctx.sem.wait();
            ctx.n.* += 1;
            ctx.sem.post();
        }
    };
    const num_threads = 3;
    var sem = Semaphore{ .permits = 1 };
    var threads: [num_threads]std.Thread = undefined;
    var n: i32 = 0;
    var ctx = TestContext{ .sem = &sem, .n = &n };

    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, TestContext.worker, .{&ctx});
    for (threads) |t| t.join();
    sem.wait();
    try testing.expect(n == num_threads);
}

test timedWait {
    var sem = Semaphore{};
    try testing.expectEqual(0, sem.permits);

    try testing.expectError(error.Timeout, sem.timedWait(1));

    sem.post();
    try testing.expectEqual(1, sem.permits);

    try sem.timedWait(1);
    try testing.expectEqual(0, sem.permits);
}
const builtin = @import("builtin");
const std = @import("std");
const assert = std.debug.assert;
const WaitGroup = @This();

const is_waiting: usize = 1 << 0;
const one_pending: usize = 1 << 1;

state: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
event: std.Thread.ResetEvent = .{},

pub fn start(self: *WaitGroup) void {
    const state = self.state.fetchAdd(one_pending, .monotonic);
    assert((state / one_pending) < (std.math.maxInt(usize) / one_pending));
}

pub fn startMany(self: *WaitGroup, n: usize) void {
    const state = self.state.fetchAdd(one_pending * n, .monotonic);
    assert((state / one_pending) < (std.math.maxInt(usize) / one_pending));
}

pub fn finish(self: *WaitGroup) void {
    const state = self.state.fetchSub(one_pending, .acq_rel);
    assert((state / one_pending) > 0);

    if (state == (one_pending | is_waiting)) {
        self.event.set();
    }
}

pub fn wait(self: *WaitGroup) void {
    const state = self.state.fetchAdd(is_waiting, .acquire);
    assert(state & is_waiting == 0);

    if ((state / one_pending) > 0) {
        self.event.wait();
    }
}

pub fn reset(self: *WaitGroup) void {
    self.state.store(0, .monotonic);
    self.event.reset();
}

pub fn isDone(wg: *WaitGroup) bool {
    const state = wg.state.load(.acquire);
    assert(state & is_waiting == 0);

    return (state / one_pending) == 0;
}

// Spawns a new thread for the task. This is appropriate when the callee
// delegates all work.
pub fn spawnManager(
    wg: *WaitGroup,
    comptime func: anytype,
    args: anytype,
) void {
    if (builtin.single_threaded) {
        @call(.auto, func, args);
        return;
    }
    const Manager = struct {
        fn run(wg_inner: *WaitGroup, args_inner: @TypeOf(args)) void {
            defer wg_inner.finish();
            @call(.auto, func, args_inner);
        }
    };
    wg.start();
    const t = std.Thread.spawn(.{}, Manager.run, .{ wg, args }) catch return Manager.run(wg, args);
    t.detach();
}
const std = @import("std.zig");
const builtin = @import("builtin");
const assert = std.debug.assert;
const testing = std.testing;
const math = std.math;
const windows = std.os.windows;
const posix = std.posix;

pub const epoch = @import("time/epoch.zig");

/// Deprecated: moved to std.Thread.sleep
pub const sleep = std.Thread.sleep;

/// Get a calendar timestamp, in seconds, relative to UTC 1970-01-01.
/// Precision of timing depends on the hardware and operating system.
/// The return value is signed because it is possible to have a date that is
/// before the epoch.
/// See `posix.clock_gettime` for a POSIX timestamp.
pub fn timestamp() i64 {
    return @divFloor(milliTimestamp(), ms_per_s);
}

/// Get a calendar timestamp, in milliseconds, relative to UTC 1970-01-01.
/// Precision of timing depends on the hardware and operating system.
/// The return value is signed because it is possible to have a date that is
/// before the epoch.
/// See `posix.clock_gettime` for a POSIX timestamp.
pub fn milliTimestamp() i64 {
    return @as(i64, @intCast(@divFloor(nanoTimestamp(), ns_per_ms)));
}

/// Get a calendar timestamp, in microseconds, relative to UTC 1970-01-01.
/// Precision of timing depends on the hardware and operating system.
/// The return value is signed because it is possible to have a date that is
/// before the epoch.
/// See `posix.clock_gettime` for a POSIX timestamp.
pub fn microTimestamp() i64 {
    return @as(i64, @intCast(@divFloor(nanoTimestamp(), ns_per_us)));
}

/// Get a calendar timestamp, in nanoseconds, relative to UTC 1970-01-01.
/// Precision of timing depends on the hardware and operating system.
/// On Windows this has a maximum granularity of 100 nanoseconds.
/// The return value is signed because it is possible to have a date that is
/// before the epoch.
/// See `posix.clock_gettime` for a POSIX timestamp.
pub fn nanoTimestamp() i128 {
    switch (builtin.os.tag) {
        .windows => {
            // RtlGetSystemTimePrecise() has a granularity of 100 nanoseconds and uses the NTFS/Windows epoch,
            // which is 1601-01-01.
            const epoch_adj = epoch.windows * (ns_per_s / 100);
            return @as(i128, windows.ntdll.RtlGetSystemTimePrecise() + epoch_adj) * 100;
        },
        .wasi => {
            var ns: std.os.wasi.timestamp_t = undefined;
            const err = std.os.wasi.clock_time_get(.REALTIME, 1, &ns);
            assert(err == .SUCCESS);
            return ns;
        },
        .uefi => {
            var value: std.os.uefi.Time = undefined;
            const status = std.os.uefi.system_table.runtime_services.getTime(&value, null);
            assert(status == .success);
            return value.toEpoch();
        },
        else => {
            const ts = posix.clock_gettime(.REALTIME) catch |err| switch (err) {
                error.UnsupportedClock, error.Unexpected => return 0, // "Precision of timing depends on hardware and OS".
            };
            return (@as(i128, ts.sec) * ns_per_s) + ts.nsec;
        },
    }
}

test milliTimestamp {
    const time_0 = milliTimestamp();
    std.Thread.sleep(ns_per_ms);
    const time_1 = milliTimestamp();
    const interval = time_1 - time_0;
    try testing.expect(interval > 0);
}

// Divisions of a nanosecond.
pub const ns_per_us = 1000;
pub const ns_per_ms = 1000 * ns_per_us;
pub const ns_per_s = 1000 * ns_per_ms;
pub const ns_per_min = 60 * ns_per_s;
pub const ns_per_hour = 60 * ns_per_min;
pub const ns_per_day = 24 * ns_per_hour;
pub const ns_per_week = 7 * ns_per_day;

// Divisions of a microsecond.
pub const us_per_ms = 1000;
pub const us_per_s = 1000 * us_per_ms;
pub const us_per_min = 60 * us_per_s;
pub const us_per_hour = 60 * us_per_min;
pub const us_per_day = 24 * us_per_hour;
pub const us_per_week = 7 * us_per_day;

// Divisions of a millisecond.
pub const ms_per_s = 1000;
pub const ms_per_min = 60 * ms_per_s;
pub const ms_per_hour = 60 * ms_per_min;
pub const ms_per_day = 24 * ms_per_hour;
pub const ms_per_week = 7 * ms_per_day;

// Divisions of a second.
pub const s_per_min = 60;
pub const s_per_hour = s_per_min * 60;
pub const s_per_day = s_per_hour * 24;
pub const s_per_week = s_per_day * 7;

/// An Instant represents a timestamp with respect to the currently
/// executing program that ticks during suspend and can be used to
/// record elapsed time unlike `nanoTimestamp`.
///
/// It tries to sample the system's fastest and most precise timer available.
/// It also tries to be monotonic, but this is not a guarantee due to OS/hardware bugs.
/// If you need monotonic readings for elapsed time, consider `Timer` instead.
pub const Instant = struct {
    timestamp: if (is_posix) posix.timespec else u64,

    // true if we should use clock_gettime()
    const is_posix = switch (builtin.os.tag) {
        .windows, .uefi, .wasi => false,
        else => true,
    };

    /// Queries the system for the current moment of time as an Instant.
    /// This is not guaranteed to be monotonic or steadily increasing, but for
    /// most implementations it is.
    /// Returns `error.Unsupported` when a suitable clock is not detected.
    pub fn now() error{Unsupported}!Instant {
        const clock_id = switch (builtin.os.tag) {
            .windows => {
                // QPC on windows doesn't fail on >= XP/2000 and includes time suspended.
                return .{ .timestamp = windows.QueryPerformanceCounter() };
            },
            .wasi => {
                var ns: std.os.wasi.timestamp_t = undefined;
                const rc = std.os.wasi.clock_time_get(.MONOTONIC, 1, &ns);
                if (rc != .SUCCESS) return error.Unsupported;
                return .{ .timestamp = ns };
            },
            .uefi => {
                var value: std.os.uefi.Time = undefined;
                const status = std.os.uefi.system_table.runtime_services.getTime(&value, null);
                if (status != .success) return error.Unsupported;
                return .{ .timestamp = value.toEpoch() };
            },
            // On darwin, use UPTIME_RAW instead of MONOTONIC as it ticks while
            // suspended.
            .macos, .ios, .tvos, .watchos, .visionos => posix.CLOCK.UPTIME_RAW,
            // On freebsd derivatives, use MONOTONIC_FAST as currently there's
            // no precision tradeoff.
            .freebsd, .dragonfly => posix.CLOCK.MONOTONIC_FAST,
            // On linux, use BOOTTIME instead of MONOTONIC as it ticks while
            // suspended.
            .linux => posix.CLOCK.BOOTTIME,
            // On other posix systems, MONOTONIC is generally the fastest and
            // ticks while suspended.
            else => posix.CLOCK.MONOTONIC,
        };

        const ts = posix.clock_gettime(clock_id) catch return error.Unsupported;
        return .{ .timestamp = ts };
    }

    /// Quickly compares two instances between each other.
    pub fn order(self: Instant, other: Instant) std.math.Order {
        // windows and wasi timestamps are in u64 which is easily comparible
        if (!is_posix) {
            return std.math.order(self.timestamp, other.timestamp);
        }

        var ord = std.math.order(self.timestamp.sec, other.timestamp.sec);
        if (ord == .eq) {
            ord = std.math.order(self.timestamp.nsec, other.timestamp.nsec);
        }
        return ord;
    }

    /// Returns elapsed time in nanoseconds since the `earlier` Instant.
    /// This assumes that the `earlier` Instant represents a moment in time before or equal to `self`.
    /// This also assumes that the time that has passed between both Instants fits inside a u64 (~585 yrs).
    pub fn since(self: Instant, earlier: Instant) u64 {
        switch (builtin.os.tag) {
            .windows => {
                // We don't need to cache QPF as it's internally just a memory read to KUSER_SHARED_DATA
                // (a read-only page of info updated and mapped by the kernel to all processes):
                // https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
                // https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntexapi_x/kuser_shared_data/index.htm
                const qpc = self.timestamp - earlier.timestamp;
                const qpf = windows.QueryPerformanceFrequency();

                // 10Mhz (1 qpc tick every 100ns) is a common enough QPF value that we can optimize on it.
                // https://github.com/microsoft/STL/blob/785143a0c73f030238ef618890fd4d6ae2b3a3a0/stl/inc/chrono#L694-L701
                const common_qpf = 10_000_000;
                if (qpf == common_qpf) {
                    return qpc * (ns_per_s / common_qpf);
                }

                // Convert to ns using fixed point.
                const scale = @as(u64, std.time.ns_per_s << 32) / @as(u32, @intCast(qpf));
                const result = (@as(u96, qpc) * scale) >> 32;
                return @as(u64, @truncate(result));
            },
            .uefi, .wasi => {
                // UEFI and WASI timestamps are directly in nanoseconds
                return self.timestamp - earlier.timestamp;
            },
            else => {
                // Convert timespec diff to ns
                const seconds = @as(u64, @intCast(self.timestamp.sec - earlier.timestamp.sec));
                const elapsed = (seconds * ns_per_s) + @as(u32, @intCast(self.timestamp.nsec));
                return elapsed - @as(u32, @intCast(earlier.timestamp.nsec));
            },
        }
    }
};

/// A monotonic, high performance timer.
///
/// Timer.start() is used to initialize the timer
/// and gives the caller an opportunity to check for the existence of a supported clock.
/// Once a supported clock is discovered,
/// it is assumed that it will be available for the duration of the Timer's use.
///
/// Monotonicity is ensured by saturating on the most previous sample.
/// This means that while timings reported are monotonic,
/// they're not guaranteed to tick at a steady rate as this is up to the underlying system.
pub const Timer = struct {
    started: Instant,
    previous: Instant,

    pub const Error = error{TimerUnsupported};

    /// Initialize the timer by querying for a supported clock.
    /// Returns `error.TimerUnsupported` when such a clock is unavailable.
    /// This should only fail in hostile environments such as linux seccomp misuse.
    pub fn start() Error!Timer {
        const current = Instant.now() catch return error.TimerUnsupported;
        return Timer{ .started = current, .previous = current };
    }

    /// Reads the timer value since start or the last reset in nanoseconds.
    pub fn read(self: *Timer) u64 {
        const current = self.sample();
        return current.since(self.started);
    }

    /// Resets the timer value to 0/now.
    pub fn reset(self: *Timer) void {
        const current = self.sample();
        self.started = current;
    }

    /// Returns the current value of the timer in nanoseconds, then resets it.
    pub fn lap(self: *Timer) u64 {
        const current = self.sample();
        defer self.started = current;
        return current.since(self.started);
    }

    /// Returns an Instant sampled at the callsite that is
    /// guaranteed to be monotonic with respect to the timer's starting point.
    fn sample(self: *Timer) Instant {
        const current = Instant.now() catch unreachable;
        if (current.order(self.previous) == .gt) {
            self.previous = current;
        }
        return self.previous;
    }
};

test Timer {
    var timer = try Timer.start();

    std.Thread.sleep(10 * ns_per_ms);
    const time_0 = timer.read();
    try testing.expect(time_0 > 0);

    const time_1 = timer.lap();
    try testing.expect(time_1 >= time_0);
}

test {
    _ = epoch;
}
//! Epoch reference times in terms of their difference from
//! UTC 1970-01-01 in seconds.
const std = @import("../std.zig");
const testing = std.testing;
const math = std.math;

/// Jan 01, 1970 AD
pub const posix = 0;
/// Jan 01, 1980 AD
pub const dos = 315532800;
/// Jan 01, 2001 AD
pub const ios = 978307200;
/// Nov 17, 1858 AD
pub const openvms = -3506716800;
/// Jan 01, 1900 AD
pub const zos = -2208988800;
/// Jan 01, 1601 AD
pub const windows = -11644473600;
/// Jan 01, 1978 AD
pub const amiga = 252460800;
/// Dec 31, 1967 AD
pub const pickos = -63244800;
/// Jan 06, 1980 AD
pub const gps = 315964800;
/// Jan 01, 0001 AD
pub const clr = -62135769600;

pub const unix = posix;
pub const android = posix;
pub const os2 = dos;
pub const bios = dos;
pub const vfat = dos;
pub const ntfs = windows;
pub const ntp = zos;
pub const jbase = pickos;
pub const aros = amiga;
pub const morphos = amiga;
pub const brew = gps;
pub const atsc = gps;
pub const go = clr;

/// The type that holds the current year, i.e. 2016
pub const Year = u16;

pub const epoch_year = 1970;
pub const secs_per_day: u17 = 24 * 60 * 60;

pub fn isLeapYear(year: Year) bool {
    if (@mod(year, 4) != 0)
        return false;
    if (@mod(year, 100) != 0)
        return true;
    return (0 == @mod(year, 400));
}

test isLeapYear {
    try testing.expectEqual(false, isLeapYear(2095));
    try testing.expectEqual(true, isLeapYear(2096));
    try testing.expectEqual(false, isLeapYear(2100));
    try testing.expectEqual(true, isLeapYear(2400));
}

pub fn getDaysInYear(year: Year) u9 {
    return if (isLeapYear(year)) 366 else 365;
}

pub const Month = enum(u4) {
    jan = 1,
    feb,
    mar,
    apr,
    may,
    jun,
    jul,
    aug,
    sep,
    oct,
    nov,
    dec,

    /// return the numeric calendar value for the given month
    /// i.e. jan=1, feb=2, etc
    pub fn numeric(self: Month) u4 {
        return @intFromEnum(self);
    }
};

/// Get the number of days in the given month and year
pub fn getDaysInMonth(year: Year, month: Month) u5 {
    return switch (month) {
        .jan => 31,
        .feb => @as(u5, switch (isLeapYear(year)) {
            true => 29,
            false => 28,
        }),
        .mar => 31,
        .apr => 30,
        .may => 31,
        .jun => 30,
        .jul => 31,
        .aug => 31,
        .sep => 30,
        .oct => 31,
        .nov => 30,
        .dec => 31,
    };
}

pub const YearAndDay = struct {
    year: Year,
    /// The number of days into the year (0 to 365)
    day: u9,

    pub fn calculateMonthDay(self: YearAndDay) MonthAndDay {
        var month: Month = .jan;
        var days_left = self.day;
        while (true) {
            const days_in_month = getDaysInMonth(self.year, month);
            if (days_left < days_in_month)
                break;
            days_left -= days_in_month;
            month = @as(Month, @enumFromInt(@intFromEnum(month) + 1));
        }
        return .{ .month = month, .day_index = @as(u5, @intCast(days_left)) };
    }
};

pub const MonthAndDay = struct {
    month: Month,
    day_index: u5, // days into the month (0 to 30)
};

/// days since epoch Jan 1, 1970
pub const EpochDay = struct {
    day: u47, // u47 = u64 - u17 (because day = sec(u64) / secs_per_day(u17)
    pub fn calculateYearDay(self: EpochDay) YearAndDay {
        var year_day = self.day;
        var year: Year = epoch_year;
        while (true) {
            const year_size = getDaysInYear(year);
            if (year_day < year_size)
                break;
            year_day -= year_size;
            year += 1;
        }
        return .{ .year = year, .day = @as(u9, @intCast(year_day)) };
    }
};

/// seconds since start of day
pub const DaySeconds = struct {
    secs: u17, // max is 24*60*60 = 86400

    /// the number of hours past the start of the day (0 to 23)
    pub fn getHoursIntoDay(self: DaySeconds) u5 {
        return @as(u5, @intCast(@divTrunc(self.secs, 3600)));
    }
    /// the number of minutes past the hour (0 to 59)
    pub fn getMinutesIntoHour(self: DaySeconds) u6 {
        return @as(u6, @intCast(@divTrunc(@mod(self.secs, 3600), 60)));
    }
    /// the number of seconds past the start of the minute (0 to 59)
    pub fn getSecondsIntoMinute(self: DaySeconds) u6 {
        return math.comptimeMod(self.secs, 60);
    }
};

/// seconds since epoch Jan 1, 1970 at 12:00 AM
pub const EpochSeconds = struct {
    secs: u64,

    /// Returns the number of days since the epoch as an EpochDay.
    /// Use EpochDay to get information about the day of this time.
    pub fn getEpochDay(self: EpochSeconds) EpochDay {
        return EpochDay{ .day = @as(u47, @intCast(@divTrunc(self.secs, secs_per_day))) };
    }

    /// Returns the number of seconds into the day as DaySeconds.
    /// Use DaySeconds to get information about the time.
    pub fn getDaySeconds(self: EpochSeconds) DaySeconds {
        return DaySeconds{ .secs = math.comptimeMod(self.secs, secs_per_day) };
    }
};

fn testEpoch(secs: u64, expected_year_day: YearAndDay, expected_month_day: MonthAndDay, expected_day_seconds: struct {
    /// 0 to 23
    hours_into_day: u5,
    /// 0 to 59
    minutes_into_hour: u6,
    /// 0 to 59
    seconds_into_minute: u6,
}) !void {
    const epoch_seconds = EpochSeconds{ .secs = secs };
    const epoch_day = epoch_seconds.getEpochDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    try testing.expectEqual(expected_year_day, year_day);
    try testing.expectEqual(expected_month_day, year_day.calculateMonthDay());
    try testing.expectEqual(expected_day_seconds.hours_into_day, day_seconds.getHoursIntoDay());
    try testing.expectEqual(expected_day_seconds.minutes_into_hour, day_seconds.getMinutesIntoHour());
    try testing.expectEqual(expected_day_seconds.seconds_into_minute, day_seconds.getSecondsIntoMinute());
}

test "epoch decoding" {
    try testEpoch(0, .{ .year = 1970, .day = 0 }, .{
        .month = .jan,
        .day_index = 0,
    }, .{ .hours_into_day = 0, .minutes_into_hour = 0, .seconds_into_minute = 0 });

    try testEpoch(31535999, .{ .year = 1970, .day = 364 }, .{
        .month = .dec,
        .day_index = 30,
    }, .{ .hours_into_day = 23, .minutes_into_hour = 59, .seconds_into_minute = 59 });

    try testEpoch(1622924906, .{ .year = 2021, .day = 31 + 28 + 31 + 30 + 31 + 4 }, .{
        .month = .jun,
        .day_index = 4,
    }, .{ .hours_into_day = 20, .minutes_into_hour = 28, .seconds_into_minute = 26 });

    try testEpoch(1625159473, .{ .year = 2021, .day = 31 + 28 + 31 + 30 + 31 + 30 }, .{
        .month = .jul,
        .day_index = 0,
    }, .{ .hours_into_day = 17, .minutes_into_hour = 11, .seconds_into_minute = 13 });
}
const std = @import("std.zig");
const assert = std.debug.assert;
const testing = std.testing;
const Order = std.math.Order;

pub fn Treap(comptime Key: type, comptime compareFn: anytype) type {
    return struct {
        const Self = @This();

        // Allow for compareFn to be fn (anytype, anytype) anytype
        // which allows the convenient use of std.math.order.
        fn compare(a: Key, b: Key) Order {
            return compareFn(a, b);
        }

        root: ?*Node = null,
        prng: Prng = .{},

        /// A customized pseudo random number generator for the treap.
        /// This just helps reducing the memory size of the treap itself
        /// as std.Random.DefaultPrng requires larger state (while producing better entropy for randomness to be fair).
        const Prng = struct {
            xorshift: usize = 0,

            fn random(self: *Prng, seed: usize) usize {
                // Lazily seed the prng state
                if (self.xorshift == 0) {
                    self.xorshift = seed;
                }

                // Since we're using usize, decide the shifts by the integer's bit width.
                const shifts = switch (@bitSizeOf(usize)) {
                    64 => .{ 13, 7, 17 },
                    32 => .{ 13, 17, 5 },
                    16 => .{ 7, 9, 8 },
                    else => @compileError("platform not supported"),
                };

                self.xorshift ^= self.xorshift >> shifts[0];
                self.xorshift ^= self.xorshift << shifts[1];
                self.xorshift ^= self.xorshift >> shifts[2];

                assert(self.xorshift != 0);
                return self.xorshift;
            }
        };

        /// A Node represents an item or point in the treap with a uniquely associated key.
        pub const Node = struct {
            key: Key,
            priority: usize,
            parent: ?*Node,
            children: [2]?*Node,

            pub fn next(node: *Node) ?*Node {
                return nextOnDirection(node, 1);
            }
            pub fn prev(node: *Node) ?*Node {
                return nextOnDirection(node, 0);
            }
        };

        fn extremeInSubtreeOnDirection(node: *Node, direction: u1) *Node {
            var cur = node;
            while (cur.children[direction]) |next| cur = next;
            return cur;
        }

        fn nextOnDirection(node: *Node, direction: u1) ?*Node {
            if (node.children[direction]) |child| {
                return extremeInSubtreeOnDirection(child, direction ^ 1);
            }
            var cur = node;
            // Traversing upward until we find `parent` to `cur` is NOT on
            // `direction`, or equivalently, `cur` to `parent` IS on
            // `direction` thus `parent` is the next.
            while (true) {
                if (cur.parent) |parent| {
                    // If `parent -> node` is NOT on `direction`, then
                    // `node -> parent` IS on `direction`
                    if (parent.children[direction] != cur) return parent;
                    cur = parent;
                } else {
                    return null;
                }
            }
        }

        /// Returns the smallest Node by key in the treap if there is one.
        /// Use `getEntryForExisting()` to replace/remove this Node from the treap.
        pub fn getMin(self: Self) ?*Node {
            if (self.root) |root| return extremeInSubtreeOnDirection(root, 0);
            return null;
        }

        /// Returns the largest Node by key in the treap if there is one.
        /// Use `getEntryForExisting()` to replace/remove this Node from the treap.
        pub fn getMax(self: Self) ?*Node {
            if (self.root) |root| return extremeInSubtreeOnDirection(root, 1);
            return null;
        }

        /// Lookup the Entry for the given key in the treap.
        /// The Entry act's as a slot in the treap to insert/replace/remove the node associated with the key.
        pub fn getEntryFor(self: *Self, key: Key) Entry {
            var parent: ?*Node = undefined;
            const node = self.find(key, &parent);

            return Entry{
                .key = key,
                .treap = self,
                .node = node,
                .context = .{ .inserted_under = parent },
            };
        }

        /// Get an entry for a Node that currently exists in the treap.
        /// It is undefined behavior if the Node is not currently inserted in the treap.
        /// The Entry act's as a slot in the treap to insert/replace/remove the node associated with the key.
        pub fn getEntryForExisting(self: *Self, node: *Node) Entry {
            assert(node.priority != 0);

            return Entry{
                .key = node.key,
                .treap = self,
                .node = node,
                .context = .{ .inserted_under = node.parent },
            };
        }

        /// An Entry represents a slot in the treap associated with a given key.
        pub const Entry = struct {
            /// The associated key for this entry.
            key: Key,
            /// A reference to the treap this entry is apart of.
            treap: *Self,
            /// The current node at this entry.
            node: ?*Node,
            /// The current state of the entry.
            context: union(enum) {
                /// A find() was called for this entry and the position in the treap is known.
                inserted_under: ?*Node,
                /// The entry's node was removed from the treap and a lookup must occur again for modification.
                removed,
            },

            /// Update's the Node at this Entry in the treap with the new node (null for deleting). `new_node`
            /// can have `undefind` content because the value will be initialized internally.
            pub fn set(self: *Entry, new_node: ?*Node) void {
                // Update the entry's node reference after updating the treap below.
                defer self.node = new_node;

                if (self.node) |old| {
                    if (new_node) |new| {
                        self.treap.replace(old, new);
                        return;
                    }

                    self.treap.remove(old);
                    self.context = .removed;
                    return;
                }

                if (new_node) |new| {
                    // A previous treap.remove() could have rebalanced the nodes
                    // so when inserting after a removal, we have to re-lookup the parent again.
                    // This lookup shouldn't find a node because we're yet to insert it..
                    var parent: ?*Node = undefined;
                    switch (self.context) {
                        .inserted_under => |p| parent = p,
                        .removed => assert(self.treap.find(self.key, &parent) == null),
                    }

                    self.treap.insert(self.key, parent, new);
                    self.context = .{ .inserted_under = parent };
                }
            }
        };

        fn find(self: Self, key: Key, parent_ref: *?*Node) ?*Node {
            var node = self.root;
            parent_ref.* = null;

            // basic binary search while tracking the parent.
            while (node) |current| {
                const order = compare(key, current.key);
                if (order == .eq) break;

                parent_ref.* = current;
                node = current.children[@intFromBool(order == .gt)];
            }

            return node;
        }

        fn insert(self: *Self, key: Key, parent: ?*Node, node: *Node) void {
            // generate a random priority & prepare the node to be inserted into the tree
            node.key = key;
            node.priority = self.prng.random(@intFromPtr(node));
            node.parent = parent;
            node.children = [_]?*Node{ null, null };

            // point the parent at the new node
            const link = if (parent) |p| &p.children[@intFromBool(compare(key, p.key) == .gt)] else &self.root;
            assert(link.* == null);
            link.* = node;

            // rotate the node up into the tree to balance it according to its priority
            while (node.parent) |p| {
                if (p.priority <= node.priority) break;

                const is_right = p.children[1] == node;
                assert(p.children[@intFromBool(is_right)] == node);

                const rotate_right = !is_right;
                self.rotate(p, rotate_right);
            }
        }

        fn replace(self: *Self, old: *Node, new: *Node) void {
            // copy over the values from the old node
            new.key = old.key;
            new.priority = old.priority;
            new.parent = old.parent;
            new.children = old.children;

            // point the parent at the new node
            const link = if (old.parent) |p| &p.children[@intFromBool(p.children[1] == old)] else &self.root;
            assert(link.* == old);
            link.* = new;

            // point the children's parent at the new node
            for (old.childr```
