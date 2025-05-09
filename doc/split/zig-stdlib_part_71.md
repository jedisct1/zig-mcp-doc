```
 var b = try Managed.initSet(testing.allocator, 0x99990000111122223333);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(0xe38f38e39161aaabd03f0f1b, try q.toInt(u128));
    try testing.expectEqual(0x28de0acacd806823638, try r.toInt(u128));
}

test "div multi-multi no rem" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.initSet(testing.allocator, 0x8888999911110000ffffeeeedb4fec200ee3a4286361);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x99990000111122223333);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(0xe38f38e39161aaabd03f0f1b, try q.toInt(u128));
    try testing.expectEqual(0, try r.toInt(u128));
}

test "div multi-multi (2 branch)" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.initSet(testing.allocator, 0x866666665555555588888887777777761111111111111111);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x86666666555555554444444433333333);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(0x10000000000000000, try q.toInt(u128));
    try testing.expectEqual(0x44444443444444431111111111111111, try r.toInt(u128));
}

test "div multi-multi (3.1/3.3 branch)" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.initSet(testing.allocator, 0x11111111111111111111111111111111111111111111111111111111111111);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x1111111111111111111111111111111111111111171);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(0xfffffffffffffffffff, try q.toInt(u128));
    try testing.expectEqual(0x1111111111111111111110b12222222222222222282, try r.toInt(u256));
}

test "div multi-single zero-limb trailing" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.initSet(testing.allocator, 0x60000000000000000000000000000000000000000000000000000000000000000);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x10000000000000000);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    var expected = try Managed.initSet(testing.allocator, 0x6000000000000000000000000000000000000000000000000);
    defer expected.deinit();
    try testing.expect(q.eql(expected));
    try testing.expect(r.eqlZero());
}

test "div multi-multi zero-limb trailing (with rem)" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.initSet(testing.allocator, 0x86666666555555558888888777777776111111111111111100000000000000000000000000000000);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x8666666655555555444444443333333300000000000000000000000000000000);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(0x10000000000000000, try q.toInt(u128));

    const rs = try r.toString(testing.allocator, 16, .lower);
    defer testing.allocator.free(rs);
    try testing.expectEqualStrings("4444444344444443111111111111111100000000000000000000000000000000", rs);
}

test "div multi-multi zero-limb trailing (with rem) and dividend zero-limb count > divisor zero-limb count" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.initSet(testing.allocator, 0x8666666655555555888888877777777611111111111111110000000000000000);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x8666666655555555444444443333333300000000000000000000000000000000);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    try testing.expectEqual(0x1, try q.toInt(u128));

    const rs = try r.toString(testing.allocator, 16, .lower);
    defer testing.allocator.free(rs);
    try testing.expectEqualStrings("444444434444444311111111111111110000000000000000", rs);
}

test "div multi-multi zero-limb trailing (with rem) and dividend zero-limb count < divisor zero-limb count" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.initSet(testing.allocator, 0x86666666555555558888888777777776111111111111111100000000000000000000000000000000);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x866666665555555544444444333333330000000000000000);
    defer b.deinit();

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    const qs = try q.toString(testing.allocator, 16, .lower);
    defer testing.allocator.free(qs);
    try testing.expectEqualStrings("10000000000000000820820803105186f", qs);

    const rs = try r.toString(testing.allocator, 16, .lower);
    defer testing.allocator.free(rs);
    try testing.expectEqualStrings("4e11f2baa5896a321d463b543d0104e30000000000000000", rs);
}

test "div multi-multi fuzz case #1" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    try a.setString(16, "ffffffffffffffffffffffffffffc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    try b.setString(16, "3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0000000000000000000000000000000000001ffffffffffffffffffffffffffffffffffffffffffffffffffc000000000000000000000000000000007fffffffffff");

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    const qs = try q.toString(testing.allocator, 16, .lower);
    defer testing.allocator.free(qs);
    try testing.expectEqualStrings("3ffffffffffffffffffffffffffff0000000000000000000000000000000000001ffffffffffffffffffffffffffff7fffffffe000000000000000000000000000180000000000000000000003fffffbfffffffdfffffffffffffeffff800000100101000000100000000020003fffffdfbfffffe3ffffffffffffeffff7fffc00800a100000017ffe000002000400007efbfff7fe9f00000037ffff3fff7fffa004006100000009ffe00000190038200bf7d2ff7fefe80400060000f7d7f8fbf9401fe38e0403ffc0bdffffa51102c300d7be5ef9df4e5060007b0127ad3fa69f97d0f820b6605ff617ddf7f32ad7a05c0d03f2e7bc78a6000e087a8bbcdc59e07a5a079128a7861f553ddebed7e8e56701756f9ead39b48cd1b0831889ea6ec1fddf643d0565b075ff07e6caea4e2854ec9227fd635ed60a2f5eef2893052ffd54718fa08604acbf6a15e78a467c4a3c53c0278af06c4416573f925491b195e8fd79302cb1aaf7caf4ecfc9aec1254cc969786363ac729f914c6ddcc26738d6b0facd54eba026580aba2eb6482a088b0d224a8852420b91ec1", qs);

    const rs = try r.toString(testing.allocator, 16, .lower);
    defer testing.allocator.free(rs);
    try testing.expectEqualStrings("310d1d4c414426b4836c2635bad1df3a424e50cbdd167ffccb4dfff57d36b4aae0d6ca0910698220171a0f3373c1060a046c2812f0027e321f72979daa5e7973214170d49e885de0c0ecc167837d44502430674a82522e5df6a0759548052420b91ec1", rs);
}

test "div multi-multi fuzz case #2" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();
    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    try a.setString(16, "3ffffffffe00000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffe000000000000000000000000000000000000000000000000000000000000001fffffffffffffffff800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffc000000000000000000000000000000000000000000000000000000000000000");
    try b.setString(16, "ffc0000000000000000000000000000000000000000000000000");

    var q = try Managed.init(testing.allocator);
    defer q.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    try Managed.divTrunc(&q, &r, &a, &b);

    const qs = try q.toString(testing.allocator, 16, .lower);
    defer testing.allocator.free(qs);
    try testing.expectEqualStrings("40100400fe3f8fe3f8fe3f8fe3f8fe3f8fe4f93e4f93e4f93e4f93e4f93e4f93e4f93e4f93e4f93e4f93e4f93e4f91e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4992649926499264991e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4791e4792e4b92e4b92e4b92e4b92a4a92a4a92a4", qs);

    const rs = try r.toString(testing.allocator, 16, .lower);
    defer testing.allocator.free(rs);
    try testing.expectEqualStrings("a900000000000000000000000000000000000000000000000000", rs);
}

test "truncate single unsigned" {
    var a = try Managed.initSet(testing.allocator, maxInt(u47));
    defer a.deinit();

    try a.truncate(&a, .unsigned, 17);

    try testing.expectEqual(maxInt(u17), try a.toInt(u17));
}

test "truncate single signed" {
    var a = try Managed.initSet(testing.allocator, 0x1_0000);
    defer a.deinit();

    try a.truncate(&a, .signed, 17);

    try testing.expectEqual(minInt(i17), try a.toInt(i17));
}

test "truncate multi to single unsigned" {
    var a = try Managed.initSet(testing.allocator, (maxInt(Limb) + 1) | 0x1234_5678_9ABC_DEF0);
    defer a.deinit();

    try a.truncate(&a, .unsigned, 27);

    try testing.expectEqual(0x2BC_DEF0, try a.toInt(u27));
}

test "truncate multi to single signed" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb) << 10);
    defer a.deinit();

    try a.truncate(&a, .signed, @bitSizeOf(i11));

    try testing.expectEqual(minInt(i11), try a.toInt(i11));
}

test "truncate multi to multi unsigned" {
    const bits = @typeInfo(SignedDoubleLimb).int.bits;
    const Int = std.meta.Int(.unsigned, bits - 1);

    var a = try Managed.initSet(testing.allocator, maxInt(SignedDoubleLimb));
    defer a.deinit();

    try a.truncate(&a, .unsigned, bits - 1);

    try testing.expectEqual(maxInt(Int), try a.toInt(Int));
}

test "truncate multi to multi signed" {
    var a = try Managed.initSet(testing.allocator, 3 << @bitSizeOf(Limb));
    defer a.deinit();

    try a.truncate(&a, .signed, @bitSizeOf(Limb) + 1);

    try testing.expectEqual(-1 << @bitSizeOf(Limb), try a.toInt(std.meta.Int(.signed, @bitSizeOf(Limb) + 1)));
}

test "truncate negative multi to single" {
    var a = try Managed.initSet(testing.allocator, -@as(SignedDoubleLimb, maxInt(Limb) + 1));
    defer a.deinit();

    try a.truncate(&a, .signed, @bitSizeOf(i17));

    try testing.expectEqual(0, try a.toInt(i17));
}

test "truncate multi unsigned many" {
    var a = try Managed.initSet(testing.allocator, 1);
    defer a.deinit();
    try a.shiftLeft(&a, 1023);

    var b = try Managed.init(testing.allocator);
    defer b.deinit();
    try b.truncate(&a, .signed, @bitSizeOf(i1));

    try testing.expectEqual(0, try b.toInt(i1));
}

test "truncate to mutable with fewer limbs" {
    var res_limbs: [1]Limb = undefined;
    var res: Mutable = .{
        .limbs = &res_limbs,
        .len = undefined,
        .positive = undefined,
    };
    res.truncate(.{ .positive = true, .limbs = &.{ 0, 1 } }, .unsigned, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = true, .limbs = &.{ 0, 1 } }, .signed, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = false, .limbs = &.{ 0, 1 } }, .unsigned, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = false, .limbs = &.{ 0, 1 } }, .signed, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = true, .limbs = &.{ maxInt(Limb), 1 } }, .unsigned, @bitSizeOf(Limb));
    try testing.expect(res.toConst().orderAgainstScalar(maxInt(Limb)).compare(.eq));
    res.truncate(.{ .positive = true, .limbs = &.{ maxInt(Limb), 1 } }, .signed, @bitSizeOf(Limb));
    try testing.expect(res.toConst().orderAgainstScalar(-1).compare(.eq));
    res.truncate(.{ .positive = false, .limbs = &.{ maxInt(Limb), 1 } }, .unsigned, @bitSizeOf(Limb));
    try testing.expect(res.toConst().orderAgainstScalar(1).compare(.eq));
    res.truncate(.{ .positive = false, .limbs = &.{ maxInt(Limb), 1 } }, .signed, @bitSizeOf(Limb));
    try testing.expect(res.toConst().orderAgainstScalar(1).compare(.eq));
}

test "truncate value that normalizes after being masked" {
    var res_limbs: [2]Limb = undefined;
    var res: Mutable = .{
        .limbs = &res_limbs,
        .len = undefined,
        .positive = undefined,
    };
    res.truncate(.{ .positive = true, .limbs = &.{ 0, 2 } }, .signed, 1 + @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = true, .limbs = &.{ 1, 2 } }, .signed, 1 + @bitSizeOf(Limb));
    try testing.expect(res.toConst().orderAgainstScalar(1).compare(.eq));
}

test "truncate to zero" {
    var res_limbs: [1]Limb = undefined;
    var res: Mutable = .{
        .limbs = &res_limbs,
        .len = undefined,
        .positive = undefined,
    };
    res.truncate(.{ .positive = true, .limbs = &.{0} }, .signed, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = false, .limbs = &.{0} }, .signed, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = true, .limbs = &.{0} }, .unsigned, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = false, .limbs = &.{0} }, .unsigned, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = true, .limbs = &.{ 0, 1 } }, .signed, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = false, .limbs = &.{ 0, 1 } }, .signed, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = true, .limbs = &.{ 0, 1 } }, .unsigned, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
    res.truncate(.{ .positive = false, .limbs = &.{ 0, 1 } }, .unsigned, @bitSizeOf(Limb));
    try testing.expect(res.positive and res.len == 1 and res.limbs[0] == 0);
}

test "truncate to minimum signed integer" {
    var res_limbs: [1]Limb = undefined;
    var res: Mutable = .{
        .limbs = &res_limbs,
        .len = undefined,
        .positive = undefined,
    };
    res.truncate(.{ .positive = true, .limbs = &.{1 << @bitSizeOf(Limb) - 1} }, .signed, @bitSizeOf(Limb));
    try testing.expect(res.toConst().orderAgainstScalar(-1 << @bitSizeOf(Limb) - 1).compare(.eq));
    res.truncate(.{ .positive = false, .limbs = &.{1 << @bitSizeOf(Limb) - 1} }, .signed, @bitSizeOf(Limb));
    try testing.expect(res.toConst().orderAgainstScalar(-1 << @bitSizeOf(Limb) - 1).compare(.eq));
    res.truncate(.{ .positive = true, .limbs = &.{1 << @bitSizeOf(Limb) - 1} }, .unsigned, @bitSizeOf(Limb));
    try testing.expect(res.toConst().orderAgainstScalar(1 << @bitSizeOf(Limb) - 1).compare(.eq));
    res.truncate(.{ .positive = false, .limbs = &.{1 << @bitSizeOf(Limb) - 1} }, .unsigned, @bitSizeOf(Limb));
    try testing.expect(res.toConst().orderAgainstScalar(1 << @bitSizeOf(Limb) - 1).compare(.eq));
}

test "saturate single signed positive" {
    var a = try Managed.initSet(testing.allocator, 0xBBBB_BBBB);
    defer a.deinit();

    try a.saturate(&a, .signed, 17);

    try testing.expectEqual(maxInt(i17), try a.toInt(i17));
}

test "saturate single signed negative" {
    var a = try Managed.initSet(testing.allocator, -1_234_567);
    defer a.deinit();

    try a.saturate(&a, .signed, 17);

    try testing.expectEqual(minInt(i17), try a.toInt(i17));
}

test "saturate single signed" {
    var a = try Managed.initSet(testing.allocator, maxInt(i17) - 1);
    defer a.deinit();

    try a.saturate(&a, .signed, 17);

    try testing.expectEqual(maxInt(i17) - 1, try a.toInt(i17));
}

test "saturate multi signed" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb) << @bitSizeOf(SignedDoubleLimb));
    defer a.deinit();

    try a.saturate(&a, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expectEqual(maxInt(SignedDoubleLimb), try a.toInt(SignedDoubleLimb));
}

test "saturate single unsigned" {
    var a = try Managed.initSet(testing.allocator, 0xFEFE_FEFE);
    defer a.deinit();

    try a.saturate(&a, .unsigned, 23);

    try testing.expectEqual(maxInt(u23), try a.toInt(u23));
}

test "saturate multi unsigned zero" {
    var a = try Managed.initSet(testing.allocator, -1);
    defer a.deinit();

    try a.saturate(&a, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expect(a.eqlZero());
}

test "saturate multi unsigned" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb) << @bitSizeOf(DoubleLimb));
    defer a.deinit();

    try a.saturate(&a, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expectEqual(maxInt(DoubleLimb), try a.toInt(DoubleLimb));
}

test "shift-right single" {
    var a = try Managed.initSet(testing.allocator, 0xffff0000);
    defer a.deinit();
    try a.shiftRight(&a, 16);

    try testing.expectEqual(0xffff, try a.toInt(u32));
}

test "shift-right multi" {
    var a = try Managed.initSet(testing.allocator, 0xffff0000eeee1111dddd2222cccc3333);
    defer a.deinit();
    try a.shiftRight(&a, 67);

    try testing.expectEqual(0x1fffe0001dddc222, try a.toInt(u64));

    try a.set(0xffff0000eeee1111dddd2222cccc3333);
    try a.shiftRight(&a, 63);
    try a.shiftRight(&a, 63);
    try a.shiftRight(&a, 2);
    try testing.expect(a.eqlZero());

    try a.set(0xffff0000eeee1111dddd2222cccc3333000000000000000000000);
    try a.shiftRight(&a, 84);
    const string = try a.toString(
        testing.allocator,
        16,
        .lower,
    );
    defer testing.allocator.free(string);
    try std.testing.expectEqualStrings(
        "ffff0000eeee1111dddd2222cccc3333",
        string,
    );
}

test "shift-left single" {
    var a = try Managed.initSet(testing.allocator, 0xffff);
    defer a.deinit();
    try a.shiftLeft(&a, 16);

    try testing.expectEqual(0xffff0000, try a.toInt(u64));
}

test "shift-left multi" {
    var a = try Managed.initSet(testing.allocator, 0x1fffe0001dddc222);
    defer a.deinit();
    try a.shiftLeft(&a, 67);

    try testing.expectEqual(0xffff0000eeee11100000000000000000, try a.toInt(u128));
}

test "shift-right negative" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    var arg = try Managed.initSet(testing.allocator, -20);
    defer arg.deinit();
    try a.shiftRight(&arg, 2);
    try testing.expectEqual(-5, try a.toInt(i32)); // -20 >> 2 == -5

    var arg2 = try Managed.initSet(testing.allocator, -5);
    defer arg2.deinit();
    try a.shiftRight(&arg2, 10);
    try testing.expectEqual(-1, try a.toInt(i32)); // -5 >> 10 == -1

    var arg3 = try Managed.initSet(testing.allocator, -10);
    defer arg3.deinit();
    try a.shiftRight(&arg3, 1232);
    try testing.expectEqual(-1, try a.toInt(i32)); // -10 >> 1232 == -1

    var arg4 = try Managed.initSet(testing.allocator, -5);
    defer arg4.deinit();
    try a.shiftRight(&arg4, 2);
    try testing.expectEqual(-2, try a.toInt(i32)); // -5 >> 2 == -2

    var arg5 = try Managed.initSet(testing.allocator, -0xffff0000eeee1111dddd2222cccc3333);
    defer arg5.deinit();
    try a.shiftRight(&arg5, 67);
    try testing.expectEqual(-0x1fffe0001dddc223, try a.toInt(i64));

    var arg6 = try Managed.initSet(testing.allocator, -0x1ffffffffffffffff);
    defer arg6.deinit();
    try a.shiftRight(&arg6, 1);
    try a.shiftRight(&a, 1);
    a.setSign(true);
    try testing.expectEqual(0x8000000000000000, try a.toInt(u64));

    var arg7 = try Managed.initSet(testing.allocator, -32767);
    defer arg7.deinit();
    a.setSign(false);
    try a.shiftRight(&arg7, 4);
    try testing.expectEqual(-2048, try a.toInt(i16));
    a.setSign(true);
    try a.shiftRight(&arg7, 4);
    try testing.expectEqual(-2048, try a.toInt(i16));

    var arg8_limbs: [1]Limb = undefined;
    var arg8: Mutable = .{
        .limbs = &arg8_limbs,
        .len = undefined,
        .positive = undefined,
    };
    arg8.shiftRight(.{ .limbs = &.{ 1, 1 }, .positive = false }, @bitSizeOf(Limb));
    try testing.expect(arg8.toConst().orderAgainstScalar(-2).compare(.eq));
}

test "sat shift-left simple unsigned" {
    var a = try Managed.initSet(testing.allocator, 0xffff);
    defer a.deinit();
    try a.shiftLeftSat(&a, 16, .unsigned, 21);

    try testing.expectEqual(0x1fffff, try a.toInt(u64));
}

test "sat shift-left simple unsigned no sat" {
    var a = try Managed.initSet(testing.allocator, 1);
    defer a.deinit();
    try a.shiftLeftSat(&a, 16, .unsigned, 21);

    try testing.expectEqual(0x10000, try a.toInt(u64));
}

test "sat shift-left multi unsigned" {
    var a = try Managed.initSet(testing.allocator, 16);
    defer a.deinit();
    try a.shiftLeftSat(&a, @bitSizeOf(DoubleLimb) - 3, .unsigned, @bitSizeOf(DoubleLimb) - 1);

    try testing.expectEqual(maxInt(DoubleLimb) >> 1, try a.toInt(DoubleLimb));
}

test "sat shift-left unsigned shift > bitcount" {
    var a = try Managed.initSet(testing.allocator, 1);
    defer a.deinit();
    try a.shiftLeftSat(&a, 10, .unsigned, 10);

    try testing.expectEqual(maxInt(u10), try a.toInt(u10));
}

test "sat shift-left unsigned zero" {
    var a = try Managed.initSet(testing.allocator, 0);
    defer a.deinit();
    try a.shiftLeftSat(&a, 1, .unsigned, 0);

    try testing.expectEqual(0, try a.toInt(u64));
}

test "sat shift-left unsigned negative" {
    var a = try Managed.initSet(testing.allocator, -100);
    defer a.deinit();
    try a.shiftLeftSat(&a, 0, .unsigned, 0);

    try testing.expectEqual(0, try a.toInt(u64));
}

test "sat shift-left signed simple negative" {
    var a = try Managed.initSet(testing.allocator, -100);
    defer a.deinit();
    try a.shiftLeftSat(&a, 3, .signed, 10);

    try testing.expectEqual(minInt(i10), try a.toInt(i10));
}

test "sat shift-left signed simple positive" {
    var a = try Managed.initSet(testing.allocator, 100);
    defer a.deinit();
    try a.shiftLeftSat(&a, 3, .signed, 10);

    try testing.expectEqual(maxInt(i10), try a.toInt(i10));
}

test "sat shift-left signed multi positive" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;

    var x: SignedDoubleLimb = 1;
    _ = &x;

    const shift = @bitSizeOf(SignedDoubleLimb) - 1;

    var a = try Managed.initSet(testing.allocator, x);
    defer a.deinit();
    try a.shiftLeftSat(&a, shift, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expectEqual(x <<| shift, try a.toInt(SignedDoubleLimb));
}

test "sat shift-left signed multi negative" {
    if (builtin.zig_backend == .stage2_x86_64) return error.SkipZigTest;

    var x: SignedDoubleLimb = -1;
    _ = &x;

    const shift = @bitSizeOf(SignedDoubleLimb) - 1;

    var a = try Managed.initSet(testing.allocator, x);
    defer a.deinit();
    try a.shiftLeftSat(&a, shift, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expectEqual(x <<| shift, try a.toInt(SignedDoubleLimb));
}

test "bitNotWrap unsigned simple" {
    var x: u10 = 123;
    _ = &x;

    var a = try Managed.initSet(testing.allocator, x);
    defer a.deinit();

    try a.bitNotWrap(&a, .unsigned, 10);

    try testing.expectEqual(~x, try a.toInt(u10));
}

test "bitNotWrap unsigned multi" {
    var a = try Managed.initSet(testing.allocator, 0);
    defer a.deinit();

    try a.bitNotWrap(&a, .unsigned, @bitSizeOf(DoubleLimb));

    try testing.expectEqual(maxInt(DoubleLimb), try a.toInt(DoubleLimb));
}

test "bitNotWrap signed simple" {
    var x: i11 = -456;
    _ = &x;

    var a = try Managed.initSet(testing.allocator, -456);
    defer a.deinit();

    try a.bitNotWrap(&a, .signed, 11);

    try testing.expectEqual(~x, try a.toInt(i11));
}

test "bitNotWrap signed multi" {
    var a = try Managed.initSet(testing.allocator, 0);
    defer a.deinit();

    try a.bitNotWrap(&a, .signed, @bitSizeOf(SignedDoubleLimb));

    try testing.expectEqual(-1, try a.toInt(SignedDoubleLimb));
}

test "bitNotWrap more than two limbs" {
    // This test requires int sizes greater than 128 bits.
    if (builtin.zig_backend == .stage2_wasm) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_aarch64) return error.SkipZigTest; // TODO
    if (builtin.zig_backend == .stage2_arm) return error.SkipZigTest; // TODO
    // LLVM: unexpected runtime library name: __umodei4
    if (builtin.zig_backend == .stage2_llvm and comptime builtin.target.cpu.arch.isWasm()) return error.SkipZigTest; // TODO

    var a = try Managed.initSet(testing.allocator, maxInt(Limb));
    defer a.deinit();

    var res = try Managed.init(testing.allocator);
    defer res.deinit();

    const bits = @bitSizeOf(Limb) * 4 + 2;

    try res.bitNotWrap(&a, .unsigned, bits);
    const Unsigned = @Type(.{ .int = .{ .signedness = .unsigned, .bits = bits } });
    try testing.expectEqual((try res.toInt(Unsigned)), ~@as(Unsigned, maxInt(Limb)));

    try res.bitNotWrap(&a, .signed, bits);
    const Signed = @Type(.{ .int = .{ .signedness = .signed, .bits = bits } });
    try testing.expectEqual((try res.toInt(Signed)), ~@as(Signed, maxInt(Limb)));
}

test "bitwise and simple" {
    var a = try Managed.initSet(testing.allocator, 0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0xeeeeeeee22222222);
    defer b.deinit();

    try a.bitAnd(&a, &b);

    try testing.expectEqual(0xeeeeeeee00000000, try a.toInt(u64));
}

test "bitwise and multi-limb" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb) + 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, maxInt(Limb));
    defer b.deinit();

    try a.bitAnd(&a, &b);

    try testing.expectEqual(0, try a.toInt(u128));
}

test "bitwise and negative-positive simple" {
    var a = try Managed.initSet(testing.allocator, -0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0xeeeeeeee22222222);
    defer b.deinit();

    try a.bitAnd(&a, &b);

    try testing.expectEqual(0x22222222, try a.toInt(u64));
}

test "bitwise and negative-positive multi-limb" {
    var a = try Managed.initSet(testing.allocator, -maxInt(Limb) - 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, maxInt(Limb));
    defer b.deinit();

    try a.bitAnd(&a, &b);

    try testing.expect(a.eqlZero());
}

test "bitwise and positive-negative simple" {
    var a = try Managed.initSet(testing.allocator, 0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -0xeeeeeeee22222222);
    defer b.deinit();

    try a.bitAnd(&a, &b);

    try testing.expectEqual(0x1111111111111110, try a.toInt(u64));
}

test "bitwise and positive-negative multi-limb" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb));
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -maxInt(Limb) - 1);
    defer b.deinit();

    try a.bitAnd(&a, &b);

    try testing.expect(a.eqlZero());
}

test "bitwise and negative-negative simple" {
    var a = try Managed.initSet(testing.allocator, -0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -0xeeeeeeee22222222);
    defer b.deinit();

    try a.bitAnd(&a, &b);

    try testing.expectEqual(-0xffffffff33333332, try a.toInt(i128));
}

test "bitwise and negative-negative multi-limb" {
    var a = try Managed.initSet(testing.allocator, -maxInt(Limb) - 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -maxInt(Limb) - 2);
    defer b.deinit();

    try a.bitAnd(&a, &b);

    try testing.expectEqual(-maxInt(Limb) * 2 - 2, try a.toInt(i128));
}

test "bitwise and negative overflow" {
    var a = try Managed.initSet(testing.allocator, -maxInt(Limb));
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -2);
    defer b.deinit();

    try a.bitAnd(&a, &b);

    try testing.expectEqual(-maxInt(Limb) - 1, try a.toInt(SignedDoubleLimb));
}

test "bitwise xor simple" {
    var a = try Managed.initSet(testing.allocator, 0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0xeeeeeeee22222222);
    defer b.deinit();

    try a.bitXor(&a, &b);

    try testing.expectEqual(0x1111111133333333, try a.toInt(u64));
}

test "bitwise xor multi-limb" {
    var x: DoubleLimb = maxInt(Limb) + 1;
    var y: DoubleLimb = maxInt(Limb);
    _ = .{ &x, &y };

    var a = try Managed.initSet(testing.allocator, x);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, y);
    defer b.deinit();

    try a.bitXor(&a, &b);

    try testing.expectEqual(x ^ y, try a.toInt(DoubleLimb));
}

test "bitwise xor single negative simple" {
    var a = try Managed.initSet(testing.allocator, 0x6b03e381328a3154);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -0x45fd3acef9191fad);
    defer b.deinit();

    try a.bitXor(&a, &b);

    try testing.expectEqual(-0x2efed94fcb932ef9, try a.toInt(i64));
}

test "bitwise xor single negative multi-limb" {
    var a = try Managed.initSet(testing.allocator, -0x9849c6e7a10d66d0e4260d4846254c32);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0xf2194e7d1c855272a997fcde16f6d5a8);
    defer b.deinit();

    try a.bitXor(&a, &b);

    try testing.expectEqual(-0x6a50889abd8834a24db1f19650d3999a, try a.toInt(i128));
}

test "bitwise xor single negative overflow" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb));
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -1);
    defer b.deinit();

    try a.bitXor(&a, &b);

    try testing.expectEqual(-(maxInt(Limb) + 1), try a.toInt(SignedDoubleLimb));
}

test "bitwise xor double negative simple" {
    var a = try Managed.initSet(testing.allocator, -0x8e48bd5f755ef1f3);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -0x4dd4fa576f3046ac);
    defer b.deinit();

    try a.bitXor(&a, &b);

    try testing.expectEqual(0xc39c47081a6eb759, try a.toInt(u64));
}

test "bitwise xor double negative multi-limb" {
    var a = try Managed.initSet(testing.allocator, -0x684e5da8f500ec8ca7204c33ccc51c9c);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -0xcb07736a7b62289c78d967c3985eebeb);
    defer b.deinit();

    try a.bitXor(&a, &b);

    try testing.expectEqual(0xa3492ec28e62c410dff92bf0549bf771, try a.toInt(u128));
}

test "bitwise or simple" {
    var a = try Managed.initSet(testing.allocator, 0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0xeeeeeeee22222222);
    defer b.deinit();

    try a.bitOr(&a, &b);

    try testing.expectEqual(0xffffffff33333333, try a.toInt(u64));
}

test "bitwise or multi-limb" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb) + 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, maxInt(Limb));
    defer b.deinit();

    try a.bitOr(&a, &b);

    try testing.expectEqual((maxInt(Limb) + 1) + maxInt(Limb), try a.toInt(DoubleLimb));
}

test "bitwise or negative-positive simple" {
    var a = try Managed.initSet(testing.allocator, -0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0xeeeeeeee22222222);
    defer b.deinit();

    try a.bitOr(&a, &b);

    try testing.expectEqual(-0x1111111111111111, try a.toInt(i64));
}

test "bitwise or negative-positive multi-limb" {
    var a = try Managed.initSet(testing.allocator, -maxInt(Limb) - 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 1);
    defer b.deinit();

    try a.bitOr(&a, &b);

    try testing.expectEqual(-maxInt(Limb), try a.toInt(SignedDoubleLimb));
}

test "bitwise or positive-negative simple" {
    var a = try Managed.initSet(testing.allocator, 0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -0xeeeeeeee22222222);
    defer b.deinit();

    try a.bitOr(&a, &b);

    try testing.expectEqual(-0x22222221, try a.toInt(i64));
}

test "bitwise or positive-negative multi-limb" {
    var a = try Managed.initSet(testing.allocator, maxInt(Limb) + 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -1);
    defer b.deinit();

    try a.bitOr(&a, &b);

    try testing.expectEqual(-1, try a.toInt(SignedDoubleLimb));
}

test "bitwise or negative-negative simple" {
    var a = try Managed.initSet(testing.allocator, -0xffffffff11111111);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -0xeeeeeeee22222222);
    defer b.deinit();

    try a.bitOr(&a, &b);

    try testing.expectEqual(-0xeeeeeeee00000001, try a.toInt(i128));
}

test "bitwise or negative-negative multi-limb" {
    var a = try Managed.initSet(testing.allocator, -maxInt(Limb) - 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, -maxInt(Limb));
    defer b.deinit();

    try a.bitOr(&a, &b);

    try testing.expectEqual(-maxInt(Limb), try a.toInt(SignedDoubleLimb));
}

test "var args" {
    var a = try Managed.initSet(testing.allocator, 5);
    defer a.deinit();

    var b = try Managed.initSet(testing.allocator, 6);
    defer b.deinit();
    try a.add(&a, &b);
    try testing.expectEqual(11, try a.toInt(u64));

    var c = try Managed.initSet(testing.allocator, 11);
    defer c.deinit();
    try testing.expectEqual(.eq, a.order(c));

    var d = try Managed.initSet(testing.allocator, 14);
    defer d.deinit();
    try testing.expect(a.order(d) != .gt);
}

test "gcd non-one small" {
    var a = try Managed.initSet(testing.allocator, 17);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 97);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.gcd(&a, &b);

    try testing.expectEqual(1, try r.toInt(u32));
}

test "gcd non-one medium" {
    var a = try Managed.initSet(testing.allocator, 4864);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 3458);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.gcd(&a, &b);

    try testing.expectEqual(38, try r.toInt(u32));
}

test "gcd non-one large" {
    var a = try Managed.initSet(testing.allocator, 0xffffffffffffffff);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0xffffffffffffffff7777);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.gcd(&a, &b);

    try testing.expectEqual(4369, try r.toInt(u32));
}

test "gcd large multi-limb result" {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest;

    var a = try Managed.initSet(testing.allocator, 0x12345678123456781234567812345678123456781234567812345678);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 0x12345671234567123456712345671234567123456712345671234567);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.gcd(&a, &b);

    const answer = (try r.toInt(u256));
    try testing.expectEqual(0xf000000ff00000fff0000ffff000fffff00ffffff1, answer);
}

test "gcd one large" {
    var a = try Managed.initSet(testing.allocator, 1897056385327307);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 2251799813685248);
    defer b.deinit();
    var r = try Managed.init(testing.allocator);
    defer r.deinit();

    try r.gcd(&a, &b);

    try testing.expectEqual(1, try r.toInt(u64));
}

test "mutable to managed" {
    const allocator = testing.allocator;
    const limbs_buf = try allocator.alloc(Limb, 8);
    defer allocator.free(limbs_buf);

    var a = Mutable.init(limbs_buf, 0xdeadbeef);
    var a_managed = a.toManaged(allocator);

    try testing.expect(a.toConst().eql(a_managed.toConst()));
}

test "const to managed" {
    var a = try Managed.initSet(testing.allocator, 123423453456);
    defer a.deinit();

    var b = try a.toConst().toManaged(testing.allocator);
    defer b.deinit();

    try testing.expect(a.toConst().eql(b.toConst()));
}

test "pow" {
    {
        var a = try Managed.initSet(testing.allocator, -3);
        defer a.deinit();

        try a.pow(&a, 3);
        try testing.expectEqual(@as(i32, -27), try a.toInt(i32));

        try a.pow(&a, 4);
        try testing.expectEqual(@as(i32, 531441), try a.toInt(i32));
    }
    {
        var a = try Managed.initSet(testing.allocator, 10);
        defer a.deinit();

        var y = try Managed.init(testing.allocator);
        defer y.deinit();

        // y and a are not aliased
        try y.pow(&a, 123);
        // y and a are aliased
        try a.pow(&a, 123);

        try testing.expect(a.eql(y));

        const ys = try y.toString(testing.allocator, 16, .lower);
        defer testing.allocator.free(ys);
        try testing.expectEqualSlices(
            u8,
            "183425a5f872f126e00a5ad62c839075cd6846c6fb0230887c7ad7a9dc530fcb" ++
                "4933f60e8000000000000000000000000000000",
            ys,
        );
    }
    // Special cases
    {
        var a = try Managed.initSet(testing.allocator, 0);
        defer a.deinit();

        try a.pow(&a, 100);
        try testing.expectEqual(@as(i32, 0), try a.toInt(i32));

        try a.set(1);
        try a.pow(&a, 0);
        try testing.expectEqual(@as(i32, 1), try a.toInt(i32));
        try a.pow(&a, 100);
        try testing.expectEqual(@as(i32, 1), try a.toInt(i32));
        try a.set(-1);
        try a.pow(&a, 15);
        try testing.expectEqual(@as(i32, -1), try a.toInt(i32));
        try a.pow(&a, 16);
        try testing.expectEqual(@as(i32, 1), try a.toInt(i32));
    }
}

test "sqrt" {
    var r = try Managed.init(testing.allocator);
    defer r.deinit();
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    // not aliased
    try r.set(0);
    try a.set(25);
    try r.sqrt(&a);
    try testing.expectEqual(@as(i32, 5), try r.toInt(i32));

    // aliased
    try a.set(25);
    try a.sqrt(&a);
    try testing.expectEqual(@as(i32, 5), try a.toInt(i32));

    // bottom
    try r.set(0);
    try a.set(24);
    try r.sqrt(&a);
    try testing.expectEqual(@as(i32, 4), try r.toInt(i32));

    // large number
    try r.set(0);
    try a.set(0x1_0000_0000_0000);
    try r.sqrt(&a);
    try testing.expectEqual(@as(i32, 0x100_0000), try r.toInt(i32));
}

test "regression test for 1 limb overflow with alias" {
    // Note these happen to be two consecutive Fibonacci sequence numbers, the
    // first two whose sum exceeds 2**64.
    var a = try Managed.initSet(testing.allocator, 7540113804746346429);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 12200160415121876738);
    defer b.deinit();

    try a.ensureAddCapacity(a.toConst(), b.toConst());
    try a.add(&a, &b);

    try testing.expectEqual(.eq, a.toConst().orderAgainstScalar(19740274219868223167));
}

test "regression test for realloc with alias" {
    // Note these happen to be two consecutive Fibonacci sequence numbers, the
    // second of which is the first such number to exceed 2**192.
    var a = try Managed.initSet(testing.allocator, 5611500259351924431073312796924978741056961814867751431689);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, 9079598147510263717870894449029933369491131786514446266146);
    defer b.deinit();

    try a.ensureAddCapacity(a.toConst(), b.toConst());
    try a.add(&a, &b);

    try testing.expectEqual(.eq, a.toConst().orderAgainstScalar(14691098406862188148944207245954912110548093601382197697835));
}

test "big int popcount" {
    var a = try Managed.init(testing.allocator);
    defer a.deinit();

    try a.set(0);
    try popCountTest(&a, 0, 0);
    try popCountTest(&a, 567, 0);

    try a.set(1);
    try popCountTest(&a, 1, 1);
    try popCountTest(&a, 13, 1);
    try popCountTest(&a, 432, 1);

    try a.set(255);
    try popCountTest(&a, 8, 8);
    try a.set(-128);
    try popCountTest(&a, 8, 1);

    try a.set(-2);
    try popCountTest(&a, 16, 15);
    try popCountTest(&a, 15, 14);

    try a.set(-2047);
    try popCountTest(&a, 12, 2);
    try popCountTest(&a, 24, 14);

    try a.set(maxInt(u5000));
    try popCountTest(&a, 5000, 5000);
    try a.set(minInt(i5000));
    try popCountTest(&a, 5000, 1);

    // Check -1 at various bit counts that cross Limb size multiples.
    const limb_bits = @bitSizeOf(Limb);
    try a.set(-1);
    try popCountTest(&a, 1, 1); // i1
    try popCountTest(&a, 2, 2);
    try popCountTest(&a, 16, 16);
    try popCountTest(&a, 543, 543);
    try popCountTest(&a, 544, 544);
    try popCountTest(&a, limb_bits - 1, limb_bits - 1);
    try popCountTest(&a, limb_bits, limb_bits);
    try popCountTest(&a, limb_bits + 1, limb_bits + 1);
    try popCountTest(&a, limb_bits * 2 - 1, limb_bits * 2 - 1);
    try popCountTest(&a, limb_bits * 2, limb_bits * 2);
    try popCountTest(&a, limb_bits * 2 + 1, limb_bits * 2 + 1);

    // Check very large numbers.
    try a.setString(16, "ff00000100000100" ++ ("0000000000000000" ** 62));
    try popCountTest(&a, 4032, 10);
    try popCountTest(&a, 6000, 10);
    a.negate();
    try popCountTest(&a, 4033, 48);
    try popCountTest(&a, 4133, 148);

    // Check when most significant limb is full of 1s.
    const limb_size = @bitSizeOf(Limb);
    try a.set(maxInt(Limb));
    try popCountTest(&a, limb_size, limb_size);
    try popCountTest(&a, limb_size + 1, limb_size);
    try popCountTest(&a, limb_size * 10 + 2, limb_size);
    a.negate();
    try popCountTest(&a, limb_size * 2 - 2, limb_size - 1);
    try popCountTest(&a, limb_size * 2 - 1, limb_size);
    try popCountTest(&a, limb_size * 2, limb_size + 1);
    try popCountTest(&a, limb_size * 2 + 1, limb_size + 2);
    try popCountTest(&a, limb_size * 2 + 2, limb_size + 3);
    try popCountTest(&a, limb_size * 2 + 3, limb_size + 4);
    try popCountTest(&a, limb_size * 2 + 4, limb_size + 5);
    try popCountTest(&a, limb_size * 4 + 2, limb_size * 3 + 3);
}

fn popCountTest(val: *const Managed, bit_count: usize, expected: usize) !void {
    var b = try Managed.init(testing.allocator);
    defer b.deinit();
    try b.popCount(val, bit_count);

    try testing.expectEqual(std.math.Order.eq, b.toConst().orderAgainstScalar(expected));
    try testing.expectEqual(expected, val.toConst().popCount(bit_count));
}

test "big int conversion read/write twos complement" {
    var a = try Managed.initSet(testing.allocator, (1 << 493) - 1);
    defer a.deinit();
    var b = try Managed.initSet(testing.allocator, (1 << 493) - 1);
    defer b.deinit();
    var m = b.toMutable();

    var buffer1 = try testing.allocator.alloc(u8, 64);
    defer testing.allocator.free(buffer1);

    const endians = [_]std.builtin.Endian{ .little, .big };
    const abi_size = 64;

    for (endians) |endian| {
        // Writing to buffer and back should not change anything
        a.toConst().writeTwosComplement(buffer1[0..abi_size], endian);
        m.readTwosComplement(buffer1[0..abi_size], 493, endian, .unsigned);
        try testing.expectEqual(.eq, m.toConst().order(a.toConst()));

        // Equivalent to @bitCast(i493, @as(u493, intMax(u493))
        a.toConst().writeTwosComplement(buffer1[0..abi_size], endian);
        m.readTwosComplement(buffer1[0..abi_size], 493, endian, .signed);
        try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(-1));
    }
}

test "big int conversion read twos complement with padding" {
    var a = try Managed.initSet(testing.allocator, 0x01_02030405_06070809_0a0b0c0d);
    defer a.deinit();

    var buffer1 = try testing.allocator.alloc(u8, 16);
    defer testing.allocator.free(buffer1);
    @memset(buffer1, 0xaa);

    // writeTwosComplement:
    // (1) should not write beyond buffer[0..abi_size]
    // (2) should correctly order bytes based on the provided endianness
    // (3) should sign-extend any bits from bit_count to 8 * abi_size

    var bit_count: usize = 12 * 8 + 1;
    a.toConst().writeTwosComplement(buffer1[0..13], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0xaa, 0xaa, 0xaa }));
    a.toConst().writeTwosComplement(buffer1[0..13], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xaa, 0xaa, 0xaa }));
    a.toConst().writeTwosComplement(buffer1[0..16], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0, 0x0, 0x0 }));
    a.toConst().writeTwosComplement(buffer1[0..16], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0x0, 0x0, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd }));

    @memset(buffer1, 0xaa);
    try a.set(-0x01_02030405_06070809_0a0b0c0d);
    bit_count = 12 * 8 + 2;

    a.toConst().writeTwosComplement(buffer1[0..13], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xf3, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xaa, 0xaa, 0xaa }));
    a.toConst().writeTwosComplement(buffer1[0..13], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf3, 0xaa, 0xaa, 0xaa }));
    a.toConst().writeTwosComplement(buffer1[0..16], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xf3, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0xff, 0xff }));
    a.toConst().writeTwosComplement(buffer1[0..16], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &[_]u8{ 0xff, 0xff, 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf3 }));
}

test "big int write twos complement +/- zero" {
    var a = try Managed.initSet(testing.allocator, 0x0);
    defer a.deinit();
    var m = a.toMutable();

    var buffer1 = try testing.allocator.alloc(u8, 16);
    defer testing.allocator.free(buffer1);
    @memset(buffer1, 0xaa);

    // Test zero

    m.toConst().writeTwosComplement(buffer1[0..13], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 13) ++ ([_]u8{0xaa} ** 3))));
    m.toConst().writeTwosComplement(buffer1[0..13], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 13) ++ ([_]u8{0xaa} ** 3))));
    m.toConst().writeTwosComplement(buffer1[0..16], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 16))));
    m.toConst().writeTwosComplement(buffer1[0..16], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 16))));

    @memset(buffer1, 0xaa);
    m.positive = false;

    // Test negative zero

    m.toConst().writeTwosComplement(buffer1[0..13], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 13) ++ ([_]u8{0xaa} ** 3))));
    m.toConst().writeTwosComplement(buffer1[0..13], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 13) ++ ([_]u8{0xaa} ** 3))));
    m.toConst().writeTwosComplement(buffer1[0..16], .little);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 16))));
    m.toConst().writeTwosComplement(buffer1[0..16], .big);
    try testing.expect(std.mem.eql(u8, buffer1, &(([_]u8{0} ** 16))));
}

test "big int conversion write twos complement with padding" {
    var a = try Managed.initSet(testing.allocator, 0x01_ffffffff_ffffffff_ffffffff);
    defer a.deinit();

    var m = a.toMutable();

    // readTwosComplement:
    // (1) should not read beyond buffer[0..abi_size]
    // (2) should correctly interpret bytes based on the provided endianness
    // (3) should ignore any bits from bit_count to 8 * abi_size

    var bit_count: usize = 12 * 8 + 1;
    var buffer: []const u8 = undefined;

    // Test 0x01_02030405_06070809_0a0b0c0d

    buffer = &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0xb };
    m.readTwosComplement(buffer[0..13], bit_count, .little, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x01_02030405_06070809_0a0b0c0d));

    buffer = &[_]u8{ 0xb, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd };
    m.readTwosComplement(buffer[0..13], bit_count, .big, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x01_02030405_06070809_0a0b0c0d));

    buffer = &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0xab, 0xaa, 0xaa, 0xaa };
    m.readTwosComplement(buffer[0..16], bit_count, .little, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x01_02030405_06070809_0a0b0c0d));

    buffer = &[_]u8{ 0xaa, 0xaa, 0xaa, 0xab, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd };
    m.readTwosComplement(buffer[0..16], bit_count, .big, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x01_02030405_06070809_0a0b0c0d));

    bit_count = @sizeOf(Limb) * 8;

    // Test 0x0a0a0a0a_02030405_06070809_0a0b0c0d

    buffer = &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0xaa };
    m.readTwosComplement(buffer[0..13], bit_count, .little, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(@as(Limb, @truncate(0xaa_02030405_06070809_0a0b0c0d))));

    buffer = &[_]u8{ 0xaa, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd };
    m.readTwosComplement(buffer[0..13], bit_count, .big, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(@as(Limb, @truncate(0xaa_02030405_06070809_0a0b0c0d))));

    buffer = &[_]u8{ 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0xaa, 0xaa, 0xaa, 0xaa };
    m.readTwosComplement(buffer[0..16], bit_count, .little, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(@as(Limb, @truncate(0xaaaaaaaa_02030405_06070809_0a0b0c0d))));

    buffer = &[_]u8{ 0xaa, 0xaa, 0xaa, 0xaa, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd };
    m.readTwosComplement(buffer[0..16], bit_count, .big, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(@as(Limb, @truncate(0xaaaaaaaa_02030405_06070809_0a0b0c0d))));

    bit_count = 12 * 8 + 2;

    // Test -0x01_02030405_06070809_0a0b0c0d

    buffer = &[_]u8{ 0xf3, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0x02 };
    m.readTwosComplement(buffer[0..13], bit_count, .little, .signed);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(-0x01_02030405_06070809_0a0b0c0d));

    buffer = &[_]u8{ 0x02, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf3 };
    m.readTwosComplement(buffer[0..13], bit_count, .big, .signed);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(-0x01_02030405_06070809_0a0b0c0d));

    buffer = &[_]u8{ 0xf3, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0x02, 0xaa, 0xaa, 0xaa };
    m.readTwosComplement(buffer[0..16], bit_count, .little, .signed);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(-0x01_02030405_06070809_0a0b0c0d));

    buffer = &[_]u8{ 0xaa, 0xaa, 0xaa, 0x02, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf3 };
    m.readTwosComplement(buffer[0..16], bit_count, .big, .signed);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(-0x01_02030405_06070809_0a0b0c0d));

    // Test 0

    buffer = &([_]u8{0} ** 16);
    m.readTwosComplement(buffer[0..13], bit_count, .little, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));
    m.readTwosComplement(buffer[0..13], bit_count, .big, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));
    m.readTwosComplement(buffer[0..16], bit_count, .little, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));
    m.readTwosComplement(buffer[0..16], bit_count, .big, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));

    bit_count = 0;
    buffer = &([_]u8{0xaa} ** 16);
    m.readTwosComplement(buffer[0..13], bit_count, .little, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));
    m.readTwosComplement(buffer[0..13], bit_count, .big, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));
    m.readTwosComplement(buffer[0..16], bit_count, .little, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));
    m.readTwosComplement(buffer[0..16], bit_count, .big, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));
}

test "big int conversion write twos complement zero" {
    var a = try Managed.initSet(testing.allocator, 0x01_ffffffff_ffffffff_ffffffff);
    defer a.deinit();

    var m = a.toMutable();

    // readTwosComplement:
    // (1) should not read beyond buffer[0..abi_size]
    // (2) should correctly interpret bytes based on the provided endianness
    // (3) should ignore any bits from bit_count to 8 * abi_size

    const bit_count: usize = 12 * 8 + 1;
    var buffer: []const u8 = undefined;

    buffer = &([_]u8{0} ** 13);
    m.readTwosComplement(buffer[0..13], bit_count, .little, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));
    m.readTwosComplement(buffer[0..13], bit_count, .big, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));

    buffer = &([_]u8{0} ** 16);
    m.readTwosComplement(buffer[0..16], bit_count, .little, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));
    m.readTwosComplement(buffer[0..16], bit_count, .big, .unsigned);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(0x0));
}

fn bitReverseTest(comptime T: type, comptime input: comptime_int, comptime expected_output: comptime_int) !void {
    const bit_count = @typeInfo(T).int.bits;
    const signedness = @typeInfo(T).int.signedness;

    var a = try Managed.initSet(testing.allocator, input);
    defer a.deinit();

    try a.ensureCapacity(calcTwosCompLimbCount(bit_count));
    var m = a.toMutable();
    m.bitReverse(a.toConst(), signedness, bit_count);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(expected_output));
}

test "big int bit reverse" {
    var a = try Managed.initSet(testing.allocator, 0x01_ffffffff_ffffffff_ffffffff);
    defer a.deinit();

    try bitReverseTest(u0, 0, 0);
    try bitReverseTest(u5, 0x12, 0x09);
    try bitReverseTest(u8, 0x12, 0x48);
    try bitReverseTest(u16, 0x1234, 0x2c48);
    try bitReverseTest(u24, 0x123456, 0x6a2c48);
    try bitReverseTest(u32, 0x12345678, 0x1e6a2c48);
    try bitReverseTest(u40, 0x123456789a, 0x591e6a2c48);
    try bitReverseTest(u48, 0x123456789abc, 0x3d591e6a2c48);
    try bitReverseTest(u56, 0x123456789abcde, 0x7b3d591e6a2c48);
    try bitReverseTest(u64, 0x123456789abcdef1, 0x8f7b3d591e6a2c48);
    try bitReverseTest(u95, 0x123456789abcdef111213141, 0x4146424447bd9eac8f351624);
    try bitReverseTest(u96, 0x123456789abcdef111213141, 0x828c84888f7b3d591e6a2c48);
    try bitReverseTest(u128, 0x123456789abcdef11121314151617181, 0x818e868a828c84888f7b3d591e6a2c48);

    try bitReverseTest(i8, @as(i8, @bitCast(@as(u8, 0x92))), @as(i8, @bitCast(@as(u8, 0x49))));
    try bitReverseTest(i16, @as(i16, @bitCast(@as(u16, 0x1234))), @as(i16, @bitCast(@as(u16, 0x2c48))));
    try bitReverseTest(i24, @as(i24, @bitCast(@as(u24, 0x123456))), @as(i24, @bitCast(@as(u24, 0x6a2c48))));
    try bitReverseTest(i24, @as(i24, @bitCast(@as(u24, 0x12345f))), @as(i24, @bitCast(@as(u24, 0xfa2c48))));
    try bitReverseTest(i24, @as(i24, @bitCast(@as(u24, 0xf23456))), @as(i24, @bitCast(@as(u24, 0x6a2c4f))));
    try bitReverseTest(i32, @as(i32, @bitCast(@as(u32, 0x12345678))), @as(i32, @bitCast(@as(u32, 0x1e6a2c48))));
    try bitReverseTest(i32, @as(i32, @bitCast(@as(u32, 0xf2345678))), @as(i32, @bitCast(@as(u32, 0x1e6a2c4f))));
    try bitReverseTest(i32, @as(i32, @bitCast(@as(u32, 0x1234567f))), @as(i32, @bitCast(@as(u32, 0xfe6a2c48))));
    try bitReverseTest(i40, @as(i40, @bitCast(@as(u40, 0x123456789a))), @as(i40, @bitCast(@as(u40, 0x591e6a2c48))));
    try bitReverseTest(i48, @as(i48, @bitCast(@as(u48, 0x123456789abc))), @as(i48, @bitCast(@as(u48, 0x3d591e6a2c48))));
    try bitReverseTest(i56, @as(i56, @bitCast(@as(u56, 0x123456789abcde))), @as(i56, @bitCast(@as(u56, 0x7b3d591e6a2c48))));
    try bitReverseTest(i64, @as(i64, @bitCast(@as(u64, 0x123456789abcdef1))), @as(i64, @bitCast(@as(u64, 0x8f7b3d591e6a2c48))));
    try bitReverseTest(i96, @as(i96, @bitCast(@as(u96, 0x123456789abcdef111213141))), @as(i96, @bitCast(@as(u96, 0x828c84888f7b3d591e6a2c48))));
    try bitReverseTest(i128, @as(i128, @bitCast(@as(u128, 0x123456789abcdef11121314151617181))), @as(i128, @bitCast(@as(u128, 0x818e868a828c84888f7b3d591e6a2c48))));
}

fn byteSwapTest(comptime T: type, comptime input: comptime_int, comptime expected_output: comptime_int) !void {
    const byte_count = @typeInfo(T).int.bits / 8;
    const signedness = @typeInfo(T).int.signedness;

    var a = try Managed.initSet(testing.allocator, input);
    defer a.deinit();

    try a.ensureCapacity(calcTwosCompLimbCount(8 * byte_count));
    var m = a.toMutable();
    m.byteSwap(a.toConst(), signedness, byte_count);
    try testing.expectEqual(.eq, m.toConst().orderAgainstScalar(expected_output));
}

test "big int byte swap" {
    var a = try Managed.initSet(testing.allocator, 0x01_ffffffff_ffffffff_ffffffff);
    defer a.deinit();

    @setEvalBranchQuota(10_000);

    try byteSwapTest(u0, 0, 0);
    try byteSwapTest(u8, 0x12, 0x12);
    try byteSwapTest(u16, 0x1234, 0x3412);
    try byteSwapTest(u24, 0x123456, 0x563412);
    try byteSwapTest(u32, 0x12345678, 0x78563412);
    try byteSwapTest(u40, 0x123456789a, 0x9a78563412);
    try byteSwapTest(u48, 0x123456789abc, 0xbc9a78563412);
    try byteSwapTest(u56, 0x123456789abcde, 0xdebc9a78563412);
    try byteSwapTest(u64, 0x123456789abcdef1, 0xf1debc9a78563412);
    try byteSwapTest(u88, 0x123456789abcdef1112131, 0x312111f1debc9a78563412);
    try byteSwapTest(u96, 0x123456789abcdef111213141, 0x41312111f1debc9a78563412);
    try byteSwapTest(u128, 0x123456789abcdef11121314151617181, 0x8171615141312111f1debc9a78563412);

    try byteSwapTest(i8, -50, -50);
    try byteSwapTest(i16, @as(i16, @bitCast(@as(u16, 0x1234))), @as(i16, @bitCast(@as(u16, 0x3412))));
    try byteSwapTest(i24, @as(i24, @bitCast(@as(u24, 0x123456))), @as(i24, @bitCast(@as(u24, 0x563412))));
    try byteSwapTest(i32, @as(i32, @bitCast(@as(u32, 0x12345678))), @as(i32, @bitCast(@as(u32, 0x78563412))));
    try byteSwapTest(i40, @as(i40, @bitCast(@as(u40, 0x123456789a))), @as(i40, @bitCast(@as(u40, 0x9a78563412))));
    try byteSwapTest(i48, @as(i48, @bitCast(@as(u48, 0x123456789abc))), @as(i48, @bitCast(@as(u48, 0xbc9a78563412))));
    try byteSwapTest(i56, @as(i56, @bitCast(@as(u56, 0x123456789abcde))), @as(i56, @bitCast(@as(u56, 0xdebc9a78563412))));
    try byteSwapTest(i64, @as(i64, @bitCast(@as(u64, 0x123456789abcdef1))), @as(i64, @bitCast(@as(u64, 0xf1debc9a78563412))));
    try byteSwapTest(i88, @as(i88, @bitCast(@as(u88, 0x123456789abcdef1112131))), @as(i88, @bitCast(@as(u88, 0x312111f1debc9a78563412))));
    try byteSwapTest(i96, @as(i96, @bitCast(@as(u96, 0x123456789abcdef111213141))), @as(i96, @bitCast(@as(u96, 0x41312111f1debc9a78563412))));
    try byteSwapTest(i128, @as(i128, @bitCast(@as(u128, 0x123456789abcdef11121314151617181))), @as(i128, @bitCast(@as(u128, 0x8171615141312111f1debc9a78563412))));

    try byteSwapTest(u512, 0x80, 1 << 511);
    try byteSwapTest(i512, 0x80, minInt(i512));
    try byteSwapTest(i512, 0x40, 1 << 510);
    try byteSwapTest(i512, -0x100, (1 << 504) - 1);
    try byteSwapTest(i400, -0x100, (1 << 392) - 1);
    try byteSwapTest(i400, -0x2, -(1 << 392) - 1);
    try byteSwapTest(i24, @as(i24, @bitCast(@as(u24, 0xf23456))), 0x5634f2);
    try byteSwapTest(i24, 0x1234f6, @as(i24, @bitCast(@as(u24, 0xf63412))));
    try byteSwapTest(i32, @as(i32, @bitCast(@as(u32, 0xf2345678))), 0x785634f2);
    try byteSwapTest(i32, 0x123456f8, @as(i32, @bitCast(@as(u32, 0xf8563412))));
    try byteSwapTest(i48, 0x123456789abc, @as(i48, @bitCast(@as(u48, 0xbc9a78563412))));
}

test "mul multi-multi alias r with a and b" {
    var a = try Managed.initSet(testing.allocator, 2 * maxInt(Limb));
    defer a.deinit();

    try a.mul(&a, &a);

    var want = try Managed.initSet(testing.allocator, 4 * maxInt(Limb) * maxInt(Limb));
    defer want.deinit();

    try testing.expect(a.eql(want));

    if (@typeInfo(Limb).int.bits == 64) {
        try testing.expectEqual(@as(usize, 5), a.limbs.len);
    }
}

test "sqr multi alias r with a" {
    var a = try Managed.initSet(testing.allocator, 2 * maxInt(Limb));
    defer a.deinit();

    try a.sqr(&a);

    var want = try Managed.initSet(testing.allocator, 4 * maxInt(Limb) * maxInt(Limb));
    defer want.deinit();

    try testing.expect(a.eql(want));

    if (@typeInfo(Limb).int.bits == 64) {
        try testing.expectEqual(@as(usize, 5), a.limbs.len);
    }
}

test "eql zeroes #17296" {
    var zero = try Managed.init(testing.allocator);
    defer zero.deinit();
    try zero.setString(10, "0");
    try std.testing.expect(zero.eql(zero));

    {
        var sum = try Managed.init(testing.allocator);
        defer sum.deinit();
        try sum.add(&zero, &zero);
        try std.testing.expect(zero.eql(sum));
    }

    {
        var diff = try Managed.init(testing.allocator);
        defer diff.deinit();
        try diff.sub(&zero, &zero);
        try std.testing.expect(zero.eql(diff));
    }
}

test "Const.order 0 == -0" {
    const a = std.math.big.int.Const{
        .limbs = &.{0},
        .positive = true,
    };
    const b = std.math.big.int.Const{
        .limbs = &.{0},
        .positive = false,
    };
    try std.testing.expectEqual(std.math.Order.eq, a.order(b));
}

test "Managed sqrt(0) = 0" {
    const allocator = testing.allocator;
    var a = try Managed.initSet(allocator, 1);
    defer a.deinit();

    var res = try Managed.initSet(allocator, 1);
    defer res.deinit();

    try a.setString(10, "0");

    try res.sqrt(&a);
    try testing.expectEqual(@as(i32, 0), try res.toInt(i32));
}

test "Managed sqrt(-1) = error" {
    const allocator = testing.allocator;
    var a = try Managed.initSet(allocator, 1);
    defer a.deinit();

    var res = try Managed.initSet(allocator, 1);
    defer res.deinit();

    try a.setString(10, "-1");

    try testing.expectError(error.SqrtOfNegativeNumber, res.sqrt(&a));
}

test "Managed sqrt(n) succeed with res.bitCountAbs() >= usize bits" {
    const allocator = testing.allocator;
    var a = try Managed.initSet(allocator, 1);
    defer a.deinit();

    var res = try Managed.initSet(allocator, 1);
    defer res.deinit();

    // a.bitCountAbs() = 127 so the first attempt has 64 bits >= usize bits
    try a.setString(10, "136036462105870278006290938611834481486");
    try res.sqrt(&a);

    var expected = try Managed.initSet(allocator, 1);
    defer expected.deinit();
    try expected.setString(10, "11663466984815033033");
    try std.testing.expectEqual(std.math.Order.eq, expected.order(res));
}

test "(BigInt) positive" {
    var a = try Managed.initSet(testing.allocator, 2);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var c = try Managed.initSet(testing.allocator, 1);
    defer c.deinit();

    // a = pow(2, 64 * @sizeOf(usize) * 8), b = a - 1
    try a.pow(&a, 64 * @sizeOf(Limb) * 8);
    try b.sub(&a, &c);

    const a_fmt = try std.fmt.allocPrintZ(testing.allocator, "{d}", .{a});
    defer testing.allocator.free(a_fmt);

    const b_fmt = try std.fmt.allocPrintZ(testing.allocator, "{d}", .{b});
    defer testing.allocator.free(b_fmt);

    try testing.expect(mem.eql(u8, a_fmt, "(BigInt)"));
    try testing.expect(!mem.eql(u8, b_fmt, "(BigInt)"));
}

test "(BigInt) negative" {
    var a = try Managed.initSet(testing.allocator, 2);
    defer a.deinit();

    var b = try Managed.init(testing.allocator);
    defer b.deinit();

    var c = try Managed.initSet(testing.allocator, 1);
    defer c.deinit();

    // a = -pow(2, 64 * @sizeOf(usize) * 8), b = a + 1
    try a.pow(&a, 64 * @sizeOf(Limb) * 8);
    a.negate();
    try b.add(&a, &c);

    const a_fmt = try std.fmt.allocPrintZ(testing.allocator, "{d}", .{a});
    defer testing.allocator.free(a_fmt);

    const b_fmt = try std.fmt.allocPrintZ(testing.allocator, "{d}", .{b});
    defer testing.allocator.free(b_fmt);

    try testing.expect(mem.eql(u8, a_fmt, "(BigInt)"));
    try testing.expect(!mem.eql(u8, b_fmt, "(BigInt)"));
}

test "clz" {
    const neg_limb_max_squared: std.math.big.int.Const = .{
        .limbs = &.{ 1, maxInt(Limb) - 1 },
        .positive = false,
    };
    try testing.expectEqual(0, neg_limb_max_squared.clz(@bitSizeOf(Limb) * 2 + 1));

    const neg_limb_max_squared_plus_one: std.math.big.int.Const = .{
        .limbs = &.{ 0, maxInt(Limb) - 1 },
        .positive = false,
    };
    try testing.expectEqual(0, neg_limb_max_squared_plus_one.clz(@bitSizeOf(Limb) * 2 + 1));

    const neg_limb_msb_squared: std.math.big.int.Const = .{
        .limbs = &.{ 0, 1 << @bitSizeOf(Limb) - 2 },
        .positive = false,
    };
    try testing.expectEqual(0, neg_limb_msb_squared.clz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(0, neg_limb_msb_squared.clz(@bitSizeOf(Limb) * 2 + 1));

    const neg_limb_max: std.math.big.int.Const = .{
        .limbs = &.{maxInt(Limb)},
        .positive = false,
    };
    try testing.expectEqual(0, neg_limb_max.clz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(0, neg_limb_max.clz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(0, neg_limb_max.clz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(0, neg_limb_max.clz(@bitSizeOf(Limb) * 2 + 1));

    const neg_limb_msb: std.math.big.int.Const = .{
        .limbs = &.{1 << @bitSizeOf(Limb) - 1},
        .positive = false,
    };
    try testing.expectEqual(0, neg_limb_msb.clz(@bitSizeOf(Limb)));
    try testing.expectEqual(0, neg_limb_msb.clz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(0, neg_limb_msb.clz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(0, neg_limb_msb.clz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(0, neg_limb_msb.clz(@bitSizeOf(Limb) * 2 + 1));

    const neg_one: std.math.big.int.Const = .{
        .limbs = &.{1},
        .positive = false,
    };
    try testing.expectEqual(0, neg_one.clz(@bitSizeOf(Limb)));
    try testing.expectEqual(0, neg_one.clz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(0, neg_one.clz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(0, neg_one.clz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(0, neg_one.clz(@bitSizeOf(Limb) * 2 + 1));

    const zero: std.math.big.int.Const = .{
        .limbs = &.{0},
        .positive = true,
    };
    try testing.expectEqual(@bitSizeOf(Limb), zero.clz(@bitSizeOf(Limb)));
    try testing.expectEqual(@bitSizeOf(Limb) + 1, zero.clz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(@bitSizeOf(Limb) * 2 - 1, zero.clz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(@bitSizeOf(Limb) * 2, zero.clz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(@bitSizeOf(Limb) * 2 + 1, zero.clz(@bitSizeOf(Limb) * 2 + 1));

    const one: std.math.big.int.Const = .{
        .limbs = &.{1},
        .positive = true,
    };
    try testing.expectEqual(@bitSizeOf(Limb) - 1, one.clz(@bitSizeOf(Limb)));
    try testing.expectEqual(@bitSizeOf(Limb), one.clz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(@bitSizeOf(Limb) * 2 - 2, one.clz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(@bitSizeOf(Limb) * 2 - 1, one.clz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(@bitSizeOf(Limb) * 2, one.clz(@bitSizeOf(Limb) * 2 + 1));

    const limb_msb: std.math.big.int.Const = .{
        .limbs = &.{1 << @bitSizeOf(Limb) - 1},
        .positive = true,
    };
    try testing.expectEqual(0, limb_msb.clz(@bitSizeOf(Limb)));
    try testing.expectEqual(1, limb_msb.clz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(@bitSizeOf(Limb) - 1, limb_msb.clz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(@bitSizeOf(Limb), limb_msb.clz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(@bitSizeOf(Limb) + 1, limb_msb.clz(@bitSizeOf(Limb) * 2 + 1));

    const limb_max: std.math.big.int.Const = .{
        .limbs = &.{maxInt(Limb)},
        .positive = true,
    };
    try testing.expectEqual(0, limb_max.clz(@bitSizeOf(Limb)));
    try testing.expectEqual(1, limb_max.clz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(@bitSizeOf(Limb) - 1, limb_max.clz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(@bitSizeOf(Limb), limb_max.clz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(@bitSizeOf(Limb) + 1, limb_max.clz(@bitSizeOf(Limb) * 2 + 1));

    const limb_msb_squared: std.math.big.int.Const = .{
        .limbs = &.{ 0, 1 << @bitSizeOf(Limb) - 2 },
        .positive = true,
    };
    try testing.expectEqual(0, limb_msb_squared.clz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(1, limb_msb_squared.clz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(2, limb_msb_squared.clz(@bitSizeOf(Limb) * 2 + 1));

    const limb_max_squared_minus_one: std.math.big.int.Const = .{
        .limbs = &.{ 0, maxInt(Limb) - 1 },
        .positive = true,
    };
    try testing.expectEqual(0, limb_max_squared_minus_one.clz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(1, limb_max_squared_minus_one.clz(@bitSizeOf(Limb) * 2 + 1));

    const limb_max_squared: std.math.big.int.Const = .{
        .limbs = &.{ 1, maxInt(Limb) - 1 },
        .positive = true,
    };
    try testing.expectEqual(0, limb_max_squared.clz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(1, limb_max_squared.clz(@bitSizeOf(Limb) * 2 + 1));
}

test "ctz" {
    const neg_limb_max_squared: std.math.big.int.Const = .{
        .limbs = &.{ 1, maxInt(Limb) - 1 },
        .positive = false,
    };
    try testing.expectEqual(0, neg_limb_max_squared.ctz(@bitSizeOf(Limb) * 2 + 1));

    const neg_limb_max_squared_plus_one: std.math.big.int.Const = .{
        .limbs = &.{ 0, maxInt(Limb) - 1 },
        .positive = false,
    };
    try testing.expectEqual(@bitSizeOf(Limb) + 1, neg_limb_max_squared_plus_one.ctz(@bitSizeOf(Limb) * 2 + 1));

    const neg_limb_msb_squared: std.math.big.int.Const = .{
        .limbs = &.{ 0, 1 << @bitSizeOf(Limb) - 2 },
        .positive = false,
    };
    try testing.expectEqual(@bitSizeOf(Limb) * 2 - 2, neg_limb_msb_squared.ctz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(@bitSizeOf(Limb) * 2 - 2, neg_limb_msb_squared.ctz(@bitSizeOf(Limb) * 2 + 1));

    const neg_limb_max: std.math.big.int.Const = .{
        .limbs = &.{maxInt(Limb)},
        .positive = false,
    };
    try testing.expectEqual(0, neg_limb_max.ctz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(0, neg_limb_max.ctz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(0, neg_limb_max.ctz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(0, neg_limb_max.ctz(@bitSizeOf(Limb) * 2 + 1));

    const neg_limb_msb: std.math.big.int.Const = .{
        .limbs = &.{1 << @bitSizeOf(Limb) - 1},
        .positive = false,
    };
    try testing.expectEqual(@bitSizeOf(Limb) - 1, neg_limb_msb.ctz(@bitSizeOf(Limb)));
    try testing.expectEqual(@bitSizeOf(Limb) - 1, neg_limb_msb.ctz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(@bitSizeOf(Limb) - 1, neg_limb_msb.ctz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(@bitSizeOf(Limb) - 1, neg_limb_msb.ctz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(@bitSizeOf(Limb) - 1, neg_limb_msb.ctz(@bitSizeOf(Limb) * 2 + 1));

    const neg_one: std.math.big.int.Const = .{
        .limbs = &.{1},
        .positive = false,
    };
    try testing.expectEqual(0, neg_one.ctz(@bitSizeOf(Limb)));
    try testing.expectEqual(0, neg_one.ctz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(0, neg_one.ctz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(0, neg_one.ctz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(0, neg_one.ctz(@bitSizeOf(Limb) * 2 + 1));

    const zero: std.math.big.int.Const = .{
        .limbs = &.{0},
        .positive = true,
    };
    try testing.expectEqual(@bitSizeOf(Limb), zero.ctz(@bitSizeOf(Limb)));
    try testing.expectEqual(@bitSizeOf(Limb) + 1, zero.ctz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(@bitSizeOf(Limb) * 2 - 1, zero.ctz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(@bitSizeOf(Limb) * 2, zero.ctz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(@bitSizeOf(Limb) * 2 + 1, zero.ctz(@bitSizeOf(Limb) * 2 + 1));

    const one: std.math.big.int.Const = .{
        .limbs = &.{1},
        .positive = true,
    };
    try testing.expectEqual(0, one.ctz(@bitSizeOf(Limb)));
    try testing.expectEqual(0, one.ctz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(0, one.ctz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(0, one.ctz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(0, one.ctz(@bitSizeOf(Limb) * 2 + 1));

    const limb_msb: std.math.big.int.Const = .{
        .limbs = &.{1 << @bitSizeOf(Limb) - 1},
        .positive = true,
    };
    try testing.expectEqual(@bitSizeOf(Limb) - 1, limb_msb.ctz(@bitSizeOf(Limb)));
    try testing.expectEqual(@bitSizeOf(Limb) - 1, limb_msb.ctz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(@bitSizeOf(Limb) - 1, limb_msb.ctz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(@bitSizeOf(Limb) - 1, limb_msb.ctz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(@bitSizeOf(Limb) - 1, limb_msb.ctz(@bitSizeOf(Limb) * 2 + 1));

    const limb_max: std.math.big.int.Const = .{
        .limbs = &.{maxInt(Limb)},
        .positive = true,
    };
    try testing.expectEqual(0, limb_max.ctz(@bitSizeOf(Limb)));
    try testing.expectEqual(0, limb_max.ctz(@bitSizeOf(Limb) + 1));
    try testing.expectEqual(0, limb_max.ctz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(0, limb_max.ctz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(0, limb_max.ctz(@bitSizeOf(Limb) * 2 + 1));

    const limb_msb_squared: std.math.big.int.Const = .{
        .limbs = &.{ 0, 1 << @bitSizeOf(Limb) - 2 },
        .positive = true,
    };
    try testing.expectEqual(@bitSizeOf(Limb) * 2 - 2, limb_msb_squared.ctz(@bitSizeOf(Limb) * 2 - 1));
    try testing.expectEqual(@bitSizeOf(Limb) * 2 - 2, limb_msb_squared.ctz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(@bitSizeOf(Limb) * 2 - 2, limb_msb_squared.ctz(@bitSizeOf(Limb) * 2 + 1));

    const limb_max_squared_minus_one: std.math.big.int.Const = .{
        .limbs = &.{ 0, maxInt(Limb) - 1 },
        .positive = true,
    };
    try testing.expectEqual(@bitSizeOf(Limb) + 1, limb_max_squared_minus_one.ctz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(@bitSizeOf(Limb) + 1, limb_max_squared_minus_one.ctz(@bitSizeOf(Limb) * 2 + 1));

    const limb_max_squared: std.math.big.int.Const = .{
        .limbs = &.{ 1, maxInt(Limb) - 1 },
        .positive = true,
    };
    try testing.expectEqual(0, limb_max_squared.ctz(@bitSizeOf(Limb) * 2));
    try testing.expectEqual(0, limb_max_squared.ctz(@bitSizeOf(Limb) * 2 + 1));
}
const std = @import("../../std.zig");
const builtin = @import("builtin");
const math = std.math;
const Limb = std.math.big.Limb;
const limb_bits = @typeInfo(Limb).int.bits;
const HalfLimb = std.math.big.HalfLimb;
const half_limb_bits = @typeInfo(HalfLimb).int.bits;
const DoubleLimb = std.math.big.DoubleLimb;
const SignedDoubleLimb = std.math.big.SignedDoubleLimb;
const Log2Limb = std.math.big.Log2Limb;
const Allocator = std.mem.Allocator;
const mem = std.mem;
const maxInt = std.math.maxInt;
const minInt = std.math.minInt;
const assert = std.debug.assert;
const Endian = std.builtin.Endian;
const Signedness = std.builtin.Signedness;
const native_endian = builtin.cpu.arch.endian();

/// Returns the number of limbs needed to store `scalar`, which must be a
/// primitive integer value.
/// Note: A comptime-known upper bound of this value that may be used
/// instead if `scalar` is not already comptime-known is
/// `calcTwosCompLimbCount(@typeInfo(@TypeOf(scalar)).int.bits)`
pub fn calcLimbLen(scalar: anytype) usize {
    if (scalar == 0) {
        return 1;
    }

    const w_value = @abs(scalar);
    return @as(usize, @intCast(@divFloor(@as(Limb, @intCast(math.log2(w_value))), limb_bits) + 1));
}

pub fn calcToStringLimbsBufferLen(a_len: usize, base: u8) usize {
    if (math.isPowerOfTwo(base))
        return 0;
    return a_len + 2 + a_len + calcDivLimbsBufferLen(a_len, 1);
}

pub fn calcDivLimbsBufferLen(a_len: usize, b_len: usize) usize {
    return a_len + b_len + 4;
}

pub fn calcMulLimbsBufferLen(a_len: usize, b_len: usize, aliases: usize) usize {
    return aliases * @max(a_len, b_len);
}

pub fn calcMulWrapLimbsBufferLen(bit_count: usize, a_len: usize, b_len: usize, aliases: usize) usize {
    const req_limbs = calcTwosCompLimbCount(bit_count);
    return aliases * @min(req_limbs, @max(a_len, b_len));
}

pub fn calcSetStringLimbsBufferLen(base: u8, string_len: usize) usize {
    const limb_count = calcSetStringLimbCount(base, string_len);
    return calcMulLimbsBufferLen(limb_count, limb_count, 2);
}

/// Assumes `string_len` doesn't account for minus signs if the number is negative.
pub fn calcSetStringLimbCount(base: u8, string_len: usize) usize {
    const base_f: f32 = @floatFromInt(base);
    const string_len_f: f32 = @floatFromInt(string_len);
    return 1 + @as(usize, @intFromFloat(@ceil(string_len_f * std.math.log2(base_f) / limb_bits)));
}

pub fn calcPowLimbsBufferLen(a_bit_count: usize, y: usize) usize {
    // The 2 accounts for the minimum space requirement for llmulacc
    return 2 + (a_bit_count * y + (limb_bits - 1)) / limb_bits;
}

pub fn calcSqrtLimbsBufferLen(a_bit_count: usize) usize {
    const a_limb_count = (a_bit_count - 1) / limb_bits + 1;
    const shift = (a_bit_count + 1) / 2;
    const u_s_rem_limb_count = 1 + ((shift / limb_bits) + 1);
    return a_limb_count + 3 * u_s_rem_limb_count + calcDivLimbsBufferLen(a_limb_count, u_s_rem_limb_count);
}

/// Compute the number of limbs required to store a 2s-complement number of `bit_count` bits.
pub fn calcNonZeroTwosCompLimbCount(bit_count: usize) usize {
    assert(bit_count != 0);
    return calcTwosCompLimbCount(bit_count);
}

/// Compute the number of limbs required to store a 2s-complement number of `bit_count` bits.
///
/// Special cases `bit_count == 0` to return 1. Zero-bit integers can only store the value zero
/// and this big integer implementation stores zero using one limb.
pub fn calcTwosCompLimbCount(bit_count: usize) usize {
    return @max(std.math.divCeil(usize, bit_count, @bitSizeOf(Limb)) catch unreachable, 1);
}

/// a + b * c + *carry, sets carry to the overflow bits
pub fn addMulLimbWithCarry(a: Limb, b: Limb, c: Limb, carry: *Limb) Limb {
    // ov1[0] = a + *carry
    const ov1 = @addWithOverflow(a, carry.*);

    // r2 = b * c
    const bc = @as(DoubleLimb, math.mulWide(Limb, b, c));
    const r2 = @as(Limb, @truncate(bc));
    const c2 = @as(Limb, @truncate(bc >> limb_bits));

    // ov2[0] = ov1[0] + r2
    const ov2 = @addWithOverflow(ov1[0], r2);

    // This never overflows, c1, c3 are either 0 or 1 and if both are 1 then
    // c2 is at least <= maxInt(Limb) - 2.
    carry.* = ov1[1] + c2 + ov2[1];

    return ov2[0];
}

/// a - b * c - *carry, sets carry to the overflow bits
fn subMulLimbWithBorrow(a: Limb, b: Limb, c: Limb, carry: *Limb) Limb {
    // ov1[0] = a - *carry
    const ov1 = @subWithOverflow(a, carry.*);

    // r2 = b * c
    const bc = @as(DoubleLimb, std.math.mulWide(Limb, b, c));
    const r2 = @as(Limb, @truncate(bc));
    const c2 = @as(Limb, @truncate(bc >> limb_bits));

    // ov2[0] = ov1[0] - r2
    const ov2 = @subWithOverflow(ov1[0], r2);
    carry.* = ov1[1] + c2 + ov2[1];

    return ov2[0];
}

/// Used to indicate either limit of a 2s-complement integer.
pub const TwosCompIntLimit = enum {
    // The low limit, either 0x00 (unsigned) or (-)0x80 (signed) for an 8-bit integer.
    min,

    // The high limit, either 0xFF (unsigned) or 0x7F (signed) for an 8-bit integer.
    max,
};

/// A arbitrary-precision big integer, with a fixed set of mutable limbs.
pub const Mutable = struct {
    /// Raw digits. These are:
    ///
    /// * Little-endian ordered
    /// * limbs.len >= 1
    /// * Zero is represented as limbs.len == 1 with limbs[0] == 0.
    ///
    /// Accessing limbs directly should be avoided.
    /// These are allocated limbs; the `len` field tells the valid range.
    limbs: []Limb,
    len: usize,
    positive: bool,

    pub fn toConst(self: Mutable) Const {
        return .{
            .limbs = self.limbs[0..self.len],
            .positive = self.positive,
        };
    }

    /// Returns true if `a == 0`.
    pub fn eqlZero(self: Mutable) bool {
        return self.toConst().eqlZero();
    }

    /// Asserts that the allocator owns the limbs memory. If this is not the case,
    /// use `toConst().toManaged()`.
    pub fn toManaged(self: Mutable, allocator: Allocator) Managed {
        return .{
            .allocator = allocator,
            .limbs = self.limbs,
            .metadata = if (self.positive)
                self.len & ~Managed.sign_bit
            else
                self.len | Managed.sign_bit,
        };
    }

    /// `value` is a primitive integer type.
    /// Asserts the value fits within the provided `limbs_buffer`.
    /// Note: `calcLimbLen` can be used to figure out how big an array to allocate for `limbs_buffer`.
    pub fn init(limbs_buffer: []Limb, value: anytype) Mutable {
        limbs_buffer[0] = 0;
        var self: Mutable = .{
            .limbs = limbs_buffer,
            .len = 1,
            .positive = true,
        };
        self.set(value);
        return self;
    }

    /// Copies the value of a Const to an existing Mutable so that they both have the same value.
    /// Asserts the value fits in the limbs buffer.
    pub fn copy(self: *Mutable, other: Const) void {
        if (self.limbs.ptr != other.limbs.ptr) {
            @memcpy(self.limbs[0..other.limbs.len], other.limbs[0..other.limbs.len]);
        }
        // Normalize before setting `positive` so the `eqlZero` doesn't need to iterate
        // over the extra zero limbs.
        self.normalize(other.limbs.len);
        self.positive = other.positive or other.eqlZero();
    }

    /// Efficiently swap an Mutable with another. This swaps the limb pointers and a full copy is not
    /// performed. The address of the limbs field will not be the same after this function.
    pub fn swap(self: *Mutable, other: *Mutable) void {
        mem.swap(Mutable, self, other);
    }

    pub fn dump(self: Mutable) void {
        for (self.limbs[0..self.len]) |limb| {
            std.debug.print("{x} ", .{limb});
        }
        std.debug.print("len={} capacity={} positive={}\n", .{ self.len, self.limbs.len, self.positive });
    }

    /// Clones an Mutable and returns a new Mutable with the same value. The new Mutable is a deep copy and
    /// can be modified separately from the original.
    /// Asserts that limbs is big enough to store the value.
    pub fn clone(other: Mutable, limbs: []Limb) Mutable {
        @memcpy(limbs[0..other.len], other.limbs[0..other.len]);
        return .{
            .limbs = limbs,
            .len = other.len,
            .positive = other.positive,
        };
    }

    pub fn negate(self: *Mutable) void {
        self.positive = !self.positive;
    }

    /// Modify to become the absolute value
    pub fn abs(self: *Mutable) void {
        self.positive = true;
    }

    /// Sets the Mutable to value. Value must be an primitive integer type.
    /// Asserts the value fits within the limbs buffer.
    /// Note: `calcLimbLen` can be used to figure out how big the limbs buffer
    /// needs to be to store a specific value.
    pub fn set(self: *Mutable, value: anytype) void {
        const T = @TypeOf(value);
        const needed_limbs = calcLimbLen(value);
        assert(needed_limbs <= self.limbs.len); // value too big

        self.len = needed_limbs;
        self.positive = value >= 0;

        switch (@typeInfo(T)) {
            .int => |info| {
                var w_value = @abs(value);

                if (info.bits <= limb_bits) {
                    self.limbs[0] = w_value;
                } else {
                    var i: usize = 0;
                    while (true) : (i += 1) {
                        self.limbs[i] = @as(Limb, @truncate(w_value));
                        w_value >>= limb_bits;

                        if (w_value == 0) break;
                    }
                }
            },
            .comptime_int => {
                comptime var w_value = @abs(value);

                if (w_value <= maxInt(Limb)) {
                    self.limbs[0] = w_value;
                } else {
                    const mask = (1 << limb_bits) - 1;

                    comptime var i = 0;
                    inline while (true) : (i += 1) {
                        self.limbs[i] = w_value & mask;
                        w_value >>= limb_bits;

                        if (w_value == 0) break;
                    }
                }
            },
            else => @compileError("cannot set Mutable using type " ++ @typeName(T)),
        }
    }

    /// Set self from the string representation `value`.
    ///
    /// `value` must contain only digits <= `base` and is case insensitive.  Base prefixes are
    /// not allowed (e.g. 0x43 should simply be 43).  Underscores in the input string are
    /// ignored and can be used as digit separators.
    ///
    /// Asserts there is enough memory for the value in `self.limbs`. An upper bound on number of limbs can
    /// be determined with `calcSetStringLimbCount`.
    /// Asserts the base is in the range [2, 36].
    ///
    /// Returns an error if the value has invalid digits for the requested base.
    ///
    /// `limbs_buffer` is used for temporary storage. The size required can be found with
    /// `calcSetStringLimbsBufferLen`.
    ///
    /// If `allocator` is provided, it will be used for temporary storage to improve
    /// multiplication performance. `error.OutOfMemory` is handled with a fallback algorithm.
    pub fn setString(
        self: *Mutable,
        base: u8,
        value: []const u8,
        limbs_buffer: []Limb,
        allocator: ?Allocator,
    ) error{InvalidCharacter}!void {
        assert(base >= 2);
        assert(base <= 36);

        var i: usize = 0;
        var positive = true;
        if (value.len > 0 and value[0] == '-') {
            positive = false;
            i += 1;
        }

        const ap_base: Const = .{ .limbs = &[_]Limb{base}, .positive = true };
        self.set(0);

        for (value[i..]) |ch| {
            if (ch == '_') {
                continue;
            }
            const d = try std.fmt.charToDigit(ch, base);
            const ap_d: Const = .{ .limbs = &[_]Limb{d}, .positive = true };

            self.mul(self.toConst(), ap_base, limbs_buffer, allocator);
            self.add(self.toConst(), ap_d);
        }
        self.positive = positive;
    }

    /// Set self to either bound of a 2s-complement integer.
    /// Note: The result is still sign-magnitude, not twos complement! In order to convert the
    /// result to twos complement, it is sufficient to take the absolute value.
    ///
    /// Asserts the result fits in `r`. An upper bound on the number of limbs needed by
    /// r is `calcTwosCompLimbCount(bit_count)`.
    pub fn setTwosCompIntLimit(
        r: *Mutable,
        limit: TwosCompIntLimit,
        signedness: Signedness,
        bit_count: usize,
    ) void {
        // Handle zero-bit types.
        if (bit_count == 0) {
            r.set(0);
            return;
        }

        const req_limbs = calcTwosCompLimbCount(bit_count);
        const bit: Log2Limb = @truncate(bit_count - 1);
        const signmask = @as(Limb, 1) << bit; // 0b0..010..0 where 1 is the sign bit.
        const mask = (signmask << 1) -% 1; // 0b0..011..1 where the leftmost 1 is the sign bit.

        r.positive = true;

        switch (signedness) {
            .signed => switch (limit) {
                .min => {
                    // Negative bound, signed = -0x80.
                    r.len = req_limbs;
                    @memset(r.limbs[0 .. r.len - 1], 0);
                    r.limbs[r.len - 1] = signmask;
                    r.positive = false;
                },
                .max => {
                    // Positive bound, signed = 0x7F
                    // Note, in this branch we need to normalize because the first bit is
                    // supposed to be 0.

                    // Special case for 1-bit integers.
                    if (bit_count == 1) {
                        r.set(0);
                    } else {
                        const new_req_limbs = calcTwosCompLimbCount(bit_count - 1);
                        const msb = @as(Log2Limb, @truncate(bit_count - 2));
                        const new_signmask = @as(Limb, 1) << msb; // 0b0..010..0 where 1 is the sign bit.
                        const new_mask = (new_signmask << 1) -% 1; // 0b0..001..1 where the rightmost 0 is the sign bit.

                        r.len = new_req_limbs;
                        @memset(r.limbs[0 .. r.len - 1], maxInt(Limb));
                        r.limbs[r.len - 1] = new_mask;
                    }
                },
            },
            .unsigned => switch (limit) {
                .min => {
                    // Min bound, unsigned = 0x00
                    r.set(0);
                },
                .max => {
                    // Max bound, unsigned = 0xFF
                    r.len = req_limbs;
                    @memset(r.limbs[0 .. r.len - 1], maxInt(Limb));
                    r.limbs[r.len - 1] = mask;
                },
            },
        }
    }

    /// r = a + scalar
    ///
    /// r and a may be aliases.
    /// scalar is a primitive integer type.
    ///
    /// Asserts the result fits in `r`. An upper bound on the number of limbs needed by
    /// r is `@max(a.limbs.len, calcLimbLen(scalar)) + 1`.
    pub fn addScalar(r: *Mutable, a: Const, scalar: anytype) void {
        // Normally we could just determine the number of limbs needed with calcLimbLen,
        // but that is not comptime-known when scalar is not a comptime_int.  Instead, we
        // use calcTwosCompLimbCount for a non-comptime_int scalar, which can be pessimistic
        // in the case that scalar happens to be small in magnitude within its type, but it
        // is well worth being able to use the stack and not needing an allocator passed in.
        // Note that Mutable.init still sets len to calcLimbLen(scalar) in any case.
        const limb_len = comptime switch (@typeInfo(@TypeOf(scalar))) {
            .comptime_int => calcLimbLen(scalar),
            .int => |info| calcTwosCompLimbCount(info.bits),
            else => @compileError("expected scalar to be an int"),
        };
        var limbs: [limb_len]Limb = undefined;
        const operand = init(&limbs, scalar).toConst();
        return add(r, a, operand);
    }

    /// Base implementation for addition. Adds `@max(a.limbs.len, b.limbs.len)` elements from a and b,
    /// and returns whether any overflow occurred.
    /// r, a and b may be aliases.
    ///
    /// Asserts r has enough elements to hold the result. The upper bound is `@max(a.limbs.len, b.limbs.len)`.
    fn addCarry(r: *Mutable, a: Const, b: Const) bool {
        if (a.eqlZero()) {
            r.copy(b);
            return false;
        } else if (b.eqlZero()) {
            r.copy(a);
            return false;
        } else if (a.positive != b.positive) {
            if (a.positive) {
                // (a) + (-b) => a - b
                return r.subCarry(a, b.abs());
            } else {
                // (-a) + (b) => b - a
                return r.subCarry(b, a.abs());
            }
        } else {
            r.positive = a.positive;
            if (a.limbs.len >= b.limbs.len) {
                const c = lladdcarry(r.limbs, a.limbs, b.limbs);
                r.normalize(a.limbs.len);
                return c != 0;
            } else {
                const c = lladdcarry(r.limbs, b.limbs, a.limbs);
                r.normalize(b.limbs.len);
                return c != 0;
            }
        }
    }

    /// r = a + b
    ///
    /// r, a and b may be aliases.
    ///
    /// Asserts the result fits in `r`. An upper bound on the number of limbs needed by
    /// r is `@max(a.limbs.len, b.limbs.len) + 1`.
    pub fn add(r: *Mutable, a: Const, b: Const) void {
        if (r.addCarry(a, b)) {
            // Fix up the result. Note that addCarry normalizes by a.limbs.len or b.limbs.len,
            // so we need to set the length here.
            const msl = @max(a.limbs.len, b.limbs.len);
            // `[add|sub]Carry` normalizes by `msl`, so we need to fix up the result manually here.
            // Note, the fact that it normalized means that the intermediary limbs are zero here.
            r.len = msl + 1;
            r.limbs[msl] = 1; // If this panics, there wasn't enough space in `r`.
        }
    }

    /// r = a + b with 2s-complement wrapping semantics. Returns whether overflow occurred.
    /// r, a and b may be aliases
    ///
    /// Asserts the result fits in `r`. An upper bound on the number of limbs needed by
    /// r is `calcTwosCompLimbCount(bit_count)`.
    pub fn addWrap(r: *Mutable, a: Const, b: Const, signedness: Signedness, bit_count: usize) bool {
        const req_limbs = calcTwosCompLimbCount(bit_count);

        // Slice of the upper bits if they exist, these will be ignored and allows us to use addCarry to determine
        // if an overflow occurred.
        const x = Const{
            .positive = a.positive,
            .limbs = a.limbs[0..@min(req_limbs, a.limbs.len)],
        };

        const y = Const{
            .positive = b.positive,
            .limbs = b.limbs[0..@min(req_limbs, b.limbs.len)],
        };

        var carry_truncated = false;
        if (r.addCarry(x, y)) {
            // There are two possibilities here:
            // - We overflowed req_limbs. In this case, the carry is ignored, as it would be removed by
            //   truncate anyway.
            // - a and b had less elements than req_limbs, and those were overflowed. This case needs to be handled.
            //   Note: after this we still might need to wrap.
            const msl = @max(a.limbs.len, b.limbs.len);
            if (msl < req_limbs) {
                r.limbs[msl] = 1;
                r.len = req_limbs;
                @memset(r.limbs[msl + 1 .. req_limbs], 0);
            } else {
                carry_truncated = true;
            }
        }

        if (!r.toConst().fitsInTwosComp(signedness, bit_count)) {
            r.truncate(r.toConst(), signedness, bit_count);
            return true;
        }

        return carry_truncated;
    }

    /// r = a + b with 2s-complement saturating semantics.
    /// r, a and b may be aliases.
    ///
    /// Assets the result fits in `r`. Upper bound on the number of limbs needed by
    /// r is `calcTwosCompLimbCount(bit_count)`.
    pub fn addSat(r: *Mutable, a: Const, b: Const, signedness: Signedness, bit_count: usize) void {
        const req_limbs = calcTwosCompLimbCount(bit_count);

        // Slice of the upper bits if they exist, these will be ignored and allows us to use addCarry to determine
        // if an overflow occurred.
        const x = Const{
            .positive = a.positive,
            .limbs = a.limbs[0..@min(req_limbs, a.limbs.len)],
        };

        const y = Const{
            .positive = b.positive,
            .limbs = b.limbs[0..@min(req_limbs, b.limbs.len)],
        };

        if (r.addCarry(x, y)) {
            // There are two possibilities here:
            // - We overflowed req_limbs, in which case we need to saturate.
            // - a and b had less elements than req_limbs, and those were overflowed.
            //   Note: In this case, might _also_ need to saturate.
            const msl = @max(a.limbs.len, b.limbs.len);
            if (msl < req_limbs) {
                r.limbs[msl] = 1;
                r.len = req_limbs;
                // Note: Saturation may still be required if msl == req_limbs - 1
            } else {
                // Overflowed req_limbs, definitely saturate.
                r.setTwosCompIntLimit(if (r.positive) .max else .min, signedness, bit_count);
            }
        }

        // Saturate if the result didn't fit.
        r.saturate(r.toConst(), signedness, bit_count);
    }

    /// Base implementation for subtraction. Subtracts `@max(a.limbs.len, b.limbs.len)` elements from a and b,
    /// and returns whether any overflow occurred.
    /// r, a and b may be aliases.
    ///
    /// Asserts r has enough elements to hold the result. The upper bound is `@max(a.limbs.len, b.limbs.len)`.
    fn subCarry(r: *Mutable, a: Const, b: Const) bool {
        if (a.eqlZero()) {
            r.copy(b);
            r.positive = !b.positive;
            return false;
        } else if (b.eqlZero()) {
            r.copy(a);
            return false;
        } else if (a.positive != b.positive) {
            if (a.po```
