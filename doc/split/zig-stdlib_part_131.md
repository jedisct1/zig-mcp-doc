```
           },
        },
        .{
            "@divExact",
            .{
                .tag = .div_exact,
                .param_count = 2,
            },
        },
        .{
            "@divFloor",
            .{
                .tag = .div_floor,
                .param_count = 2,
            },
        },
        .{
            "@divTrunc",
            .{
                .tag = .div_trunc,
                .param_count = 2,
            },
        },
        .{
            "@embedFile",
            .{
                .tag = .embed_file,
                .param_count = 1,
            },
        },
        .{
            "@intFromEnum",
            .{
                .tag = .int_from_enum,
                .param_count = 1,
            },
        },
        .{
            "@errorName",
            .{
                .tag = .error_name,
                .param_count = 1,
            },
        },
        .{
            "@errorReturnTrace",
            .{
                .tag = .error_return_trace,
                .param_count = 0,
            },
        },
        .{
            "@intFromError",
            .{
                .tag = .int_from_error,
                .param_count = 1,
            },
        },
        .{
            "@errorCast",
            .{
                .tag = .error_cast,
                .eval_to_error = .maybe,
                .param_count = 1,
            },
        },
        .{
            "@export",
            .{
                .tag = .@"export",
                .param_count = 2,
            },
        },
        .{
            "@extern",
            .{
                .tag = .@"extern",
                .param_count = 2,
            },
        },
        .{
            "@field",
            .{
                .tag = .field,
                .eval_to_error = .maybe,
                .param_count = 2,
                .allows_lvalue = true,
            },
        },
        .{
            "@fieldParentPtr",
            .{
                .tag = .field_parent_ptr,
                .param_count = 2,
            },
        },
        .{
            "@FieldType",
            .{
                .tag = .FieldType,
                .param_count = 2,
            },
        },
        .{
            "@floatCast",
            .{
                .tag = .float_cast,
                .param_count = 1,
            },
        },
        .{
            "@intFromFloat",
            .{
                .tag = .int_from_float,
                .param_count = 1,
            },
        },
        .{
            "@frame",
            .{
                .tag = .frame,
                .param_count = 0,
            },
        },
        .{
            "@Frame",
            .{
                .tag = .Frame,
                .param_count = 1,
            },
        },
        .{
            "@frameAddress",
            .{
                .tag = .frame_address,
                .param_count = 0,
                .illegal_outside_function = true,
            },
        },
        .{
            "@frameSize",
            .{
                .tag = .frame_size,
                .param_count = 1,
            },
        },
        .{
            "@hasDecl",
            .{
                .tag = .has_decl,
                .param_count = 2,
            },
        },
        .{
            "@hasField",
            .{
                .tag = .has_field,
                .param_count = 2,
            },
        },
        .{
            "@import",
            .{
                .tag = .import,
                .param_count = 1,
            },
        },
        .{
            "@inComptime",
            .{
                .tag = .in_comptime,
                .param_count = 0,
            },
        },
        .{
            "@intCast",
            .{
                .tag = .int_cast,
                .param_count = 1,
            },
        },
        .{
            "@enumFromInt",
            .{
                .tag = .enum_from_int,
                .param_count = 1,
            },
        },
        .{
            "@errorFromInt",
            .{
                .tag = .error_from_int,
                .eval_to_error = .always,
                .param_count = 1,
            },
        },
        .{
            "@floatFromInt",
            .{
                .tag = .float_from_int,
                .param_count = 1,
            },
        },
        .{
            "@ptrFromInt",
            .{
                .tag = .ptr_from_int,
                .param_count = 1,
            },
        },
        .{
            "@max",
            .{
                .tag = .max,
                .param_count = null,
            },
        },
        .{
            "@memcpy",
            .{
                .tag = .memcpy,
                .param_count = 2,
            },
        },
        .{
            "@memset",
            .{
                .tag = .memset,
                .param_count = 2,
            },
        },
        .{
            "@memmove",
            .{
                .tag = .memmove,
                .param_count = 2,
            },
        },
        .{
            "@min",
            .{
                .tag = .min,
                .param_count = null,
            },
        },
        .{
            "@wasmMemorySize",
            .{
                .tag = .wasm_memory_size,
                .param_count = 1,
            },
        },
        .{
            "@wasmMemoryGrow",
            .{
                .tag = .wasm_memory_grow,
                .param_count = 2,
            },
        },
        .{
            "@mod",
            .{
                .tag = .mod,
                .param_count = 2,
            },
        },
        .{
            "@mulWithOverflow",
            .{
                .tag = .mul_with_overflow,
                .param_count = 2,
            },
        },
        .{
            "@panic",
            .{
                .tag = .panic,
                .param_count = 1,
            },
        },
        .{
            "@popCount",
            .{
                .tag = .pop_count,
                .param_count = 1,
            },
        },
        .{
            "@prefetch",
            .{
                .tag = .prefetch,
                .param_count = 2,
            },
        },
        .{
            "@ptrCast",
            .{
                .tag = .ptr_cast,
                .param_count = 1,
            },
        },
        .{
            "@intFromPtr",
            .{
                .tag = .int_from_ptr,
                .param_count = 1,
            },
        },
        .{
            "@rem",
            .{
                .tag = .rem,
                .param_count = 2,
            },
        },
        .{
            "@returnAddress",
            .{
                .tag = .return_address,
                .param_count = 0,
                .illegal_outside_function = true,
            },
        },
        .{
            "@select",
            .{
                .tag = .select,
                .param_count = 4,
            },
        },
        .{
            "@setEvalBranchQuota",
            .{
                .tag = .set_eval_branch_quota,
                .param_count = 1,
            },
        },
        .{
            "@setFloatMode",
            .{
                .tag = .set_float_mode,
                .param_count = 1,
            },
        },
        .{
            "@setRuntimeSafety",
            .{
                .tag = .set_runtime_safety,
                .param_count = 1,
            },
        },
        .{
            "@shlExact",
            .{
                .tag = .shl_exact,
                .param_count = 2,
            },
        },
        .{
            "@shlWithOverflow",
            .{
                .tag = .shl_with_overflow,
                .param_count = 2,
            },
        },
        .{
            "@shrExact",
            .{
                .tag = .shr_exact,
                .param_count = 2,
            },
        },
        .{
            "@shuffle",
            .{
                .tag = .shuffle,
                .param_count = 4,
            },
        },
        .{
            "@sizeOf",
            .{
                .tag = .size_of,
                .param_count = 1,
            },
        },
        .{
            "@splat",
            .{
                .tag = .splat,
                .param_count = 1,
            },
        },
        .{
            "@reduce",
            .{
                .tag = .reduce,
                .param_count = 2,
            },
        },
        .{
            "@src",
            .{
                .tag = .src,
                .param_count = 0,
                .illegal_outside_function = true,
            },
        },
        .{
            "@sqrt",
            .{
                .tag = .sqrt,
                .param_count = 1,
            },
        },
        .{
            "@sin",
            .{
                .tag = .sin,
                .param_count = 1,
            },
        },
        .{
            "@cos",
            .{
                .tag = .cos,
                .param_count = 1,
            },
        },
        .{
            "@tan",
            .{
                .tag = .tan,
                .param_count = 1,
            },
        },
        .{
            "@exp",
            .{
                .tag = .exp,
                .param_count = 1,
            },
        },
        .{
            "@exp2",
            .{
                .tag = .exp2,
                .param_count = 1,
            },
        },
        .{
            "@log",
            .{
                .tag = .log,
                .param_count = 1,
            },
        },
        .{
            "@log2",
            .{
                .tag = .log2,
                .param_count = 1,
            },
        },
        .{
            "@log10",
            .{
                .tag = .log10,
                .param_count = 1,
            },
        },
        .{
            "@abs",
            .{
                .tag = .abs,
                .param_count = 1,
            },
        },
        .{
            "@floor",
            .{
                .tag = .floor,
                .param_count = 1,
            },
        },
        .{
            "@ceil",
            .{
                .tag = .ceil,
                .param_count = 1,
            },
        },
        .{
            "@trunc",
            .{
                .tag = .trunc,
                .param_count = 1,
            },
        },
        .{
            "@round",
            .{
                .tag = .round,
                .param_count = 1,
            },
        },
        .{
            "@subWithOverflow",
            .{
                .tag = .sub_with_overflow,
                .param_count = 2,
            },
        },
        .{
            "@tagName",
            .{
                .tag = .tag_name,
                .param_count = 1,
            },
        },
        .{
            "@This",
            .{
                .tag = .This,
                .param_count = 0,
            },
        },
        .{
            "@trap",
            .{
                .tag = .trap,
                .param_count = 0,
            },
        },
        .{
            "@truncate",
            .{
                .tag = .truncate,
                .param_count = 1,
            },
        },
        .{
            "@Type",
            .{
                .tag = .Type,
                .param_count = 1,
            },
        },
        .{
            "@typeInfo",
            .{
                .tag = .type_info,
                .param_count = 1,
            },
        },
        .{
            "@typeName",
            .{
                .tag = .type_name,
                .param_count = 1,
            },
        },
        .{
            "@TypeOf",
            .{
                .tag = .TypeOf,
                .param_count = null,
            },
        },
        .{
            "@unionInit",
            .{
                .tag = .union_init,
                .param_count = 3,
            },
        },
        .{
            "@Vector",
            .{
                .tag = .Vector,
                .param_count = 2,
            },
        },
        .{
            "@volatileCast",
            .{
                .tag = .volatile_cast,
                .param_count = 1,
            },
        },
        .{
            "@workItemId", .{
                .tag = .work_item_id,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
        .{
            "@workGroupSize",
            .{
                .tag = .work_group_size,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
        .{
            "@workGroupId",
            .{
                .tag = .work_group_id,
                .param_count = 1,
                .illegal_outside_function = true,
            },
        },
    });
};

const std = @import("std");
const BuiltinFn = @This();
const std = @import("std");

pub inline fn __builtin_bswap16(val: u16) u16 {
    return @byteSwap(val);
}
pub inline fn __builtin_bswap32(val: u32) u32 {
    return @byteSwap(val);
}
pub inline fn __builtin_bswap64(val: u64) u64 {
    return @byteSwap(val);
}

pub inline fn __builtin_signbit(val: f64) c_int {
    return @intFromBool(std.math.signbit(val));
}
pub inline fn __builtin_signbitf(val: f32) c_int {
    return @intFromBool(std.math.signbit(val));
}

pub inline fn __builtin_popcount(val: c_uint) c_int {
    // popcount of a c_uint will never exceed the capacity of a c_int
    @setRuntimeSafety(false);
    return @as(c_int, @bitCast(@as(c_uint, @popCount(val))));
}
pub inline fn __builtin_ctz(val: c_uint) c_int {
    // Returns the number of trailing 0-bits in val, starting at the least significant bit position.
    // In C if `val` is 0, the result is undefined; in zig it's the number of bits in a c_uint
    @setRuntimeSafety(false);
    return @as(c_int, @bitCast(@as(c_uint, @ctz(val))));
}
pub inline fn __builtin_clz(val: c_uint) c_int {
    // Returns the number of leading 0-bits in x, starting at the most significant bit position.
    // In C if `val` is 0, the result is undefined; in zig it's the number of bits in a c_uint
    @setRuntimeSafety(false);
    return @as(c_int, @bitCast(@as(c_uint, @clz(val))));
}

pub inline fn __builtin_sqrt(val: f64) f64 {
    return @sqrt(val);
}
pub inline fn __builtin_sqrtf(val: f32) f32 {
    return @sqrt(val);
}

pub inline fn __builtin_sin(val: f64) f64 {
    return @sin(val);
}
pub inline fn __builtin_sinf(val: f32) f32 {
    return @sin(val);
}
pub inline fn __builtin_cos(val: f64) f64 {
    return @cos(val);
}
pub inline fn __builtin_cosf(val: f32) f32 {
    return @cos(val);
}

pub inline fn __builtin_exp(val: f64) f64 {
    return @exp(val);
}
pub inline fn __builtin_expf(val: f32) f32 {
    return @exp(val);
}
pub inline fn __builtin_exp2(val: f64) f64 {
    return @exp2(val);
}
pub inline fn __builtin_exp2f(val: f32) f32 {
    return @exp2(val);
}
pub inline fn __builtin_log(val: f64) f64 {
    return @log(val);
}
pub inline fn __builtin_logf(val: f32) f32 {
    return @log(val);
}
pub inline fn __builtin_log2(val: f64) f64 {
    return @log2(val);
}
pub inline fn __builtin_log2f(val: f32) f32 {
    return @log2(val);
}
pub inline fn __builtin_log10(val: f64) f64 {
    return @log10(val);
}
pub inline fn __builtin_log10f(val: f32) f32 {
    return @log10(val);
}

// Standard C Library bug: The absolute value of the most negative integer remains negative.
pub inline fn __builtin_abs(val: c_int) c_int {
    return if (val == std.math.minInt(c_int)) val else @intCast(@abs(val));
}
pub inline fn __builtin_labs(val: c_long) c_long {
    return if (val == std.math.minInt(c_long)) val else @intCast(@abs(val));
}
pub inline fn __builtin_llabs(val: c_longlong) c_longlong {
    return if (val == std.math.minInt(c_longlong)) val else @intCast(@abs(val));
}
pub inline fn __builtin_fabs(val: f64) f64 {
    return @abs(val);
}
pub inline fn __builtin_fabsf(val: f32) f32 {
    return @abs(val);
}

pub inline fn __builtin_floor(val: f64) f64 {
    return @floor(val);
}
pub inline fn __builtin_floorf(val: f32) f32 {
    return @floor(val);
}
pub inline fn __builtin_ceil(val: f64) f64 {
    return @ceil(val);
}
pub inline fn __builtin_ceilf(val: f32) f32 {
    return @ceil(val);
}
pub inline fn __builtin_trunc(val: f64) f64 {
    return @trunc(val);
}
pub inline fn __builtin_truncf(val: f32) f32 {
    return @trunc(val);
}
pub inline fn __builtin_round(val: f64) f64 {
    return @round(val);
}
pub inline fn __builtin_roundf(val: f32) f32 {
    return @round(val);
}

pub inline fn __builtin_strlen(s: [*c]const u8) usize {
    return std.mem.sliceTo(s, 0).len;
}
pub inline fn __builtin_strcmp(s1: [*c]const u8, s2: [*c]const u8) c_int {
    return switch (std.mem.orderZ(u8, s1, s2)) {
        .lt => -1,
        .eq => 0,
        .gt => 1,
    };
}

pub inline fn __builtin_object_size(ptr: ?*const anyopaque, ty: c_int) usize {
    _ = ptr;
    // clang semantics match gcc's: https://gcc.gnu.org/onlinedocs/gcc/Object-Size-Checking.html
    // If it is not possible to determine which objects ptr points to at compile time,
    // __builtin_object_size should return (size_t) -1 for type 0 or 1 and (size_t) 0
    // for type 2 or 3.
    if (ty == 0 or ty == 1) return @as(usize, @bitCast(-@as(isize, 1)));
    if (ty == 2 or ty == 3) return 0;
    unreachable;
}

pub inline fn __builtin___memset_chk(
    dst: ?*anyopaque,
    val: c_int,
    len: usize,
    remaining: usize,
) ?*anyopaque {
    if (len > remaining) @panic("std.c.builtins.memset_chk called with len > remaining");
    return __builtin_memset(dst, val, len);
}

pub inline fn __builtin_memset(dst: ?*anyopaque, val: c_int, len: usize) ?*anyopaque {
    const dst_cast = @as([*c]u8, @ptrCast(dst));
    @memset(dst_cast[0..len], @as(u8, @bitCast(@as(i8, @truncate(val)))));
    return dst;
}

pub inline fn __builtin___memcpy_chk(
    noalias dst: ?*anyopaque,
    noalias src: ?*const anyopaque,
    len: usize,
    remaining: usize,
) ?*anyopaque {
    if (len > remaining) @panic("std.c.builtins.memcpy_chk called with len > remaining");
    return __builtin_memcpy(dst, src, len);
}

pub inline fn __builtin_memcpy(
    noalias dst: ?*anyopaque,
    noalias src: ?*const anyopaque,
    len: usize,
) ?*anyopaque {
    if (len > 0) @memcpy(
        @as([*]u8, @ptrCast(dst.?))[0..len],
        @as([*]const u8, @ptrCast(src.?)),
    );
    return dst;
}

/// The return value of __builtin_expect is `expr`. `c` is the expected value
/// of `expr` and is used as a hint to the compiler in C. Here it is unused.
pub inline fn __builtin_expect(expr: c_long, c: c_long) c_long {
    _ = c;
    return expr;
}

/// returns a quiet NaN. Quiet NaNs have many representations; tagp is used to select one in an
/// implementation-defined way.
/// This implementation is based on the description for __builtin_nan provided in the GCC docs at
/// https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html#index-_005f_005fbuiltin_005fnan
/// Comment is reproduced below:
/// Since ISO C99 defines this function in terms of strtod, which we do not implement, a description
/// of the parsing is in order.
/// The string is parsed as by strtol; that is, the base is recognized by leading ‘0’ or ‘0x’ prefixes.
/// The number parsed is placed in the significand such that the least significant bit of the number is
///    at the least significant bit of the significand.
/// The number is truncated to fit the significand field provided.
/// The significand is forced to be a quiet NaN.
///
/// If tagp contains any non-numeric characters, the function returns a NaN whose significand is zero.
/// If tagp is empty, the function returns a NaN whose significand is zero.
pub inline fn __builtin_nanf(tagp: []const u8) f32 {
    const parsed = std.fmt.parseUnsigned(c_ulong, tagp, 0) catch 0;
    const bits: u23 = @truncate(parsed); // single-precision float trailing significand is 23 bits
    return @bitCast(@as(u32, bits) | @as(u32, @bitCast(std.math.nan(f32))));
}

pub inline fn __builtin_huge_valf() f32 {
    return std.math.inf(f32);
}

pub inline fn __builtin_inff() f32 {
    return std.math.inf(f32);
}

pub inline fn __builtin_isnan(x: anytype) c_int {
    return @intFromBool(std.math.isNan(x));
}

pub inline fn __builtin_isinf(x: anytype) c_int {
    return @intFromBool(std.math.isInf(x));
}

/// Similar to isinf, except the return value is -1 for an argument of -Inf and 1 for an argument of +Inf.
pub inline fn __builtin_isinf_sign(x: anytype) c_int {
    if (!std.math.isInf(x)) return 0;
    return if (std.math.isPositiveInf(x)) 1 else -1;
}

pub inline fn __has_builtin(func: anytype) c_int {
    _ = func;
    return @intFromBool(true);
}

pub inline fn __builtin_assume(cond: bool) void {
    if (!cond) unreachable;
}

pub inline fn __builtin_unreachable() noreturn {
    unreachable;
}

pub inline fn __builtin_constant_p(expr: anytype) c_int {
    _ = expr;
    return @intFromBool(false);
}
pub fn __builtin_mul_overflow(a: anytype, b: anytype, result: *@TypeOf(a, b)) c_int {
    const res = @mulWithOverflow(a, b);
    result.* = res[0];
    return res[1];
}

// __builtin_alloca_with_align is not currently implemented.
// It is used in a run-translated-c test and a test-translate-c test to ensure that non-implemented
// builtins are correctly demoted. If you implement __builtin_alloca_with_align, please update the
// run-translated-c test and the test-translate-c test to use a different non-implemented builtin.
// pub inline fn __builtin_alloca_with_align(size: usize, alignment: usize) *anyopaque {}
const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const math = std.math;
const mem = std.mem;

/// Given a type and value, cast the value to the type as c would.
pub fn cast(comptime DestType: type, target: anytype) DestType {
    // this function should behave like transCCast in translate-c, except it's for macros
    const SourceType = @TypeOf(target);
    switch (@typeInfo(DestType)) {
        .@"fn" => return castToPtr(*const DestType, SourceType, target),
        .pointer => return castToPtr(DestType, SourceType, target),
        .optional => |dest_opt| {
            if (@typeInfo(dest_opt.child) == .pointer) {
                return castToPtr(DestType, SourceType, target);
            } else if (@typeInfo(dest_opt.child) == .@"fn") {
                return castToPtr(?*const dest_opt.child, SourceType, target);
            }
        },
        .int => {
            switch (@typeInfo(SourceType)) {
                .pointer => {
                    return castInt(DestType, @intFromPtr(target));
                },
                .optional => |opt| {
                    if (@typeInfo(opt.child) == .pointer) {
                        return castInt(DestType, @intFromPtr(target));
                    }
                },
                .int => {
                    return castInt(DestType, target);
                },
                .@"fn" => {
                    return castInt(DestType, @intFromPtr(&target));
                },
                .bool => {
                    return @intFromBool(target);
                },
                else => {},
            }
        },
        .float => {
            switch (@typeInfo(SourceType)) {
                .int => return @as(DestType, @floatFromInt(target)),
                .float => return @as(DestType, @floatCast(target)),
                .bool => return @as(DestType, @floatFromInt(@intFromBool(target))),
                else => {},
            }
        },
        .@"union" => |info| {
            inline for (info.fields) |field| {
                if (field.type == SourceType) return @unionInit(DestType, field.name, target);
            }
            @compileError("cast to union type '" ++ @typeName(DestType) ++ "' from type '" ++ @typeName(SourceType) ++ "' which is not present in union");
        },
        .bool => return cast(usize, target) != 0,
        else => {},
    }
    return @as(DestType, target);
}

fn castInt(comptime DestType: type, target: anytype) DestType {
    const dest = @typeInfo(DestType).int;
    const source = @typeInfo(@TypeOf(target)).int;

    if (dest.bits < source.bits)
        return @as(DestType, @bitCast(@as(std.meta.Int(source.signedness, dest.bits), @truncate(target))))
    else
        return @as(DestType, @bitCast(@as(std.meta.Int(source.signedness, dest.bits), target)));
}

fn castPtr(comptime DestType: type, target: anytype) DestType {
    return @constCast(@volatileCast(@alignCast(@ptrCast(target))));
}

fn castToPtr(comptime DestType: type, comptime SourceType: type, target: anytype) DestType {
    switch (@typeInfo(SourceType)) {
        .int => {
            return @as(DestType, @ptrFromInt(castInt(usize, target)));
        },
        .comptime_int => {
            if (target < 0)
                return @as(DestType, @ptrFromInt(@as(usize, @bitCast(@as(isize, @intCast(target))))))
            else
                return @as(DestType, @ptrFromInt(@as(usize, @intCast(target))));
        },
        .pointer => {
            return castPtr(DestType, target);
        },
        .@"fn" => {
            return castPtr(DestType, &target);
        },
        .optional => |target_opt| {
            if (@typeInfo(target_opt.child) == .pointer) {
                return castPtr(DestType, target);
            }
        },
        else => {},
    }
    return @as(DestType, target);
}

fn ptrInfo(comptime PtrType: type) std.builtin.Type.Pointer {
    return switch (@typeInfo(PtrType)) {
        .optional => |opt_info| @typeInfo(opt_info.child).pointer,
        .pointer => |ptr_info| ptr_info,
        else => unreachable,
    };
}

test "cast" {
    var i = @as(i64, 10);

    try testing.expect(cast(*u8, 16) == @as(*u8, @ptrFromInt(16)));
    try testing.expect(cast(*u64, &i).* == @as(u64, 10));
    try testing.expect(cast(*i64, @as(?*align(1) i64, &i)) == &i);

    try testing.expect(cast(?*u8, 2) == @as(*u8, @ptrFromInt(2)));
    try testing.expect(cast(?*i64, @as(*align(1) i64, &i)) == &i);
    try testing.expect(cast(?*i64, @as(?*align(1) i64, &i)) == &i);

    try testing.expectEqual(@as(u32, 4), cast(u32, @as(*u32, @ptrFromInt(4))));
    try testing.expectEqual(@as(u32, 4), cast(u32, @as(?*u32, @ptrFromInt(4))));
    try testing.expectEqual(@as(u32, 10), cast(u32, @as(u64, 10)));

    try testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x8000_0000))), cast(i32, @as(u32, 0x8000_0000)));

    try testing.expectEqual(@as(*u8, @ptrFromInt(2)), cast(*u8, @as(*const u8, @ptrFromInt(2))));
    try testing.expectEqual(@as(*u8, @ptrFromInt(2)), cast(*u8, @as(*volatile u8, @ptrFromInt(2))));

    try testing.expectEqual(@as(?*anyopaque, @ptrFromInt(2)), cast(?*anyopaque, @as(*u8, @ptrFromInt(2))));

    var foo: c_int = -1;
    _ = &foo;
    try testing.expect(cast(*anyopaque, -1) == @as(*anyopaque, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))))));
    try testing.expect(cast(*anyopaque, foo) == @as(*anyopaque, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))))));
    try testing.expect(cast(?*anyopaque, -1) == @as(?*anyopaque, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))))));
    try testing.expect(cast(?*anyopaque, foo) == @as(?*anyopaque, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))))));

    const FnPtr = ?*align(1) const fn (*anyopaque) void;
    try testing.expect(cast(FnPtr, 0) == @as(FnPtr, @ptrFromInt(@as(usize, 0))));
    try testing.expect(cast(FnPtr, foo) == @as(FnPtr, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1))))));
}

/// Given a value returns its size as C's sizeof operator would.
pub fn sizeof(target: anytype) usize {
    const T: type = if (@TypeOf(target) == type) target else @TypeOf(target);
    switch (@typeInfo(T)) {
        .float, .int, .@"struct", .@"union", .array, .bool, .vector => return @sizeOf(T),
        .@"fn" => {
            // sizeof(main) in C returns 1
            return 1;
        },
        .null => return @sizeOf(*anyopaque),
        .void => {
            // Note: sizeof(void) is 1 on clang/gcc and 0 on MSVC.
            return 1;
        },
        .@"opaque" => {
            if (T == anyopaque) {
                // Note: sizeof(void) is 1 on clang/gcc and 0 on MSVC.
                return 1;
            } else {
                @compileError("Cannot use C sizeof on opaque type " ++ @typeName(T));
            }
        },
        .optional => |opt| {
            if (@typeInfo(opt.child) == .pointer) {
                return sizeof(opt.child);
            } else {
                @compileError("Cannot use C sizeof on non-pointer optional " ++ @typeName(T));
            }
        },
        .pointer => |ptr| {
            if (ptr.size == .slice) {
                @compileError("Cannot use C sizeof on slice type " ++ @typeName(T));
            }
            // for strings, sizeof("a") returns 2.
            // normal pointer decay scenarios from C are handled
            // in the .array case above, but strings remain literals
            // and are therefore always pointers, so they need to be
            // specially handled here.
            if (ptr.size == .one and ptr.is_const and @typeInfo(ptr.child) == .array) {
                const array_info = @typeInfo(ptr.child).array;
                if ((array_info.child == u8 or array_info.child == u16) and array_info.sentinel() == 0) {
                    // length of the string plus one for the null terminator.
                    return (array_info.len + 1) * @sizeOf(array_info.child);
                }
            }
            // When zero sized pointers are removed, this case will no
            // longer be reachable and can be deleted.
            if (@sizeOf(T) == 0) {
                return @sizeOf(*anyopaque);
            }
            return @sizeOf(T);
        },
        .comptime_float => return @sizeOf(f64), // TODO c_double #3999
        .comptime_int => {
            // TODO to get the correct result we have to translate
            // `1073741824 * 4` as `int(1073741824) *% int(4)` since
            // sizeof(1073741824 * 4) != sizeof(4294967296).

            // TODO test if target fits in int, long or long long
            return @sizeOf(c_int);
        },
        else => @compileError("std.meta.sizeof does not support type " ++ @typeName(T)),
    }
}

test "sizeof" {
    const S = extern struct { a: u32 };

    const ptr_size = @sizeOf(*anyopaque);

    try testing.expect(sizeof(u32) == 4);
    try testing.expect(sizeof(@as(u32, 2)) == 4);
    try testing.expect(sizeof(2) == @sizeOf(c_int));

    try testing.expect(sizeof(2.0) == @sizeOf(f64));

    try testing.expect(sizeof(S) == 4);

    try testing.expect(sizeof([_]u32{ 4, 5, 6 }) == 12);
    try testing.expect(sizeof([3]u32) == 12);
    try testing.expect(sizeof([3:0]u32) == 16);
    try testing.expect(sizeof(&[_]u32{ 4, 5, 6 }) == ptr_size);

    try testing.expect(sizeof(*u32) == ptr_size);
    try testing.expect(sizeof([*]u32) == ptr_size);
    try testing.expect(sizeof([*c]u32) == ptr_size);
    try testing.expect(sizeof(?*u32) == ptr_size);
    try testing.expect(sizeof(?[*]u32) == ptr_size);
    try testing.expect(sizeof(*anyopaque) == ptr_size);
    try testing.expect(sizeof(*void) == ptr_size);
    try testing.expect(sizeof(null) == ptr_size);

    try testing.expect(sizeof("foobar") == 7);
    try testing.expect(sizeof(&[_:0]u16{ 'f', 'o', 'o', 'b', 'a', 'r' }) == 14);
    try testing.expect(sizeof(*const [4:0]u8) == 5);
    try testing.expect(sizeof(*[4:0]u8) == ptr_size);
    try testing.expect(sizeof([*]const [4:0]u8) == ptr_size);
    try testing.expect(sizeof(*const *const [4:0]u8) == ptr_size);
    try testing.expect(sizeof(*const [4]u8) == ptr_size);

    if (false) { // TODO
        try testing.expect(sizeof(&sizeof) == @sizeOf(@TypeOf(&sizeof)));
        try testing.expect(sizeof(sizeof) == 1);
    }

    try testing.expect(sizeof(void) == 1);
    try testing.expect(sizeof(anyopaque) == 1);
}

pub const CIntLiteralBase = enum { decimal, octal, hex };

/// Deprecated: use `CIntLiteralBase`
pub const CIntLiteralRadix = CIntLiteralBase;

fn PromoteIntLiteralReturnType(comptime SuffixType: type, comptime number: comptime_int, comptime base: CIntLiteralBase) type {
    const signed_decimal = [_]type{ c_int, c_long, c_longlong, c_ulonglong };
    const signed_oct_hex = [_]type{ c_int, c_uint, c_long, c_ulong, c_longlong, c_ulonglong };
    const unsigned = [_]type{ c_uint, c_ulong, c_ulonglong };

    const list: []const type = if (@typeInfo(SuffixType).int.signedness == .unsigned)
        &unsigned
    else if (base == .decimal)
        &signed_decimal
    else
        &signed_oct_hex;

    var pos = mem.indexOfScalar(type, list, SuffixType).?;

    while (pos < list.len) : (pos += 1) {
        if (number >= math.minInt(list[pos]) and number <= math.maxInt(list[pos])) {
            return list[pos];
        }
    }
    @compileError("Integer literal is too large");
}

/// Promote the type of an integer literal until it fits as C would.
pub fn promoteIntLiteral(
    comptime SuffixType: type,
    comptime number: comptime_int,
    comptime base: CIntLiteralBase,
) PromoteIntLiteralReturnType(SuffixType, number, base) {
    return number;
}

test "promoteIntLiteral" {
    const signed_hex = promoteIntLiteral(c_int, math.maxInt(c_int) + 1, .hex);
    try testing.expectEqual(c_uint, @TypeOf(signed_hex));

    if (math.maxInt(c_longlong) == math.maxInt(c_int)) return;

    const signed_decimal = promoteIntLiteral(c_int, math.maxInt(c_int) + 1, .decimal);
    const unsigned = promoteIntLiteral(c_uint, math.maxInt(c_uint) + 1, .hex);

    if (math.maxInt(c_long) > math.maxInt(c_int)) {
        try testing.expectEqual(c_long, @TypeOf(signed_decimal));
        try testing.expectEqual(c_ulong, @TypeOf(unsigned));
    } else {
        try testing.expectEqual(c_longlong, @TypeOf(signed_decimal));
        try testing.expectEqual(c_ulonglong, @TypeOf(unsigned));
    }
}

/// Convert from clang __builtin_shufflevector index to Zig @shuffle index
/// clang requires __builtin_shufflevector index arguments to be integer constants.
/// negative values for `this_index` indicate "don't care".
/// clang enforces that `this_index` is less than the total number of vector elements
/// See https://ziglang.org/documentation/master/#shuffle
/// See https://clang.llvm.org/docs/LanguageExtensions.html#langext-builtin-shufflevector
pub fn shuffleVectorIndex(comptime this_index: c_int, comptime source_vector_len: usize) i32 {
    const positive_index = std.math.cast(usize, this_index) orelse return undefined;
    if (positive_index < source_vector_len) return @as(i32, @intCast(this_index));
    const b_index = positive_index - source_vector_len;
    return ~@as(i32, @intCast(b_index));
}

test "shuffleVectorIndex" {
    const vector_len: usize = 4;

    _ = shuffleVectorIndex(-1, vector_len);

    try testing.expect(shuffleVectorIndex(0, vector_len) == 0);
    try testing.expect(shuffleVectorIndex(1, vector_len) == 1);
    try testing.expect(shuffleVectorIndex(2, vector_len) == 2);
    try testing.expect(shuffleVectorIndex(3, vector_len) == 3);

    try testing.expect(shuffleVectorIndex(4, vector_len) == -1);
    try testing.expect(shuffleVectorIndex(5, vector_len) == -2);
    try testing.expect(shuffleVectorIndex(6, vector_len) == -3);
    try testing.expect(shuffleVectorIndex(7, vector_len) == -4);
}

/// Constructs a [*c] pointer with the const and volatile annotations
/// from SelfType for pointing to a C flexible array of ElementType.
pub fn FlexibleArrayType(comptime SelfType: type, comptime ElementType: type) type {
    switch (@typeInfo(SelfType)) {
        .pointer => |ptr| {
            return @Type(.{ .pointer = .{
                .size = .c,
                .is_const = ptr.is_const,
                .is_volatile = ptr.is_volatile,
                .alignment = @alignOf(ElementType),
                .address_space = .generic,
                .child = ElementType,
                .is_allowzero = true,
                .sentinel_ptr = null,
            } });
        },
        else => |info| @compileError("Invalid self type \"" ++ @tagName(info) ++ "\" for flexible array getter: " ++ @typeName(SelfType)),
    }
}

test "Flexible Array Type" {
    const Container = extern struct {
        size: usize,
    };

    try testing.expectEqual(FlexibleArrayType(*Container, c_int), [*c]c_int);
    try testing.expectEqual(FlexibleArrayType(*const Container, c_int), [*c]const c_int);
    try testing.expectEqual(FlexibleArrayType(*volatile Container, c_int), [*c]volatile c_int);
    try testing.expectEqual(FlexibleArrayType(*const volatile Container, c_int), [*c]const volatile c_int);
}

/// C `%` operator for signed integers
/// C standard states: "If the quotient a/b is representable, the expression (a/b)*b + a%b shall equal a"
/// The quotient is not representable if denominator is zero, or if numerator is the minimum integer for
/// the type and denominator is -1. C has undefined behavior for those two cases; this function has safety
/// checked undefined behavior
pub fn signedRemainder(numerator: anytype, denominator: anytype) @TypeOf(numerator, denominator) {
    std.debug.assert(@typeInfo(@TypeOf(numerator, denominator)).int.signedness == .signed);
    if (denominator > 0) return @rem(numerator, denominator);
    return numerator - @divTrunc(numerator, denominator) * denominator;
}

pub const Macros = struct {
    pub fn U_SUFFIX(comptime n: comptime_int) @TypeOf(promoteIntLiteral(c_uint, n, .decimal)) {
        return promoteIntLiteral(c_uint, n, .decimal);
    }

    fn L_SUFFIX_ReturnType(comptime number: anytype) type {
        switch (@typeInfo(@TypeOf(number))) {
            .int, .comptime_int => return @TypeOf(promoteIntLiteral(c_long, number, .decimal)),
            .float, .comptime_float => return c_longdouble,
            else => @compileError("Invalid value for L suffix"),
        }
    }
    pub fn L_SUFFIX(comptime number: anytype) L_SUFFIX_ReturnType(number) {
        switch (@typeInfo(@TypeOf(number))) {
            .int, .comptime_int => return promoteIntLiteral(c_long, number, .decimal),
            .float, .comptime_float => @compileError("TODO: c_longdouble initialization from comptime_float not supported"),
            else => @compileError("Invalid value for L suffix"),
        }
    }

    pub fn UL_SUFFIX(comptime n: comptime_int) @TypeOf(promoteIntLiteral(c_ulong, n, .decimal)) {
        return promoteIntLiteral(c_ulong, n, .decimal);
    }

    pub fn LL_SUFFIX(comptime n: comptime_int) @TypeOf(promoteIntLiteral(c_longlong, n, .decimal)) {
        return promoteIntLiteral(c_longlong, n, .decimal);
    }

    pub fn ULL_SUFFIX(comptime n: comptime_int) @TypeOf(promoteIntLiteral(c_ulonglong, n, .decimal)) {
        return promoteIntLiteral(c_ulonglong, n, .decimal);
    }

    pub fn F_SUFFIX(comptime f: comptime_float) f32 {
        return @as(f32, f);
    }

    pub fn WL_CONTAINER_OF(ptr: anytype, sample: anytype, comptime member: []const u8) @TypeOf(sample) {
        return @fieldParentPtr(member, ptr);
    }

    /// A 2-argument function-like macro defined as #define FOO(A, B) (A)(B)
    /// could be either: cast B to A, or call A with the value B.
    pub fn CAST_OR_CALL(a: anytype, b: anytype) switch (@typeInfo(@TypeOf(a))) {
        .type => a,
        .@"fn" => |fn_info| fn_info.return_type orelse void,
        else => |info| @compileError("Unexpected argument type: " ++ @tagName(info)),
    } {
        switch (@typeInfo(@TypeOf(a))) {
            .type => return cast(a, b),
            .@"fn" => return a(b),
            else => unreachable, // return type will be a compile error otherwise
        }
    }

    pub inline fn DISCARD(x: anytype) void {
        _ = x;
    }
};

/// Integer promotion described in C11 6.3.1.1.2
fn PromotedIntType(comptime T: type) type {
    return switch (T) {
        bool, c_short => c_int,
        c_ushort => if (@sizeOf(c_ushort) == @sizeOf(c_int)) c_uint else c_int,
        c_int, c_uint, c_long, c_ulong, c_longlong, c_ulonglong => T,
        else => switch (@typeInfo(T)) {
            .comptime_int => @compileError("Cannot promote `" ++ @typeName(T) ++ "`; a fixed-size number type is required"),
            // promote to c_int if it can represent all values of T
            .int => |int_info| if (int_info.bits < @bitSizeOf(c_int))
                c_int
                // otherwise, restore the original C type
            else if (int_info.bits == @bitSizeOf(c_int))
                if (int_info.signedness == .unsigned) c_uint else c_int
            else if (int_info.bits <= @bitSizeOf(c_long))
                if (int_info.signedness == .unsigned) c_ulong else c_long
            else if (int_info.bits <= @bitSizeOf(c_longlong))
                if (int_info.signedness == .unsigned) c_ulonglong else c_longlong
            else
                @compileError("Cannot promote `" ++ @typeName(T) ++ "`; a C ABI type is required"),
            else => @compileError("Attempted to promote invalid type `" ++ @typeName(T) ++ "`"),
        },
    };
}

/// C11 6.3.1.1.1
fn integerRank(comptime T: type) u8 {
    return switch (T) {
        bool => 0,
        u8, i8 => 1,
        c_short, c_ushort => 2,
        c_int, c_uint => 3,
        c_long, c_ulong => 4,
        c_longlong, c_ulonglong => 5,
        else => @compileError("integer rank not supported for `" ++ @typeName(T) ++ "`"),
    };
}

fn ToUnsigned(comptime T: type) type {
    return switch (T) {
        c_int => c_uint,
        c_long => c_ulong,
        c_longlong => c_ulonglong,
        else => @compileError("Cannot convert `" ++ @typeName(T) ++ "` to unsigned"),
    };
}

/// "Usual arithmetic conversions" from C11 standard 6.3.1.8
fn ArithmeticConversion(comptime A: type, comptime B: type) type {
    if (A == c_longdouble or B == c_longdouble) return c_longdouble;
    if (A == f80 or B == f80) return f80;
    if (A == f64 or B == f64) return f64;
    if (A == f32 or B == f32) return f32;

    const A_Promoted = PromotedIntType(A);
    const B_Promoted = PromotedIntType(B);
    comptime {
        std.debug.assert(integerRank(A_Promoted) >= integerRank(c_int));
        std.debug.assert(integerRank(B_Promoted) >= integerRank(c_int));
    }

    if (A_Promoted == B_Promoted) return A_Promoted;

    const a_signed = @typeInfo(A_Promoted).int.signedness == .signed;
    const b_signed = @typeInfo(B_Promoted).int.signedness == .signed;

    if (a_signed == b_signed) {
        return if (integerRank(A_Promoted) > integerRank(B_Promoted)) A_Promoted else B_Promoted;
    }

    const SignedType = if (a_signed) A_Promoted else B_Promoted;
    const UnsignedType = if (!a_signed) A_Promoted else B_Promoted;

    if (integerRank(UnsignedType) >= integerRank(SignedType)) return UnsignedType;

    if (std.math.maxInt(SignedType) >= std.math.maxInt(UnsignedType)) return SignedType;

    return ToUnsigned(SignedType);
}

test "ArithmeticConversion" {
    // Promotions not necessarily the same for other platforms
    if (builtin.target.cpu.arch != .x86_64 or builtin.target.os.tag != .linux) return error.SkipZigTest;

    const Test = struct {
        /// Order of operands should not matter for arithmetic conversions
        fn checkPromotion(comptime A: type, comptime B: type, comptime Expected: type) !void {
            try std.testing.expect(ArithmeticConversion(A, B) == Expected);
            try std.testing.expect(ArithmeticConversion(B, A) == Expected);
        }
    };

    try Test.checkPromotion(c_longdouble, c_int, c_longdouble);
    try Test.checkPromotion(c_int, f64, f64);
    try Test.checkPromotion(f32, bool, f32);

    try Test.checkPromotion(bool, c_short, c_int);
    try Test.checkPromotion(c_int, c_int, c_int);
    try Test.checkPromotion(c_short, c_int, c_int);

    try Test.checkPromotion(c_int, c_long, c_long);

    try Test.checkPromotion(c_ulonglong, c_uint, c_ulonglong);

    try Test.checkPromotion(c_uint, c_int, c_uint);

    try Test.checkPromotion(c_uint, c_long, c_long);

    try Test.checkPromotion(c_ulong, c_longlong, c_ulonglong);

    // stdint.h
    try Test.checkPromotion(u8, i8, c_int);
    try Test.checkPromotion(u16, i16, c_int);
    try Test.checkPromotion(i32, c_int, c_int);
    try Test.checkPromotion(u32, c_int, c_uint);
    try Test.checkPromotion(i64, c_int, c_long);
    try Test.checkPromotion(u64, c_int, c_ulong);
    try Test.checkPromotion(isize, c_int, c_long);
    try Test.checkPromotion(usize, c_int, c_ulong);
}

pub const MacroArithmetic = struct {
    pub fn div(a: anytype, b: anytype) ArithmeticConversion(@TypeOf(a), @TypeOf(b)) {
        const ResType = ArithmeticConversion(@TypeOf(a), @TypeOf(b));
        const a_casted = cast(ResType, a);
        const b_casted = cast(ResType, b);
        switch (@typeInfo(ResType)) {
            .float => return a_casted / b_casted,
            .int => return @divTrunc(a_casted, b_casted),
            else => unreachable,
        }
    }

    pub fn rem(a: anytype, b: anytype) ArithmeticConversion(@TypeOf(a), @TypeOf(b)) {
        const ResType = ArithmeticConversion(@TypeOf(a), @TypeOf(b));
        const a_casted = cast(ResType, a);
        const b_casted = cast(ResType, b);
        switch (@typeInfo(ResType)) {
            .int => {
                if (@typeInfo(ResType).int.signedness == .signed) {
                    return signedRemainder(a_casted, b_casted);
                } else {
                    return a_casted % b_casted;
                }
            },
            else => unreachable,
        }
    }
};

test "Macro suffix functions" {
    try testing.expect(@TypeOf(Macros.F_SUFFIX(1)) == f32);

    try testing.expect(@TypeOf(Macros.U_SUFFIX(1)) == c_uint);
    if (math.maxInt(c_ulong) > math.maxInt(c_uint)) {
        try testing.expect(@TypeOf(Macros.U_SUFFIX(math.maxInt(c_uint) + 1)) == c_ulong);
    }
    if (math.maxInt(c_ulonglong) > math.maxInt(c_ulong)) {
        try testing.expect(@TypeOf(Macros.U_SUFFIX(math.maxInt(c_ulong) + 1)) == c_ulonglong);
    }

    try testing.expect(@TypeOf(Macros.L_SUFFIX(1)) == c_long);
    if (math.maxInt(c_long) > math.maxInt(c_int)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(math.maxInt(c_int) + 1)) == c_long);
    }
    if (math.maxInt(c_longlong) > math.maxInt(c_long)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(math.maxInt(c_long) + 1)) == c_longlong);
    }

    try testing.expect(@TypeOf(Macros.UL_SUFFIX(1)) == c_ulong);
    if (math.maxInt(c_ulonglong) > math.maxInt(c_ulong)) {
        try testing.expect(@TypeOf(Macros.UL_SUFFIX(math.maxInt(c_ulong) + 1)) == c_ulonglong);
    }

    try testing.expect(@TypeOf(Macros.LL_SUFFIX(1)) == c_longlong);
    try testing.expect(@TypeOf(Macros.ULL_SUFFIX(1)) == c_ulonglong);
}

test "WL_CONTAINER_OF" {
    const S = struct {
        a: u32 = 0,
        b: u32 = 0,
    };
    const x = S{};
    const y = S{};
    const ptr = Macros.WL_CONTAINER_OF(&x.b, &y, "b");
    try testing.expectEqual(&x, ptr);
}

test "CAST_OR_CALL casting" {
    const arg: c_int = 1000;
    const casted = Macros.CAST_OR_CALL(u8, arg);
    try testing.expectEqual(cast(u8, arg), casted);

    const S = struct {
        x: u32 = 0,
    };
    var s: S = .{};
    const casted_ptr = Macros.CAST_OR_CALL(*u8, &s);
    try testing.expectEqual(cast(*u8, &s), casted_ptr);
}

test "CAST_OR_CALL calling" {
    const Helper = struct {
        var last_val: bool = false;
        fn returnsVoid(val: bool) void {
            last_val = val;
        }
        fn returnsBool(f: f32) bool {
            return f > 0;
        }
        fn identity(self: c_uint) c_uint {
            return self;
        }
    };

    Macros.CAST_OR_CALL(Helper.returnsVoid, true);
    try testing.expectEqual(true, Helper.last_val);
    Macros.CAST_OR_CALL(Helper.returnsVoid, false);
    try testing.expectEqual(false, Helper.last_val);

    try testing.expectEqual(Helper.returnsBool(1), Macros.CAST_OR_CALL(Helper.returnsBool, @as(f32, 1)));
    try testing.expectEqual(Helper.returnsBool(-1), Macros.CAST_OR_CALL(Helper.returnsBool, @as(f32, -1)));

    try testing.expectEqual(Helper.identity(@as(c_uint, 100)), Macros.CAST_OR_CALL(Helper.identity, @as(c_uint, 100)));
}

test "Extended C ABI casting" {
    if (math.maxInt(c_long) > math.maxInt(c_char)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_char, math.maxInt(c_char) - 1))) == c_long); // c_char
    }
    if (math.maxInt(c_long) > math.maxInt(c_short)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_short, math.maxInt(c_short) - 1))) == c_long); // c_short
    }

    if (math.maxInt(c_long) > math.maxInt(c_ushort)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_ushort, math.maxInt(c_ushort) - 1))) == c_long); //c_ushort
    }

    if (math.maxInt(c_long) > math.maxInt(c_int)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_int, math.maxInt(c_int) - 1))) == c_long); // c_int
    }

    if (math.maxInt(c_long) > math.maxInt(c_uint)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_uint, math.maxInt(c_uint) - 1))) == c_long); // c_uint
        try testing.expect(@TypeOf(Macros.L_SUFFIX(math.maxInt(c_uint) + 1)) == c_long); // comptime_int -> c_long
    }

    if (math.maxInt(c_longlong) > math.maxInt(c_long)) {
        try testing.expect(@TypeOf(Macros.L_SUFFIX(@as(c_long, math.maxInt(c_long) - 1))) == c_long); // c_long
        try testing.expect(@TypeOf(Macros.L_SUFFIX(math.maxInt(c_long) + 1)) == c_longlong); // comptime_int -> c_longlong
    }
}

// Function with complex signature for testing the SDL case
fn complexFunction(_: ?*anyopaque, _: c_uint, _: ?*const fn (?*anyopaque) callconv(.c) c_uint, _: ?*anyopaque, _: c_uint, _: [*c]c_uint) callconv(.c) usize {
    return 0;
}

test "function pointer casting" {
    const SDL_FunctionPointer = ?*const fn () callconv(.c) void;
    const fn_ptr = cast(SDL_FunctionPointer, complexFunction);
    try testing.expect(fn_ptr != null);
}
pub const Message = struct {
    pub const Header = extern struct {
        tag: Tag,
        /// Size of the body only; does not include this Header.
        bytes_len: u32,
    };

    pub const Tag = enum(u32) {
        /// Tells the compiler to shut down cleanly.
        /// No body.
        exit,
        /// Tells the compiler to detect changes in source files and update the
        /// affected output compilation artifacts.
        /// If one of the compilation artifacts is an executable that is
        /// running as a child process, the compiler will wait for it to exit
        /// before performing the update.
        /// No body.
        update,
        /// Tells the compiler to execute the executable as a child process.
        /// No body.
        run,
        /// Tells the compiler to detect changes in source files and update the
        /// affected output compilation artifacts.
        /// If one of the compilation artifacts is an executable that is
        /// running as a child process, the compiler will perform a hot code
        /// swap.
        /// No body.
        hot_update,
        /// Ask the test runner for metadata about all the unit tests that can
        /// be run. Server will respond with a `test_metadata` message.
        /// No body.
        query_test_metadata,
        /// Ask the test runner to run a particular test.
        /// The message body is a u32 test index.
        run_test,
        /// Ask the test runner to start fuzzing a particular test.
        /// The message body is a u32 test index.
        start_fuzzing,

        _,
    };
};
//! To support incremental compilation, errors are stored in various places
//! so that they can be created and destroyed appropriately. This structure
//! is used to collect all the errors from the various places into one
//! convenient place for API users to consume.
//!
//! There is one special encoding for this data structure. If both arrays are
//! empty, it means there are no errors. This special encoding exists so that
//! heap allocation is not needed in the common case of no errors.

string_bytes: []const u8,
/// The first thing in this array is an `ErrorMessageList`.
extra: []const u32,

/// Index into `string_bytes`.
pub const String = u32;
/// Index into `string_bytes`, or null.
pub const OptionalString = u32;

/// Special encoding when there are no errors.
pub const empty: ErrorBundle = .{
    .string_bytes = &.{},
    .extra = &.{},
};

// An index into `extra` pointing at an `ErrorMessage`.
pub const MessageIndex = enum(u32) {
    _,
};

// An index into `extra` pointing at an `SourceLocation`.
pub const SourceLocationIndex = enum(u32) {
    none = 0,
    _,
};

/// There will be a MessageIndex for each len at start.
pub const ErrorMessageList = struct {
    len: u32,
    start: u32,
    /// null-terminated string index. 0 means no compile log text.
    compile_log_text: OptionalString,
};

/// Trailing:
/// * ReferenceTrace for each reference_trace_len
pub const SourceLocation = struct {
    src_path: String,
    line: u32,
    column: u32,
    /// byte offset of starting token
    span_start: u32,
    /// byte offset of main error location
    span_main: u32,
    /// byte offset of end of last token
    span_end: u32,
    /// Does not include the trailing newline.
    source_line: OptionalString = 0,
    reference_trace_len: u32 = 0,
};

/// Trailing:
/// * MessageIndex for each notes_len.
pub const ErrorMessage = struct {
    msg: String,
    /// Usually one, but incremented for redundant messages.
    count: u32 = 1,
    src_loc: SourceLocationIndex = .none,
    notes_len: u32 = 0,
};

pub const ReferenceTrace = struct {
    /// null terminated string index
    /// Except for the sentinel ReferenceTrace element, in which case:
    /// * 0 means remaining references hidden
    /// * >0 means N references hidden
    decl_name: String,
    /// Index into extra of a SourceLocation
    /// If this is 0, this is the sentinel ReferenceTrace element.
    src_loc: SourceLocationIndex,
};

pub fn deinit(eb: *ErrorBundle, gpa: Allocator) void {
    gpa.free(eb.string_bytes);
    gpa.free(eb.extra);
    eb.* = undefined;
}

pub fn errorMessageCount(eb: ErrorBundle) u32 {
    if (eb.extra.len == 0) return 0;
    return eb.getErrorMessageList().len;
}

pub fn getErrorMessageList(eb: ErrorBundle) ErrorMessageList {
    return eb.extraData(ErrorMessageList, 0).data;
}

pub fn getMessages(eb: ErrorBundle) []const MessageIndex {
    const list = eb.getErrorMessageList();
    return @as([]const MessageIndex, @ptrCast(eb.extra[list.start..][0..list.len]));
}

pub fn getErrorMessage(eb: ErrorBundle, index: MessageIndex) ErrorMessage {
    return eb.extraData(ErrorMessage, @intFromEnum(index)).data;
}

pub fn getSourceLocation(eb: ErrorBundle, index: SourceLocationIndex) SourceLocation {
    assert(index != .none);
    return eb.extraData(SourceLocation, @intFromEnum(index)).data;
}

pub fn getNotes(eb: ErrorBundle, index: MessageIndex) []const MessageIndex {
    const notes_len = eb.getErrorMessage(index).notes_len;
    const start = @intFromEnum(index) + @typeInfo(ErrorMessage).@"struct".fields.len;
    return @as([]const MessageIndex, @ptrCast(eb.extra[start..][0..notes_len]));
}

pub fn getCompileLogOutput(eb: ErrorBundle) [:0]const u8 {
    return nullTerminatedString(eb, getErrorMessageList(eb).compile_log_text);
}

/// Returns the requested data, as well as the new index which is at the start of the
/// trailers for the object.
fn extraData(eb: ErrorBundle, comptime T: type, index: usize) struct { data: T, end: usize } {
    const fields = @typeInfo(T).@"struct".fields;
    var i: usize = index;
    var result: T = undefined;
    inline for (fields) |field| {
        @field(result, field.name) = switch (field.type) {
            u32 => eb.extra[i],
            MessageIndex => @as(MessageIndex, @enumFromInt(eb.extra[i])),
            SourceLocationIndex => @as(SourceLocationIndex, @enumFromInt(eb.extra[i])),
            else => @compileError("bad field type"),
        };
        i += 1;
    }
    return .{
        .data = result,
        .end = i,
    };
}

/// Given an index into `string_bytes` returns the null-terminated string found there.
pub fn nullTerminatedString(eb: ErrorBundle, index: String) [:0]const u8 {
    const string_bytes = eb.string_bytes;
    var end: usize = index;
    while (string_bytes[end] != 0) {
        end += 1;
    }
    return string_bytes[index..end :0];
}

pub const RenderOptions = struct {
    ttyconf: std.io.tty.Config,
    include_reference_trace: bool = true,
    include_source_line: bool = true,
    include_log_text: bool = true,
};

pub fn renderToStdErr(eb: ErrorBundle, options: RenderOptions) void {
    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    const stderr = std.io.getStdErr();
    return renderToWriter(eb, options, stderr.writer()) catch return;
}

pub fn renderToWriter(eb: ErrorBundle, options: RenderOptions, writer: anytype) anyerror!void {
    if (eb.extra.len == 0) return;
    for (eb.getMessages()) |err_msg| {
        try renderErrorMessageToWriter(eb, options, err_msg, writer, "error", .red, 0);
    }

    if (options.include_log_text) {
        const log_text = eb.getCompileLogOutput();
        if (log_text.len != 0) {
            try writer.writeAll("\nCompile Log Output:\n");
            try writer.writeAll(log_text);
        }
    }
}

fn renderErrorMessageToWriter(
    eb: ErrorBundle,
    options: RenderOptions,
    err_msg_index: MessageIndex,
    stderr: anytype,
    kind: []const u8,
    color: std.io.tty.Color,
    indent: usize,
) anyerror!void {
    const ttyconf = options.ttyconf;
    var counting_writer = std.io.countingWriter(stderr);
    const counting_stderr = counting_writer.writer();
    const err_msg = eb.getErrorMessage(err_msg_index);
    if (err_msg.src_loc != .none) {
        const src = eb.extraData(SourceLocation, @intFromEnum(err_msg.src_loc));
        try counting_stderr.writeByteNTimes(' ', indent);
        try ttyconf.setColor(stderr, .bold);
        try counting_stderr.print("{s}:{d}:{d}: ", .{
            eb.nullTerminatedString(src.data.src_path),
            src.data.line + 1,
            src.data.column + 1,
        });
        try ttyconf.setColor(stderr, color);
        try counting_stderr.writeAll(kind);
        try counting_stderr.writeAll(": ");
        // This is the length of the part before the error message:
        // e.g. "file.zig:4:5: error: "
        const prefix_len: usize = @intCast(counting_stderr.context.bytes_written);
        try ttyconf.setColor(stderr, .reset);
        try ttyconf.setColor(stderr, .bold);
        if (err_msg.count == 1) {
            try writeMsg(eb, err_msg, stderr, prefix_len);
            try stderr.writeByte('\n');
        } else {
            try writeMsg(eb, err_msg, stderr, prefix_len);
            try ttyconf.setColor(stderr, .dim);
            try stderr.print(" ({d} times)\n", .{err_msg.count});
        }
        try ttyconf.setColor(stderr, .reset);
        if (src.data.source_line != 0 and options.include_source_line) {
            const line = eb.nullTerminatedString(src.data.source_line);
            for (line) |b| switch (b) {
                '\t' => try stderr.writeByte(' '),
                else => try stderr.writeByte(b),
            };
            try stderr.writeByte('\n');
            // TODO basic unicode code point monospace width
            const before_caret = src.data.span_main - src.data.span_start;
            // -1 since span.main includes the caret
            const after_caret = src.data.span_end -| src.data.span_main -| 1;
            try stderr.writeByteNTimes(' ', src.data.column - before_caret);
            try ttyconf.setColor(stderr, .green);
            try stderr.writeByteNTimes('~', before_caret);
            try stderr.writeByte('^');
            try stderr.writeByteNTimes('~', after_caret);
            try stderr.writeByte('\n');
            try ttyconf.setColor(stderr, .reset);
        }
        for (eb.getNotes(err_msg_index)) |note| {
            try renderErrorMessageToWriter(eb, options, note, stderr, "note", .cyan, indent);
        }
        if (src.data.reference_trace_len > 0 and options.include_reference_trace) {
            try ttyconf.setColor(stderr, .reset);
            try ttyconf.setColor(stderr, .dim);
            try stderr.print("referenced by:\n", .{});
            var ref_index = src.end;
            for (0..src.data.reference_trace_len) |_| {
                const ref_trace = eb.extraData(ReferenceTrace, ref_index);
                ref_index = ref_trace.end;
                if (ref_trace.data.src_loc != .none) {
                    const ref_src = eb.getSourceLocation(ref_trace.data.src_loc);
                    try stderr.print("    {s}: {s}:{d}:{d}\n", .{
                        eb.nullTerminatedString(ref_trace.data.decl_name),
                        eb.nullTerminatedString(ref_src.src_path),
                        ref_src.line + 1,
                        ref_src.column + 1,
                    });
                } else if (ref_trace.data.decl_name != 0) {
                    const count = ref_trace.data.decl_name;
                    try stderr.print(
                        "    {d} reference(s) hidden; use '-freference-trace={d}' to see all references\n",
                        .{ count, count + src.data.reference_trace_len - 1 },
                    );
                } else {
                    try stderr.print(
                        "    remaining reference traces hidden; use '-freference-trace' to see all reference traces\n",
                        .{},
                    );
                }
            }
            try ttyconf.setColor(stderr, .reset);
        }
    } else {
        try ttyconf.setColor(stderr, color);
        try stderr.writeByteNTimes(' ', indent);
        try stderr.writeAll(kind);
        try stderr.writeAll(": ");
        try ttyconf.setColor(stderr, .reset);
        const msg = eb.nullTerminatedString(err_msg.msg);
        if (err_msg.count == 1) {
            try stderr.print("{s}\n", .{msg});
        } else {
            try stderr.print("{s}", .{msg});
            try ttyconf.setColor(stderr, .dim);
            try stderr.print(" ({d} times)\n", .{err_msg.count});
        }
        try ttyconf.setColor(stderr, .reset);
        for (eb.getNotes(err_msg_index)) |note| {
            try renderErrorMessageToWriter(eb, options, note, stderr, "note", .cyan, indent + 4);
        }
    }
}

/// Splits the error message up into lines to properly indent them
/// to allow for long, good-looking error messages.
///
/// This is used to split the message in `@compileError("hello\nworld")` for example.
fn writeMsg(eb: ErrorBundle, err_msg: ErrorMessage, stderr: anytype, indent: usize) !void {
    var lines = std.mem.splitScalar(u8, eb.nullTerminatedString(err_msg.msg), '\n');
    while (lines.next()) |line| {
        try stderr.writeAll(line);
        if (lines.index == null) break;
        try stderr.writeByte('\n');
        try stderr.writeByteNTimes(' ', indent);
    }
}

const std = @import("std");
const ErrorBundle = @This();
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const Wip = struct {
    gpa: Allocator,
    string_bytes: std.ArrayListUnmanaged(u8),
    /// The first thing in this array is a ErrorMessageList.
    extra: std.ArrayListUnmanaged(u32),
    root_list: std.ArrayListUnmanaged(MessageIndex),

    pub fn init(wip: *Wip, gpa: Allocator) !void {
        wip.* = .{
            .gpa = gpa,
            .string_bytes = .{},
            .extra = .{},
            .root_list = .{},
        };

        // So that 0 can be used to indicate a null string.
        try wip.string_bytes.append(gpa, 0);

        assert(0 == try addExtra(wip, ErrorMessageList{
            .len = 0,
            .start = 0,
            .compile_log_text = 0,
        }));
    }

    pub fn deinit(wip: *Wip) void {
        const gpa = wip.gpa;
        wip.root_list.deinit(gpa);
        wip.string_bytes.deinit(gpa);
        wip.extra.deinit(gpa);
        wip.* = undefined;
    }

    pub fn toOwnedBundle(wip: *Wip, compile_log_text: []const u8) !ErrorBundle {
        const gpa = wip.gpa;
        if (wip.root_list.items.len == 0) {
            assert(compile_log_text.len == 0);
            // Special encoding when there are no errors.
            wip.deinit();
            wip.* = .{
                .gpa = gpa,
                .string_bytes = .{},
                .extra = .{},
                .root_list = .{},
            };
            return empty;
        }

        const compile_log_str_index = if (compile_log_text.len == 0) 0 else str: {
            const str: u32 = @intCast(wip.string_bytes.items.len);
            try wip.string_bytes.ensureUnusedCapacity(gpa, compile_log_text.len + 1);
            wip.string_bytes.appendSliceAssumeCapacity(compile_log_text);
            wip.string_bytes.appendAssumeCapacity(0);
            break :str str;
        };

        wip.setExtra(0, ErrorMessageList{
            .len = @intCast(wip.root_list.items.len),
            .start = @intCast(wip.extra.items.len),
            .compile_log_text = compile_log_str_index,
        });
        try wip.extra.appendSlice(gpa, @as([]const u32, @ptrCast(wip.root_list.items)));
        wip.root_list.clearAndFree(gpa);
        return .{
            .string_bytes = try wip.string_bytes.toOwnedSlice(gpa),
            .extra = try wip.extra.toOwnedSlice(gpa),
        };
    }

    pub fn tmpBundle(wip: Wip) ErrorBundle {
        return .{
            .string_bytes = wip.string_bytes.items,
            .extra = wip.extra.items,
        };
    }

    pub fn addString(wip: *Wip, s: []const u8) Allocator.Error!String {
        const gpa = wip.gpa;
        const index: String = @intCast(wip.string_bytes.items.len);
        try wip.string_bytes.ensureUnusedCapacity(gpa, s.len + 1);
        wip.string_bytes.appendSliceAssumeCapacity(s);
        wip.string_bytes.appendAssumeCapacity(0);
        return index;
    }

    pub fn printString(wip: *Wip, comptime fmt: []const u8, args: anytype) Allocator.Error!String {
        const gpa = wip.gpa;
        const index: String = @intCast(wip.string_bytes.items.len);
        try wip.string_bytes.writer(gpa).print(fmt, args);
        try wip.string_bytes.append(gpa, 0);
        return index;
    }

    pub fn addRootErrorMessage(wip: *Wip, em: ErrorMessage) Allocator.Error!void {
        try wip.root_list.ensureUnusedCapacity(wip.gpa, 1);
        wip.root_list.appendAssumeCapacity(try addErrorMessage(wip, em));
    }

    pub fn addErrorMessage(wip: *Wip, em: ErrorMessage) Allocator.Error!MessageIndex {
        return @enumFromInt(try addExtra(wip, em));
    }

    pub fn addErrorMessageAssumeCapacity(wip: *Wip, em: ErrorMessage) MessageIndex {
        return @enumFromInt(addExtraAssumeCapacity(wip, em));
    }

    pub fn addSourceLocation(wip: *Wip, sl: SourceLocation) Allocator.Error!SourceLocationIndex {
        return @enumFromInt(try addExtra(wip, sl));
    }

    pub fn addReferenceTrace(wip: *Wip, rt: ReferenceTrace) Allocator.Error!void {
        _ = try addExtra(wip, rt);
    }

    pub fn addBundleAsNotes(wip: *Wip, other: ErrorBundle) Allocator.Error!void {
        const gpa = wip.gpa;

        try wip.string_bytes.ensureUnusedCapacity(gpa, other.string_bytes.len);
        try wip.extra.ensureUnusedCapacity(gpa, other.extra.len);

        const other_list = other.getMessages();

        // The ensureUnusedCapacity call above guarantees this.
        const notes_start = wip.reserveNotes(@intCast(other_list.len)) catch unreachable;
        for (notes_start.., other_list) |note, message| {
            // This line can cause `wip.extra.items` to be resized.
            const note_index = @intFromEnum(wip.addOtherMessage(other, message) catch unreachable);
            wip.extra.items[note] = note_index;
        }
    }

    pub fn addBundleAsRoots(wip: *Wip, other: ErrorBundle) !void {
        const gpa = wip.gpa;

        try wip.string_bytes.ensureUnusedCapacity(gpa, other.string_bytes.len);
        try wip.extra.ensureUnusedCapacity(gpa, other.extra.len);

        const other_list = other.getMessages();

        try wip.root_list.ensureUnusedCapacity(gpa, other_list.len);
        for (other_list) |other_msg| {
            // The ensureUnusedCapacity calls above guarantees this.
            wip.root_list.appendAssumeCapacity(wip.addOtherMessage(other, other_msg) catch unreachable);
        }
    }

    pub fn reserveNotes(wip: *Wip, notes_len: u32) !u32 {
        try wip.extra.ensureUnusedCapacity(wip.gpa, notes_len +
            notes_len * @typeInfo(ErrorBundle.ErrorMessage).@"struct".fields.len);
        wip.extra.items.len += notes_len;
        return @intCast(wip.extra.items.len - notes_len);
    }

    pub fn addZirErrorMessages(
        eb: *ErrorBundle.Wip,
        zir: std.zig.Zir,
        tree: std.zig.Ast,
        source: [:0]const u8,
        src_path: []const u8,
    ) !void {
        const Zir = std.zig.Zir;
        const payload_index = zir.extra[@intFromEnum(Zir.ExtraIndex.compile_errors)];
        assert(payload_index != 0);

        const header = zir.extraData(Zir.Inst.CompileErrors, payload_index);
        const items_len = header.data.items_len;
        var extra_index = header.end;
        for (0..items_len) |_| {
            const item = zir.extraData(Zir.Inst.CompileErrors.Item, extra_index);
            extra_index = item.end;
            const err_span = blk: {
                if (item.data.node.unwrap()) |node| {
                    break :blk tree.nodeToSpan(node);
                } else if (item.data.token.unwrap()) |token| {
                    const start = tree.tokenStart(token) + item.data.byte_offset;
                    const end = start + @as(u32, @intCast(tree.tokenSlice(token).len)) - item.data.byte_offset;
                    break :blk std.zig.Ast.Span{ .start = start, .end = end, .main = start };
                } else unreachable;
            };
            const err_loc = std.zig.findLineColumn(source, err_span.main);

            {
                const msg = zir.nullTerminatedString(item.data.msg);
                try eb.addRootErrorMessage(.{
                    .msg = try eb.addString(msg),
                    .src_loc = try eb.addSourceLocation(.{
                        .src_path = try eb.addString(src_path),
                        .span_start = err_span.start,
                        .span_main = err_span.main,
                        .span_end = err_span.end,
                        .line = @intCast(err_loc.line),
                        .column = @intCast(err_loc.column),
                        .source_line = try eb.addString(err_loc.source_line),
                    }),
                    .notes_len = item.data.notesLen(zir),
                });
            }

            if (item.data.notes != 0) {
                const notes_start = try eb.reserveNotes(item.data.notesLen(zir));
                const block = zir.extraData(Zir.Inst.Block, item.data.notes);
                const body = zir.extra[block.end..][0..block.data.body_len];
                for (notes_start.., body) |note_i, body_elem| {
                    const note_item = zir.extraData(Zir.Inst.CompileErrors.Item, body_elem);
                    const msg = zir.nullTerminatedString(note_item.data.msg);
                    const span = blk: {
                        if (note_item.data.node.unwrap()) |node| {
                            break :blk tree.nodeToSpan(node);
                        } else if (note_item.data.token.unwrap()) |token| {
                            const start = tree.tokenStart(token) + note_item.data.byte_offset;
                            const end = start + @as(u32, @intCast(tree.tokenSlice(token).len)) - item.data.byte_offset;
                            break :blk std.zig.Ast.Span{ .start = start, .end = end, .main = start };
                        } else unreachable;
                    };
                    const loc = std.zig.findLineColumn(source, span.main);

                    // This line can cause `wip.extra.items` to be resized.
                    const note_index = @intFromEnum(try eb.addErrorMessage(.{
                        .msg = try eb.addString(msg),
                        .src_loc = try eb.addSourceLocation(.{
                            .src_path = try eb.addString(src_path),
                            .span_start = span.start,
                            .span_main = span.main,
                            .span_end = span.end,
                            .line = @intCast(loc.line),
                            .column = @intCast(loc.column),
                            .source_line = if (loc.eql(err_loc))
                                0
                            else
                                try eb.addString(loc.source_line),
                        }),
                        .notes_len = 0, // TODO rework this function to be recursive
                    }));
                    eb.extra.items[note_i] = note_index;
                }
            }
        }
    }

    pub fn addZoirErrorMessages(
        eb: *ErrorBundle.Wip,
        zoir: std.zig.Zoir,
        tree: std.zig.Ast,
        source: [:0]const u8,
        src_path: []const u8,
    ) !void {
        assert(zoir.hasCompileErrors());

        for (zoir.compile_errors) |err| {
            const err_span: std.zig.Ast.Span = span: {
                if (err.token.unwrap()) |token| {
                    const token_start = tree.tokenStart(token);
                    const start = token_start + err.node_or_offset;
                    const end = token_start + @as(u32, @intCast(tree.tokenSlice(token).len));
                    break :span .{ .start = start, .end = end, .main = start };
                } else {
                    break :span tree.nodeToSpan(@enumFromInt(err.node_or_offset));
                }
            };
            const err_loc = std.zig.findLineColumn(source, err_span.main);

            try eb.addRootErrorMessage(.{
                .msg = try eb.addString(err.msg.get(zoir)),
                .src_loc = try eb.addSourceLocation(.{
                    .src_path = try eb.addString(src_path),
                    .span_start = err_span.start,
                    .span_main = err_span.main,
                    .span_end = err_span.end,
                    .line = @intCast(err_loc.line),
                    .column = @intCast(err_loc.column),
                    .source_line = try eb.addString(err_loc.source_line),
                }),
                .notes_len = err.note_count,
            });

            const notes_start = try eb.reserveNotes(err.note_count);
            for (notes_start.., err.first_note.., 0..err.note_count) |eb_note_idx, zoir_note_idx, _| {
                const note = zoir.error_notes[zoir_note_idx];
                const note_span: std.zig.Ast.Span = span: {
                    if (note.token.unwrap()) |token| {
                        const token_start = tree.tokenStart(token);
                        const start = token_start + note.node_or_offset;
                        const end = token_start + @as(u32, @intCast(tree.tokenSlice(token).len));
                        break :span .{ .start = start, .end = end, .main = start };
                    } else {
                        break :span tree.nodeToSpan(@enumFromInt(note.node_or_offset));
                    }
                };
                const note_loc = std.zig.findLineColumn(source, note_span.main);

                // This line can cause `wip.extra.items` to be resized.
                const note_index = @intFromEnum(try eb.addErrorMessage(.{
                    .msg = try eb.addString(note.msg.get(zoir)),
                    .src_loc = try eb.addSourceLocation(.{
                        .src_path = try eb.addString(src_path),
                        .span_start = note_span.start,
                        .span_main = note_span.main,
                        .span_end = note_span.end,
                        .line = @intCast(note_loc.line),
                        .column = @intCast(note_loc.column),
                        .source_line = if (note_loc.eql(err_loc))
                            0
                        else
                            try eb.addString(note_loc.source_line),
                    }),
                    .notes_len = 0,
                }));
                eb.extra.items[eb_note_idx] = note_index;
            }
        }
    }

    fn addOtherMessage(wip: *Wip, other: ErrorBundle, msg_index: MessageIndex) !MessageIndex {
        const other_msg = other.getErrorMessage(msg_index);
        const src_loc = try wip.addOtherSourceLocation(other, other_msg.src_loc);
        const msg = try wip.addErrorMessage(.{
            .msg = try wip.addString(other.nullTerminatedString(other_msg.msg)),
            .count = other_msg.count,
            .src_loc = src_loc,
            .notes_len = other_msg.notes_len,
        });
        const notes_start = try wip.reserveNotes(other_msg.notes_len);
        for (notes_start.., other.getNotes(msg_index)) |note, other_note| {
            wip.extra.items[note] = @intFromEnum(try wip.addOtherMessage(other, other_note));
        }
        return msg;
    }

    fn addOtherSourceLocation(
        wip: *Wip,
        other: ErrorBundle,
        index: SourceLocationIndex,
    ) !SourceLocationIndex {
        if (index == .none) return .none;
        const other_sl = other.getSourceLocation(index);

        var ref_traces: std.ArrayListUnmanaged(ReferenceTrace) = .empty;
        defer ref_traces.deinit(wip.gpa);

        if (other_sl.reference_trace_len > 0) {
            var ref_index = other.extraData(SourceLocation, @intFromEnum(index)).end;
            for (0..other_sl.reference_trace_len) |_| {
                const other_ref_trace_ed = other.extraData(ReferenceTrace, ref_index);
                const other_ref_trace = other_ref_trace_ed.data;
                ref_index = other_ref_trace_ed.end;

                const ref_trace: ReferenceTrace = if (other_ref_trace.src_loc == .none) .{
                    // sentinel ReferenceTrace does not store a string index in decl_name
                    .decl_name = other_ref_trace.decl_name,
                    .src_loc = .none,
                } else .{
                    .decl_name = try wip.addString(other.nullTerminatedString(other_ref_trace.decl_name)),
                    .src_loc = try wip.addOtherSourceLocation(other, other_ref_trace.src_loc),
                };
                try ref_traces.append(wip.gpa, ref_trace);
            }
        }

        const src_loc = try wip.addSourceLocation(.{
            .src_path = try wip.addString(other.nullTerminatedString(other_sl.src_path)),
            .line = other_sl.line,
            .column = other_sl.column,
            .span_start = other_sl.span_start,
            .span_main = other_sl.span_main,
            .span_end = other_sl.span_end,
            .source_line = if (other_sl.source_line != 0)
                try wip.addString(other.nullTerminatedString(other_sl.source_line))
            else
                0,
            .reference_trace_len = other_sl.reference_trace_len,
        });

        for (ref_traces.items) |ref_trace| {
            try wip.addReferenceTrace(ref_trace);
        }

        return src_loc;
    }

    fn addExtra(wip: *Wip, extra: anytype) Allocator.Error!u32 {
        const gpa = wip.gpa;
        const fields = @typeInfo(@TypeOf(extra)).@"struct".fields;
        try wip.extra.ensureUnusedCapacity(gpa, fields.len);
        return addExtraAssumeCapacity(wip, extra);
    }

    fn addExtraAssumeCapacity(wip: *Wip, extra: anytype) u32 {
        const fields = @typeInfo(@TypeOf(extra)).@"struct".fields;
        const result: u32 = @intCast(wip.extra.items.len);
        wip.extra.items.len += fields.len;
        setExtra(wip, result, extra);
        return result;
    }

    fn setExtra(wip: *Wip, index: usize, extra: anytype) void {
        const fields = @typeInfo(@TypeOf(extra)).@"struct".fields;
        var i = index;
        inline for (fields) |field| {
            wip.extra.items[i] = switch (field.type) {
                u32 => @field(extra, field.name),
                MessageIndex => @intFromEnum(@field(extra, field.name)),
                SourceLocationIndex => @intFromEnum(@field(extra, field.name)),
                else => @compileError("bad field type"),
            };
            i += 1;
        }
    }

    test addBundleAsRoots {
        var bundle = bundle: {
            var wip: ErrorBundle.Wip = undefined;
            try wip.init(std.testing.allocator);
            errdefer wip.deinit();

            var ref_traces: [3]ReferenceTrace = undefined;
            for (&ref_traces, 0..) |*ref_trace, i| {
                if (i == ref_traces.len - 1) {
                    // sentinel reference trace
                    ref_trace.* = .{
                        .decl_name = 3, // signifies 3 hidden references
                        .src_loc = .none,
                    };
                } else {
                    ref_trace.* = .{
                        .decl_name = try wip.addString("foo"),
                        .src_loc = try wip.addSourceLocation(.{
                            .src_path = try wip.addString("foo"),
                            .line = 1,
                            .column = 2,
                            .span_start = 3,
                            .span_main = 4,
                            .span_end = 5,
                            .source_line = 0,
                        }),
                    };
                }
            }

            const src_loc = try wip.addSourceLocation(.{
                .src_path = try wip.addString("foo"),
                .line = 1,
                .column = 2,
                .span_start = 3,
                .span_main = 4,
                .span_end = 5,
                .source_line = try wip.addString("some source code"),
                .reference_trace_len = ref_traces.len,
            });
            for (&ref_traces) |ref_trace| {
                try wip.addReferenceTrace(ref_trace);
            }

            try wip.addRootErrorMessage(ErrorMessage{
                .msg = try wip.addString("hello world"),
                .src_loc = src_loc,
                .notes_len = 1,
            });
            const i = try wip.reserveNotes(1);
            const note_index = @intFromEnum(wip.addErrorMessageAssumeCapacity(.{
                .msg = try wip.addString("this is a note"),
                .src_loc = try wip.addSourceLocation(.{
                    .src_path = try wip.addString("bar"),
                    .line = 1,
                    .column = 2,
                    .span_start = 3,
                    .span_main = 4,
                    .span_end = 5,
                    .source_line = try wip.addString("another line of source"),
                }),
            }));
            wip.extra.items[i] = note_index;

            break :bundle try wip.toOwnedBundle("");
        };
        defer bundle.deinit(std.testing.allocator);

        const ttyconf: std.io.tty.Config = .no_color;

        var bundle_buf = std.ArrayList(u8).init(std.testing.allocator);
        defer bundle_buf.deinit();
        try bundle.renderToWriter(.{ .ttyconf = ttyconf }, bundle_buf.writer());

        var copy = copy: {
            var wip: ErrorBundle.Wip = undefined;
            try wip.init(std.testing.allocator);
            errdefer wip.deinit();

            try wip.addBundleAsRoots(bundle);

            break :copy try wip.toOwnedBundle("");
        };
        defer copy.deinit(std.testing.allocator);

        var copy_buf = std.ArrayList(u8).init(std.testing.allocator);
        defer copy_buf.deinit();
        try copy.renderToWriter(.{ .ttyconf = ttyconf }, copy_buf.writer());

        try std.testing.expectEqualStrings(bundle_buf.items, copy_buf.items);
    }
};
libc_include_dir_list: []const []const u8,
libc_installation: ?*const LibCInstallation,
libc_framework_dir_list: []const []const u8,
sysroot: ?[]const u8,
darwin_sdk_layout: ?DarwinSdkLayout,

/// The filesystem layout of darwin SDK elements.
pub const DarwinSdkLayout = enum {
    /// macOS SDK layout: TOP { /usr/include, /usr/lib, /System/Library/Frameworks }.
    sdk,
    /// Shipped libc layout: TOP { /lib/libc/include,  /lib/libc/darwin, <NONE> }.
    vendored,
};

pub fn detect(
    arena: Allocator,
    zig_lib_dir: []const u8,
    target: std.Target,
    is_native_abi: bool,
    link_libc: bool,
    libc_installation: ?*const LibCInstallation,
) !LibCDirs {
    if (!link_libc) {
        return .{
            .libc_include_dir_list = &[0][]u8{},
            .libc_installation = null,
            .libc_framework_dir_list = &.{},
            .sysroot = null,
            .darwin_sdk_layout = null,
        };
    }

    if (libc_installation) |lci| {
        return detectFromInstallation(arena, target, lci);
    }

    // If linking system libraries and targeting the native abi, default to
    // using the system libc installation.
    if (is_native_abi and !target.isMinGW()) {
        const libc = try arena.create(LibCInstallation);
        libc.* = LibCInstallation.findNative(.{ .allocator = arena, .target = target }) catch |err| switch (err) {
            error.CCompilerExitCode,
            error.CCompilerCrashed,
            error.CCompilerCannotFindHeaders,
            error.UnableToSpawnCCompiler,
            error.DarwinSdkNotFound,
            => |e| {
                // We tried to integrate with the native system C compiler,
                // however, it is not installed. So we must rely on our bundled
                // libc files.
                if (std.zig.target.canBuildLibC(target)) {
                    return detectFromBuilding(arena, zig_lib_dir, target);
                }
                return e;
            },
            else => |e| return e,
        };
        return detectFromInstallation(arena, target, libc);
    }

    // If not linking system libraries, build and provide our own libc by
    // default if possible.
    if (std.zig.target.canBuildLibC(target)) {
        return detectFromBuilding(arena, zig_lib_dir, target);
    }

    // If zig can't build the libc for the target and we are targeting the
    // native abi, fall back to using the system libc installation.
    // On windows, instead of the native (mingw) abi, we want to check
    // for the MSVC abi as a fallback.
    const use_system_abi = if (builtin.os.tag == .windows)
        target.abi == .msvc or target.abi == .itanium
    else
        is_native_abi;

    if (use_system_abi) {
        const libc = try arena.create(LibCInstallation);
        libc.* = try LibCInstallation.findNative(.{ .allocator = arena, .verbose = true, .target = target });
        return detectFromInstallation(arena, target, libc);
    }

    return .{
        .libc_include_dir_list = &[0][]u8{},
        .libc_installation = null,
        .libc_framework_dir_list = &.{},
        .sysroot = null,
        .darwin_sdk_layout = null,
    };
}

fn detectFromInstallation(arena: Allocator, target: std.Target, lci: *const LibCInstallation) !LibCDirs {
    var list = try std.ArrayList([]const u8).initCapacity(arena, 5);
    var framework_list = std.ArrayList([]const u8).init(arena);

    list.appendAssumeCapacity(lci.include_dir.?);

    const is_redundant = std.mem.eql(u8, lci.sys_include_dir.?, lci.include_dir.?);
    if (!is_redundant) list.appendAssumeCapacity(lci.sys_include_dir.?);

    if (target.os.tag == .windows) {
        if (std.fs.path.dirname(lci.sys_include_dir.?)) |sys_include_dir_parent| {
            // This include path will only exist when the optional "Desktop development with C++"
            // is installed. It contains headers, .rc files, and resources. It is especially
            // necessary when working with Windows resources.
            const atlmfc_dir = try std.fs.path.join(arena, &[_][]const u8{ sys_include_dir_parent, "atlmfc", "include" });
            list.appendAssumeCapacity(atlmfc_dir);
        }
        if (std.fs.path.dirname(lci.include_dir.?)) |include_dir_parent| {
            const um_dir = try std.fs.path.join(arena, &[_][]const u8{ include_dir_parent, "um" });
            list.appendAssumeCapacity(um_dir);

            const shared_dir = try std.fs.path.join(arena, &[_][]const u8{ include_dir_parent, "shared" });
            list.appendAssumeCapacity(shared_dir);
        }
    }
    if (target.os.tag == .haiku) {
        const include_dir_path = lci.include_dir orelse return error.LibCInstallationNotAvailable;
        const os_dir = try std.fs.path.join(arena, &[_][]const u8{ include_dir_path, "os" });
        list.appendAssumeCapacity(os_dir);
        // Errors.h
        const os_support_dir = try std.fs.path.join(arena, &[_][]const u8{ include_dir_path, "os/support" });
        list.appendAssumeCapacity(os_support_dir);

        const config_dir = try std.fs.path.join(arena, &[_][]const u8{ include_dir_path, "config" });
        list.appendAssumeCapacity(config_dir);
    }

    var sysroot: ?[]const u8 = null;

    if (target.os.tag.isDarwin()) d: {
        const down1 = std.fs.path.dirname(lci.sys_include_dir.?) orelse break :d;
        const down2 = std.fs.path.dirname(down1) orelse break :d;
        try framework_list.append(try std.fs.path.join(arena, &.{ down2, "System", "Library", "Frameworks" }));
        sysroot = down2;
    }

    return .{
        .libc_include_dir_list = list.items,
        .libc_installation = lci,
        .libc_framework_dir_list = framework_list.items,
        .sysroot = sysroot,
        .darwin_sdk_layout = if (sysroot == null) null else .sdk,
    };
}

pub fn detectFromBuilding(
    arena: Allocator,
    zig_lib_dir: []const u8,
    target: std.Target,
) !LibCDirs {
    const s = std.fs.path.sep_str;

    if (target.os.tag.isDarwin()) {
        const list = try arena.alloc([]const u8, 1);
        list[0] = try std.fmt.allocPrint(
            arena,
            "{s}" ++ s ++ "libc" ++ s ++ "include" ++ s ++ "any-macos-any",
            .{zig_lib_dir},
        );
        return .{
            .libc_include_dir_list = list,
            .libc_installation = null,
            .libc_framework_dir_list = &.{},
            .sysroot = null,
            .darwin_sdk_layout = .vendored,
        };
    }

    const generic_name = libCGenericName(target);
    // Some architecture families are handled by the same set of headers.
    const arch_name = if (target.abi.isMusl())
        std.zig.target.muslArchNameHeaders(target.cpu.arch)
    else
        @tagName(target.cpu.arch);
    const os_name = @tagName(target.os.tag);
    const abi_name = if (target.abi.isMusl())
        std.zig.target.muslAbiNameHeaders(target.abi)
    else
        @tagName(target.abi);
    const arch_include_dir = try std.fmt.allocPrint(
        arena,
        "{s}" ++ s ++ "libc" ++ s ++ "include" ++ s ++ "{s}-{s}-{s}",
        .{ zig_lib_dir, arch_name, os_name, abi_name },
    );
    const generic_include_dir = try std.fmt.allocPrint(
        arena,
        "{s}" ++ s ++ "libc" ++ s ++ "include" ++ s ++ "generic-{s}",
        .{ zig_lib_dir, generic_name },
    );
    const generic_arch_name = std.zig.target.osArchName(target);
    const arch_os_include_dir = try std.fmt.allocPrint(
        arena,
        "{s}" ++ s ++ "libc" ++ s ++ "include" ++ s ++ "{s}-{s}-any",
        .{ zig_lib_dir, generic_arch_name, os_name },
    );
    const generic_os_include_dir = try std.fmt.allocPrint(
        arena,
        "{s}" ++ s ++ "libc" ++ s ++ "include" ++ s ++ "any-{s}-any",
        .{ zig_lib_dir, os_name },
    );

    const list = try arena.alloc([]const u8, 4);
    list[0] = arch_include_dir;
    list[1] = generic_include_dir;
    list[2] = arch_os_include_dir;
    list[3] = generic_os_include_dir;

    return .{
        .libc_include_dir_list = list,
        .libc_installation = null,
        .libc_framework_dir_list = &.{},
        .sysroot = null,
        .darwin_sdk_layout = .vendored,
    };
}

fn libCGenericName(target: std.Target) [:0]const u8 {
    switch (target.os.tag) {
        .windows => return "mingw",
        .macos, .ios, .tvos, .watchos, .visionos => return "darwin",
        else => {},
    }
    switch (target.abi) {
        .gnu,
        .gnuabin32,
        .gnuabi64,
        .gnueabi,
        .gnueabihf,
        .gnuf32,
        .gnusf,
        .gnux32,
        => return "glibc",
        .musl,
        .muslabin32,
        .muslabi64,
        .musleabi,
        .musleabihf,
        .muslf32,
        .muslsf,
        .muslx32,
        .none,
        .ohos,
        .ohoseabi,
        => return "musl",
        .code16,
        .eabi,
        .eabihf,
        .ilp32,
        .android,
        .androideabi,
        .msvc,
        .itanium,
        .cygnus,
        .simulator,
        .macabi,
        => unreachable,
    }
}

const LibCDirs = @This();
const builtin = @import("builtin");
const std = @import("../std.zig");
const LibCInstallation = std.zig.LibCInstallation;
const Allocator = std.mem.Allocator;
//! See the render function implementation for documentation of the fields.

include_dir: ?[]const u8 = null,
sys_include_dir: ?[]const u8 = null,
crt_dir: ?[]const u8 = null,
msvc_lib_dir: ?[]const u8 = null,
kernel32_lib_dir: ?[]const u8 = null,
gcc_dir: ?[]const u8 = null,

pub const FindError = error{
    OutOfMemory,
    FileSystem,
    UnableToSpawnCCompiler,
    CCompilerExitCode,
    CCompilerCrashed,
    CCompilerCannotFindHeaders,
    LibCRuntimeNotFound,
    LibCStdLibHeaderNotFound,
    LibCKernel32LibNotFound,
    UnsupportedArchitecture,
    WindowsSdkNotFound,
    DarwinSdkNotFound,
    ZigIsTheCCompiler,
};

pub fn parse(
    allocator: Allocator,
    libc_file: []const u8,
    target: std.Target,
) !LibCInstallation {
    var self: LibCInstallation = .{};

    const fields = std.meta.fields(LibCInstallation);
    const FoundKey = struct {
        found: bool,
        allocated: ?[:0]u8,
    };
    var found_keys = [1]FoundKey{FoundKey{ .found = false, .allocated = null }} ** fields.len;
    errdefer {
        self = .{};
        for (found_keys) |found_key| {
            if (found_key.allocated) |s| allocator.free(s);
        }
    }

    const contents = try std.fs.cwd().readFileAlloc(allocator, libc_file, std.math.maxInt(usize));
    defer allocator.free(contents);

    var it = std.mem.tokenizeScalar(u8, contents, '\n');
    while (it.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var line_it = std.mem.splitScalar(u8, line, '=');
        const name = line_it.first();
        const value = line_it.rest();
        inline for (fields, 0..) |field, i| {
            if (std.mem.eql(u8, name, field.name)) {
                found_keys[i].found = true;
                if (value.len == 0) {
                    @field(self, field.name) = null;
                } else {
                    found_keys[i].allocated = try allocator.dupeZ(u8, value);
                    @field(self, field.name) = found_keys[i].allocated;
                }
                break;
            }
        }
    }
    inline for (fields, 0..) |field, i| {
        if (!found_keys[i].found) {
            log.err("missing field: {s}", .{field.name});
            return error.ParseError;
        }
    }
    if (self.include_dir == null) {
        log.err("include_dir may not be empty", .{});
        return error.ParseError;
    }
    if (self.sys_include_dir == null) {
        log.err("sys_include_dir may not be empty", .{});
        return error.ParseError;
    }

    const os_tag = target.os.tag;
    if (self.crt_dir == null and !target.os.tag.isDarwin()) {
        log.err("crt_dir may not be empty for {s}", .{@tagName(os_tag)});
        return error.ParseError;
    }

    if (self.msvc_lib_dir == null and os_tag == .windows and (target.abi == .msvc or target.abi == .itanium)) {
        log.err("msvc_lib_dir may not be empty for {s}-{s}", .{
            @tagName(os_tag),
            @tagName(target.abi),
        });
        return error.ParseError;
    }
    if (self.kernel32_lib_dir == null and os_tag == .windows and (target.abi == .msvc or target.abi == .itanium)) {
        log.err("kernel32_lib_dir may not be empty for {s}-{s}", .{
            @tagName(os_tag),
            @tagName(target.abi),
        });
        return error.ParseError;
    }

    if (self.gcc_dir == null and os_tag == .haiku) {
        log.err("gcc_dir may not be empty for {s}", .{@tagName(os_tag)});
        return error.ParseError;
    }

    return self;
}

pub fn render(self: LibCInstallation, out: anytype) !void {
    @setEvalBranchQuota(4000);
    const include_dir = self.include_dir orelse "";
    const sys_include_dir = self.sys_include_dir orelse "";
    const crt_dir = self.crt_dir orelse "";
    const msvc_lib_dir = self.msvc_lib_dir orelse "";
    const kernel32_lib_dir = self.kernel32_lib_dir orelse "";
    const gcc_dir = self.gcc_dir orelse "";

    try out.print(
        \\# The directory that contains `stdlib.h`.
        \\# On POSIX-like systems, include directories be found with: `cc -E -Wp,-v -xc /dev/null`
        \\include_dir={s}
        \\
        \\# The system-specific include directory. May be the same as `include_dir`.
        \\# On Windows it's the directory that includes `vcruntime.h`.
        \\# On POSIX it's the directory that includes `sys/errno.h`.
        \\sys_include_dir={s}
        \\
        \\# The directory that contains `crt1.o` or `crt2.o`.
        \\# On POSIX, can be found with `cc -print-file-name=crt1.o`.
        \\# Not needed when targeting MacOS.
        \\crt_dir={s}
        \\
        \\# The directory that contains `vcruntime.lib`.
        \\# Only needed when targeting MSVC on Windows.
        \\msvc_lib_dir={s}
        \\
        \\# The directory that contains `kernel32.lib`.
        \\# Only needed when targeting MSVC on Windows.
        \\kernel32_lib_dir={s}
        \\
        \\# The directory that contains `crtbeginS.o` and `crtendS.o`
        \\# Only needed when targeting Haiku.
        \\gcc_dir={s}
        \\
    , .{
        include_dir,
        sys_include_dir,
        crt_dir,
        msvc_lib_dir,
        kernel32_lib_dir,
        gcc_dir,
    });
}

pub const FindNativeOptions = struct {
    allocator: Allocator,
    target: std.Target,

    /// If enabled, will print human-friendly errors to stderr.
    verbose: bool = false,
};

/// Finds the default, native libc.
pub fn findNative(args: FindNativeOptions) FindError!LibCInstallation {
    var self: LibCInstallation = .{};

    if (is_darwin and args.target.os.tag.isDarwin()) {
        if (!std.zig.system.darwin.isSdkInstalled(args.allocator))
            return error.DarwinSdkNotFound;
        const sdk = std.zig.system.darwin.getSdk(args.allocator, args.target) orelse
            return error.DarwinSdkNotFound;
        defer args.allocator.free(sdk);

        self.include_dir = try fs.path.join(args.allocator, &.{
            sdk, "usr/include",
        });
        self.sys_include_dir = try fs.path.join(args.allocator, &.{
            sdk, "usr/include",
        });
        return self;
    } else if (is_windows) {
        const sdk = std.zig.WindowsSdk.find(args.allocator, args.target.cpu.arch) catch |err| switch (err) {
            error.NotFound => return error.WindowsSdkNotFound,
            error.PathTooLong => return error.WindowsSdkNotFound,
            error.OutOfMemory => return error.OutOfMemory,
```
