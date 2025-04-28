```
                               .value = v,
                                },
                            },
                            .regval_type => |r| .{
                                .regval_type = .{
                                    .type_offset = type_offset,
                                    .type_size = r.type_size,
                                    .value = r.value,
                                },
                            },
                            .const_type => |c| .{
                                .const_type = .{
                                    .type_offset = type_offset,
                                    .value_bytes = c.value_bytes,
                                },
                            },
                        };
                    }
                },

                // 2.5.1.7: Special Operations
                OP.nop => {},
                OP.entry_value => {
                    const block = operand.?.block;
                    if (block.len == 0) return error.InvalidSubExpression;

                    // TODO: The spec states that this sub-expression needs to observe the state (ie. registers)
                    //       as it was upon entering the current subprogram. If this isn't being called at the
                    //       end of a frame unwind operation, an additional ThreadContext with this state will be needed.

                    if (isOpcodeRegisterLocation(block[0])) {
                        if (context.thread_context == null) return error.IncompleteExpressionContext;

                        var block_stream = std.io.fixedBufferStream(block);
                        const register = (try readOperand(&block_stream, block[0], context)).?.register;
                        const value = mem.readInt(usize, (try abi.regBytes(context.thread_context.?, register, context.reg_context))[0..@sizeOf(usize)], native_endian);
                        try self.stack.append(allocator, .{ .generic = value });
                    } else {
                        var stack_machine: Self = .{};
                        defer stack_machine.deinit(allocator);

                        var sub_context = context;
                        sub_context.entry_value_context = true;
                        const result = try stack_machine.run(block, allocator, sub_context, null);
                        try self.stack.append(allocator, result orelse return error.InvalidSubExpression);
                    }
                },

                // These have already been handled by readOperand
                OP.lo_user...OP.hi_user => unreachable,
                else => {
                    //std.debug.print("Unknown DWARF expression opcode: {x}\n", .{opcode});
                    return error.UnknownExpressionOpcode;
                },
            }

            return stream.pos < stream.buffer.len;
        }
    };
}

pub fn Builder(comptime options: Options) type {
    const addr_type = switch (options.addr_size) {
        2 => u16,
        4 => u32,
        8 => u64,
        else => @compileError("Unsupported address size of " ++ options.addr_size),
    };

    return struct {
        /// Zero-operand instructions
        pub fn writeOpcode(writer: anytype, comptime opcode: u8) !void {
            if (options.call_frame_context and !comptime isOpcodeValidInCFA(opcode)) return error.InvalidCFAOpcode;
            switch (opcode) {
                OP.dup,
                OP.drop,
                OP.over,
                OP.swap,
                OP.rot,
                OP.deref,
                OP.xderef,
                OP.push_object_address,
                OP.form_tls_address,
                OP.call_frame_cfa,
                OP.abs,
                OP.@"and",
                OP.div,
                OP.minus,
                OP.mod,
                OP.mul,
                OP.neg,
                OP.not,
                OP.@"or",
                OP.plus,
                OP.shl,
                OP.shr,
                OP.shra,
                OP.xor,
                OP.le,
                OP.ge,
                OP.eq,
                OP.lt,
                OP.gt,
                OP.ne,
                OP.nop,
                OP.stack_value,
                => try writer.writeByte(opcode),
                else => @compileError("This opcode requires operands, use `write<Opcode>()` instead"),
            }
        }

        // 2.5.1.1: Literal Encodings
        pub fn writeLiteral(writer: anytype, literal: u8) !void {
            switch (literal) {
                0...31 => |n| try writer.writeByte(n + OP.lit0),
                else => return error.InvalidLiteral,
            }
        }

        pub fn writeConst(writer: anytype, comptime T: type, value: T) !void {
            if (@typeInfo(T) != .int) @compileError("Constants must be integers");

            switch (T) {
                u8, i8, u16, i16, u32, i32, u64, i64 => {
                    try writer.writeByte(switch (T) {
                        u8 => OP.const1u,
                        i8 => OP.const1s,
                        u16 => OP.const2u,
                        i16 => OP.const2s,
                        u32 => OP.const4u,
                        i32 => OP.const4s,
                        u64 => OP.const8u,
                        i64 => OP.const8s,
                        else => unreachable,
                    });

                    try writer.writeInt(T, value, options.endian);
                },
                else => switch (@typeInfo(T).int.signedness) {
                    .unsigned => {
                        try writer.writeByte(OP.constu);
                        try leb.writeUleb128(writer, value);
                    },
                    .signed => {
                        try writer.writeByte(OP.consts);
                        try leb.writeIleb128(writer, value);
                    },
                },
            }
        }

        pub fn writeConstx(writer: anytype, debug_addr_offset: anytype) !void {
            try writer.writeByte(OP.constx);
            try leb.writeUleb128(writer, debug_addr_offset);
        }

        pub fn writeConstType(writer: anytype, die_offset: anytype, value_bytes: []const u8) !void {
            if (options.call_frame_context) return error.InvalidCFAOpcode;
            if (value_bytes.len > 0xff) return error.InvalidTypeLength;
            try writer.writeByte(OP.const_type);
            try leb.writeUleb128(writer, die_offset);
            try writer.writeByte(@intCast(value_bytes.len));
            try writer.writeAll(value_bytes);
        }

        pub fn writeAddr(writer: anytype, value: addr_type) !void {
            try writer.writeByte(OP.addr);
            try writer.writeInt(addr_type, value, options.endian);
        }

        pub fn writeAddrx(writer: anytype, debug_addr_offset: anytype) !void {
            if (options.call_frame_context) return error.InvalidCFAOpcode;
            try writer.writeByte(OP.addrx);
            try leb.writeUleb128(writer, debug_addr_offset);
        }

        // 2.5.1.2: Register Values
        pub fn writeFbreg(writer: anytype, offset: anytype) !void {
            try writer.writeByte(OP.fbreg);
            try leb.writeIleb128(writer, offset);
        }

        pub fn writeBreg(writer: anytype, register: u8, offset: anytype) !void {
            if (register > 31) return error.InvalidRegister;
            try writer.writeByte(OP.breg0 + register);
            try leb.writeIleb128(writer, offset);
        }

        pub fn writeBregx(writer: anytype, register: anytype, offset: anytype) !void {
            try writer.writeByte(OP.bregx);
            try leb.writeUleb128(writer, register);
            try leb.writeIleb128(writer, offset);
        }

        pub fn writeRegvalType(writer: anytype, register: anytype, offset: anytype) !void {
            if (options.call_frame_context) return error.InvalidCFAOpcode;
            try writer.writeByte(OP.regval_type);
            try leb.writeUleb128(writer, register);
            try leb.writeUleb128(writer, offset);
        }

        // 2.5.1.3: Stack Operations
        pub fn writePick(writer: anytype, index: u8) !void {
            try writer.writeByte(OP.pick);
            try writer.writeByte(index);
        }

        pub fn writeDerefSize(writer: anytype, size: u8) !void {
            try writer.writeByte(OP.deref_size);
            try writer.writeByte(size);
        }

        pub fn writeXDerefSize(writer: anytype, size: u8) !void {
            try writer.writeByte(OP.xderef_size);
            try writer.writeByte(size);
        }

        pub fn writeDerefType(writer: anytype, size: u8, die_offset: anytype) !void {
            if (options.call_frame_context) return error.InvalidCFAOpcode;
            try writer.writeByte(OP.deref_type);
            try writer.writeByte(size);
            try leb.writeUleb128(writer, die_offset);
        }

        pub fn writeXDerefType(writer: anytype, size: u8, die_offset: anytype) !void {
            try writer.writeByte(OP.xderef_type);
            try writer.writeByte(size);
            try leb.writeUleb128(writer, die_offset);
        }

        // 2.5.1.4: Arithmetic and Logical Operations

        pub fn writePlusUconst(writer: anytype, uint_value: anytype) !void {
            try writer.writeByte(OP.plus_uconst);
            try leb.writeUleb128(writer, uint_value);
        }

        // 2.5.1.5: Control Flow Operations

        pub fn writeSkip(writer: anytype, offset: i16) !void {
            try writer.writeByte(OP.skip);
            try writer.writeInt(i16, offset, options.endian);
        }

        pub fn writeBra(writer: anytype, offset: i16) !void {
            try writer.writeByte(OP.bra);
            try writer.writeInt(i16, offset, options.endian);
        }

        pub fn writeCall(writer: anytype, comptime T: type, offset: T) !void {
            if (options.call_frame_context) return error.InvalidCFAOpcode;
            switch (T) {
                u16 => try writer.writeByte(OP.call2),
                u32 => try writer.writeByte(OP.call4),
                else => @compileError("Call operand must be a 2 or 4 byte offset"),
            }

            try writer.writeInt(T, offset, options.endian);
        }

        pub fn writeCallRef(writer: anytype, comptime is_64: bool, value: if (is_64) u64 else u32) !void {
            if (options.call_frame_context) return error.InvalidCFAOpcode;
            try writer.writeByte(OP.call_ref);
            try writer.writeInt(if (is_64) u64 else u32, value, options.endian);
        }

        pub fn writeConvert(writer: anytype, die_offset: anytype) !void {
            if (options.call_frame_context) return error.InvalidCFAOpcode;
            try writer.writeByte(OP.convert);
            try leb.writeUleb128(writer, die_offset);
        }

        pub fn writeReinterpret(writer: anytype, die_offset: anytype) !void {
            if (options.call_frame_context) return error.InvalidCFAOpcode;
            try writer.writeByte(OP.reinterpret);
            try leb.writeUleb128(writer, die_offset);
        }

        // 2.5.1.7: Special Operations

        pub fn writeEntryValue(writer: anytype, expression: []const u8) !void {
            try writer.writeByte(OP.entry_value);
            try leb.writeUleb128(writer, expression.len);
            try writer.writeAll(expression);
        }

        // 2.6: Location Descriptions
        pub fn writeReg(writer: anytype, register: u8) !void {
            try writer.writeByte(OP.reg0 + register);
        }

        pub fn writeRegx(writer: anytype, register: anytype) !void {
            try writer.writeByte(OP.regx);
            try leb.writeUleb128(writer, register);
        }

        pub fn writeImplicitValue(writer: anytype, value_bytes: []const u8) !void {
            try writer.writeByte(OP.implicit_value);
            try leb.writeUleb128(writer, value_bytes.len);
            try writer.writeAll(value_bytes);
        }
    };
}

// Certain opcodes are not allowed in a CFA context, see 6.4.2
fn isOpcodeValidInCFA(opcode: u8) bool {
    return switch (opcode) {
        OP.addrx,
        OP.call2,
        OP.call4,
        OP.call_ref,
        OP.const_type,
        OP.constx,
        OP.convert,
        OP.deref_type,
        OP.regval_type,
        OP.reinterpret,
        OP.push_object_address,
        OP.call_frame_cfa,
        => false,
        else => true,
    };
}

fn isOpcodeRegisterLocation(opcode: u8) bool {
    return switch (opcode) {
        OP.reg0...OP.reg31, OP.regx => true,
        else => false,
    };
}

const testing = std.testing;
test "DWARF expressions" {
    const allocator = std.testing.allocator;

    const options = Options{};
    var stack_machine = StackMachine(options){};
    defer stack_machine.deinit(allocator);

    const b = Builder(options);

    var program = std.ArrayList(u8).init(allocator);
    defer program.deinit();

    const writer = program.writer();

    // Literals
    {
        const context = Context{};
        for (0..32) |i| {
            try b.writeLiteral(writer, @intCast(i));
        }

        _ = try stack_machine.run(program.items, allocator, context, 0);

        for (0..32) |i| {
            const expected = 31 - i;
            try testing.expectEqual(expected, stack_machine.stack.pop().?.generic);
        }
    }

    // Constants
    {
        stack_machine.reset();
        program.clearRetainingCapacity();

        const input = [_]comptime_int{
            1,
            -1,
            @as(usize, @truncate(0x0fff)),
            @as(isize, @truncate(-0x0fff)),
            @as(usize, @truncate(0x0fffffff)),
            @as(isize, @truncate(-0x0fffffff)),
            @as(usize, @truncate(0x0fffffffffffffff)),
            @as(isize, @truncate(-0x0fffffffffffffff)),
            @as(usize, @truncate(0x8000000)),
            @as(isize, @truncate(-0x8000000)),
            @as(usize, @truncate(0x12345678_12345678)),
            @as(usize, @truncate(0xffffffff_ffffffff)),
            @as(usize, @truncate(0xeeeeeeee_eeeeeeee)),
        };

        try b.writeConst(writer, u8, input[0]);
        try b.writeConst(writer, i8, input[1]);
        try b.writeConst(writer, u16, input[2]);
        try b.writeConst(writer, i16, input[3]);
        try b.writeConst(writer, u32, input[4]);
        try b.writeConst(writer, i32, input[5]);
        try b.writeConst(writer, u64, input[6]);
        try b.writeConst(writer, i64, input[7]);
        try b.writeConst(writer, u28, input[8]);
        try b.writeConst(writer, i28, input[9]);
        try b.writeAddr(writer, input[10]);

        var mock_compile_unit: std.debug.Dwarf.CompileUnit = undefined;
        mock_compile_unit.addr_base = 1;

        var mock_debug_addr = std.ArrayList(u8).init(allocator);
        defer mock_debug_addr.deinit();

        try mock_debug_addr.writer().writeInt(u16, 0, native_endian);
        try mock_debug_addr.writer().writeInt(usize, input[11], native_endian);
        try mock_debug_addr.writer().writeInt(usize, input[12], native_endian);

        const context = Context{
            .compile_unit = &mock_compile_unit,
            .debug_addr = mock_debug_addr.items,
        };

        try b.writeConstx(writer, @as(usize, 1));
        try b.writeAddrx(writer, @as(usize, 1 + @sizeOf(usize)));

        const die_offset: usize = @truncate(0xaabbccdd);
        const type_bytes: []const u8 = &.{ 1, 2, 3, 4 };
        try b.writeConstType(writer, die_offset, type_bytes);

        _ = try stack_machine.run(program.items, allocator, context, 0);

        const const_type = stack_machine.stack.pop().?.const_type;
        try testing.expectEqual(die_offset, const_type.type_offset);
        try testing.expectEqualSlices(u8, type_bytes, const_type.value_bytes);

        const expected = .{
            .{ usize, input[12], usize },
            .{ usize, input[11], usize },
            .{ usize, input[10], usize },
            .{ isize, input[9], isize },
            .{ usize, input[8], usize },
            .{ isize, input[7], isize },
            .{ usize, input[6], usize },
            .{ isize, input[5], isize },
            .{ usize, input[4], usize },
            .{ isize, input[3], isize },
            .{ usize, input[2], usize },
            .{ isize, input[1], isize },
            .{ usize, input[0], usize },
        };

        inline for (expected) |e| {
            try testing.expectEqual(@as(e[0], e[1]), @as(e[2], @bitCast(stack_machine.stack.pop().?.generic)));
        }
    }

    // Register values
    if (@sizeOf(std.debug.ThreadContext) != 0) {
        stack_machine.reset();
        program.clearRetainingCapacity();

        const reg_context = abi.RegisterContext{
            .eh_frame = true,
            .is_macho = builtin.os.tag == .macos,
        };
        var thread_context: std.debug.ThreadContext = undefined;
        std.debug.relocateContext(&thread_context);
        const context = Context{
            .thread_context = &thread_context,
            .reg_context = reg_context,
        };

        // Only test register operations on arch / os that have them implemented
        if (abi.regBytes(&thread_context, 0, reg_context)) |reg_bytes| {

            // TODO: Test fbreg (once implemented): mock a DIE and point compile_unit.frame_base at it

            mem.writeInt(usize, reg_bytes[0..@sizeOf(usize)], 0xee, native_endian);
            (try abi.regValueNative(&thread_context, abi.fpRegNum(native_arch, reg_context), reg_context)).* = 1;
            (try abi.regValueNative(&thread_context, abi.spRegNum(native_arch, reg_context), reg_context)).* = 2;
            (try abi.regValueNative(&thread_context, abi.ipRegNum(native_arch).?, reg_context)).* = 3;

            try b.writeBreg(writer, abi.fpRegNum(native_arch, reg_context), @as(usize, 100));
            try b.writeBreg(writer, abi.spRegNum(native_arch, reg_context), @as(usize, 200));
            try b.writeBregx(writer, abi.ipRegNum(native_arch).?, @as(usize, 300));
            try b.writeRegvalType(writer, @as(u8, 0), @as(usize, 400));

            _ = try stack_machine.run(program.items, allocator, context, 0);

            const regval_type = stack_machine.stack.pop().?.regval_type;
            try testing.expectEqual(@as(usize, 400), regval_type.type_offset);
            try testing.expectEqual(@as(u8, @sizeOf(usize)), regval_type.type_size);
            try testing.expectEqual(@as(usize, 0xee), regval_type.value);

            try testing.expectEqual(@as(usize, 303), stack_machine.stack.pop().?.generic);
            try testing.expectEqual(@as(usize, 202), stack_machine.stack.pop().?.generic);
            try testing.expectEqual(@as(usize, 101), stack_machine.stack.pop().?.generic);
        } else |err| {
            switch (err) {
                error.UnimplementedArch,
                error.UnimplementedOs,
                error.ThreadContextNotSupported,
                => {},
                else => return err,
            }
        }
    }

    // Stack operations
    {
        var context = Context{};

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u8, 1);
        try b.writeOpcode(writer, OP.dup);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 1), stack_machine.stack.pop().?.generic);
        try testing.expectEqual(@as(usize, 1), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u8, 1);
        try b.writeOpcode(writer, OP.drop);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expect(stack_machine.stack.pop() == null);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u8, 4);
        try b.writeConst(writer, u8, 5);
        try b.writeConst(writer, u8, 6);
        try b.writePick(writer, 2);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 4), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u8, 4);
        try b.writeConst(writer, u8, 5);
        try b.writeConst(writer, u8, 6);
        try b.writeOpcode(writer, OP.over);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 5), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u8, 5);
        try b.writeConst(writer, u8, 6);
        try b.writeOpcode(writer, OP.swap);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 5), stack_machine.stack.pop().?.generic);
        try testing.expectEqual(@as(usize, 6), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u8, 4);
        try b.writeConst(writer, u8, 5);
        try b.writeConst(writer, u8, 6);
        try b.writeOpcode(writer, OP.rot);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 5), stack_machine.stack.pop().?.generic);
        try testing.expectEqual(@as(usize, 4), stack_machine.stack.pop().?.generic);
        try testing.expectEqual(@as(usize, 6), stack_machine.stack.pop().?.generic);

        const deref_target: usize = @truncate(0xffeeffee_ffeeffee);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeAddr(writer, @intFromPtr(&deref_target));
        try b.writeOpcode(writer, OP.deref);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(deref_target, stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeLiteral(writer, 0);
        try b.writeAddr(writer, @intFromPtr(&deref_target));
        try b.writeOpcode(writer, OP.xderef);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(deref_target, stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeAddr(writer, @intFromPtr(&deref_target));
        try b.writeDerefSize(writer, 1);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, @as(*const u8, @ptrCast(&deref_target)).*), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeLiteral(writer, 0);
        try b.writeAddr(writer, @intFromPtr(&deref_target));
        try b.writeXDerefSize(writer, 1);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, @as(*const u8, @ptrCast(&deref_target)).*), stack_machine.stack.pop().?.generic);

        const type_offset: usize = @truncate(0xaabbaabb_aabbaabb);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeAddr(writer, @intFromPtr(&deref_target));
        try b.writeDerefType(writer, 1, type_offset);
        _ = try stack_machine.run(program.items, allocator, context, null);
        const deref_type = stack_machine.stack.pop().?.regval_type;
        try testing.expectEqual(type_offset, deref_type.type_offset);
        try testing.expectEqual(@as(u8, 1), deref_type.type_size);
        try testing.expectEqual(@as(usize, @as(*const u8, @ptrCast(&deref_target)).*), deref_type.value);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeLiteral(writer, 0);
        try b.writeAddr(writer, @intFromPtr(&deref_target));
        try b.writeXDerefType(writer, 1, type_offset);
        _ = try stack_machine.run(program.items, allocator, context, null);
        const xderef_type = stack_machine.stack.pop().?.regval_type;
        try testing.expectEqual(type_offset, xderef_type.type_offset);
        try testing.expectEqual(@as(u8, 1), xderef_type.type_size);
        try testing.expectEqual(@as(usize, @as(*const u8, @ptrCast(&deref_target)).*), xderef_type.value);

        context.object_address = &deref_target;

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeOpcode(writer, OP.push_object_address);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, @intFromPtr(context.object_address.?)), stack_machine.stack.pop().?.generic);

        // TODO: Test OP.form_tls_address

        context.cfa = @truncate(0xccddccdd_ccddccdd);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeOpcode(writer, OP.call_frame_cfa);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(context.cfa.?, stack_machine.stack.pop().?.generic);
    }

    // Arithmetic and Logical Operations
    {
        const context = Context{};

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, i16, -4096);
        try b.writeOpcode(writer, OP.abs);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 4096), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 0xff0f);
        try b.writeConst(writer, u16, 0xf0ff);
        try b.writeOpcode(writer, OP.@"and");
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 0xf00f), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, i16, -404);
        try b.writeConst(writer, i16, 100);
        try b.writeOpcode(writer, OP.div);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(isize, -404 / 100), @as(isize, @bitCast(stack_machine.stack.pop().?.generic)));

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 200);
        try b.writeConst(writer, u16, 50);
        try b.writeOpcode(writer, OP.minus);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 150), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 123);
        try b.writeConst(writer, u16, 100);
        try b.writeOpcode(writer, OP.mod);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 23), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 0xff);
        try b.writeConst(writer, u16, 0xee);
        try b.writeOpcode(writer, OP.mul);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 0xed12), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 5);
        try b.writeOpcode(writer, OP.neg);
        try b.writeConst(writer, i16, -6);
        try b.writeOpcode(writer, OP.neg);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 6), stack_machine.stack.pop().?.generic);
        try testing.expectEqual(@as(isize, -5), @as(isize, @bitCast(stack_machine.stack.pop().?.generic)));

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 0xff0f);
        try b.writeOpcode(writer, OP.not);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(~@as(usize, 0xff0f), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 0xff0f);
        try b.writeConst(writer, u16, 0xf0ff);
        try b.writeOpcode(writer, OP.@"or");
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 0xffff), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, i16, 402);
        try b.writeConst(writer, i16, 100);
        try b.writeOpcode(writer, OP.plus);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 502), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 4096);
        try b.writePlusUconst(writer, @as(usize, 8192));
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 4096 + 8192), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 0xfff);
        try b.writeConst(writer, u16, 1);
        try b.writeOpcode(writer, OP.shl);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 0xfff << 1), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 0xfff);
        try b.writeConst(writer, u16, 1);
        try b.writeOpcode(writer, OP.shr);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 0xfff >> 1), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 0xfff);
        try b.writeConst(writer, u16, 1);
        try b.writeOpcode(writer, OP.shr);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, @bitCast(@as(isize, 0xfff) >> 1)), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConst(writer, u16, 0xf0ff);
        try b.writeConst(writer, u16, 0xff0f);
        try b.writeOpcode(writer, OP.xor);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 0x0ff0), stack_machine.stack.pop().?.generic);
    }

    // Control Flow Operations
    {
        const context = Context{};
        const expected = .{
            .{ OP.le, 1, 1, 0 },
            .{ OP.ge, 1, 0, 1 },
            .{ OP.eq, 1, 0, 0 },
            .{ OP.lt, 0, 1, 0 },
            .{ OP.gt, 0, 0, 1 },
            .{ OP.ne, 0, 1, 1 },
        };

        inline for (expected) |e| {
            stack_machine.reset();
            program.clearRetainingCapacity();

            try b.writeConst(writer, u16, 0);
            try b.writeConst(writer, u16, 0);
            try b.writeOpcode(writer, e[0]);
            try b.writeConst(writer, u16, 0);
            try b.writeConst(writer, u16, 1);
            try b.writeOpcode(writer, e[0]);
            try b.writeConst(writer, u16, 1);
            try b.writeConst(writer, u16, 0);
            try b.writeOpcode(writer, e[0]);
            _ = try stack_machine.run(program.items, allocator, context, null);
            try testing.expectEqual(@as(usize, e[3]), stack_machine.stack.pop().?.generic);
            try testing.expectEqual(@as(usize, e[2]), stack_machine.stack.pop().?.generic);
            try testing.expectEqual(@as(usize, e[1]), stack_machine.stack.pop().?.generic);
        }

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeLiteral(writer, 2);
        try b.writeSkip(writer, 1);
        try b.writeLiteral(writer, 3);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 2), stack_machine.stack.pop().?.generic);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeLiteral(writer, 2);
        try b.writeBra(writer, 1);
        try b.writeLiteral(writer, 3);
        try b.writeLiteral(writer, 0);
        try b.writeBra(writer, 1);
        try b.writeLiteral(writer, 4);
        try b.writeLiteral(writer, 5);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(@as(usize, 5), stack_machine.stack.pop().?.generic);
        try testing.expectEqual(@as(usize, 4), stack_machine.stack.pop().?.generic);
        try testing.expect(stack_machine.stack.pop() == null);

        // TODO: Test call2, call4, call_ref once implemented

    }

    // Type conversions
    {
        const context = Context{};
        stack_machine.reset();
        program.clearRetainingCapacity();

        // TODO: Test typed OP.convert once implemented

        const value: usize = @truncate(0xffeeffee_ffeeffee);
        var value_bytes: [options.addr_size]u8 = undefined;
        mem.writeInt(usize, &value_bytes, value, native_endian);

        // Convert to generic type
        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConstType(writer, @as(usize, 0), &value_bytes);
        try b.writeConvert(writer, @as(usize, 0));
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(value, stack_machine.stack.pop().?.generic);

        // Reinterpret to generic type
        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConstType(writer, @as(usize, 0), &value_bytes);
        try b.writeReinterpret(writer, @as(usize, 0));
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expectEqual(value, stack_machine.stack.pop().?.generic);

        // Reinterpret to new type
        const die_offset: usize = 0xffee;

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeConstType(writer, @as(usize, 0), &value_bytes);
        try b.writeReinterpret(writer, die_offset);
        _ = try stack_machine.run(program.items, allocator, context, null);
        const const_type = stack_machine.stack.pop().?.const_type;
        try testing.expectEqual(die_offset, const_type.type_offset);

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeLiteral(writer, 0);
        try b.writeReinterpret(writer, die_offset);
        _ = try stack_machine.run(program.items, allocator, context, null);
        const regval_type = stack_machine.stack.pop().?.regval_type;
        try testing.expectEqual(die_offset, regval_type.type_offset);
    }

    // Special operations
    {
        var context = Context{};

        stack_machine.reset();
        program.clearRetainingCapacity();
        try b.writeOpcode(writer, OP.nop);
        _ = try stack_machine.run(program.items, allocator, context, null);
        try testing.expect(stack_machine.stack.pop() == null);

        // Sub-expression
        {
            var sub_program = std.ArrayList(u8).init(allocator);
            defer sub_program.deinit();
            const sub_writer = sub_program.writer();
            try b.writeLiteral(sub_writer, 3);

            stack_machine.reset();
            program.clearRetainingCapacity();
            try b.writeEntryValue(writer, sub_program.items);
            _ = try stack_machine.run(program.items, allocator, context, null);
            try testing.expectEqual(@as(usize, 3), stack_machine.stack.pop().?.generic);
        }

        // Register location description
        const reg_context = abi.RegisterContext{
            .eh_frame = true,
            .is_macho = builtin.os.tag == .macos,
        };
        var thread_context: std.debug.ThreadContext = undefined;
        std.debug.relocateContext(&thread_context);
        context = Context{
            .thread_context = &thread_context,
            .reg_context = reg_context,
        };

        if (abi.regBytes(&thread_context, 0, reg_context)) |reg_bytes| {
            mem.writeInt(usize, reg_bytes[0..@sizeOf(usize)], 0xee, native_endian);

            var sub_program = std.ArrayList(u8).init(allocator);
            defer sub_program.deinit();
            const sub_writer = sub_program.writer();
            try b.writeReg(sub_writer, 0);

            stack_machine.reset();
            program.clearRetainingCapacity();
            try b.writeEntryValue(writer, sub_program.items);
            _ = try stack_machine.run(program.items, allocator, context, null);
            try testing.expectEqual(@as(usize, 0xee), stack_machine.stack.pop().?.generic);
        } else |err| {
            switch (err) {
                error.UnimplementedArch,
                error.UnimplementedOs,
                error.ThreadContextNotSupported,
                => {},
                else => return err,
            }
        }
    }
}
//! Optimized for performance in debug builds.

const std = @import("../std.zig");
const MemoryAccessor = std.debug.MemoryAccessor;

const FixedBufferReader = @This();

buf: []const u8,
pos: usize = 0,
endian: std.builtin.Endian,

pub const Error = error{ EndOfBuffer, Overflow, InvalidBuffer };

pub fn seekTo(fbr: *FixedBufferReader, pos: u64) Error!void {
    if (pos > fbr.buf.len) return error.EndOfBuffer;
    fbr.pos = @intCast(pos);
}

pub fn seekForward(fbr: *FixedBufferReader, amount: u64) Error!void {
    if (fbr.buf.len - fbr.pos < amount) return error.EndOfBuffer;
    fbr.pos += @intCast(amount);
}

pub inline fn readByte(fbr: *FixedBufferReader) Error!u8 {
    if (fbr.pos >= fbr.buf.len) return error.EndOfBuffer;
    defer fbr.pos += 1;
    return fbr.buf[fbr.pos];
}

pub fn readByteSigned(fbr: *FixedBufferReader) Error!i8 {
    return @bitCast(try fbr.readByte());
}

pub fn readInt(fbr: *FixedBufferReader, comptime T: type) Error!T {
    const size = @divExact(@typeInfo(T).int.bits, 8);
    if (fbr.buf.len - fbr.pos < size) return error.EndOfBuffer;
    defer fbr.pos += size;
    return std.mem.readInt(T, fbr.buf[fbr.pos..][0..size], fbr.endian);
}

pub fn readIntChecked(
    fbr: *FixedBufferReader,
    comptime T: type,
    ma: *MemoryAccessor,
) Error!T {
    if (ma.load(T, @intFromPtr(fbr.buf[fbr.pos..].ptr)) == null)
        return error.InvalidBuffer;

    return fbr.readInt(T);
}

pub fn readUleb128(fbr: *FixedBufferReader, comptime T: type) Error!T {
    return std.leb.readUleb128(T, fbr);
}

pub fn readIleb128(fbr: *FixedBufferReader, comptime T: type) Error!T {
    return std.leb.readIleb128(T, fbr);
}

pub fn readAddress(fbr: *FixedBufferReader, format: std.dwarf.Format) Error!u64 {
    return switch (format) {
        .@"32" => try fbr.readInt(u32),
        .@"64" => try fbr.readInt(u64),
    };
}

pub fn readAddressChecked(
    fbr: *FixedBufferReader,
    format: std.dwarf.Format,
    ma: *MemoryAccessor,
) Error!u64 {
    return switch (format) {
        .@"32" => try fbr.readIntChecked(u32, ma),
        .@"64" => try fbr.readIntChecked(u64, ma),
    };
}

pub fn readBytes(fbr: *FixedBufferReader, len: usize) Error![]const u8 {
    if (fbr.buf.len - fbr.pos < len) return error.EndOfBuffer;
    defer fbr.pos += len;
    return fbr.buf[fbr.pos..][0..len];
}

pub fn readBytesTo(fbr: *FixedBufferReader, comptime sentinel: u8) Error![:sentinel]const u8 {
    const end = @call(.always_inline, std.mem.indexOfScalarPos, .{
        u8,
        fbr.buf,
        fbr.pos,
        sentinel,
    }) orelse return error.EndOfBuffer;
    defer fbr.pos = end + 1;
    return fbr.buf[fbr.pos..end :sentinel];
}
//! Cross-platform abstraction for loading debug information into an in-memory
//! format that supports queries such as "what is the source location of this
//! virtual memory address?"
//!
//! Unlike `std.debug.SelfInfo`, this API does not assume the debug information
//! in question happens to match the host CPU architecture, OS, or other target
//! properties.

const std = @import("../std.zig");
const Allocator = std.mem.Allocator;
const Path = std.Build.Cache.Path;
const Dwarf = std.debug.Dwarf;
const assert = std.debug.assert;
const Coverage = std.debug.Coverage;
const SourceLocation = std.debug.Coverage.SourceLocation;

const Info = @This();

/// Sorted by key, ascending.
address_map: std.AutoArrayHashMapUnmanaged(u64, Dwarf.ElfModule),
/// Externally managed, outlives this `Info` instance.
coverage: *Coverage,

pub const LoadError = Dwarf.ElfModule.LoadError;

pub fn load(gpa: Allocator, path: Path, coverage: *Coverage) LoadError!Info {
    var sections: Dwarf.SectionArray = Dwarf.null_section_array;
    var elf_module = try Dwarf.ElfModule.loadPath(gpa, path, null, null, &sections, null);
    try elf_module.dwarf.populateRanges(gpa);
    var info: Info = .{
        .address_map = .{},
        .coverage = coverage,
    };
    try info.address_map.put(gpa, elf_module.base_address, elf_module);
    return info;
}

pub fn deinit(info: *Info, gpa: Allocator) void {
    for (info.address_map.values()) |*elf_module| {
        elf_module.dwarf.deinit(gpa);
    }
    info.address_map.deinit(gpa);
    info.* = undefined;
}

pub const ResolveAddressesError = Coverage.ResolveAddressesDwarfError;

/// Given an array of virtual memory addresses, sorted ascending, outputs a
/// corresponding array of source locations.
pub fn resolveAddresses(
    info: *Info,
    gpa: Allocator,
    /// Asserts the addresses are in ascending order.
    sorted_pc_addrs: []const u64,
    /// Asserts its length equals length of `sorted_pc_addrs`.
    output: []SourceLocation,
) ResolveAddressesError!void {
    assert(sorted_pc_addrs.len == output.len);
    if (info.address_map.entries.len != 1) @panic("TODO");
    const elf_module = &info.address_map.values()[0];
    return info.coverage.resolveAddressesDwarf(gpa, sorted_pc_addrs, output, &elf_module.dwarf);
}
//! Reads memory from any address of the current location using OS-specific
//! syscalls, bypassing memory page protection. Useful for stack unwinding.

const builtin = @import("builtin");
const native_os = builtin.os.tag;

const std = @import("../std.zig");
const posix = std.posix;
const File = std.fs.File;
const page_size_min = std.heap.page_size_min;

const MemoryAccessor = @This();

var cached_pid: posix.pid_t = -1;

mem: switch (native_os) {
    .linux => File,
    else => void,
},

pub const init: MemoryAccessor = .{
    .mem = switch (native_os) {
        .linux => .{ .handle = -1 },
        else => {},
    },
};

pub fn deinit(ma: *MemoryAccessor) void {
    switch (native_os) {
        .linux => switch (ma.mem.handle) {
            -2, -1 => {},
            else => ma.mem.close(),
        },
        else => {},
    }
    ma.* = undefined;
}

fn read(ma: *MemoryAccessor, address: usize, buf: []u8) bool {
    switch (native_os) {
        .linux => while (true) switch (ma.mem.handle) {
            -2 => break,
            -1 => {
                const linux = std.os.linux;
                const pid = switch (@atomicLoad(posix.pid_t, &cached_pid, .monotonic)) {
                    -1 => pid: {
                        const pid = linux.getpid();
                        @atomicStore(posix.pid_t, &cached_pid, pid, .monotonic);
                        break :pid pid;
                    },
                    else => |pid| pid,
                };
                const bytes_read = linux.process_vm_readv(
                    pid,
                    &.{.{ .base = buf.ptr, .len = buf.len }},
                    &.{.{ .base = @ptrFromInt(address), .len = buf.len }},
                    0,
                );
                switch (linux.E.init(bytes_read)) {
                    .SUCCESS => return bytes_read == buf.len,
                    .FAULT => return false,
                    .INVAL, .SRCH => unreachable, // own pid is always valid
                    .PERM => {}, // Known to happen in containers.
                    .NOMEM => {},
                    .NOSYS => {}, // QEMU is known not to implement this syscall.
                    else => unreachable, // unexpected
                }
                var path_buf: [
                    std.fmt.count("/proc/{d}/mem", .{std.math.minInt(posix.pid_t)})
                ]u8 = undefined;
                const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/mem", .{pid}) catch
                    unreachable;
                ma.mem = std.fs.openFileAbsolute(path, .{}) catch {
                    ma.mem.handle = -2;
                    break;
                };
            },
            else => return (ma.mem.pread(buf, address) catch return false) == buf.len,
        },
        else => {},
    }
    if (!isValidMemory(address)) return false;
    @memcpy(buf, @as([*]const u8, @ptrFromInt(address)));
    return true;
}

pub fn load(ma: *MemoryAccessor, comptime Type: type, address: usize) ?Type {
    var result: Type = undefined;
    return if (ma.read(address, std.mem.asBytes(&result))) result else null;
}

pub fn isValidMemory(address: usize) bool {
    // We are unable to determine validity of memory for freestanding targets
    if (native_os == .freestanding or native_os == .other or native_os == .uefi) return true;

    const page_size = std.heap.pageSize();
    const aligned_address = address & ~(page_size - 1);
    if (aligned_address == 0) return false;
    const aligned_memory = @as([*]align(page_size_min) u8, @ptrFromInt(aligned_address))[0..page_size];

    if (native_os == .windows) {
        const windows = std.os.windows;

        var memory_info: windows.MEMORY_BASIC_INFORMATION = undefined;

        // The only error this function can throw is ERROR_INVALID_PARAMETER.
        // supply an address that invalid i'll be thrown.
        const rc = windows.VirtualQuery(@ptrCast(aligned_memory), &memory_info, aligned_memory.len) catch {
            return false;
        };

        // Result code has to be bigger than zero (number of bytes written)
        if (rc == 0) {
            return false;
        }

        // Free pages cannot be read, they are unmapped
        if (memory_info.State == windows.MEM_FREE) {
            return false;
        }

        return true;
    } else if (have_msync) {
        posix.msync(aligned_memory, posix.MSF.ASYNC) catch |err| {
            switch (err) {
                error.UnmappedMemory => return false,
                else => unreachable,
            }
        };

        return true;
    } else {
        // We are unable to determine validity of memory on this target.
        return true;
    }
}

const have_msync = switch (native_os) {
    .wasi, .emscripten, .windows => false,
    else => true,
};
//! This namespace can be used with `pub const panic = std.debug.no_panic;` in the root file.
//! It emits as little code as possible, for testing purposes.
//!
//! For a functional alternative, see `std.debug.FullPanic`.

const std = @import("../std.zig");

pub fn call(_: []const u8, _: ?usize) noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn sentinelMismatch(_: anytype, _: anytype) noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn unwrapError(_: anyerror) noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn outOfBounds(_: usize, _: usize) noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn startGreaterThanEnd(_: usize, _: usize) noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn inactiveUnionField(_: anytype, _: anytype) noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn sliceCastLenRemainder(_: usize) noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn reachedUnreachable() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn unwrapNull() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn castToNull() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn incorrectAlignment() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn invalidErrorCode() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn castTruncatedData() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn negativeToUnsigned() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn integerOverflow() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn shlOverflow() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn shrOverflow() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn divideByZero() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn exactDivisionRemainder() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn integerPartOutOfBounds() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn corruptSwitch() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn shiftRhsTooBig() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn invalidEnumValue() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn forLenMismatch() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn memcpyLenMismatch() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn memcpyAlias() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn memmoveLenMismatch() noreturn {
    @branchHint(.cold);
    @trap();
}

pub fn noreturnReturned() noreturn {
    @branchHint(.cold);
    @trap();
}
const std = @import("../std.zig");
const File = std.fs.File;
const Allocator = std.mem.Allocator;
const pdb = std.pdb;

const Pdb = @This();

in_file: File,
msf: Msf,
allocator: Allocator,
string_table: ?*MsfStream,
dbi: ?*MsfStream,
modules: []Module,
sect_contribs: []pdb.SectionContribEntry,
guid: [16]u8,
age: u32,

pub const Module = struct {
    mod_info: pdb.ModInfo,
    module_name: []u8,
    obj_file_name: []u8,
    // The fields below are filled on demand.
    populated: bool,
    symbols: []u8,
    subsect_info: []u8,
    checksum_offset: ?usize,

    pub fn deinit(self: *Module, allocator: Allocator) void {
        allocator.free(self.module_name);
        allocator.free(self.obj_file_name);
        if (self.populated) {
            allocator.free(self.symbols);
            allocator.free(self.subsect_info);
        }
    }
};

pub fn init(allocator: Allocator, path: []const u8) !Pdb {
    const file = try std.fs.cwd().openFile(path, .{});
    errdefer file.close();

    return .{
        .in_file = file,
        .allocator = allocator,
        .string_table = null,
        .dbi = null,
        .msf = try Msf.init(allocator, file),
        .modules = &[_]Module{},
        .sect_contribs = &[_]pdb.SectionContribEntry{},
        .guid = undefined,
        .age = undefined,
    };
}

pub fn deinit(self: *Pdb) void {
    self.in_file.close();
    self.msf.deinit(self.allocator);
    for (self.modules) |*module| {
        module.deinit(self.allocator);
    }
    self.allocator.free(self.modules);
    self.allocator.free(self.sect_contribs);
}

pub fn parseDbiStream(self: *Pdb) !void {
    var stream = self.getStream(pdb.StreamType.dbi) orelse
        return error.InvalidDebugInfo;
    const reader = stream.reader();

    const header = try reader.readStruct(std.pdb.DbiStreamHeader);
    if (header.version_header != 19990903) // V70, only value observed by LLVM team
        return error.UnknownPDBVersion;
    // if (header.Age != age)
    //     return error.UnmatchingPDB;

    const mod_info_size = header.mod_info_size;
    const section_contrib_size = header.section_contribution_size;

    var modules = std.ArrayList(Module).init(self.allocator);
    errdefer modules.deinit();

    // Module Info Substream
    var mod_info_offset: usize = 0;
    while (mod_info_offset != mod_info_size) {
        const mod_info = try reader.readStruct(pdb.ModInfo);
        var this_record_len: usize = @sizeOf(pdb.ModInfo);

        const module_name = try reader.readUntilDelimiterAlloc(self.allocator, 0, 1024);
        errdefer self.allocator.free(module_name);
        this_record_len += module_name.len + 1;

        const obj_file_name = try reader.readUntilDelimiterAlloc(self.allocator, 0, 1024);
        errdefer self.allocator.free(obj_file_name);
        this_record_len += obj_file_name.len + 1;

        if (this_record_len % 4 != 0) {
            const round_to_next_4 = (this_record_len | 0x3) + 1;
            const march_forward_bytes = round_to_next_4 - this_record_len;
            try stream.seekBy(@as(isize, @intCast(march_forward_bytes)));
            this_record_len += march_forward_bytes;
        }

        try modules.append(Module{
            .mod_info = mod_info,
            .module_name = module_name,
            .obj_file_name = obj_file_name,

            .populated = false,
            .symbols = undefined,
            .subsect_info = undefined,
            .checksum_offset = null,
        });

        mod_info_offset += this_record_len;
        if (mod_info_offset > mod_info_size)
            return error.InvalidDebugInfo;
    }

    // Section Contribution Substream
    var sect_contribs = std.ArrayList(pdb.SectionContribEntry).init(self.allocator);
    errdefer sect_contribs.deinit();

    var sect_cont_offset: usize = 0;
    if (section_contrib_size != 0) {
        const version = reader.readEnum(std.pdb.SectionContrSubstreamVersion, .little) catch |err| switch (err) {
            error.InvalidValue => return error.InvalidDebugInfo,
            else => |e| return e,
        };
        _ = version;
        sect_cont_offset += @sizeOf(u32);
    }
    while (sect_cont_offset != section_contrib_size) {
        const entry = try sect_contribs.addOne();
        entry.* = try reader.readStruct(pdb.SectionContribEntry);
        sect_cont_offset += @sizeOf(pdb.SectionContribEntry);

        if (sect_cont_offset > section_contrib_size)
            return error.InvalidDebugInfo;
    }

    self.modules = try modules.toOwnedSlice();
    self.sect_contribs = try sect_contribs.toOwnedSlice();
}

pub fn parseInfoStream(self: *Pdb) !void {
    var stream = self.getStream(pdb.StreamType.pdb) orelse
        return error.InvalidDebugInfo;
    const reader = stream.reader();

    // Parse the InfoStreamHeader.
    const version = try reader.readInt(u32, .little);
    const signature = try reader.readInt(u32, .little);
    _ = signature;
    const age = try reader.readInt(u32, .little);
    const guid = try reader.readBytesNoEof(16);

    if (version != 20000404) // VC70, only value observed by LLVM team
        return error.UnknownPDBVersion;

    self.guid = guid;
    self.age = age;

    // Find the string table.
    const string_table_index = str_tab_index: {
        const name_bytes_len = try reader.readInt(u32, .little);
        const name_bytes = try self.allocator.alloc(u8, name_bytes_len);
        defer self.allocator.free(name_bytes);
        try reader.readNoEof(name_bytes);

        const HashTableHeader = extern struct {
            size: u32,
            capacity: u32,

            fn maxLoad(cap: u32) u32 {
                return cap * 2 / 3 + 1;
            }
        };
        const hash_tbl_hdr = try reader.readStruct(HashTableHeader);
        if (hash_tbl_hdr.capacity == 0)
            return error.InvalidDebugInfo;

        if (hash_tbl_hdr.size > HashTableHeader.maxLoad(hash_tbl_hdr.capacity))
            return error.InvalidDebugInfo;

        const present = try readSparseBitVector(&reader, self.allocator);
        defer self.allocator.free(present);
        if (present.len != hash_tbl_hdr.size)
            return error.InvalidDebugInfo;
        const deleted = try readSparseBitVector(&reader, self.allocator);
        defer self.allocator.free(deleted);

        for (present) |_| {
            const name_offset = try reader.readInt(u32, .little);
            const name_index = try reader.readInt(u32, .little);
            if (name_offset > name_bytes.len)
                return error.InvalidDebugInfo;
            const name = std.mem.sliceTo(name_bytes[name_offset..], 0);
            if (std.mem.eql(u8, name, "/names")) {
                break :str_tab_index name_index;
            }
        }
        return error.MissingDebugInfo;
    };

    self.string_table = self.getStreamById(string_table_index) orelse
        return error.MissingDebugInfo;
}

pub fn getSymbolName(self: *Pdb, module: *Module, address: u64) ?[]const u8 {
    _ = self;
    std.debug.assert(module.populated);

    var symbol_i: usize = 0;
    while (symbol_i != module.symbols.len) {
        const prefix: *align(1) pdb.RecordPrefix = @ptrCast(&module.symbols[symbol_i]);
        if (prefix.record_len < 2)
            return null;
        switch (prefix.record_kind) {
            .lproc32, .gproc32 => {
                const proc_sym: *align(1) pdb.ProcSym = @ptrCast(&module.symbols[symbol_i + @sizeOf(pdb.RecordPrefix)]);
                if (address >= proc_sym.code_offset and address < proc_sym.code_offset + proc_sym.code_size) {
                    return std.mem.sliceTo(@as([*:0]u8, @ptrCast(&proc_sym.name[0])), 0);
                }
            },
            else => {},
        }
        symbol_i += prefix.record_len + @sizeOf(u16);
    }

    return null;
}

pub fn getLineNumberInfo(self: *Pdb, module: *Module, address: u64) !std.debug.SourceLocation {
    std.debug.assert(module.populated);
    const subsect_info = module.subsect_info;

    var sect_offset: usize = 0;
    var skip_len: usize = undefined;
    const checksum_offset = module.checksum_offset orelse return error.MissingDebugInfo;
    while (sect_offset != subsect_info.len) : (sect_offset += skip_len) {
        const subsect_hdr: *align(1) pdb.DebugSubsectionHeader = @ptrCast(&subsect_info[sect_offset]);
        skip_len = subsect_hdr.length;
        sect_offset += @sizeOf(pdb.DebugSubsectionHeader);

        switch (subsect_hdr.kind) {
            .lines => {
                var line_index = sect_offset;

                const line_hdr: *align(1) pdb.LineFragmentHeader = @ptrCast(&subsect_info[line_index]);
                if (line_hdr.reloc_segment == 0)
                    return error.MissingDebugInfo;
                line_index += @sizeOf(pdb.LineFragmentHeader);
                const frag_vaddr_start = line_hdr.reloc_offset;
                const frag_vaddr_end = frag_vaddr_start + line_hdr.code_size;

                if (address >= frag_vaddr_start and address < frag_vaddr_end) {
                    // There is an unknown number of LineBlockFragmentHeaders (and their accompanying line and column records)
                    // from now on. We will iterate through them, and eventually find a SourceLocation that we're interested in,
                    // breaking out to :subsections. If not, we will make sure to not read anything outside of this subsection.
                    const subsection_end_index = sect_offset + subsect_hdr.length;

                    while (line_index < subsection_end_index) {
                        const block_hdr: *align(1) pdb.LineBlockFragmentHeader = @ptrCast(&subsect_info[line_index]);
                        line_index += @sizeOf(pdb.LineBlockFragmentHeader);
                        const start_line_index = line_index;

                        const has_column = line_hdr.flags.have_columns;

                        // All line entries are stored inside their line block by ascending start address.
                        // Heuristic: we want to find the last line entry
                        // that has a vaddr_start <= address.
                        // This is done with a simple linear search.
                        var line_i: u32 = 0;
                        while (line_i < block_hdr.num_lines) : (line_i += 1) {
                            const line_num_entry: *align(1) pdb.LineNumberEntry = @ptrCast(&subsect_info[line_index]);
                            line_index += @sizeOf(pdb.LineNumberEntry);

                            const vaddr_start = frag_vaddr_start + line_num_entry.offset;
                            if (address < vaddr_start) {
                                break;
                            }
                        }

                        // line_i == 0 would mean that no matching pdb.LineNumberEntry was found.
                        if (line_i > 0) {
                            const subsect_index = checksum_offset + block_hdr.name_index;
                            const chksum_hdr: *align(1) pdb.FileChecksumEntryHeader = @ptrCast(&module.subsect_info[subsect_index]);
                            const strtab_offset = @sizeOf(pdb.StringTableHeader) + chksum_hdr.file_name_offset;
                            try self.string_table.?.seekTo(strtab_offset);
                            const source_file_name = try self.string_table.?.reader().readUntilDelimiterAlloc(self.allocator, 0, 1024);

                            const line_entry_idx = line_i - 1;

                            const column = if (has_column) blk: {
                                const start_col_index = start_line_index + @sizeOf(pdb.LineNumberEntry) * block_hdr.num_lines;
                                const col_index = start_col_index + @sizeOf(pdb.ColumnNumberEntry) * line_entry_idx;
                                const col_num_entry: *align(1) pdb.ColumnNumberEntry = @ptrCast(&subsect_info[col_index]);
                                break :blk col_num_entry.start_column;
                            } else 0;

                            const found_line_index = start_line_index + line_entry_idx * @sizeOf(pdb.LineNumberEntry);
                            const line_num_entry: *align(1) pdb.LineNumberEntry = @ptrCast(&subsect_info[found_line_index]);

                            return .{
                                .file_name = source_file_name,
                                .line = line_num_entry.flags.start,
                                .column = column,
                            };
                        }
                    }

                    // Checking that we are not reading garbage after the (possibly) multiple block fragments.
                    if (line_index != subsection_end_index) {
                        return error.InvalidDebugInfo;
                    }
                }
            },
            else => {},
        }

        if (sect_offset > subsect_info.len)
            return error.InvalidDebugInfo;
    }

    return error.MissingDebugInfo;
}

pub fn getModule(self: *Pdb, index: usize) !?*Module {
    if (index >= self.modules.len)
        return null;

    const mod = &self.modules[index];
    if (mod.populated)
        return mod;

    // At most one can be non-zero.
    if (mod.mod_info.c11_byte_size != 0 and mod.mod_info.c13_byte_size != 0)
        return error.InvalidDebugInfo;
    if (mod.mod_info.c13_byte_size == 0)
        return error.InvalidDebugInfo;

    const stream = self.getStreamById(mod.mod_info.module_sym_stream) orelse
        return error.MissingDebugInfo;
    const reader = stream.reader();

    const signature = try reader.readInt(u32, .little);
    if (signature != 4)
        return error.InvalidDebugInfo;

    mod.symbols = try self.allocator.alloc(u8, mod.mod_info.sym_byte_size - 4);
    errdefer self.allocator.free(mod.symbols);
    try reader.readNoEof(mod.symbols);

    mod.subsect_info = try self.allocator.alloc(u8, mod.mod_info.c13_byte_size);
    errdefer self.allocator.free(mod.subsect_info);
    try reader.readNoEof(mod.subsect_info);

    var sect_offset: usize = 0;
    var skip_len: usize = undefined;
    while (sect_offset != mod.subsect_info.len) : (sect_offset += skip_len) {
        const subsect_hdr: *align(1) pdb.DebugSubsectionHeader = @ptrCast(&mod.subsect_info[sect_offset]);
        skip_len = subsect_hdr.length;
        sect_offset += @sizeOf(pdb.DebugSubsectionHeader);

        switch (subsect_hdr.kind) {
            .file_checksums => {
                mod.checksum_offset = sect_offset;
                break;
            },
            else => {},
        }

        if (sect_offset > mod.subsect_info.len)
            return error.InvalidDebugInfo;
    }

    mod.populated = true;
    return mod;
}

pub fn getStreamById(self: *Pdb, id: u32) ?*MsfStream {
    if (id >= self.msf.streams.len)
        return null;
    return &self.msf.streams[id];
}

pub fn getStream(self: *Pdb, stream: pdb.StreamType) ?*MsfStream {
    const id = @intFromEnum(stream);
    return self.getStreamById(id);
}

/// https://llvm.org/docs/PDB/MsfFile.html
const Msf = struct {
    directory: MsfStream,
    streams: []MsfStream,

    fn init(allocator: Allocator, file: File) !Msf {
        const in = file.reader();

        const superblock = try in.readStruct(pdb.SuperBlock);

        // Sanity checks
        if (!std.mem.eql(u8, &superblock.file_magic, pdb.SuperBlock.expect_magic))
            return error.InvalidDebugInfo;
        if (superblock.free_block_map_block != 1 and superblock.free_block_map_block != 2)
            return error.InvalidDebugInfo;
        const file_len = try file.getEndPos();
        if (superblock.num_blocks * superblock.block_size != file_len)
            return error.InvalidDebugInfo;
        switch (superblock.block_size) {
            // llvm only supports 4096 but we can handle any of these values
            512, 1024, 2048, 4096 => {},
            else => return error.InvalidDebugInfo,
        }

        const dir_block_count = blockCountFromSize(superblock.num_directory_bytes, superblock.block_size);
        if (dir_block_count > superblock.block_size / @sizeOf(u32))
            return error.UnhandledBigDirectoryStream; // cf. BlockMapAddr comment.

        try file.seekTo(superblock.block_size * superblock.block_map_addr);
        const dir_blocks = try allocator.alloc(u32, dir_block_count);
        for (dir_blocks) |*b| {
            b.* = try in.readInt(u32, .little);
        }
        var directory = MsfStream.init(
            superblock.block_size,
            file,
            dir_blocks,
        );

        const begin = directory.pos;
        const stream_count = try directory.reader().readInt(u32, .little);
        const stream_sizes = try allocator.alloc(u32, stream_count);
        defer allocator.free(stream_sizes);

        // Microsoft's implementation uses @as(u32, -1) for inexistent streams.
        // These streams are not used, but still participate in the file
        // and must be taken into account when resolving stream indices.
        const Nil = 0xFFFFFFFF;
        for (stream_sizes) |*s| {
            const size = try directory.reader().readInt(u32, .little);
            s.* = if (size == Nil) 0 else blockCountFromSize(size, superblock.block_size);
        }

        const streams = try allocator.alloc(MsfStream, stream_count);
        for (streams, 0..) |*stream, i| {
            const size = stream_sizes[i];
            if (size == 0) {
                stream.* = MsfStream{
                    .blocks = &[_]u32{},
                };
            } else {
                var blocks = try allocator.alloc(u32, size);
                var j: u32 = 0;
                while (j < size) : (j += 1) {
                    const block_id = try directory.reader().readInt(u32, .little);
                    const n = (block_id % superblock.block_size);
                    // 0 is for pdb.SuperBlock, 1 and 2 for FPMs.
                    if (block_id == 0 or n == 1 or n == 2 or block_id * superblock.block_size > file_len)
                        return error.InvalidBlockIndex;
                    blocks[j] = block_id;
                }

                stream.* = MsfStream.init(
                    superblock.block_size,
                    file,
                    blocks,
                );
            }
        }

        const end = directory.pos;
        if (end - begin != superblock.num_directory_bytes)
            return error.InvalidStreamDirectory;

        return Msf{
            .directory = directory,
            .streams = streams,
        };
    }

    fn deinit(self: *Msf, allocator: Allocator) void {
        allocator.free(self.directory.blocks);
        for (self.streams) |*stream| {
            allocator.free(stream.blocks);
        }
        allocator.free(self.streams);
    }
};

const MsfStream = struct {
    in_file: File = undefined,
    pos: u64 = undefined,
    blocks: []u32 = undefined,
    block_size: u32 = undefined,

    pub const Error = @typeInfo(@typeInfo(@TypeOf(read)).@"fn".return_type.?).error_union.error_set;

    fn init(block_size: u32, file: File, blocks: []u32) MsfStream {
        const stream = MsfStream{
            .in_file = file,
            .pos = 0,
            .blocks = blocks,
            .block_size = block_size,
        };

        return stream;
    }

    fn read(self: *MsfStream, buffer: []u8) !usize {
        var block_id = @as(usize, @intCast(self.pos / self.block_size));
        if (block_id >= self.blocks.len) return 0; // End of Stream
        var block = self.blocks[block_id];
        var offset = self.pos % self.block_size;

        try self.in_file.seekTo(block * self.block_size + offset);
        const in = self.in_file.reader();

        var size: usize = 0;
        var rem_buffer = buffer;
        while (size < buffer.len) {
            const size_to_read = @min(self.block_size - offset, rem_buffer.len);
            size += try in.read(rem_buffer[0..size_to_read]);
            rem_buffer = buffer[size..];
            offset += size_to_read;

            // If we're at the end of a block, go to the next one.
            if (offset == self.block_size) {
                offset = 0;
                block_id += 1;
                if (block_id >= self.blocks.len) break; // End of Stream
                block = self.blocks[block_id];
                try self.in_file.seekTo(block * self.block_size);
            }
        }

        self.pos += buffer.len;
        return buffer.len;
    }

    pub fn seekBy(self: *MsfStream, len: i64) !void {
        self.pos = @as(u64, @intCast(@as(i64, @intCast(self.pos)) + len));
        if (self.pos >= self.blocks.len * self.block_size)
            return error.EOF;
    }

    pub fn seekTo(self: *MsfStream, len: u64) !void {
        self.pos = len;
        if (self.pos >= self.blocks.len * self.block_size)
            return error.EOF;
    }

    fn getSize(self: *const MsfStream) u64 {
        return self.blocks.len * self.block_size;
    }

    fn getFilePos(self: MsfStream) u64 {
        const block_id = self.pos / self.block_size;
        const block = self.blocks[block_id];
        const offset = self.pos % self.block_size;

        return block * self.block_size + offset;
    }

    pub fn reader(self: *MsfStream) std.io.Reader(*MsfStream, Error, read) {
        return .{ .context = self };
    }
};

fn readSparseBitVector(stream: anytype, allocator: Allocator) ![]u32 {
    const num_words = try stream.readInt(u32, .little);
    var list = std.ArrayList(u32).init(allocator);
    errdefer list.deinit();
    var word_i: u32 = 0;
    while (word_i != num_words) : (word_i += 1) {
        const word = try stream.readInt(u32, .little);
        var bit_i: u5 = 0;
        while (true) : (bit_i += 1) {
            if (word & (@as(u32, 1) << bit_i) != 0) {
                try list.append(word_i * 32 + bit_i);
            }
            if (bit_i == std.math.maxInt(u5)) break;
        }
    }
    return try list.toOwnedSlice();
}

fn blockCountFromSize(size: u32, block_size: u32) u32 {
    return (size + block_size - 1) / block_size;
}
//! Cross-platform abstraction for this binary's own debug information, with a
//! goal of minimal code bloat and compilation speed penalty.

const builtin = @import("builtin");
const native_os = builtin.os.tag;
const native_endian = native_arch.endian();
const native_arch = builtin.cpu.arch;

const std = @import("../std.zig");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const windows = std.os.windows;
const macho = std.macho;
const fs = std.fs;
const coff = std.coff;
const pdb = std.pdb;
const assert = std.debug.assert;
const posix = std.posix;
const elf = std.elf;
const Dwarf = std.debug.Dwarf;
const Pdb = std.debug.Pdb;
const File = std.fs.File;
const math = std.math;
const testing = std.testing;
const StackIterator = std.debug.StackIterator;
const regBytes = Dwarf.abi.regBytes;
const regValueNative = Dwarf.abi.regValueNative;

const SelfInfo = @This();

const root = @import("root");

allocator: Allocator,
address_map: std.AutoHashMap(usize, *Module),
modules: if (native_os == .windows) std.ArrayListUnmanaged(WindowsModule) else void,

pub const OpenError = error{
    MissingDebugInfo,
    UnsupportedOperatingSystem,
} || @typeInfo(@typeInfo(@TypeOf(SelfInfo.init)).@"fn".return_type.?).error_union.error_set;

pub fn open(allocator: Allocator) OpenError!SelfInfo {
    nosuspend {
        if (builtin.strip_debug_info)
            return error.MissingDebugInfo;
        switch (native_os) {
            .linux,
            .freebsd,
            .netbsd,
            .dragonfly,
            .openbsd,
            .macos,
            .solaris,
            .illumos,
            .windows,
            => return try SelfInfo.init(allocator),
            else => return error.UnsupportedOperatingSystem,
        }
    }
}

pub fn init(allocator: Allocator) !SelfInfo {
    var debug_info: SelfInfo = .{
        .allocator = allocator,
        .address_map = std.AutoHashMap(usize, *Module).init(allocator),
        .modules = if (native_os == .windows) .{} else {},
    };

    if (native_os == .windows) {
        errdefer debug_info.modules.deinit(allocator);

        const handle = windows.kernel32.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE | windows.TH32CS_SNAPMODULE32, 0);
        if (handle == windows.INVALID_HANDLE_VALUE) {
            switch (windows.GetLastError()) {
                else => |err| return windows.unexpectedError(err),
            }
        }
        defer windows.CloseHandle(handle);

        var module_entry: windows.MODULEENTRY32 = undefined;
        module_entry.dwSize = @sizeOf(windows.MODULEENTRY32);
        if (windows.kernel32.Module32First(handle, &module_entry) == 0) {
            return error.MissingDebugInfo;
        }

        var module_valid = true;
        while (module_valid) {
            const module_info = try debug_info.modules.addOne(allocator);
            const name = allocator.dupe(u8, mem.sliceTo(&module_entry.szModule, 0)) catch &.{};
            errdefer allocator.free(name);

            module_info.* = .{
                .base_address = @intFromPtr(module_entry.modBaseAddr),
                .size = module_entry.modBaseSize,
                .name = name,
                .handle = module_entry.hModule,
            };

            module_valid = windows.kernel32.Module32Next(handle, &module_entry) == 1;
        }
    }

    return debug_info;
}

pub fn deinit(self: *SelfInfo) void {
    var it = self.address_map.iterator();
    while (it.next()) |entry| {
        const mdi = entry.value_ptr.*;
        mdi.deinit(self.allocator);
        self.allocator.destroy(mdi);
    }
    self.address_map.deinit();
    if (native_os == .windows) {
        for (self.modules.items) |module| {
            self.allocator.free(module.name);
            if (module.mapped_file) |mapped_file| mapped_file.deinit();
        }
        self.modules.deinit(self.allocator);
    }
}

pub fn getModuleForAddress(self: *SelfInfo, address: usize) !*Module {
    if (builtin.target.os.tag.isDarwin()) {
        return self.lookupModuleDyld(address);
    } else if (native_os == .windows) {
        return self.lookupModuleWin32(address);
    } else if (native_os == .haiku) {
        return self.lookupModuleHaiku(address);
    } else if (builtin.target.cpu.arch.isWasm()) {
        return self.lookupModuleWasm(address);
    } else {
        return self.lookupModuleDl(address);
    }
}

// Returns the module name for a given address.
// This can be called when getModuleForAddress fails, so implementations should provide
// a path that doesn't rely on any side-effects of a prior successful module lookup.
pub fn getModuleNameForAddress(self: *SelfInfo, address: usize) ?[]const u8 {
    if (builtin.target.os.tag.isDarwin()) {
        return self.lookupModuleNameDyld(address);
    } else if (native_os == .windows) {
        return self.lookupModuleNameWin32(address);
    } else if (native_os == .haiku) {
        return null;
    } else if (builtin.target.cpu.arch.isWasm()) {
        return null;
    } else {
        return self.lookupModuleNameDl(address);
    }
}

fn lookupModuleDyld(self: *SelfInfo, address: usize) !*Module {
    const image_count = std.c._dyld_image_count();

    var i: u32 = 0;
    while (i < image_count) : (i += 1) {
        const header = std.c._dyld_get_image_header(i) orelse continue;
        const base_address = @intFromPtr(header);
        if (address < base_address) continue;
        const vmaddr_slide = std.c._dyld_get_image_vmaddr_slide(i);

        var it = macho.LoadCommandIterator{
            .ncmds = header.ncmds,
            .buffer = @alignCast(@as(
                [*]u8,
                @ptrFromInt(@intFromPtr(header) + @sizeOf(macho.mach_header_64)),
            )[0..header.sizeofcmds]),
        };

        var unwind_info: ?[]const u8 = null;
        var eh_frame: ?[]const u8 = null;
        while (it.next()) |cmd| switch (cmd.cmd()) {
            .SEGMENT_64 => {
                const segment_cmd = cmd.cast(macho.segment_command_64).?;
                if (!mem.eql(u8, "__TEXT", segment_cmd.segName())) continue;

                const seg_start = segment_cmd.vmaddr + vmaddr_slide;
                const seg_end = seg_start + segment_cmd.vmsize;
                if (address >= seg_start and address < seg_end) {
                    if (self.address_map.get(base_address)) |obj_di| {
                        return obj_di;
                    }

                    for (cmd.getSections()) |sect| {
                        const sect_addr: usize = @intCast(sect.addr);
                        const sect_size: usize = @intCast(sect.size);
                        if (mem.eql(u8, "__unwind_info", sect.sectName())) {
                            unwind_info = @as([*]const u8, @ptrFromInt(sect_addr + vmaddr_slide))[0..sect_size];
                        } else if (mem.eql(u8, "__eh_frame", sect.sectName())) {
                            eh_frame = @as([*]const u8, @ptrFromInt(sect_addr + vmaddr_slide))[0..sect_size];
                        }
                    }

                    const obj_di = try self.allocator.create(Module);
                    errdefer self.allocator.destroy(obj_di);

                    const macho_path = mem.sliceTo(std.c._dyld_get_image_name(i), 0);
                    const macho_file = fs.cwd().openFile(macho_path, .{}) catch |err| switch (err) {
                        error.FileNotFound => return error.MissingDebugInfo,
                        else => return err,
                    };
                    obj_di.* = try readMachODebugInfo(self.allocator, macho_file);
                    obj_di.base_address = base_address;
                    obj_di.vmaddr_slide = vmaddr_slide;
                    obj_di.unwind_info = unwind_info;
                    obj_di.eh_frame = eh_frame;

                    try self.address_map.putNoClobber(base_address, obj_di);

                    return obj_di;
                }
            },
            else => {},
        };
    }

    return error.MissingDebugInfo;
}

fn lookupModuleNameDyld(self: *SelfInfo, address: usize) ?[]const u8 {
    _ = self;
    const image_count = std.c._dyld_image_count();

    var i: u32 = 0;
    while (i < image_count) : (i += 1) {
        const header = std.c._dyld_get_image_header(i) orelse continue;
        const base_address = @intFromPtr(header);
        if (address < base_address) continue;
        const vmaddr_slide = std.c._dyld_get_image_vmaddr_slide(i);

        var it = macho.LoadCommandIterator{
            .ncmds = header.ncmds,
            .buffer = @alignCast(@as(
                [*]u8,
                @ptrFromInt(@intFromPtr(header) + @sizeOf(macho.mach_header_64)),
            )[0..header.sizeofcmds]),
        };

        while (it.next()) |cmd| switch (cmd.cmd()) {
            .SEGMENT_64 => {
                const segment_cmd = cmd.cast(macho.segment_command_64).?;
                if (!mem.eql(u8, "__TEXT", segment_cmd.segName())) continue;

                const original_address = address - vmaddr_slide;
                const seg_start = segment_cmd.vmaddr;
                const seg_end = seg_start + segment_cmd.vmsize;
                if (original_address >= seg_start and original_address < seg_end) {
                    return fs.path.basename(mem.sliceTo(std.c._dyld_get_image_name(i), 0));
                }
            },
            else => {},
        };
    }

    return null;
}

fn lookupModuleWin32(self: *SelfInfo, address: usize) !*Module {
    for (self.modules.items) |*module| {
        if (address >= module.base_address and address < module.base_address + module.size) {
            if (self.address_map.get(module.base_address)) |obj_di| {
                return obj_di;
            }

            const obj_di = try self.allocator.create(Module);
            errdefer self.allocator.destroy(obj_di);

            const mapped_module = @as([*]const u8, @ptrFromInt(module.base_address))[0..module.size];
            var coff_obj = try coff.Coff.init(mapped_module, true);

            // The string table is not mapped into memory by the loader, so if a section name is in the
            // string table then we have to map the full image file from disk. This can happen when
            // a binary is produced with -gdwarf, since the section names are longer than 8 bytes.
            if (coff_obj.strtabRequired()) {
                var name_buffer: [windows.PATH_MAX_WIDE + 4:0]u16 = undefined;
                // openFileAbsoluteW requires the prefix to be present
                @memcpy(name_buffer[0..4], &[_]u16{ '\\', '?', '?', '\\' });

                const process_handle = windows.GetCurrentProcess();
                const len = windows.kernel32.GetModuleFileNameExW(
                    process_handle,
                    module.handle,
                    @ptrCast(&name_buffer[4]),
                    windows.PATH_MAX_WIDE,
                );

                if (len == 0) return error.MissingDebugInfo;
                const coff_file = fs.openFileAbsoluteW(name_buffer[0 .. len + 4 :0], .{}) catch |err| switch (err) {
                    error.FileNotFound => return error.MissingDebugInfo,
                    else => return err,
                };
                errdefer coff_file.close();

                var section_handle: windows.HANDLE = undefined;
                const create_section_rc = windows.ntdll.NtCreateSection(
                    &section_handle,
                    windows.STANDARD_RIGHTS_REQUIRED | windows.SECTION_QUERY | windows.SECTION_MAP_READ,
                    null,
                    null,
                    windows.PAGE_READONLY,
                    // The documentation states that if no AllocationAttribute is specified, then SEC_COMMIT is the default.
                    // In practice, this isn't the case and specifying 0 will result in INVALID_PARAMETER_6.
                    windows.SEC_COMMIT,
                    coff_file.handle,
                );
                if (create_section_rc != .SUCCESS) return error.MissingDebugInfo;
                errdefer windows.CloseHandle(section_handle);

                var coff_len: usize = 0;
                var base_ptr: usize = 0;
                const map_section_rc = windows.ntdll.NtMapViewOfSection(
                    section_handle,
                    process_handle,
                    @ptrCast(&base_ptr),
                    null,
                    0,
                    null,
                    &coff_len,
                    .ViewUnmap,
                    0,
                    windows.PAGE_READONLY,
                );
                if (map_section_rc != .SUCCESS) return error.MissingDebugInfo;
                errdefer assert(windows.ntdll.NtUnmapViewOfSection(process_handle, @ptrFromInt(base_ptr)) == .SUCCESS);

                const section_view = @as([*]const u8, @ptrFromInt(base_ptr))[0..coff_len];
                coff_obj = try coff.Coff.init(section_view, false);

                module.mapped_file = .{
                    .file = coff_file,
                    .section_handle = section_handle,
                    .section_view = section_view,
                };
            }
            errdefer if (module.mapped_file) |mapped_file| mapped_file.deinit();

            obj_di.* = try readCoffDebugInfo(self.allocator, &coff_obj);
            obj_di.base_address = module.base_address;

            try self.address_map.putNoClobber(module.base_address, obj_di);
            return obj_di;
        }
    }

    return error.MissingDebugInfo;
}

fn lookupModuleNameWin32(self: *SelfInfo, address: usize) ?[]const u8 {
    for (self.modules.items) |module| {
        if (address >= module.base_address and address < module.base_address + module.size) {
            return module.name;
        }
    }
    return null;
}

fn lookupModuleNameDl(self: *SelfInfo, address: usize) ?[]const u8 {
    _ = self;

    var ctx: struct {
        // Input
        address: usize,
        // Output
        name: []const u8 = "",
    } = .{ .address = address };
    const CtxTy = @TypeOf(ctx);

    if (posix.dl_iterate_phdr(&ctx, error{Found}, struct {
        fn callback(info: *posix.dl_phdr_info, size: usize, context: *CtxTy) !void {
            _ = size;
            if (context.address < info.addr) return;
            const phdrs = info.phdr[0..info.phnum];
            for (phdrs) |*phdr| {
                if (phdr.p_type != elf.PT_LOAD) continue;

                const seg_start = info.addr +% phdr.p_vaddr;
                const seg_end = seg_start + phdr.p_memsz;
                if (context.address >= seg_start and context.address < seg_end) {
                    context.name = mem.sliceTo(info.name, 0) orelse "";
                    break;
                }
            } else return;

            return error.Found;
        }
    }.callback)) {
        return null;
    } else |err| switch (err) {
        error.Found => return fs.path.basename(ctx.name),
    }

    return null;
}

fn lookupModuleDl(self: *SelfInfo, address: usize) !*Module {
    var ctx: struct {
        // Input
        address: usize,
        // Output
        base_address: usize = undefined,
        name: []const u8 = undefined,
        build_id: ?[]const u8 = null,
        gnu_eh_frame: ?[]const u8 = null,
    } = .{ .address = address };
    const CtxTy = @TypeOf(ctx);

    if (posix.dl_iterate_phdr(&ctx, error{Found}, struct {
        fn callback(info: *posix.dl_phdr_info, size: usize, context: *CtxTy) !void {
            _ = size;
            // The base address is too high
            if (context.address < info.addr)
                return;

            const phdrs = info.phdr[0..info.phnum];
            for (phdrs) |*phdr| {
                if (phdr.p_type != elf.PT_LOAD) continue;

                // Overflowing addition is used to handle the case of VSDOs having a p_vaddr = 0xffffffffff700000
                const seg_start = info.addr +% phdr.p_vaddr;
                const seg_end = seg_start + phdr.p_memsz;
                if (context.address >= seg_start and context.address < seg_end) {
                    // Android libc uses NULL instead of an empty string to mark the
                    // main program
                    context.name = mem.sliceTo(info.name, 0) orelse "";
                    context.base_address = info.addr;
                    break;
                }
            } else return;

            for (info.phdr[0..info.phnum]) |phdr| {
                switch (phdr.p_type) {
                    elf.PT_NOTE => {
                        // Look for .note.gnu.build-id
                        const note_bytes = @as([*]const u8, @ptrFromInt(info.addr + phdr.p_vaddr))[0..phdr.p_memsz];
                        const name_size = mem.readInt(u32, note_bytes[0..4], native_endian);
                        if (name_size != 4) continue;
                        const desc_size = mem.readInt(u32, note_bytes[4..8], native_endian);
                        const note_type = mem.readInt(u32, note_bytes[8..12], native_endian);
                        if (note_type != elf.NT_GNU_BUILD_ID) continue;
                        if (!mem.eql(u8, "GNU\x00", note_bytes[12..16])) continue;
                        context.build_id = note_bytes[16..][0..desc_size];
                    },
                    elf.PT_GNU_EH_FRAME => {
                        context.gnu_eh_frame = @as([*]const u8, @ptrFromInt(info.addr + phdr.p_vaddr))[0..phdr.p_memsz];
                    },
                    else => {},
                }
            }

            // Stop the iteration
            return error.Found;
        }
    }.callback)) {
        return error.MissingDebugInfo;
    } else |err| switch (err) {
        error.Found => {},
    }

    if (self.address_map.get(ctx.base_address)) |obj_di| {
        return obj_di;
    }

    const obj_di = try self.allocator.create(Module);
    errdefer self.allocator.destroy(obj_di);

    var sections: Dwarf.SectionArray = Dwarf.null_section_array;
    if (ctx.gnu_eh_frame) |eh_frame_hdr| {
        // This is a special case - pointer offsets inside .eh_frame_hdr
        // are encoded relative to its base address, so we must use the
        // version that is already memory mapped, and not the one that
        // will be mapped separately from the ELF file.
        sections[@intFromEnum(Dwarf.Section.Id.eh_frame_hdr)] = .{
            .data = eh_frame_hdr,
            .owned = false,
        };
    }

    obj_di.* = try readElfDebugInfo(self.allocator, if (ctx.name.len > 0) ctx.name else null, ctx.build_id, null, &sections, null);
    obj_di.base_address = ctx.base_address;

    // Missing unwind info isn't treated as a failure, as the unwinder will fall back to FP-based unwinding
    obj_di.dwarf.scanAllUnwindInfo(self.allocator, ctx.base_address) catch {};

    try self.address_map.putNoClobber(ctx.base_address, obj_di);

    return obj_di;
}

fn lookupModuleHaiku(self: *SelfInfo, address: usize) !*Module {
    _ = self;
    _ = address;
    @panic("TODO implement lookup module for Haiku");
}

fn lookupModuleWasm(self: *SelfInfo, address: usize) !*Module {
    _ = self;
    _ = address;
    @panic("TODO implement lookup module for Wasm");
}

pub const Module = switch (native_os) {
    .macos, .ios, .watchos, .tvos, .visionos => struct {
        base_address: usize,
        vmaddr_slide: usize,
        mapped_memory: []align(std.heap.page_size_min) const u8,
        symbols: []const MachoSymbol,
        strings: [:0]const u8,
        ofiles: OFileTable,

        // Backed by the in-memory sections mapped by the loader
        unwind_info: ?[]const u8 = null,
        eh_frame: ?[]const u8 = null,

        const OFileTable = std.StringHashMap(OFileInfo);
        const OFileInfo = struct {
            di: Dwarf,
            addr_table: std.StringHashMap(u64),
        };

        pub fn deinit(self: *@This(), allocator: Allocator) void {
            var it = self.ofiles.iterator();
            while (it.next()) |entry| {
                const ofile = entry.value_ptr;
                ofile.di.deinit(allocator);
                ofile.addr_table.deinit();
            }
            self.ofiles.deinit();
            allocator.free(self.symbols);
            posix.munmap(self.mapped_memory);
        }

        fn loadOFile(self: *@This(), allocator: Allocator, o_file_path: []const u8) !*OFileInfo {
            const o_file = try fs.cwd().openFile(o_file_path, .{});
            const mapped_mem = try mapWholeFile(o_file);

            const hdr: *const macho.mach_header_64 = @ptrCast(@alignCast(mapped_mem.ptr));
            if (hdr.magic != std.macho.MH_MAGIC_64)
                return error.InvalidDebugInfo;

            var segcmd: ?macho.LoadCommandIterator.LoadCommand = null;
            var symtabcmd: ?macho.symtab_command = null;
            var it = macho.LoadCommandIterator{
                .ncmds = hdr.ncmds,
                .buffer = mapped_mem[@sizeOf(macho.mach_header_64)..][0..hdr.sizeofcmds],
            };
            while (it.next()) |cmd| switch (cmd.cmd()) {
                .SEGMENT_64 => segcmd = cmd,
                .SYMTAB => symtabcmd = cmd.cast(macho.symtab_command).?,
                else => {},
            };

            if (segcmd == null or symtabcmd == null) return error.MissingDebugInfo;

            // Parse symbols
            const strtab = @as(
                [*]const u8,
                @ptrCast(&mapped_mem[symtabcmd.?.stroff]),
            )[0 .. symtabcmd.?.strsize - 1 :0];
            const symtab = @as(
                [*]const macho.nlist_64,
                @ptrCast(@alignCast(&mapped_mem[symtabcmd.?.symoff])),
            )[0..symtabcmd.?.nsyms];

            // TODO handle tentative (common) symbols
            var addr_table = std.StringHashMap(u64).init(allocator);
            try addr_table.ensureTotalCapacity(@as(u32, @intCast(symtab.len)));
            for (symtab) |sym| {
                if (sym.n_strx == 0) continue;
                if (sym.undf() or sym.tentative() or sym.abs()) continue;
                const sym_name = mem.sliceTo(strtab[sym.n_strx..], 0);
                // TODO is it possible to have a symbol collision?
                addr_table.putAssumeCapacityNoClobber(sym_name, sym.n_value);
            }

            var sections: Dwarf.SectionArray = Dwarf.null_section_array;
            if (self.eh_frame) |eh_frame| sections[@intFromEnum(Dwarf.Section.Id.eh_frame)] = .{
                .data = eh_frame,
                .owned = false,
            };

            for (segcmd.?.getSections()) |sect| {
                if (!std.mem.eql(u8, "__DWARF", sect.segName())) continue;

                var section_index: ?usize = null;
                inline for (@typeInfo(Dwarf.Section.Id).@"enum".fields, 0..) |section, i| {
                    if (mem.eql(u8, "__" ++ section.name, sect.sectName())) section_index = i;
                }
                if (section_index == null) continue;

                const section_bytes = try Dwarf.chopSlice(mapped_mem, sect.offset, sect.size);
                sections[section_index.?] = .{
                    .data = section_bytes,
                    .virtual_address = @intCast(sect.addr),
                    .owned = false,
                };
            }

            const missing_debug_info =
                sections[@intFromEnum(Dwarf.Section.Id.debug_info)] == null or
                sections[@intFromEnum(Dwarf.Section.Id.debug_abbrev)] == null or
                sections[@intFromEnum(Dwarf.Section.Id.debug_str)] == null or
                sections[@intFromEnum(Dwarf.Section.Id.debug_line)] == null;
            if (missing_debug_info) return error.MissingDebugInfo;

            var di: Dwarf = .{
                .endian = .little,
                .sections = sections,
                .is_macho = true,
            };

            try Dwarf.open(&di, allocator);
            const info = OFileInfo{
                .di = di,
                .addr_table = addr_table,
            };

            // Add the debug info to the cache
            const result = try self.ofiles.getOrPut(o_file_path);
            assert(!result.found_existing);
            result.value_ptr.* = info;

            return result.value_ptr;
        }

        pub fn getSymbolAtAddress(self: *@This(), allocator: Allocator, address: usize) !std.debug.Symbol {
            nosuspend {
                const result = try self.getOFileInfoForAddress(allocator, address);
                if (result.symbol == null) return .{};

                // Take the symbol name from the N_FUN STAB entry, we're going to
                // use it if we fail to find the DWARF infos
                const stab_symbol = mem.sliceTo(self.strings[result.symbol.?.strx..], 0);
                if (result.o_file_info == null) return .{ .name = stab_symbol };

                // Translate again the address, this time into an address inside the
                // .o file
                const relocated_address_o = result.o_file_info.?.addr_table.get(stab_symbol) orelse return .{
                    .name = "???",
                };

                const addr_off = result.relocated_address - result.symbol.?.addr;
                const o_file_di = &result.o_file_info.?.di;
                if (o_file_di.findCompileUnit(relocated_address_o)) |compile_unit| {
                    return .{
                        .name = o_file_di.getSymbolName(relocated_address_o) orelse "???",
                        .compile_unit_name = compile_unit.die.getAttrString(
                            o_file_di,
                            std.dwarf.AT.name,
                            o_file_di.section(.debug_str),
                            compile_unit.*,
                        ) catch |err| switch (err) {
                            error.MissingDebugInfo, error.InvalidDebugInfo => "???",
                        },
                        .source_location = o_file_di.getLineNumberInfo(
                            allocator,
                            compile_unit,
                            relocated_address_o + addr_off,
                        ) catch |err| switch (err) {
                            error.MissingDebugInfo, error.InvalidDebugInfo => null,
                            else => return err,
                        },
                    };
                } else |err| switch (err) {
                    error.MissingDebugInfo, error.InvalidDebugInfo => {
                        return .{ .name = stab_symbol };
                    },
                    else => return err,
                }
            }
        }

        pub fn getOFileInfoForAddress(self: *@This(), allocator: Allocator, address: usize) !struct {
            relocated_address: usize,
            symbol: ?*const MachoSymbol = null,
            o_file_info: ?*OFileInfo = null,
        } {
            nosuspend {
                // Translate the VA into an address into this object
                const relocated_address = address - self.vmaddr_slide;

                // Find the .o file where this symbol is defined
                const symbol = machoSearchSymbols(self.symbols, relocated_address) orelse return .{
                    .relocated_address = relocated_address,
                };

                // Check if its debug infos are already in the cache
                const o_file_path = mem.sliceTo(self.strings[symbol.ofile..], 0);
                const o_file_info = self.ofiles.getPtr(o_file_path) orelse
                    (self.loadOFile(allocator, o_file_path) catch |err| switch (err) {
                        error.FileNotFound,
                        error.MissingDebugInfo,
                        error.InvalidDebugInfo,
                        => return .{
                            .relocated_address = relocated_address,
                            .symbol = symbol,
                        },
                        else => return err,
        ```
