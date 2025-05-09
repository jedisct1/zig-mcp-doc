```
try form_value.getString(d.*),
                    DW.LNCT.directory_index => e.dir_index = try form_value.getUInt(u32),
                    DW.LNCT.timestamp => e.mtime = try form_value.getUInt(u64),
                    DW.LNCT.size => e.size = try form_value.getUInt(u64),
                    DW.LNCT.MD5 => e.md5 = switch (form_value) {
                        .data16 => |data16| data16.*,
                        else => return bad(),
                    },
                    else => continue,
                }
            }
        }
    }

    var prog = LineNumberProgram.init(default_is_stmt, version);
    var line_table: CompileUnit.SrcLocCache.LineTable = .{};
    errdefer line_table.deinit(gpa);

    try fbr.seekTo(prog_start_offset);

    const next_unit_pos = line_info_offset + next_offset;

    while (fbr.pos < next_unit_pos) {
        const opcode = try fbr.readByte();

        if (opcode == DW.LNS.extended_op) {
            const op_size = try fbr.readUleb128(u64);
            if (op_size < 1) return bad();
            const sub_op = try fbr.readByte();
            switch (sub_op) {
                DW.LNE.end_sequence => {
                    // The row being added here is an "end" address, meaning
                    // that it does not map to the source location here -
                    // rather it marks the previous address as the last address
                    // that maps to this source location.

                    // In this implementation we don't mark end of addresses.
                    // This is a performance optimization based on the fact
                    // that we don't need to know if an address is missing
                    // source location info; we are only interested in being
                    // able to look up source location info for addresses that
                    // are known to have debug info.
                    //if (debug_debug_mode) assert(!line_table.contains(prog.address));
                    //try line_table.put(gpa, prog.address, CompileUnit.SrcLocCache.LineEntry.invalid);
                    prog.reset();
                },
                DW.LNE.set_address => {
                    const addr = try fbr.readInt(usize);
                    prog.address = addr;
                },
                DW.LNE.define_file => {
                    const path = try fbr.readBytesTo(0);
                    const dir_index = try fbr.readUleb128(u32);
                    const mtime = try fbr.readUleb128(u64);
                    const size = try fbr.readUleb128(u64);
                    try file_entries.append(gpa, .{
                        .path = path,
                        .dir_index = dir_index,
                        .mtime = mtime,
                        .size = size,
                    });
                },
                else => try fbr.seekForward(op_size - 1),
            }
        } else if (opcode >= opcode_base) {
            // special opcodes
            const adjusted_opcode = opcode - opcode_base;
            const inc_addr = minimum_instruction_length * (adjusted_opcode / line_range);
            const inc_line = @as(i32, line_base) + @as(i32, adjusted_opcode % line_range);
            prog.line += inc_line;
            prog.address += inc_addr;
            try prog.addRow(gpa, &line_table);
            prog.basic_block = false;
        } else {
            switch (opcode) {
                DW.LNS.copy => {
                    try prog.addRow(gpa, &line_table);
                    prog.basic_block = false;
                },
                DW.LNS.advance_pc => {
                    const arg = try fbr.readUleb128(usize);
                    prog.address += arg * minimum_instruction_length;
                },
                DW.LNS.advance_line => {
                    const arg = try fbr.readIleb128(i64);
                    prog.line += arg;
                },
                DW.LNS.set_file => {
                    const arg = try fbr.readUleb128(usize);
                    prog.file = arg;
                },
                DW.LNS.set_column => {
                    const arg = try fbr.readUleb128(u64);
                    prog.column = arg;
                },
                DW.LNS.negate_stmt => {
                    prog.is_stmt = !prog.is_stmt;
                },
                DW.LNS.set_basic_block => {
                    prog.basic_block = true;
                },
                DW.LNS.const_add_pc => {
                    const inc_addr = minimum_instruction_length * ((255 - opcode_base) / line_range);
                    prog.address += inc_addr;
                },
                DW.LNS.fixed_advance_pc => {
                    const arg = try fbr.readInt(u16);
                    prog.address += arg;
                },
                DW.LNS.set_prologue_end => {},
                else => {
                    if (opcode - 1 >= standard_opcode_lengths.len) return bad();
                    try fbr.seekForward(standard_opcode_lengths[opcode - 1]);
                },
            }
        }
    }

    // Dwarf standard v5, 6.2.5 says
    // > Within a sequence, addresses and operation pointers may only increase.
    // However, this is empirically not the case in reality, so we sort here.
    line_table.sortUnstable(struct {
        keys: []const u64,

        pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
            return ctx.keys[a_index] < ctx.keys[b_index];
        }
    }{ .keys = line_table.keys() });

    return .{
        .line_table = line_table,
        .directories = try directories.toOwnedSlice(gpa),
        .files = try file_entries.toOwnedSlice(gpa),
        .version = version,
    };
}

pub fn populateSrcLocCache(d: *Dwarf, gpa: Allocator, cu: *CompileUnit) ScanError!void {
    if (cu.src_loc_cache != null) return;
    cu.src_loc_cache = try runLineNumberProgram(d, gpa, cu);
}

pub fn getLineNumberInfo(
    d: *Dwarf,
    gpa: Allocator,
    compile_unit: *CompileUnit,
    target_address: u64,
) !std.debug.SourceLocation {
    try populateSrcLocCache(d, gpa, compile_unit);
    const slc = &compile_unit.src_loc_cache.?;
    const entry = try slc.findSource(target_address);
    const file_index = entry.file - @intFromBool(slc.version < 5);
    if (file_index >= slc.files.len) return bad();
    const file_entry = &slc.files[file_index];
    if (file_entry.dir_index >= slc.directories.len) return bad();
    const dir_name = slc.directories[file_entry.dir_index].path;
    const file_name = try std.fs.path.join(gpa, &.{ dir_name, file_entry.path });
    return .{
        .line = entry.line,
        .column = entry.column,
        .file_name = file_name,
    };
}

fn getString(di: Dwarf, offset: u64) ![:0]const u8 {
    return getStringGeneric(di.section(.debug_str), offset);
}

fn getLineString(di: Dwarf, offset: u64) ![:0]const u8 {
    return getStringGeneric(di.section(.debug_line_str), offset);
}

fn readDebugAddr(di: Dwarf, compile_unit: CompileUnit, index: u64) !u64 {
    const debug_addr = di.section(.debug_addr) orelse return bad();

    // addr_base points to the first item after the header, however we
    // need to read the header to know the size of each item. Empirically,
    // it may disagree with is_64 on the compile unit.
    // The header is 8 or 12 bytes depending on is_64.
    if (compile_unit.addr_base < 8) return bad();

    const version = mem.readInt(u16, debug_addr[compile_unit.addr_base - 4 ..][0..2], di.endian);
    if (version != 5) return bad();

    const addr_size = debug_addr[compile_unit.addr_base - 2];
    const seg_size = debug_addr[compile_unit.addr_base - 1];

    const byte_offset = @as(usize, @intCast(compile_unit.addr_base + (addr_size + seg_size) * index));
    if (byte_offset + addr_size > debug_addr.len) return bad();
    return switch (addr_size) {
        1 => debug_addr[byte_offset],
        2 => mem.readInt(u16, debug_addr[byte_offset..][0..2], di.endian),
        4 => mem.readInt(u32, debug_addr[byte_offset..][0..4], di.endian),
        8 => mem.readInt(u64, debug_addr[byte_offset..][0..8], di.endian),
        else => bad(),
    };
}

/// If `.eh_frame_hdr` is present, then only the header needs to be parsed. Otherwise, `.eh_frame`
/// and `.debug_frame` are scanned and a sorted list of FDEs is built for binary searching during
/// unwinding. Even if `.eh_frame_hdr` is used, we may find during unwinding that it's incomplete,
/// in which case we build the sorted list of FDEs at that point.
///
/// See also `scanCieFdeInfo`.
pub fn scanAllUnwindInfo(di: *Dwarf, allocator: Allocator, base_address: usize) !void {
    if (di.section(.eh_frame_hdr)) |eh_frame_hdr| blk: {
        var fbr: FixedBufferReader = .{ .buf = eh_frame_hdr, .endian = native_endian };

        const version = try fbr.readByte();
        if (version != 1) break :blk;

        const eh_frame_ptr_enc = try fbr.readByte();
        if (eh_frame_ptr_enc == EH.PE.omit) break :blk;
        const fde_count_enc = try fbr.readByte();
        if (fde_count_enc == EH.PE.omit) break :blk;
        const table_enc = try fbr.readByte();
        if (table_enc == EH.PE.omit) break :blk;

        const eh_frame_ptr = cast(usize, try readEhPointer(&fbr, eh_frame_ptr_enc, @sizeOf(usize), .{
            .pc_rel_base = @intFromPtr(&eh_frame_hdr[fbr.pos]),
            .follow_indirect = true,
        }) orelse return bad()) orelse return bad();

        const fde_count = cast(usize, try readEhPointer(&fbr, fde_count_enc, @sizeOf(usize), .{
            .pc_rel_base = @intFromPtr(&eh_frame_hdr[fbr.pos]),
            .follow_indirect = true,
        }) orelse return bad()) orelse return bad();

        const entry_size = try ExceptionFrameHeader.entrySize(table_enc);
        const entries_len = fde_count * entry_size;
        if (entries_len > eh_frame_hdr.len - fbr.pos) return bad();

        di.eh_frame_hdr = .{
            .eh_frame_ptr = eh_frame_ptr,
            .table_enc = table_enc,
            .fde_count = fde_count,
            .entries = eh_frame_hdr[fbr.pos..][0..entries_len],
        };

        // No need to scan .eh_frame, we have a binary search table already
        return;
    }

    try di.scanCieFdeInfo(allocator, base_address);
}

/// Scan `.eh_frame` and `.debug_frame` and build a sorted list of FDEs for binary searching during
/// unwinding.
pub fn scanCieFdeInfo(di: *Dwarf, allocator: Allocator, base_address: usize) !void {
    const frame_sections = [2]Section.Id{ .eh_frame, .debug_frame };
    for (frame_sections) |frame_section| {
        if (di.section(frame_section)) |section_data| {
            var fbr: FixedBufferReader = .{ .buf = section_data, .endian = di.endian };
            while (fbr.pos < fbr.buf.len) {
                const entry_header = try EntryHeader.read(&fbr, null, frame_section);
                switch (entry_header.type) {
                    .cie => {
                        const cie = try CommonInformationEntry.parse(
                            entry_header.entry_bytes,
                            di.sectionVirtualOffset(frame_section, base_address).?,
                            true,
                            entry_header.format,
                            frame_section,
                            entry_header.length_offset,
                            @sizeOf(usize),
                            di.endian,
                        );
                        try di.cie_map.put(allocator, entry_header.length_offset, cie);
                    },
                    .fde => |cie_offset| {
                        const cie = di.cie_map.get(cie_offset) orelse return bad();
                        const fde = try FrameDescriptionEntry.parse(
                            entry_header.entry_bytes,
                            di.sectionVirtualOffset(frame_section, base_address).?,
                            true,
                            cie,
                            @sizeOf(usize),
                            di.endian,
                        );
                        try di.fde_list.append(allocator, fde);
                    },
                    .terminator => break,
                }
            }

            std.mem.sortUnstable(FrameDescriptionEntry, di.fde_list.items, {}, struct {
                fn lessThan(ctx: void, a: FrameDescriptionEntry, b: FrameDescriptionEntry) bool {
                    _ = ctx;
                    return a.pc_begin < b.pc_begin;
                }
            }.lessThan);
        }
    }
}

fn parseFormValue(
    fbr: *FixedBufferReader,
    form_id: u64,
    format: Format,
    implicit_const: ?i64,
) ScanError!FormValue {
    return switch (form_id) {
        FORM.addr => .{ .addr = try fbr.readAddress(switch (@bitSizeOf(usize)) {
            32 => .@"32",
            64 => .@"64",
            else => @compileError("unsupported @sizeOf(usize)"),
        }) },
        FORM.addrx1 => .{ .addrx = try fbr.readInt(u8) },
        FORM.addrx2 => .{ .addrx = try fbr.readInt(u16) },
        FORM.addrx3 => .{ .addrx = try fbr.readInt(u24) },
        FORM.addrx4 => .{ .addrx = try fbr.readInt(u32) },
        FORM.addrx => .{ .addrx = try fbr.readUleb128(usize) },

        FORM.block1,
        FORM.block2,
        FORM.block4,
        FORM.block,
        => .{ .block = try fbr.readBytes(switch (form_id) {
            FORM.block1 => try fbr.readInt(u8),
            FORM.block2 => try fbr.readInt(u16),
            FORM.block4 => try fbr.readInt(u32),
            FORM.block => try fbr.readUleb128(usize),
            else => unreachable,
        }) },

        FORM.data1 => .{ .udata = try fbr.readInt(u8) },
        FORM.data2 => .{ .udata = try fbr.readInt(u16) },
        FORM.data4 => .{ .udata = try fbr.readInt(u32) },
        FORM.data8 => .{ .udata = try fbr.readInt(u64) },
        FORM.data16 => .{ .data16 = (try fbr.readBytes(16))[0..16] },
        FORM.udata => .{ .udata = try fbr.readUleb128(u64) },
        FORM.sdata => .{ .sdata = try fbr.readIleb128(i64) },
        FORM.exprloc => .{ .exprloc = try fbr.readBytes(try fbr.readUleb128(usize)) },
        FORM.flag => .{ .flag = (try fbr.readByte()) != 0 },
        FORM.flag_present => .{ .flag = true },
        FORM.sec_offset => .{ .sec_offset = try fbr.readAddress(format) },

        FORM.ref1 => .{ .ref = try fbr.readInt(u8) },
        FORM.ref2 => .{ .ref = try fbr.readInt(u16) },
        FORM.ref4 => .{ .ref = try fbr.readInt(u32) },
        FORM.ref8 => .{ .ref = try fbr.readInt(u64) },
        FORM.ref_udata => .{ .ref = try fbr.readUleb128(u64) },

        FORM.ref_addr => .{ .ref_addr = try fbr.readAddress(format) },
        FORM.ref_sig8 => .{ .ref = try fbr.readInt(u64) },

        FORM.string => .{ .string = try fbr.readBytesTo(0) },
        FORM.strp => .{ .strp = try fbr.readAddress(format) },
        FORM.strx1 => .{ .strx = try fbr.readInt(u8) },
        FORM.strx2 => .{ .strx = try fbr.readInt(u16) },
        FORM.strx3 => .{ .strx = try fbr.readInt(u24) },
        FORM.strx4 => .{ .strx = try fbr.readInt(u32) },
        FORM.strx => .{ .strx = try fbr.readUleb128(usize) },
        FORM.line_strp => .{ .line_strp = try fbr.readAddress(format) },
        FORM.indirect => parseFormValue(fbr, try fbr.readUleb128(u64), format, implicit_const),
        FORM.implicit_const => .{ .sdata = implicit_const orelse return bad() },
        FORM.loclistx => .{ .loclistx = try fbr.readUleb128(u64) },
        FORM.rnglistx => .{ .rnglistx = try fbr.readUleb128(u64) },
        else => {
            //debug.print("unrecognized form id: {x}\n", .{form_id});
            return bad();
        },
    };
}

const FileEntry = struct {
    path: []const u8,
    dir_index: u32 = 0,
    mtime: u64 = 0,
    size: u64 = 0,
    md5: [16]u8 = [1]u8{0} ** 16,
};

const LineNumberProgram = struct {
    address: u64,
    file: usize,
    line: i64,
    column: u64,
    version: u16,
    is_stmt: bool,
    basic_block: bool,

    default_is_stmt: bool,

    // Reset the state machine following the DWARF specification
    pub fn reset(self: *LineNumberProgram) void {
        self.address = 0;
        self.file = 1;
        self.line = 1;
        self.column = 0;
        self.is_stmt = self.default_is_stmt;
        self.basic_block = false;
    }

    pub fn init(is_stmt: bool, version: u16) LineNumberProgram {
        return .{
            .address = 0,
            .file = 1,
            .line = 1,
            .column = 0,
            .version = version,
            .is_stmt = is_stmt,
            .basic_block = false,
            .default_is_stmt = is_stmt,
        };
    }

    pub fn addRow(prog: *LineNumberProgram, gpa: Allocator, table: *CompileUnit.SrcLocCache.LineTable) !void {
        if (prog.line == 0) {
            //if (debug_debug_mode) @panic("garbage line data");
            return;
        }
        if (debug_debug_mode) assert(!table.contains(prog.address));
        try table.put(gpa, prog.address, .{
            .line = cast(u32, prog.line) orelse maxInt(u32),
            .column = cast(u32, prog.column) orelse maxInt(u32),
            .file = cast(u32, prog.file) orelse return bad(),
        });
    }
};

const UnitHeader = struct {
    format: Format,
    header_length: u4,
    unit_length: u64,
};

fn readUnitHeader(fbr: *FixedBufferReader, opt_ma: ?*MemoryAccessor) ScanError!UnitHeader {
    return switch (try if (opt_ma) |ma| fbr.readIntChecked(u32, ma) else fbr.readInt(u32)) {
        0...0xfffffff0 - 1 => |unit_length| .{
            .format = .@"32",
            .header_length = 4,
            .unit_length = unit_length,
        },
        0xfffffff0...0xffffffff - 1 => bad(),
        0xffffffff => .{
            .format = .@"64",
            .header_length = 12,
            .unit_length = try if (opt_ma) |ma| fbr.readIntChecked(u64, ma) else fbr.readInt(u64),
        },
    };
}

/// Returns the DWARF register number for an x86_64 register number found in compact unwind info
pub fn compactUnwindToDwarfRegNumber(unwind_reg_number: u3) !u8 {
    return switch (unwind_reg_number) {
        1 => 3, // RBX
        2 => 12, // R12
        3 => 13, // R13
        4 => 14, // R14
        5 => 15, // R15
        6 => 6, // RBP
        else => error.InvalidUnwindRegisterNumber,
    };
}

/// This function is to make it handy to comment out the return and make it
/// into a crash when working on this file.
pub fn bad() error{InvalidDebugInfo} {
    if (debug_debug_mode) @panic("bad dwarf");
    return error.InvalidDebugInfo;
}

fn missing() error{MissingDebugInfo} {
    if (debug_debug_mode) @panic("missing dwarf");
    return error.MissingDebugInfo;
}

fn getStringGeneric(opt_str: ?[]const u8, offset: u64) ![:0]const u8 {
    const str = opt_str orelse return bad();
    if (offset > str.len) return bad();
    const casted_offset = cast(usize, offset) orelse return bad();
    // Valid strings always have a terminating zero byte
    const last = std.mem.indexOfScalarPos(u8, str, casted_offset, 0) orelse return bad();
    return str[casted_offset..last :0];
}

const EhPointerContext = struct {
    // The address of the pointer field itself
    pc_rel_base: u64,

    // Whether or not to follow indirect pointers. This should only be
    // used when decoding pointers at runtime using the current process's
    // debug info
    follow_indirect: bool,

    // These relative addressing modes are only used in specific cases, and
    // might not be available / required in all parsing contexts
    data_rel_base: ?u64 = null,
    text_rel_base: ?u64 = null,
    function_rel_base: ?u64 = null,
};
fn readEhPointer(fbr: *FixedBufferReader, enc: u8, addr_size_bytes: u8, ctx: EhPointerContext) !?u64 {
    if (enc == EH.PE.omit) return null;

    const value: union(enum) {
        signed: i64,
        unsigned: u64,
    } = switch (enc & EH.PE.type_mask) {
        EH.PE.absptr => .{
            .unsigned = switch (addr_size_bytes) {
                2 => try fbr.readInt(u16),
                4 => try fbr.readInt(u32),
                8 => try fbr.readInt(u64),
                else => return error.InvalidAddrSize,
            },
        },
        EH.PE.uleb128 => .{ .unsigned = try fbr.readUleb128(u64) },
        EH.PE.udata2 => .{ .unsigned = try fbr.readInt(u16) },
        EH.PE.udata4 => .{ .unsigned = try fbr.readInt(u32) },
        EH.PE.udata8 => .{ .unsigned = try fbr.readInt(u64) },
        EH.PE.sleb128 => .{ .signed = try fbr.readIleb128(i64) },
        EH.PE.sdata2 => .{ .signed = try fbr.readInt(i16) },
        EH.PE.sdata4 => .{ .signed = try fbr.readInt(i32) },
        EH.PE.sdata8 => .{ .signed = try fbr.readInt(i64) },
        else => return bad(),
    };

    const base = switch (enc & EH.PE.rel_mask) {
        EH.PE.pcrel => ctx.pc_rel_base,
        EH.PE.textrel => ctx.text_rel_base orelse return error.PointerBaseNotSpecified,
        EH.PE.datarel => ctx.data_rel_base orelse return error.PointerBaseNotSpecified,
        EH.PE.funcrel => ctx.function_rel_base orelse return error.PointerBaseNotSpecified,
        else => null,
    };

    const ptr: u64 = if (base) |b| switch (value) {
        .signed => |s| @intCast(try std.math.add(i64, s, @as(i64, @intCast(b)))),
        // absptr can actually contain signed values in some cases (aarch64 MachO)
        .unsigned => |u| u +% b,
    } else switch (value) {
        .signed => |s| @as(u64, @intCast(s)),
        .unsigned => |u| u,
    };

    if ((enc & EH.PE.indirect) > 0 and ctx.follow_indirect) {
        if (@sizeOf(usize) != addr_size_bytes) {
            // See the documentation for `follow_indirect`
            return error.NonNativeIndirection;
        }

        const native_ptr = cast(usize, ptr) orelse return error.PointerOverflow;
        return switch (addr_size_bytes) {
            2, 4, 8 => return @as(*const usize, @ptrFromInt(native_ptr)).*,
            else => return error.UnsupportedAddrSize,
        };
    } else {
        return ptr;
    }
}

fn pcRelBase(field_ptr: usize, pc_rel_offset: i64) !usize {
    if (pc_rel_offset < 0) {
        return std.math.sub(usize, field_ptr, @as(usize, @intCast(-pc_rel_offset)));
    } else {
        return std.math.add(usize, field_ptr, @as(usize, @intCast(pc_rel_offset)));
    }
}

pub const ElfModule = struct {
    base_address: usize,
    dwarf: Dwarf,
    mapped_memory: []align(std.heap.page_size_min) const u8,
    external_mapped_memory: ?[]align(std.heap.page_size_min) const u8,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        self.dwarf.deinit(allocator);
        std.posix.munmap(self.mapped_memory);
        if (self.external_mapped_memory) |m| std.posix.munmap(m);
    }

    pub fn getSymbolAtAddress(self: *@This(), allocator: Allocator, address: usize) !std.debug.Symbol {
        // Translate the VA into an address into this object
        const relocated_address = address - self.base_address;
        return self.dwarf.getSymbol(allocator, relocated_address);
    }

    pub fn getDwarfInfoForAddress(self: *@This(), allocator: Allocator, address: usize) !?*Dwarf {
        _ = allocator;
        _ = address;
        return &self.dwarf;
    }

    pub const LoadError = error{
        InvalidDebugInfo,
        MissingDebugInfo,
        InvalidElfMagic,
        InvalidElfVersion,
        InvalidElfEndian,
        /// TODO: implement this and then remove this error code
        UnimplementedDwarfForeignEndian,
        /// The debug info may be valid but this implementation uses memory
        /// mapping which limits things to usize. If the target debug info is
        /// 64-bit and host is 32-bit, there may be debug info that is not
        /// supportable using this method.
        Overflow,

        PermissionDenied,
        LockedMemoryLimitExceeded,
        MemoryMappingNotSupported,
    } || Allocator.Error || std.fs.File.OpenError || OpenError;

    /// Reads debug info from an already mapped ELF file.
    ///
    /// If the required sections aren't present but a reference to external debug
    /// info is, then this this function will recurse to attempt to load the debug
    /// sections from an external file.
    pub fn load(
        gpa: Allocator,
        mapped_mem: []align(std.heap.page_size_min) const u8,
        build_id: ?[]const u8,
        expected_crc: ?u32,
        parent_sections: *Dwarf.SectionArray,
        parent_mapped_mem: ?[]align(std.heap.page_size_min) const u8,
        elf_filename: ?[]const u8,
    ) LoadError!Dwarf.ElfModule {
        if (expected_crc) |crc| if (crc != std.hash.crc.Crc32.hash(mapped_mem)) return error.InvalidDebugInfo;

        const hdr: *const elf.Ehdr = @ptrCast(&mapped_mem[0]);
        if (!mem.eql(u8, hdr.e_ident[0..4], elf.MAGIC)) return error.InvalidElfMagic;
        if (hdr.e_ident[elf.EI_VERSION] != 1) return error.InvalidElfVersion;

        const endian: std.builtin.Endian = switch (hdr.e_ident[elf.EI_DATA]) {
            elf.ELFDATA2LSB => .little,
            elf.ELFDATA2MSB => .big,
            else => return error.InvalidElfEndian,
        };
        if (endian != native_endian) return error.UnimplementedDwarfForeignEndian;

        const shoff = hdr.e_shoff;
        const str_section_off = shoff + @as(u64, hdr.e_shentsize) * @as(u64, hdr.e_shstrndx);
        const str_shdr: *const elf.Shdr = @ptrCast(@alignCast(&mapped_mem[cast(usize, str_section_off) orelse return error.Overflow]));
        const header_strings = mapped_mem[str_shdr.sh_offset..][0..str_shdr.sh_size];
        const shdrs = @as(
            [*]const elf.Shdr,
            @ptrCast(@alignCast(&mapped_mem[shoff])),
        )[0..hdr.e_shnum];

        var sections: Dwarf.SectionArray = Dwarf.null_section_array;

        // Combine section list. This takes ownership over any owned sections from the parent scope.
        for (parent_sections, &sections) |*parent, *section_elem| {
            if (parent.*) |*p| {
                section_elem.* = p.*;
                p.owned = false;
            }
        }
        errdefer for (sections) |opt_section| if (opt_section) |s| if (s.owned) gpa.free(s.data);

        var separate_debug_filename: ?[]const u8 = null;
        var separate_debug_crc: ?u32 = null;

        for (shdrs) |*shdr| {
            if (shdr.sh_type == elf.SHT_NULL or shdr.sh_type == elf.SHT_NOBITS) continue;
            const name = mem.sliceTo(header_strings[shdr.sh_name..], 0);

            if (mem.eql(u8, name, ".gnu_debuglink")) {
                const gnu_debuglink = try chopSlice(mapped_mem, shdr.sh_offset, shdr.sh_size);
                const debug_filename = mem.sliceTo(@as([*:0]const u8, @ptrCast(gnu_debuglink.ptr)), 0);
                const crc_offset = mem.alignForward(usize, debug_filename.len + 1, 4);
                const crc_bytes = gnu_debuglink[crc_offset..][0..4];
                separate_debug_crc = mem.readInt(u32, crc_bytes, native_endian);
                separate_debug_filename = debug_filename;
                continue;
            }

            var section_index: ?usize = null;
            inline for (@typeInfo(Dwarf.Section.Id).@"enum".fields, 0..) |sect, i| {
                if (mem.eql(u8, "." ++ sect.name, name)) section_index = i;
            }
            if (section_index == null) continue;
            if (sections[section_index.?] != null) continue;

            const section_bytes = try chopSlice(mapped_mem, shdr.sh_offset, shdr.sh_size);
            sections[section_index.?] = if ((shdr.sh_flags & elf.SHF_COMPRESSED) > 0) blk: {
                var section_stream = std.io.fixedBufferStream(section_bytes);
                const section_reader = section_stream.reader();
                const chdr = section_reader.readStruct(elf.Chdr) catch continue;
                if (chdr.ch_type != .ZLIB) continue;

                var zlib_stream = std.compress.zlib.decompressor(section_reader);

                const decompressed_section = try gpa.alloc(u8, chdr.ch_size);
                errdefer gpa.free(decompressed_section);

                const read = zlib_stream.reader().readAll(decompressed_section) catch continue;
                assert(read == decompressed_section.len);

                break :blk .{
                    .data = decompressed_section,
                    .virtual_address = shdr.sh_addr,
                    .owned = true,
                };
            } else .{
                .data = section_bytes,
                .virtual_address = shdr.sh_addr,
                .owned = false,
            };
        }

        const missing_debug_info =
            sections[@intFromEnum(Dwarf.Section.Id.debug_info)] == null or
            sections[@intFromEnum(Dwarf.Section.Id.debug_abbrev)] == null or
            sections[@intFromEnum(Dwarf.Section.Id.debug_str)] == null or
            sections[@intFromEnum(Dwarf.Section.Id.debug_line)] == null;

        // Attempt to load debug info from an external file
        // See: https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
        if (missing_debug_info) {

            // Only allow one level of debug info nesting
            if (parent_mapped_mem) |_| {
                return error.MissingDebugInfo;
            }

            // $XDG_CACHE_HOME/debuginfod_client/<buildid>/debuginfo
            // This only opportunisticly tries to load from the debuginfod cache, but doesn't try to populate it.
            // One can manually run `debuginfod-find debuginfo PATH` to download the symbols
            if (build_id) |id| blk: {
                var debuginfod_dir: std.fs.Dir = switch (builtin.os.tag) {
                    .wasi, .windows => break :blk,
                    else => dir: {
                        if (std.posix.getenv("DEBUGINFOD_CACHE_PATH")) |path| {
                            break :dir std.fs.openDirAbsolute(path, .{}) catch break :blk;
                        }
                        if (std.posix.getenv("XDG_CACHE_HOME")) |cache_path| {
                            if (cache_path.len > 0) {
                                const path = std.fs.path.join(gpa, &[_][]const u8{ cache_path, "debuginfod_client" }) catch break :blk;
                                defer gpa.free(path);
                                break :dir std.fs.openDirAbsolute(path, .{}) catch break :blk;
                            }
                        }
                        if (std.posix.getenv("HOME")) |home_path| {
                            const path = std.fs.path.join(gpa, &[_][]const u8{ home_path, ".cache", "debuginfod_client" }) catch break :blk;
                            defer gpa.free(path);
                            break :dir std.fs.openDirAbsolute(path, .{}) catch break :blk;
                        }
                        break :blk;
                    },
                };
                defer debuginfod_dir.close();

                const filename = std.fmt.allocPrint(
                    gpa,
                    "{s}/debuginfo",
                    .{std.fmt.fmtSliceHexLower(id)},
                ) catch break :blk;
                defer gpa.free(filename);

                const path: Path = .{
                    .root_dir = .{ .path = null, .handle = debuginfod_dir },
                    .sub_path = filename,
                };

                return loadPath(gpa, path, null, separate_debug_crc, &sections, mapped_mem) catch break :blk;
            }

            const global_debug_directories = [_][]const u8{
                "/usr/lib/debug",
            };

            // <global debug directory>/.build-id/<2-character id prefix>/<id remainder>.debug
            if (build_id) |id| blk: {
                if (id.len < 3) break :blk;

                // Either md5 (16 bytes) or sha1 (20 bytes) are used here in practice
                const extension = ".debug";
                var id_prefix_buf: [2]u8 = undefined;
                var filename_buf: [38 + extension.len]u8 = undefined;

                _ = std.fmt.bufPrint(&id_prefix_buf, "{s}", .{std.fmt.fmtSliceHexLower(id[0..1])}) catch unreachable;
                const filename = std.fmt.bufPrint(
                    &filename_buf,
                    "{s}" ++ extension,
                    .{std.fmt.fmtSliceHexLower(id[1..])},
                ) catch break :blk;

                for (global_debug_directories) |global_directory| {
                    const path: Path = .{
                        .root_dir = std.Build.Cache.Directory.cwd(),
                        .sub_path = try std.fs.path.join(gpa, &.{
                            global_directory, ".build-id", &id_prefix_buf, filename,
                        }),
                    };
                    defer gpa.free(path.sub_path);

                    return loadPath(gpa, path, null, separate_debug_crc, &sections, mapped_mem) catch continue;
                }
            }

            // use the path from .gnu_debuglink, in the same search order as gdb
            if (separate_debug_filename) |separate_filename| blk: {
                if (elf_filename != null and mem.eql(u8, elf_filename.?, separate_filename))
                    return error.MissingDebugInfo;

                exe_dir: {
                    var exe_dir_buf: [std.fs.max_path_bytes]u8 = undefined;
                    const exe_dir_path = std.fs.selfExeDirPath(&exe_dir_buf) catch break :exe_dir;
                    var exe_dir = std.fs.openDirAbsolute(exe_dir_path, .{}) catch break :exe_dir;
                    defer exe_dir.close();

                    // <exe_dir>/<gnu_debuglink>
                    if (loadPath(
                        gpa,
                        .{
                            .root_dir = .{ .path = null, .handle = exe_dir },
                            .sub_path = separate_filename,
                        },
                        null,
                        separate_debug_crc,
                        &sections,
                        mapped_mem,
                    )) |debug_info| {
                        return debug_info;
                    } else |_| {}

                    // <exe_dir>/.debug/<gnu_debuglink>
                    const path: Path = .{
                        .root_dir = .{ .path = null, .handle = exe_dir },
                        .sub_path = try std.fs.path.join(gpa, &.{ ".debug", separate_filename }),
                    };
                    defer gpa.free(path.sub_path);

                    if (loadPath(gpa, path, null, separate_debug_crc, &sections, mapped_mem)) |debug_info| return debug_info else |_| {}
                }

                var cwd_buf: [std.fs.max_path_bytes]u8 = undefined;
                const cwd_path = std.posix.realpath(".", &cwd_buf) catch break :blk;

                // <global debug directory>/<absolute folder of current binary>/<gnu_debuglink>
                for (global_debug_directories) |global_directory| {
                    const path: Path = .{
                        .root_dir = std.Build.Cache.Directory.cwd(),
                        .sub_path = try std.fs.path.join(gpa, &.{ global_directory, cwd_path, separate_filename }),
                    };
                    defer gpa.free(path.sub_path);
                    if (loadPath(gpa, path, null, separate_debug_crc, &sections, mapped_mem)) |debug_info| return debug_info else |_| {}
                }
            }

            return error.MissingDebugInfo;
        }

        var di: Dwarf = .{
            .endian = endian,
            .sections = sections,
            .is_macho = false,
        };

        try Dwarf.open(&di, gpa);

        return .{
            .base_address = 0,
            .dwarf = di,
            .mapped_memory = parent_mapped_mem orelse mapped_mem,
            .external_mapped_memory = if (parent_mapped_mem != null) mapped_mem else null,
        };
    }

    pub fn loadPath(
        gpa: Allocator,
        elf_file_path: Path,
        build_id: ?[]const u8,
        expected_crc: ?u32,
        parent_sections: *Dwarf.SectionArray,
        parent_mapped_mem: ?[]align(std.heap.page_size_min) const u8,
    ) LoadError!Dwarf.ElfModule {
        const elf_file = elf_file_path.root_dir.handle.openFile(elf_file_path.sub_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return missing(),
            else => return err,
        };
        defer elf_file.close();

        const end_pos = elf_file.getEndPos() catch return bad();
        const file_len = cast(usize, end_pos) orelse return error.Overflow;

        const mapped_mem = std.posix.mmap(
            null,
            file_len,
            std.posix.PROT.READ,
            .{ .TYPE = .SHARED },
            elf_file.handle,
            0,
        ) catch |err| switch (err) {
            error.MappingAlreadyExists => unreachable,
            else => |e| return e,
        };
        errdefer std.posix.munmap(mapped_mem);

        return load(
            gpa,
            mapped_mem,
            build_id,
            expected_crc,
            parent_sections,
            parent_mapped_mem,
            elf_file_path.sub_path,
        );
    }
};

pub fn getSymbol(di: *Dwarf, allocator: Allocator, address: u64) !std.debug.Symbol {
    if (di.findCompileUnit(address)) |compile_unit| {
        return .{
            .name = di.getSymbolName(address) orelse "???",
            .compile_unit_name = compile_unit.die.getAttrString(di, std.dwarf.AT.name, di.section(.debug_str), compile_unit.*) catch |err| switch (err) {
                error.MissingDebugInfo, error.InvalidDebugInfo => "???",
            },
            .source_location = di.getLineNumberInfo(allocator, compile_unit, address) catch |err| switch (err) {
                error.MissingDebugInfo, error.InvalidDebugInfo => null,
                else => return err,
            },
        };
    } else |err| switch (err) {
        error.MissingDebugInfo, error.InvalidDebugInfo => return .{},
        else => return err,
    }
}

pub fn chopSlice(ptr: []const u8, offset: u64, size: u64) error{Overflow}![]const u8 {
    const start = cast(usize, offset) orelse return error.Overflow;
    const end = start + (cast(usize, size) orelse return error.Overflow);
    return ptr[start..end];
}
const builtin = @import("builtin");

const std = @import("../../std.zig");
const mem = std.mem;
const posix = std.posix;
const Arch = std.Target.Cpu.Arch;

/// Tells whether unwinding for this target is supported by the Dwarf standard.
///
/// See also `std.debug.SelfInfo.supportsUnwinding` which tells whether the Zig
/// standard library has a working implementation of unwinding for this target.
pub fn supportsUnwinding(target: std.Target) bool {
    return switch (target.cpu.arch) {
        .amdgcn,
        .nvptx,
        .nvptx64,
        .spirv,
        .spirv32,
        .spirv64,
        => false,

        // Enabling this causes relocation errors such as:
        // error: invalid relocation type R_RISCV_SUB32 at offset 0x20
        .riscv64, .riscv32 => false,

        // Conservative guess. Feel free to update this logic with any targets
        // that are known to not support Dwarf unwinding.
        else => true,
    };
}

/// Returns `null` for CPU architectures without an instruction pointer register.
pub fn ipRegNum(arch: Arch) ?u8 {
    return switch (arch) {
        .x86 => 8,
        .x86_64 => 16,
        .arm, .armeb, .thumb, .thumbeb => 15,
        .aarch64, .aarch64_be => 32,
        else => null,
    };
}

pub fn fpRegNum(arch: Arch, reg_context: RegisterContext) u8 {
    return switch (arch) {
        // GCC on OS X historically did the opposite of ELF for these registers
        // (only in .eh_frame), and that is now the convention for MachO
        .x86 => if (reg_context.eh_frame and reg_context.is_macho) 4 else 5,
        .x86_64 => 6,
        .arm, .armeb, .thumb, .thumbeb => 11,
        .aarch64, .aarch64_be => 29,
        else => unreachable,
    };
}

pub fn spRegNum(arch: Arch, reg_context: RegisterContext) u8 {
    return switch (arch) {
        .x86 => if (reg_context.eh_frame and reg_context.is_macho) 5 else 4,
        .x86_64 => 7,
        .arm, .armeb, .thumb, .thumbeb => 13,
        .aarch64, .aarch64_be => 31,
        else => unreachable,
    };
}

pub const RegisterContext = struct {
    eh_frame: bool,
    is_macho: bool,
};

pub const RegBytesError = error{
    InvalidRegister,
    UnimplementedArch,
    UnimplementedOs,
    RegisterContextRequired,
    ThreadContextNotSupported,
};

/// Returns a slice containing the backing storage for `reg_number`.
///
/// This function assumes the Dwarf information corresponds not necessarily to
/// the current executable, but at least with a matching CPU architecture and
/// OS. It is planned to lift this limitation with a future enhancement.
///
/// `reg_context` describes in what context the register number is used, as it can have different
/// meanings depending on the DWARF container. It is only required when getting the stack or
/// frame pointer register on some architectures.
pub fn regBytes(
    thread_context_ptr: *std.debug.ThreadContext,
    reg_number: u8,
    reg_context: ?RegisterContext,
) RegBytesError![]u8 {
    if (builtin.os.tag == .windows) {
        return switch (builtin.cpu.arch) {
            .x86 => switch (reg_number) {
                0 => mem.asBytes(&thread_context_ptr.Eax),
                1 => mem.asBytes(&thread_context_ptr.Ecx),
                2 => mem.asBytes(&thread_context_ptr.Edx),
                3 => mem.asBytes(&thread_context_ptr.Ebx),
                4 => mem.asBytes(&thread_context_ptr.Esp),
                5 => mem.asBytes(&thread_context_ptr.Ebp),
                6 => mem.asBytes(&thread_context_ptr.Esi),
                7 => mem.asBytes(&thread_context_ptr.Edi),
                8 => mem.asBytes(&thread_context_ptr.Eip),
                9 => mem.asBytes(&thread_context_ptr.EFlags),
                10 => mem.asBytes(&thread_context_ptr.SegCs),
                11 => mem.asBytes(&thread_context_ptr.SegSs),
                12 => mem.asBytes(&thread_context_ptr.SegDs),
                13 => mem.asBytes(&thread_context_ptr.SegEs),
                14 => mem.asBytes(&thread_context_ptr.SegFs),
                15 => mem.asBytes(&thread_context_ptr.SegGs),
                else => error.InvalidRegister,
            },
            .x86_64 => switch (reg_number) {
                0 => mem.asBytes(&thread_context_ptr.Rax),
                1 => mem.asBytes(&thread_context_ptr.Rdx),
                2 => mem.asBytes(&thread_context_ptr.Rcx),
                3 => mem.asBytes(&thread_context_ptr.Rbx),
                4 => mem.asBytes(&thread_context_ptr.Rsi),
                5 => mem.asBytes(&thread_context_ptr.Rdi),
                6 => mem.asBytes(&thread_context_ptr.Rbp),
                7 => mem.asBytes(&thread_context_ptr.Rsp),
                8 => mem.asBytes(&thread_context_ptr.R8),
                9 => mem.asBytes(&thread_context_ptr.R9),
                10 => mem.asBytes(&thread_context_ptr.R10),
                11 => mem.asBytes(&thread_context_ptr.R11),
                12 => mem.asBytes(&thread_context_ptr.R12),
                13 => mem.asBytes(&thread_context_ptr.R13),
                14 => mem.asBytes(&thread_context_ptr.R14),
                15 => mem.asBytes(&thread_context_ptr.R15),
                16 => mem.asBytes(&thread_context_ptr.Rip),
                else => error.InvalidRegister,
            },
            .aarch64, .aarch64_be => switch (reg_number) {
                0...30 => mem.asBytes(&thread_context_ptr.DUMMYUNIONNAME.X[reg_number]),
                31 => mem.asBytes(&thread_context_ptr.Sp),
                32 => mem.asBytes(&thread_context_ptr.Pc),
                else => error.InvalidRegister,
            },
            else => error.UnimplementedArch,
        };
    }

    if (!std.debug.have_ucontext) return error.ThreadContextNotSupported;

    const ucontext_ptr = thread_context_ptr;
    return switch (builtin.cpu.arch) {
        .x86 => switch (builtin.os.tag) {
            .linux, .netbsd, .solaris, .illumos => switch (reg_number) {
                0 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.EAX]),
                1 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.ECX]),
                2 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.EDX]),
                3 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.EBX]),
                4...5 => if (reg_context) |r| bytes: {
                    if (reg_number == 4) {
                        break :bytes if (r.eh_frame and r.is_macho)
                            mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.EBP])
                        else
                            mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.ESP]);
                    } else {
                        break :bytes if (r.eh_frame and r.is_macho)
                            mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.ESP])
                        else
                            mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.EBP]);
                    }
                } else error.RegisterContextRequired,
                6 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.ESI]),
                7 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.EDI]),
                8 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.EIP]),
                9 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.EFL]),
                10 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.CS]),
                11 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.SS]),
                12 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.DS]),
                13 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.ES]),
                14 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.FS]),
                15 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.GS]),
                16...23 => error.InvalidRegister, // TODO: Support loading ST0-ST7 from mcontext.fpregs
                32...39 => error.InvalidRegister, // TODO: Support loading XMM0-XMM7 from mcontext.fpregs
                else => error.InvalidRegister,
            },
            else => error.UnimplementedOs,
        },
        .x86_64 => switch (builtin.os.tag) {
            .linux, .solaris, .illumos => switch (reg_number) {
                0 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.RAX]),
                1 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.RDX]),
                2 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.RCX]),
                3 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.RBX]),
                4 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.RSI]),
                5 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.RDI]),
                6 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.RBP]),
                7 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.RSP]),
                8 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.R8]),
                9 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.R9]),
                10 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.R10]),
                11 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.R11]),
                12 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.R12]),
                13 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.R13]),
                14 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.R14]),
                15 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.R15]),
                16 => mem.asBytes(&ucontext_ptr.mcontext.gregs[posix.REG.RIP]),
                17...32 => |i| if (builtin.os.tag.isSolarish())
                    mem.asBytes(&ucontext_ptr.mcontext.fpregs.chip_state.xmm[i - 17])
                else
                    mem.asBytes(&ucontext_ptr.mcontext.fpregs.xmm[i - 17]),
                else => error.InvalidRegister,
            },
            .freebsd => switch (reg_number) {
                0 => mem.asBytes(&ucontext_ptr.mcontext.rax),
                1 => mem.asBytes(&ucontext_ptr.mcontext.rdx),
                2 => mem.asBytes(&ucontext_ptr.mcontext.rcx),
                3 => mem.asBytes(&ucontext_ptr.mcontext.rbx),
                4 => mem.asBytes(&ucontext_ptr.mcontext.rsi),
                5 => mem.asBytes(&ucontext_ptr.mcontext.rdi),
                6 => mem.asBytes(&ucontext_ptr.mcontext.rbp),
                7 => mem.asBytes(&ucontext_ptr.mcontext.rsp),
                8 => mem.asBytes(&ucontext_ptr.mcontext.r8),
                9 => mem.asBytes(&ucontext_ptr.mcontext.r9),
                10 => mem.asBytes(&ucontext_ptr.mcontext.r10),
                11 => mem.asBytes(&ucontext_ptr.mcontext.r11),
                12 => mem.asBytes(&ucontext_ptr.mcontext.r12),
                13 => mem.asBytes(&ucontext_ptr.mcontext.r13),
                14 => mem.asBytes(&ucontext_ptr.mcontext.r14),
                15 => mem.asBytes(&ucontext_ptr.mcontext.r15),
                16 => mem.asBytes(&ucontext_ptr.mcontext.rip),
                // TODO: Extract xmm state from mcontext.fpstate?
                else => error.InvalidRegister,
            },
            .openbsd => switch (reg_number) {
                0 => mem.asBytes(&ucontext_ptr.sc_rax),
                1 => mem.asBytes(&ucontext_ptr.sc_rdx),
                2 => mem.asBytes(&ucontext_ptr.sc_rcx),
                3 => mem.asBytes(&ucontext_ptr.sc_rbx),
                4 => mem.asBytes(&ucontext_ptr.sc_rsi),
                5 => mem.asBytes(&ucontext_ptr.sc_rdi),
                6 => mem.asBytes(&ucontext_ptr.sc_rbp),
                7 => mem.asBytes(&ucontext_ptr.sc_rsp),
                8 => mem.asBytes(&ucontext_ptr.sc_r8),
                9 => mem.asBytes(&ucontext_ptr.sc_r9),
                10 => mem.asBytes(&ucontext_ptr.sc_r10),
                11 => mem.asBytes(&ucontext_ptr.sc_r11),
                12 => mem.asBytes(&ucontext_ptr.sc_r12),
                13 => mem.asBytes(&ucontext_ptr.sc_r13),
                14 => mem.asBytes(&ucontext_ptr.sc_r14),
                15 => mem.asBytes(&ucontext_ptr.sc_r15),
                16 => mem.asBytes(&ucontext_ptr.sc_rip),
                // TODO: Extract xmm state from sc_fpstate?
                else => error.InvalidRegister,
            },
            .macos, .ios => switch (reg_number) {
                0 => mem.asBytes(&ucontext_ptr.mcontext.ss.rax),
                1 => mem.asBytes(&ucontext_ptr.mcontext.ss.rdx),
                2 => mem.asBytes(&ucontext_ptr.mcontext.ss.rcx),
                3 => mem.asBytes(&ucontext_ptr.mcontext.ss.rbx),
                4 => mem.asBytes(&ucontext_ptr.mcontext.ss.rsi),
                5 => mem.asBytes(&ucontext_ptr.mcontext.ss.rdi),
                6 => mem.asBytes(&ucontext_ptr.mcontext.ss.rbp),
                7 => mem.asBytes(&ucontext_ptr.mcontext.ss.rsp),
                8 => mem.asBytes(&ucontext_ptr.mcontext.ss.r8),
                9 => mem.asBytes(&ucontext_ptr.mcontext.ss.r9),
                10 => mem.asBytes(&ucontext_ptr.mcontext.ss.r10),
                11 => mem.asBytes(&ucontext_ptr.mcontext.ss.r11),
                12 => mem.asBytes(&ucontext_ptr.mcontext.ss.r12),
                13 => mem.asBytes(&ucontext_ptr.mcontext.ss.r13),
                14 => mem.asBytes(&ucontext_ptr.mcontext.ss.r14),
                15 => mem.asBytes(&ucontext_ptr.mcontext.ss.r15),
                16 => mem.asBytes(&ucontext_ptr.mcontext.ss.rip),
                else => error.InvalidRegister,
            },
            else => error.UnimplementedOs,
        },
        .arm, .armeb, .thumb, .thumbeb => switch (builtin.os.tag) {
            .linux => switch (reg_number) {
                0 => mem.asBytes(&ucontext_ptr.mcontext.arm_r0),
                1 => mem.asBytes(&ucontext_ptr.mcontext.arm_r1),
                2 => mem.asBytes(&ucontext_ptr.mcontext.arm_r2),
                3 => mem.asBytes(&ucontext_ptr.mcontext.arm_r3),
                4 => mem.asBytes(&ucontext_ptr.mcontext.arm_r4),
                5 => mem.asBytes(&ucontext_ptr.mcontext.arm_r5),
                6 => mem.asBytes(&ucontext_ptr.mcontext.arm_r6),
                7 => mem.asBytes(&ucontext_ptr.mcontext.arm_r7),
                8 => mem.asBytes(&ucontext_ptr.mcontext.arm_r8),
                9 => mem.asBytes(&ucontext_ptr.mcontext.arm_r9),
                10 => mem.asBytes(&ucontext_ptr.mcontext.arm_r10),
                11 => mem.asBytes(&ucontext_ptr.mcontext.arm_fp),
                12 => mem.asBytes(&ucontext_ptr.mcontext.arm_ip),
                13 => mem.asBytes(&ucontext_ptr.mcontext.arm_sp),
                14 => mem.asBytes(&ucontext_ptr.mcontext.arm_lr),
                15 => mem.asBytes(&ucontext_ptr.mcontext.arm_pc),
                // CPSR is not allocated a register number (See: https://github.com/ARM-software/abi-aa/blob/main/aadwarf32/aadwarf32.rst, Section 4.1)
                else => error.InvalidRegister,
            },
            else => error.UnimplementedOs,
        },
        .aarch64, .aarch64_be => switch (builtin.os.tag) {
            .macos, .ios, .watchos => switch (reg_number) {
                0...28 => mem.asBytes(&ucontext_ptr.mcontext.ss.regs[reg_number]),
                29 => mem.asBytes(&ucontext_ptr.mcontext.ss.fp),
                30 => mem.asBytes(&ucontext_ptr.mcontext.ss.lr),
                31 => mem.asBytes(&ucontext_ptr.mcontext.ss.sp),
                32 => mem.asBytes(&ucontext_ptr.mcontext.ss.pc),

                // TODO: Find storage for this state
                //34 => mem.asBytes(&ucontext_ptr.ra_sign_state),

                // V0-V31
                64...95 => mem.asBytes(&ucontext_ptr.mcontext.ns.q[reg_number - 64]),
                else => error.InvalidRegister,
            },
            .netbsd => switch (reg_number) {
                0...34 => mem.asBytes(&ucontext_ptr.mcontext.gregs[reg_number]),
                else => error.InvalidRegister,
            },
            .freebsd => switch (reg_number) {
                0...29 => mem.asBytes(&ucontext_ptr.mcontext.gpregs.x[reg_number]),
                30 => mem.asBytes(&ucontext_ptr.mcontext.gpregs.lr),
                31 => mem.asBytes(&ucontext_ptr.mcontext.gpregs.sp),

                // TODO: This seems wrong, but it was in the previous debug.zig code for mapping PC, check this
                32 => mem.asBytes(&ucontext_ptr.mcontext.gpregs.elr),

                else => error.InvalidRegister,
            },
            .openbsd => switch (reg_number) {
                0...30 => mem.asBytes(&ucontext_ptr.sc_x[reg_number]),
                31 => mem.asBytes(&ucontext_ptr.sc_sp),
                32 => mem.asBytes(&ucontext_ptr.sc_lr),
                33 => mem.asBytes(&ucontext_ptr.sc_elr),
                34 => mem.asBytes(&ucontext_ptr.sc_spsr),
                else => error.InvalidRegister,
            },
            else => switch (reg_number) {
                0...30 => mem.asBytes(&ucontext_ptr.mcontext.regs[reg_number]),
                31 => mem.asBytes(&ucontext_ptr.mcontext.sp),
                32 => mem.asBytes(&ucontext_ptr.mcontext.pc),
                else => error.InvalidRegister,
            },
        },
        else => error.UnimplementedArch,
    };
}

/// Returns a pointer to a register stored in a ThreadContext, preserving the
/// pointer attributes of the context.
pub fn regValueNative(
    thread_context_ptr: *std.debug.ThreadContext,
    reg_number: u8,
    reg_context: ?RegisterContext,
) !*align(1) usize {
    const reg_bytes = try regBytes(thread_context_ptr, reg_number, reg_context);
    if (@sizeOf(usize) != reg_bytes.len) return error.IncompatibleRegisterSize;
    return mem.bytesAsValue(usize, reg_bytes[0..@sizeOf(usize)]);
}
const builtin = @import("builtin");
const std = @import("../../std.zig");
const mem = std.mem;
const debug = std.debug;
const leb = std.leb;
const DW = std.dwarf;
const abi = std.debug.Dwarf.abi;
const assert = std.debug.assert;
const native_endian = builtin.cpu.arch.endian();

/// TODO merge with std.dwarf.CFA
const Opcode = enum(u8) {
    advance_loc = 0x1 << 6,
    offset = 0x2 << 6,
    restore = 0x3 << 6,

    nop = 0x00,
    set_loc = 0x01,
    advance_loc1 = 0x02,
    advance_loc2 = 0x03,
    advance_loc4 = 0x04,
    offset_extended = 0x05,
    restore_extended = 0x06,
    undefined = 0x07,
    same_value = 0x08,
    register = 0x09,
    remember_state = 0x0a,
    restore_state = 0x0b,
    def_cfa = 0x0c,
    def_cfa_register = 0x0d,
    def_cfa_offset = 0x0e,
    def_cfa_expression = 0x0f,
    expression = 0x10,
    offset_extended_sf = 0x11,
    def_cfa_sf = 0x12,
    def_cfa_offset_sf = 0x13,
    val_offset = 0x14,
    val_offset_sf = 0x15,
    val_expression = 0x16,

    // These opcodes encode an operand in the lower 6 bits of the opcode itself
    pub const lo_inline = @intFromEnum(Opcode.advance_loc);
    pub const hi_inline = @intFromEnum(Opcode.restore) | 0b111111;

    // These opcodes are trailed by zero or more operands
    pub const lo_reserved = @intFromEnum(Opcode.nop);
    pub const hi_reserved = @intFromEnum(Opcode.val_expression);

    // Vendor-specific opcodes
    pub const lo_user = 0x1c;
    pub const hi_user = 0x3f;
};

fn readBlock(stream: *std.io.FixedBufferStream([]const u8)) ![]const u8 {
    const reader = stream.reader();
    const block_len = try leb.readUleb128(usize, reader);
    if (stream.pos + block_len > stream.buffer.len) return error.InvalidOperand;

    const block = stream.buffer[stream.pos..][0..block_len];
    reader.context.pos += block_len;

    return block;
}

pub const Instruction = union(Opcode) {
    advance_loc: struct {
        delta: u8,
    },
    offset: struct {
        register: u8,
        offset: u64,
    },
    restore: struct {
        register: u8,
    },
    nop: void,
    set_loc: struct {
        address: u64,
    },
    advance_loc1: struct {
        delta: u8,
    },
    advance_loc2: struct {
        delta: u16,
    },
    advance_loc4: struct {
        delta: u32,
    },
    offset_extended: struct {
        register: u8,
        offset: u64,
    },
    restore_extended: struct {
        register: u8,
    },
    undefined: struct {
        register: u8,
    },
    same_value: struct {
        register: u8,
    },
    register: struct {
        register: u8,
        target_register: u8,
    },
    remember_state: void,
    restore_state: void,
    def_cfa: struct {
        register: u8,
        offset: u64,
    },
    def_cfa_register: struct {
        register: u8,
    },
    def_cfa_offset: struct {
        offset: u64,
    },
    def_cfa_expression: struct {
        block: []const u8,
    },
    expression: struct {
        register: u8,
        block: []const u8,
    },
    offset_extended_sf: struct {
        register: u8,
        offset: i64,
    },
    def_cfa_sf: struct {
        register: u8,
        offset: i64,
    },
    def_cfa_offset_sf: struct {
        offset: i64,
    },
    val_offset: struct {
        register: u8,
        offset: u64,
    },
    val_offset_sf: struct {
        register: u8,
        offset: i64,
    },
    val_expression: struct {
        register: u8,
        block: []const u8,
    },

    pub fn read(
        stream: *std.io.FixedBufferStream([]const u8),
        addr_size_bytes: u8,
        endian: std.builtin.Endian,
    ) !Instruction {
        const reader = stream.reader();
        switch (try reader.readByte()) {
            Opcode.lo_inline...Opcode.hi_inline => |opcode| {
                const e: Opcode = @enumFromInt(opcode & 0b11000000);
                const value: u6 = @intCast(opcode & 0b111111);
                return switch (e) {
                    .advance_loc => .{
                        .advance_loc = .{ .delta = value },
                    },
                    .offset => .{
                        .offset = .{
                            .register = value,
                            .offset = try leb.readUleb128(u64, reader),
                        },
                    },
                    .restore => .{
                        .restore = .{ .register = value },
                    },
                    else => unreachable,
                };
            },
            Opcode.lo_reserved...Opcode.hi_reserved => |opcode| {
                const e: Opcode = @enumFromInt(opcode);
                return switch (e) {
                    .advance_loc,
                    .offset,
                    .restore,
                    => unreachable,
                    .nop => .{ .nop = {} },
                    .set_loc => .{
                        .set_loc = .{
                            .address = switch (addr_size_bytes) {
                                2 => try reader.readInt(u16, endian),
                                4 => try reader.readInt(u32, endian),
                                8 => try reader.readInt(u64, endian),
                                else => return error.InvalidAddrSize,
                            },
                        },
                    },
                    .advance_loc1 => .{
                        .advance_loc1 = .{ .delta = try reader.readByte() },
                    },
                    .advance_loc2 => .{
                        .advance_loc2 = .{ .delta = try reader.readInt(u16, endian) },
                    },
                    .advance_loc4 => .{
                        .advance_loc4 = .{ .delta = try reader.readInt(u32, endian) },
                    },
                    .offset_extended => .{
                        .offset_extended = .{
                            .register = try leb.readUleb128(u8, reader),
                            .offset = try leb.readUleb128(u64, reader),
                        },
                    },
                    .restore_extended => .{
                        .restore_extended = .{
                            .register = try leb.readUleb128(u8, reader),
                        },
                    },
                    .undefined => .{
                        .undefined = .{
                            .register = try leb.readUleb128(u8, reader),
                        },
                    },
                    .same_value => .{
                        .same_value = .{
                            .register = try leb.readUleb128(u8, reader),
                        },
                    },
                    .register => .{
                        .register = .{
                            .register = try leb.readUleb128(u8, reader),
                            .target_register = try leb.readUleb128(u8, reader),
                        },
                    },
                    .remember_state => .{ .remember_state = {} },
                    .restore_state => .{ .restore_state = {} },
                    .def_cfa => .{
                        .def_cfa = .{
                            .register = try leb.readUleb128(u8, reader),
                            .offset = try leb.readUleb128(u64, reader),
                        },
                    },
                    .def_cfa_register => .{
                        .def_cfa_register = .{
                            .register = try leb.readUleb128(u8, reader),
                        },
                    },
                    .def_cfa_offset => .{
                        .def_cfa_offset = .{
                            .offset = try leb.readUleb128(u64, reader),
                        },
                    },
                    .def_cfa_expression => .{
                        .def_cfa_expression = .{
                            .block = try readBlock(stream),
                        },
                    },
                    .expression => .{
                        .expression = .{
                            .register = try leb.readUleb128(u8, reader),
                            .block = try readBlock(stream),
                        },
                    },
                    .offset_extended_sf => .{
                        .offset_extended_sf = .{
                            .register = try leb.readUleb128(u8, reader),
                            .offset = try leb.readIleb128(i64, reader),
                        },
                    },
                    .def_cfa_sf => .{
                        .def_cfa_sf = .{
                            .register = try leb.readUleb128(u8, reader),
                            .offset = try leb.readIleb128(i64, reader),
                        },
                    },
                    .def_cfa_offset_sf => .{
                        .def_cfa_offset_sf = .{
                            .offset = try leb.readIleb128(i64, reader),
                        },
                    },
                    .val_offset => .{
                        .val_offset = .{
                            .register = try leb.readUleb128(u8, reader),
                            .offset = try leb.readUleb128(u64, reader),
                        },
                    },
                    .val_offset_sf => .{
                        .val_offset_sf = .{
                            .register = try leb.readUleb128(u8, reader),
                            .offset = try leb.readIleb128(i64, reader),
                        },
                    },
                    .val_expression => .{
                        .val_expression = .{
                            .register = try leb.readUleb128(u8, reader),
                            .block = try readBlock(stream),
                        },
                    },
                };
            },
            Opcode.lo_user...Opcode.hi_user => return error.UnimplementedUserOpcode,
            else => return error.InvalidOpcode,
        }
    }
};
const builtin = @import("builtin");
const native_arch = builtin.cpu.arch;
const native_endian = native_arch.endian();

const std = @import("std");
const leb = std.leb;
const OP = std.dwarf.OP;
const abi = std.debug.Dwarf.abi;
const mem = std.mem;
const assert = std.debug.assert;

/// Expressions can be evaluated in different contexts, each requiring its own set of inputs.
/// Callers should specify all the fields relevant to their context. If a field is required
/// by the expression and it isn't in the context, error.IncompleteExpressionContext is returned.
pub const Context = struct {
    /// The dwarf format of the section this expression is in
    format: std.dwarf.Format = .@"32",
    /// If specified, any addresses will pass through before being accessed
    memory_accessor: ?*std.debug.MemoryAccessor = null,
    /// The compilation unit this expression relates to, if any
    compile_unit: ?*const std.debug.Dwarf.CompileUnit = null,
    /// When evaluating a user-presented expression, this is the address of the object being evaluated
    object_address: ?*const anyopaque = null,
    /// .debug_addr section
    debug_addr: ?[]const u8 = null,
    /// Thread context
    thread_context: ?*std.debug.ThreadContext = null,
    reg_context: ?abi.RegisterContext = null,
    /// Call frame address, if in a CFI context
    cfa: ?usize = null,
    /// This expression is a sub-expression from an OP.entry_value instruction
    entry_value_context: bool = false,
};

pub const Options = struct {
    /// The address size of the target architecture
    addr_size: u8 = @sizeOf(usize),
    /// Endianness of the target architecture
    endian: std.builtin.Endian = native_endian,
    /// Restrict the stack machine to a subset of opcodes used in call frame instructions
    call_frame_context: bool = false,
};

// Explicitly defined to support executing sub-expressions
pub const Error = error{
    UnimplementedExpressionCall,
    UnimplementedOpcode,
    UnimplementedUserOpcode,
    UnimplementedTypedComparison,
    UnimplementedTypeConversion,

    UnknownExpressionOpcode,

    IncompleteExpressionContext,

    InvalidCFAOpcode,
    InvalidExpression,
    InvalidFrameBase,
    InvalidIntegralTypeSize,
    InvalidRegister,
    InvalidSubExpression,
    InvalidTypeLength,

    TruncatedIntegralType,
} || abi.RegBytesError || error{ EndOfStream, Overflow, OutOfMemory, DivisionByZero };

/// A stack machine that can decode and run DWARF expressions.
/// Expressions can be decoded for non-native address size and endianness,
/// but can only be executed if the current target matches the configuration.
pub fn StackMachine(comptime options: Options) type {
    const addr_type = switch (options.addr_size) {
        2 => u16,
        4 => u32,
        8 => u64,
        else => @compileError("Unsupported address size of " ++ options.addr_size),
    };

    const addr_type_signed = switch (options.addr_size) {
        2 => i16,
        4 => i32,
        8 => i64,
        else => @compileError("Unsupported address size of " ++ options.addr_size),
    };

    return struct {
        const Self = @This();

        const Operand = union(enum) {
            generic: addr_type,
            register: u8,
            type_size: u8,
            branch_offset: i16,
            base_register: struct {
                base_register: u8,
                offset: i64,
            },
            composite_location: struct {
                size: u64,
                offset: i64,
            },
            block: []const u8,
            register_type: struct {
                register: u8,
                type_offset: addr_type,
            },
            const_type: struct {
                type_offset: addr_type,
                value_bytes: []const u8,
            },
            deref_type: struct {
                size: u8,
                type_offset: addr_type,
            },
        };

        const Value = union(enum) {
            generic: addr_type,

            // Typed value with a maximum size of a register
            regval_type: struct {
                // Offset of DW_TAG_base_type DIE
                type_offset: addr_type,
                type_size: u8,
                value: addr_type,
            },

            // Typed value specified directly in the instruction stream
            const_type: struct {
                // Offset of DW_TAG_base_type DIE
                type_offset: addr_type,
                // Backed by the instruction stream
                value_bytes: []const u8,
            },

            pub fn asIntegral(self: Value) !addr_type {
                return switch (self) {
                    .generic => |v| v,

                    // TODO: For these two prongs, look up the type and assert it's integral?
                    .regval_type => |regval_type| regval_type.value,
                    .const_type => |const_type| {
                        const value: u64 = switch (const_type.value_bytes.len) {
                            1 => mem.readInt(u8, const_type.value_bytes[0..1], native_endian),
                            2 => mem.readInt(u16, const_type.value_bytes[0..2], native_endian),
                            4 => mem.readInt(u32, const_type.value_bytes[0..4], native_endian),
                            8 => mem.readInt(u64, const_type.value_bytes[0..8], native_endian),
                            else => return error.InvalidIntegralTypeSize,
                        };

                        return std.math.cast(addr_type, value) orelse error.TruncatedIntegralType;
                    },
                };
            }
        };

        stack: std.ArrayListUnmanaged(Value) = .empty,

        pub fn reset(self: *Self) void {
            self.stack.clearRetainingCapacity();
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.stack.deinit(allocator);
        }

        fn generic(value: anytype) Operand {
            const int_info = @typeInfo(@TypeOf(value)).int;
            if (@sizeOf(@TypeOf(value)) > options.addr_size) {
                return .{ .generic = switch (int_info.signedness) {
                    .signed => @bitCast(@as(addr_type_signed, @truncate(value))),
                    .unsigned => @truncate(value),
                } };
            } else {
                return .{ .generic = switch (int_info.signedness) {
                    .signed => @bitCast(@as(addr_type_signed, @intCast(value))),
                    .unsigned => @intCast(value),
                } };
            }
        }

        pub fn readOperand(stream: *std.io.FixedBufferStream([]const u8), opcode: u8, context: Context) !?Operand {
            const reader = stream.reader();
            return switch (opcode) {
                OP.addr => generic(try reader.readInt(addr_type, options.endian)),
                OP.call_ref => switch (context.format) {
                    .@"32" => generic(try reader.readInt(u32, options.endian)),
                    .@"64" => generic(try reader.readInt(u64, options.endian)),
                },
                OP.const1u,
                OP.pick,
                => generic(try reader.readByte()),
                OP.deref_size,
                OP.xderef_size,
                => .{ .type_size = try reader.readByte() },
                OP.const1s => generic(try reader.readByteSigned()),
                OP.const2u,
                OP.call2,
                => generic(try reader.readInt(u16, options.endian)),
                OP.call4 => generic(try reader.readInt(u32, options.endian)),
                OP.const2s => generic(try reader.readInt(i16, options.endian)),
                OP.bra,
                OP.skip,
                => .{ .branch_offset = try reader.readInt(i16, options.endian) },
                OP.const4u => generic(try reader.readInt(u32, options.endian)),
                OP.const4s => generic(try reader.readInt(i32, options.endian)),
                OP.const8u => generic(try reader.readInt(u64, options.endian)),
                OP.const8s => generic(try reader.readInt(i64, options.endian)),
                OP.constu,
                OP.plus_uconst,
                OP.addrx,
                OP.constx,
                OP.convert,
                OP.reinterpret,
                => generic(try leb.readUleb128(u64, reader)),
                OP.consts,
                OP.fbreg,
                => generic(try leb.readIleb128(i64, reader)),
                OP.lit0...OP.lit31 => |n| generic(n - OP.lit0),
                OP.reg0...OP.reg31 => |n| .{ .register = n - OP.reg0 },
                OP.breg0...OP.breg31 => |n| .{ .base_register = .{
                    .base_register = n - OP.breg0,
                    .offset = try leb.readIleb128(i64, reader),
                } },
                OP.regx => .{ .register = try leb.readUleb128(u8, reader) },
                OP.bregx => blk: {
                    const base_register = try leb.readUleb128(u8, reader);
                    const offset = try leb.readIleb128(i64, reader);
                    break :blk .{ .base_register = .{
                        .base_register = base_register,
                        .offset = offset,
                    } };
                },
                OP.regval_type => blk: {
                    const register = try leb.readUleb128(u8, reader);
                    const type_offset = try leb.readUleb128(addr_type, reader);
                    break :blk .{ .register_type = .{
                        .register = register,
                        .type_offset = type_offset,
                    } };
                },
                OP.piece => .{
                    .composite_location = .{
                        .size = try leb.readUleb128(u8, reader),
                        .offset = 0,
                    },
                },
                OP.bit_piece => blk: {
                    const size = try leb.readUleb128(u8, reader);
                    const offset = try leb.readIleb128(i64, reader);
                    break :blk .{ .composite_location = .{
                        .size = size,
                        .offset = offset,
                    } };
                },
                OP.implicit_value, OP.entry_value => blk: {
                    const size = try leb.readUleb128(u8, reader);
                    if (stream.pos + size > stream.buffer.len) return error.InvalidExpression;
                    const block = stream.buffer[stream.pos..][0..size];
                    stream.pos += size;
                    break :blk .{
                        .block = block,
                    };
                },
                OP.const_type => blk: {
                    const type_offset = try leb.readUleb128(addr_type, reader);
                    const size = try reader.readByte();
                    if (stream.pos + size > stream.buffer.len) return error.InvalidExpression;
                    const value_bytes = stream.buffer[stream.pos..][0..size];
                    stream.pos += size;
                    break :blk .{ .const_type = .{
                        .type_offset = type_offset,
                        .value_bytes = value_bytes,
                    } };
                },
                OP.deref_type,
                OP.xderef_type,
                => .{
                    .deref_type = .{
                        .size = try reader.readByte(),
                        .type_offset = try leb.readUleb128(addr_type, reader),
                    },
                },
                OP.lo_user...OP.hi_user => return error.UnimplementedUserOpcode,
                else => null,
            };
        }

        pub fn run(
            self: *Self,
            expression: []const u8,
            allocator: std.mem.Allocator,
            context: Context,
            initial_value: ?usize,
        ) Error!?Value {
            if (initial_value) |i| try self.stack.append(allocator, .{ .generic = i });
            var stream = std.io.fixedBufferStream(expression);
            while (try self.step(&stream, allocator, context)) {}
            if (self.stack.items.len == 0) return null;
            return self.stack.items[self.stack.items.len - 1];
        }

        /// Reads an opcode and its operands from `stream`, then executes it
        pub fn step(
            self: *Self,
            stream: *std.io.FixedBufferStream([]const u8),
            allocator: std.mem.Allocator,
            context: Context,
        ) Error!bool {
            if (@sizeOf(usize) != @sizeOf(addr_type) or options.endian != native_endian)
                @compileError("Execution of non-native address sizes / endianness is not supported");

            const opcode = try stream.reader().readByte();
            if (options.call_frame_context and !isOpcodeValidInCFA(opcode)) return error.InvalidCFAOpcode;
            const operand = try readOperand(stream, opcode, context);
            switch (opcode) {

                // 2.5.1.1: Literal Encodings
                OP.lit0...OP.lit31,
                OP.addr,
                OP.const1u,
                OP.const2u,
                OP.const4u,
                OP.const8u,
                OP.const1s,
                OP.const2s,
                OP.const4s,
                OP.const8s,
                OP.constu,
                OP.consts,
                => try self.stack.append(allocator, .{ .generic = operand.?.generic }),

                OP.const_type => {
                    const const_type = operand.?.const_type;
                    try self.stack.append(allocator, .{ .const_type = .{
                        .type_offset = const_type.type_offset,
                        .value_bytes = const_type.value_bytes,
                    } });
                },

                OP.addrx,
                OP.constx,
                => {
                    if (context.compile_unit == null) return error.IncompleteExpressionContext;
                    if (context.debug_addr == null) return error.IncompleteExpressionContext;
                    const debug_addr_index = operand.?.generic;
                    const offset = context.compile_unit.?.addr_base + debug_addr_index;
                    if (offset >= context.debug_addr.?.len) return error.InvalidExpression;
                    const value = mem.readInt(usize, context.debug_addr.?[offset..][0..@sizeOf(usize)], native_endian);
                    try self.stack.append(allocator, .{ .generic = value });
                },

                // 2.5.1.2: Register Values
                OP.fbreg => {
                    if (context.compile_unit == null) return error.IncompleteExpressionContext;
                    if (context.compile_unit.?.frame_base == null) return error.IncompleteExpressionContext;

                    const offset: i64 = @intCast(operand.?.generic);
                    _ = offset;

                    switch (context.compile_unit.?.frame_base.?.*) {
                        .exprloc => {
                            // TODO: Run this expression in a nested stack machine
                            return error.UnimplementedOpcode;
                        },
                        .loclistx => {
                            // TODO: Read value from .debug_loclists
                            return error.UnimplementedOpcode;
                        },
                        .sec_offset => {
                            // TODO: Read value from .debug_loclists
                            return error.UnimplementedOpcode;
                        },
                        else => return error.InvalidFrameBase,
                    }
                },
                OP.breg0...OP.breg31,
                OP.bregx,
                => {
                    if (context.thread_context == null) return error.IncompleteExpressionContext;

                    const base_register = operand.?.base_register;
                    var value: i64 = @intCast(mem.readInt(usize, (try abi.regBytes(
                        context.thread_context.?,
                        base_register.base_register,
                        context.reg_context,
                    ))[0..@sizeOf(usize)], native_endian));
                    value += base_register.offset;
                    try self.stack.append(allocator, .{ .generic = @intCast(value) });
                },
                OP.regval_type => {
                    const register_type = operand.?.register_type;
                    const value = mem.readInt(usize, (try abi.regBytes(
                        context.thread_context.?,
                        register_type.register,
                        context.reg_context,
                    ))[0..@sizeOf(usize)], native_endian);
                    try self.stack.append(allocator, .{
                        .regval_type = .{
                            .type_offset = register_type.type_offset,
                            .type_size = @sizeOf(addr_type),
                            .value = value,
                        },
                    });
                },

                // 2.5.1.3: Stack Operations
                OP.dup => {
                    if (self.stack.items.len == 0) return error.InvalidExpression;
                    try self.stack.append(allocator, self.stack.items[self.stack.items.len - 1]);
                },
                OP.drop => {
                    _ = self.stack.pop();
                },
                OP.pick, OP.over => {
                    const stack_index = if (opcode == OP.over) 1 else operand.?.generic;
                    if (stack_index >= self.stack.items.len) return error.InvalidExpression;
                    try self.stack.append(allocator, self.stack.items[self.stack.items.len - 1 - stack_index]);
                },
                OP.swap => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    mem.swap(Value, &self.stack.items[self.stack.items.len - 1], &self.stack.items[self.stack.items.len - 2]);
                },
                OP.rot => {
                    if (self.stack.items.len < 3) return error.InvalidExpression;
                    const first = self.stack.items[self.stack.items.len - 1];
                    self.stack.items[self.stack.items.len - 1] = self.stack.items[self.stack.items.len - 2];
                    self.stack.items[self.stack.items.len - 2] = self.stack.items[self.stack.items.len - 3];
                    self.stack.items[self.stack.items.len - 3] = first;
                },
                OP.deref,
                OP.xderef,
                OP.deref_size,
                OP.xderef_size,
                OP.deref_type,
                OP.xderef_type,
                => {
                    if (self.stack.items.len == 0) return error.InvalidExpression;
                    const addr = try self.stack.items[self.stack.items.len - 1].asIntegral();
                    const addr_space_identifier: ?usize = switch (opcode) {
                        OP.xderef,
                        OP.xderef_size,
                        OP.xderef_type,
                        => blk: {
                            _ = self.stack.pop();
                            if (self.stack.items.len == 0) return error.InvalidExpression;
                            break :blk try self.stack.items[self.stack.items.len - 1].asIntegral();
                        },
                        else => null,
                    };

                    // Usage of addr_space_identifier in the address calculation is implementation defined.
                    // This code will need to be updated to handle any architectures that utilize this.
                    _ = addr_space_identifier;

                    const size = switch (opcode) {
                        OP.deref,
                        OP.xderef,
                        => @sizeOf(addr_type),
                        OP.deref_size,
                        OP.xderef_size,
                        => operand.?.type_size,
                        OP.deref_type,
                        OP.xderef_type,
                        => operand.?.deref_type.size,
                        else => unreachable,
                    };

                    if (context.memory_accessor) |memory_accessor| {
                        if (!switch (size) {
                            1 => memory_accessor.load(u8, addr) != null,
                            2 => memory_accessor.load(u16, addr) != null,
                            4 => memory_accessor.load(u32, addr) != null,
                            8 => memory_accessor.load(u64, addr) != null,
                            else => return error.InvalidExpression,
                        }) return error.InvalidExpression;
                    }

                    const value: addr_type = std.math.cast(addr_type, @as(u64, switch (size) {
                        1 => @as(*const u8, @ptrFromInt(addr)).*,
                        2 => @as(*const u16, @ptrFromInt(addr)).*,
                        4 => @as(*const u32, @ptrFromInt(addr)).*,
                        8 => @as(*const u64, @ptrFromInt(addr)).*,
                        else => return error.InvalidExpression,
                    })) orelse return error.InvalidExpression;

                    switch (opcode) {
                        OP.deref_type,
                        OP.xderef_type,
                        => {
                            self.stack.items[self.stack.items.len - 1] = .{
                                .regval_type = .{
                                    .type_offset = operand.?.deref_type.type_offset,
                                    .type_size = operand.?.deref_type.size,
                                    .value = value,
                                },
                            };
                        },
                        else => {
                            self.stack.items[self.stack.items.len - 1] = .{ .generic = value };
                        },
                    }
                },
                OP.push_object_address => {
                    // In sub-expressions, `push_object_address` is not meaningful (as per the
                    // spec), so treat it like a nop
                    if (!context.entry_value_context) {
                        if (context.object_address == null) return error.IncompleteExpressionContext;
                        try self.stack.append(allocator, .{ .generic = @intFromPtr(context.object_address.?) });
                    }
                },
                OP.form_tls_address => {
                    return error.UnimplementedOpcode;
                },
                OP.call_frame_cfa => {
                    if (context.cfa) |cfa| {
                        try self.stack.append(allocator, .{ .generic = cfa });
                    } else return error.IncompleteExpressionContext;
                },

                // 2.5.1.4: Arithmetic and Logical Operations
                OP.abs => {
                    if (self.stack.items.len == 0) return error.InvalidExpression;
                    const value: isize = @bitCast(try self.stack.items[self.stack.items.len - 1].asIntegral());
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = @abs(value),
                    };
                },
                OP.@"and" => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const a = try self.stack.pop().?.asIntegral();
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = a & try self.stack.items[self.stack.items.len - 1].asIntegral(),
                    };
                },
                OP.div => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const a: isize = @bitCast(try self.stack.pop().?.asIntegral());
                    const b: isize = @bitCast(try self.stack.items[self.stack.items.len - 1].asIntegral());
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = @bitCast(try std.math.divTrunc(isize, b, a)),
                    };
                },
                OP.minus => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const b = try self.stack.pop().?.asIntegral();
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = try std.math.sub(addr_type, try self.stack.items[self.stack.items.len - 1].asIntegral(), b),
                    };
                },
                OP.mod => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const a: isize = @bitCast(try self.stack.pop().?.asIntegral());
                    const b: isize = @bitCast(try self.stack.items[self.stack.items.len - 1].asIntegral());
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = @bitCast(@mod(b, a)),
                    };
                },
                OP.mul => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const a: isize = @bitCast(try self.stack.pop().?.asIntegral());
                    const b: isize = @bitCast(try self.stack.items[self.stack.items.len - 1].asIntegral());
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = @bitCast(@mulWithOverflow(a, b)[0]),
                    };
                },
                OP.neg => {
                    if (self.stack.items.len == 0) return error.InvalidExpression;
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = @bitCast(
                            try std.math.negate(
                                @as(isize, @bitCast(try self.stack.items[self.stack.items.len - 1].asIntegral())),
                            ),
                        ),
                    };
                },
                OP.not => {
                    if (self.stack.items.len == 0) return error.InvalidExpression;
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = ~try self.stack.items[self.stack.items.len - 1].asIntegral(),
                    };
                },
                OP.@"or" => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const a = try self.stack.pop().?.asIntegral();
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = a | try self.stack.items[self.stack.items.len - 1].asIntegral(),
                    };
                },
                OP.plus => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const b = try self.stack.pop().?.asIntegral();
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = try std.math.add(addr_type, try self.stack.items[self.stack.items.len - 1].asIntegral(), b),
                    };
                },
                OP.plus_uconst => {
                    if (self.stack.items.len == 0) return error.InvalidExpression;
                    const constant = operand.?.generic;
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = try std.math.add(addr_type, try self.stack.items[self.stack.items.len - 1].asIntegral(), constant),
                    };
                },
                OP.shl => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const a = try self.stack.pop().?.asIntegral();
                    const b = try self.stack.items[self.stack.items.len - 1].asIntegral();
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = std.math.shl(usize, b, a),
                    };
                },
                OP.shr => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const a = try self.stack.pop().?.asIntegral();
                    const b = try self.stack.items[self.stack.items.len - 1].asIntegral();
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = std.math.shr(usize, b, a),
                    };
                },
                OP.shra => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const a = try self.stack.pop().?.asIntegral();
                    const b: isize = @bitCast(try self.stack.items[self.stack.items.len - 1].asIntegral());
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = @bitCast(std.math.shr(isize, b, a)),
                    };
                },
                OP.xor => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const a = try self.stack.pop().?.asIntegral();
                    self.stack.items[self.stack.items.len - 1] = .{
                        .generic = a ^ try self.stack.items[self.stack.items.len - 1].asIntegral(),
                    };
                },

                // 2.5.1.5: Control Flow Operations
                OP.le,
                OP.ge,
                OP.eq,
                OP.lt,
                OP.gt,
                OP.ne,
                => {
                    if (self.stack.items.len < 2) return error.InvalidExpression;
                    const a = self.stack.pop().?;
                    const b = self.stack.items[self.stack.items.len - 1];

                    if (a == .generic and b == .generic) {
                        const a_int: isize = @bitCast(a.asIntegral() catch unreachable);
                        const b_int: isize = @bitCast(b.asIntegral() catch unreachable);
                        const result = @intFromBool(switch (opcode) {
                            OP.le => b_int <= a_int,
                            OP.ge => b_int >= a_int,
                            OP.eq => b_int == a_int,
                            OP.lt => b_int < a_int,
                            OP.gt => b_int > a_int,
                            OP.ne => b_int != a_int,
                            else => unreachable,
                        });

                        self.stack.items[self.stack.items.len - 1] = .{ .generic = result };
                    } else {
                        // TODO: Load the types referenced by these values, find their comparison operator, and run it
                        return error.UnimplementedTypedComparison;
                    }
                },
                OP.skip, OP.bra => {
                    const branch_offset = operand.?.branch_offset;
                    const condition = if (opcode == OP.bra) blk: {
                        if (self.stack.items.len == 0) return error.InvalidExpression;
                        break :blk try self.stack.pop().?.asIntegral() != 0;
                    } else true;

                    if (condition) {
                        const new_pos = std.math.cast(
                            usize,
                            try std.math.add(isize, @as(isize, @intCast(stream.pos)), branch_offset),
                        ) orelse return error.InvalidExpression;

                        if (new_pos < 0 or new_pos > stream.buffer.len) return error.InvalidExpression;
                        stream.pos = new_pos;
                    }
                },
                OP.call2,
                OP.call4,
                OP.call_ref,
                => {
                    const debug_info_offset = operand.?.generic;
                    _ = debug_info_offset;

                    // TODO: Load a DIE entry at debug_info_offset in a .debug_info section (the spec says that it
                    //       can be in a separate exe / shared object from the one containing this expression).
                    //       Transfer control to the DW_AT_location attribute, with the current stack as input.

                    return error.UnimplementedExpressionCall;
                },

                // 2.5.1.6: Type Conversions
                OP.convert => {
                    if (self.stack.items.len == 0) return error.InvalidExpression;
                    const type_offset = operand.?.generic;

                    // TODO: Load the DW_TAG_base_type entries in context.compile_unit and verify both types are the same size
                    const value = self.stack.items[self.stack.items.len - 1];
                    if (type_offset == 0) {
                        self.stack.items[self.stack.items.len - 1] = .{ .generic = try value.asIntegral() };
                    } else {
                        // TODO: Load the DW_TAG_base_type entry in context.compile_unit, find a conversion operator
                        //       from the old type to the new type, run it.
                        return error.UnimplementedTypeConversion;
                    }
                },
                OP.reinterpret => {
                    if (self.stack.items.len == 0) return error.InvalidExpression;
                    const type_offset = operand.?.generic;

                    // TODO: Load the DW_TAG_base_type entries in context.compile_unit and verify both types are the same size
                    const value = self.stack.items[self.stack.items.len - 1];
                    if (type_offset == 0) {
                        self.stack.items[self.stack.items.len - 1] = .{ .generic = try value.asIntegral() };
                    } else {
                        self.stack.items[self.stack.items.len - 1] = switch (value) {
                            .generic => |v| .{
                                .regval_type = .{
                                    .type_offset = type_offset,
                                    .type_size = @sizeOf(addr_type),
     ```
