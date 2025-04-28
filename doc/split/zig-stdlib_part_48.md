```
            });

                return .{
                    .relocated_address = relocated_address,
                    .symbol = symbol,
                    .o_file_info = o_file_info,
                };
            }
        }

        pub fn getDwarfInfoForAddress(self: *@This(), allocator: Allocator, address: usize) !?*Dwarf {
            return if ((try self.getOFileInfoForAddress(allocator, address)).o_file_info) |o_file_info| &o_file_info.di else null;
        }
    },
    .uefi, .windows => struct {
        base_address: usize,
        pdb: ?Pdb = null,
        dwarf: ?Dwarf = null,
        coff_image_base: u64,

        /// Only used if pdb is non-null
        coff_section_headers: []coff.SectionHeader,

        pub fn deinit(self: *@This(), allocator: Allocator) void {
            if (self.dwarf) |*dwarf| {
                dwarf.deinit(allocator);
            }

            if (self.pdb) |*p| {
                p.deinit();
                allocator.free(self.coff_section_headers);
            }
        }

        fn getSymbolFromPdb(self: *@This(), relocated_address: usize) !?std.debug.Symbol {
            var coff_section: *align(1) const coff.SectionHeader = undefined;
            const mod_index = for (self.pdb.?.sect_contribs) |sect_contrib| {
                if (sect_contrib.section > self.coff_section_headers.len) continue;
                // Remember that SectionContribEntry.Section is 1-based.
                coff_section = &self.coff_section_headers[sect_contrib.section - 1];

                const vaddr_start = coff_section.virtual_address + sect_contrib.offset;
                const vaddr_end = vaddr_start + sect_contrib.size;
                if (relocated_address >= vaddr_start and relocated_address < vaddr_end) {
                    break sect_contrib.module_index;
                }
            } else {
                // we have no information to add to the address
                return null;
            };

            const module = (try self.pdb.?.getModule(mod_index)) orelse
                return error.InvalidDebugInfo;
            const obj_basename = fs.path.basename(module.obj_file_name);

            const symbol_name = self.pdb.?.getSymbolName(
                module,
                relocated_address - coff_section.virtual_address,
            ) orelse "???";
            const opt_line_info = try self.pdb.?.getLineNumberInfo(
                module,
                relocated_address - coff_section.virtual_address,
            );

            return .{
                .name = symbol_name,
                .compile_unit_name = obj_basename,
                .source_location = opt_line_info,
            };
        }

        pub fn getSymbolAtAddress(self: *@This(), allocator: Allocator, address: usize) !std.debug.Symbol {
            // Translate the VA into an address into this object
            const relocated_address = address - self.base_address;

            if (self.pdb != null) {
                if (try self.getSymbolFromPdb(relocated_address)) |symbol| return symbol;
            }

            if (self.dwarf) |*dwarf| {
                const dwarf_address = relocated_address + self.coff_image_base;
                return dwarf.getSymbol(allocator, dwarf_address);
            }

            return .{};
        }

        pub fn getDwarfInfoForAddress(self: *@This(), allocator: Allocator, address: usize) !?*Dwarf {
            _ = allocator;
            _ = address;

            return switch (self.debug_data) {
                .dwarf => |*dwarf| dwarf,
                else => null,
            };
        }
    },
    .linux, .netbsd, .freebsd, .dragonfly, .openbsd, .haiku, .solaris, .illumos => Dwarf.ElfModule,
    .wasi, .emscripten => struct {
        pub fn deinit(self: *@This(), allocator: Allocator) void {
            _ = self;
            _ = allocator;
        }

        pub fn getSymbolAtAddress(self: *@This(), allocator: Allocator, address: usize) !std.debug.Symbol {
            _ = self;
            _ = allocator;
            _ = address;
            return .{};
        }

        pub fn getDwarfInfoForAddress(self: *@This(), allocator: Allocator, address: usize) !?*Dwarf {
            _ = self;
            _ = allocator;
            _ = address;
            return null;
        }
    },
    else => Dwarf,
};

/// How is this different than `Module` when the host is Windows?
/// Why are both stored in the `SelfInfo` struct?
/// Boy, it sure would be nice if someone added documentation comments for this
/// struct explaining it.
pub const WindowsModule = struct {
    base_address: usize,
    size: u32,
    name: []const u8,
    handle: windows.HMODULE,

    // Set when the image file needed to be mapped from disk
    mapped_file: ?struct {
        file: File,
        section_handle: windows.HANDLE,
        section_view: []const u8,

        pub fn deinit(self: @This()) void {
            const process_handle = windows.GetCurrentProcess();
            assert(windows.ntdll.NtUnmapViewOfSection(process_handle, @constCast(@ptrCast(self.section_view.ptr))) == .SUCCESS);
            windows.CloseHandle(self.section_handle);
            self.file.close();
        }
    } = null,
};

/// This takes ownership of macho_file: users of this function should not close
/// it themselves, even on error.
/// TODO it's weird to take ownership even on error, rework this code.
fn readMachODebugInfo(allocator: Allocator, macho_file: File) !Module {
    const mapped_mem = try mapWholeFile(macho_file);

    const hdr: *const macho.mach_header_64 = @ptrCast(@alignCast(mapped_mem.ptr));
    if (hdr.magic != macho.MH_MAGIC_64)
        return error.InvalidDebugInfo;

    var it = macho.LoadCommandIterator{
        .ncmds = hdr.ncmds,
        .buffer = mapped_mem[@sizeOf(macho.mach_header_64)..][0..hdr.sizeofcmds],
    };
    const symtab = while (it.next()) |cmd| switch (cmd.cmd()) {
        .SYMTAB => break cmd.cast(macho.symtab_command).?,
        else => {},
    } else return error.MissingDebugInfo;

    const syms = @as(
        [*]const macho.nlist_64,
        @ptrCast(@alignCast(&mapped_mem[symtab.symoff])),
    )[0..symtab.nsyms];
    const strings = mapped_mem[symtab.stroff..][0 .. symtab.strsize - 1 :0];

    const symbols_buf = try allocator.alloc(MachoSymbol, syms.len);

    var ofile: u32 = undefined;
    var last_sym: MachoSymbol = undefined;
    var symbol_index: usize = 0;
    var state: enum {
        init,
        oso_open,
        oso_close,
        bnsym,
        fun_strx,
        fun_size,
        ensym,
    } = .init;

    for (syms) |*sym| {
        if (!sym.stab()) continue;

        // TODO handle globals N_GSYM, and statics N_STSYM
        switch (sym.n_type) {
            macho.N_OSO => {
                switch (state) {
                    .init, .oso_close => {
                        state = .oso_open;
                        ofile = sym.n_strx;
                    },
                    else => return error.InvalidDebugInfo,
                }
            },
            macho.N_BNSYM => {
                switch (state) {
                    .oso_open, .ensym => {
                        state = .bnsym;
                        last_sym = .{
                            .strx = 0,
                            .addr = sym.n_value,
                            .size = 0,
                            .ofile = ofile,
                        };
                    },
                    else => return error.InvalidDebugInfo,
                }
            },
            macho.N_FUN => {
                switch (state) {
                    .bnsym => {
                        state = .fun_strx;
                        last_sym.strx = sym.n_strx;
                    },
                    .fun_strx => {
                        state = .fun_size;
                        last_sym.size = @as(u32, @intCast(sym.n_value));
                    },
                    else => return error.InvalidDebugInfo,
                }
            },
            macho.N_ENSYM => {
                switch (state) {
                    .fun_size => {
                        state = .ensym;
                        symbols_buf[symbol_index] = last_sym;
                        symbol_index += 1;
                    },
                    else => return error.InvalidDebugInfo,
                }
            },
            macho.N_SO => {
                switch (state) {
                    .init, .oso_close => {},
                    .oso_open, .ensym => {
                        state = .oso_close;
                    },
                    else => return error.InvalidDebugInfo,
                }
            },
            else => {},
        }
    }

    switch (state) {
        .init => return error.MissingDebugInfo,
        .oso_close => {},
        else => return error.InvalidDebugInfo,
    }

    const symbols = try allocator.realloc(symbols_buf, symbol_index);

    // Even though lld emits symbols in ascending order, this debug code
    // should work for programs linked in any valid way.
    // This sort is so that we can binary search later.
    mem.sort(MachoSymbol, symbols, {}, MachoSymbol.addressLessThan);

    return .{
        .base_address = undefined,
        .vmaddr_slide = undefined,
        .mapped_memory = mapped_mem,
        .ofiles = Module.OFileTable.init(allocator),
        .symbols = symbols,
        .strings = strings,
    };
}

fn readCoffDebugInfo(allocator: Allocator, coff_obj: *coff.Coff) !Module {
    nosuspend {
        var di: Module = .{
            .base_address = undefined,
            .coff_image_base = coff_obj.getImageBase(),
            .coff_section_headers = undefined,
        };

        if (coff_obj.getSectionByName(".debug_info")) |_| {
            // This coff file has embedded DWARF debug info
            var sections: Dwarf.SectionArray = Dwarf.null_section_array;
            errdefer for (sections) |section| if (section) |s| if (s.owned) allocator.free(s.data);

            inline for (@typeInfo(Dwarf.Section.Id).@"enum".fields, 0..) |section, i| {
                sections[i] = if (coff_obj.getSectionByName("." ++ section.name)) |section_header| blk: {
                    break :blk .{
                        .data = try coff_obj.getSectionDataAlloc(section_header, allocator),
                        .virtual_address = section_header.virtual_address,
                        .owned = true,
                    };
                } else null;
            }

            var dwarf: Dwarf = .{
                .endian = native_endian,
                .sections = sections,
                .is_macho = false,
            };

            try Dwarf.open(&dwarf, allocator);
            di.dwarf = dwarf;
        }

        const raw_path = try coff_obj.getPdbPath() orelse return di;
        const path = blk: {
            if (fs.path.isAbsolute(raw_path)) {
                break :blk raw_path;
            } else {
                const self_dir = try fs.selfExeDirPathAlloc(allocator);
                defer allocator.free(self_dir);
                break :blk try fs.path.join(allocator, &.{ self_dir, raw_path });
            }
        };
        defer if (path.ptr != raw_path.ptr) allocator.free(path);

        di.pdb = Pdb.init(allocator, path) catch |err| switch (err) {
            error.FileNotFound, error.IsDir => {
                if (di.dwarf == null) return error.MissingDebugInfo;
                return di;
            },
            else => return err,
        };
        try di.pdb.?.parseInfoStream();
        try di.pdb.?.parseDbiStream();

        if (!mem.eql(u8, &coff_obj.guid, &di.pdb.?.guid) or coff_obj.age != di.pdb.?.age)
            return error.InvalidDebugInfo;

        // Only used by the pdb path
        di.coff_section_headers = try coff_obj.getSectionHeadersAlloc(allocator);
        errdefer allocator.free(di.coff_section_headers);

        return di;
    }
}

/// Reads debug info from an ELF file, or the current binary if none in specified.
/// If the required sections aren't present but a reference to external debug info is,
/// then this this function will recurse to attempt to load the debug sections from
/// an external file.
pub fn readElfDebugInfo(
    allocator: Allocator,
    elf_filename: ?[]const u8,
    build_id: ?[]const u8,
    expected_crc: ?u32,
    parent_sections: *Dwarf.SectionArray,
    parent_mapped_mem: ?[]align(std.heap.page_size_min) const u8,
) !Dwarf.ElfModule {
    nosuspend {
        const elf_file = (if (elf_filename) |filename| blk: {
            break :blk fs.cwd().openFile(filename, .{});
        } else fs.openSelfExe(.{})) catch |err| switch (err) {
            error.FileNotFound => return error.MissingDebugInfo,
            else => return err,
        };

        const mapped_mem = try mapWholeFile(elf_file);
        return Dwarf.ElfModule.load(
            allocator,
            mapped_mem,
            build_id,
            expected_crc,
            parent_sections,
            parent_mapped_mem,
            elf_filename,
        );
    }
}

const MachoSymbol = struct {
    strx: u32,
    addr: u64,
    size: u32,
    ofile: u32,

    /// Returns the address from the macho file
    fn address(self: MachoSymbol) u64 {
        return self.addr;
    }

    fn addressLessThan(context: void, lhs: MachoSymbol, rhs: MachoSymbol) bool {
        _ = context;
        return lhs.addr < rhs.addr;
    }
};

/// Takes ownership of file, even on error.
/// TODO it's weird to take ownership even on error, rework this code.
fn mapWholeFile(file: File) ![]align(std.heap.page_size_min) const u8 {
    nosuspend {
        defer file.close();

        const file_len = math.cast(usize, try file.getEndPos()) orelse math.maxInt(usize);
        const mapped_mem = try posix.mmap(
            null,
            file_len,
            posix.PROT.READ,
            .{ .TYPE = .SHARED },
            file.handle,
            0,
        );
        errdefer posix.munmap(mapped_mem);

        return mapped_mem;
    }
}

fn machoSearchSymbols(symbols: []const MachoSymbol, address: usize) ?*const MachoSymbol {
    var min: usize = 0;
    var max: usize = symbols.len - 1;
    while (min < max) {
        const mid = min + (max - min) / 2;
        const curr = &symbols[mid];
        const next = &symbols[mid + 1];
        if (address >= next.address()) {
            min = mid + 1;
        } else if (address < curr.address()) {
            max = mid;
        } else {
            return curr;
        }
    }

    const max_sym = &symbols[symbols.len - 1];
    if (address >= max_sym.address())
        return max_sym;

    return null;
}

test machoSearchSymbols {
    const symbols = [_]MachoSymbol{
        .{ .addr = 100, .strx = undefined, .size = undefined, .ofile = undefined },
        .{ .addr = 200, .strx = undefined, .size = undefined, .ofile = undefined },
        .{ .addr = 300, .strx = undefined, .size = undefined, .ofile = undefined },
    };

    try testing.expectEqual(null, machoSearchSymbols(&symbols, 0));
    try testing.expectEqual(null, machoSearchSymbols(&symbols, 99));
    try testing.expectEqual(&symbols[0], machoSearchSymbols(&symbols, 100).?);
    try testing.expectEqual(&symbols[0], machoSearchSymbols(&symbols, 150).?);
    try testing.expectEqual(&symbols[0], machoSearchSymbols(&symbols, 199).?);

    try testing.expectEqual(&symbols[1], machoSearchSymbols(&symbols, 200).?);
    try testing.expectEqual(&symbols[1], machoSearchSymbols(&symbols, 250).?);
    try testing.expectEqual(&symbols[1], machoSearchSymbols(&symbols, 299).?);

    try testing.expectEqual(&symbols[2], machoSearchSymbols(&symbols, 300).?);
    try testing.expectEqual(&symbols[2], machoSearchSymbols(&symbols, 301).?);
    try testing.expectEqual(&symbols[2], machoSearchSymbols(&symbols, 5000).?);
}

/// Unwind a frame using MachO compact unwind info (from __unwind_info).
/// If the compact encoding can't encode a way to unwind a frame, it will
/// defer unwinding to DWARF, in which case `.eh_frame` will be used if available.
pub fn unwindFrameMachO(
    allocator: Allocator,
    base_address: usize,
    context: *UnwindContext,
    ma: *std.debug.MemoryAccessor,
    unwind_info: []const u8,
    eh_frame: ?[]const u8,
) !usize {
    const header = std.mem.bytesAsValue(
        macho.unwind_info_section_header,
        unwind_info[0..@sizeOf(macho.unwind_info_section_header)],
    );
    const indices = std.mem.bytesAsSlice(
        macho.unwind_info_section_header_index_entry,
        unwind_info[header.indexSectionOffset..][0 .. header.indexCount * @sizeOf(macho.unwind_info_section_header_index_entry)],
    );
    if (indices.len == 0) return error.MissingUnwindInfo;

    const mapped_pc = context.pc - base_address;
    const second_level_index = blk: {
        var left: usize = 0;
        var len: usize = indices.len;

        while (len > 1) {
            const mid = left + len / 2;
            const offset = indices[mid].functionOffset;
            if (mapped_pc < offset) {
                len /= 2;
            } else {
                left = mid;
                if (mapped_pc == offset) break;
                len -= len / 2;
            }
        }

        // Last index is a sentinel containing the highest address as its functionOffset
        if (indices[left].secondLevelPagesSectionOffset == 0) return error.MissingUnwindInfo;
        break :blk &indices[left];
    };

    const common_encodings = std.mem.bytesAsSlice(
        macho.compact_unwind_encoding_t,
        unwind_info[header.commonEncodingsArraySectionOffset..][0 .. header.commonEncodingsArrayCount * @sizeOf(macho.compact_unwind_encoding_t)],
    );

    const start_offset = second_level_index.secondLevelPagesSectionOffset;
    const kind = std.mem.bytesAsValue(
        macho.UNWIND_SECOND_LEVEL,
        unwind_info[start_offset..][0..@sizeOf(macho.UNWIND_SECOND_LEVEL)],
    );

    const entry: struct {
        function_offset: usize,
        raw_encoding: u32,
    } = switch (kind.*) {
        .REGULAR => blk: {
            const page_header = std.mem.bytesAsValue(
                macho.unwind_info_regular_second_level_page_header,
                unwind_info[start_offset..][0..@sizeOf(macho.unwind_info_regular_second_level_page_header)],
            );

            const entries = std.mem.bytesAsSlice(
                macho.unwind_info_regular_second_level_entry,
                unwind_info[start_offset + page_header.entryPageOffset ..][0 .. page_header.entryCount * @sizeOf(macho.unwind_info_regular_second_level_entry)],
            );
            if (entries.len == 0) return error.InvalidUnwindInfo;

            var left: usize = 0;
            var len: usize = entries.len;
            while (len > 1) {
                const mid = left + len / 2;
                const offset = entries[mid].functionOffset;
                if (mapped_pc < offset) {
                    len /= 2;
                } else {
                    left = mid;
                    if (mapped_pc == offset) break;
                    len -= len / 2;
                }
            }

            break :blk .{
                .function_offset = entries[left].functionOffset,
                .raw_encoding = entries[left].encoding,
            };
        },
        .COMPRESSED => blk: {
            const page_header = std.mem.bytesAsValue(
                macho.unwind_info_compressed_second_level_page_header,
                unwind_info[start_offset..][0..@sizeOf(macho.unwind_info_compressed_second_level_page_header)],
            );

            const entries = std.mem.bytesAsSlice(
                macho.UnwindInfoCompressedEntry,
                unwind_info[start_offset + page_header.entryPageOffset ..][0 .. page_header.entryCount * @sizeOf(macho.UnwindInfoCompressedEntry)],
            );
            if (entries.len == 0) return error.InvalidUnwindInfo;

            var left: usize = 0;
            var len: usize = entries.len;
            while (len > 1) {
                const mid = left + len / 2;
                const offset = second_level_index.functionOffset + entries[mid].funcOffset;
                if (mapped_pc < offset) {
                    len /= 2;
                } else {
                    left = mid;
                    if (mapped_pc == offset) break;
                    len -= len / 2;
                }
            }

            const entry = entries[left];
            const function_offset = second_level_index.functionOffset + entry.funcOffset;
            if (entry.encodingIndex < header.commonEncodingsArrayCount) {
                if (entry.encodingIndex >= common_encodings.len) return error.InvalidUnwindInfo;
                break :blk .{
                    .function_offset = function_offset,
                    .raw_encoding = common_encodings[entry.encodingIndex],
                };
            } else {
                const local_index = try math.sub(
                    u8,
                    entry.encodingIndex,
                    math.cast(u8, header.commonEncodingsArrayCount) orelse return error.InvalidUnwindInfo,
                );
                const local_encodings = std.mem.bytesAsSlice(
                    macho.compact_unwind_encoding_t,
                    unwind_info[start_offset + page_header.encodingsPageOffset ..][0 .. page_header.encodingsCount * @sizeOf(macho.compact_unwind_encoding_t)],
                );
                if (local_index >= local_encodings.len) return error.InvalidUnwindInfo;
                break :blk .{
                    .function_offset = function_offset,
                    .raw_encoding = local_encodings[local_index],
                };
            }
        },
        else => return error.InvalidUnwindInfo,
    };

    if (entry.raw_encoding == 0) return error.NoUnwindInfo;
    const reg_context = Dwarf.abi.RegisterContext{
        .eh_frame = false,
        .is_macho = true,
    };

    const encoding: macho.CompactUnwindEncoding = @bitCast(entry.raw_encoding);
    const new_ip = switch (builtin.cpu.arch) {
        .x86_64 => switch (encoding.mode.x86_64) {
            .OLD => return error.UnimplementedUnwindEncoding,
            .RBP_FRAME => blk: {
                const regs: [5]u3 = .{
                    encoding.value.x86_64.frame.reg0,
                    encoding.value.x86_64.frame.reg1,
                    encoding.value.x86_64.frame.reg2,
                    encoding.value.x86_64.frame.reg3,
                    encoding.value.x86_64.frame.reg4,
                };

                const frame_offset = encoding.value.x86_64.frame.frame_offset * @sizeOf(usize);
                var max_reg: usize = 0;
                inline for (regs, 0..) |reg, i| {
                    if (reg > 0) max_reg = i;
                }

                const fp = (try regValueNative(context.thread_context, fpRegNum(reg_context), reg_context)).*;
                const new_sp = fp + 2 * @sizeOf(usize);

                // Verify the stack range we're about to read register values from
                if (ma.load(usize, new_sp) == null or ma.load(usize, fp - frame_offset + max_reg * @sizeOf(usize)) == null) return error.InvalidUnwindInfo;

                const ip_ptr = fp + @sizeOf(usize);
                const new_ip = @as(*const usize, @ptrFromInt(ip_ptr)).*;
                const new_fp = @as(*const usize, @ptrFromInt(fp)).*;

                (try regValueNative(context.thread_context, fpRegNum(reg_context), reg_context)).* = new_fp;
                (try regValueNative(context.thread_context, spRegNum(reg_context), reg_context)).* = new_sp;
                (try regValueNative(context.thread_context, ip_reg_num, reg_context)).* = new_ip;

                for (regs, 0..) |reg, i| {
                    if (reg == 0) continue;
                    const addr = fp - frame_offset + i * @sizeOf(usize);
                    const reg_number = try Dwarf.compactUnwindToDwarfRegNumber(reg);
                    (try regValueNative(context.thread_context, reg_number, reg_context)).* = @as(*const usize, @ptrFromInt(addr)).*;
                }

                break :blk new_ip;
            },
            .STACK_IMMD,
            .STACK_IND,
            => blk: {
                const sp = (try regValueNative(context.thread_context, spRegNum(reg_context), reg_context)).*;
                const stack_size = if (encoding.mode.x86_64 == .STACK_IMMD)
                    @as(usize, encoding.value.x86_64.frameless.stack.direct.stack_size) * @sizeOf(usize)
                else stack_size: {
                    // In .STACK_IND, the stack size is inferred from the subq instruction at the beginning of the function.
                    const sub_offset_addr =
                        base_address +
                        entry.function_offset +
                        encoding.value.x86_64.frameless.stack.indirect.sub_offset;
                    if (ma.load(usize, sub_offset_addr) == null) return error.InvalidUnwindInfo;

                    // `sub_offset_addr` points to the offset of the literal within the instruction
                    const sub_operand = @as(*align(1) const u32, @ptrFromInt(sub_offset_addr)).*;
                    break :stack_size sub_operand + @sizeOf(usize) * @as(usize, encoding.value.x86_64.frameless.stack.indirect.stack_adjust);
                };

                // Decode the Lehmer-coded sequence of registers.
                // For a description of the encoding see lib/libc/include/any-macos.13-any/mach-o/compact_unwind_encoding.h

                // Decode the variable-based permutation number into its digits. Each digit represents
                // an index into the list of register numbers that weren't yet used in the sequence at
                // the time the digit was added.
                const reg_count = encoding.value.x86_64.frameless.stack_reg_count;
                const ip_ptr = if (reg_count > 0) reg_blk: {
                    var digits: [6]u3 = undefined;
                    var accumulator: usize = encoding.value.x86_64.frameless.stack_reg_permutation;
                    var base: usize = 2;
                    for (0..reg_count) |i| {
                        const div = accumulator / base;
                        digits[digits.len - 1 - i] = @intCast(accumulator - base * div);
                        accumulator = div;
                        base += 1;
                    }

                    const reg_numbers = [_]u3{ 1, 2, 3, 4, 5, 6 };
                    var registers: [reg_numbers.len]u3 = undefined;
                    var used_indices = [_]bool{false} ** reg_numbers.len;
                    for (digits[digits.len - reg_count ..], 0..) |target_unused_index, i| {
                        var unused_count: u8 = 0;
                        const unused_index = for (used_indices, 0..) |used, index| {
                            if (!used) {
                                if (target_unused_index == unused_count) break index;
                                unused_count += 1;
                            }
                        } else unreachable;

                        registers[i] = reg_numbers[unused_index];
                        used_indices[unused_index] = true;
                    }

                    var reg_addr = sp + stack_size - @sizeOf(usize) * @as(usize, reg_count + 1);
                    if (ma.load(usize, reg_addr) == null) return error.InvalidUnwindInfo;
                    for (0..reg_count) |i| {
                        const reg_number = try Dwarf.compactUnwindToDwarfRegNumber(registers[i]);
                        (try regValueNative(context.thread_context, reg_number, reg_context)).* = @as(*const usize, @ptrFromInt(reg_addr)).*;
                        reg_addr += @sizeOf(usize);
                    }

                    break :reg_blk reg_addr;
                } else sp + stack_size - @sizeOf(usize);

                const new_ip = @as(*const usize, @ptrFromInt(ip_ptr)).*;
                const new_sp = ip_ptr + @sizeOf(usize);
                if (ma.load(usize, new_sp) == null) return error.InvalidUnwindInfo;

                (try regValueNative(context.thread_context, spRegNum(reg_context), reg_context)).* = new_sp;
                (try regValueNative(context.thread_context, ip_reg_num, reg_context)).* = new_ip;

                break :blk new_ip;
            },
            .DWARF => {
                return unwindFrameMachODwarf(allocator, base_address, context, ma, eh_frame orelse return error.MissingEhFrame, @intCast(encoding.value.x86_64.dwarf));
            },
        },
        .aarch64, .aarch64_be => switch (encoding.mode.arm64) {
            .OLD => return error.UnimplementedUnwindEncoding,
            .FRAMELESS => blk: {
                const sp = (try regValueNative(context.thread_context, spRegNum(reg_context), reg_context)).*;
                const new_sp = sp + encoding.value.arm64.frameless.stack_size * 16;
                const new_ip = (try regValueNative(context.thread_context, 30, reg_context)).*;
                if (ma.load(usize, new_sp) == null) return error.InvalidUnwindInfo;
                (try regValueNative(context.thread_context, spRegNum(reg_context), reg_context)).* = new_sp;
                break :blk new_ip;
            },
            .DWARF => {
                return unwindFrameMachODwarf(allocator, base_address, context, ma, eh_frame orelse return error.MissingEhFrame, @intCast(encoding.value.arm64.dwarf));
            },
            .FRAME => blk: {
                const fp = (try regValueNative(context.thread_context, fpRegNum(reg_context), reg_context)).*;
                const new_sp = fp + 16;
                const ip_ptr = fp + @sizeOf(usize);

                const num_restored_pairs: usize =
                    @popCount(@as(u5, @bitCast(encoding.value.arm64.frame.x_reg_pairs))) +
                    @popCount(@as(u4, @bitCast(encoding.value.arm64.frame.d_reg_pairs)));
                const min_reg_addr = fp - num_restored_pairs * 2 * @sizeOf(usize);

                if (ma.load(usize, new_sp) == null or ma.load(usize, min_reg_addr) == null) return error.InvalidUnwindInfo;

                var reg_addr = fp - @sizeOf(usize);
                inline for (@typeInfo(@TypeOf(encoding.value.arm64.frame.x_reg_pairs)).@"struct".fields, 0..) |field, i| {
                    if (@field(encoding.value.arm64.frame.x_reg_pairs, field.name) != 0) {
                        (try regValueNative(context.thread_context, 19 + i, reg_context)).* = @as(*const usize, @ptrFromInt(reg_addr)).*;
                        reg_addr += @sizeOf(usize);
                        (try regValueNative(context.thread_context, 20 + i, reg_context)).* = @as(*const usize, @ptrFromInt(reg_addr)).*;
                        reg_addr += @sizeOf(usize);
                    }
                }

                inline for (@typeInfo(@TypeOf(encoding.value.arm64.frame.d_reg_pairs)).@"struct".fields, 0..) |field, i| {
                    if (@field(encoding.value.arm64.frame.d_reg_pairs, field.name) != 0) {
                        // Only the lower half of the 128-bit V registers are restored during unwinding
                        @memcpy(
                            try regBytes(context.thread_context, 64 + 8 + i, context.reg_context),
                            std.mem.asBytes(@as(*const usize, @ptrFromInt(reg_addr))),
                        );
                        reg_addr += @sizeOf(usize);
                        @memcpy(
                            try regBytes(context.thread_context, 64 + 9 + i, context.reg_context),
                            std.mem.asBytes(@as(*const usize, @ptrFromInt(reg_addr))),
                        );
                        reg_addr += @sizeOf(usize);
                    }
                }

                const new_ip = @as(*const usize, @ptrFromInt(ip_ptr)).*;
                const new_fp = @as(*const usize, @ptrFromInt(fp)).*;

                (try regValueNative(context.thread_context, fpRegNum(reg_context), reg_context)).* = new_fp;
                (try regValueNative(context.thread_context, ip_reg_num, reg_context)).* = new_ip;

                break :blk new_ip;
            },
        },
        else => return error.UnimplementedArch,
    };

    context.pc = stripInstructionPtrAuthCode(new_ip);
    if (context.pc > 0) context.pc -= 1;
    return new_ip;
}

pub const UnwindContext = struct {
    allocator: Allocator,
    cfa: ?usize,
    pc: usize,
    thread_context: *std.debug.ThreadContext,
    reg_context: Dwarf.abi.RegisterContext,
    vm: VirtualMachine,
    stack_machine: Dwarf.expression.StackMachine(.{ .call_frame_context = true }),

    pub fn init(
        allocator: Allocator,
        thread_context: *std.debug.ThreadContext,
    ) !UnwindContext {
        comptime assert(supports_unwinding);

        const pc = stripInstructionPtrAuthCode(
            (try regValueNative(thread_context, ip_reg_num, null)).*,
        );

        const context_copy = try allocator.create(std.debug.ThreadContext);
        std.debug.copyContext(thread_context, context_copy);

        return .{
            .allocator = allocator,
            .cfa = null,
            .pc = pc,
            .thread_context = context_copy,
            .reg_context = undefined,
            .vm = .{},
            .stack_machine = .{},
        };
    }

    pub fn deinit(self: *UnwindContext) void {
        self.vm.deinit(self.allocator);
        self.stack_machine.deinit(self.allocator);
        self.allocator.destroy(self.thread_context);
        self.* = undefined;
    }

    pub fn getFp(self: *const UnwindContext) !usize {
        return (try regValueNative(self.thread_context, fpRegNum(self.reg_context), self.reg_context)).*;
    }
};

/// Some platforms use pointer authentication - the upper bits of instruction pointers contain a signature.
/// This function clears these signature bits to make the pointer usable.
pub inline fn stripInstructionPtrAuthCode(ptr: usize) usize {
    if (native_arch.isAARCH64()) {
        // `hint 0x07` maps to `xpaclri` (or `nop` if the hardware doesn't support it)
        // The save / restore is because `xpaclri` operates on x30 (LR)
        return asm (
            \\mov x16, x30
            \\mov x30, x15
            \\hint 0x07
            \\mov x15, x30
            \\mov x30, x16
            : [ret] "={x15}" (-> usize),
            : [ptr] "{x15}" (ptr),
            : "x16"
        );
    }

    return ptr;
}

/// Unwind a stack frame using DWARF unwinding info, updating the register context.
///
/// If `.eh_frame_hdr` is available and complete, it will be used to binary search for the FDE.
/// Otherwise, a linear scan of `.eh_frame` and `.debug_frame` is done to find the FDE. The latter
/// may require lazily loading the data in those sections.
///
/// `explicit_fde_offset` is for cases where the FDE offset is known, such as when __unwind_info
/// defers unwinding to DWARF. This is an offset into the `.eh_frame` section.
pub fn unwindFrameDwarf(
    allocator: Allocator,
    di: *Dwarf,
    base_address: usize,
    context: *UnwindContext,
    ma: *std.debug.MemoryAccessor,
    explicit_fde_offset: ?usize,
) !usize {
    if (!supports_unwinding) return error.UnsupportedCpuArchitecture;
    if (context.pc == 0) return 0;

    // Find the FDE and CIE
    const cie, const fde = if (explicit_fde_offset) |fde_offset| blk: {
        const dwarf_section: Dwarf.Section.Id = .eh_frame;
        const frame_section = di.section(dwarf_section) orelse return error.MissingFDE;
        if (fde_offset >= frame_section.len) return error.MissingFDE;

        var fbr: std.debug.FixedBufferReader = .{
            .buf = frame_section,
            .pos = fde_offset,
            .endian = di.endian,
        };

        const fde_entry_header = try Dwarf.EntryHeader.read(&fbr, null, dwarf_section);
        if (fde_entry_header.type != .fde) return error.MissingFDE;

        const cie_offset = fde_entry_header.type.fde;
        try fbr.seekTo(cie_offset);

        fbr.endian = native_endian;
        const cie_entry_header = try Dwarf.EntryHeader.read(&fbr, null, dwarf_section);
        if (cie_entry_header.type != .cie) return Dwarf.bad();

        const cie = try Dwarf.CommonInformationEntry.parse(
            cie_entry_header.entry_bytes,
            0,
            true,
            cie_entry_header.format,
            dwarf_section,
            cie_entry_header.length_offset,
            @sizeOf(usize),
            native_endian,
        );
        const fde = try Dwarf.FrameDescriptionEntry.parse(
            fde_entry_header.entry_bytes,
            0,
            true,
            cie,
            @sizeOf(usize),
            native_endian,
        );

        break :blk .{ cie, fde };
    } else blk: {
        // `.eh_frame_hdr` may be incomplete. We'll try it first, but if the lookup fails, we fall
        // back to loading `.eh_frame`/`.debug_frame` and using those from that point on.

        if (di.eh_frame_hdr) |header| hdr: {
            const eh_frame_len = if (di.section(.eh_frame)) |eh_frame| eh_frame.len else null;

            var cie: Dwarf.CommonInformationEntry = undefined;
            var fde: Dwarf.FrameDescriptionEntry = undefined;

            header.findEntry(
                ma,
                eh_frame_len,
                @intFromPtr(di.section(.eh_frame_hdr).?.ptr),
                context.pc,
                &cie,
                &fde,
            ) catch |err| switch (err) {
                error.InvalidDebugInfo => {
                    // `.eh_frame_hdr` appears to be incomplete, so go ahead and populate `cie_map`
                    // and `fde_list`, and fall back to the binary search logic below.
                    try di.scanCieFdeInfo(allocator, base_address);

                    // Since `.eh_frame_hdr` is incomplete, we're very likely to get more lookup
                    // failures using it, and we've just built a complete, sorted list of FDEs
                    // anyway, so just stop using `.eh_frame_hdr` altogether.
                    di.eh_frame_hdr = null;

                    break :hdr;
                },
                else => return err,
            };

            break :blk .{ cie, fde };
        }

        const index = std.sort.binarySearch(Dwarf.FrameDescriptionEntry, di.fde_list.items, context.pc, struct {
            pub fn compareFn(pc: usize, item: Dwarf.FrameDescriptionEntry) std.math.Order {
                if (pc < item.pc_begin) return .lt;

                const range_end = item.pc_begin + item.pc_range;
                if (pc < range_end) return .eq;

                return .gt;
            }
        }.compareFn);

        const fde = if (index) |i| di.fde_list.items[i] else return error.MissingFDE;
        const cie = di.cie_map.get(fde.cie_length_offset) orelse return error.MissingCIE;

        break :blk .{ cie, fde };
    };

    var expression_context: Dwarf.expression.Context = .{
        .format = cie.format,
        .memory_accessor = ma,
        .compile_unit = di.findCompileUnit(fde.pc_begin) catch null,
        .thread_context = context.thread_context,
        .reg_context = context.reg_context,
        .cfa = context.cfa,
    };

    context.vm.reset();
    context.reg_context.eh_frame = cie.version != 4;
    context.reg_context.is_macho = di.is_macho;

    const row = try context.vm.runToNative(context.allocator, context.pc, cie, fde);
    context.cfa = switch (row.cfa.rule) {
        .val_offset => |offset| blk: {
            const register = row.cfa.register orelse return error.InvalidCFARule;
            const value = mem.readInt(usize, (try regBytes(context.thread_context, register, context.reg_context))[0..@sizeOf(usize)], native_endian);
            break :blk try applyOffset(value, offset);
        },
        .expression => |expr| blk: {
            context.stack_machine.reset();
            const value = try context.stack_machine.run(
                expr,
                context.allocator,
                expression_context,
                context.cfa,
            );

            if (value) |v| {
                if (v != .generic) return error.InvalidExpressionValue;
                break :blk v.generic;
            } else return error.NoExpressionValue;
        },
        else => return error.InvalidCFARule,
    };

    if (ma.load(usize, context.cfa.?) == null) return error.InvalidCFA;
    expression_context.cfa = context.cfa;

    // Buffering the modifications is done because copying the thread context is not portable,
    // some implementations (ie. darwin) use internal pointers to the mcontext.
    var arena = std.heap.ArenaAllocator.init(context.allocator);
    defer arena.deinit();
    const update_allocator = arena.allocator();

    const RegisterUpdate = struct {
        // Backed by thread_context
        dest: []u8,
        // Backed by arena
        src: []const u8,
        prev: ?*@This(),
    };

    var update_tail: ?*RegisterUpdate = null;
    var has_return_address = true;
    for (context.vm.rowColumns(row)) |column| {
        if (column.register) |register| {
            if (register == cie.return_address_register) {
                has_return_address = column.rule != .undefined;
            }

            const dest = try regBytes(context.thread_context, register, context.reg_context);
            const src = try update_allocator.alloc(u8, dest.len);

            const prev = update_tail;
            update_tail = try update_allocator.create(RegisterUpdate);
            update_tail.?.* = .{
                .dest = dest,
                .src = src,
                .prev = prev,
            };

            try column.resolveValue(
                context,
                expression_context,
                ma,
                src,
            );
        }
    }

    // On all implemented architectures, the CFA is defined as being the previous frame's SP
    (try regValueNative(context.thread_context, spRegNum(context.reg_context), context.reg_context)).* = context.cfa.?;

    while (update_tail) |tail| {
        @memcpy(tail.dest, tail.src);
        update_tail = tail.prev;
    }

    if (has_return_address) {
        context.pc = stripInstructionPtrAuthCode(mem.readInt(usize, (try regBytes(
            context.thread_context,
            cie.return_address_register,
            context.reg_context,
        ))[0..@sizeOf(usize)], native_endian));
    } else {
        context.pc = 0;
    }

    (try regValueNative(context.thread_context, ip_reg_num, context.reg_context)).* = context.pc;

    // The call instruction will have pushed the address of the instruction that follows the call as the return address.
    // This next instruction may be past the end of the function if the caller was `noreturn` (ie. the last instruction in
    // the function was the call). If we were to look up an FDE entry using the return address directly, it could end up
    // either not finding an FDE at all, or using the next FDE in the program, producing incorrect results. To prevent this,
    // we subtract one so that the next lookup is guaranteed to land inside the
    //
    // The exception to this rule is signal frames, where we return execution would be returned to the instruction
    // that triggered the handler.
    const return_address = context.pc;
    if (context.pc > 0 and !cie.isSignalFrame()) context.pc -= 1;

    return return_address;
}

fn fpRegNum(reg_context: Dwarf.abi.RegisterContext) u8 {
    return Dwarf.abi.fpRegNum(native_arch, reg_context);
}

fn spRegNum(reg_context: Dwarf.abi.RegisterContext) u8 {
    return Dwarf.abi.spRegNum(native_arch, reg_context);
}

const ip_reg_num = Dwarf.abi.ipRegNum(native_arch).?;

/// Tells whether unwinding for the host is implemented.
pub const supports_unwinding = supportsUnwinding(builtin.target);

comptime {
    if (supports_unwinding) assert(Dwarf.abi.supportsUnwinding(builtin.target));
}

/// Tells whether unwinding for this target is *implemented* here in the Zig
/// standard library.
///
/// See also `Dwarf.abi.supportsUnwinding` which tells whether Dwarf supports
/// unwinding on that target *in theory*.
pub fn supportsUnwinding(target: std.Target) bool {
    return switch (target.cpu.arch) {
        .x86 => switch (target.os.tag) {
            .linux, .netbsd, .solaris, .illumos => true,
            else => false,
        },
        .x86_64 => switch (target.os.tag) {
            .linux, .netbsd, .freebsd, .openbsd, .macos, .ios, .solaris, .illumos => true,
            else => false,
        },
        .arm, .armeb, .thumb, .thumbeb => switch (target.os.tag) {
            .linux => true,
            else => false,
        },
        .aarch64, .aarch64_be => switch (target.os.tag) {
            .linux, .netbsd, .freebsd, .macos, .ios => true,
            else => false,
        },
        // Unwinding is possible on other targets but this implementation does
        // not support them...yet!
        else => false,
    };
}

fn unwindFrameMachODwarf(
    allocator: Allocator,
    base_address: usize,
    context: *UnwindContext,
    ma: *std.debug.MemoryAccessor,
    eh_frame: []const u8,
    fde_offset: usize,
) !usize {
    var di: Dwarf = .{
        .endian = native_endian,
        .is_macho = true,
    };
    defer di.deinit(context.allocator);

    di.sections[@intFromEnum(Dwarf.Section.Id.eh_frame)] = .{
        .data = eh_frame,
        .owned = false,
    };

    return unwindFrameDwarf(allocator, &di, base_address, context, ma, fde_offset);
}

/// This is a virtual machine that runs DWARF call frame instructions.
pub const VirtualMachine = struct {
    /// See section 6.4.1 of the DWARF5 specification for details on each
    const RegisterRule = union(enum) {
        // The spec says that the default rule for each column is the undefined rule.
        // However, it also allows ABI / compiler authors to specify alternate defaults, so
        // there is a distinction made here.
        default: void,
        undefined: void,
        same_value: void,
        // offset(N)
        offset: i64,
        // val_offset(N)
        val_offset: i64,
        // register(R)
        register: u8,
        // expression(E)
        expression: []const u8,
        // val_expression(E)
        val_expression: []const u8,
        // Augmenter-defined rule
        architectural: void,
    };

    /// Each row contains unwinding rules for a set of registers.
    pub const Row = struct {
        /// Offset from `FrameDescriptionEntry.pc_begin`
        offset: u64 = 0,
        /// Special-case column that defines the CFA (Canonical Frame Address) rule.
        /// The register field of this column defines the register that CFA is derived from.
        cfa: Column = .{},
        /// The register fields in these columns define the register the rule applies to.
        columns: ColumnRange = .{},
        /// Indicates that the next write to any column in this row needs to copy
        /// the backing column storage first, as it may be referenced by previous rows.
        copy_on_write: bool = false,
    };

    pub const Column = struct {
        register: ?u8 = null,
        rule: RegisterRule = .{ .default = {} },

        /// Resolves the register rule and places the result into `out` (see regBytes)
        pub fn resolveValue(
            self: Column,
            context: *SelfInfo.UnwindContext,
            expression_context: std.debug.Dwarf.expression.Context,
            ma: *std.debug.MemoryAccessor,
            out: []u8,
        ) !void {
            switch (self.rule) {
                .default => {
                    const register = self.register orelse return error.InvalidRegister;
                    try getRegDefaultValue(register, context, out);
                },
                .undefined => {
                    @memset(out, undefined);
                },
                .same_value => {
                    // TODO: This copy could be eliminated if callers always copy the state then call this function to update it
                    const register = self.register orelse return error.InvalidRegister;
                    const src = try regBytes(context.thread_context, register, context.reg_context);
                    if (src.len != out.len) return error.RegisterSizeMismatch;
                    @memcpy(out, src);
                },
                .offset => |offset| {
                    if (context.cfa) |cfa| {
                        const addr = try applyOffset(cfa, offset);
                        if (ma.load(usize, addr) == null) return error.InvalidAddress;
                        const ptr: *const usize = @ptrFromInt(addr);
                        mem.writeInt(usize, out[0..@sizeOf(usize)], ptr.*, native_endian);
                    } else return error.InvalidCFA;
                },
                .val_offset => |offset| {
                    if (context.cfa) |cfa| {
                        mem.writeInt(usize, out[0..@sizeOf(usize)], try applyOffset(cfa, offset), native_endian);
                    } else return error.InvalidCFA;
                },
                .register => |register| {
                    const src = try regBytes(context.thread_context, register, context.reg_context);
                    if (src.len != out.len) return error.RegisterSizeMismatch;
                    @memcpy(out, try regBytes(context.thread_context, register, context.reg_context));
                },
                .expression => |expression| {
                    context.stack_machine.reset();
                    const value = try context.stack_machine.run(expression, context.allocator, expression_context, context.cfa.?);
                    const addr = if (value) |v| blk: {
                        if (v != .generic) return error.InvalidExpressionValue;
                        break :blk v.generic;
                    } else return error.NoExpressionValue;

                    if (ma.load(usize, addr) == null) return error.InvalidExpressionAddress;
                    const ptr: *usize = @ptrFromInt(addr);
                    mem.writeInt(usize, out[0..@sizeOf(usize)], ptr.*, native_endian);
                },
                .val_expression => |expression| {
                    context.stack_machine.reset();
                    const value = try context.stack_machine.run(expression, context.allocator, expression_context, context.cfa.?);
                    if (value) |v| {
                        if (v != .generic) return error.InvalidExpressionValue;
                        mem.writeInt(usize, out[0..@sizeOf(usize)], v.generic, native_endian);
                    } else return error.NoExpressionValue;
                },
                .architectural => return error.UnimplementedRegisterRule,
            }
        }
    };

    const ColumnRange = struct {
        /// Index into `columns` of the first column in this row.
        start: usize = undefined,
        len: u8 = 0,
    };

    columns: std.ArrayListUnmanaged(Column) = .empty,
    stack: std.ArrayListUnmanaged(ColumnRange) = .empty,
    current_row: Row = .{},

    /// The result of executing the CIE's initial_instructions
    cie_row: ?Row = null,

    pub fn deinit(self: *VirtualMachine, allocator: std.mem.Allocator) void {
        self.stack.deinit(allocator);
        self.columns.deinit(allocator);
        self.* = undefined;
    }

    pub fn reset(self: *VirtualMachine) void {
        self.stack.clearRetainingCapacity();
        self.columns.clearRetainingCapacity();
        self.current_row = .{};
        self.cie_row = null;
    }

    /// Return a slice backed by the row's non-CFA columns
    pub fn rowColumns(self: VirtualMachine, row: Row) []Column {
        if (row.columns.len == 0) return &.{};
        return self.columns.items[row.columns.start..][0..row.columns.len];
    }

    /// Either retrieves or adds a column for `register` (non-CFA) in the current row.
    fn getOrAddColumn(self: *VirtualMachine, allocator: std.mem.Allocator, register: u8) !*Column {
        for (self.rowColumns(self.current_row)) |*c| {
            if (c.register == register) return c;
        }

        if (self.current_row.columns.len == 0) {
            self.current_row.columns.start = self.columns.items.len;
        }
        self.current_row.columns.len += 1;

        const column = try self.columns.addOne(allocator);
        column.* = .{
            .register = register,
        };

        return column;
    }

    /// Runs the CIE instructions, then the FDE instructions. Execution halts
    /// once the row that corresponds to `pc` is known, and the row is returned.
    pub fn runTo(
        self: *VirtualMachine,
        allocator: std.mem.Allocator,
        pc: u64,
        cie: std.debug.Dwarf.CommonInformationEntry,
        fde: std.debug.Dwarf.FrameDescriptionEntry,
        addr_size_bytes: u8,
        endian: std.builtin.Endian,
    ) !Row {
        assert(self.cie_row == null);
        if (pc < fde.pc_begin or pc >= fde.pc_begin + fde.pc_range) return error.AddressOutOfRange;

        var prev_row: Row = self.current_row;

        var cie_stream = std.io.fixedBufferStream(cie.initial_instructions);
        var fde_stream = std.io.fixedBufferStream(fde.instructions);
        var streams = [_]*std.io.FixedBufferStream([]const u8){
            &cie_stream,
            &fde_stream,
        };

        for (&streams, 0..) |stream, i| {
            while (stream.pos < stream.buffer.len) {
                const instruction = try std.debug.Dwarf.call_frame.Instruction.read(stream, addr_size_bytes, endian);
                prev_row = try self.step(allocator, cie, i == 0, instruction);
                if (pc < fde.pc_begin + self.current_row.offset) return prev_row;
            }
        }

        return self.current_row;
    }

    pub fn runToNative(
        self: *VirtualMachine,
        allocator: std.mem.Allocator,
        pc: u64,
        cie: std.debug.Dwarf.CommonInformationEntry,
        fde: std.debug.Dwarf.FrameDescriptionEntry,
    ) !Row {
        return self.runTo(allocator, pc, cie, fde, @sizeOf(usize), native_endian);
    }

    fn resolveCopyOnWrite(self: *VirtualMachine, allocator: std.mem.Allocator) !void {
        if (!self.current_row.copy_on_write) return;

        const new_start = self.columns.items.len;
        if (self.current_row.columns.len > 0) {
            try self.columns.ensureUnusedCapacity(allocator, self.current_row.columns.len);
            self.columns.appendSliceAssumeCapacity(self.rowColumns(self.current_row));
            self.current_row.columns.start = new_start;
        }
    }

    /// Executes a single instruction.
    /// If this instruction is from the CIE, `is_initial` should be set.
    /// Returns the value of `current_row` before executing this instruction.
    pub fn step(
        self: *VirtualMachine,
        allocator: std.mem.Allocator,
        cie: std.debug.Dwarf.CommonInformationEntry,
        is_initial: bool,
        instruction: Dwarf.call_frame.Instruction,
    ) !Row {
        // CIE instructions must be run before FDE instructions
        assert(!is_initial or self.cie_row == null);
        if (!is_initial and self.cie_row == null) {
            self.cie_row = self.current_row;
            self.current_row.copy_on_write = true;
        }

        const prev_row = self.current_row;
        switch (instruction) {
            .set_loc => |i| {
                if (i.address <= self.current_row.offset) return error.InvalidOperation;
                // TODO: Check cie.segment_selector_size != 0 for DWARFV4
                self.current_row.offset = i.address;
            },
            inline .advance_loc,
            .advance_loc1,
            .advance_loc2,
            .advance_loc4,
            => |i| {
                self.current_row.offset += i.delta * cie.code_alignment_factor;
                self.current_row.copy_on_write = true;
            },
            inline .offset,
            .offset_extended,
            .offset_extended_sf,
            => |i| {
                try self.resolveCopyOnWrite(allocator);
                const column = try self.getOrAddColumn(allocator, i.register);
                column.rule = .{ .offset = @as(i64, @intCast(i.offset)) * cie.data_alignment_factor };
            },
            inline .restore,
            .restore_extended,
            => |i| {
                try self.resolveCopyOnWrite(allocator);
                if (self.cie_row) |cie_row| {
                    const column = try self.getOrAddColumn(allocator, i.register);
                    column.rule = for (self.rowColumns(cie_row)) |cie_column| {
                        if (cie_column.register == i.register) break cie_column.rule;
                    } else .{ .default = {} };
                } else return error.InvalidOperation;
            },
            .nop => {},
            .undefined => |i| {
                try self.resolveCopyOnWrite(allocator);
                const column = try self.getOrAddColumn(allocator, i.register);
                column.rule = .{ .undefined = {} };
            },
            .same_value => |i| {
                try self.resolveCopyOnWrite(allocator);
                const column = try self.getOrAddColumn(allocator, i.register);
                column.rule = .{ .same_value = {} };
            },
            .register => |i| {
                try self.resolveCopyOnWrite(allocator);
                const column = try self.getOrAddColumn(allocator, i.register);
                column.rule = .{ .register = i.target_register };
            },
            .remember_state => {
                try self.stack.append(allocator, self.current_row.columns);
                self.current_row.copy_on_write = true;
            },
            .restore_state => {
                const restored_columns = self.stack.pop() orelse return error.InvalidOperation;
                self.columns.shrinkRetainingCapacity(self.columns.items.len - self.current_row.columns.len);
                try self.columns.ensureUnusedCapacity(allocator, restored_columns.len);

                self.current_row.columns.start = self.columns.items.len;
                self.current_row.columns.len = restored_columns.len;
                self.columns.appendSliceAssumeCapacity(self.columns.items[restored_columns.start..][0..restored_columns.len]);
            },
            .def_cfa => |i| {
                try self.resolveCopyOnWrite(allocator);
                self.current_row.cfa = .{
                    .register = i.register,
                    .rule = .{ .val_offset = @intCast(i.offset) },
                };
            },
            .def_cfa_sf => |i| {
                try self.resolveCopyOnWrite(allocator);
                self.current_row.cfa = .{
                    .register = i.register,
                    .rule = .{ .val_offset = i.offset * cie.data_alignment_factor },
                };
            },
            .def_cfa_register => |i| {
                try self.resolveCopyOnWrite(allocator);
                if (self.current_row.cfa.register == null or self.current_row.cfa.rule != .val_offset) return error.InvalidOperation;
                self.current_row.cfa.register = i.register;
            },
            .def_cfa_offset => |i| {
                try self.resolveCopyOnWrite(allocator);
                if (self.current_row.cfa.register == null or self.current_row.cfa.rule != .val_offset) return error.InvalidOperation;
                self.current_row.cfa.rule = .{
                    .val_offset = @intCast(i.offset),
                };
            },
            .def_cfa_offset_sf => |i| {
                try self.resolveCopyOnWrite(allocator);
                if (self.current_row.cfa.register == null or self.current_row.cfa.rule != .val_offset) return error.InvalidOperation;
                self.current_row.cfa.rule = .{
                    .val_offset = i.offset * cie.data_alignment_factor,
                };
            },
            .def_cfa_expression => |i| {
                try self.resolveCopyOnWrite(allocator);
                self.current_row.cfa.register = undefined;
                self.current_row.cfa.rule = .{
                    .expression = i.block,
                };
            },
            .expression => |i| {
                try self.resolveCopyOnWrite(allocator);
                const column = try self.getOrAddColumn(allocator, i.register);
                column.rule = .{
                    .expression = i.block,
                };
            },
            .val_offset => |i| {
                try self.resolveCopyOnWrite(allocator);
                const column = try self.getOrAddColumn(allocator, i.register);
                column.rule = .{
                    .val_offset = @as(i64, @intCast(i.offset)) * cie.data_alignment_factor,
                };
            },
            .val_offset_sf => |i| {
                try self.resolveCopyOnWrite(allocator);
                const column = try self.getOrAddColumn(allocator, i.register);
                column.rule = .{
                    .val_offset = i.offset * cie.data_alignment_factor,
                };
            },
            .val_expression => |i| {
                try self.resolveCopyOnWrite(allocator);
                const column = try self.getOrAddColumn(allocator, i.register);
                column.rule = .{
                    .val_expression = i.block,
                };
            },
        }

        return prev_row;
    }
};

/// Returns the ABI-defined default value this register has in the unwinding table
/// before running any of the CIE instructions. The DWARF spec defines these as having
/// the .undefined rule by default, but allows ABI authors to override that.
fn getRegDefaultValue(reg_number: u8, context: *UnwindContext, out: []u8) !void {
    switch (builtin.cpu.arch) {
        .aarch64, .aarch64_be => {
            // Callee-saved registers are initialized as if they had the .same_value rule
            if (reg_number >= 19 and reg_number <= 28) {
                const src = try regBytes(context.thread_context, reg_number, context.reg_context);
                if (src.len != out.len) return error.RegisterSizeMismatch;
                @memcpy(out, src);
                return;
            }
        },
        else => {},
    }

    @memset(out, undefined);
}

/// Since register rules are applied (usually) during a panic,
/// checked addition / subtraction is used so that we can return
/// an error and fall back to FP-based unwinding.
fn applyOffset(base: usize, offset: i64) !usize {
    return if (offset >= 0)
        try std.math.add(usize, base, @as(usize, @intCast(offset)))
    else
        try std.math.sub(usize, base, @as(usize, @intCast(-offset)));
}
//! This namespace is the default one used by the Zig compiler to emit various
//! kinds of safety panics, due to the logic in `std.builtin.panic`.
//!
//! Since Zig does not have interfaces, this file serves as an example template
//! for users to provide their own alternative panic handling.
//!
//! As an alternative, see `std.debug.FullPanic`.

const std = @import("../std.zig");

/// Prints the message to stderr without a newline and then traps.
///
/// Explicit calls to `@panic` lower to calling this function.
pub fn call(msg: []const u8, ra: ?usize) noreturn {
    @branchHint(.cold);
    _ = ra;
    std.debug.lockStdErr();
    const stderr = std.io.getStdErr();
    stderr.writeAll(msg) catch {};
    @trap();
}

pub fn sentinelMismatch(expected: anytype, found: @TypeOf(expected)) noreturn {
    _ = found;
    call("sentinel mismatch", null);
}

pub fn unwrapError(err: anyerror) noreturn {
    _ = &err;
    call("attempt to unwrap error", null);
}

pub fn outOfBounds(index: usize, len: usize) noreturn {
    _ = index;
    _ = len;
    call("index out of bounds", null);
}

pub fn startGreaterThanEnd(start: usize, end: usize) noreturn {
    _ = start;
    _ = end;
    call("start index is larger than end index", null);
}

pub fn inactiveUnionField(active: anytype, accessed: @TypeOf(active)) noreturn {
    _ = accessed;
    call("access of inactive union field", null);
}

pub fn sliceCastLenRemainder(src_len: usize) noreturn {
    _ = src_len;
    call("slice length does not divide exactly into destination elements", null);
}

pub fn reachedUnreachable() noreturn {
    call("reached unreachable code", null);
}

pub fn unwrapNull() noreturn {
    call("attempt to use null value", null);
}

pub fn castToNull() noreturn {
    call("cast causes pointer to be null", null);
}

pub fn incorrectAlignment() noreturn {
    call("incorrect alignment", null);
}

pub fn invalidErrorCode() noreturn {
    call("invalid error code", null);
}

pub fn castTruncatedData() noreturn {
    call("integer cast truncated bits", null);
}

pub fn negativeToUnsigned() noreturn {
    call("attempt to cast negative value to unsigned integer", null);
}

pub fn integerOverflow() noreturn {
    call("integer overflow", null);
}

pub fn shlOverflow() noreturn {
    call("left shift overflowed bits", null);
}

pub fn shrOverflow() noreturn {
    call("right shift overflowed bits", null);
}

pub fn divideByZero() noreturn {
    call("division by zero", null);
}

pub fn exactDivisionRemainder() noreturn {
    call("exact division produced remainder", null);
}

pub fn integerPartOutOfBounds() noreturn {
    call("integer part of floating point value out of bounds", null);
}

pub fn corruptSwitch() noreturn {
    call("switch on corrupt value", null);
}

pub fn shiftRhsTooBig() noreturn {
    call("shift amount is greater than the type size", null);
}

pub fn invalidEnumValue() noreturn {
    call("invalid enum value", null);
}

pub fn forLenMismatch() noreturn {
    call("for loop over objects with non-equal lengths", null);
}

pub fn memcpyLenMismatch() noreturn {
    call("@memcpy arguments have non-equal lengths", null);
}

pub fn memcpyAlias() noreturn {
    call("@memcpy arguments alias", null);
}

pub fn memmoveLenMismatch() noreturn {
    call("@memmove arguments have non-equal lengths", null);
}

pub fn noreturnReturned() noreturn {
    call("'noreturn' function returned", null);
}
//! A doubly-linked list has a pair of pointers to both the head and
//! tail of the list. List elements have pointers to both the previous
//! and next elements in the sequence. The list can be traversed both
//! forward and backward. Some operations that take linear O(n) time
//! with a singly-linked list can be done without traversal in constant
//! O(1) time with a doubly-linked list:
//!
//! * Removing an element.
//! * Inserting a new element before an existing element.
//! * Pushing or popping an element from the end of the list.

const std = @import("std.zig");
const debug = std.debug;
const assert = debug.assert;
const testing = std.testing;
const DoublyLinkedList = @This();

first: ?*Node = null,
last: ?*Node = null,

/// This struct contains only the prev and next pointers and not any data
/// payload. The intended usage is to embed it intrusively into another data
/// structure and access the data with `@fieldParentPtr`.
pub const Node = struct {
    prev: ?*Node = null,
    next: ?*Node = null,
};

pub fn insertAfter(list: *DoublyLinkedList, existing_node: *Node, new_node: *Node) void {
    new_node.prev = existing_node;
    if (existing_node.next) |next_node| {
        // Intermediate node.
        new_node.next = next_node;
        next_node.prev = new_node;
    } else {
        // Last element of the list.
        new_node.next = null;
        list.last = new_node;
    }
    existing_node.next = new_node;
}

pub fn insertBefore(list: *DoublyLinkedList, existing_node: *Node, new_node: *Node) void {
    new_node.next = existing_node;
    if (existing_node.prev) |prev_node| {
        // Intermediate node.
        new_node.prev = prev_node;
        prev_node.next = new_node;
    } else {
        // First element of the list.
        new_node.prev = null;
        list.first = new_node;
    }
    existing_node.prev = new_node;
}

/// Concatenate list2 onto the end of list1, removing all entries from the former.
///
/// Arguments:
///     list1: the list to concatenate onto
///     list2: the list to be concatenated
pub fn concatByMoving(list1: *DoublyLinkedList, list2: *DoublyLinkedList) void {
    const l2_first = list2.first orelse return;
    if (list1.last) |l1_last| {
        l1_last.next = list2.first;
        l2_first.prev = list1.last;
    } else {
        // list1 was empty
        list1.first = list2.first;
    }
    list1.last = list2.last;
    list2.first = null;
    list2.last = null;
}

/// Insert a new node at the end of the list.
///
/// Arguments:
///     new_node: Pointer to the new node to insert.
pub fn append(list: *DoublyLinkedList, new_node: *Node) void {
    if (list.last) |last| {
        // Insert after last.
        list.insertAfter(last, new_node);
    } else {
        // Empty list.
        list.prepend(new_node);
    }
}

/// Insert a new node at the beginning of the list.
///
/// Arguments:
///     new_node: Pointer to the new node to insert.
pub fn prepend(list: *DoublyLinkedList, new_node: *Node) void {
    if (list.first) |first| {
        // Insert before first.
        list.insertBefore(first, new_node);
    } else {
        // Empty list.
        list.first = new_node;
        list.last = new_node;
        new_node.prev = null;
        new_node.next = null;
    }
}

/// Remove a node from the list.
///
/// Arguments:
///     node: Pointer to the node to be removed.
pub fn remove(list: *DoublyLinkedList, node: *Node) void {
    if (node.prev) |prev_node| {
        // Intermediate node.
        prev_node.next = node.next;
    } else {
        // First element of the list.
        list.first = node.next;
    }

    if (node.next) |next_node| {
        // Intermediate node.
        next_node.prev = node.prev;
    } else {
        // Last element of the list.
        list.last = node.prev;
    }
}

/// Remove and return the last node in the list.
///
/// Returns:
///     A pointer to the last node in the list.
pub fn pop(list: *DoublyLinkedList) ?*Node {
    const last = list.last orelse return null;
    list.remove(last);
    return last;
}

/// Remove and return the first node in the list.
///
/// Returns:
///     A pointer to the first node in the list.
pub fn popFirst(list: *DoublyLinkedList) ?*Node {
    const first = list.first orelse return null;
    list.remove(first);
    return first;
}

/// Iterate over all nodes, returning the count.
///
/// This operation is O(N). Consider tracking the length separately rather than
/// computing it.
pub fn len(list: DoublyLinkedList) usize {
    var count: usize = 0;
    var it: ?*const Node = list.first;
    while (it) |n| : (it = n.next) count += 1;
    return count;
}

test "basics" {
    const L = struct {
        data: u32,
        node: DoublyLinkedList.Node = .{},
    };
    var list: DoublyLinkedList = .{};

    var one: L = .{ .data = 1 };
    var two: L = .{ .data = 2 };
    var three: L = .{ .data = 3 };
    var four: L = .{ .data = 4 };
    var five: L = .{ .data = 5 };

    list.append(&two.node); // {2}
    list.append(&five.node); // {2, 5}
    list.prepend(&one.node); // {1, 2, 5}
    list.insertBefore(&five.node, &four.node); // {1, 2, 4, 5}
    list.insertAfter(&two.node, &three.node); // {1, 2, 3, 4, 5}

    // Traverse forwards.
    {
        var it = list.first;
        var index: u32 = 1;
        while (it) |node| : (it = node.next) {
            const l: *L = @fieldParentPtr("node", node);
            try testing.expect(l.data == index);
            index += 1;
        }
    }

    // Traverse backwards.
    {
        var it = list.last;
        var index: u32 = 1;
        while (it) |node| : (it = node.prev) {
            const l: *L = @fieldParentPtr("node", node);
            try testing.expect(l.data == (6 - index));
            index += 1;
        }
    }

    _ = list.popFirst(); // {2, 3, 4, 5}
    _ = list.pop(); // {2, 3, 4}
    list.remove(&three.node); // {2, 4}

    try testing.expect(@as(*L, @fieldParentPtr("node", list.first.?)).data == 2);
    try testing.expect(@as(*L, @fieldParentPtr("node", list.last.?)).data == 4);
    try testing.expect(list.len() == 2);
}

test "concatenation" {
    const L = struct {
        data: u32,
        node: DoublyLinkedList.Node = .{},
    };
    var list1: DoublyLinkedList = .{};
    var list2: DoublyLinkedList = .{};

    var one: L = .{ .data = 1 };
    var two: L = .{ .data = 2 };
    var three: L = .{ .data = 3 };
    var four: L = .{ .data = 4 };
    var five: L = .{ .data = 5 };

    list1.append(&one.node);
    list1.append(&two.node);
    list2.append(&three.node);
    list2.append(&four.node);
    list2.append(&five.node);

    list1.concatByMoving(&list2);

    try testing.expect(list1.last == &five.node);
    try testing.expect(list1.len() == 5);
    try testing.expect(list2.first == null);
    try testing.expect(list2.last == null);
    try testing.expect(list2.len() == 0);

    // Traverse forwards.
    {
        var it = list1.first;
        var index: u32 = 1;
        while (it) |node| : (it = node.next) {
            const l: *L = @fieldParentPtr("node", node);
            try testing.expect(l.data == index);
            index += 1;
        }
    }

    // Traverse backwards.
    {
        var it = list1.last;
        var index: u32 = 1;
        while (it) |node| : (it = node.prev) {
            const l: *L = @fieldParentPtr("node", node);
            try testing.expect(l.data == (6 - index));
            index += 1;
        }
    }

    // Swap them back, this verifies that concatenating to an empty list works.
    list2.concatByMoving(&list1);

    // Traverse forwards.
    {
        var it = list2.first;
        var index: u32 = 1;
        while (it) |node| : (it = node.next) {
            const l: *L = @fieldParentPtr("node", node);
            try testing.expect(l.data == index);
            index += 1;
        }
    }

    // Traverse backwards.
    {
        var it = list2.last;
        var index: u32 = 1;
        while (it) |node| : (it = node.prev) {
            const l: *L = @fieldParentPtr("node", node);
            try testing.expect(l.data == (6 - index));
            index += 1;
        }
    }
}
//! DWARF debugging data format.
//!
//! This namespace contains unopinionated types and data definitions only. For
//! an implementation of parsing and caching DWARF information, see
//! `std.debug.Dwarf`.

pub const TAG = @import("dwarf/TAG.zig");
pub const AT = @import("dwarf/AT.zig");
pub const OP = @import("dwarf/OP.zig");
pub const LANG = @import("dwarf/LANG.zig");
pub const FORM = @import("dwarf/FORM.zig");
pub const ATE = @import("dwarf/ATE.zig");
pub const EH = @import("dwarf/EH.zig");
pub const Format = enum { @"32", @"64" };

pub const LLE = struct {
    pub const end_of_list = 0x00;
    pub const base_addressx = 0x01;
    pub const startx_endx = 0x02;
    pub const startx_length = 0x03;
    pub const offset_pair = 0x04;
    pub const default_location = 0x05;
    pub const base_address = 0x06;
    pub const start_end = 0x07;
    pub const start_length = 0x08;
};

pub const CFA = struct {
    pub const advance_loc = 0x40;
    pub const offset = 0x80;
    pub const restore = 0xc0;
    pub const nop = 0x00;
    pub const set_loc = 0x01;
    pub const advance_loc1 = 0x02;
    pub const advance_loc2 = 0x03;
    pub const advance_loc4 = 0x04;
    pub const offset_extended = 0x05;
    pub const restore_extended = 0x06;
    pub const @"undefined" = 0x07;
    pub const same_value = 0x08;
    pub const register = 0x09;
    pub const remember_state = 0x0a;
    pub const restore_state = 0x0b;
    pub const def_cfa = 0x0c;
    pub const def_cfa_register = 0x0d;
    pub const def_cfa_offset = 0x0e;

    // DWARF 3.
    pub const def_cfa_expression = 0x0f;
    pub const expression = 0x10;
    pub const offset_extended_sf = 0x11;
    pub const def_cfa_sf = 0x12;
    pub const def_cfa_offset_sf = 0x13;
    pub const val_offset = 0x14;
    pub const val_offset_sf = 0x15;
    pub const val_expression = 0x16;

    pub const lo_user = 0x1c;
    pub const hi_user = 0x3f;

    // SGI/MIPS specific.
    pub const MIPS_advance_loc8 = 0x1d;

    // GNU extensions.
    pub const GNU_window_save = 0x2d;
    pub const GNU_args_size = 0x2e;
    pub const GNU_negative_offset_extended = 0x2f;
};

pub const CHILDREN = struct {
    pub const no = 0x00;
    pub const yes = 0x01;
};

pub const LNS = struct {
    pub const extended_op = 0x00;
    pub const copy = 0x01;
    pub const advance_pc = 0x02;
    pub const advance_line = 0x03;
    pub const set_file = 0x04;
    pub const set_column = 0x05;
    pub const negate_stmt = 0x06;
    pub const set_basic_block = 0x07;
    pub const const_add_pc = 0x08;
    pub const fixed_advance_pc = 0x09;
    pub const set_prologue_end = 0x0a;
    pub const set_epilogue_begin = 0x0b;
    pub const set_isa = 0x0c;
};

pub const LNE = struct {
    pub const padding = 0x00;
    pub const end_sequence = 0x01;
    pub const set_address = 0x02;
    pub const define_file = 0x03;
    pub const set_discriminator = 0x04;
    pub const lo_user = 0x80;
    pub const hi_user = 0xff;

    // Zig extensions
    pub const ZIG_set_decl = 0xec;
};

pub const UT = struct {
    pub const compile = 0x01;
    pub const @"type" = 0x02;
    pub const partial = 0x03;
    pub const skeleton = 0x04;
    pub const split_compile = 0x05;
    pub const split_type = 0x06;

    pub const lo_user = 0x80;
    pub const hi_user = 0xff;
};

pub const LNCT = struct {
    pub const path = 0x1;
    pub const directory_index = 0x2;
    pub const timestamp = 0x3;
    pub const size = 0x4;
    pub const MD5 = 0x5;

    pub const lo_user = 0x2000;
    pub const hi_user = 0x3fff;

    pub const LLVM_source = 0x2001;
};

pub const RLE = struct {
    pub const end_of_list = 0x00;
    pub const base_addressx = 0x01;
    pub const startx_endx = 0x02;
    pub const startx_length = 0x03;
    pub const offset_pair = 0x04;
    pub const base_address = 0x05;
    pub const start_end = 0x06;
    pub const start_length = 0x07;
};

pub const CC = enum(u8) {
    normal = 0x1,
    program = 0x2,
    nocall = 0x3,

    pass_by_reference = 0x4,
    pass_by_value = 0x5,

    GNU_renesas_sh = 0x40,
    GNU_borland_fastcall_i386 = 0x41,

    BORLAND_safecall = 0xb0,
    BORLAND_stdcall = 0xb1,
    BORLAND_pascal = 0xb2,
    BORLAND_msfastcall = 0xb3,
    BORLAND_msreturn = 0xb4,
    BORLAND_thiscall = 0xb5,
    BORLAND_fastcall = 0xb6,

    LLVM_vectorcall = 0xc0,
    LLVM_Win64 = 0xc1,
    LLVM_X86_64SysV = 0xc2,
    LLVM_AAPCS = 0xc3,
    LLVM_AAPCS_VFP = 0xc4,
    LLVM_IntelOclBicc = 0xc5,
    LLVM_SpirFunction = 0xc6,
    LLVM_OpenCLKernel = 0xc7,
    LLVM_Swift = 0xc8,
    LLVM_PreserveMost = 0xc9,
    LLVM_PreserveAll = 0xca,
    LLVM_X86RegCall = 0xcb,
    LLVM_M68kRTD = 0xcc,
    LLVM_PreserveNone = 0xcd,
    LLVM_RISCVVectorCall = 0xce,
    LLVM_SwiftTail = 0xcf,

    pub const lo_user = 0x40;
    pub const hi_user = 0xff;
};

pub const ACCESS = struct {
    pub const public = 0x01;
    pub const protected = 0x02;
    pub const private = 0x03;
};
pub const sibling = 0x01;
pub const location = 0x02;
pub const name = 0x03;
pub const ordering = 0x09;
pub const subscr_data = 0x0a;
pub const byte_size = 0x0b;
pub const bit_offset = 0x0c;
pub const bit_size = 0x0d;
pub const element_list = 0x0f;
pub const stmt_list = 0x10;
pub const low_pc = 0x11;
pub const high_pc = 0x12;
pub const language = 0x13;
pub const member = 0x14;
pub const discr = 0x15;
pub const discr_value = 0x16;
pub const visibility = 0x17;
pub const import = 0x18;
pub const string_length = 0x19;
pub const common_reference = 0x1a;
pub const comp_dir = 0x1b;
pub const const_value = 0x1c;
pub const containing_type = 0x1d;
pub const default_value = 0x1e;
pub const @"inline" = 0x20;
pub const is_optional = 0x21;
pub const lower_bound = 0x22;
pub const producer = 0x25;
pub const prototyped = 0x27;
pub const return_addr = 0x2a;
pub const start_scope = 0x2c;
pub const bit_stride = 0x2e;
pub const upper_bound = 0x2f;
pub const abstract_origin = 0x31;
pub const accessibility = 0x32;
pub const address_class = 0x33;
pub const artificial = 0x34;
pub const base_types = 0x35;
pub const calling_convention = 0x36;
pub const count = 0x37;
pub const data_member_location = 0x38;
pub const decl_column = 0x39;
pub const decl_file = 0x3a;
pub const decl_line = 0x3b;
pub const declaration = 0x3c;
pub const discr_list = 0x3d;
pub const encoding = 0x3e;
pub const external = 0x3f;
pub const frame_base = 0x40;
pub const friend = 0x41;
pub const identifier_case = 0x42;
pub const macro_info = 0x43;
pub const namelist_items = 0x44;
pub const priority = 0x45;
pub const segment = 0x46;
pub const specification = 0x47;
pub const static_link = 0x48;
pub const @"type" = 0x49;
pub const use_location = 0x4a;
pub const variable_parameter = 0x4b;
pub const virtuality = 0x4c;
pub const vtable_elem_location = 0x4d;

// DWARF 3 values.
pub const allocated = 0x4e;
pub const associated = 0x4f;
pub const data_location = 0x50;
pub const byte_stride = 0x51;
pub const entry_pc = 0x52;
pub const use_UTF8 = 0x53;
pub const extension = 0x54;
pub const ranges = 0x55;
pub const trampoline = 0x56;
pub const call_column = 0x57;
pub const call_file = 0x58;
pub const call_line = 0x59;
pub const description = 0x5a;
pub const binary_scale = 0x5b;
pub const decimal_scale = 0x5c;
pub const small = 0x5d;
pub const decimal_sign = 0x5e;
pub const digit_count = 0x5f;
pub const picture_string = 0x60;
pub const mutable = 0x61;
pub const threads_scaled = 0x62;
pub const explicit = 0x63;
pub const object_pointer = 0x64;
pub const endianity = 0x65;
pub const elemental = 0x66;
pub const pure = 0x67;
pub const recursive = 0x68;

// DWARF 4.
pub const signature = 0x69;
pub const main_subprogram = 0x6a;
pub const data_bit_offset = 0x6b;
pub const const_expr = 0x6c;
pub const enum_class = 0x6d;
pub const linkage_name = 0x6e;

// DWARF 5
pub const string_length_bit_size = 0x6f;
pub const string_length_byte_size = 0x70;
pub const rank = 0x71;
pub const str_offsets_base = 0x72;
pub const addr_base = 0x73;
pub const rnglists_base = 0x74;
pub const dwo_name = 0x76;
pub const reference = 0x77;
pub const rvalue_reference = 0x78;
pub const macros = 0x79;
pub const call_all_calls = 0x7a;
pub const call_all_source_calls = 0x7b;
pub const call_all_tail_calls = 0x7c;
pub const call_return_pc = 0x7d;
pub const call_value = 0x7e;
pub const call_origin = 0x7f;
pub const call_parameter = 0x80;
pub const call_pc = 0x81;
pub const call_tail_call = 0x82;
pub const call_target = 0x83;
pub const call_target_clobbered = 0x84;
pub const call_data_location = 0x85;
pub const call_data_value = 0x86;
pub const @"noreturn" = 0x87;
pub const alignment = 0x88;
pub const export_symbols = 0x89;
pub const deleted = 0x8a;
pub const defaulted = 0x8b;
pub const loclists_base = 0x8c;

pub const lo_user = 0x2000; // Implementation-defined range start.
pub const hi_user = 0x3fff; // Implementation-defined range end.

// SGI/MIPS extensions.
pub const MIPS_fde = 0x2001;
pub const MIPS_loop_begin = 0x2002;
pub const MIPS_tail_loop_begin = 0x2003;
pub const MIPS_epilog_begin = 0x2004;
pub const MIPS_loop_unroll_factor = 0x2005;
pub const MIPS_software_pipeline_depth = 0x2006;
pub const MIPS_linkage_name = 0x2007;
pub const MIPS_stride = 0x2008;
pub const MIPS_abstract_name = 0x2009;
pub const MIPS_clone_origin = 0x200a;
pub const MIPS_has_inlines = 0x200b;

// HP extensions.
pub const HP_block_index = 0x2000;
pub const HP_unmodifiable = 0x2001; // Same as AT.MIPS_fde.
pub const HP_prologue = 0x2005; // Same as AT.MIPS_loop_unroll.
pub const HP_epilogue = 0x2008; // Same as AT.MIPS_stride.
pub const HP_actuals_stmt_list = 0x2010;
pub const HP_proc_per_section = 0x2011;
pub const HP_raw_data_ptr = 0x2012;
pub const HP_pass_by_reference = 0x2013;
pub const HP_opt_level = 0x2014;
pub const HP_prof_version_id = 0x2015;
pub const HP_opt_flags = 0x2016;
pub const HP_cold_region_low_pc = 0x2017;
pub const HP_cold_region_high_pc = 0x2018;
pub const HP_all_variables_modifiable = 0x2019;
pub const HP_linkage_name = 0x201a;
pub const HP_prof_flags = 0x201b; // In comp unit of procs_info for -g.
pub const HP_unit_name = 0x201f;
pub const HP_unit_size = 0x2020;
pub const HP_widened_byte_size = 0x2021;
pub const HP_definition_points = 0x2022;
pub const HP_default_location = 0x2023;
pub const HP_is_result_param = 0x2029;

// GNU extensions.
pub const sf_names = 0x2101;
pub const src_info = 0x2102;
pub const mac_info = 0x2103;
pub const src_coords = 0x2104;
pub const body_begin = 0x2105;
pub const body_end = 0x2106;
pub const GNU_vector = 0x2107;
// Thread-safety annotations.
// See http://gcc.gnu.org/wiki/ThreadSafetyAnnotation .
pub const GNU_guarded_by = 0x2108;
pub const GNU_pt_guarded_by = 0x2109;
pub const GNU_guarded = 0x210a;
pub const GNU_pt_guarded = 0x210b;
pub const GNU_locks_excluded = 0x210c;
pub const GNU_exclusive_locks_required = 0x210d;
pub const GNU_shared_locks_required = 0x210e;
// One-definition rule violation detection.
// See http://gcc.gnu.org/wiki/DwarfSeparateTypeInfo .
pub const GNU_odr_signature = 0x210f;
// Template template argument name.
// See http://gcc.gnu.org/wiki/TemplateParmsDwarf .
pub const GNU_template_name = 0x2110;
// The GNU call site extension.
// See http://www.dwarfstd.org/ShowIssue.php?issue=100909.2&type=open .
pub const GNU_call_site_value = 0x2111;
pub const GNU_call_site_data_value = 0x2112;
pub const GNU_call_site_target = 0x2113;
pub const GNU_call_site_target_clobbered = 0x2114;
pub const GNU_tail_call = 0x2115;
pub const GNU_all_tail_call_sites = 0x2116;
pub const GNU_all_call_sites = 0x2117;
pub const GNU_all_source_call_sites = 0x2118;
// Section offset into .debug_macro section.
pub const GNU_macros = 0x2119;
// Extensions for Fission.  See http://gcc.gnu.org/wiki/DebugFission.
pub const GNU_dwo_name = 0x2130;
pub const GNU_dwo_id = 0x2131;
pub const GNU_ranges_base = 0x2132;
pub const GNU_addr_base = 0x2133;
pub const GNU_pubnames = 0x2134;
pub const GNU_pubtypes = 0x2135;
// VMS extensions.
pub const VMS_rtnbeg_pd_address = 0x2201;
// GNAT extensions.
// GNAT descriptive type.
// See http://gcc.gnu.org/wiki/DW_AT_GNAT_descriptive_type .
pub const use_GNAT_descriptive_type = 0x2301;
pub const GNAT_descriptive_type = 0x2302;

// Zig extensions.
pub const ZIG_parent = 0x2ccd;
pub const ZIG_padding = 0x2cce;
pub const ZIG_relative_decl = 0x2cd0;
pub const ZIG_decl_line_relative = 0x2cd1;
pub const ZIG_comptime_value = 0x2cd2;
pub const ZIG_sentinel = 0x2ce2;

// UPC extension.
pub const upc_threads_scaled = 0x3210;
// PGI (STMicroelectronics) extensions.
pub const PGI_lbase = 0x3a00;
pub const PGI_soffset = 0x3a01;
pub const PGI_lstride = 0x3a02;
pub const @"void" = 0x0;
pub const address = 0x1;
pub const boolean = 0x2;
pub const complex_float = 0x3;
pub const float = 0x4;
pub const signed = 0x5;
pub const signed_char = 0x6;
pub const unsigned = 0x7;
pub const unsigned_char = 0x8;

// DWARF 3.
pub const imaginary_float = 0x9;
pub const packed_decimal = 0xa;
pub const numeric_string = 0xb;
pub const edited = 0xc;
pub const signed_fixed = 0xd;
pub const unsigned_fixed = 0xe;
pub const decimal_float = 0xf;

// DWARF 4.
pub const UTF = 0x10;

// DWARF 5.
pub const UCS = 0x11;
pub const ASCII = 0x12;

pub const lo_user = 0x80;
pub const hi_user = 0xff;

// HP extensions.
pub const HP_float80 = 0x80; // Floating-point (80 bit).
pub const HP_complex_float80 = 0x81; // Complex floating-point (80 bit).
pub const HP_float128 = 0x82; // Floating-point (128 bit).
pub const HP_complex_float128 = 0x83; // Complex fp (128 bit).
pub const HP_floathpintel = 0x84; // Floating-point (82 bit IA64).
pub const HP_imaginary_float80 = 0x85;
pub const HP_imaginary_float128 = 0x86;
pub const HP_VAX_float = 0x88; // F or G floating.
pub const HP_VAX_float_d = 0x89; // D floating.
pub const HP_packed_decimal = 0x8a; // Cobol.
pub const HP_zoned_decimal = 0x8b; // Cobol.
pub const HP_edited = 0x8c; // Cobol.
pub const HP_signed_fixed = 0x8d; // Cobol.
pub const HP_unsigned_fixed = 0x8e; // Cobol.
pub const HP_VAX_complex_float = 0x8f; // F or G floating complex.
pub const HP_VAX_complex_float_d = 0x90; // D floating complex.
pub const PE = struct {
    pub const absptr = 0x00;

    pub const size_mask = 0x7;
    pub const sign_mask = 0x8;
    pub const type_mask = size_mask | sign_mask;

    pub const uleb128 = 0x01;
    pub const udata2 = 0x02;
    pub const udata4 = 0x03;
    pub const udata8 = 0x04;
    pub const sleb128 = 0x09;
    pub const sdata2 = 0x0A;
    pub const sdata4 = 0x0B;
    pub const sdata8 = 0x0C;

    pub const rel_mask = 0x70;
    pub const pcrel = 0x10;
    pub const textrel = 0x20;
    pub const datarel = 0x30;
    pub const funcrel = 0x40;
    pub const aligned = 0x50;

    pub const indirect = 0x80;

    pub const omit = 0xff;
};
pub const addr = 0x01;
pub const block2 = 0x03;
pub const block4 = 0x04;
pub const data2 = 0x05;
pub const data4 = 0x06;
pub const data8 = 0x07;
pub const string = 0x08;
pub const block = 0x09;
pub const block1 = 0x0a;
pub const data1 = 0x0b;
pub const flag = 0x0c;
pub const sdata = 0x0d;
pub const strp = 0x0e;
pub const udata = 0x0f;
pub const ref_addr = 0x10;
pub const ref1 = 0x11;
pub const ref2 = 0x12;
pub const ref4 = 0x13;
pub const ref8 = 0x14;
pub const ref_udata = 0x15;
pub const indirect = 0x16;
pub const sec_offset = 0x17;
pub const exprloc = 0x18;
pub const flag_present = 0x19;
pub const strx = 0x1a;
pub const addrx = 0x1b;
pub const ref_sup4 = 0x1c;
pub const strp_sup = 0x1d;
pub const data16 = 0x1e;
pub const line_strp = 0x1f;
pub const ref_sig8 = 0x20;
pub const implicit_const = 0x21;
pub const loclistx = 0x22;
pub const rnglistx = 0x23;
pub const ref_sup8 = 0x24;
pub const strx1 = 0x25;
pub const strx2 = 0x26;
pub const strx3 = 0x27;
pub const strx4 = 0x28;
pub const addrx1 = 0x29;
pub const addrx2 = 0x2a;
pub const addrx3 = 0x2b;
pub const addrx4 = 0x2c;

// Extensions for Fission.  See http://gcc.gnu.org/wiki/DebugFission.
pub const GNU_addr_index = 0x1f01;
pub const GNU_str_index = 0x1f02;

// Extensions for DWZ multifile.
// See http://www.dwarfstd.org/ShowIssue.php?issue=120604.1&type=open .
pub const GNU_ref_alt = 0x1f20;
pub const GNU_strp_alt = 0x1f21;
pub const C89 = 0x0001;
pub const C = 0x0002;
pub const Ada83 = 0x0003;
pub const C_plus_plus = 0x0004;
pub const Cobol74 = 0x0005;
pub const Cobol85 = 0x0006;
pub const Fortran77 = 0x0007;
pub const Fortran90 = 0x0008;
pub const Pascal83 = 0x0009;
pub const Modula2 = 0x000a;
pub const Java = 0x000b;
pub const C99 = 0x000c;
pub const Ada95 = 0x000d;
pub const Fortran95 = 0x000e;
pub const PLI = 0x000f;
pub const ObjC = 0x0010;
pub const ObjC_plus_plus = 0x0011;
pub const UPC = 0x0012;
pub const D = 0x0013;
pub const Python = 0x0014;
pub const OpenCL = 0x0015;
pub const Go = 0x0016;
pub const Modula3 = 0x0017;
pub const Haskell = 0x0018;
pub const C_plus_plus_03 = 0x0019;
pub const C_plus_plus_11 = 0x001a;
pub const OCaml = 0x001b;
pub const Rust = 0x001c;
pub const C11 = 0x001d;
pub const Swift = 0x001e;
pub const Julia = 0x001f;
pub const Dylan = 0x0020;
pub const C_plus_plus_14 = 0x0021;
pub const Fortran03 = 0x0022;
pub const Fortran08 = 0x0023;
pub const RenderScript = 0x0024;
pub const BLISS = 0x0025;
pub const Kotlin = 0x0026;
pub const Zig = 0x0027;
pub const Crystal = 0x0028;
pub const C_plus_plus_17 = 0x002a;
pub const C_plus_plus_20 = 0x002b;
pub const C17 = 0x002c;
pub const Fortran18 = 0x002d;
pub const Ada2005 = 0x002e;
pub const Ada2012 = 0x002f;
pub const HIP = 0x0030;
pub const Assembly = 0x0031;
pub const C_sharp = 0x0032;
pub const Mojo = 0x0033;
pub const GLSL = 0x0034;
pub const GLSL_ES = 0x0035;
pub const HLSL = 0x0036;
pub const OpenCL_CPP = 0x0037;
pub const CPP_for_OpenCL = 0x0038;
pub const SYCL = 0x0039;
pub const C_plus_plus_23 = 0x003a;
pub const Odin = 0x003b;
pub const Ruby = 0x0040;
pub const Move = 0x0041;
pub const Hylo = 0x0042;

pub const lo_user = 0x8000;
pub const hi_user = 0xffff;

pub const Mips_Assembler = 0x8001;
pub const Upc = 0x8765;
pub const HP_Bliss = 0x8003;
pub const HP_Basic91 = 0x8004;
pub const HP_Pascal91 = 0x8005;
pub const HP_IMacro = 0x8006;
pub const HP_Assembler = 0x8007;
pub const addr = 0x03;
pub const deref = 0x06;
pub const const1u = 0x08;
pub const const1s = 0x09;
pub const const2u = 0x0a;
pub const const2s = 0x0b;
pub const const4u = 0x0c;
pub const const4s = 0x0d;
pub const const8u = 0x0e;
pub const const8s = 0x0f;
pub const constu = 0x10;
pub const consts = 0x11;
pub const dup = 0x12;
pub const drop = 0x13;
pub const over = 0x14;
pub const pick = 0x15;
pub const swap = 0x16;
pub const rot = 0x17;
pub const xderef = 0x18;
pub const abs = 0x19;
pub const @"and" = 0x1a;
pub const div = 0x1b;
pub const minus = 0x1c;
pub const mod = 0x1d;
pub const mul = 0x1e;
pub const neg = 0x1f;
pub const not = 0x20;
pub const @"or" = 0x21;
pub const plus = 0x22;
pub const plus_uconst = 0x23;
pub const shl = 0x24;
pub const shr = 0x25;
pub const shra = 0x26;
pub const xor = 0x27;
pub const bra = 0x28;
pub const eq = 0x29;
pub const ge = 0x2a;
pub const gt = 0x2b;
pub const le = 0x2c;
pub const lt = 0x2d;
pub const ne = 0x2e;
pub const skip = 0x2f;
pub const lit0 = 0x30;
pub const lit1 = 0x31;
pub const lit2 = 0x32;
pub const lit3 = 0x33;
pub const lit4 = 0x34;
pub const lit5 = 0x35;
pub const lit6 = 0x36;
pub const lit7 = 0x37;
pub const lit8 = 0x38;
pub const lit9 = 0x39;
pub const lit10 = 0x3a;
pub const lit11 = 0x3b;
pub const lit12 = 0x3c;
pub const lit13 = 0x3d;
pub const lit14 = 0x3e;
pub const lit15 = 0x3f;
pub const lit16 = 0x40;
pub const lit17 = 0x41;
pub const lit18 = 0x42;
pub const lit19 = 0x43;
pub const lit20 = 0x44;
pub const lit21 = 0x45;
pub const lit22 = 0x46;
pub const lit23 = 0x47;
pub const lit24 = 0x48;
pub const lit25 = 0x49;
pub const lit26 = 0x4a;
pub const lit27 = 0x4b;
pub const lit28 = 0x4c;
pub const lit29 = 0x4d;
pub const lit30 = 0x4e;
pub const lit31 = 0x4f;
pub const reg0 = 0x50;
pub const reg1 = 0x51;
pub const reg2 = 0x52;
pub const reg3 = 0x53;
pub const reg4 = 0x54;
pub const reg5 = 0x55;
pub const reg6 = 0x56;
pub const reg7 = 0x57;
pub const reg8 = 0x58;
pub const reg9 = 0x59;
pub const reg10 = 0x5a;
pub const reg11 = 0x5b;
pub const reg12 = 0x5c;
pub const reg13 = 0x5d;
pub const reg14 = 0x5e;
pub const reg15 = 0x5f;
pub const reg16 = 0x60;
pub const reg17 = 0x61;
pub const reg18 = 0x62;
pub const reg19 = 0x63;
pub const reg20 = 0x64;
pub const reg21 = 0x65;
pub const reg22 = 0x66;
pub const reg23 = 0x67;
pub const reg24 = 0x68;
pub const reg25 = 0x69;
pub const reg26 = 0x6a;
pub const reg27 = 0x6b;
pub const reg28 = 0x6c;
pub const reg29 = 0x6d;
pub const reg30 = 0x6e;
pub const reg31 = 0x6f;
pub const breg0 = 0x70;
pub const breg1 = 0x71;
pub const breg2 = 0x72;
pub const breg3 = 0x73;
pub const breg4 = 0x74;
pub const breg5 = 0x75;
pub const breg6 = 0x76;
pub const breg7 = 0x77;
pub const breg8 = 0x78;
pub const breg9 = 0x79;
pub const breg10 = 0x7a;
pub const breg11 = 0x7b;
pub const breg12 = 0x7c;
pub const breg13 = 0x7d;
pub const breg14 = 0x7e;
pub const breg15 = 0x7f;
pub const breg16 = 0x80;
pub const breg17 = 0x81;
pub const breg18 = 0x82;
pub const breg19 = 0x83;
pub const breg20 = 0x84;
pub const breg21 = 0x85;
pub const breg22 = 0x86;
pub const breg23 = 0x87;
pub const breg24 = 0x88;
pub const breg25 = 0x89;
pub const breg26 = 0x8a;
pub const breg27 = 0x8b;
pub const breg28 = 0x8c;
pub const breg29 = 0x8d;
pub const breg30 = 0x8e;
pub const breg31 = 0x8f;
pub const regx = 0x90;
pub const fbreg = 0x91;
pub const bregx = 0x92;
pub const piece = 0x93;
pub const deref_size = 0x94;
pub const xderef_size = 0x95;
pub const nop = 0x96;

// DWARF 3 extensions.
pub const push_object_address = 0x97;
pub const call2 = 0x98;
pub const call4 = 0x99;
pub const call_ref = 0x9a;
pub const form_tls_address = 0x9b;
pub const call_frame_cfa = 0x9c;
pub const bit_piece = 0x9d;

// DWARF 4 extensions.
pub const implicit_value = 0x9e;
pub const stack_value = 0x9f;

// DWARF 5 extensions.
pub const implicit_pointer = 0xa0;
pub const addrx = 0xa1;
pub const constx = 0xa2;
pub const entry_value = 0xa3;
pub const const_type = 0xa4;
pub const regval_type = 0xa5;
pub const deref_type = 0xa6;
pub const xderef_type = 0xa7;
pub const convert = 0xa8;
pub const reinterpret = 0xa9;

pub const lo_user = 0xe0; // Implementation-defined range start.
pub const hi_user = 0xff; // Implementation-defined range end.

// GNU extensions.
pub const GNU_push_tls_address = 0xe0;
// The following is for marking variables that are uninitialized.
pub const GNU_uninit = 0xf0;
pub const GNU_encoded_addr = 0xf1;
// The GNU implicit pointer extension.
// See http://www.dwarfstd.org/ShowIssue.php?issue=100831.1&type=open .
pub const GNU_implicit_pointer = 0xf2;
// The GNU entry value extension.
// See http://www.dwarfstd.org/ShowIssue.php?issue=100909.1&type=open .
pub const GNU_entry_value = 0xf3;
// The GNU typed stack extension.
// See http://www.dwarfstd.org/doc/040408.1.html .
pub const GNU_const_type = 0xf4;
pub const GNU_regval_type = 0xf5;
pub const GNU_deref_type = 0xf6;
pub const GNU_convert = 0xf7;
pub const GNU_reinterpret = 0xf9;
// The GNU parameter ref extension.
pub const GNU_parameter_ref = 0xfa;
// Extension for Fission.  See http://gcc.gnu.org/wiki/DebugFission.
pub const GNU_addr_index = 0xfb;
pub const GNU_const_index = 0xfc;
// HP extensions.
pub const HP_unknown = 0xe0; // Ouch, the same as GNU_push_tls_address.
pub const HP_is_value = 0xe1;
pub const HP_fltconst4 = 0xe2;
pub const HP_fltconst8 = 0xe3;
pub const HP_mod_range = 0xe4;
pub const HP_unmod_range = 0xe5;
pub const HP_tls = 0xe6;
// PGI (STMicroelectronics) extensions.
pub const PGI_omp_thread_num = 0xf8;
// Wasm extensions.
pub const WASM_location = 0xed;
pub const WASM_local = 0x00;
pub const WASM_global = 0x01;
pub const WASM_global_u32 = 0x03;
pub const WASM_operand_stack = 0x02;
pub const padding = 0x00;
pub const array_type = 0x01;
pub const class_type = 0x02;
pub const entry_point = 0x03;
pub const enumeration_type = 0x04;
pub const formal_parameter = 0x05;
pub const imported_declaration = 0x08;
pub const label = 0x0a;
pub const lexical_block = 0x0b;
pub const member = 0x0d;
pub const pointer_type = 0x0f;
pub const reference_type = 0x10;
pub const compile_unit = 0x11;
pub const string_type = 0x12;
pub const structure_type = 0x13;
pub const subroutine = 0x14;
pub const subroutine_type = 0x15;
pub const typedef = 0x16;
pub const union_type = 0x17;
pub const unspecified_parameters = 0x18;
pub const variant = 0x19;
pub const common_block = 0x1a;
pub const common_inclusion = 0x1b;
pub const inheritance = 0x1c;
pub const inlined_subroutine = 0x1d;
pub const module = 0x1e;
pub const ptr_to_member_type = 0x1f;
pub const set_type = 0x20;
pub const subrange_type = 0x21;
pub const with_stmt = 0x22;
pub const access_declaration = 0x23;
pub const base_type = 0x24;
pub const catch_block = 0x25;
pub const const_type = 0x26;
pub const constant = 0x27;
pub const enumerator = 0x28;
pub const file_type = 0x29;
pub const friend = 0x2a;
pub const namelist = 0x2b;
pub const namelist_item = 0x2c;
pub const packed_type = 0x2d;
pub const subprogram = 0x2e;
pub const template_type_param = 0x2f;
pub const template_value_param = 0x30;
pub const thrown_type = 0x31;
pub const try_block = 0x32;
pub const variant_part = 0x33;
pub const variable = 0x34;
pub const volatile_type = 0x35;

// DWARF 3
pub const dwarf_procedure = 0x36;
pub const restrict_type = 0x37;
pub const interface_type = 0x38;
pub const namespace = 0x39;
pub const imported_module = 0x3a;
pub const unspecified_type = 0x3b;
pub const partial_unit = 0x3c;
pub const imported_unit = 0x3d;
pub const condition = 0x3f;
pub const shared_type = 0x40;

// DW```
