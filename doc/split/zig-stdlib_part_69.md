```
 0x4;

/// the object file's undefined references are bound by the dynamic linker when loaded.
pub const MH_BINDATLOAD = 0x8;

/// the file has its dynamic undefined references prebound.
pub const MH_PREBOUND = 0x10;

/// the file has its read-only and read-write segments split
pub const MH_SPLIT_SEGS = 0x20;

/// the shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete)
pub const MH_LAZY_INIT = 0x40;

/// the image is using two-level name space bindings
pub const MH_TWOLEVEL = 0x80;

/// the executable is forcing all images to use flat name space bindings
pub const MH_FORCE_FLAT = 0x100;

/// this umbrella guarantees no multiple definitions of symbols in its sub-images so the two-level namespace hints can always be used.
pub const MH_NOMULTIDEFS = 0x200;

/// do not have dyld notify the prebinding agent about this executable
pub const MH_NOFIXPREBINDING = 0x400;

/// the binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set.
pub const MH_PREBINDABLE = 0x800;

/// indicates that this binary binds to all two-level namespace modules of its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL are both set.
pub const MH_ALLMODSBOUND = 0x1000;

/// safe to divide up the sections into sub-sections via symbols for dead code stripping
pub const MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000;

/// the binary has been canonicalized via the unprebind operation
pub const MH_CANONICAL = 0x4000;

/// the final linked image contains external weak symbols
pub const MH_WEAK_DEFINES = 0x8000;

/// the final linked image uses weak symbols
pub const MH_BINDS_TO_WEAK = 0x10000;

/// When this bit is set, all stacks in the task will be given stack execution privilege.  Only used in MH_EXECUTE filetypes.
pub const MH_ALLOW_STACK_EXECUTION = 0x20000;

/// When this bit is set, the binary declares it is safe for use in processes with uid zero
pub const MH_ROOT_SAFE = 0x40000;

/// When this bit is set, the binary declares it is safe for use in processes when issetugid() is true
pub const MH_SETUID_SAFE = 0x80000;

/// When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported
pub const MH_NO_REEXPORTED_DYLIBS = 0x100000;

/// When this bit is set, the OS will load the main executable at a random address.  Only used in MH_EXECUTE filetypes.
pub const MH_PIE = 0x200000;

/// Only for use on dylibs.  When linking against a dylib that has this bit set, the static linker will automatically not create a LC_LOAD_DYLIB load command to the dylib if no symbols are being referenced from the dylib.
pub const MH_DEAD_STRIPPABLE_DYLIB = 0x400000;

/// Contains a section of type S_THREAD_LOCAL_VARIABLES
pub const MH_HAS_TLV_DESCRIPTORS = 0x800000;

/// When this bit is set, the OS will run the main executable with a non-executable heap even on platforms (e.g. x86) that don't require it. Only used in MH_EXECUTE filetypes.
pub const MH_NO_HEAP_EXECUTION = 0x1000000;

/// The code was linked for use in an application extension.
pub const MH_APP_EXTENSION_SAFE = 0x02000000;

/// The external symbols listed in the nlist symbol table do not include all the symbols listed in the dyld info.
pub const MH_NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x04000000;

/// Allow LC_MIN_VERSION_MACOS and LC_BUILD_VERSION load commands with the platforms macOS, iOSMac, iOSSimulator, tvOSSimulator and watchOSSimulator.
pub const MH_SIM_SUPPORT = 0x08000000;

/// Only for use on dylibs. When this bit is set, the dylib is part of the dyld shared cache, rather than loose in the filesystem.
pub const MH_DYLIB_IN_CACHE = 0x80000000;

// Constants for the flags field of the fat_header

/// the fat magic number
pub const FAT_MAGIC = 0xcafebabe;

/// NXSwapLong(FAT_MAGIC)
pub const FAT_CIGAM = 0xbebafeca;

/// the 64-bit fat magic number
pub const FAT_MAGIC_64 = 0xcafebabf;

/// NXSwapLong(FAT_MAGIC_64)
pub const FAT_CIGAM_64 = 0xbfbafeca;

/// Segment flags
/// The file contents for this segment is for the high part of the VM space, the low part
/// is zero filled (for stacks in core files).
pub const SG_HIGHVM = 0x1;
/// This segment is the VM that is allocated by a fixed VM library, for overlap checking in
/// the link editor.
pub const SG_FVMLIB = 0x2;
/// This segment has nothing that was relocated in it and nothing relocated to it, that is
/// it maybe safely replaced without relocation.
pub const SG_NORELOC = 0x4;
/// This segment is protected.  If the segment starts at file offset 0, the
/// first page of the segment is not protected.  All other pages of the segment are protected.
pub const SG_PROTECTED_VERSION_1 = 0x8;
/// This segment is made read-only after fixups
pub const SG_READ_ONLY = 0x10;

/// The flags field of a section structure is separated into two parts a section
/// type and section attributes.  The section types are mutually exclusive (it
/// can only have one type) but the section attributes are not (it may have more
/// than one attribute).
/// 256 section types
pub const SECTION_TYPE = 0x000000ff;

///  24 section attributes
pub const SECTION_ATTRIBUTES = 0xffffff00;

/// regular section
pub const S_REGULAR = 0x0;

/// zero fill on demand section
pub const S_ZEROFILL = 0x1;

/// section with only literal C string
pub const S_CSTRING_LITERALS = 0x2;

/// section with only 4 byte literals
pub const S_4BYTE_LITERALS = 0x3;

/// section with only 8 byte literals
pub const S_8BYTE_LITERALS = 0x4;

/// section with only pointers to
pub const S_LITERAL_POINTERS = 0x5;

/// if any of these bits set, a symbolic debugging entry
pub const N_STAB = 0xe0;

/// private external symbol bit
pub const N_PEXT = 0x10;

/// mask for the type bits
pub const N_TYPE = 0x0e;

/// external symbol bit, set for external symbols
pub const N_EXT = 0x01;

/// symbol is undefined
pub const N_UNDF = 0x0;

/// symbol is absolute
pub const N_ABS = 0x2;

/// symbol is defined in the section number given in n_sect
pub const N_SECT = 0xe;

/// symbol is undefined  and the image is using a prebound
/// value  for the symbol
pub const N_PBUD = 0xc;

/// symbol is defined to be the same as another symbol; the n_value
/// field is an index into the string table specifying the name of the
/// other symbol
pub const N_INDR = 0xa;

/// global symbol: name,,NO_SECT,type,0
pub const N_GSYM = 0x20;

/// procedure name (f77 kludge): name,,NO_SECT,0,0
pub const N_FNAME = 0x22;

/// procedure: name,,n_sect,linenumber,address
pub const N_FUN = 0x24;

/// static symbol: name,,n_sect,type,address
pub const N_STSYM = 0x26;

/// .lcomm symbol: name,,n_sect,type,address
pub const N_LCSYM = 0x28;

/// begin nsect sym: 0,,n_sect,0,address
pub const N_BNSYM = 0x2e;

/// AST file path: name,,NO_SECT,0,0
pub const N_AST = 0x32;

/// emitted with gcc2_compiled and in gcc source
pub const N_OPT = 0x3c;

/// register sym: name,,NO_SECT,type,register
pub const N_RSYM = 0x40;

/// src line: 0,,n_sect,linenumber,address
pub const N_SLINE = 0x44;

/// end nsect sym: 0,,n_sect,0,address
pub const N_ENSYM = 0x4e;

/// structure elt: name,,NO_SECT,type,struct_offset
pub const N_SSYM = 0x60;

/// source file name: name,,n_sect,0,address
pub const N_SO = 0x64;

/// object file name: name,,0,0,st_mtime
pub const N_OSO = 0x66;

/// local sym: name,,NO_SECT,type,offset
pub const N_LSYM = 0x80;

/// include file beginning: name,,NO_SECT,0,sum
pub const N_BINCL = 0x82;

/// #included file name: name,,n_sect,0,address
pub const N_SOL = 0x84;

/// compiler parameters: name,,NO_SECT,0,0
pub const N_PARAMS = 0x86;

/// compiler version: name,,NO_SECT,0,0
pub const N_VERSION = 0x88;

/// compiler -O level: name,,NO_SECT,0,0
pub const N_OLEVEL = 0x8A;

/// parameter: name,,NO_SECT,type,offset
pub const N_PSYM = 0xa0;

/// include file end: name,,NO_SECT,0,0
pub const N_EINCL = 0xa2;

/// alternate entry: name,,n_sect,linenumber,address
pub const N_ENTRY = 0xa4;

/// left bracket: 0,,NO_SECT,nesting level,address
pub const N_LBRAC = 0xc0;

/// deleted include file: name,,NO_SECT,0,sum
pub const N_EXCL = 0xc2;

/// right bracket: 0,,NO_SECT,nesting level,address
pub const N_RBRAC = 0xe0;

/// begin common: name,,NO_SECT,0,0
pub const N_BCOMM = 0xe2;

/// end common: name,,n_sect,0,0
pub const N_ECOMM = 0xe4;

/// end common (local name): 0,,n_sect,0,address
pub const N_ECOML = 0xe8;

/// second stab entry with length information
pub const N_LENG = 0xfe;

// For the two types of symbol pointers sections and the symbol stubs section
// they have indirect symbol table entries.  For each of the entries in the
// section the indirect symbol table entries, in corresponding order in the
// indirect symbol table, start at the index stored in the reserved1 field
// of the section structure.  Since the indirect symbol table entries
// correspond to the entries in the section the number of indirect symbol table
// entries is inferred from the size of the section divided by the size of the
// entries in the section.  For symbol pointers sections the size of the entries
// in the section is 4 bytes and for symbol stubs sections the byte size of the
// stubs is stored in the reserved2 field of the section structure.

/// section with only non-lazy symbol pointers
pub const S_NON_LAZY_SYMBOL_POINTERS = 0x6;

/// section with only lazy symbol pointers
pub const S_LAZY_SYMBOL_POINTERS = 0x7;

/// section with only symbol stubs, byte size of stub in the reserved2 field
pub const S_SYMBOL_STUBS = 0x8;

/// section with only function pointers for initialization
pub const S_MOD_INIT_FUNC_POINTERS = 0x9;

/// section with only function pointers for termination
pub const S_MOD_TERM_FUNC_POINTERS = 0xa;

/// section contains symbols that are to be coalesced
pub const S_COALESCED = 0xb;

/// zero fill on demand section (that can be larger than 4 gigabytes)
pub const S_GB_ZEROFILL = 0xc;

/// section with only pairs of function pointers for interposing
pub const S_INTERPOSING = 0xd;

/// section with only 16 byte literals
pub const S_16BYTE_LITERALS = 0xe;

/// section contains DTrace Object Format
pub const S_DTRACE_DOF = 0xf;

/// section with only lazy symbol pointers to lazy loaded dylibs
pub const S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10;

// If a segment contains any sections marked with S_ATTR_DEBUG then all
// sections in that segment must have this attribute.  No section other than
// a section marked with this attribute may reference the contents of this
// section.  A section with this attribute may contain no symbols and must have
// a section type S_REGULAR.  The static linker will not copy section contents
// from sections with this attribute into its output file.  These sections
// generally contain DWARF debugging info.

/// a debug section
pub const S_ATTR_DEBUG = 0x02000000;

/// section contains only true machine instructions
pub const S_ATTR_PURE_INSTRUCTIONS = 0x80000000;

/// section contains coalesced symbols that are not to be in a ranlib
/// table of contents
pub const S_ATTR_NO_TOC = 0x40000000;

/// ok to strip static symbols in this section in files with the
/// MH_DYLDLINK flag
pub const S_ATTR_STRIP_STATIC_SYMS = 0x20000000;

/// no dead stripping
pub const S_ATTR_NO_DEAD_STRIP = 0x10000000;

/// blocks are live if they reference live blocks
pub const S_ATTR_LIVE_SUPPORT = 0x8000000;

/// used with x86 code stubs written on by dyld
pub const S_ATTR_SELF_MODIFYING_CODE = 0x4000000;

/// section contains some machine instructions
pub const S_ATTR_SOME_INSTRUCTIONS = 0x400;

/// section has external relocation entries
pub const S_ATTR_EXT_RELOC = 0x200;

/// section has local relocation entries
pub const S_ATTR_LOC_RELOC = 0x100;

/// template of initial values for TLVs
pub const S_THREAD_LOCAL_REGULAR = 0x11;

/// template of initial values for TLVs
pub const S_THREAD_LOCAL_ZEROFILL = 0x12;

/// TLV descriptors
pub const S_THREAD_LOCAL_VARIABLES = 0x13;

/// pointers to TLV descriptors
pub const S_THREAD_LOCAL_VARIABLE_POINTERS = 0x14;

/// functions to call to initialize TLV values
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15;

/// 32-bit offsets to initializers
pub const S_INIT_FUNC_OFFSETS = 0x16;

/// CPU type targeting 64-bit Intel-based Macs
pub const CPU_TYPE_X86_64: cpu_type_t = 0x01000007;

/// CPU type targeting 64-bit ARM-based Macs
pub const CPU_TYPE_ARM64: cpu_type_t = 0x0100000C;

/// All Intel-based Macs
pub const CPU_SUBTYPE_X86_64_ALL: cpu_subtype_t = 0x3;

/// All ARM-based Macs
pub const CPU_SUBTYPE_ARM_ALL: cpu_subtype_t = 0x0;

// The following are used to encode rebasing information
pub const REBASE_TYPE_POINTER: u8 = 1;
pub const REBASE_TYPE_TEXT_ABSOLUTE32: u8 = 2;
pub const REBASE_TYPE_TEXT_PCREL32: u8 = 3;

pub const REBASE_OPCODE_MASK: u8 = 0xF0;
pub const REBASE_IMMEDIATE_MASK: u8 = 0x0F;
pub const REBASE_OPCODE_DONE: u8 = 0x00;
pub const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
pub const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
pub const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
pub const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
pub const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
pub const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

// The following are used to encode binding information
pub const BIND_TYPE_POINTER: u8 = 1;
pub const BIND_TYPE_TEXT_ABSOLUTE32: u8 = 2;
pub const BIND_TYPE_TEXT_PCREL32: u8 = 3;

pub const BIND_SPECIAL_DYLIB_SELF: i8 = 0;
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i8 = -1;
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i8 = -2;

pub const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8 = 0x1;
pub const BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION: u8 = 0x8;

pub const BIND_OPCODE_MASK: u8 = 0xf0;
pub const BIND_IMMEDIATE_MASK: u8 = 0x0f;
pub const BIND_OPCODE_DONE: u8 = 0x00;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
pub const BIND_OPCODE_DO_BIND: u8 = 0x90;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xa0;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xb0;
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xc0;

pub const reloc_type_x86_64 = enum(u4) {
    /// for absolute addresses
    X86_64_RELOC_UNSIGNED = 0,

    /// for signed 32-bit displacement
    X86_64_RELOC_SIGNED,

    /// a CALL/JMP instruction with 32-bit displacement
    X86_64_RELOC_BRANCH,

    /// a MOVQ load of a GOT entry
    X86_64_RELOC_GOT_LOAD,

    /// other GOT references
    X86_64_RELOC_GOT,

    /// must be followed by a X86_64_RELOC_UNSIGNED
    X86_64_RELOC_SUBTRACTOR,

    /// for signed 32-bit displacement with a -1 addend
    X86_64_RELOC_SIGNED_1,

    /// for signed 32-bit displacement with a -2 addend
    X86_64_RELOC_SIGNED_2,

    /// for signed 32-bit displacement with a -4 addend
    X86_64_RELOC_SIGNED_4,

    /// for thread local variables
    X86_64_RELOC_TLV,
};

pub const reloc_type_arm64 = enum(u4) {
    /// For pointers.
    ARM64_RELOC_UNSIGNED = 0,

    /// Must be followed by a ARM64_RELOC_UNSIGNED.
    ARM64_RELOC_SUBTRACTOR,

    /// A B/BL instruction with 26-bit displacement.
    ARM64_RELOC_BRANCH26,

    /// Pc-rel distance to page of target.
    ARM64_RELOC_PAGE21,

    /// Offset within page, scaled by r_length.
    ARM64_RELOC_PAGEOFF12,

    /// Pc-rel distance to page of GOT slot.
    ARM64_RELOC_GOT_LOAD_PAGE21,

    /// Offset within page of GOT slot, scaled by r_length.
    ARM64_RELOC_GOT_LOAD_PAGEOFF12,

    /// For pointers to GOT slots.
    ARM64_RELOC_POINTER_TO_GOT,

    /// Pc-rel distance to page of TLVP slot.
    ARM64_RELOC_TLVP_LOAD_PAGE21,

    /// Offset within page of TLVP slot, scaled by r_length.
    ARM64_RELOC_TLVP_LOAD_PAGEOFF12,

    /// Must be followed by PAGE21 or PAGEOFF12.
    ARM64_RELOC_ADDEND,
};

/// This symbol is a reference to an external non-lazy (data) symbol.
pub const REFERENCE_FLAG_UNDEFINED_NON_LAZY: u16 = 0x0;

/// This symbol is a reference to an external lazy symbol—that is, to a function call.
pub const REFERENCE_FLAG_UNDEFINED_LAZY: u16 = 0x1;

/// This symbol is defined in this module.
pub const REFERENCE_FLAG_DEFINED: u16 = 0x2;

/// This symbol is defined in this module and is visible only to modules within this shared library.
pub const REFERENCE_FLAG_PRIVATE_DEFINED: u16 = 3;

/// This symbol is defined in another module in this file, is a non-lazy (data) symbol, and is visible
/// only to modules within this shared library.
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY: u16 = 4;

/// This symbol is defined in another module in this file, is a lazy (function) symbol, and is visible
/// only to modules within this shared library.
pub const REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY: u16 = 5;

/// Must be set for any defined symbol that is referenced by dynamic-loader APIs (such as dlsym and
/// NSLookupSymbolInImage) and not ordinary undefined symbol references. The strip tool uses this bit
/// to avoid removing symbols that must exist: If the symbol has this bit set, strip does not strip it.
pub const REFERENCED_DYNAMICALLY: u16 = 0x10;

/// The N_NO_DEAD_STRIP bit of the n_desc field only ever appears in a
/// relocatable .o file (MH_OBJECT filetype). And is used to indicate to the
/// static link editor it is never to dead strip the symbol.
pub const N_NO_DEAD_STRIP: u16 = 0x20;

/// Used by the dynamic linker at runtime. Do not set this bit.
pub const N_DESC_DISCARDED: u16 = 0x20;

/// Indicates that this symbol is a weak reference. If the dynamic linker cannot find a definition
/// for this symbol, it sets the address of this symbol to 0. The static linker sets this symbol given
/// the appropriate weak-linking flags.
pub const N_WEAK_REF: u16 = 0x40;

/// Indicates that this symbol is a weak definition. If the static linker or the dynamic linker finds
/// another (non-weak) definition for this symbol, the weak definition is ignored. Only symbols in a
/// coalesced section (page 23) can be marked as a weak definition.
pub const N_WEAK_DEF: u16 = 0x80;

/// The N_SYMBOL_RESOLVER bit of the n_desc field indicates that the
/// that the function is actually a resolver function and should
/// be called to get the address of the real function to use.
/// This bit is only available in .o files (MH_OBJECT filetype)
pub const N_SYMBOL_RESOLVER: u16 = 0x100;

// The following are used on the flags byte of a terminal node in the export information.
pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u8 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u8 = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u8 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u8 = 0x02;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u8 = 0x04;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u8 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u8 = 0x10;

// An indirect symbol table entry is simply a 32bit index into the symbol table
// to the symbol that the pointer or stub is referring to.  Unless it is for a
// non-lazy symbol pointer section for a defined symbol which strip(1) as
// removed.  In which case it has the value INDIRECT_SYMBOL_LOCAL.  If the
// symbol was also absolute INDIRECT_SYMBOL_ABS is or'ed with that.
pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x80000000;
pub const INDIRECT_SYMBOL_ABS: u32 = 0x40000000;

// Codesign consts and structs taken from:
// https://opensource.apple.com/source/xnu/xnu-6153.81.5/osfmk/kern/cs_blobs.h.auto.html

/// Single Requirement blob
pub const CSMAGIC_REQUIREMENT: u32 = 0xfade0c00;
/// Requirements vector (internal requirements)
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;
/// CodeDirectory blob
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
/// embedded form of signature data
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
/// XXX
pub const CSMAGIC_EMBEDDED_SIGNATURE_OLD: u32 = 0xfade0b02;
/// Embedded entitlements
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;
/// Embedded DER encoded entitlements
pub const CSMAGIC_EMBEDDED_DER_ENTITLEMENTS: u32 = 0xfade7172;
/// Multi-arch collection of embedded signatures
pub const CSMAGIC_DETACHED_SIGNATURE: u32 = 0xfade0cc1;
/// CMS Signature, among other things
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xfade0b01;

pub const CS_SUPPORTSSCATTER: u32 = 0x20100;
pub const CS_SUPPORTSTEAMID: u32 = 0x20200;
pub const CS_SUPPORTSCODELIMIT64: u32 = 0x20300;
pub const CS_SUPPORTSEXECSEG: u32 = 0x20400;

/// Slot index for CodeDirectory
pub const CSSLOT_CODEDIRECTORY: u32 = 0;
pub const CSSLOT_INFOSLOT: u32 = 1;
pub const CSSLOT_REQUIREMENTS: u32 = 2;
pub const CSSLOT_RESOURCEDIR: u32 = 3;
pub const CSSLOT_APPLICATION: u32 = 4;
pub const CSSLOT_ENTITLEMENTS: u32 = 5;
pub const CSSLOT_DER_ENTITLEMENTS: u32 = 7;

/// first alternate CodeDirectory, if any
pub const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
/// Max number of alternate CD slots
pub const CSSLOT_ALTERNATE_CODEDIRECTORY_MAX: u32 = 5;
/// One past the last
pub const CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT: u32 = CSSLOT_ALTERNATE_CODEDIRECTORIES + CSSLOT_ALTERNATE_CODEDIRECTORY_MAX;

/// CMS Signature
pub const CSSLOT_SIGNATURESLOT: u32 = 0x10000;
pub const CSSLOT_IDENTIFICATIONSLOT: u32 = 0x10001;
pub const CSSLOT_TICKETSLOT: u32 = 0x10002;

/// Compat with amfi
pub const CSTYPE_INDEX_REQUIREMENTS: u32 = 0x00000002;
/// Compat with amfi
pub const CSTYPE_INDEX_ENTITLEMENTS: u32 = 0x00000005;

pub const CS_HASHTYPE_SHA1: u8 = 1;
pub const CS_HASHTYPE_SHA256: u8 = 2;
pub const CS_HASHTYPE_SHA256_TRUNCATED: u8 = 3;
pub const CS_HASHTYPE_SHA384: u8 = 4;

pub const CS_SHA1_LEN: u32 = 20;
pub const CS_SHA256_LEN: u32 = 32;
pub const CS_SHA256_TRUNCATED_LEN: u32 = 20;

/// Always - larger hashes are truncated
pub const CS_CDHASH_LEN: u32 = 20;
/// Max size of the hash we'll support
pub const CS_HASH_MAX_SIZE: u32 = 48;

pub const CS_SIGNER_TYPE_UNKNOWN: u32 = 0;
pub const CS_SIGNER_TYPE_LEGACYVPN: u32 = 5;
pub const CS_SIGNER_TYPE_MAC_APP_STORE: u32 = 6;

pub const CS_ADHOC: u32 = 0x2;
pub const CS_LINKER_SIGNED: u32 = 0x20000;

pub const CS_EXECSEG_MAIN_BINARY: u32 = 0x1;

/// This CodeDirectory is tailored specifically at version 0x20400.
pub const CodeDirectory = extern struct {
    /// Magic number (CSMAGIC_CODEDIRECTORY)
    magic: u32,

    /// Total length of CodeDirectory blob
    length: u32,

    /// Compatibility version
    version: u32,

    /// Setup and mode flags
    flags: u32,

    /// Offset of hash slot element at index zero
    hashOffset: u32,

    /// Offset of identifier string
    identOffset: u32,

    /// Number of special hash slots
    nSpecialSlots: u32,

    /// Number of ordinary (code) hash slots
    nCodeSlots: u32,

    /// Limit to main image signature range
    codeLimit: u32,

    /// Size of each hash in bytes
    hashSize: u8,

    /// Type of hash (cdHashType* constants)
    hashType: u8,

    /// Platform identifier; zero if not platform binary
    platform: u8,

    /// log2(page size in bytes); 0 => infinite
    pageSize: u8,

    /// Unused (must be zero)
    spare2: u32,

    ///
    scatterOffset: u32,

    ///
    teamOffset: u32,

    ///
    spare3: u32,

    ///
    codeLimit64: u64,

    /// Offset of executable segment
    execSegBase: u64,

    /// Limit of executable segment
    execSegLimit: u64,

    /// Executable segment flags
    execSegFlags: u64,
};

/// Structure of an embedded-signature SuperBlob
pub const BlobIndex = extern struct {
    /// Type of entry
    type: u32,

    /// Offset of entry
    offset: u32,
};

/// This structure is followed by GenericBlobs in no particular
/// order as indicated by offsets in index
pub const SuperBlob = extern struct {
    /// Magic number
    magic: u32,

    /// Total length of SuperBlob
    length: u32,

    /// Number of index BlobIndex entries following this struct
    count: u32,
};

pub const GenericBlob = extern struct {
    /// Magic number
    magic: u32,

    /// Total length of blob
    length: u32,
};

/// The LC_DATA_IN_CODE load commands uses a linkedit_data_command
/// to point to an array of data_in_code_entry entries. Each entry
/// describes a range of data in a code section.
pub const data_in_code_entry = extern struct {
    /// From mach_header to start of data range.
    offset: u32,

    /// Number of bytes in data range.
    length: u16,

    /// A DICE_KIND value.
    kind: u16,
};

pub const LoadCommandIterator = struct {
    ncmds: usize,
    buffer: []const u8,
    index: usize = 0,

    pub const LoadCommand = struct {
        hdr: load_command,
        data: []const u8,

        pub fn cmd(lc: LoadCommand) LC {
            return lc.hdr.cmd;
        }

        pub fn cmdsize(lc: LoadCommand) u32 {
            return lc.hdr.cmdsize;
        }

        pub fn cast(lc: LoadCommand, comptime Cmd: type) ?Cmd {
            if (lc.data.len < @sizeOf(Cmd)) return null;
            return @as(*align(1) const Cmd, @ptrCast(lc.data.ptr)).*;
        }

        /// Asserts LoadCommand is of type segment_command_64.
        pub fn getSections(lc: LoadCommand) []align(1) const section_64 {
            const segment_lc = lc.cast(segment_command_64).?;
            if (segment_lc.nsects == 0) return &[0]section_64{};
            const data = lc.data[@sizeOf(segment_command_64)..];
            const sections = @as([*]align(1) const section_64, @ptrCast(data.ptr))[0..segment_lc.nsects];
            return sections;
        }

        /// Asserts LoadCommand is of type dylib_command.
        pub fn getDylibPathName(lc: LoadCommand) []const u8 {
            const dylib_lc = lc.cast(dylib_command).?;
            const data = lc.data[dylib_lc.dylib.name..];
            return mem.sliceTo(data, 0);
        }

        /// Asserts LoadCommand is of type rpath_command.
        pub fn getRpathPathName(lc: LoadCommand) []const u8 {
            const rpath_lc = lc.cast(rpath_command).?;
            const data = lc.data[rpath_lc.path..];
            return mem.sliceTo(data, 0);
        }

        /// Asserts LoadCommand is of type build_version_command.
        pub fn getBuildVersionTools(lc: LoadCommand) []align(1) const build_tool_version {
            const build_lc = lc.cast(build_version_command).?;
            const ntools = build_lc.ntools;
            if (ntools == 0) return &[0]build_tool_version{};
            const data = lc.data[@sizeOf(build_version_command)..];
            const tools = @as([*]align(1) const build_tool_version, @ptrCast(data.ptr))[0..ntools];
            return tools;
        }
    };

    pub fn next(it: *LoadCommandIterator) ?LoadCommand {
        if (it.index >= it.ncmds) return null;

        const hdr = @as(*align(1) const load_command, @ptrCast(it.buffer.ptr)).*;
        const cmd = LoadCommand{
            .hdr = hdr,
            .data = it.buffer[0..hdr.cmdsize],
        };

        it.buffer = it.buffer[hdr.cmdsize..];
        it.index += 1;

        return cmd;
    }
};

pub const compact_unwind_encoding_t = u32;

// Relocatable object files: __LD,__compact_unwind

pub const compact_unwind_entry = extern struct {
    rangeStart: u64,
    rangeLength: u32,
    compactUnwindEncoding: u32,
    personalityFunction: u64,
    lsda: u64,
};

// Final linked images: __TEXT,__unwind_info
// The __TEXT,__unwind_info section is laid out for an efficient two level lookup.
// The header of the section contains a coarse index that maps function address
// to the page (4096 byte block) containing the unwind info for that function.

pub const UNWIND_SECTION_VERSION = 1;

pub const unwind_info_section_header = extern struct {
    /// UNWIND_SECTION_VERSION
    version: u32 = UNWIND_SECTION_VERSION,
    commonEncodingsArraySectionOffset: u32,
    commonEncodingsArrayCount: u32,
    personalityArraySectionOffset: u32,
    personalityArrayCount: u32,
    indexSectionOffset: u32,
    indexCount: u32,
    // compact_unwind_encoding_t[]
    // uint32_t personalities[]
    // unwind_info_section_header_index_entry[]
    // unwind_info_section_header_lsda_index_entry[]
};

pub const unwind_info_section_header_index_entry = extern struct {
    functionOffset: u32,

    /// section offset to start of regular or compress page
    secondLevelPagesSectionOffset: u32,

    /// section offset to start of lsda_index array for this range
    lsdaIndexArraySectionOffset: u32,
};

pub const unwind_info_section_header_lsda_index_entry = extern struct {
    functionOffset: u32,
    lsdaOffset: u32,
};

// There are two kinds of second level index pages: regular and compressed.
// A compressed page can hold up to 1021 entries, but it cannot be used if
// too many different encoding types are used. The regular page holds 511
// entries.

pub const unwind_info_regular_second_level_entry = extern struct {
    functionOffset: u32,
    encoding: compact_unwind_encoding_t,
};

pub const UNWIND_SECOND_LEVEL = enum(u32) {
    REGULAR = 2,
    COMPRESSED = 3,
    _,
};

pub const unwind_info_regular_second_level_page_header = extern struct {
    /// UNWIND_SECOND_LEVEL_REGULAR
    kind: UNWIND_SECOND_LEVEL = .REGULAR,

    entryPageOffset: u16,
    entryCount: u16,
    // entry array
};

pub const unwind_info_compressed_second_level_page_header = extern struct {
    /// UNWIND_SECOND_LEVEL_COMPRESSED
    kind: UNWIND_SECOND_LEVEL = .COMPRESSED,

    entryPageOffset: u16,
    entryCount: u16,
    encodingsPageOffset: u16,
    encodingsCount: u16,
    // 32bit entry array
    // encodings array
};

pub const UnwindInfoCompressedEntry = packed struct {
    funcOffset: u24,
    encodingIndex: u8,
};

pub const UNWIND_IS_NOT_FUNCTION_START: u32 = 0x80000000;
pub const UNWIND_HAS_LSDA: u32 = 0x40000000;
pub const UNWIND_PERSONALITY_MASK: u32 = 0x30000000;

// x86_64
pub const UNWIND_X86_64_MODE_MASK: u32 = 0x0F000000;
pub const UNWIND_X86_64_MODE = enum(u4) {
    OLD = 0,
    RBP_FRAME = 1,
    STACK_IMMD = 2,
    STACK_IND = 3,
    DWARF = 4,
};
pub const UNWIND_X86_64_RBP_FRAME_REGISTERS: u32 = 0x00007FFF;
pub const UNWIND_X86_64_RBP_FRAME_OFFSET: u32 = 0x00FF0000;

pub const UNWIND_X86_64_FRAMELESS_STACK_SIZE: u32 = 0x00FF0000;
pub const UNWIND_X86_64_FRAMELESS_STACK_ADJUST: u32 = 0x0000E000;
pub const UNWIND_X86_64_FRAMELESS_STACK_REG_COUNT: u32 = 0x00001C00;
pub const UNWIND_X86_64_FRAMELESS_STACK_REG_PERMUTATION: u32 = 0x000003FF;

pub const UNWIND_X86_64_DWARF_SECTION_OFFSET: u32 = 0x00FFFFFF;

pub const UNWIND_X86_64_REG = enum(u3) {
    NONE = 0,
    RBX = 1,
    R12 = 2,
    R13 = 3,
    R14 = 4,
    R15 = 5,
    RBP = 6,
};

// arm64
pub const UNWIND_ARM64_MODE_MASK: u32 = 0x0F000000;
pub const UNWIND_ARM64_MODE = enum(u4) {
    OLD = 0,
    FRAMELESS = 2,
    DWARF = 3,
    FRAME = 4,
};

pub const UNWIND_ARM64_FRAME_X19_X20_PAIR: u32 = 0x00000001;
pub const UNWIND_ARM64_FRAME_X21_X22_PAIR: u32 = 0x00000002;
pub const UNWIND_ARM64_FRAME_X23_X24_PAIR: u32 = 0x00000004;
pub const UNWIND_ARM64_FRAME_X25_X26_PAIR: u32 = 0x00000008;
pub const UNWIND_ARM64_FRAME_X27_X28_PAIR: u32 = 0x00000010;
pub const UNWIND_ARM64_FRAME_D8_D9_PAIR: u32 = 0x00000100;
pub const UNWIND_ARM64_FRAME_D10_D11_PAIR: u32 = 0x00000200;
pub const UNWIND_ARM64_FRAME_D12_D13_PAIR: u32 = 0x00000400;
pub const UNWIND_ARM64_FRAME_D14_D15_PAIR: u32 = 0x00000800;

pub const UNWIND_ARM64_FRAMELESS_STACK_SIZE_MASK: u32 = 0x00FFF000;
pub const UNWIND_ARM64_DWARF_SECTION_OFFSET: u32 = 0x00FFFFFF;

pub const CompactUnwindEncoding = packed struct(u32) {
    value: packed union {
        x86_64: packed union {
            frame: packed struct(u24) {
                reg4: u3,
                reg3: u3,
                reg2: u3,
                reg1: u3,
                reg0: u3,
                unused: u1 = 0,
                frame_offset: u8,
            },
            frameless: packed struct(u24) {
                stack_reg_permutation: u10,
                stack_reg_count: u3,
                stack: packed union {
                    direct: packed struct(u11) {
                        _: u3,
                        stack_size: u8,
                    },
                    indirect: packed struct(u11) {
                        stack_adjust: u3,
                        sub_offset: u8,
                    },
                },
            },
            dwarf: u24,
        },
        arm64: packed union {
            frame: packed struct(u24) {
                x_reg_pairs: packed struct(u5) {
                    x19_x20: u1,
                    x21_x22: u1,
                    x23_x24: u1,
                    x25_x26: u1,
                    x27_x28: u1,
                },
                d_reg_pairs: packed struct(u4) {
                    d8_d9: u1,
                    d10_d11: u1,
                    d12_d13: u1,
                    d14_d15: u1,
                },
                _: u15,
            },
            frameless: packed struct(u24) {
                _: u12 = 0,
                stack_size: u12,
            },
            dwarf: u24,
        },
    },
    mode: packed union {
        x86_64: UNWIND_X86_64_MODE,
        arm64: UNWIND_ARM64_MODE,
    },
    personality_index: u2,
    has_lsda: u1,
    start: u1,
};
const builtin = @import("builtin");
const std = @import("std.zig");
const float = @import("math/float.zig");
const assert = std.debug.assert;
const mem = std.mem;
const testing = std.testing;
const Alignment = std.mem.Alignment;

/// Euler's number (e)
pub const e = 2.71828182845904523536028747135266249775724709369995;

/// Archimedes' constant (π)
pub const pi = 3.14159265358979323846264338327950288419716939937510;

/// Phi or Golden ratio constant (Φ) = (1 + sqrt(5))/2
pub const phi = 1.6180339887498948482045868343656381177203091798057628621;

/// Circle constant (τ)
pub const tau = 2 * pi;

/// log2(e)
pub const log2e = 1.442695040888963407359924681001892137;

/// log10(e)
pub const log10e = 0.434294481903251827651128918916605082;

/// ln(2)
pub const ln2 = 0.693147180559945309417232121458176568;

/// ln(10)
pub const ln10 = 2.302585092994045684017991454684364208;

/// 2/sqrt(π)
pub const two_sqrtpi = 1.128379167095512573896158903121545172;

/// sqrt(2)
pub const sqrt2 = 1.414213562373095048801688724209698079;

/// 1/sqrt(2)
pub const sqrt1_2 = 0.707106781186547524400844362104849039;

/// pi/180.0
pub const rad_per_deg = 0.0174532925199432957692369076848861271344287188854172545609719144;

/// 180.0/pi
pub const deg_per_rad = 57.295779513082320876798154814105170332405472466564321549160243861;

pub const floatExponentBits = float.floatExponentBits;
pub const floatMantissaBits = float.floatMantissaBits;
pub const floatFractionalBits = float.floatFractionalBits;
pub const floatExponentMin = float.floatExponentMin;
pub const floatExponentMax = float.floatExponentMax;
pub const floatTrueMin = float.floatTrueMin;
pub const floatMin = float.floatMin;
pub const floatMax = float.floatMax;
pub const floatEps = float.floatEps;
pub const floatEpsAt = float.floatEpsAt;
pub const inf = float.inf;
pub const nan = float.nan;
pub const snan = float.snan;

/// Performs an approximate comparison of two floating point values `x` and `y`.
/// Returns true if the absolute difference between them is less or equal than
/// the specified tolerance.
///
/// The `tolerance` parameter is the absolute tolerance used when determining if
/// the two numbers are close enough; a good value for this parameter is a small
/// multiple of `floatEps(T)`.
///
/// Note that this function is recommended for comparing small numbers
/// around zero; using `approxEqRel` is suggested otherwise.
///
/// NaN values are never considered equal to any value.
pub fn approxEqAbs(comptime T: type, x: T, y: T, tolerance: T) bool {
    assert(@typeInfo(T) == .float or @typeInfo(T) == .comptime_float);
    assert(tolerance >= 0);

    // Fast path for equal values (and signed zeros and infinites).
    if (x == y)
        return true;

    if (isNan(x) or isNan(y))
        return false;

    return @abs(x - y) <= tolerance;
}

/// Performs an approximate comparison of two floating point values `x` and `y`.
/// Returns true if the absolute difference between them is less or equal than
/// `max(|x|, |y|) * tolerance`, where `tolerance` is a positive number greater
/// than zero.
///
/// The `tolerance` parameter is the relative tolerance used when determining if
/// the two numbers are close enough; a good value for this parameter is usually
/// `sqrt(floatEps(T))`, meaning that the two numbers are considered equal if at
/// least half of the digits are equal.
///
/// Note that for comparisons of small numbers around zero this function won't
/// give meaningful results, use `approxEqAbs` instead.
///
/// NaN values are never considered equal to any value.
pub fn approxEqRel(comptime T: type, x: T, y: T, tolerance: T) bool {
    assert(@typeInfo(T) == .float or @typeInfo(T) == .comptime_float);
    assert(tolerance > 0);

    // Fast path for equal values (and signed zeros and infinites).
    if (x == y)
        return true;

    if (isNan(x) or isNan(y))
        return false;

    return @abs(x - y) <= @max(@abs(x), @abs(y)) * tolerance;
}

test approxEqAbs {
    inline for ([_]type{ f16, f32, f64, f128 }) |T| {
        const eps_value = comptime floatEps(T);
        const min_value = comptime floatMin(T);

        try testing.expect(approxEqAbs(T, 0.0, 0.0, eps_value));
        try testing.expect(approxEqAbs(T, -0.0, -0.0, eps_value));
        try testing.expect(approxEqAbs(T, 0.0, -0.0, eps_value));
        try testing.expect(!approxEqAbs(T, 1.0 + 2 * eps_value, 1.0, eps_value));
        try testing.expect(approxEqAbs(T, 1.0 + 1 * eps_value, 1.0, eps_value));
        try testing.expect(approxEqAbs(T, min_value, 0.0, eps_value * 2));
        try testing.expect(approxEqAbs(T, -min_value, 0.0, eps_value * 2));
    }

    comptime {
        // `comptime_float` is guaranteed to have the same precision and operations of
        // the largest other floating point type, which is f128 but it doesn't have a
        // defined layout so we can't rely on `@bitCast` to construct the smallest
        // possible epsilon value like we do in the tests above. In the same vein, we
        // also can't represent a max/min, `NaN` or `Inf` values.
        const eps_value = 1e-4;

        try testing.expect(approxEqAbs(comptime_float, 0.0, 0.0, eps_value));
        try testing.expect(approxEqAbs(comptime_float, -0.0, -0.0, eps_value));
        try testing.expect(approxEqAbs(comptime_float, 0.0, -0.0, eps_value));
        try testing.expect(!approxEqAbs(comptime_float, 1.0 + 2 * eps_value, 1.0, eps_value));
        try testing.expect(approxEqAbs(comptime_float, 1.0 + 1 * eps_value, 1.0, eps_value));
    }
}

test approxEqRel {
    inline for ([_]type{ f16, f32, f64, f128 }) |T| {
        const eps_value = comptime floatEps(T);
        const sqrt_eps_value = comptime sqrt(eps_value);
        const nan_value = comptime nan(T);
        const inf_value = comptime inf(T);
        const min_value = comptime floatMin(T);

        try testing.expect(approxEqRel(T, 1.0, 1.0, sqrt_eps_value));
        try testing.expect(!approxEqRel(T, 1.0, 0.0, sqrt_eps_value));
        try testing.expect(!approxEqRel(T, 1.0, nan_value, sqrt_eps_value));
        try testing.expect(!approxEqRel(T, nan_value, nan_value, sqrt_eps_value));
        try testing.expect(approxEqRel(T, inf_value, inf_value, sqrt_eps_value));
        try testing.expect(approxEqRel(T, min_value, min_value, sqrt_eps_value));
        try testing.expect(approxEqRel(T, -min_value, -min_value, sqrt_eps_value));
    }

    comptime {
        // `comptime_float` is guaranteed to have the same precision and operations of
        // the largest other floating point type, which is f128 but it doesn't have a
        // defined layout so we can't rely on `@bitCast` to construct the smallest
        // possible epsilon value like we do in the tests above. In the same vein, we
        // also can't represent a max/min, `NaN` or `Inf` values.
        const eps_value = 1e-4;
        const sqrt_eps_value = sqrt(eps_value);

        try testing.expect(approxEqRel(comptime_float, 1.0, 1.0, sqrt_eps_value));
        try testing.expect(!approxEqRel(comptime_float, 1.0, 0.0, sqrt_eps_value));
    }
}

pub fn raiseInvalid() void {
    // Raise INVALID fpu exception
}

pub fn raiseUnderflow() void {
    // Raise UNDERFLOW fpu exception
}

pub fn raiseOverflow() void {
    // Raise OVERFLOW fpu exception
}

pub fn raiseInexact() void {
    // Raise INEXACT fpu exception
}

pub fn raiseDivByZero() void {
    // Raise INEXACT fpu exception
}

pub const isNan = @import("math/isnan.zig").isNan;
pub const isSignalNan = @import("math/isnan.zig").isSignalNan;
pub const frexp = @import("math/frexp.zig").frexp;
pub const Frexp = @import("math/frexp.zig").Frexp;
pub const modf = @import("math/modf.zig").modf;
pub const Modf = @import("math/modf.zig").Modf;
pub const copysign = @import("math/copysign.zig").copysign;
pub const isFinite = @import("math/isfinite.zig").isFinite;
pub const isInf = @import("math/isinf.zig").isInf;
pub const isPositiveInf = @import("math/isinf.zig").isPositiveInf;
pub const isNegativeInf = @import("math/isinf.zig").isNegativeInf;
pub const isPositiveZero = @import("math/iszero.zig").isPositiveZero;
pub const isNegativeZero = @import("math/iszero.zig").isNegativeZero;
pub const isNormal = @import("math/isnormal.zig").isNormal;
pub const nextAfter = @import("math/nextafter.zig").nextAfter;
pub const signbit = @import("math/signbit.zig").signbit;
pub const scalbn = @import("math/scalbn.zig").scalbn;
pub const ldexp = @import("math/ldexp.zig").ldexp;
pub const pow = @import("math/pow.zig").pow;
pub const powi = @import("math/powi.zig").powi;
pub const sqrt = @import("math/sqrt.zig").sqrt;
pub const cbrt = @import("math/cbrt.zig").cbrt;
pub const acos = @import("math/acos.zig").acos;
pub const asin = @import("math/asin.zig").asin;
pub const atan = @import("math/atan.zig").atan;
pub const atan2 = @import("math/atan2.zig").atan2;
pub const hypot = @import("math/hypot.zig").hypot;
pub const expm1 = @import("math/expm1.zig").expm1;
pub const ilogb = @import("math/ilogb.zig").ilogb;
pub const log = @import("math/log.zig").log;
pub const log2 = @import("math/log2.zig").log2;
pub const log10 = @import("math/log10.zig").log10;
pub const log10_int = @import("math/log10.zig").log10_int;
pub const log_int = @import("math/log_int.zig").log_int;
pub const log1p = @import("math/log1p.zig").log1p;
pub const asinh = @import("math/asinh.zig").asinh;
pub const acosh = @import("math/acosh.zig").acosh;
pub const atanh = @import("math/atanh.zig").atanh;
pub const sinh = @import("math/sinh.zig").sinh;
pub const cosh = @import("math/cosh.zig").cosh;
pub const tanh = @import("math/tanh.zig").tanh;
pub const gcd = @import("math/gcd.zig").gcd;
pub const lcm = @import("math/lcm.zig").lcm;
pub const gamma = @import("math/gamma.zig").gamma;
pub const lgamma = @import("math/gamma.zig").lgamma;

/// Sine trigonometric function on a floating point number.
/// Uses a dedicated hardware instruction when available.
/// This is the same as calling the builtin @sin
pub inline fn sin(value: anytype) @TypeOf(value) {
    return @sin(value);
}

/// Cosine trigonometric function on a floating point number.
/// Uses a dedicated hardware instruction when available.
/// This is the same as calling the builtin @cos
pub inline fn cos(value: anytype) @TypeOf(value) {
    return @cos(value);
}

/// Tangent trigonometric function on a floating point number.
/// Uses a dedicated hardware instruction when available.
/// This is the same as calling the builtin @tan
pub inline fn tan(value: anytype) @TypeOf(value) {
    return @tan(value);
}

/// Converts an angle in radians to degrees. T must be a float or comptime number or a vector of floats.
pub fn radiansToDegrees(ang: anytype) if (@TypeOf(ang) == comptime_int) comptime_float else @TypeOf(ang) {
    const T = @TypeOf(ang);
    switch (@typeInfo(T)) {
        .float, .comptime_float, .comptime_int => return ang * deg_per_rad,
        .vector => |V| if (@typeInfo(V.child) == .float) return ang * @as(T, @splat(deg_per_rad)),
        else => {},
    }
    @compileError("Input must be float or a comptime number, or a vector of floats.");
}

test radiansToDegrees {
    const zero: f32 = 0;
    const half_pi: f32 = pi / 2.0;
    const neg_quart_pi: f32 = -pi / 4.0;
    const one_pi: f32 = pi;
    const two_pi: f32 = 2.0 * pi;
    try std.testing.expectApproxEqAbs(@as(f32, 0), radiansToDegrees(zero), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 90), radiansToDegrees(half_pi), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, -45), radiansToDegrees(neg_quart_pi), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 180), radiansToDegrees(one_pi), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 360), radiansToDegrees(two_pi), 1e-6);

    const result = radiansToDegrees(@Vector(4, f32){
        half_pi,
        neg_quart_pi,
        one_pi,
        two_pi,
    });
    try std.testing.expectApproxEqAbs(@as(f32, 90), result[0], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, -45), result[1], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 180), result[2], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 360), result[3], 1e-6);
}

/// Converts an angle in degrees to radians. T must be a float or comptime number or a vector of floats.
pub fn degreesToRadians(ang: anytype) if (@TypeOf(ang) == comptime_int) comptime_float else @TypeOf(ang) {
    const T = @TypeOf(ang);
    switch (@typeInfo(T)) {
        .float, .comptime_float, .comptime_int => return ang * rad_per_deg,
        .vector => |V| if (@typeInfo(V.child) == .float) return ang * @as(T, @splat(rad_per_deg)),
        else => {},
    }
    @compileError("Input must be float or a comptime number, or a vector of floats.");
}

test degreesToRadians {
    const ninety: f32 = 90;
    const neg_two_seventy: f32 = -270;
    const three_sixty: f32 = 360;
    try std.testing.expectApproxEqAbs(@as(f32, pi / 2.0), degreesToRadians(ninety), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, -3 * pi / 2.0), degreesToRadians(neg_two_seventy), 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 2 * pi), degreesToRadians(three_sixty), 1e-6);

    const result = degreesToRadians(@Vector(3, f32){
        ninety,
        neg_two_seventy,
        three_sixty,
    });
    try std.testing.expectApproxEqAbs(@as(f32, pi / 2.0), result[0], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, -3 * pi / 2.0), result[1], 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, 2 * pi), result[2], 1e-6);
}

/// Base-e exponential function on a floating point number.
/// Uses a dedicated hardware instruction when available.
/// This is the same as calling the builtin @exp
pub inline fn exp(value: anytype) @TypeOf(value) {
    return @exp(value);
}

/// Base-2 exponential function on a floating point number.
/// Uses a dedicated hardware instruction when available.
/// This is the same as calling the builtin @exp2
pub inline fn exp2(value: anytype) @TypeOf(value) {
    return @exp2(value);
}

pub const complex = @import("math/complex.zig");
pub const Complex = complex.Complex;

pub const big = @import("math/big.zig");

test {
    _ = floatExponentBits;
    _ = floatMantissaBits;
    _ = floatFractionalBits;
    _ = floatExponentMin;
    _ = floatExponentMax;
    _ = floatTrueMin;
    _ = floatMin;
    _ = floatMax;
    _ = floatEps;
    _ = inf;
    _ = nan;
    _ = snan;
    _ = isNan;
    _ = isSignalNan;
    _ = frexp;
    _ = Frexp;
    _ = modf;
    _ = Modf;
    _ = copysign;
    _ = isFinite;
    _ = isInf;
    _ = isPositiveInf;
    _ = isNegativeInf;
    _ = isNormal;
    _ = nextAfter;
    _ = signbit;
    _ = scalbn;
    _ = ldexp;
    _ = pow;
    _ = powi;
    _ = sqrt;
    _ = cbrt;
    _ = acos;
    _ = asin;
    _ = atan;
    _ = atan2;
    _ = hypot;
    _ = expm1;
    _ = ilogb;
    _ = log;
    _ = log2;
    _ = log10;
    _ = log10_int;
    _ = log_int;
    _ = log1p;
    _ = asinh;
    _ = acosh;
    _ = atanh;
    _ = sinh;
    _ = cosh;
    _ = tanh;
    _ = gcd;
    _ = lcm;
    _ = gamma;
    _ = lgamma;

    _ = complex;
    _ = Complex;

    _ = big;
}

/// Given two types, returns the smallest one which is capable of holding the
/// full range of the minimum value.
pub fn Min(comptime A: type, comptime B: type) type {
    switch (@typeInfo(A)) {
        .int => |a_info| switch (@typeInfo(B)) {
            .int => |b_info| if (a_info.signedness == .unsigned and b_info.signedness == .unsigned) {
                if (a_info.bits < b_info.bits) {
                    return A;
                } else {
                    return B;
                }
            },
            else => {},
        },
        else => {},
    }
    return @TypeOf(@as(A, 0) + @as(B, 0));
}

/// Odd sawtooth function
/// ```
///         |
///      /  | /    /
///     /   |/    /
///  --/----/----/--
///   /    /|   /
///  /    / |  /
///         |
/// ```
/// Limit x to the half-open interval [-r, r).
pub fn wrap(x: anytype, r: anytype) @TypeOf(x) {
    const info_x = @typeInfo(@TypeOf(x));
    const info_r = @typeInfo(@TypeOf(r));
    if (info_x == .int and info_x.int.signedness != .signed) {
        @compileError("x must be floating point, comptime integer, or signed integer.");
    }
    switch (info_r) {
        .int => {
            // in the rare usecase of r not being comptime_int or float,
            // take the penalty of having an intermediary type conversion,
            // otherwise the alternative is to unwind iteratively to avoid overflow
            const R = comptime do: {
                var info = info_r;
                info.int.bits += 1;
                info.int.signedness = .signed;
                break :do @Type(info);
            };
            const radius: if (info_r.int.signedness == .signed) @TypeOf(r) else R = r;
            return @intCast(@mod(x - radius, 2 * @as(R, r)) - r); // provably impossible to overflow
        },
        else => {
            return @mod(x - r, 2 * r) - r;
        },
    }
}
test wrap {
    // Within range
    try testing.expect(wrap(@as(i32, -75), @as(i32, 180)) == -75);
    try testing.expect(wrap(@as(i32, -75), @as(i32, -180)) == -75);
    // Below
    try testing.expect(wrap(@as(i32, -225), @as(i32, 180)) == 135);
    try testing.expect(wrap(@as(i32, -225), @as(i32, -180)) == 135);
    // Above
    try testing.expect(wrap(@as(i32, 361), @as(i32, 180)) == 1);
    try testing.expect(wrap(@as(i32, 361), @as(i32, -180)) == 1);

    // One period, right limit, positive r
    try testing.expect(wrap(@as(i32, 180), @as(i32, 180)) == -180);
    // One period, left limit, positive r
    try testing.expect(wrap(@as(i32, -180), @as(i32, 180)) == -180);
    // One period, right limit, negative r
    try testing.expect(wrap(@as(i32, 180), @as(i32, -180)) == 180);
    // One period, left limit, negative r
    try testing.expect(wrap(@as(i32, -180), @as(i32, -180)) == 180);

    // Two periods, right limit, positive r
    try testing.expect(wrap(@as(i32, 540), @as(i32, 180)) == -180);
    // Two periods, left limit, positive r
    try testing.expect(wrap(@as(i32, -540), @as(i32, 180)) == -180);
    // Two periods, right limit, negative r
    try testing.expect(wrap(@as(i32, 540), @as(i32, -180)) == 180);
    // Two periods, left limit, negative r
    try testing.expect(wrap(@as(i32, -540), @as(i32, -180)) == 180);

    // Floating point
    try testing.expect(wrap(@as(f32, 1.125), @as(f32, 1.0)) == -0.875);
    try testing.expect(wrap(@as(f32, -127.5), @as(f32, 180)) == -127.5);

    // Mix of comptime and non-comptime
    var i: i32 = 1;
    _ = &i;
    try testing.expect(wrap(i, 10) == 1);

    const limit: i32 = 180;
    // Within range
    try testing.expect(wrap(@as(i32, -75), limit) == -75);
    // Below
    try testing.expect(wrap(@as(i32, -225), limit) == 135);
    // Above
    try testing.expect(wrap(@as(i32, 361), limit) == 1);
}

/// Odd ramp function
/// ```
///         |  _____
///         | /
///         |/
///  -------/-------
///        /|
///  _____/ |
///         |
/// ```
/// Limit val to the inclusive range [lower, upper].
pub fn clamp(val: anytype, lower: anytype, upper: anytype) @TypeOf(val, lower, upper) {
    const T = @TypeOf(val, lower, upper);
    switch (@typeInfo(T)) {
        .int, .float, .comptime_int, .comptime_float => assert(lower <= upper),
        .vector => |vinfo| switch (@typeInfo(vinfo.child)) {
            .int, .float => assert(@reduce(.And, lower <= upper)),
            else => @compileError("Expected vector of ints or floats, found " ++ @typeName(T)),
        },
        else => @compileError("Expected an int, float or vector of one, found " ++ @typeName(T)),
    }
    return @max(lower, @min(val, upper));
}
test clamp {
    // Within range
    try testing.expect(std.math.clamp(@as(i32, -1), @as(i32, -4), @as(i32, 7)) == -1);
    // Below
    try testing.expect(std.math.clamp(@as(i32, -5), @as(i32, -4), @as(i32, 7)) == -4);
    // Above
    try testing.expect(std.math.clamp(@as(i32, 8), @as(i32, -4), @as(i32, 7)) == 7);

    // Floating point
    try testing.expect(std.math.clamp(@as(f32, 1.1), @as(f32, 0.0), @as(f32, 1.0)) == 1.0);
    try testing.expect(std.math.clamp(@as(f32, -127.5), @as(f32, -200), @as(f32, -100)) == -127.5);

    // Vector
    try testing.expect(@reduce(.And, std.math.clamp(@as(@Vector(3, f32), .{ 1.4, 15.23, 28.3 }), @as(@Vector(3, f32), .{ 9.8, 13.2, 15.6 }), @as(@Vector(3, f32), .{ 15.2, 22.8, 26.3 })) == @as(@Vector(3, f32), .{ 9.8, 15.23, 26.3 })));

    // Mix of comptime and non-comptime
    var i: i32 = 1;
    _ = &i;
    try testing.expect(std.math.clamp(i, 0, 1) == 1);
}

/// Returns the product of a and b. Returns an error on overflow.
pub fn mul(comptime T: type, a: T, b: T) (error{Overflow}!T) {
    if (T == comptime_int) return a * b;
    const ov = @mulWithOverflow(a, b);
    if (ov[1] != 0) return error.Overflow;
    return ov[0];
}

/// Returns the sum of a and b. Returns an error on overflow.
pub fn add(comptime T: type, a: T, b: T) (error{Overflow}!T) {
    if (T == comptime_int) return a + b;
    const ov = @addWithOverflow(a, b);
    if (ov[1] != 0) return error.Overflow;
    return ov[0];
}

/// Returns a - b, or an error on overflow.
pub fn sub(comptime T: type, a: T, b: T) (error{Overflow}!T) {
    if (T == comptime_int) return a - b;
    const ov = @subWithOverflow(a, b);
    if (ov[1] != 0) return error.Overflow;
    return ov[0];
}

pub fn negate(x: anytype) !@TypeOf(x) {
    return sub(@TypeOf(x), 0, x);
}

/// Shifts a left by shift_amt. Returns an error on overflow. shift_amt
/// is unsigned.
pub fn shlExact(comptime T: type, a: T, shift_amt: Log2Int(T)) !T {
    if (T == comptime_int) return a << shift_amt;
    const ov = @shlWithOverflow(a, shift_amt);
    if (ov[1] != 0) return error.Overflow;
    return ov[0];
}

/// Shifts left. Overflowed bits are truncated.
/// A negative shift amount results in a right shift.
pub fn shl(comptime T: type, a: T, shift_amt: anytype) T {
    const abs_shift_amt = @abs(shift_amt);

    const casted_shift_amt = blk: {
        if (@typeInfo(T) == .vector) {
            const C = @typeInfo(T).vector.child;
            const len = @typeInfo(T).vector.len;
            if (abs_shift_amt >= @typeInfo(C).int.bits) return @splat(0);
            break :blk @as(@Vector(len, Log2Int(C)), @splat(@as(Log2Int(C), @intCast(abs_shift_amt))));
        } else {
            if (abs_shift_amt >= @typeInfo(T).int.bits) return 0;
            break :blk @as(Log2Int(T), @intCast(abs_shift_amt));
        }
    };

    if (@TypeOf(shift_amt) == comptime_int or @typeInfo(@TypeOf(shift_amt)).int.signedness == .signed) {
        if (shift_amt < 0) {
            return a >> casted_shift_amt;
        }
    }

    return a << casted_shift_amt;
}

test shl {
    try testing.expect(shl(u8, 0b11111111, @as(usize, 3)) == 0b11111000);
    try testing.expect(shl(u8, 0b11111111, @as(usize, 8)) == 0);
    try testing.expect(shl(u8, 0b11111111, @as(usize, 9)) == 0);
    try testing.expect(shl(u8, 0b11111111, @as(isize, -2)) == 0b00111111);
    try testing.expect(shl(u8, 0b11111111, 3) == 0b11111000);
    try testing.expect(shl(u8, 0b11111111, 8) == 0);
    try testing.expect(shl(u8, 0b11111111, 9) == 0);
    try testing.expect(shl(u8, 0b11111111, -2) == 0b00111111);
    try testing.expect(shl(@Vector(1, u32), @Vector(1, u32){42}, @as(usize, 1))[0] == @as(u32, 42) << 1);
    try testing.expect(shl(@Vector(1, u32), @Vector(1, u32){42}, @as(isize, -1))[0] == @as(u32, 42) >> 1);
    try testing.expect(shl(@Vector(1, u32), @Vector(1, u32){42}, 33)[0] == 0);
}

/// Shifts right. Overflowed bits are truncated.
/// A negative shift amount results in a left shift.
pub fn shr(comptime T: type, a: T, shift_amt: anytype) T {
    const abs_shift_amt = @abs(shift_amt);

    const casted_shift_amt = blk: {
        if (@typeInfo(T) == .vector) {
            const C = @typeInfo(T).vector.child;
            const len = @typeInfo(T).vector.len;
            if (abs_shift_amt >= @typeInfo(C).int.bits) return @splat(0);
            break :blk @as(@Vector(len, Log2Int(C)), @splat(@as(Log2Int(C), @intCast(abs_shift_amt))));
        } else {
            if (abs_shift_amt >= @typeInfo(T).int.bits) return 0;
            break :blk @as(Log2Int(T), @intCast(abs_shift_amt));
        }
    };

    if (@TypeOf(shift_amt) == comptime_int or @typeInfo(@TypeOf(shift_amt)).int.signedness == .signed) {
        if (shift_amt < 0) {
            return a << casted_shift_amt;
        }
    }

    return a >> casted_shift_amt;
}

test shr {
    try testing.expect(shr(u8, 0b11111111, @as(usize, 3)) == 0b00011111);
    try testing.expect(shr(u8, 0b11111111, @as(usize, 8)) == 0);
    try testing.expect(shr(u8, 0b11111111, @as(usize, 9)) == 0);
    try testing.expect(shr(u8, 0b11111111, @as(isize, -2)) == 0b11111100);
    try testing.expect(shr(u8, 0b11111111, 3) == 0b00011111);
    try testing.expect(shr(u8, 0b11111111, 8) == 0);
    try testing.expect(shr(u8, 0b11111111, 9) == 0);
    try testing.expect(shr(u8, 0b11111111, -2) == 0b11111100);
    try testing.expect(shr(@Vector(1, u32), @Vector(1, u32){42}, @as(usize, 1))[0] == @as(u32, 42) >> 1);
    try testing.expect(shr(@Vector(1, u32), @Vector(1, u32){42}, @as(isize, -1))[0] == @as(u32, 42) << 1);
    try testing.expect(shr(@Vector(1, u32), @Vector(1, u32){42}, 33)[0] == 0);
}

/// Rotates right. Only unsigned values can be rotated.  Negative shift
/// values result in shift modulo the bit count.
pub fn rotr(comptime T: type, x: T, r: anytype) T {
    if (@typeInfo(T) == .vector) {
        const C = @typeInfo(T).vector.child;
        if (C == u0) return 0;

        if (@typeInfo(C).int.signedness == .signed) {
            @compileError("cannot rotate signed integers");
        }
        const ar: Log2Int(C) = @intCast(@mod(r, @typeInfo(C).int.bits));
        return (x >> @splat(ar)) | (x << @splat(1 + ~ar));
    } else if (@typeInfo(T).int.signedness == .signed) {
        @compileError("cannot rotate signed integer");
    } else {
        if (T == u0) return 0;

        if (comptime isPowerOfTwo(@typeInfo(T).int.bits)) {
            const ar: Log2Int(T) = @intCast(@mod(r, @typeInfo(T).int.bits));
            return x >> ar | x << (1 +% ~ar);
        } else {
            const ar = @mod(r, @typeInfo(T).int.bits);
            return shr(T, x, ar) | shl(T, x, @typeInfo(T).int.bits - ar);
        }
    }
}

test rotr {
    try testing.expect(rotr(u0, 0b0, @as(usize, 3)) == 0b0);
    try testing.expect(rotr(u5, 0b00001, @as(usize, 0)) == 0b00001);
    try testing.expect(rotr(u6, 0b000001, @as(usize, 7)) == 0b100000);
    try testing.expect(rotr(u8, 0b00000001, @as(usize, 0)) == 0b00000001);
    try testing.expect(rotr(u8, 0b00000001, @as(usize, 9)) == 0b10000000);
    try testing.expect(rotr(u8, 0b00000001, @as(usize, 8)) == 0b00000001);
    try testing.expect(rotr(u8, 0b00000001, @as(usize, 4)) == 0b00010000);
    try testing.expect(rotr(u8, 0b00000001, @as(isize, -1)) == 0b00000010);
    try testing.expect(rotr(u12, 0o7777, 1) == 0o7777);
    try testing.expect(rotr(@Vector(1, u32), @Vector(1, u32){1}, @as(usize, 1))[0] == @as(u32, 1) << 31);
    try testing.expect(rotr(@Vector(1, u32), @Vector(1, u32){1}, @as(isize, -1))[0] == @as(u32, 1) << 1);
}

/// Rotates left. Only unsigned values can be rotated.  Negative shift
/// values result in shift modulo the bit count.
pub fn rotl(comptime T: type, x: T, r: anytype) T {
    if (@typeInfo(T) == .vector) {
        const C = @typeInfo(T).vector.child;
        if (C == u0) return 0;

        if (@typeInfo(C).int.signedness == .signed) {
            @compileError("cannot rotate signed integers");
        }
        const ar: Log2Int(C) = @intCast(@mod(r, @typeInfo(C).int.bits));
        return (x << @splat(ar)) | (x >> @splat(1 +% ~ar));
    } else if (@typeInfo(T).int.signedness == .signed) {
        @compileError("cannot rotate signed integer");
    } else {
        if (T == u0) return 0;

        if (comptime isPowerOfTwo(@typeInfo(T).int.bits)) {
            const ar: Log2Int(T) = @intCast(@mod(r, @typeInfo(T).int.bits));
            return x << ar | x >> 1 +% ~ar;
        } else {
            const ar = @mod(r, @typeInfo(T).int.bits);
            return shl(T, x, ar) | shr(T, x, @typeInfo(T).int.bits - ar);
        }
    }
}

test rotl {
    try testing.expect(rotl(u0, 0b0, @as(usize, 3)) == 0b0);
    try testing.expect(rotl(u5, 0b00001, @as(usize, 0)) == 0b00001);
    try testing.expect(rotl(u6, 0b000001, @as(usize, 7)) == 0b000010);
    try testing.expect(rotl(u8, 0b00000001, @as(usize, 0)) == 0b00000001);
    try testing.expect(rotl(u8, 0b00000001, @as(usize, 9)) == 0b00000010);
    try testing.expect(rotl(u8, 0b00000001, @as(usize, 8)) == 0b00000001);
    try testing.expect(rotl(u8, 0b00000001, @as(usize, 4)) == 0b00010000);
    try testing.expect(rotl(u8, 0b00000001, @as(isize, -1)) == 0b10000000);
    try testing.expect(rotl(u12, 0o7777, 1) == 0o7777);
    try testing.expect(rotl(@Vector(1, u32), @Vector(1, u32){1 << 31}, @as(usize, 1))[0] == 1);
    try testing.expect(rotl(@Vector(1, u32), @Vector(1, u32){1 << 31}, @as(isize, -1))[0] == @as(u32, 1) << 30);
}

/// Returns an unsigned int type that can hold the number of bits in T - 1.
/// Suitable for 0-based bit indices of T.
pub fn Log2Int(comptime T: type) type {
    // comptime ceil log2
    if (T == comptime_int) return comptime_int;
    const bits: u16 = @typeInfo(T).int.bits;
    const log2_bits = 16 - @clz(bits - 1);
    return std.meta.Int(.unsigned, log2_bits);
}

/// Returns an unsigned int type that can hold the number of bits in T.
pub fn Log2IntCeil(comptime T: type) type {
    // comptime ceil log2
    if (T == comptime_int) return comptime_int;
    const bits: u16 = @typeInfo(T).int.bits;
    const log2_bits = 16 - @clz(bits);
    return std.meta.Int(.unsigned, log2_bits);
}

/// Returns the smallest integer type that can hold both from and to.
pub fn IntFittingRange(comptime from: comptime_int, comptime to: comptime_int) type {
    assert(from <= to);
    if (from == 0 and to == 0) {
        return u0;
    }
    const signedness: std.builtin.Signedness = if (from < 0) .signed else .unsigned;
    const largest_positive_integer = @max(if (from < 0) (-from) - 1 else from, to); // two's complement
    const base = log2(largest_positive_integer);
    const upper = (1 << base) - 1;
    var magnitude_bits = if (upper >= largest_positive_integer) base else base + 1;
    if (signedness == .signed) {
        magnitude_bits += 1;
    }
    return std.meta.Int(signedness, magnitude_bits);
}

test IntFittingRange {
    try testing.expect(IntFittingRange(0, 0) == u0);
    try testing.expect(IntFittingRange(0, 1) == u1);
    try testing.expect(IntFittingRange(0, 2) == u2);
    try testing.expect(IntFittingRange(0, 3) == u2);
    try testing.expect(IntFittingRange(0, 4) == u3);
    try testing.expect(IntFittingRange(0, 7) == u3);
    try testing.expect(IntFittingRange(0, 8) == u4);
    try testing.expect(IntFittingRange(0, 9) == u4);
    try testing.expect(IntFittingRange(0, 15) == u4);
    try testing.expect(IntFittingRange(0, 16) == u5);
    try testing.expect(IntFittingRange(0, 17) == u5);
    try testing.expect(IntFittingRange(0, 4095) == u12);
    try testing.expect(IntFittingRange(2000, 4095) == u12);
    try testing.expect(IntFittingRange(0, 4096) == u13);
    try testing.expect(IntFittingRange(2000, 4096) == u13);
    try testing.expect(IntFittingRange(0, 4097) == u13);
    try testing.expect(IntFittingRange(2000, 4097) == u13);
    try testing.expect(IntFittingRange(0, 123456789123456798123456789) == u87);
    try testing.expect(IntFittingRange(0, 123456789123456798123456789123456789123456798123456789) == u177);

    try testing.expect(IntFittingRange(-1, -1) == i1);
    try testing.expect(IntFittingRange(-1, 0) == i1);
    try testing.expect(IntFittingRange(-1, 1) == i2);
    try testing.expect(IntFittingRange(-2, -2) == i2);
    try testing.expect(IntFittingRange(-2, -1) == i2);
    try testing.expect(IntFittingRange(-2, 0) == i2);
    try testing.expect(IntFittingRange(-2, 1) == i2);
    try testing.expect(IntFittingRange(-2, 2) == i3);
    try testing.expect(IntFittingRange(-1, 2) == i3);
    try testing.expect(IntFittingRange(-1, 3) == i3);
    try testing.expect(IntFittingRange(-1, 4) == i4);
    try testing.expect(IntFittingRange(-1, 7) == i4);
    try testing.expect(IntFittingRange(-1, 8) == i5);
    try testing.expect(IntFittingRange(-1, 9) == i5);
    try testing.expect(IntFittingRange(-1, 15) == i5);
    try testing.expect(IntFittingRange(-1, 16) == i6);
    try testing.expect(IntFittingRange(-1, 17) == i6);
    try testing.expect(IntFittingRange(-1, 4095) == i13);
    try testing.expect(IntFittingRange(-4096, 4095) == i13);
    try testing.expect(IntFittingRange(-1, 4096) == i14);
    try testing.expect(IntFittingRange(-4097, 4095) == i14);
    try testing.expect(IntFittingRange(-1, 4097) == i14);
    try testing.expect(IntFittingRange(-1, 123456789123456798123456789) == i88);
    try testing.expect(IntFittingRange(-1, 123456789123456798123456789123456789123456798123456789) == i178);
}

test "overflow functions" {
    try testOverflow();
    try comptime testOverflow();
}

fn testOverflow() !void {
    try testing.expect((mul(i32, 3, 4) catch unreachable) == 12);
    try testing.expect((add(i32, 3, 4) catch unreachable) == 7);
    try testing.expect((sub(i32, 3, 4) catch unreachable) == -1);
    try testing.expect((shlExact(i32, 0b11, 4) catch unreachable) == 0b110000);
}

/// Divide numerator by denominator, rounding toward zero. Returns an
/// error on overflow or when denominator is zero.
pub fn divTrunc(comptime T: type, numerator: T, denominator: T) !T {
    @setRuntimeSafety(false);
    if (denominator == 0) return error.DivisionByZero;
    if (@typeInfo(T) == .int and @typeInfo(T).int.signedness == .signed and numerator == minInt(T) and denominator == -1) return error.Overflow;
    return @divTrunc(numerator, denominator);
}

test divTrunc {
    try testDivTrunc();
    try comptime testDivTrunc();
}
fn testDivTrunc() !void {
    try testing.expect((divTrunc(i32, 5, 3) catch unreachable) == 1);
    try testing.expect((divTrunc(i32, -5, 3) catch unreachable) == -1);
    try testing.expectError(error.DivisionByZero, divTrunc(i8, -5, 0));
    try testing.expectError(error.Overflow, divTrunc(i8, -128, -1));

    try testing.expect((divTrunc(f32, 5.0, 3.0) catch unreachable) == 1.0);
    try testing.expect((divTrunc(f32, -5.0, 3.0) catch unreachable) == -1.0);
}

/// Divide numerator by denominator, rounding toward negative
/// infinity. Returns an error on overflow or when denominator is
/// zero.
pub fn divFloor(comptime T: type, numerator: T, denominator: T) !T {
    @setRuntimeSafety(false);
    if (denominator == 0) return error.DivisionByZero;
    if (@typeInfo(T) == .int and @typeInfo(T).int.signedness == .signed and numerator == minInt(T) and denominator == -1) return error.Overflow;
    return @divFloor(numerator, denominator);
}

test divFloor {
    try testDivFloor();
    try comptime testDivFloor();
}
fn testDivFloor() !void {
    try testing.expect((divFloor(i32, 5, 3) catch unreachable) == 1);
    try testing.expect((divFloor(i32, -5, 3) catch unreachable) == -2);
    try testing.expectError(error.DivisionByZero, divFloor(i8, -5, 0));
    try testing.expectError(error.Overflow, divFloor(i8, -128, -1));

    try testing.expect((divFloor(f32, 5.0, 3.0) catch unreachable) == 1.0);
    try testing.expect((divFloor(f32, -5.0, 3.0) catch unreachable) == -2.0);
}

/// Divide numerator by denominator, rounding toward positive
/// infinity. Returns an error on overflow or when denominator is
/// zero.
pub fn divCeil(comptime T: type, numerator: T, denominator: T) !T {
    @setRuntimeSafety(false);
    if (denominator == 0) return error.DivisionByZero;
    const info = @typeInfo(T);
    switch (info) {
        .comptime_float, .float => return @ceil(numerator / denominator),
        .comptime_int, .int => {
            if (numerator < 0 and denominator < 0) {
                if (info == .int and numerator == minInt(T) and denominator == -1)
                    return error.Overflow;
                return @divFloor(numerator + 1, denominator) + 1;
            }
            if (numerator > 0 and denominator > 0)
                return @divFloor(numerator - 1, denominator) + 1;
            return @divTrunc(numerator, denominator);
        },
        else => @compileError("divCeil unsupported on " ++ @typeName(T)),
    }
}

test divCeil {
    try testDivCeil();
    try comptime testDivCeil();
}
fn testDivCeil() !void {
    try testing.expectEqual(@as(i32, 2), divCeil(i32, 5, 3) catch unreachable);
    try testing.expectEqual(@as(i32, -1), divCeil(i32, -5, 3) catch unreachable);
    try testing.expectEqual(@as(i32, -1), divCeil(i32, 5, -3) catch unreachable);
    try testing.expectEqual(@as(i32, 2), divCeil(i32, -5, -3) catch unreachable);
    try testing.expectEqual(@as(i32, 0), divCeil(i32, 0, 5) catch unreachable);
    try testing.expectEqual(@as(u32, 0), divCeil(u32, 0, 5) catch unreachable);
    try testing.expectError(error.DivisionByZero, divCeil(i8, -5, 0));
    try testing.expectError(error.Overflow, divCeil(i8, -128, -1));

    try testing.expectEqual(@as(f32, 0.0), divCeil(f32, 0.0, 5.0) catch unreachable);
    try testing.expectEqual(@as(f32, 2.0), divCeil(f32, 5.0, 3.0) catch unreachable);
    try testing.expectEqual(@as(f32, -1.0), divCeil(f32, -5.0, 3.0) catch unreachable);
    try testing.expectEqual(@as(f32, -1.0), divCeil(f32, 5.0, -3.0) catch unreachable);
    try testing.expectEqual(@as(f32, 2.0), divCeil(f32, -5.0, -3.0) catch unreachable);

    try testing.expectEqual(6, divCeil(comptime_int, 23, 4) catch unreachable);
    try testing.expectEqual(-5, divCeil(comptime_int, -23, 4) catch unreachable);
    try testing.expectEqual(-5, divCeil(comptime_int, 23, -4) catch unreachable);
    try testing.expectEqual(6, divCeil(comptime_int, -23, -4) catch unreachable);
    try testing.expectError(error.DivisionByZero, divCeil(comptime_int, 23, 0));

    try testing.expectEqual(6.0, divCeil(comptime_float, 23.0, 4.0) catch unreachable);
    try testing.expectEqual(-5.0, divCeil(comptime_float, -23.0, 4.0) catch unreachable);
    try testing.expectEqual(-5.0, divCeil(comptime_float, 23.0, -4.0) catch unreachable);
    try testing.expectEqual(6.0, divCeil(comptime_float, -23.0, -4.0) catch unreachable);
    try testing.expectError(error.DivisionByZero, divCeil(comptime_float, 23.0, 0.0));
}

/// Divide numerator by denominator. Return an error if quotient is
/// not an integer, denominator is zero, or on overflow.
pub fn divExact(comptime T: type, numerator: T, denominator: T) !T {
    @setRuntimeSafety(false);
    if (denominator == 0) return error.DivisionByZero;
    if (@typeInfo(T) == .int and @typeInfo(T).int.signedness == .signed and numerator == minInt(T) and denominator == -1) return error.Overflow;
    const result = @divTrunc(numerator, denominator);
    if (result * denominator != numerator) return error.UnexpectedRemainder;
    return result;
}

test divExact {
    try testDivExact();
    try comptime testDivExact();
}
fn testDivExact() !void {
    try testing.expect((divExact(i32, 10, 5) catch unreachable) == 2);
    try testing.expect((divExact(i32, -10, 5) catch unreachable) == -2);
    try testing.expectError(error.DivisionByZero, divExact(i8, -5, 0));
    try testing.expectError(error.Overflow, divExact(i8, -128, -1));
    try testing.expectError(error.UnexpectedRemainder, divExact(i32, 5, 2));

    try testing.expect((divExact(f32, 10.0, 5.0) catch unreachable) == 2.0);
    try testing.expect((divExact(f32, -10.0, 5.0) catch unreachable) == -2.0);
    try testing.expectError(error.UnexpectedRemainder, divExact(f32, 5.0, 2.0));
}

/// Returns numerator modulo denominator, or an error if denominator is
/// zero or negative. Negative numerators never result in negative
/// return values.
pub fn mod(comptime T: type, numerator: T, denominator: T) !T {
    @setRuntimeSafety(false);
    if (denominator == 0) return error.DivisionByZero;
    if (denominator < 0) return error.NegativeDenominator;
    return @mod(numerator, denominator);
}

test mod {
    try testMod();
    try comptime testMod();
}
fn testMod() !void {
    try testing.expect((mod(i32, -5, 3) catch unreachable) == 1);
    try testing.expect((mod(i32, 5, 3) catch unreachable) == 2);
    try testing.expectError(error.NegativeDenominator, mod(i32, 10, -1));
    try testing.expectError(error.DivisionByZero, mod(i32, 10, 0));

    try testing.expect((mod(f32, -5, 3) catch unreachable) == 1);
    try testing.expect((mod(f32, 5, 3) catch unreachable) == 2);
    try testing.expectError(error.NegativeDenominator, mod(f32, 10, -1));
    try testing.expectError(error.DivisionByZero, mod(f32, 10, 0));
}

/// Returns the remainder when numerator is divided by denominator, or
/// an error if denominator is zero or negative. Negative numerators
/// can give negative results.
pub fn rem(comptime T: type, numerator: T, denominator: T) !T {
    @setRuntimeSafety(false);
    if (denominator == 0) return error.DivisionByZero;
    if (denominator < 0) return error.NegativeDenominator;
    return @rem(numerator, denominator);
}

test rem {
    try testRem();
    try comptime testRem();
}
fn testRem() !void {
    try testing.expect((rem(i32, -5, 3) catch unreachable) == -2);
    try testing.expect((rem(i32, 5, 3) catch unreachable) == 2);
    try testing.expectError(error.NegativeDenominator, rem(i32, 10, -1));
    try testing.expectError(error.DivisionByZero, rem(i32, 10, 0));

    try testing.expect((rem(f32, -5, 3) catch unreachable) == -2);
    try testing.expect((rem(f32, 5, 3) catch unreachable) == 2);
    try testing.expectError(error.NegativeDenominator, rem(f32, 10, -1));
    try testing.expectError(error.DivisionByZero, rem(f32, 10, 0));
}

/// Returns the negation of the integer parameter.
/// Result is a signed integer.
pub fn negateCast(x: anytype) !std.meta.Int(.signed, @bitSizeOf(@TypeOf(x))) {
    if (@typeInfo(@TypeOf(x)).int.signedness == .signed) return negate(x);

    const int = std.meta.Int(.signed, @bitSizeOf(@TypeOf(x)));
    if (x > -minInt(int)) return error.Overflow;

    if (x == -minInt(int)) return minInt(int);

    return -@as(int, @intCast(x));
}

test negateCast {
    try testing.expect((negateCast(@as(u32, 999)) catch unreachable) == -999);
    try testing.expect(@TypeOf(negateCast(@as(u32, 999)) catch unreachable) == i32);

    try testing.expect((negateCast(@as(u32, -minInt(i32))) catch unreachable) == minInt(i32));
    try testing.expect(@TypeOf(negateCast(@as(u32, -minInt(i32))) catch unreachable) == i32);

    try testing.expectError(error.Overflow, negateCast(@as(u32, maxInt(i32) + 10)));
}

/// Cast an integer to a different integer type. If the value doesn't fit,
/// return null.
pub fn cast(comptime T: type, x: anytype) ?T {
    comptime assert(@typeInfo(T) == .int); // must pass an integer
    const is_comptime = @TypeOf(x) == comptime_int;
    comptime assert(is_comptime or @typeInfo(@TypeOf(x)) == .int); // must pass an integer
    if ((is_comptime or maxInt(@TypeOf(x)) > maxInt(T)) and x > maxInt(T)) {
        return null;
    } else if ((is_comptime or minInt(@TypeOf(x)) < minInt(T)) and x < minInt(T)) {
        return null;
    } else {
        return @as(T, @intCast(x));
    }
}

test cast {
    try testing.expect(cast(u8, 300) == null);
    try testing.expect(cast(u8, @as(u32, 300)) == null);
    try testing.expect(cast(i8, -200) == null);
    try testing.expect(cast(i8, @as(i32, -200)) == null);
    try testing.expect(cast(u8, -1) == null);
    try testing.expect(cast(u8, @as(i8, -1)) == null);
    try testing.expect(cast(u64, -1) == null);
    try testing.expect(cast(u64, @as(i8, -1)) == null);

    try testing.expect(cast(u8, 255).? == @as(u8, 255));
    try testing.expect(cast(u8, @as(u32, 255)).? == @as(u8, 255));
    try testing.expect(@TypeOf(cast(u8, 255).?) == u8);
    try testing.expect(@TypeOf(cast(u8, @as(u32, 255)).?) == u8);
}

pub const AlignCastError = error{UnalignedMemory};

fn AlignCastResult(comptime alignment: Alignment, comptime Ptr: type) type {
    var ptr_info = @typeInfo(Ptr);
    ptr_info.pointer.alignment = alignment.toByteUnits();
    return @Type(ptr_info);
}

/// Align cast a pointer but return an error if it's the wrong alignment
pub fn alignCast(comptime alignment: Alignment, ptr: anytype) AlignCastError!AlignCastResult(alignment, @TypeOf(ptr)) {
    if (alignment.check(@intFromPtr(ptr))) return @alignCast(ptr);
    return error.UnalignedMemory;
}

/// Asserts `int > 0`.
pub fn isPowerOfTwo(int: anytype) bool {
    assert(int > 0);
    return (int & (int - 1)) == 0;
}

test isPowerOfTwo {
    try testing.expect(isPowerOfTwo(@as(u8, 1)));
    try testing.expect(isPowerOfTwo(2));
    try testing.expect(!isPowerOfTwo(@as(i16, 3)));
    try testing.expect(isPowerOfTwo(4));
    try testing.expect(!isPowerOfTwo(@as(u32, 31)));
    try testing.expect(isPowerOfTwo(32));
    try testing.expect(!isPowerOfTwo(@as(i64, 63)));
    try testing.expect(isPowerOfTwo(128));
    try testing.expect(isPowerOfTwo(@as(u128, 256)));
}

/// Aligns the given integer type bit width to a width divisible by 8.
pub fn ByteAlignedInt(comptime T: type) type {
    const info = @typeInfo(T).int;
    const bits = (info.bits + 7) / 8 * 8;
    const extended_type = std.meta.Int(info.signedness, bits);
    return extended_type;
}

test ByteAlignedInt {
    try testing.expect(ByteAlignedInt(u0) == u0);
    try testing.expect(ByteAlignedInt(i0) == i0);
    try testing.expect(ByteAlignedInt(u3) == u8);
    try testing.expect(ByteAlignedInt(u8) == u8);
    try testing.expect(ByteAlignedInt(i111) == i112);
    try testing.expect(ByteAlignedInt(u129) == u136);
}

/// Rounds the given floating point number to the nearest integer.
/// If two integers are equally close, rounds away from zero.
/// Uses a dedicated hardware instruction when available.
/// This is the same as calling the builtin @round
pub inline fn round(value: anytype) @TypeOf(value) {
    return @round(value);
}

/// Rounds the given floating point number to an integer, towards zero.
/// Uses a dedicated hardware instruction when available.
/// This is the same as calling the builtin @trunc
pub inline fn trunc(value: anytype) @TypeOf(value) {
    return @trunc(value);
}

/// Returns the largest integral value not greater than the given floating point number.
/// Uses a dedicated hardware instruction when available.
/// This is the same as calling the builtin @floor
pub inline fn floor(value: anytype) @TypeOf(value) {
    return @floor(value);
}

/// Returns the nearest power of two less than or equal to value, or
/// zero if value is less than or equal to zero.
pub fn floorPowerOfTwo(comptime T: type, value: T) T {
    const uT = std.meta.Int(.unsigned, @typeInfo(T).int.bits);
    if (value <= 0) return 0;
    return @as(T, 1) << log2_int(uT, @as(uT, @intCast(value)));
}

test floorPowerOfTwo {
    try testFloorPowerOfTwo();
    try comptime testFloorPowerOfTwo();
}

fn testFloorPowerOfTwo() !void {
    try testing.expect(floorPowerOfTwo(u32, 63) == 32);
    try testing.expect(floorPowerOfTwo(u32, 64) == 64);
    try testing.expect(floorPowerOfTwo(u32, 65) == 64);
    try testing.expect(floorPowerOfTwo(u32, 0) == 0);
    try testing.expect(floorPowerOfTwo(u4, 7) == 4);
    try testing.expect(floorPowerOfTwo(u4, 8) == 8);
    try testing.expect(floorPowerOfTwo(u4, 9) == 8);
    try testing.expect(floorPowerOfTwo(u4, 0) == 0);
    try testing.expect(floorPowerOfTwo(i4, 7) == 4);
    try testing.expect(floorPowerOfTwo(i4, -8) == 0);
    try testing.expect(floorPowerOfTwo(i4, -1) == 0);
    try testing.expect(floorPowerOfTwo(i4, 0) == 0);
}

/// Returns the smallest integral value not less than the given floating point number.
/// Uses a dedicated hardware instruction when available.
/// This is the same as calling the builtin @ceil
pub inline fn ceil(value: anytype) @TypeOf(value) {
    return @ceil(value);
}

/// Returns the next power of two (if the value is not already a power of two).
/// Only unsigned integers can be used. Zero is not an allowed input.
/// Result is a type with 1 more bit than the input type.
pub fn ceilPowerOfTwoPromote(comptime T: type, value: T) std.meta.Int(@typeInfo(T).int.signedness, @typeInfo(T).int.bits + 1) {
    comptime assert(@typeInfo(T) == .int);
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    assert(value != 0);
    const PromotedType = std.meta.Int(@typeInfo(T).int.signedness, @typeInfo(T).int.bits + 1);
    const ShiftType = std.math.Log2Int(PromotedType);
    return @as(PromotedType, 1) << @as(ShiftType, @intCast(@typeInfo(T).int.bits - @clz(value - 1)));
}

/// Returns the next power of two (if the value is not already a power of two).
/// Only unsigned integers can be used. Zero is not an allowed input.
/// If the value doesn't fit, returns an error.
pub fn ceilPowerOfTwo(comptime T: type, value: T) (error{Overflow}!T) {
    comptime assert(@typeInfo(T) == .int);
    const info = @typeInfo(T).int;
    comptime assert(info.signedness == .unsigned);
    const PromotedType = std.meta.Int(info.signedness, info.bits + 1);
    const overflowBit = @as(PromotedType, 1) << info.bits;
    const x = ceilPowerOfTwoPromote(T, value);
    if (overflowBit & x != 0) {
        return error.Overflow;
    }
    return @as(T, @intCast(x));
}

/// Returns the next power of two (if the value is not already a power
/// of two). Only unsigned integers can be used. Zero is not an
/// allowed input. Asserts that the value fits.
pub fn ceilPowerOfTwoAssert(comptime T: type, value: T) T {
    return ceilPowerOfTwo(T, value) catch unreachable;
}

test ceilPowerOfTwoPromote {
    try testCeilPowerOfTwoPromote();
    try comptime testCeilPowerOfTwoPromote();
}

fn testCeilPowerOfTwoPromote() !void {
    try testing.expectEqual(@as(u33, 1), ceilPowerOfTwoPromote(u32, 1));
    try testing.expectEqual(@as(u33, 2), ceilPowerOfTwoPromote(u32, 2));
    try testing.expectEqual(@as(u33, 64), ceilPowerOfTwoPromote(u32, 63));
    try testing.expectEqual(@as(u33, 64), ceilPowerOfTwoPromote(u32, 64));
    try testing.expectEqual(@as(u33, 128), ceilPowerOfTwoPromote(u32, 65));
    try testing.expectEqual(@as(u6, 8), ceilPowerOfTwoPromote(u5, 7));
    try testing.expectEqual(@as(u6, 8), ceilPowerOfTwoPromote(u5, 8));
    try testing.expectEqual(@as(u6, 16), ceilPowerOfTwoPromote(u5, 9));
    try testing.expectEqual(@as(u5, 16), ceilPowerOfTwoPromote(u4, 9));
}

test ceilPowerOfTwo {
    try testCeilPowerOfTwo();
    try comptime testCeilPowerOfTwo();
}

fn testCeilPowerOfTwo() !void {
    try testing.expectEqual(@as(u32, 1), try ceilPowerOfTwo(u32, 1));
    try testing.expectEqual(@as(u32, 2), try ceilPowerOfTwo(u32, 2));
    try testing.expectEqual(@as(u32, 64), try ceilPowerOfTwo(u32, 63));
    try testing.expectEqual(@as(u32, 64), try ceilPowerOfTwo(u32, 64));
    try testing.expectEqual(@as(u32, 128), try ceilPowerOfTwo(u32, 65));
    try testing.expectEqual(@as(u5, 8), try ceilPowerOfTwo(u5, 7));
    try testing.expectEqual(@as(u5, 8), try ceilPowerOfTwo(u5, 8));
    try testing.expectEqual(@as(u5, 16), try ceilPowerOfTwo(u5, 9));
    try testing.expectError(error.Overflow, ceilPowerOfTwo(u4, 9));
}

/// Return the log base 2 of integer value x, rounding down to the
/// nearest integer.
pub fn log2_int(comptime T: type, x: T) Log2Int(T) {
    if (@typeInfo(T) != .int or @typeInfo(T).int.signedness != .unsigned)
        @compileError("log2_int requires an unsigned integer, found " ++ @typeName(T));
    assert(x != 0);
    return @as(Log2Int(T), @intCast(@typeInfo(T).int.bits - 1 - @clz(x)));
}

/// Return the log base 2 of integer value x, rounding up to the
/// nearest integer.
pub fn log2_int_ceil(comptime T: type, x: T) Log2IntCeil(T) {
    if (@typeInfo(T) != .int or @typeInfo(T).int.signedness != .unsigned)
        @compileError("log2_int_ceil requires an unsigned integer, found " ++ @typeName(T));
    assert(x != 0);
    if (x == 1) return 0;
    const log2_val: Log2IntCeil(T) = log2_int(T, x - 1);
    return log2_val + 1;
}

test log2_int_ceil {
    try testing.expect(log2_int_ceil(u32, 1) == 0);
    try testing.expect(log2_int_ceil(u32, 2) == 1);
    try testing.expect(log2_int_ceil(u32, 3) == 2);
    try testing.expect(log2_int_ceil(u32, 4) == 2);
    try testing.expect(log2_int_ceil(u32, 5) == 3);
    try testing.expect(log2_int_ceil(u32, 6) == 3);
    try testing.expect(log2_int_ceil(u32, 7) == 3);
    try testing.expect(log2_int_ceil(u32, 8) == 3);
    try testing.expect(log2_int_ceil(u32, 9) == 4);
    try testing.expect(log2_int_ceil(u32, 10) == 4);
}

/// Cast a value to a different type. If the value doesn't fit in, or
/// can't be perfectly represented by, the new type, it will be
/// converted to the closest possible representation.
pub fn lossyCast(comptime T: type, value: anytype) T {
    switch (@typeInfo(T)) {
        .float => {
            switch (@typeInfo(@TypeOf(value))) {
                .int => return @floatFromInt(value),
                .float => return @floatCast(value),
                .comptime_int => return value,
                .comptime_float => return value,
                else => @compileError("bad type"),
            }
        },
        .int => {
            switch (@typeInfo(@TypeOf(value))) {
                .int, .comptime_int => {
                    if (value >= maxInt(T)) {
                        return maxInt(T);
                    } else if (value <= minInt(T)) {
                        return minInt(T);
                    } else {
                        return @intCast(value);
                    }
                },
                .float, .comptime_float => {
                    if (isNan(value)) {
                        return 0;
                    } else if (value >= maxInt(T)) {
                        return maxInt(T);
                    } else if (value <= minInt(T)) {
                        return minInt(T);
                    } else {
                        return @intFromFloat(value);
                    }
                },
                else => @compileError("bad type"),
            }
        },
        else => @compileError("bad result type"),
    }
}

test lossyCast {
    try testing.expect(lossyCast(i16, 70000.0) == @as(i16, 32767));
    try testing.expect(lossyCast(u32, @as(i16, -255)) == @as(u32, 0));
    try testing.expect(lossyCast(i9, @as(u32, 200)) == @as(i9, 200));
    try testing.expect(lossyCast(u32, @as(f32, maxInt(u32))) == maxInt(u32));
    try testing.expect(lossyCast(u32, nan(f32)) == 0);
}

/// Performs linear interpolation between *a* and *b* based on *t*.
/// *t* ranges from 0.0 to 1.0, but may exceed these bounds.
/// Supports floats and vectors of floats.
///
/// This does not guarantee returning *b* if *t* is 1 due to floating-point errors.
/// This is monotonic.
pub fn lerp(a: anytype, b: anytype, t: anytype) @TypeOf(a, b, t) {
    const Type = @TypeOf(a, b, t);
    return @mulAdd(Type, b - a, t, a);
}

test lerp {
    if (builtin.zig_backend == .stage2_c) return error.SkipZigTest; // https://github.com/ziglang/zig/issues/17884
    if (builtin.zig_backend == .stage2_x86_64 and
        !comptime std.Target.x86.featureSetHas(builtin.cpu.features, .fma)) return error.SkipZigTest; // https://github.com/ziglang/zig/issues/17884

    try testing.expectEqual(@as(f64, 75), lerp(50, 100, 0.5));
    try testing.expectEqual(@as(f32, 43.75), lerp(50, 25, 0.25));
    try testing.expectEqual(@as(f64, -31.25), lerp(-50, 25, 0.25));

    try testing.expectEqual(@as(f64, 30), lerp(10, 20, 2.0));
    try testing.expectEqual(@as(f64, 5), lerp(10, 20, -0.5));

    try testing.expectApproxEqRel(@as(f32, -7.16067345e+03), lerp(-10000.12345, -5000.12345, 0.56789), 1e-19);
    try testing.expectApproxEqRel(@as(f64, 7.010987590521e+62), lerp(0.123456789e-64, 0.123456789e64, 0.56789), 1e-33);

    try testing.expectEqual(@as(f32, 0.0), lerp(@as(f32, 1.0e8), 1.0, 1.0));
    try testing.expectEqual(@as(f64, 0.0), lerp(@as(f64, 1.0e16), 1.0, 1.0));
    try testing.expectEqual(@as(f32, 1.0), lerp(@as(f32, 1.0e7), 1.0, 1.0));
    try testing.expectEqual(@as(f64, 1.0), lerp(@as(f64, 1.0e15), 1.0, 1.0));

    {
        const a: @Vector(3, f32) = @splat(0);
        const b: @Vector(3, f32) = @splat(50);
        const t: @Vector(3, f32) = @splat(0.5);
        try testing.expectEqual(
            @Vector(3, f32){ 25, 25, 25 },
            lerp(a, b, t),
        );
    }
    {
        const a: @Vector(3, f64) = @splat(50);
        const b: @Vector(3, f64) = @splat(100);
        const t: @Vector(3, f64) = @splat(0.5);
        try testing.expectEqual(
            @Vector(3, f64){ 75, 75, 75 },
            lerp(a, b, t),
        );
    }
    {
        const a: @Vector(2, f32) = @splat(40);
        const b: @Vector(2, f32) = @splat(80);
        const t: @Vector(2, f32) = @Vector(2, f32){ 0.25, 0.75 };
        try testing.expectEqual(
            @Vector(2, f32){ 50, 70 },
            lerp(a, b, t),
        );
    }
}

/// Returns the maximum value of integer type T.
pub fn maxInt(comptime T: type) comptime_int {
    const info = @typeInfo(T);
    const bit_count = info.int.bits;
    if (bit_count == 0) return 0;
    return (1 << (bit_count - @intFromBool(info.int.signedness == .signed))) - 1;
}

/// Returns the minimum value of integer type T.
pub fn minInt(comptime T: type) comptime_int {
    const info = @typeInfo(T);
    const bit_count = info.int.bits;
    if (info.int.signedness == .unsigned) return 0;
    if (bit_count == 0) return 0;
    return -(1 << (bit_count - 1));
}

test maxInt {
    try testing.expect(maxInt(u0) == 0);
    try testing.expect(maxInt(u1) == 1);
    try testing.expect(maxInt(u8) == 255);
    try testing.expect(maxInt(u16) == 65535);
    try testing.expect(maxInt(u32) == 4294967295);
    try testing.expect(maxInt(u64) == 18446744073709551615);
    try testing.expect(maxInt(u128) == 340282366920938463463374607431768211455);

    try testing.expect(maxInt(i0) == 0);
    try testing.expect(maxInt(i1) == 0);
    try testing.expect(maxInt(i8) == 127);
    try testing.expect(maxInt(i16) == 32767);
    try testing.expect(maxInt(i32) == 2147483647);
    try testing.expect(maxInt(i63) == 4611686018427387903);
    try testing.expect(maxInt(i64) == 9223372036854775807);
    try testing.expect(maxInt(i128) == 170141183460469231731687303715884105727);
}

test minInt {
    try testing.expect(minInt(u0) == 0);
    try testing.expect(minInt(u1) == 0);
    try testing.expect(minInt(u8) == 0);
    try testing.expect(minInt(u16) == 0);
    try testing.expect(minInt(u32) == 0);
    try testing.expect(minInt(u63) == 0);
    try testing.expect(minInt(u64) == 0);
    try testing.expect(minInt(u128) == 0);

    try testing.expect(minInt(i0) == 0);
    try testing.expect(minInt(i1) == -1);
    try testing.expect(minInt(i8) == -128);
    try testing.expect(minInt(i16) == -32768);
    try testing.expect(minInt(i32) == -2147483648);
    try testing.expect(minInt(i63) == -4611686018427387904);
    try testing.expect(minInt(i64) == -9223372036854775808);
    try testing.expect(minInt(i128) == -170141183460469231731687303715884105728);
}

test "max value type" {
    const x: u32 = maxInt(i32);
    try testing.expect(x == 2147483647);
}

/// Multiply a and b. Return type is wide enough to guarantee no
/// overflow.
pub fn mulWide(comptime T: type, a: T, b: T) std.meta.Int(
    @typeInfo(T).int.signedness,
    @typeInfo(T).int.bits * 2,
) {
    const ResultInt = std.meta.Int(
        @typeInfo(T).int.signedness,
        @typeInfo(T).int.bits * 2,
    );
    return @as(ResultInt, a) * @as(ResultInt, b);
}

test mulWide {
    try testing.expect(mulWide(u8, 5, 5) == 25);
    try testing.expect(mulWide(i8, 5, -5) == -25);
    try testing.expect(mulWide(u8, 100, 100) == 10000);
}

/// See also `CompareOperator`.
pub const Order = enum {
    /// Greater than (`>`)
    gt,

    /// Less than (`<`)
    lt,

    /// Equal (`==`)
    eq,

    pub fn invert(self: Order) Order {
        return switch (self) {
            .lt => .gt,
            .eq => .eq,
            .gt => .lt,
        };
    }

    test invert {
        try testing.expect(Order.invert(order(0, 0)) == .eq);
        try testing.expect(Order.invert(order(1, 0)) == .lt);
        try testing.expect(Order.invert(order(-1, 0)) == .gt);
    }

    pub fn differ(self: Order) ?Order {
        return if (self != .eq) self else null;
    }

    test differ {
        const neg: i32 = -1;
        const zero: i32 = 0;
        const pos: i32 = 1;
        try testing.expect(order(zero, neg).differ() orelse
            order(pos, zero) == .gt);
        try testing.expect(order(zero, zero).differ() orelse
            order(zero, zero) == .eq);
        try testing.expect(order(pos, pos).differ() orelse
            order(neg, zero) == .lt);
        try testing.expect(order(zero, zero).differ() orelse
            order(pos, neg).differ() orelse
            order(neg, zero) == .gt);
        try testing.expect(order(pos, pos).differ() orelse
            order(pos, pos).differ() orelse
            order(neg, neg) == .eq);
        try testing.expect(order(zero, pos).differ() orelse
            order(neg, pos).differ() orelse
            order(pos, neg) == .lt);
    }

    pub fn compare(self: Order, op: CompareOperator) bool {
        return switch (self) {
            .lt => switch (op) {
                .lt => true,
                .lte => true,
                .eq => false,
                .gte => false,
                .gt => false,
                .neq => true,
            },
            .eq => switch (op) {
                .lt => false,
                .lte => true,
                .eq => true,
                .gte => true,
                .gt => false,
                .neq => false,
            },
            .gt => switch (op) {
                .lt => false,
                .lte => false,
                .eq => false,
                .gte => true,
                .gt => true,
                .neq => true,
            },
        };
    }

    // https://github.com/ziglang/zig/issues/19295
    test "compare" {
        try testing.expect(order(-1, 0).compare(.lt));
        try testing.expect(order(-1, 0).compare(.lte));
        try testing.expect(order(0, 0).compare(.lte));
        try testing.expect(order(0, 0).compare(.eq));
        try testing.expect(order(0, 0).compare(.gte));
        try testing.expect(order(1, 0).compare(.gte));
        try testing.expect(order(1, 0).compare(.gt));
        try testing.expect(order(1, 0).compare(.neq));
    }
};

/// Given two numbers, this function returns the order they are with respect to each other.
pub fn order(a: anytype, b: anytype) Order {
    if (a == b) {
        return .eq;
    } else if (a < b) {
        return .lt;
    } else if (a > b) {
        return .gt;
    } else {
        unreachable;
    }
}

/// See also `Order`.
pub const CompareOperator = enum {
    /// Less than (`<`)
    lt,
    /// Less than or equal (`<=`)
    lte,
    /// Equal (`==`)
    eq,
    /// Greater than or equal (`>=`)
    gte,
    /// Greater than (`>`)
    gt,
    /// Not equal (`!=`)
    neq,

    /// Reverse the direction of the comparison.
    /// Use when swapping the left and right hand operands.
    pub fn reverse(op: CompareOperator) CompareOperator {
        return switch (op) {
            .lt => .gt,
            .lte => .gte,
            .gt => .lt,
            .gte => .lte,
            .eq => .eq,
            .neq => .neq,
        };
    }

    test reverse {
        inline for (@typeInfo(CompareOperator).@"enum".fields) |op_field| {
            const op = @as(CompareOperator, @enumFromInt(op_field.value));
            try testing.expect(compare(2, op, 3) == compare(3, op.reverse(), 2));
            try testing.expect(compare(3, op, 3) == compare(3, op.reverse(), 3));
            try testing.expect(compare(4, op, 3) == compare(3, op.reverse(), 4));
        }
    }
};

/// This function does the same thing as comparison operators, however the
/// operator is a runtime-known enum value. Works on any operands that
/// support comparison operators.
pub fn compare(a: anytype, op: CompareOperator, b: anytype) bool {
    return switch (op) {
        .lt => a < b,
        .lte => a <= b,
        .eq => a == b,
        .neq => a != b,
        .gt => a > b,
        .gte => a >= b,
    };
}

test compare {
    try testing.expect(compare(@as(i8, -1), .lt, @as(u8, 255)));
    try testing.expect(compare(@as(i8, 2), .gt, @as(u8, 1)));
    try testing.expect(!compare(@as(i8, -1), .gte, @as(u8, 255)));
    try testing.expect(compare(@as(u8, 255), .gt, @as(i8, -1)));
    try testing.expect(!compare(@as(u8, 255), .lte, @as(i8, -1)));
    try testing.expect(compare(@as(i8, -1), .lt, @as(u9, 255)));
    try testing.expect(!compare(@as(i8, -1), .gte, @as(u9, 255)));
    try testing.expect(compare(@as(u9, 255), .gt, @as(i8, -1)));
    try testing.expect(!compare(@as(u9, 255), .lte, @as(i8, -1)));
    try testing.expect(compare(@as(i9, -1), .lt, @as(u8, 255)));
    try testing.expect(!compare(@as(i9, -1), .gte, @as(u8, 255)));
    try testing.expect(compare(@as(u8, 255), .gt, @as(i9, -1)));
    try testing.expect(!compare(@as(u8, 255), .lte, @as(i9, -1)));
    try testing.expect(compare(@as(u8, 1), .lt, @as(u8, 2)));
    try testing.expect(@as(u8, @bitCast(@as(i8, -1))) == @as(u8, 255));
    try testing.expect(!compare(@as(u8, 255), .eq, @as(i8, -1)));
    try testing.expect(compare(@as(u8, 1), .eq, @as(u8, 1)));
}

test order {
    try testing.expect(order(0, 0) == .eq);
    try testing.expect(order(1, 0) == .gt);
    try testing.expect(order(-1, 0) == .lt);
}

/// Returns a mask of all ones if value is true,
/// and a mask of all zeroes if value is false.
/// Compiles to one instruction for register sized integers.
pub inline fn boolMask(comptime MaskInt: type, value: bool) MaskInt {
    if (@typeInfo(MaskInt) != .int)
        @compileError("boolMask requires an integer mask type.");

    if (MaskInt == u0 or MaskInt == i0)
        @compileError("boolMask cannot convert to u0 or i0, they are too small.");

    // The u1 and i1 cases tend to overflow,
    // so we special case them here.
    if (MaskInt == u1) return @intFromBool(value);
    if (MaskInt == i1) {
        // The @as here is a workaround for #7950
        return @as(i1, @bitCast(@as(u1, @intFromBool(v```
