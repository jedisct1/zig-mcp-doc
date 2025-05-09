```
    struct_ops,
    netfilter,
    tcx_ingress,
    tcx_egress,
    trace_uprobe_multi,
    cgroup_unix_connect,
    cgroup_unix_sendmsg,
    cgroup_unix_recvmsg,
    cgroup_unix_getpeername,
    cgroup_unix_getsockname,
    netkit_primary,
    netkit_peer,
    trace_kprobe_session,
    _,
};

const obj_name_len = 16;
/// struct used by Cmd.map_create command
pub const MapCreateAttr = extern struct {
    /// one of MapType
    map_type: u32,

    /// size of key in bytes
    key_size: u32,

    /// size of value in bytes
    value_size: u32,

    /// max number of entries in a map
    max_entries: u32,

    /// .map_create related flags
    map_flags: u32,

    /// fd pointing to the inner map
    inner_map_fd: fd_t,

    /// numa node (effective only if MapCreateFlags.numa_node is set)
    numa_node: u32,
    map_name: [obj_name_len]u8,

    /// ifindex of netdev to create on
    map_ifindex: u32,

    /// fd pointing to a BTF type data
    btf_fd: fd_t,

    /// BTF type_id of the key
    btf_key_type_id: u32,

    /// BTF type_id of the value
    bpf_value_type_id: u32,

    /// BTF type_id of a kernel struct stored as the map value
    btf_vmlinux_value_type_id: u32,
};

/// struct used by Cmd.map_*_elem commands
pub const MapElemAttr = extern struct {
    map_fd: fd_t,
    key: u64,
    result: extern union {
        value: u64,
        next_key: u64,
    },
    flags: u64,
};

/// struct used by Cmd.map_*_batch commands
pub const MapBatchAttr = extern struct {
    /// start batch, NULL to start from beginning
    in_batch: u64,

    /// output: next start batch
    out_batch: u64,
    keys: u64,
    values: u64,

    /// input/output:
    /// input: # of key/value elements
    /// output: # of filled elements
    count: u32,
    map_fd: fd_t,
    elem_flags: u64,
    flags: u64,
};

/// struct used by Cmd.prog_load command
pub const ProgLoadAttr = extern struct {
    /// one of ProgType
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,

    /// verbosity level of verifier
    log_level: u32,

    /// size of user buffer
    log_size: u32,

    /// user supplied buffer
    log_buf: u64,

    /// not used
    kern_version: u32,
    prog_flags: u32,
    prog_name: [obj_name_len]u8,

    /// ifindex of netdev to prep for.
    prog_ifindex: u32,

    /// For some prog types expected attach type must be known at load time to
    /// verify attach type specific parts of prog (context accesses, allowed
    /// helpers, etc).
    expected_attach_type: u32,

    /// fd pointing to BTF type data
    prog_btf_fd: fd_t,

    /// userspace bpf_func_info size
    func_info_rec_size: u32,
    func_info: u64,

    /// number of bpf_func_info records
    func_info_cnt: u32,

    /// userspace bpf_line_info size
    line_info_rec_size: u32,
    line_info: u64,

    /// number of bpf_line_info records
    line_info_cnt: u32,

    /// in-kernel BTF type id to attach to
    attact_btf_id: u32,

    /// 0 to attach to vmlinux
    attach_prog_id: u32,
};

/// struct used by Cmd.obj_* commands
pub const ObjAttr = extern struct {
    pathname: u64,
    bpf_fd: fd_t,
    file_flags: u32,
};

/// struct used by Cmd.prog_attach/detach commands
pub const ProgAttachAttr = extern struct {
    /// container object to attach to
    target_fd: fd_t,

    /// eBPF program to attach
    attach_bpf_fd: fd_t,

    attach_type: u32,
    attach_flags: u32,

    // TODO: BPF_F_REPLACE flags
    /// previously attached eBPF program to replace if .replace is used
    replace_bpf_fd: fd_t,
};

/// struct used by Cmd.prog_test_run command
pub const TestRunAttr = extern struct {
    prog_fd: fd_t,
    retval: u32,

    /// input: len of data_in
    data_size_in: u32,

    /// input/output: len of data_out. returns ENOSPC if data_out is too small.
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,

    /// input: len of ctx_in
    ctx_size_in: u32,

    /// input/output: len of ctx_out. returns ENOSPC if ctx_out is too small.
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
};

/// struct used by Cmd.*_get_*_id commands
pub const GetIdAttr = extern struct {
    id: extern union {
        start_id: u32,
        prog_id: u32,
        map_id: u32,
        btf_id: u32,
        link_id: u32,
    },
    next_id: u32,
    open_flags: u32,
};

/// struct used by Cmd.obj_get_info_by_fd command
pub const InfoAttr = extern struct {
    bpf_fd: fd_t,
    info_len: u32,
    info: u64,
};

/// struct used by Cmd.prog_query command
pub const QueryAttr = extern struct {
    /// container object to query
    target_fd: fd_t,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
};

/// struct used by Cmd.raw_tracepoint_open command
pub const RawTracepointAttr = extern struct {
    name: u64,
    prog_fd: fd_t,
};

/// struct used by Cmd.btf_load command
pub const BtfLoadAttr = extern struct {
    btf: u64,
    btf_log_buf: u64,
    btf_size: u32,
    btf_log_size: u32,
    btf_log_level: u32,
};

/// struct used by Cmd.task_fd_query
pub const TaskFdQueryAttr = extern struct {
    /// input: pid
    pid: pid_t,

    /// input: fd
    fd: fd_t,

    /// input: flags
    flags: u32,

    /// input/output: buf len
    buf_len: u32,

    /// input/output:
    ///     tp_name for tracepoint
    ///     symbol for kprobe
    ///     filename for uprobe
    buf: u64,

    /// output: prod_id
    prog_id: u32,

    /// output: BPF_FD_TYPE
    fd_type: u32,

    /// output: probe_offset
    probe_offset: u64,

    /// output: probe_addr
    probe_addr: u64,
};

/// struct used by Cmd.link_create command
pub const LinkCreateAttr = extern struct {
    /// eBPF program to attach
    prog_fd: fd_t,

    /// object to attach to
    target_fd: fd_t,
    attach_type: u32,

    /// extra flags
    flags: u32,
};

/// struct used by Cmd.link_update command
pub const LinkUpdateAttr = extern struct {
    link_fd: fd_t,

    /// new program to update link with
    new_prog_fd: fd_t,

    /// extra flags
    flags: u32,

    /// expected link's program fd, it is specified only if BPF_F_REPLACE is
    /// set in flags
    old_prog_fd: fd_t,
};

/// struct used by Cmd.enable_stats command
pub const EnableStatsAttr = extern struct {
    type: u32,
};

/// struct used by Cmd.iter_create command
pub const IterCreateAttr = extern struct {
    link_fd: fd_t,
    flags: u32,
};

/// Mega struct that is passed to the bpf() syscall
pub const Attr = extern union {
    map_create: MapCreateAttr,
    map_elem: MapElemAttr,
    map_batch: MapBatchAttr,
    prog_load: ProgLoadAttr,
    obj: ObjAttr,
    prog_attach: ProgAttachAttr,
    test_run: TestRunAttr,
    get_id: GetIdAttr,
    info: InfoAttr,
    query: QueryAttr,
    raw_tracepoint: RawTracepointAttr,
    btf_load: BtfLoadAttr,
    task_fd_query: TaskFdQueryAttr,
    link_create: LinkCreateAttr,
    link_update: LinkUpdateAttr,
    enable_stats: EnableStatsAttr,
    iter_create: IterCreateAttr,
};

pub const Log = struct {
    level: u32,
    buf: []u8,
};

pub fn map_create(map_type: MapType, key_size: u32, value_size: u32, max_entries: u32) !fd_t {
    var attr = Attr{
        .map_create = std.mem.zeroes(MapCreateAttr),
    };

    attr.map_create.map_type = @intFromEnum(map_type);
    attr.map_create.key_size = key_size;
    attr.map_create.value_size = value_size;
    attr.map_create.max_entries = max_entries;

    const rc = linux.bpf(.map_create, &attr, @sizeOf(MapCreateAttr));
    switch (errno(rc)) {
        .SUCCESS => return @as(fd_t, @intCast(rc)),
        .INVAL => return error.MapTypeOrAttrInvalid,
        .NOMEM => return error.SystemResources,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

test "map_create" {
    const map = try map_create(.hash, 4, 4, 32);
    defer std.os.close(map);
}

pub fn map_lookup_elem(fd: fd_t, key: []const u8, value: []u8) !void {
    var attr = Attr{
        .map_elem = std.mem.zeroes(MapElemAttr),
    };

    attr.map_elem.map_fd = fd;
    attr.map_elem.key = @intFromPtr(key.ptr);
    attr.map_elem.result.value = @intFromPtr(value.ptr);

    const rc = linux.bpf(.map_lookup_elem, &attr, @sizeOf(MapElemAttr));
    switch (errno(rc)) {
        .SUCCESS => return,
        .BADF => return error.BadFd,
        .FAULT => unreachable,
        .INVAL => return error.FieldInAttrNeedsZeroing,
        .NOENT => return error.NotFound,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn map_update_elem(fd: fd_t, key: []const u8, value: []const u8, flags: u64) !void {
    var attr = Attr{
        .map_elem = std.mem.zeroes(MapElemAttr),
    };

    attr.map_elem.map_fd = fd;
    attr.map_elem.key = @intFromPtr(key.ptr);
    attr.map_elem.result = .{ .value = @intFromPtr(value.ptr) };
    attr.map_elem.flags = flags;

    const rc = linux.bpf(.map_update_elem, &attr, @sizeOf(MapElemAttr));
    switch (errno(rc)) {
        .SUCCESS => return,
        .@"2BIG" => return error.ReachedMaxEntries,
        .BADF => return error.BadFd,
        .FAULT => unreachable,
        .INVAL => return error.FieldInAttrNeedsZeroing,
        .NOMEM => return error.SystemResources,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn map_delete_elem(fd: fd_t, key: []const u8) !void {
    var attr = Attr{
        .map_elem = std.mem.zeroes(MapElemAttr),
    };

    attr.map_elem.map_fd = fd;
    attr.map_elem.key = @intFromPtr(key.ptr);

    const rc = linux.bpf(.map_delete_elem, &attr, @sizeOf(MapElemAttr));
    switch (errno(rc)) {
        .SUCCESS => return,
        .BADF => return error.BadFd,
        .FAULT => unreachable,
        .INVAL => return error.FieldInAttrNeedsZeroing,
        .NOENT => return error.NotFound,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

pub fn map_get_next_key(fd: fd_t, key: []const u8, next_key: []u8) !bool {
    var attr = Attr{
        .map_elem = std.mem.zeroes(MapElemAttr),
    };

    attr.map_elem.map_fd = fd;
    attr.map_elem.key = @intFromPtr(key.ptr);
    attr.map_elem.result.next_key = @intFromPtr(next_key.ptr);

    const rc = linux.bpf(.map_get_next_key, &attr, @sizeOf(MapElemAttr));
    switch (errno(rc)) {
        .SUCCESS => return true,
        .BADF => return error.BadFd,
        .FAULT => unreachable,
        .INVAL => return error.FieldInAttrNeedsZeroing,
        .NOENT => return false,
        .PERM => return error.PermissionDenied,
        else => |err| return unexpectedErrno(err),
    }
}

test "map lookup, update, and delete" {
    const key_size = 4;
    const value_size = 4;
    const map = try map_create(.hash, key_size, value_size, 1);
    defer std.os.close(map);

    const key = std.mem.zeroes([key_size]u8);
    var value = std.mem.zeroes([value_size]u8);

    // fails looking up value that doesn't exist
    try expectError(error.NotFound, map_lookup_elem(map, &key, &value));

    // succeed at updating and looking up element
    try map_update_elem(map, &key, &value, 0);
    try map_lookup_elem(map, &key, &value);

    // fails inserting more than max entries
    const second_key = [key_size]u8{ 0, 0, 0, 1 };
    try expectError(error.ReachedMaxEntries, map_update_elem(map, &second_key, &value, 0));

    // succeed at iterating all keys of map
    var lookup_key = [_]u8{ 1, 0, 0, 0 };
    var next_key = [_]u8{ 2, 3, 4, 5 }; // garbage value
    const status = try map_get_next_key(map, &lookup_key, &next_key);
    try expectEqual(status, true);
    try expectEqual(next_key, key);
    lookup_key = next_key;
    const status2 = try map_get_next_key(map, &lookup_key, &next_key);
    try expectEqual(status2, false);

    // succeed at deleting an existing elem
    try map_delete_elem(map, &key);
    try expectError(error.NotFound, map_lookup_elem(map, &key, &value));

    // fail at deleting a non-existing elem
    try expectError(error.NotFound, map_delete_elem(map, &key));
}

pub fn prog_load(
    prog_type: ProgType,
    insns: []const Insn,
    log: ?*Log,
    license: []const u8,
    kern_version: u32,
    flags: u32,
) !fd_t {
    var attr = Attr{
        .prog_load = std.mem.zeroes(ProgLoadAttr),
    };

    attr.prog_load.prog_type = @intFromEnum(prog_type);
    attr.prog_load.insns = @intFromPtr(insns.ptr);
    attr.prog_load.insn_cnt = @as(u32, @intCast(insns.len));
    attr.prog_load.license = @intFromPtr(license.ptr);
    attr.prog_load.kern_version = kern_version;
    attr.prog_load.prog_flags = flags;

    if (log) |l| {
        attr.prog_load.log_buf = @intFromPtr(l.buf.ptr);
        attr.prog_load.log_size = @as(u32, @intCast(l.buf.len));
        attr.prog_load.log_level = l.level;
    }

    const rc = linux.bpf(.prog_load, &attr, @sizeOf(ProgLoadAttr));
    return switch (errno(rc)) {
        .SUCCESS => @as(fd_t, @intCast(rc)),
        .ACCES => error.UnsafeProgram,
        .FAULT => unreachable,
        .INVAL => error.InvalidProgram,
        .PERM => error.PermissionDenied,
        else => |err| unexpectedErrno(err),
    };
}

test "prog_load" {
    // this should fail because it does not set r0 before exiting
    const bad_prog = [_]Insn{
        Insn.exit(),
    };

    const good_prog = [_]Insn{
        Insn.mov(.r0, 0),
        Insn.exit(),
    };

    const prog = try prog_load(.socket_filter, &good_prog, null, "MIT", 0, 0);
    defer std.os.close(prog);

    try expectError(error.UnsafeProgram, prog_load(.socket_filter, &bad_prog, null, "MIT", 0, 0));
}
pub const Header = packed struct {
    magic: u16,
    version: u8,
    flags: u8,
    hdr_len: u32,

    /// All offsets are in bytes relative to the end of this header
    func_info_off: u32,
    func_info_len: u32,
    line_info_off: u32,
    line_info_len: u32,
};

pub const InfoSec = packed struct {
    sec_name_off: u32,
    num_info: u32,
    // TODO: communicate that there is data here
    //data: [0]u8,
};
const std = @import("../../../std.zig");

pub const magic = 0xeb9f;
pub const version = 1;

pub const ext = @import("btf_ext.zig");

/// All offsets are in bytes relative to the end of this header
pub const Header = extern struct {
    magic: u16,
    version: u8,
    flags: u8,
    hdr_len: u32,

    /// offset of type section
    type_off: u32,

    /// length of type section
    type_len: u32,

    /// offset of string section
    str_off: u32,

    /// length of string section
    str_len: u32,
};

/// Max number of type identifiers
pub const max_type = 0xfffff;

/// Max offset into string section
pub const max_name_offset = 0xffffff;

/// Max number of struct/union/enum member of func args
pub const max_vlen = 0xffff;

pub const Type = extern struct {
    name_off: u32,
    info: packed struct(u32) {
        /// number of struct's members
        vlen: u16,

        unused_1: u8,
        kind: Kind,
        unused_2: u2,

        /// used by Struct, Union, and Fwd
        kind_flag: bool,
    },

    /// size is used by Int, Enum, Struct, Union, and DataSec, it tells the size
    /// of the type it is describing
    ///
    /// type is used by Ptr, Typedef, Volatile, Const, Restrict, Func,
    /// FuncProto, and Var. It is a type_id referring to another type
    size_type: extern union { size: u32, typ: u32 },
};

/// For some kinds, Type is immediately followed by extra data
pub const Kind = enum(u5) {
    unknown,
    int,
    ptr,
    array,
    @"struct",
    @"union",
    @"enum",
    fwd,
    typedef,
    @"volatile",
    @"const",
    restrict,
    func,
    func_proto,
    @"var",
    datasec,
    float,
    decl_tag,
    type_tag,
    enum64,
};

/// int kind is followed by this struct
pub const IntInfo = packed struct(u32) {
    bits: u8,
    reserved_1: u8,
    offset: u8,
    encoding: enum(u4) {
        signed = 1 << 0,
        char = 1 << 1,
        boolean = 1 << 2,
    },
    reserved_2: u4,
};

test "IntInfo is 32 bits" {
    try std.testing.expectEqual(@bitSizeOf(IntInfo), 32);
}

/// enum kind is followed by this struct
pub const Enum = extern struct {
    name_off: u32,
    val: i32,
};

/// enum64 kind is followed by this struct
pub const Enum64 = extern struct {
    name_off: u32,
    val_lo32: i32,
    val_hi32: i32,
};

/// array kind is followed by this struct
pub const Array = extern struct {
    typ: u32,
    index_type: u32,
    nelems: u32,
};

/// struct and union kinds are followed by multiple Member structs. The exact
/// number is stored in vlen
pub const Member = extern struct {
    name_off: u32,
    typ: u32,

    /// if the kind_flag is set, offset contains both member bitfield size and
    /// bit offset, the bitfield size is set for bitfield members. If the type
    /// info kind_flag is not set, the offset contains only bit offset
    offset: packed struct(u32) {
        bit: u24,
        bitfield_size: u8,
    },
};

/// func_proto is followed by multiple Params, the exact number is stored in vlen
pub const Param = extern struct {
    name_off: u32,
    typ: u32,
};

pub const VarLinkage = enum {
    static,
    global_allocated,
    global_extern,
};

pub const FuncLinkage = enum {
    static,
    global,
    external,
};

/// var kind is followed by a single Var struct to describe additional
/// information related to the variable such as its linkage
pub const Var = extern struct {
    linkage: u32,
};

/// datasec kind is followed by multiple VarSecInfo to describe all Var kind
/// types it contains along with it's in-section offset as well as size.
pub const VarSecInfo = extern struct {
    typ: u32,
    offset: u32,
    size: u32,
};

// decl_tag kind is followed by a single DeclTag struct to describe
// additional information related to the tag applied location.
// If component_idx == -1, the tag is applied to a struct, union,
// variable or function. Otherwise, it is applied to a struct/union
// member or a func argument, and component_idx indicates which member
// or argument (0 ... vlen-1).
pub const DeclTag = extern struct {
    component_idx: u32,
};
const std = @import("../../../std.zig");
const kern = @import("kern.zig");

const PtRegs = @compileError("TODO missing os bits: PtRegs");
const TcpHdr = @compileError("TODO missing os bits: TcpHdr");
const SkFullSock = @compileError("TODO missing os bits: SkFullSock");

// in BPF, all the helper calls
// TODO: when https://github.com/ziglang/zig/issues/1717 is here, make a nice
// function that uses the Helper enum
//
// Note, these function signatures were created from documentation found in
// '/usr/include/linux/bpf.h'
pub const map_lookup_elem: *align(1) const fn (map: *const kern.MapDef, key: ?*const anyopaque) ?*anyopaque = @ptrFromInt(1);
pub const map_update_elem: *align(1) const fn (map: *const kern.MapDef, key: ?*const anyopaque, value: ?*const anyopaque, flags: u64) c_long = @ptrFromInt(2);
pub const map_delete_elem: *align(1) const fn (map: *const kern.MapDef, key: ?*const anyopaque) c_long = @ptrFromInt(3);
pub const probe_read: *align(1) const fn (dst: ?*anyopaque, size: u32, unsafe_ptr: ?*const anyopaque) c_long = @ptrFromInt(4);
pub const ktime_get_ns: *align(1) const fn () u64 = @ptrFromInt(5);
pub const trace_printk: *align(1) const fn (fmt: [*:0]const u8, fmt_size: u32, arg1: u64, arg2: u64, arg3: u64) c_long = @ptrFromInt(6);
pub const get_prandom_u32: *align(1) const fn () u32 = @ptrFromInt(7);
pub const get_smp_processor_id: *align(1) const fn () u32 = @ptrFromInt(8);
pub const skb_store_bytes: *align(1) const fn (skb: *kern.SkBuff, offset: u32, from: ?*const anyopaque, len: u32, flags: u64) c_long = @ptrFromInt(9);
pub const l3_csum_replace: *align(1) const fn (skb: *kern.SkBuff, offset: u32, from: u64, to: u64, size: u64) c_long = @ptrFromInt(10);
pub const l4_csum_replace: *align(1) const fn (skb: *kern.SkBuff, offset: u32, from: u64, to: u64, flags: u64) c_long = @ptrFromInt(11);
pub const tail_call: *align(1) const fn (ctx: ?*anyopaque, prog_array_map: *const kern.MapDef, index: u32) c_long = @ptrFromInt(12);
pub const clone_redirect: *align(1) const fn (skb: *kern.SkBuff, ifindex: u32, flags: u64) c_long = @ptrFromInt(13);
pub const get_current_pid_tgid: *align(1) const fn () u64 = @ptrFromInt(14);
pub const get_current_uid_gid: *align(1) const fn () u64 = @ptrFromInt(15);
pub const get_current_comm: *align(1) const fn (buf: ?*anyopaque, size_of_buf: u32) c_long = @ptrFromInt(16);
pub const get_cgroup_classid: *align(1) const fn (skb: *kern.SkBuff) u32 = @ptrFromInt(17);
// Note vlan_proto is big endian
pub const skb_vlan_push: *align(1) const fn (skb: *kern.SkBuff, vlan_proto: u16, vlan_tci: u16) c_long = @ptrFromInt(18);
pub const skb_vlan_pop: *align(1) const fn (skb: *kern.SkBuff) c_long = @ptrFromInt(19);
pub const skb_get_tunnel_key: *align(1) const fn (skb: *kern.SkBuff, key: *kern.TunnelKey, size: u32, flags: u64) c_long = @ptrFromInt(20);
pub const skb_set_tunnel_key: *align(1) const fn (skb: *kern.SkBuff, key: *kern.TunnelKey, size: u32, flags: u64) c_long = @ptrFromInt(21);
pub const perf_event_read: *align(1) const fn (map: *const kern.MapDef, flags: u64) u64 = @ptrFromInt(22);
pub const redirect: *align(1) const fn (ifindex: u32, flags: u64) c_long = @ptrFromInt(23);
pub const get_route_realm: *align(1) const fn (skb: *kern.SkBuff) u32 = @ptrFromInt(24);
pub const perf_event_output: *align(1) const fn (ctx: ?*anyopaque, map: *const kern.MapDef, flags: u64, data: ?*anyopaque, size: u64) c_long = @ptrFromInt(25);
pub const skb_load_bytes: *align(1) const fn (skb: ?*anyopaque, offset: u32, to: ?*anyopaque, len: u32) c_long = @ptrFromInt(26);
pub const get_stackid: *align(1) const fn (ctx: ?*anyopaque, map: *const kern.MapDef, flags: u64) c_long = @ptrFromInt(27);
// from and to point to __be32
pub const csum_diff: *align(1) const fn (from: *u32, from_size: u32, to: *u32, to_size: u32, seed: u32) i64 = @ptrFromInt(28);
pub const skb_get_tunnel_opt: *align(1) const fn (skb: *kern.SkBuff, opt: ?*anyopaque, size: u32) c_long = @ptrFromInt(29);
pub const skb_set_tunnel_opt: *align(1) const fn (skb: *kern.SkBuff, opt: ?*anyopaque, size: u32) c_long = @ptrFromInt(30);
// proto is __be16
pub const skb_change_proto: *align(1) const fn (skb: *kern.SkBuff, proto: u16, flags: u64) c_long = @ptrFromInt(31);
pub const skb_change_type: *align(1) const fn (skb: *kern.SkBuff, skb_type: u32) c_long = @ptrFromInt(32);
pub const skb_under_cgroup: *align(1) const fn (skb: *kern.SkBuff, map: ?*const anyopaque, index: u32) c_long = @ptrFromInt(33);
pub const get_hash_recalc: *align(1) const fn (skb: *kern.SkBuff) u32 = @ptrFromInt(34);
pub const get_current_task: *align(1) const fn () u64 = @ptrFromInt(35);
pub const probe_write_user: *align(1) const fn (dst: ?*anyopaque, src: ?*const anyopaque, len: u32) c_long = @ptrFromInt(36);
pub const current_task_under_cgroup: *align(1) const fn (map: *const kern.MapDef, index: u32) c_long = @ptrFromInt(37);
pub const skb_change_tail: *align(1) const fn (skb: *kern.SkBuff, len: u32, flags: u64) c_long = @ptrFromInt(38);
pub const skb_pull_data: *align(1) const fn (skb: *kern.SkBuff, len: u32) c_long = @ptrFromInt(39);
pub const csum_update: *align(1) const fn (skb: *kern.SkBuff, csum: u32) i64 = @ptrFromInt(40);
pub const set_hash_invalid: *align(1) const fn (skb: *kern.SkBuff) void = @ptrFromInt(41);
pub const get_numa_node_id: *align(1) const fn () c_long = @ptrFromInt(42);
pub const skb_change_head: *align(1) const fn (skb: *kern.SkBuff, len: u32, flags: u64) c_long = @ptrFromInt(43);
pub const xdp_adjust_head: *align(1) const fn (xdp_md: *kern.XdpMd, delta: c_int) c_long = @ptrFromInt(44);
pub const probe_read_str: *align(1) const fn (dst: ?*anyopaque, size: u32, unsafe_ptr: ?*const anyopaque) c_long = @ptrFromInt(45);
pub const get_socket_cookie: *align(1) const fn (ctx: ?*anyopaque) u64 = @ptrFromInt(46);
pub const get_socket_uid: *align(1) const fn (skb: *kern.SkBuff) u32 = @ptrFromInt(47);
pub const set_hash: *align(1) const fn (skb: *kern.SkBuff, hash: u32) c_long = @ptrFromInt(48);
pub const setsockopt: *align(1) const fn (bpf_socket: *kern.SockOps, level: c_int, optname: c_int, optval: ?*anyopaque, optlen: c_int) c_long = @ptrFromInt(49);
pub const skb_adjust_room: *align(1) const fn (skb: *kern.SkBuff, len_diff: i32, mode: u32, flags: u64) c_long = @ptrFromInt(50);
pub const redirect_map: *align(1) const fn (map: *const kern.MapDef, key: u32, flags: u64) c_long = @ptrFromInt(51);
pub const sk_redirect_map: *align(1) const fn (skb: *kern.SkBuff, map: *const kern.MapDef, key: u32, flags: u64) c_long = @ptrFromInt(52);
pub const sock_map_update: *align(1) const fn (skops: *kern.SockOps, map: *const kern.MapDef, key: ?*anyopaque, flags: u64) c_long = @ptrFromInt(53);
pub const xdp_adjust_meta: *align(1) const fn (xdp_md: *kern.XdpMd, delta: c_int) c_long = @ptrFromInt(54);
pub const perf_event_read_value: *align(1) const fn (map: *const kern.MapDef, flags: u64, buf: *kern.PerfEventValue, buf_size: u32) c_long = @ptrFromInt(55);
pub const perf_prog_read_value: *align(1) const fn (ctx: *kern.PerfEventData, buf: *kern.PerfEventValue, buf_size: u32) c_long = @ptrFromInt(56);
pub const getsockopt: *align(1) const fn (bpf_socket: ?*anyopaque, level: c_int, optname: c_int, optval: ?*anyopaque, optlen: c_int) c_long = @ptrFromInt(57);
pub const override_return: *align(1) const fn (regs: *PtRegs, rc: u64) c_long = @ptrFromInt(58);
pub const sock_ops_cb_flags_set: *align(1) const fn (bpf_sock: *kern.SockOps, argval: c_int) c_long = @ptrFromInt(59);
pub const msg_redirect_map: *align(1) const fn (msg: *kern.SkMsgMd, map: *const kern.MapDef, key: u32, flags: u64) c_long = @ptrFromInt(60);
pub const msg_apply_bytes: *align(1) const fn (msg: *kern.SkMsgMd, bytes: u32) c_long = @ptrFromInt(61);
pub const msg_cork_bytes: *align(1) const fn (msg: *kern.SkMsgMd, bytes: u32) c_long = @ptrFromInt(62);
pub const msg_pull_data: *align(1) const fn (msg: *kern.SkMsgMd, start: u32, end: u32, flags: u64) c_long = @ptrFromInt(63);
pub const bind: *align(1) const fn (ctx: *kern.BpfSockAddr, addr: *kern.SockAddr, addr_len: c_int) c_long = @ptrFromInt(64);
pub const xdp_adjust_tail: *align(1) const fn (xdp_md: *kern.XdpMd, delta: c_int) c_long = @ptrFromInt(65);
pub const skb_get_xfrm_state: *align(1) const fn (skb: *kern.SkBuff, index: u32, xfrm_state: *kern.XfrmState, size: u32, flags: u64) c_long = @ptrFromInt(66);
pub const get_stack: *align(1) const fn (ctx: ?*anyopaque, buf: ?*anyopaque, size: u32, flags: u64) c_long = @ptrFromInt(67);
pub const skb_load_bytes_relative: *align(1) const fn (skb: ?*const anyopaque, offset: u32, to: ?*anyopaque, len: u32, start_header: u32) c_long = @ptrFromInt(68);
pub const fib_lookup: *align(1) const fn (ctx: ?*anyopaque, params: *kern.FibLookup, plen: c_int, flags: u32) c_long = @ptrFromInt(69);
pub const sock_hash_update: *align(1) const fn (skops: *kern.SockOps, map: *const kern.MapDef, key: ?*anyopaque, flags: u64) c_long = @ptrFromInt(70);
pub const msg_redirect_hash: *align(1) const fn (msg: *kern.SkMsgMd, map: *const kern.MapDef, key: ?*anyopaque, flags: u64) c_long = @ptrFromInt(71);
pub const sk_redirect_hash: *align(1) const fn (skb: *kern.SkBuff, map: *const kern.MapDef, key: ?*anyopaque, flags: u64) c_long = @ptrFromInt(72);
pub const lwt_push_encap: *align(1) const fn (skb: *kern.SkBuff, typ: u32, hdr: ?*anyopaque, len: u32) c_long = @ptrFromInt(73);
pub const lwt_seg6_store_bytes: *align(1) const fn (skb: *kern.SkBuff, offset: u32, from: ?*const anyopaque, len: u32) c_long = @ptrFromInt(74);
pub const lwt_seg6_adjust_srh: *align(1) const fn (skb: *kern.SkBuff, offset: u32, delta: i32) c_long = @ptrFromInt(75);
pub const lwt_seg6_action: *align(1) const fn (skb: *kern.SkBuff, action: u32, param: ?*anyopaque, param_len: u32) c_long = @ptrFromInt(76);
pub const rc_repeat: *align(1) const fn (ctx: ?*anyopaque) c_long = @ptrFromInt(77);
pub const rc_keydown: *align(1) const fn (ctx: ?*anyopaque, protocol: u32, scancode: u64, toggle: u32) c_long = @ptrFromInt(78);
pub const skb_cgroup_id: *align(1) const fn (skb: *kern.SkBuff) u64 = @ptrFromInt(79);
pub const get_current_cgroup_id: *align(1) const fn () u64 = @ptrFromInt(80);
pub const get_local_storage: *align(1) const fn (map: ?*anyopaque, flags: u64) ?*anyopaque = @ptrFromInt(81);
pub const sk_select_reuseport: *align(1) const fn (reuse: *kern.SkReusePortMd, map: *const kern.MapDef, key: ?*anyopaque, flags: u64) c_long = @ptrFromInt(82);
pub const skb_ancestor_cgroup_id: *align(1) const fn (skb: *kern.SkBuff, ancestor_level: c_int) u64 = @ptrFromInt(83);
pub const sk_lookup_tcp: *align(1) const fn (ctx: ?*anyopaque, tuple: *kern.SockTuple, tuple_size: u32, netns: u64, flags: u64) ?*kern.Sock = @ptrFromInt(84);
pub const sk_lookup_udp: *align(1) const fn (ctx: ?*anyopaque, tuple: *kern.SockTuple, tuple_size: u32, netns: u64, flags: u64) ?*kern.Sock = @ptrFromInt(85);
pub const sk_release: *align(1) const fn (sock: *kern.Sock) c_long = @ptrFromInt(86);
pub const map_push_elem: *align(1) const fn (map: *const kern.MapDef, value: ?*const anyopaque, flags: u64) c_long = @ptrFromInt(87);
pub const map_pop_elem: *align(1) const fn (map: *const kern.MapDef, value: ?*anyopaque) c_long = @ptrFromInt(88);
pub const map_peek_elem: *align(1) const fn (map: *const kern.MapDef, value: ?*anyopaque) c_long = @ptrFromInt(89);
pub const msg_push_data: *align(1) const fn (msg: *kern.SkMsgMd, start: u32, len: u32, flags: u64) c_long = @ptrFromInt(90);
pub const msg_pop_data: *align(1) const fn (msg: *kern.SkMsgMd, start: u32, len: u32, flags: u64) c_long = @ptrFromInt(91);
pub const rc_pointer_rel: *align(1) const fn (ctx: ?*anyopaque, rel_x: i32, rel_y: i32) c_long = @ptrFromInt(92);
pub const spin_lock: *align(1) const fn (lock: *kern.SpinLock) c_long = @ptrFromInt(93);
pub const spin_unlock: *align(1) const fn (lock: *kern.SpinLock) c_long = @ptrFromInt(94);
pub const sk_fullsock: *align(1) const fn (sk: *kern.Sock) ?*SkFullSock = @ptrFromInt(95);
pub const tcp_sock: *align(1) const fn (sk: *kern.Sock) ?*kern.TcpSock = @ptrFromInt(96);
pub const skb_ecn_set_ce: *align(1) const fn (skb: *kern.SkBuff) c_long = @ptrFromInt(97);
pub const get_listener_sock: *align(1) const fn (sk: *kern.Sock) ?*kern.Sock = @ptrFromInt(98);
pub const skc_lookup_tcp: *align(1) const fn (ctx: ?*anyopaque, tuple: *kern.SockTuple, tuple_size: u32, netns: u64, flags: u64) ?*kern.Sock = @ptrFromInt(99);
pub const tcp_check_syncookie: *align(1) const fn (sk: *kern.Sock, iph: ?*anyopaque, iph_len: u32, th: *TcpHdr, th_len: u32) c_long = @ptrFromInt(100);
pub const sysctl_get_name: *align(1) const fn (ctx: *kern.SysCtl, buf: ?*u8, buf_len: c_ulong, flags: u64) c_long = @ptrFromInt(101);
pub const sysctl_get_current_value: *align(1) const fn (ctx: *kern.SysCtl, buf: ?*u8, buf_len: c_ulong) c_long = @ptrFromInt(102);
pub const sysctl_get_new_value: *align(1) const fn (ctx: *kern.SysCtl, buf: ?*u8, buf_len: c_ulong) c_long = @ptrFromInt(103);
pub const sysctl_set_new_value: *align(1) const fn (ctx: *kern.SysCtl, buf: ?*const u8, buf_len: c_ulong) c_long = @ptrFromInt(104);
pub const strtol: *align(1) const fn (buf: *const u8, buf_len: c_ulong, flags: u64, res: *c_long) c_long = @ptrFromInt(105);
pub const strtoul: *align(1) const fn (buf: *const u8, buf_len: c_ulong, flags: u64, res: *c_ulong) c_long = @ptrFromInt(106);
pub const sk_storage_get: *align(1) const fn (map: *const kern.MapDef, sk: *kern.Sock, value: ?*anyopaque, flags: u64) ?*anyopaque = @ptrFromInt(107);
pub const sk_storage_delete: *align(1) const fn (map: *const kern.MapDef, sk: *kern.Sock) c_long = @ptrFromInt(108);
pub const send_signal: *align(1) const fn (sig: u32) c_long = @ptrFromInt(109);
pub const tcp_gen_syncookie: *align(1) const fn (sk: *kern.Sock, iph: ?*anyopaque, iph_len: u32, th: *TcpHdr, th_len: u32) i64 = @ptrFromInt(110);
pub const skb_output: *align(1) const fn (ctx: ?*anyopaque, map: *const kern.MapDef, flags: u64, data: ?*anyopaque, size: u64) c_long = @ptrFromInt(111);
pub const probe_read_user: *align(1) const fn (dst: ?*anyopaque, size: u32, unsafe_ptr: ?*const anyopaque) c_long = @ptrFromInt(112);
pub const probe_read_kernel: *align(1) const fn (dst: ?*anyopaque, size: u32, unsafe_ptr: ?*const anyopaque) c_long = @ptrFromInt(113);
pub const probe_read_user_str: *align(1) const fn (dst: ?*anyopaque, size: u32, unsafe_ptr: ?*const anyopaque) c_long = @ptrFromInt(114);
pub const probe_read_kernel_str: *align(1) const fn (dst: ?*anyopaque, size: u32, unsafe_ptr: ?*const anyopaque) c_long = @ptrFromInt(115);
pub const tcp_send_ack: *align(1) const fn (tp: ?*anyopaque, rcv_nxt: u32) c_long = @ptrFromInt(116);
pub const send_signal_thread: *align(1) const fn (sig: u32) c_long = @ptrFromInt(117);
pub const jiffies64: *align(1) const fn () u64 = @ptrFromInt(118);
pub const read_branch_records: *align(1) const fn (ctx: *kern.PerfEventData, buf: ?*anyopaque, size: u32, flags: u64) c_long = @ptrFromInt(119);
pub const get_ns_current_pid_tgid: *align(1) const fn (dev: u64, ino: u64, nsdata: *kern.PidNsInfo, size: u32) c_long = @ptrFromInt(120);
pub const xdp_output: *align(1) const fn (ctx: ?*anyopaque, map: *const kern.MapDef, flags: u64, data: ?*anyopaque, size: u64) c_long = @ptrFromInt(121);
pub const get_netns_cookie: *align(1) const fn (ctx: ?*anyopaque) u64 = @ptrFromInt(122);
pub const get_current_ancestor_cgroup_id: *align(1) const fn (ancestor_level: c_int) u64 = @ptrFromInt(123);
pub const sk_assign: *align(1) const fn (skb: *kern.SkBuff, sk: *kern.Sock, flags: u64) c_long = @ptrFromInt(124);
pub const ktime_get_boot_ns: *align(1) const fn () u64 = @ptrFromInt(125);
pub const seq_printf: *align(1) const fn (m: *kern.SeqFile, fmt: ?*const u8, fmt_size: u32, data: ?*const anyopaque, data_len: u32) c_long = @ptrFromInt(126);
pub const seq_write: *align(1) const fn (m: *kern.SeqFile, data: ?*const u8, len: u32) c_long = @ptrFromInt(127);
pub const sk_cgroup_id: *align(1) const fn (sk: *kern.BpfSock) u64 = @ptrFromInt(128);
pub const sk_ancestor_cgroup_id: *align(1) const fn (sk: *kern.BpfSock, ancestor_level: c_long) u64 = @ptrFromInt(129);
pub const ringbuf_output: *align(1) const fn (ringbuf: ?*anyopaque, data: ?*anyopaque, size: u64, flags: u64) c_long = @ptrFromInt(130);
pub const ringbuf_reserve: *align(1) const fn (ringbuf: ?*anyopaque, size: u64, flags: u64) ?*anyopaque = @ptrFromInt(131);
pub const ringbuf_submit: *align(1) const fn (data: ?*anyopaque, flags: u64) void = @ptrFromInt(132);
pub const ringbuf_discard: *align(1) const fn (data: ?*anyopaque, flags: u64) void = @ptrFromInt(133);
pub const ringbuf_query: *align(1) const fn (ringbuf: ?*anyopaque, flags: u64) u64 = @ptrFromInt(134);
pub const csum_level: *align(1) const fn (skb: *kern.SkBuff, level: u64) c_long = @ptrFromInt(135);
pub const skc_to_tcp6_sock: *align(1) const fn (sk: ?*anyopaque) ?*kern.Tcp6Sock = @ptrFromInt(136);
pub const skc_to_tcp_sock: *align(1) const fn (sk: ?*anyopaque) ?*kern.TcpSock = @ptrFromInt(137);
pub const skc_to_tcp_timewait_sock: *align(1) const fn (sk: ?*anyopaque) ?*kern.TcpTimewaitSock = @ptrFromInt(138);
pub const skc_to_tcp_request_sock: *align(1) const fn (sk: ?*anyopaque) ?*kern.TcpRequestSock = @ptrFromInt(139);
pub const skc_to_udp6_sock: *align(1) const fn (sk: ?*anyopaque) ?*kern.Udp6Sock = @ptrFromInt(140);
pub const get_task_stack: *align(1) const fn (task: ?*anyopaque, buf: ?*anyopaque, size: u32, flags: u64) c_long = @ptrFromInt(141);
pub const load_hdr_opt: *align(1) const fn (?*kern.BpfSockOps, ?*anyopaque, u32, u64) c_long = @ptrFromInt(142);
pub const store_hdr_opt: *align(1) const fn (?*kern.BpfSockOps, ?*const anyopaque, u32, u64) c_long = @ptrFromInt(143);
pub const reserve_hdr_opt: *align(1) const fn (?*kern.BpfSockOps, u32, u64) c_long = @ptrFromInt(144);
pub const inode_storage_get: *align(1) const fn (?*anyopaque, ?*anyopaque, ?*anyopaque, u64) ?*anyopaque = @ptrFromInt(145);
pub const inode_storage_delete: *align(1) const fn (?*anyopaque, ?*anyopaque) c_int = @ptrFromInt(146);
pub const d_path: *align(1) const fn (?*kern.Path, [*c]u8, u32) c_long = @ptrFromInt(147);
pub const copy_from_user: *align(1) const fn (?*anyopaque, u32, ?*const anyopaque) c_long = @ptrFromInt(148);
pub const snprintf_btf: *align(1) const fn ([*c]u8, u32, ?*kern.BTFPtr, u32, u64) c_long = @ptrFromInt(149);
pub const seq_printf_btf: *align(1) const fn (?*kern.SeqFile, ?*kern.BTFPtr, u32, u64) c_long = @ptrFromInt(150);
pub const skb_cgroup_classid: *align(1) const fn (?*kern.SkBuff) u64 = @ptrFromInt(151);
pub const redirect_neigh: *align(1) const fn (u32, ?*kern.BpfRedirNeigh, c_int, u64) c_long = @ptrFromInt(152);
pub const per_cpu_ptr: *align(1) const fn (?*const anyopaque, u32) ?*anyopaque = @ptrFromInt(153);
pub const this_cpu_ptr: *align(1) const fn (?*const anyopaque) ?*anyopaque = @ptrFromInt(154);
pub const redirect_peer: *align(1) const fn (u32, u64) c_long = @ptrFromInt(155);
pub const task_storage_get: *align(1) const fn (?*anyopaque, ?*kern.Task, ?*anyopaque, u64) ?*anyopaque = @ptrFromInt(156);
pub const task_storage_delete: *align(1) const fn (?*anyopaque, ?*kern.Task) c_long = @ptrFromInt(157);
pub const get_current_task_btf: *align(1) const fn () ?*kern.Task = @ptrFromInt(158);
pub const bprm_opts_set: *align(1) const fn (?*kern.BinPrm, u64) c_long = @ptrFromInt(159);
pub const ktime_get_coarse_ns: *align(1) const fn () u64 = @ptrFromInt(160);
pub const ima_inode_hash: *align(1) const fn (?*kern.Inode, ?*anyopaque, u32) c_long = @ptrFromInt(161);
pub const sock_from_file: *align(1) const fn (?*kern.File) ?*kern.Socket = @ptrFromInt(162);
pub const check_mtu: *align(1) const fn (?*anyopaque, u32, [*c]u32, i32, u64) c_long = @ptrFromInt(163);
pub const for_each_map_elem: *align(1) const fn (?*anyopaque, ?*anyopaque, ?*anyopaque, u64) c_long = @ptrFromInt(164);
pub const snprintf: *align(1) const fn ([*c]u8, u32, [*c]const u8, [*c]u64, u32) c_long = @ptrFromInt(165);
pub const sys_bpf: *align(1) const fn (u32, ?*anyopaque, u32) c_long = @ptrFromInt(166);
pub const btf_find_by_name_kind: *align(1) const fn ([*c]u8, c_int, u32, c_int) c_long = @ptrFromInt(167);
pub const sys_close: *align(1) const fn (u32) c_long = @ptrFromInt(168);
pub const timer_init: *align(1) const fn (?*kern.BpfTimer, ?*anyopaque, u64) c_long = @ptrFromInt(169);
pub const timer_set_callback: *align(1) const fn (?*kern.BpfTimer, ?*anyopaque) c_long = @ptrFromInt(170);
pub const timer_start: *align(1) const fn (?*kern.BpfTimer, u64, u64) c_long = @ptrFromInt(171);
pub const timer_cancel: *align(1) const fn (?*kern.BpfTimer) c_long = @ptrFromInt(172);
pub const get_func_ip: *align(1) const fn (?*anyopaque) u64 = @ptrFromInt(173);
pub const get_attach_cookie: *align(1) const fn (?*anyopaque) u64 = @ptrFromInt(174);
pub const task_pt_regs: *align(1) const fn (?*kern.Task) c_long = @ptrFromInt(175);
pub const get_branch_snapshot: *align(1) const fn (?*anyopaque, u32, u64) c_long = @ptrFromInt(176);
pub const trace_vprintk: *align(1) const fn ([*c]const u8, u32, ?*const anyopaque, u32) c_long = @ptrFromInt(177);
pub const skc_to_unix_sock: *align(1) const fn (?*anyopaque) ?*kern.UnixSock = @ptrFromInt(178);
pub const kallsyms_lookup_name: *align(1) const fn ([*c]const u8, c_int, c_int, [*c]u64) c_long = @ptrFromInt(179);
pub const find_vma: *align(1) const fn (?*kern.Task, u64, ?*anyopaque, ?*anyopaque, u64) c_long = @ptrFromInt(180);
pub const loop: *align(1) const fn (u32, ?*anyopaque, ?*anyopaque, u64) c_long = @ptrFromInt(181);
pub const strncmp: *align(1) const fn ([*c]const u8, u32, [*c]const u8) c_long = @ptrFromInt(182);
pub const get_func_arg: *align(1) const fn (?*anyopaque, u32, [*c]u64) c_long = @ptrFromInt(183);
pub const get_func_ret: *align(1) const fn (?*anyopaque, [*c]u64) c_long = @ptrFromInt(184);
pub const get_func_arg_cnt: *align(1) const fn (?*anyopaque) c_long = @ptrFromInt(185);
pub const get_retval: *align(1) const fn () c_int = @ptrFromInt(186);
pub const set_retval: *align(1) const fn (c_int) c_int = @ptrFromInt(187);
pub const xdp_get_buff_len: *align(1) const fn (?*kern.XdpMd) u64 = @ptrFromInt(188);
pub const xdp_load_bytes: *align(1) const fn (?*kern.XdpMd, u32, ?*anyopaque, u32) c_long = @ptrFromInt(189);
pub const xdp_store_bytes: *align(1) const fn (?*kern.XdpMd, u32, ?*anyopaque, u32) c_long = @ptrFromInt(190);
pub const copy_from_user_task: *align(1) const fn (?*anyopaque, u32, ?*const anyopaque, ?*kern.Task, u64) c_long = @ptrFromInt(191);
pub const skb_set_tstamp: *align(1) const fn (?*kern.SkBuff, u64, u32) c_long = @ptrFromInt(192);
pub const ima_file_hash: *align(1) const fn (?*kern.File, ?*anyopaque, u32) c_long = @ptrFromInt(193);
pub const kptr_xchg: *align(1) const fn (?*anyopaque, ?*anyopaque) ?*anyopaque = @ptrFromInt(194);
pub const map_lookup_percpu_elem: *align(1) const fn (?*anyopaque, ?*const anyopaque, u32) ?*anyopaque = @ptrFromInt(195);
pub const skc_to_mptcp_sock: *align(1) const fn (?*anyopaque) ?*kern.MpTcpSock = @ptrFromInt(196);
pub const dynptr_from_mem: *align(1) const fn (?*anyopaque, u32, u64, ?*kern.BpfDynPtr) c_long = @ptrFromInt(197);
pub const ringbuf_reserve_dynptr: *align(1) const fn (?*anyopaque, u32, u64, ?*kern.BpfDynPtr) c_long = @ptrFromInt(198);
pub const ringbuf_submit_dynptr: *align(1) const fn (?*kern.BpfDynPtr, u64) void = @ptrFromInt(199);
pub const ringbuf_discard_dynptr: *align(1) const fn (?*kern.BpfDynPtr, u64) void = @ptrFromInt(200);
pub const dynptr_read: *align(1) const fn (?*anyopaque, u32, ?*kern.BpfDynPtr, u32, u64) c_long = @ptrFromInt(201);
pub const dynptr_write: *align(1) const fn (?*kern.BpfDynPtr, u32, ?*anyopaque, u32, u64) c_long = @ptrFromInt(202);
pub const dynptr_data: *align(1) const fn (?*kern.BpfDynPtr, u32, u32) ?*anyopaque = @ptrFromInt(203);
pub const tcp_raw_gen_syncookie_ipv4: *align(1) const fn (?*kern.IpHdr, ?*TcpHdr, u32) i64 = @ptrFromInt(204);
pub const tcp_raw_gen_syncookie_ipv6: *align(1) const fn (?*kern.Ipv6Hdr, ?*TcpHdr, u32) i64 = @ptrFromInt(205);
pub const tcp_raw_check_syncookie_ipv4: *align(1) const fn (?*kern.IpHdr, ?*TcpHdr) c_long = @ptrFromInt(206);
pub const tcp_raw_check_syncookie_ipv6: *align(1) const fn (?*kern.Ipv6Hdr, ?*TcpHdr) c_long = @ptrFromInt(207);
pub const ktime_get_tai_ns: *align(1) const fn () u64 = @ptrFromInt(208);
pub const user_ringbuf_drain: *align(1) const fn (?*anyopaque, ?*anyopaque, ?*anyopaque, u64) c_long = @ptrFromInt(209);
const std = @import("../../../std.zig");
const builtin = @import("builtin");

const in_bpf_program = switch (builtin.cpu.arch) {
    .bpfel, .bpfeb => true,
    else => false,
};

pub const helpers = if (in_bpf_program) @import("helpers.zig") else struct {};

pub const BinPrm = opaque {};
pub const BTFPtr = opaque {};
pub const BpfDynPtr = opaque {};
pub const BpfRedirNeigh = opaque {};
pub const BpfSock = opaque {};
pub const BpfSockAddr = opaque {};
pub const BpfSockOps = opaque {};
pub const BpfTimer = opaque {};
pub const FibLookup = opaque {};
pub const File = opaque {};
pub const Inode = opaque {};
pub const IpHdr = opaque {};
pub const Ipv6Hdr = opaque {};
pub const MapDef = opaque {};
pub const MpTcpSock = opaque {};
pub const Path = opaque {};
pub const PerfEventData = opaque {};
pub const PerfEventValue = opaque {};
pub const PidNsInfo = opaque {};
pub const SeqFile = opaque {};
pub const SkBuff = opaque {};
pub const SkMsgMd = opaque {};
pub const SkReusePortMd = opaque {};
pub const Sock = opaque {};
pub const Socket = opaque {};
pub const SockAddr = opaque {};
pub const SockOps = opaque {};
pub const SockTuple = opaque {};
pub const SpinLock = opaque {};
pub const SysCtl = opaque {};
pub const Task = opaque {};
pub const Tcp6Sock = opaque {};
pub const TcpRequestSock = opaque {};
pub const TcpSock = opaque {};
pub const TcpTimewaitSock = opaque {};
pub const TunnelKey = opaque {};
pub const Udp6Sock = opaque {};
pub const UnixSock = opaque {};
pub const XdpMd = opaque {};
pub const XfrmState = opaque {};
const builtin = @import("builtin");
const std = @import("../../std.zig");
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const linux = std.os.linux;
const SYS = linux.SYS;
const uid_t = std.os.linux.uid_t;
const gid_t = std.os.linux.gid_t;
const pid_t = std.os.linux.pid_t;
const sockaddr = linux.sockaddr;
const socklen_t = linux.socklen_t;
const timespec = std.os.linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile ("trap0(#1)"
        : [ret] "={r0}" (-> usize),
        : [number] "{r6}" (@intFromEnum(number)),
        : "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile ("trap0(#1)"
        : [ret] "={r0}" (-> usize),
        : [number] "{r6}" (@intFromEnum(number)),
          [arg1] "{r0}" (arg1),
        : "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile ("trap0(#1)"
        : [ret] "={r0}" (-> usize),
        : [number] "{r6}" (@intFromEnum(number)),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
        : "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile ("trap0(#1)"
        : [ret] "={r0}" (-> usize),
        : [number] "{r6}" (@intFromEnum(number)),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
          [arg3] "{r2}" (arg3),
        : "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile ("trap0(#1)"
        : [ret] "={r0}" (-> usize),
        : [number] "{r6}" (@intFromEnum(number)),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
          [arg3] "{r2}" (arg3),
          [arg4] "{r3}" (arg4),
        : "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile ("trap0(#1)"
        : [ret] "={r0}" (-> usize),
        : [number] "{r6}" (@intFromEnum(number)),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
          [arg3] "{r2}" (arg3),
          [arg4] "{r3}" (arg4),
          [arg5] "{r4}" (arg5),
        : "memory"
    );
}

pub fn syscall6(
    number: SYS,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) usize {
    return asm volatile ("trap0(#1)"
        : [ret] "={r0}" (-> usize),
        : [number] "{r6}" (@intFromEnum(number)),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
          [arg3] "{r2}" (arg3),
          [arg4] "{r3}" (arg4),
          [arg5] "{r4}" (arg5),
          [arg6] "{r5}" (arg6),
        : "memory"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //         r0,   r1,    r2,    r3,  r4,   r5,  +0
    //
    // syscall(SYS_clone, flags, stack, ptid, ctid, tls)
    //         r6         r0,    r1,    r2,   r3,   r4
    asm volatile (
        \\ allocframe(#8)
        \\
        \\ r11 = r0
        \\ r10 = r3
        \\
        \\ r6 = #220 // SYS_clone
        \\ r0 = r2
        \\ r1 = and(r1, #-8)
        \\ r2 = r4
        \\ r3 = memw(r30 + #8)
        \\ r4 = r5
        \\ trap0(#1)
        \\
        \\ p0 = cmp.eq(r0, #0)
        \\ if (!p0) dealloc_return
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\ .cfi_undefined r31
    );
    asm volatile (
        \\ r30 = #0
        \\ r31 = #0
        \\
        \\ r0 = r10
        \\ callr r11
        \\
        \\ r6 = #93 // SYS_exit
        \\ r0 = #0
        \\ trap0(#1)
    );
}

pub const restore = restore_rt;

pub fn restore_rt() callconv(.naked) noreturn {
    asm volatile (
        \\ trap0(#0)
        :
        : [number] "{r6}" (@intFromEnum(SYS.rt_sigreturn)),
        : "memory"
    );
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;
    pub const GETLK = 5;
    pub const SETLK = 6;
    pub const SETLKW = 7;
    pub const SETOWN = 8;
    pub const GETOWN = 9;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const timeval = extern struct {
    sec: time_t,
    usec: i32,
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    start: off_t,
    len: off_t,
    pid: pid_t,
    __unused: [4]u8,
};

pub const msghdr = extern struct {
    name: ?*sockaddr,
    namelen: socklen_t,
    iov: [*]iovec,
    iovlen: i32,
    __pad1: i32 = 0,
    control: ?*anyopaque,
    controllen: socklen_t,
    __pad2: socklen_t = 0,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    iovlen: i32,
    __pad1: i32 = 0,
    control: ?*const anyopaque,
    controllen: socklen_t,
    __pad2: socklen_t = 0,
    flags: i32,
};

pub const blksize_t = i32;
pub const nlink_t = u32;
pub const time_t = i32;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u64;
pub const blkcnt_t = i64;

// The `stat` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    ino: ino_t,
    mode: mode_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    __pad: u32,
    size: off_t,
    blksize: blksize_t,
    __pad2: i32,
    blocks: blkcnt_t,
    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    __unused: [2]u32,

    pub fn atime(self: @This()) timespec {
        return self.atim;
    }

    pub fn mtime(self: @This()) timespec {
        return self.mtim;
    }

    pub fn ctime(self: @This()) timespec {
        return self.ctim;
    }
};

pub const Elf_Symndx = u32;

pub const VDSO = void;

/// TODO
pub const ucontext_t = void;

/// TODO
pub const getcontext = {};
//! Contains only the definition of `io_uring_sqe`.
//! Split into its own file to compartmentalize the initialization methods.

const std = @import("../../std.zig");
const linux = std.os.linux;

pub const io_uring_sqe = extern struct {
    opcode: linux.IORING_OP,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    rw_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    addr3: u64,
    resv: u64,

    pub fn prep_nop(sqe: *linux.io_uring_sqe) void {
        sqe.* = .{
            .opcode = .NOP,
            .flags = 0,
            .ioprio = 0,
            .fd = 0,
            .off = 0,
            .addr = 0,
            .len = 0,
            .rw_flags = 0,
            .user_data = 0,
            .buf_index = 0,
            .personality = 0,
            .splice_fd_in = 0,
            .addr3 = 0,
            .resv = 0,
        };
    }

    pub fn prep_fsync(sqe: *linux.io_uring_sqe, fd: linux.fd_t, flags: u32) void {
        sqe.* = .{
            .opcode = .FSYNC,
            .flags = 0,
            .ioprio = 0,
            .fd = fd,
            .off = 0,
            .addr = 0,
            .len = 0,
            .rw_flags = flags,
            .user_data = 0,
            .buf_index = 0,
            .personality = 0,
            .splice_fd_in = 0,
            .addr3 = 0,
            .resv = 0,
        };
    }

    pub fn prep_rw(
        sqe: *linux.io_uring_sqe,
        op: linux.IORING_OP,
        fd: linux.fd_t,
        addr: u64,
        len: usize,
        offset: u64,
    ) void {
        sqe.* = .{
            .opcode = op,
            .flags = 0,
            .ioprio = 0,
            .fd = fd,
            .off = offset,
            .addr = addr,
            .len = @intCast(len),
            .rw_flags = 0,
            .user_data = 0,
            .buf_index = 0,
            .personality = 0,
            .splice_fd_in = 0,
            .addr3 = 0,
            .resv = 0,
        };
    }

    pub fn prep_read(sqe: *linux.io_uring_sqe, fd: linux.fd_t, buffer: []u8, offset: u64) void {
        sqe.prep_rw(.READ, fd, @intFromPtr(buffer.ptr), buffer.len, offset);
    }

    pub fn prep_write(sqe: *linux.io_uring_sqe, fd: linux.fd_t, buffer: []const u8, offset: u64) void {
        sqe.prep_rw(.WRITE, fd, @intFromPtr(buffer.ptr), buffer.len, offset);
    }

    pub fn prep_splice(sqe: *linux.io_uring_sqe, fd_in: linux.fd_t, off_in: u64, fd_out: linux.fd_t, off_out: u64, len: usize) void {
        sqe.prep_rw(.SPLICE, fd_out, undefined, len, off_out);
        sqe.addr = off_in;
        sqe.splice_fd_in = fd_in;
    }

    pub fn prep_readv(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        iovecs: []const std.posix.iovec,
        offset: u64,
    ) void {
        sqe.prep_rw(.READV, fd, @intFromPtr(iovecs.ptr), iovecs.len, offset);
    }

    pub fn prep_writev(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        iovecs: []const std.posix.iovec_const,
        offset: u64,
    ) void {
        sqe.prep_rw(.WRITEV, fd, @intFromPtr(iovecs.ptr), iovecs.len, offset);
    }

    pub fn prep_read_fixed(sqe: *linux.io_uring_sqe, fd: linux.fd_t, buffer: *std.posix.iovec, offset: u64, buffer_index: u16) void {
        sqe.prep_rw(.READ_FIXED, fd, @intFromPtr(buffer.base), buffer.len, offset);
        sqe.buf_index = buffer_index;
    }

    pub fn prep_write_fixed(sqe: *linux.io_uring_sqe, fd: linux.fd_t, buffer: *std.posix.iovec, offset: u64, buffer_index: u16) void {
        sqe.prep_rw(.WRITE_FIXED, fd, @intFromPtr(buffer.base), buffer.len, offset);
        sqe.buf_index = buffer_index;
    }

    pub fn prep_accept(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        addr: ?*linux.sockaddr,
        addrlen: ?*linux.socklen_t,
        flags: u32,
    ) void {
        // `addr` holds a pointer to `sockaddr`, and `addr2` holds a pointer to socklen_t`.
        // `addr2` maps to `sqe.off` (u64) instead of `sqe.len` (which is only a u32).
        sqe.prep_rw(.ACCEPT, fd, @intFromPtr(addr), 0, @intFromPtr(addrlen));
        sqe.rw_flags = flags;
    }

    pub fn prep_accept_direct(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        addr: ?*linux.sockaddr,
        addrlen: ?*linux.socklen_t,
        flags: u32,
        file_index: u32,
    ) void {
        prep_accept(sqe, fd, addr, addrlen, flags);
        __io_uring_set_target_fixed_file(sqe, file_index);
    }

    pub fn prep_multishot_accept_direct(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        addr: ?*linux.sockaddr,
        addrlen: ?*linux.socklen_t,
        flags: u32,
    ) void {
        prep_multishot_accept(sqe, fd, addr, addrlen, flags);
        __io_uring_set_target_fixed_file(sqe, linux.IORING_FILE_INDEX_ALLOC);
    }

    fn __io_uring_set_target_fixed_file(sqe: *linux.io_uring_sqe, file_index: u32) void {
        const sqe_file_index: u32 = if (file_index == linux.IORING_FILE_INDEX_ALLOC)
            linux.IORING_FILE_INDEX_ALLOC
        else
            // 0 means no fixed files, indexes should be encoded as "index + 1"
            file_index + 1;
        // This filed is overloaded in liburing:
        //   splice_fd_in: i32
        //   sqe_file_index: u32
        sqe.splice_fd_in = @bitCast(sqe_file_index);
    }

    pub fn prep_connect(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        addr: *const linux.sockaddr,
        addrlen: linux.socklen_t,
    ) void {
        // `addrlen` maps to `sqe.off` (u64) instead of `sqe.len` (which is only a u32).
        sqe.prep_rw(.CONNECT, fd, @intFromPtr(addr), 0, addrlen);
    }

    pub fn prep_epoll_ctl(
        sqe: *linux.io_uring_sqe,
        epfd: linux.fd_t,
        fd: linux.fd_t,
        op: u32,
        ev: ?*linux.epoll_event,
    ) void {
        sqe.prep_rw(.EPOLL_CTL, epfd, @intFromPtr(ev), op, @intCast(fd));
    }

    pub fn prep_recv(sqe: *linux.io_uring_sqe, fd: linux.fd_t, buffer: []u8, flags: u32) void {
        sqe.prep_rw(.RECV, fd, @intFromPtr(buffer.ptr), buffer.len, 0);
        sqe.rw_flags = flags;
    }

    pub fn prep_recv_multishot(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        buffer: []u8,
        flags: u32,
    ) void {
        sqe.prep_recv(fd, buffer, flags);
        sqe.ioprio |= linux.IORING_RECV_MULTISHOT;
    }

    pub fn prep_recvmsg(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        msg: *linux.msghdr,
        flags: u32,
    ) void {
        sqe.prep_rw(.RECVMSG, fd, @intFromPtr(msg), 1, 0);
        sqe.rw_flags = flags;
    }

    pub fn prep_recvmsg_multishot(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        msg: *linux.msghdr,
        flags: u32,
    ) void {
        sqe.prep_recvmsg(fd, msg, flags);
        sqe.ioprio |= linux.IORING_RECV_MULTISHOT;
    }

    pub fn prep_send(sqe: *linux.io_uring_sqe, fd: linux.fd_t, buffer: []const u8, flags: u32) void {
        sqe.prep_rw(.SEND, fd, @intFromPtr(buffer.ptr), buffer.len, 0);
        sqe.rw_flags = flags;
    }

    pub fn prep_send_zc(sqe: *linux.io_uring_sqe, fd: linux.fd_t, buffer: []const u8, flags: u32, zc_flags: u16) void {
        sqe.prep_rw(.SEND_ZC, fd, @intFromPtr(buffer.ptr), buffer.len, 0);
        sqe.rw_flags = flags;
        sqe.ioprio = zc_flags;
    }

    pub fn prep_send_zc_fixed(sqe: *linux.io_uring_sqe, fd: linux.fd_t, buffer: []const u8, flags: u32, zc_flags: u16, buf_index: u16) void {
        prep_send_zc(sqe, fd, buffer, flags, zc_flags);
        sqe.ioprio |= linux.IORING_RECVSEND_FIXED_BUF;
        sqe.buf_index = buf_index;
    }

    pub fn prep_sendmsg_zc(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        msg: *const linux.msghdr_const,
        flags: u32,
    ) void {
        prep_sendmsg(sqe, fd, msg, flags);
        sqe.opcode = .SENDMSG_ZC;
    }

    pub fn prep_sendmsg(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        msg: *const linux.msghdr_const,
        flags: u32,
    ) void {
        sqe.prep_rw(.SENDMSG, fd, @intFromPtr(msg), 1, 0);
        sqe.rw_flags = flags;
    }

    pub fn prep_openat(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        path: [*:0]const u8,
        flags: linux.O,
        mode: linux.mode_t,
    ) void {
        sqe.prep_rw(.OPENAT, fd, @intFromPtr(path), mode, 0);
        sqe.rw_flags = @bitCast(flags);
    }

    pub fn prep_openat_direct(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        path: [*:0]const u8,
        flags: linux.O,
        mode: linux.mode_t,
        file_index: u32,
    ) void {
        prep_openat(sqe, fd, path, flags, mode);
        __io_uring_set_target_fixed_file(sqe, file_index);
    }

    pub fn prep_close(sqe: *linux.io_uring_sqe, fd: linux.fd_t) void {
        sqe.* = .{
            .opcode = .CLOSE,
            .flags = 0,
            .ioprio = 0,
            .fd = fd,
            .off = 0,
            .addr = 0,
            .len = 0,
            .rw_flags = 0,
            .user_data = 0,
            .buf_index = 0,
            .personality = 0,
            .splice_fd_in = 0,
            .addr3 = 0,
            .resv = 0,
        };
    }

    pub fn prep_close_direct(sqe: *linux.io_uring_sqe, file_index: u32) void {
        prep_close(sqe, 0);
        __io_uring_set_target_fixed_file(sqe, file_index);
    }

    pub fn prep_timeout(
        sqe: *linux.io_uring_sqe,
        ts: *const linux.kernel_timespec,
        count: u32,
        flags: u32,
    ) void {
        sqe.prep_rw(.TIMEOUT, -1, @intFromPtr(ts), 1, count);
        sqe.rw_flags = flags;
    }

    pub fn prep_timeout_remove(sqe: *linux.io_uring_sqe, timeout_user_data: u64, flags: u32) void {
        sqe.* = .{
            .opcode = .TIMEOUT_REMOVE,
            .flags = 0,
            .ioprio = 0,
            .fd = -1,
            .off = 0,
            .addr = timeout_user_data,
            .len = 0,
            .rw_flags = flags,
            .user_data = 0,
            .buf_index = 0,
            .personality = 0,
            .splice_fd_in = 0,
            .addr3 = 0,
            .resv = 0,
        };
    }

    pub fn prep_link_timeout(
        sqe: *linux.io_uring_sqe,
        ts: *const linux.kernel_timespec,
        flags: u32,
    ) void {
        sqe.prep_rw(.LINK_TIMEOUT, -1, @intFromPtr(ts), 1, 0);
        sqe.rw_flags = flags;
    }

    pub fn prep_poll_add(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        poll_mask: u32,
    ) void {
        sqe.prep_rw(.POLL_ADD, fd, @intFromPtr(@as(?*anyopaque, null)), 0, 0);
        // Poll masks previously used to comprise of 16 bits in the flags union of
        // a SQE, but were then extended to comprise of 32 bits in order to make
        // room for additional option flags. To ensure that the correct bits of
        // poll masks are consistently and properly read across multiple kernel
        // versions, poll masks are enforced to be little-endian.
        // https://www.spinics.net/lists/io-uring/msg02848.html
        sqe.rw_flags = std.mem.nativeToLittle(u32, poll_mask);
    }

    pub fn prep_poll_remove(
        sqe: *linux.io_uring_sqe,
        target_user_data: u64,
    ) void {
        sqe.prep_rw(.POLL_REMOVE, -1, target_user_data, 0, 0);
    }

    pub fn prep_poll_update(
        sqe: *linux.io_uring_sqe,
        old_user_data: u64,
        new_user_data: u64,
        poll_mask: u32,
        flags: u32,
    ) void {
        sqe.prep_rw(.POLL_REMOVE, -1, old_user_data, flags, new_user_data);
        // Poll masks previously used to comprise of 16 bits in the flags union of
        // a SQE, but were then extended to comprise of 32 bits in order to make
        // room for additional option flags. To ensure that the correct bits of
        // poll masks are consistently and properly read across multiple kernel
        // versions, poll masks are enforced to be little-endian.
        // https://www.spinics.net/lists/io-uring/msg02848.html
        sqe.rw_flags = std.mem.nativeToLittle(u32, poll_mask);
    }

    pub fn prep_fallocate(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        mode: i32,
        offset: u64,
        len: u64,
    ) void {
        sqe.* = .{
            .opcode = .FALLOCATE,
            .flags = 0,
            .ioprio = 0,
            .fd = fd,
            .off = offset,
            .addr = len,
            .len = @intCast(mode),
            .rw_flags = 0,
            .user_data = 0,
            .buf_index = 0,
            .personality = 0,
            .splice_fd_in = 0,
            .addr3 = 0,
            .resv = 0,
        };
    }

    pub fn prep_statx(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        path: [*:0]const u8,
        flags: u32,
        mask: u32,
        buf: *linux.Statx,
    ) void {
        sqe.prep_rw(.STATX, fd, @intFromPtr(path), mask, @intFromPtr(buf));
        sqe.rw_flags = flags;
    }

    pub fn prep_cancel(
        sqe: *linux.io_uring_sqe,
        cancel_user_data: u64,
        flags: u32,
    ) void {
        sqe.prep_rw(.ASYNC_CANCEL, -1, cancel_user_data, 0, 0);
        sqe.rw_flags = flags;
    }

    pub fn prep_cancel_fd(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        flags: u32,
    ) void {
        sqe.prep_rw(.ASYNC_CANCEL, fd, 0, 0, 0);
        sqe.rw_flags = flags | linux.IORING_ASYNC_CANCEL_FD;
    }

    pub fn prep_shutdown(
        sqe: *linux.io_uring_sqe,
        sockfd: linux.socket_t,
        how: u32,
    ) void {
        sqe.prep_rw(.SHUTDOWN, sockfd, 0, how, 0);
    }

    pub fn prep_renameat(
        sqe: *linux.io_uring_sqe,
        old_dir_fd: linux.fd_t,
        old_path: [*:0]const u8,
        new_dir_fd: linux.fd_t,
        new_path: [*:0]const u8,
        flags: u32,
    ) void {
        sqe.prep_rw(
            .RENAMEAT,
            old_dir_fd,
            @intFromPtr(old_path),
            0,
            @intFromPtr(new_path),
        );
        sqe.len = @bitCast(new_dir_fd);
        sqe.rw_flags = flags;
    }

    pub fn prep_unlinkat(
        sqe: *linux.io_uring_sqe,
        dir_fd: linux.fd_t,
        path: [*:0]const u8,
        flags: u32,
    ) void {
        sqe.prep_rw(.UNLINKAT, dir_fd, @intFromPtr(path), 0, 0);
        sqe.rw_flags = flags;
    }

    pub fn prep_mkdirat(
        sqe: *linux.io_uring_sqe,
        dir_fd: linux.fd_t,
        path: [*:0]const u8,
        mode: linux.mode_t,
    ) void {
        sqe.prep_rw(.MKDIRAT, dir_fd, @intFromPtr(path), mode, 0);
    }

    pub fn prep_symlinkat(
        sqe: *linux.io_uring_sqe,
        target: [*:0]const u8,
        new_dir_fd: linux.fd_t,
        link_path: [*:0]const u8,
    ) void {
        sqe.prep_rw(
            .SYMLINKAT,
            new_dir_fd,
            @intFromPtr(target),
            0,
            @intFromPtr(link_path),
        );
    }

    pub fn prep_linkat(
        sqe: *linux.io_uring_sqe,
        old_dir_fd: linux.fd_t,
        old_path: [*:0]const u8,
        new_dir_fd: linux.fd_t,
        new_path: [*:0]const u8,
        flags: u32,
    ) void {
        sqe.prep_rw(
            .LINKAT,
            old_dir_fd,
            @intFromPtr(old_path),
            0,
            @intFromPtr(new_path),
        );
        sqe.len = @bitCast(new_dir_fd);
        sqe.rw_flags = flags;
    }

    pub fn prep_files_update(
        sqe: *linux.io_uring_sqe,
        fds: []const linux.fd_t,
        offset: u32,
    ) void {
        sqe.prep_rw(.FILES_UPDATE, -1, @intFromPtr(fds.ptr), fds.len, @intCast(offset));
    }

    pub fn prep_files_update_alloc(
        sqe: *linux.io_uring_sqe,
        fds: []linux.fd_t,
    ) void {
        sqe.prep_rw(.FILES_UPDATE, -1, @intFromPtr(fds.ptr), fds.len, linux.IORING_FILE_INDEX_ALLOC);
    }

    pub fn prep_provide_buffers(
        sqe: *linux.io_uring_sqe,
        buffers: [*]u8,
        buffer_len: usize,
        num: usize,
        group_id: usize,
        buffer_id: usize,
    ) void {
        const ptr = @intFromPtr(buffers);
        sqe.prep_rw(.PROVIDE_BUFFERS, @intCast(num), ptr, buffer_len, buffer_id);
        sqe.buf_index = @intCast(group_id);
    }

    pub fn prep_remove_buffers(
        sqe: *linux.io_uring_sqe,
        num: usize,
        group_id: usize,
    ) void {
        sqe.prep_rw(.REMOVE_BUFFERS, @intCast(num), 0, 0, 0);
        sqe.buf_index = @intCast(group_id);
    }

    pub fn prep_multishot_accept(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        addr: ?*linux.sockaddr,
        addrlen: ?*linux.socklen_t,
        flags: u32,
    ) void {
        prep_accept(sqe, fd, addr, addrlen, flags);
        sqe.ioprio |= linux.IORING_ACCEPT_MULTISHOT;
    }

    pub fn prep_socket(
        sqe: *linux.io_uring_sqe,
        domain: u32,
        socket_type: u32,
        protocol: u32,
        flags: u32,
    ) void {
        sqe.prep_rw(.SOCKET, @intCast(domain), 0, protocol, socket_type);
        sqe.rw_flags = flags;
    }

    pub fn prep_socket_direct(
        sqe: *linux.io_uring_sqe,
        domain: u32,
        socket_type: u32,
        protocol: u32,
        flags: u32,
        file_index: u32,
    ) void {
        prep_socket(sqe, domain, socket_type, protocol, flags);
        __io_uring_set_target_fixed_file(sqe, file_index);
    }

    pub fn prep_socket_direct_alloc(
        sqe: *linux.io_uring_sqe,
        domain: u32,
        socket_type: u32,
        protocol: u32,
        flags: u32,
    ) void {
        prep_socket(sqe, domain, socket_type, protocol, flags);
        __io_uring_set_target_fixed_file(sqe, linux.IORING_FILE_INDEX_ALLOC);
    }

    pub fn prep_waitid(
        sqe: *linux.io_uring_sqe,
        id_type: linux.P,
        id: i32,
        infop: *linux.siginfo_t,
        options: u32,
        flags: u32,
    ) void {
        sqe.prep_rw(.WAITID, id, 0, @intFromEnum(id_type), @intFromPtr(infop));
        sqe.rw_flags = flags;
        sqe.splice_fd_in = @bitCast(options);
    }

    pub fn prep_bind(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        addr: *const linux.sockaddr,
        addrlen: linux.socklen_t,
        flags: u32,
    ) void {
        sqe.prep_rw(.BIND, fd, @intFromPtr(addr), 0, addrlen);
        sqe.rw_flags = flags;
    }

    pub fn prep_listen(
        sqe: *linux.io_uring_sqe,
        fd: linux.fd_t,
        backlog: usize,
        flags: u32,
    ) void {
        sqe.prep_rw(.LISTEN, fd, 0, backlog, 0);
        sqe.rw_flags = flags;
    }

    pub fn prep_cmd_sock(
        sqe: *linux.io_uring_sqe,
        cmd_op: linux.IO_URING_SOCKET_OP,
        fd: linux.fd_t,
        level: u32,
        optname: u32,
        optval: u64,
        optlen: u32,
    ) void {
        sqe.prep_rw(.URING_CMD, fd, 0, 0, 0);
        // off is overloaded with cmd_op, https://github.com/axboe/liburing/blob/e1003e496e66f9b0ae06674869795edf772d5500/src/include/liburing/io_uring.h#L39
        sqe.off = @intFromEnum(cmd_op);
        // addr is overloaded, https://github.com/axboe/liburing/blob/e1003e496e66f9b0ae06674869795edf772d5500/src/include/liburing/io_uring.h#L46
        sqe.addr = @bitCast(packed struct {
            level: u32,
            optname: u32,
        }{
            .level = level,
            .optname = optname,
        });
        // splice_fd_in if overloaded u32 -> i32
        sqe.splice_fd_in = @bitCast(optlen);
        // addr3 is overloaded, https://github.com/axboe/liburing/blob/e1003e496e66f9b0ae06674869795edf772d5500/src/include/liburing/io_uring.h#L102
        sqe.addr3 = optval;
    }

    pub fn set_flags(sqe: *linux.io_uring_sqe, flags: u8) void {
        sqe.flags |= flags;
    }

    /// This SQE forms a link with the next SQE in the submission ring. Next SQE
    /// will not be started before this one completes. Forms a chain of SQEs.
    pub fn link_next(sqe: *linux.io_uring_sqe) void {
        sqe.flags |= linux.IOSQE_IO_LINK;
    }
};
const std = @import("../../std.zig");

const bits = switch (@import("builtin").cpu.arch) {
    .mips,
    .mipsel,
    .mips64,
    .mips64el,
    .powerpc,
    .powerpcle,
    .powerpc64,
    .powerpc64le,
    .sparc,
    .sparc64,
    => .{ .size = 13, .dir = 3, .none = 1, .read = 2, .write = 4 },
    else => .{ .size = 14, .dir = 2, .none = 0, .read = 2, .write = 1 },
};

const Direction = std.meta.Int(.unsigned, bits.dir);

pub const Request = packed struct {
    nr: u8,
    io_type: u8,
    size: std.meta.Int(.unsigned, bits.size),
    dir: Direction,
};

fn io_impl(dir: Direction, io_type: u8, nr: u8, comptime T: type) u32 {
    const request = Request{
        .dir = dir,
        .size = @sizeOf(T),
        .io_type = io_type,
        .nr = nr,
    };
    return @as(u32, @bitCast(request));
}

pub fn IO(io_type: u8, nr: u8) u32 {
    return io_impl(bits.none, io_type, nr, void);
}

pub fn IOR(io_type: u8, nr: u8, comptime T: type) u32 {
    return io_impl(bits.read, io_type, nr, T);
}

pub fn IOW(io_type: u8, nr: u8, comptime T: type) u32 {
    return io_impl(bits.write, io_type, nr, T);
}

pub fn IOWR(io_type: u8, nr: u8, comptime T: type) u32 {
    return io_impl(bits.read | bits.write, io_type, nr, T);
}

comptime {
    std.debug.assert(@bitSizeOf(Request) == 32);
}
const IoUring = @This();
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;
const is_linux = builtin.os.tag == .linux;
const page_size_min = std.heap.page_size_min;

fd: posix.fd_t = -1,
sq: SubmissionQueue,
cq: CompletionQueue,
flags: u32,
features: u32,

/// A friendly way to setup an io_uring, with default linux.io_uring_params.
/// `entries` must be a power of two between 1 and 32768, although the kernel will make the final
/// call on how many entries the submission and completion queues will ultimately have,
/// see https://github.com/torvalds/linux/blob/v5.8/fs/io_uring.c#L8027-L8050.
/// Matches the interface of io_uring_queue_init() in liburing.
pub fn init(entries: u16, flags: u32) !IoUring {
    var params = mem.zeroInit(linux.io_uring_params, .{
        .flags = flags,
        .sq_thread_idle = 1000,
    });
    return try IoUring.init_params(entries, &params);
}

/// A powerful way to setup an io_uring, if you want to tweak linux.io_uring_params such as submission
/// queue thread cpu affinity or thread idle timeout (the kernel and our default is 1 second).
/// `params` is passed by reference because the kernel needs to modify the parameters.
/// Matches the interface of io_uring_queue_init_params() in liburing.
pub fn init_params(entries: u16, p: *linux.io_uring_params) !IoUring {
    if (entries == 0) return error.EntriesZero;
    if (!std.math.isPowerOfTwo(entries)) return error.EntriesNotPowerOfTwo;

    assert(p.sq_entries == 0);
    assert(p.cq_entries == 0 or p.flags & linux.IORING_SETUP_CQSIZE != 0);
    assert(p.features == 0);
    assert(p.wq_fd == 0 or p.flags & linux.IORING_SETUP_ATTACH_WQ != 0);
    assert(p.resv[0] == 0);
    assert(p.resv[1] == 0);
    assert(p.resv[2] == 0);

    const res = linux.io_uring_setup(entries, p);
    switch (linux.E.init(res)) {
        .SUCCESS => {},
        .FAULT => return error.ParamsOutsideAccessibleAddressSpace,
        // The resv array contains non-zero data, p.flags contains an unsupported flag,
        // entries out of bounds, IORING_SETUP_SQ_AFF was specified without IORING_SETUP_SQPOLL,
        // or IORING_SETUP_CQSIZE was specified but linux.io_uring_params.cq_entries was invalid:
        .INVAL => return error.ArgumentsInvalid,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOMEM => return error.SystemResources,
        // IORING_SETUP_SQPOLL was specified but effective user ID lacks sufficient privileges,
        // or a container seccomp policy prohibits io_uring syscalls:
        .PERM => return error.PermissionDenied,
        .NOSYS => return error.SystemOutdated,
        else => |errno| return posix.unexpectedErrno(errno),
    }
    const fd = @as(posix.fd_t, @intCast(res));
    assert(fd >= 0);
    errdefer posix.close(fd);

    // Kernel versions 5.4 and up use only one mmap() for the submission and completion queues.
    // This is not an optional feature for us... if the kernel does it, we have to do it.
    // The thinking on this by the kernel developers was that both the submission and the
    // completion queue rings have sizes just over a power of two, but the submission queue ring
    // is significantly smaller with u32 slots. By bundling both in a single mmap, the kernel
    // gets the submission queue ring for free.
    // See https://patchwork.kernel.org/patch/11115257 for the kernel patch.
    // We do not support the double mmap() done before 5.4, because we want to keep the
    // init/deinit mmap paths simple and because io_uring has had many bug fixes even since 5.4.
    if ((p.features & linux.IORING_FEAT_SINGLE_MMAP) == 0) {
        return error.SystemOutdated;
    }

    // Check that the kernel has actually set params and that "impossible is nothing".
    assert(p.sq_entries != 0);
    assert(p.cq_entries != 0);
    assert(p.cq_entries >= p.sq_entries);

    // From here on, we only need to read from params, so pass `p` by value as immutable.
    // The completion queue shares the mmap with the submission queue, so pass `sq` there too.
    var sq = try SubmissionQueue.init(fd, p.*);
    errdefer sq.deinit();
    var cq = try CompletionQueue.init(fd, p.*, sq);
    errdefer cq.deinit();

    // Check that our starting state is as we expect.
    assert(sq.head.* == 0);
    assert(sq.tail.* == 0);
    assert(sq.mask == p.sq_entries - 1);
    // Allow flags.* to be non-zero, since the kernel may set IORING_SQ_NEED_WAKEUP at any time.
    assert(sq.dropped.* == 0);
    assert(sq.array.len == p.sq_entries);
    assert(sq.sqes.len == p.sq_entries);
    assert(sq.sqe_head == 0);
    assert(sq.sqe_tail == 0);

    assert(cq.head.* == 0);
    assert(cq.tail.* == 0);
    assert(cq.mask == p.cq_entries - 1);
    assert(cq.overflow.* == 0);
    assert(cq.cqes.len == p.cq_entries);

    return IoUring{
        .fd = fd,
        .sq = sq,
        .cq = cq,
        .flags = p.flags,
        .features = p.features,
    };
}

pub fn deinit(self: *IoUring) void {
    assert(self.fd >= 0);
    // The mmaps depend on the fd, so the order of these calls is important:
    self.cq.deinit();
    self.sq.deinit();
    posix.close(self.fd);
    self.fd = -1;
}

/// Returns a pointer to a vacant SQE, or an error if the submission queue is full.
/// We follow the implementation (and atomics) of liburing's `io_uring_get_sqe()` exactly.
/// However, instead of a null we return an error to force safe handling.
/// Any situation where the submission queue is full tends more towards a control flow error,
/// and the null return in liburing is more a C idiom than anything else, for lack of a better
/// alternative. In Zig, we have first-class error handling... so let's use it.
/// Matches the implementation of io_uring_get_sqe() in liburing.
pub fn get_sqe(self: *IoUring) !*linux.io_uring_sqe {
    const head = @atomicLoad(u32, self.sq.head, .acquire);
    // Remember that these head and tail offsets wrap around every four billion operations.
    // We must therefore use wrapping addition and subtraction to avoid a runtime crash.
    const next = self.sq.sqe_tail +% 1;
    if (next -% head > self.sq.sqes.len) return error.SubmissionQueueFull;
    const sqe = &self.sq.sqes[self.sq.sqe_tail & self.sq.mask];
    self.sq.sqe_tail = next;
    return sqe;
}

/// Submits the SQEs acquired via get_sqe() to the kernel. You can call this once after you have
/// called get_sqe() multiple times to setup multiple I/O requests.
/// Returns the number of SQEs submitted, if not used alongside IORING_SETUP_SQPOLL.
/// If the io_uring instance is uses IORING_SETUP_SQPOLL, the value returned on success is not
/// guaranteed to match the amount of actually submitted sqes during this call. A value higher
/// or lower, including 0, may be returned.
/// Matches the implementation of io_uring_submit() in liburing.
pub fn submit(self: *IoUring) !u32 {
    return self.submit_and_wait(0);
}

/// Like submit(), but allows waiting for events as well.
/// Returns the number of SQEs submitted.
/// Matches the implementation of io_uring_submit_and_wait() in liburing.
pub fn submit_and_wait(self: *IoUring, wait_nr: u32) !u32 {
    const submitted = self.flush_sq();
    var flags: u32 = 0;
    if (self.sq_ring_needs_enter(&flags) or wait_nr > 0) {
        if (wait_nr > 0 or (self.flags & linux.IORING_SETUP_IOPOLL) != 0) {
            flags |= linux.IORING_ENTER_GETEVENTS;
        }
        return try self.enter(submitted, wait_nr, flags);
    }
    return submitted;
}

/// Tell the kernel we have submitted SQEs and/or want to wait for CQEs.
/// Returns the number of SQEs submitted.
pub fn enter(self: *IoUring, to_submit: u32, min_complete: u32, flags: u32) !u32 {
    assert(self.fd >= 0);
    const res = linux.io_uring_enter(self.fd, to_submit, min_complete, flags, null);
    switch (linux.E.init(res)) {
        .SUCCESS => {},
        // The kernel was unable to allocate memory or ran out of resources for the request.
        // The application should wait for some completions and try again:
        .AGAIN => return error.SystemResources,
        // The SQE `fd` is invalid, or IOSQE_FIXED_FILE was set but no files were registered:
        .BADF => return error.FileDescriptorInvalid,
        // The file descriptor is valid, but the ring is not in the right state.
        // See io_uring_register(2) for how to enable the ring.
        .BADFD => return error.FileDescriptorInBadState,
        // The application attempted to overcommit the number of requests it can have pending.
        // The application should wait for some completions and try again:
        .BUSY => return error.CompletionQueueOvercommitted,
        // The SQE is invalid, or valid but the ring was setup with IORING_SETUP_IOPOLL:
        .INVAL => return error.SubmissionQueueEntryInvalid,
        // The buffer is outside the process' accessible address space, or IORING_OP_READ_FIXED
        // or IORING_OP_WRITE_FIXED was specified but no buffers were registered, or the range
        // described by `addr` and `len` is not within the buffer registered at `buf_index`:
        .FAULT => return error.BufferInvalid,
        .NXIO => return error.RingShuttingDown,
        // The kernel believes our `self.fd` does not refer to an io_uring instance,
        // or the opcode is valid but not supported by this kernel (more likely):
        .OPNOTSUPP => return error.OpcodeNotSupported,
        // The operation was interrupted by a delivery of a signal before it could complete.
        // This can happen while waiting for events with IORING_ENTER_GETEVENTS:
        .INTR => return error.SignalInterrupt,
        else => |errno| return posix.unexpectedErrno(errno),
    }
    return @as(u32, @intCast(res));
}

/// Sync internal state with kernel ring state on the SQ side.
/// Returns the number of all pending events in the SQ ring, for the shared ring.
/// This return value includes previously flushed SQEs, as per liburing.
/// The rationale is to suggest that an io_uring_enter() call is needed rather than not.
/// Matches the implementation of __io_uring_flush_sq() in liburing.
pub fn flush_sq(self: *IoUring) u32 {
    if (self.sq.sqe_head != self.sq.sqe_tail) {
        // Fill in SQEs that we have queued up, adding them to the kernel ring.
        const to_submit = self.sq.sqe_tail -% self.sq.sqe_head;
        var tail = self.sq.tail.*;
        var i: usize = 0;
        while (i < to_submit) : (i += 1) {
            self.sq.array[tail & self.sq.mask] = self.sq.sqe_head & self.sq.mask;
            tail +%= 1;
            self.sq.sqe_head +%= 1;
        }
        // Ensure that the kernel can actually see the SQE updates when it sees the tail update.
        @atomicStore(u32, self.sq.tail, tail, .release);
    }
    return self.sq_ready();
}

/// Returns true if we are not using an SQ thread (thus nobody submits but us),
/// or if IORING_SQ_NEED_WAKEUP is set and the SQ thread must be explicitly awakened.
/// For the latter case, we set the SQ thread wakeup flag.
/// Matches the implementation of sq_ring_needs_enter() in liburing.
pub fn sq_ring_needs_enter(self: *IoUring, flags: *u32) bool {
    assert(flags.* == 0);
    if ((self.flags & linux.IORING_SETUP_SQPOLL) == 0) return true;
    if ((@atomicLoad(u32, self.sq.flags, .unordered) & linux.IORING_SQ_NEED_WAKEUP) != 0) {
        flags.* |= linux.IORING_ENTER_SQ_WAKEUP;
        return true;
    }
    return false;
}

/// Returns the number of flushed and unflushed SQEs pending in the submission queue.
/// In other words, this is the number of SQEs in the submission queue, i.e. its length.
/// These are SQEs that the kernel is yet to consume.
/// Matches the implementation of io_uring_sq_ready in liburing.
pub fn sq_ready(self: *IoUring) u32 {
    // Always use the shared ring state (i.e. head and not sqe_head) to avoid going out of sync,
    // see https://github.com/axboe/liburing/issues/92.
    return self.sq.sqe_tail -% @atomicLoad(u32, self.sq.head, .acquire);
}

/// Returns the number of CQEs in the completion queue, i.e. its length.
/// These are CQEs that the application is yet to consume.
/// Matches the implementation of io_uring_cq_ready in liburing.
pub fn cq_ready(self: *IoUring) u32 {
    return @atomicLoad(u32, self.cq.tail, .acquire) -% self.cq.head.*;
}

/// Copies as many CQEs as are ready, and that can fit into the destination `cqes` slice.
/// If none are available, enters into the kernel to wait for at most `wait_nr` CQEs.
/// Returns the number of CQEs copied, advancing the CQ ring.
/// Provides all the wait/peek methods found in liburing, but with batching and a single method.
/// The rationale for copying CQEs rather than copying pointers is that pointers are 8 bytes
/// whereas CQEs are not much more at only 16 bytes, and this provides a safer faster interface.
/// Safer, because you no longer need to call cqe_seen(), avoiding idempotency bugs.
/// Faster, because we can now amortize the atomic store release to `cq.head` across the batch.
/// See https://github.com/axboe/liburing/issues/103#issuecomment-686665007.
/// Matches the implementation of io_uring_peek_batch_cqe() in liburing, but supports waiting.
pub fn copy_cqes(self: *IoUring, cqes: []linux.io_uring_cqe, wait_nr: u32) !u32 {
    const count = self.copy_cqes_ready(cqes);
    if (count > 0) return count;
    if (self.cq_ring_needs_flush() or wait_nr > 0) {
        _ = try self.enter(0, wait_nr, linux.IORING_ENTER_GETEVENTS);
        return self.copy_cqes_ready(cqes);
    }
    return 0;
}

fn copy_cqes_ready(self: *IoUring, cqes: []linux.io_uring_cqe) u32 {
    const ready = self.cq_ready();
    const count = @min(cqes.len, ready);
    const head = self.cq.head.* & self.cq.mask;

    // before wrapping
    const n = @min(self.cq.cqes.len - head, count);
    @memcpy(cqes[0..n], self.cq.cqes[head..][0..n]);

    if (count > n) {
        // wrap self.cq.cqes
        const w = count - n;
        @memcpy(cqes[n..][0..w], self.cq.cqes[0..w]);
    }

    self.cq_advance(count);
    return count;
}

/// Returns a copy of an I/O completion, waiting for it if necessary, and advancing the CQ ring.
/// A convenience method for `copy_cqes()` for when you don't need to batch or peek.
pub fn copy_cqe(ring: *IoUring) !linux.io_uring_cqe {
    var cqes: [1]linux.io_uring_cqe = undefined;
    while (true) {
        const count = try ring.copy_cqes(&cqes, 1);
        if (count > 0) return cqes[0];
    }
}

/// Matches the implementation of cq_ring_needs_flush() in liburing.
pub fn cq_ring_needs_flush(self: *IoUring) bool {
    return (@atomicLoad(u32, self.sq.flags, .unordered) & linux.IORING_SQ_CQ_OVERFLOW) != 0;
}

/// For advanced use cases only that implement custom completion queue methods.
/// If you use copy_cqes() or copy_cqe() you must not call cqe_seen() or cq_advance().
/// Must be called exactly once after a zero-copy CQE has been processed by your application.
/// Not idempotent, calling more than once will result in other CQEs being lost.
/// Matches the implementation of cqe_seen() in liburing.
pub fn cqe_seen(self: *IoUring, cqe: *linux.io_uring_cqe) void {
    _ = cqe;
    self.cq_advance(1);
}

/// For advanced use cases only that implement custom completion queue methods.
/// Matches the implementation of cq_advance() in liburing.
pub fn cq_advance(self: *IoUring, count: u32) void {
    if (count > 0) {
        // Ensure the kernel only sees the new head value after the CQEs have been read.
        @atomicStore(u32, self.cq.head, self.cq.head.* +% count, .release);
    }
}

/// Queues (but does not submit) an SQE to perform an `fsync(2)`.
/// Returns a pointer to the SQE so that you can further modify the SQE for advanced use cases.
/// For example, for `fdatasync()` you can set `IORING_FSYNC_DATASYNC` in the SQE's `rw_flags`.
/// N.B. While SQEs are initiated in the order in which they appear in the submission queue,
/// operations execute in parallel and completions are unordered. Therefore, an application that
/// submits a write followed by an fsync in the submission queue cannot expect the fsync to
/// apply to the write, since the fsync may complete before the write is issued to the disk.
/// You should preferably use `link_with_next_sqe()` on a write's SQE to link it with an fsync,
/// or else insert a full write barrier using `drain_previous_sqes()` when queueing an fsync.
pub fn fsync(self: *IoUring, user_data: u64, fd: posix.fd_t, flags: u32) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_fsync(fd, flags);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues (but does not submit) an SQE to perform a no-op.
/// Returns a pointer to the SQE so that you can further modify the SQE for advanced use cases.
/// A no-op is more useful than may appear at first glance.
/// For example, you could call `drain_previous_sqes()` on the returned SQE, to use the no-op to
/// know when the ring is idle before acting on a kill signal.
pub fn nop(self: *IoUring, user_data: u64) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_nop();
    sqe.user_data = user_data;
    return sqe;
}

/// Used to select how the read should be handled.
pub const ReadBuffer = union(enum) {
    /// io_uring will read directly into this buffer
    buffer: []u8,

    /// io_uring will read directly into these buffers using readv.
    iovecs: []const posix.iovec,

    /// io_uring will select a buffer that has previously been provided with `provide_buffers`.
    /// The buffer group reference by `group_id` must contain at least one buffer for the read to work.
    /// `len` controls the number of bytes to read into the selected buffer.
    buffer_selection: struct {
        group_id: u16,
        len: usize,
    },
};

/// Queues (but does not submit) an SQE to perform a `read(2)` or `preadv(2)` depending on the buffer type.
/// * Reading into a `ReadBuffer.buffer` uses `read(2)`
/// * Reading into a `ReadBuffer.iovecs` uses `preadv(2)`
///   If you want to do a `preadv2(2)` then set `rw_flags` on the returned SQE. See https://man7.org/linux/man-pages/man2/preadv2.2.html
///
/// Returns a pointer to the SQE.
pub fn read(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    buffer: ReadBuffer,
    offset: u64,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    switch (buffer) {
        .buffer => |slice| sqe.prep_read(fd, slice, offset),
        .iovecs => |vecs| sqe.prep_readv(fd, vecs, offset),
        .buffer_selection => |selection| {
            sqe.prep_rw(.READ, fd, 0, selection.len, offset);
            sqe.flags |= linux.IOSQE_BUFFER_SELECT;
            sqe.buf_index = selection.group_id;
        },
    }
    sqe.user_data = user_data;
    return sqe;
}

/// Queues (but does not submit) an SQE to perform a `write(2)`.
/// Returns a pointer to the SQE.
pub fn write(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    buffer: []const u8,
    offset: u64,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_write(fd, buffer, offset);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues (but does not submit) an SQE to perform a `splice(2)`
/// Either `fd_in` or `fd_out` must be a pipe.
/// If `fd_in` refers to a pipe, `off_in` is ignored and must be set to std.math.maxInt(u64).
/// If `fd_in` does not refer to a pipe and `off_in` is maxInt(u64), then `len` are read
/// from `fd_in` starting from the file offset, which is incremented by the number of bytes read.
/// If `fd_in` does not refer to a pipe and `off_in` is not maxInt(u64), then the starting offset of `fd_in` will be `off_in`.
/// This splice operation can be used to implement sendfile by splicing to an intermediate pipe first,
/// then splice to the final destination. In fact, the implementation of sendfile in kernel uses splice internally.
///
/// NOTE that even if fd_in or fd_out refers to a pipe, the splice operation can still fail with EINVAL if one of the
/// fd doesn't explicitly support splice peration, e.g. reading from terminal is unsupported from kernel 5.7 to 5.11.
/// See https://github.com/axboe/liburing/issues/291
///
/// Returns a pointer to the SQE so that you can further modify the SQE for advanced use cases.
pub fn splice(self: *IoUring, user_data: u64, fd_in: posix.fd_t, off_in: u64, fd_out: posix.fd_t, off_out: u64, len: usize) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_splice(fd_in, off_in, fd_out, off_out, len);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues (but does not submit) an SQE to perform a IORING_OP_READ_FIXED.
/// The `buffer` provided must be registered with the kernel by calling `register_buffers` first.
/// The `buffer_index` must be the same as its index in the array provided to `register_buffers`.
///
/// Returns a pointer to the SQE so that you can further modify the SQE for advanced use cases.
pub fn read_fixed(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    buffer: *posix.iovec,
    offset: u64,
    buffer_index: u16,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_read_fixed(fd, buffer, offset, buffer_index);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues (but does not submit) an SQE to perform a `pwritev()`.
/// Returns a pointer to the SQE so that you can further modify the SQE for advanced use cases.
/// For example, if you want to do a `pwritev2()` then set `rw_flags` on the returned SQE.
/// See https://linux.die.net/man/2/pwritev.
pub fn writev(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    iovecs: []const posix.iovec_const,
    offset: u64,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_writev(fd, iovecs, offset);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues (but does not submit) an SQE to perform a IORING_OP_WRITE_FIXED.
/// The `buffer` provided must be registered with the kernel by calling `register_buffers` first.
/// The `buffer_index` must be the same as its index in the array provided to `register_buffers`.
///
/// Returns a pointer to the SQE so that you can further modify the SQE for advanced use cases.
pub fn write_fixed(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    buffer: *posix.iovec,
    offset: u64,
    buffer_index: u16,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_write_fixed(fd, buffer, offset, buffer_index);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues (but does not submit) an SQE to perform an `accept4(2)` on a socket.
/// Returns a pointer to the SQE.
/// Available since 5.5
pub fn accept(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    addr: ?*posix.sockaddr,
    addrlen: ?*posix.socklen_t,
    flags: u32,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_accept(fd, addr, addrlen, flags);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues an multishot accept on a socket.
///
/// Multishot variant allows an application to issue a single accept request,
/// which will repeatedly trigger a CQE when a connection request comes in.
/// While IORING_CQE_F_MORE flag is set in CQE flags accept will generate
/// further CQEs.
///
/// Available since 5.19
pub fn accept_multishot(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    addr: ?*posix.sockaddr,
    addrlen: ?*posix.socklen_t,
    flags: u32,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_multishot_accept(fd, addr, addrlen, flags);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues an accept using direct (registered) file descriptors.
///
/// To use an accept direct variant, the application must first have registered
/// a file table (with register_files). An unused table index will be
/// dynamically chosen and returned in the CQE res field.
///
/// After creation, they can be used by setting IOSQE_FIXED_FILE in the SQE
/// flags member, and setting the SQE fd field to the direct descriptor value
/// rather than the regular file descriptor.
///
/// Available since 5.19
pub fn accept_direct(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    addr: ?*posix.sockaddr,
    addrlen: ?*posix.socklen_t,
    flags: u32,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_accept_direct(fd, addr, addrlen, flags, linux.IORING_FILE_INDEX_ALLOC);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues an multishot accept using direct (registered) file descriptors.
/// Available since 5.19
pub fn accept_multishot_direct(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    addr: ?*posix.sockaddr,
    addrlen: ?*posix.socklen_t,
    flags: u32,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_multishot_accept_direct(fd, addr, addrlen, flags);
    sqe.user_data = user_data;
    return sqe;
}

/// Queue (but does not submit) an SQE to perform a `connect(2)` on a socket.
/// Returns a pointer to the SQE.
pub fn connect(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    addr: *const posix.sockaddr,
    addrlen: posix.socklen_t,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_connect(fd, addr, addrlen);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues (but does not submit) an SQE to perform a `epoll_ctl(2)`.
/// Returns a pointer to the SQE.
pub fn epoll_ctl(
    self: *IoUring,
    user_data: u64,
    epfd: posix.fd_t,
    fd: posix.fd_t,
    op: u32,
    ev: ?*linux.epoll_event,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_epoll_ctl(epfd, fd, op, ev);
    sqe.user_data = user_data;
    return sqe;
}

/// Used to select how the recv call should be handled.
pub const RecvBuffer = union(enum) {
    /// io_uring will recv directly into this buffer
    buffer: []u8,

    /// io_uring will select a buffer that has previously been provided with `provide_buffers`.
    /// The buffer group referenced by `group_id` must contain at least one buffer for the recv call to work.
    /// `len` controls the number of bytes to read into the selected buffer.
    buffer_selection: struct {
        group_id: u16,
        len: usize,
    },
};

/// Queues (but does not submit) an SQE to perform a `recv(2)`.
/// Returns a pointer to the SQE.
/// Available since 5.6
pub fn recv(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    buffer: RecvBuffer,
    flags: u32,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    switch (buffer) {
        .buffer => |slice| sqe.prep_recv(fd, slice, flags),
        .buffer_selection => |selection| {
            sqe.prep_rw(.RECV, fd, 0, selection.len, 0);
            sqe.rw_flags = flags;
            sqe.flags |= linux.IOSQE_BUFFER_SELECT;
            sqe.buf_index = selection.group_id;
        },
    }
    sqe.user_data = user_data;
    return sqe;
}

/// Queues (but does not submit) an SQE to perform a `send(2)`.
/// Returns a pointer to the SQE.
/// Available since 5.6
pub fn send(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    buffer: []const u8,
    flags: u32,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_send(fd, buffer, flags);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues (but does not submit) an SQE to perform an async zerocopy `send(2)`.
///
/// This operation will most likely produce two CQEs. The flags field of the
/// first cqe may likely contain IORING_CQE_F_MORE, which means that there will
/// be a second cqe with the user_data field set to the same value. The user
/// must not modify the data buffer until the notification is posted. The first
/// cqe follows the usual rules and so its res field will contain the number of
/// bytes sent or a negative error code. The notification's res field will be
/// set to zero and the flags field will contain IORING_CQE_F_NOTIF. The two
/// step model is needed because the kernel may hold on to buffers for a long
/// time, e.g. waiting for a TCP ACK. Notifications responsible for controlling
/// the lifetime of the buffers. Even errored requests may generate a
/// notification.
///
/// Available since 6.0
pub fn send_zc(
    self: *IoUring,
    user_data: u64,
    fd: posix.fd_t,
    buffer: []const u8,
    send_flags: u32,
    zc_flags: u16,
) !*linux.io_uring_sqe {
    const sqe = try self.get_sqe();
    sqe.prep_send_zc(fd, buffer, send_flags, zc_flags);
    sqe.user_data = user_data;
    return sqe;
}

/// Queues (but does not submit) an SQE to perform an async zerocopy `se```
