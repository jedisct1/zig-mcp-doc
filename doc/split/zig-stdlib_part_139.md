```
er.FastMath,
    };

    pub const Cast = struct {
        const CastOpcode = Builder.CastOpcode;
        pub const ops = [_]AbbrevOp{
            .{ .literal = 3 },
            ValueAbbrev,
            .{ .fixed_runtime = Builder.Type },
            .{ .fixed = @bitSizeOf(CastOpcode) },
        };

        val: u32,
        type_index: Builder.Type,
        opcode: CastOpcode,
    };

    pub const Alloca = struct {
        pub const Flags = packed struct(u11) {
            align_lower: u5,
            inalloca: bool,
            explicit_type: bool,
            swift_error: bool,
            align_upper: u3,
        };
        pub const ops = [_]AbbrevOp{
            .{ .literal = 19 },
            .{ .fixed_runtime = Builder.Type },
            .{ .fixed_runtime = Builder.Type },
            ValueAbbrev,
            .{ .fixed = @bitSizeOf(Flags) },
        };

        inst_type: Builder.Type,
        len_type: Builder.Type,
        len_value: u32,
        flags: Flags,
    };

    pub const RetVoid = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 10 },
        };
    };

    pub const Ret = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 10 },
            ValueAbbrev,
        };
        val: u32,
    };

    pub const GetElementPtr = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 43 },
            .{ .fixed = 1 },
            .{ .fixed_runtime = Builder.Type },
            ValueAbbrev,
            ValueArrayAbbrev,
        };

        is_inbounds: bool,
        type_index: Builder.Type,
        base: Builder.Value,
        indices: []const Builder.Value,
    };

    pub const ExtractValue = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 26 },
            ValueAbbrev,
            ValueArrayAbbrev,
        };

        val: u32,
        indices: []const u32,
    };

    pub const InsertValue = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 27 },
            ValueAbbrev,
            ValueAbbrev,
            ValueArrayAbbrev,
        };

        val: u32,
        elem: u32,
        indices: []const u32,
    };

    pub const ExtractElement = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 6 },
            ValueAbbrev,
            ValueAbbrev,
        };

        val: u32,
        index: u32,
    };

    pub const InsertElement = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 7 },
            ValueAbbrev,
            ValueAbbrev,
            ValueAbbrev,
        };

        val: u32,
        elem: u32,
        index: u32,
    };

    pub const ShuffleVector = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 8 },
            ValueAbbrev,
            ValueAbbrev,
            ValueAbbrev,
        };

        lhs: u32,
        rhs: u32,
        mask: u32,
    };

    pub const Unreachable = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 15 },
        };
    };

    pub const Load = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 20 },
            ValueAbbrev,
            .{ .fixed_runtime = Builder.Type },
            .{ .fixed = @bitSizeOf(Builder.Alignment) },
            .{ .fixed = 1 },
        };
        ptr: u32,
        ty: Builder.Type,
        alignment: std.meta.Int(.unsigned, @bitSizeOf(Builder.Alignment)),
        is_volatile: bool,
    };

    pub const LoadAtomic = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 41 },
            ValueAbbrev,
            .{ .fixed_runtime = Builder.Type },
            .{ .fixed = @bitSizeOf(Builder.Alignment) },
            .{ .fixed = 1 },
            .{ .fixed = @bitSizeOf(Builder.AtomicOrdering) },
            .{ .fixed = @bitSizeOf(Builder.SyncScope) },
        };
        ptr: u32,
        ty: Builder.Type,
        alignment: std.meta.Int(.unsigned, @bitSizeOf(Builder.Alignment)),
        is_volatile: bool,
        success_ordering: Builder.AtomicOrdering,
        sync_scope: Builder.SyncScope,
    };

    pub const Store = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 44 },
            ValueAbbrev,
            ValueAbbrev,
            .{ .fixed = @bitSizeOf(Builder.Alignment) },
            .{ .fixed = 1 },
        };
        ptr: u32,
        val: u32,
        alignment: std.meta.Int(.unsigned, @bitSizeOf(Builder.Alignment)),
        is_volatile: bool,
    };

    pub const StoreAtomic = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 45 },
            ValueAbbrev,
            ValueAbbrev,
            .{ .fixed = @bitSizeOf(Builder.Alignment) },
            .{ .fixed = 1 },
            .{ .fixed = @bitSizeOf(Builder.AtomicOrdering) },
            .{ .fixed = @bitSizeOf(Builder.SyncScope) },
        };
        ptr: u32,
        val: u32,
        alignment: std.meta.Int(.unsigned, @bitSizeOf(Builder.Alignment)),
        is_volatile: bool,
        success_ordering: Builder.AtomicOrdering,
        sync_scope: Builder.SyncScope,
    };

    pub const BrUnconditional = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 11 },
            BlockAbbrev,
        };
        block: u32,
    };

    pub const BrConditional = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 11 },
            BlockAbbrev,
            BlockAbbrev,
            BlockAbbrev,
        };
        then_block: u32,
        else_block: u32,
        condition: u32,
    };

    pub const VaArg = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 23 },
            .{ .fixed_runtime = Builder.Type },
            ValueAbbrev,
            .{ .fixed_runtime = Builder.Type },
        };
        list_type: Builder.Type,
        list: u32,
        type: Builder.Type,
    };

    pub const AtomicRmw = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 59 },
            ValueAbbrev,
            ValueAbbrev,
            .{ .fixed = @bitSizeOf(Builder.Function.Instruction.AtomicRmw.Operation) },
            .{ .fixed = 1 },
            .{ .fixed = @bitSizeOf(Builder.AtomicOrdering) },
            .{ .fixed = @bitSizeOf(Builder.SyncScope) },
            .{ .fixed = @bitSizeOf(Builder.Alignment) },
        };
        ptr: u32,
        val: u32,
        operation: Builder.Function.Instruction.AtomicRmw.Operation,
        is_volatile: bool,
        success_ordering: Builder.AtomicOrdering,
        sync_scope: Builder.SyncScope,
        alignment: std.meta.Int(.unsigned, @bitSizeOf(Builder.Alignment)),
    };

    pub const CmpXchg = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 46 },
            ValueAbbrev,
            ValueAbbrev,
            ValueAbbrev,
            .{ .fixed = 1 },
            .{ .fixed = @bitSizeOf(Builder.AtomicOrdering) },
            .{ .fixed = @bitSizeOf(Builder.SyncScope) },
            .{ .fixed = @bitSizeOf(Builder.AtomicOrdering) },
            .{ .fixed = 1 },
            .{ .fixed = @bitSizeOf(Builder.Alignment) },
        };
        ptr: u32,
        cmp: u32,
        new: u32,
        is_volatile: bool,
        success_ordering: Builder.AtomicOrdering,
        sync_scope: Builder.SyncScope,
        failure_ordering: Builder.AtomicOrdering,
        is_weak: bool,
        alignment: std.meta.Int(.unsigned, @bitSizeOf(Builder.Alignment)),
    };

    pub const Fence = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 36 },
            .{ .fixed = @bitSizeOf(Builder.AtomicOrdering) },
            .{ .fixed = @bitSizeOf(Builder.SyncScope) },
        };
        ordering: Builder.AtomicOrdering,
        sync_scope: Builder.SyncScope,
    };

    pub const DebugLoc = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 35 },
            LineAbbrev,
            ColumnAbbrev,
            MetadataAbbrev,
            MetadataAbbrev,
            .{ .literal = 0 },
        };
        line: u32,
        column: u32,
        scope: Builder.Metadata,
        inlined_at: Builder.Metadata,
    };

    pub const DebugLocAgain = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 33 },
        };
    };

    pub const ColdOperandBundle = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 55 },
            .{ .literal = 0 },
        };
    };

    pub const IndirectBr = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 31 },
            .{ .fixed_runtime = Builder.Type },
            ValueAbbrev,
            BlockArrayAbbrev,
        };
        ty: Builder.Type,
        addr: Builder.Value,
        targets: []const Builder.Function.Block.Index,
    };
};

pub const FunctionValueSymbolTable = struct {
    pub const id = 14;

    pub const abbrevs = [_]type{
        BlockEntry,
    };

    pub const BlockEntry = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 2 },
            ValueAbbrev,
            .{ .array_fixed = 8 },
        };
        value_id: u32,
        string: []const u8,
    };
};

pub const Strtab = struct {
    pub const id = 23;

    pub const abbrevs = [_]type{Blob};

    pub const Blob = struct {
        pub const ops = [_]AbbrevOp{
            .{ .literal = 1 },
            .blob,
        };
        blob: []const u8,
    };
};
const std = @import("../std.zig");
const assert = std.debug.assert;
const utf8Decode = std.unicode.utf8Decode;
const utf8Encode = std.unicode.utf8Encode;

pub const ParseError = error{
    OutOfMemory,
    InvalidLiteral,
};

pub const Base = enum(u8) { decimal = 10, hex = 16, binary = 2, octal = 8 };
pub const FloatBase = enum(u8) { decimal = 10, hex = 16 };

pub const Result = union(enum) {
    /// Result fits if it fits in u64
    int: u64,
    /// Result is an int that doesn't fit in u64. Payload is the base, if it is
    /// not `.decimal` then the slice has a two character prefix.
    big_int: Base,
    /// Result is a float. Payload is the base, if it is not `.decimal` then
    /// the slice has a two character prefix.
    float: FloatBase,
    failure: Error,
};

pub const Error = union(enum) {
    /// The number has leading zeroes.
    leading_zero,
    /// Expected a digit after base prefix.
    digit_after_base,
    /// The base prefix is in uppercase.
    upper_case_base: usize,
    /// Float literal has an invalid base prefix.
    invalid_float_base: usize,
    /// Repeated '_' digit separator.
    repeated_underscore: usize,
    /// '_' digit separator after special character (+-.)
    invalid_underscore_after_special: usize,
    /// Invalid digit for the specified base.
    invalid_digit: struct { i: usize, base: Base },
    /// Invalid digit for an exponent.
    invalid_digit_exponent: usize,
    /// Float literal has multiple periods.
    duplicate_period,
    /// Float literal has multiple exponents.
    duplicate_exponent: usize,
    /// Exponent comes directly after '_' digit separator.
    exponent_after_underscore: usize,
    /// Special character (+-.) comes directly after exponent.
    special_after_underscore: usize,
    /// Number ends in special character (+-.)
    trailing_special: usize,
    /// Number ends in '_' digit separator.
    trailing_underscore: usize,
    /// Character not in [0-9a-zA-Z.+-_]
    invalid_character: usize,
    /// [+-] not immediately after [pPeE]
    invalid_exponent_sign: usize,
    /// Period comes directly after exponent.
    period_after_exponent: usize,
};

/// Parse Zig number literal accepted by fmt.parseInt, fmt.parseFloat and big_int.setString.
/// Valid for any input.
pub fn parseNumberLiteral(bytes: []const u8) Result {
    var i: usize = 0;
    var base: u8 = 10;
    if (bytes.len >= 2 and bytes[0] == '0') switch (bytes[1]) {
        'b' => {
            base = 2;
            i = 2;
        },
        'o' => {
            base = 8;
            i = 2;
        },
        'x' => {
            base = 16;
            i = 2;
        },
        'B', 'O', 'X' => return .{ .failure = .{ .upper_case_base = 1 } },
        '.', 'e', 'E' => {},
        else => return .{ .failure = .leading_zero },
    };
    if (bytes.len == 2 and base != 10) return .{ .failure = .digit_after_base };

    var x: u64 = 0;
    var overflow = false;
    var underscore = false;
    var period = false;
    var special: u8 = 0;
    var exponent = false;
    var float = false;
    while (i < bytes.len) : (i += 1) {
        const c = bytes[i];
        switch (c) {
            '_' => {
                if (i == 2 and base != 10) return .{ .failure = .{ .invalid_underscore_after_special = i } };
                if (special != 0) return .{ .failure = .{ .invalid_underscore_after_special = i } };
                if (underscore) return .{ .failure = .{ .repeated_underscore = i } };
                underscore = true;
                continue;
            },
            'e', 'E' => if (base == 10) {
                float = true;
                if (exponent) return .{ .failure = .{ .duplicate_exponent = i } };
                if (underscore) return .{ .failure = .{ .exponent_after_underscore = i } };
                special = c;
                exponent = true;
                continue;
            },
            'p', 'P' => if (base == 16) {
                if (i == 2) {
                    return .{ .failure = .{ .digit_after_base = {} } };
                }
                float = true;
                if (exponent) return .{ .failure = .{ .duplicate_exponent = i } };
                if (underscore) return .{ .failure = .{ .exponent_after_underscore = i } };
                special = c;
                exponent = true;
                continue;
            },
            '.' => {
                if (exponent) {
                    const digit_index = i - ".e".len;
                    if (digit_index < bytes.len) {
                        switch (bytes[digit_index]) {
                            '0'...'9' => return .{ .failure = .{ .period_after_exponent = i } },
                            else => {},
                        }
                    }
                }
                float = true;
                if (base != 10 and base != 16) return .{ .failure = .{ .invalid_float_base = 2 } };
                if (period) return .{ .failure = .duplicate_period };
                period = true;
                if (underscore) return .{ .failure = .{ .special_after_underscore = i } };
                special = c;
                continue;
            },
            '+', '-' => {
                switch (special) {
                    'p', 'P' => {},
                    'e', 'E' => if (base != 10) return .{ .failure = .{ .invalid_exponent_sign = i } },
                    else => return .{ .failure = .{ .invalid_exponent_sign = i } },
                }
                special = c;
                continue;
            },
            else => {},
        }
        const digit = switch (c) {
            '0'...'9' => c - '0',
            'A'...'Z' => c - 'A' + 10,
            'a'...'z' => c - 'a' + 10,
            else => return .{ .failure = .{ .invalid_character = i } },
        };
        if (digit >= base) return .{ .failure = .{ .invalid_digit = .{ .i = i, .base = @as(Base, @enumFromInt(base)) } } };
        if (exponent and digit >= 10) return .{ .failure = .{ .invalid_digit_exponent = i } };
        underscore = false;
        special = 0;

        if (float) continue;
        if (x != 0) {
            const res = @mulWithOverflow(x, base);
            if (res[1] != 0) overflow = true;
            x = res[0];
        }
        const res = @addWithOverflow(x, digit);
        if (res[1] != 0) overflow = true;
        x = res[0];
    }
    if (underscore) return .{ .failure = .{ .trailing_underscore = bytes.len - 1 } };
    if (special != 0) return .{ .failure = .{ .trailing_special = bytes.len - 1 } };

    if (float) return .{ .float = @as(FloatBase, @enumFromInt(base)) };
    if (overflow) return .{ .big_int = @as(Base, @enumFromInt(base)) };
    return .{ .int = x };
}
//! Represents in-progress parsing, will be converted to an Ast after completion.

pub const Error = error{ParseError} || Allocator.Error;

gpa: Allocator,
source: []const u8,
tokens: Ast.TokenList.Slice,
tok_i: TokenIndex,
errors: std.ArrayListUnmanaged(AstError),
nodes: Ast.NodeList,
extra_data: std.ArrayListUnmanaged(u32),
scratch: std.ArrayListUnmanaged(Node.Index),

fn tokenTag(p: *const Parse, token_index: TokenIndex) Token.Tag {
    return p.tokens.items(.tag)[token_index];
}

fn tokenStart(p: *const Parse, token_index: TokenIndex) Ast.ByteOffset {
    return p.tokens.items(.start)[token_index];
}

fn nodeTag(p: *const Parse, node: Node.Index) Node.Tag {
    return p.nodes.items(.tag)[@intFromEnum(node)];
}

fn nodeMainToken(p: *const Parse, node: Node.Index) TokenIndex {
    return p.nodes.items(.main_token)[@intFromEnum(node)];
}

fn nodeData(p: *const Parse, node: Node.Index) Node.Data {
    return p.nodes.items(.data)[@intFromEnum(node)];
}

const SmallSpan = union(enum) {
    zero_or_one: Node.OptionalIndex,
    multi: Node.SubRange,
};

const Members = struct {
    len: usize,
    /// Must be either `.opt_node_and_opt_node` if `len <= 2` or `.extra_range` otherwise.
    data: Node.Data,
    trailing: bool,

    fn toSpan(self: Members, p: *Parse) !Node.SubRange {
        return switch (self.len) {
            0 => p.listToSpan(&.{}),
            1 => p.listToSpan(&.{self.data.opt_node_and_opt_node[0].unwrap().?}),
            2 => p.listToSpan(&.{ self.data.opt_node_and_opt_node[0].unwrap().?, self.data.opt_node_and_opt_node[1].unwrap().? }),
            else => self.data.extra_range,
        };
    }
};

fn listToSpan(p: *Parse, list: []const Node.Index) Allocator.Error!Node.SubRange {
    try p.extra_data.appendSlice(p.gpa, @ptrCast(list));
    return .{
        .start = @enumFromInt(p.extra_data.items.len - list.len),
        .end = @enumFromInt(p.extra_data.items.len),
    };
}

fn addNode(p: *Parse, elem: Ast.Node) Allocator.Error!Node.Index {
    const result: Node.Index = @enumFromInt(p.nodes.len);
    try p.nodes.append(p.gpa, elem);
    return result;
}

fn setNode(p: *Parse, i: usize, elem: Ast.Node) Node.Index {
    p.nodes.set(i, elem);
    return @enumFromInt(i);
}

fn reserveNode(p: *Parse, tag: Ast.Node.Tag) !usize {
    try p.nodes.resize(p.gpa, p.nodes.len + 1);
    p.nodes.items(.tag)[p.nodes.len - 1] = tag;
    return p.nodes.len - 1;
}

fn unreserveNode(p: *Parse, node_index: usize) void {
    if (p.nodes.len == node_index) {
        p.nodes.resize(p.gpa, p.nodes.len - 1) catch unreachable;
    } else {
        // There is zombie node left in the tree, let's make it as inoffensive as possible
        // (sadly there's no no-op node)
        p.nodes.items(.tag)[node_index] = .unreachable_literal;
        p.nodes.items(.main_token)[node_index] = p.tok_i;
    }
}

fn addExtra(p: *Parse, extra: anytype) Allocator.Error!ExtraIndex {
    const fields = std.meta.fields(@TypeOf(extra));
    try p.extra_data.ensureUnusedCapacity(p.gpa, fields.len);
    const result: ExtraIndex = @enumFromInt(p.extra_data.items.len);
    inline for (fields) |field| {
        const data: u32 = switch (field.type) {
            Node.Index,
            Node.OptionalIndex,
            OptionalTokenIndex,
            ExtraIndex,
            => @intFromEnum(@field(extra, field.name)),
            TokenIndex,
            => @field(extra, field.name),
            else => @compileError("unexpected field type"),
        };
        p.extra_data.appendAssumeCapacity(data);
    }
    return result;
}

fn warnExpected(p: *Parse, expected_token: Token.Tag) error{OutOfMemory}!void {
    @branchHint(.cold);
    try p.warnMsg(.{
        .tag = .expected_token,
        .token = p.tok_i,
        .extra = .{ .expected_tag = expected_token },
    });
}

fn warn(p: *Parse, error_tag: AstError.Tag) error{OutOfMemory}!void {
    @branchHint(.cold);
    try p.warnMsg(.{ .tag = error_tag, .token = p.tok_i });
}

fn warnMsg(p: *Parse, msg: Ast.Error) error{OutOfMemory}!void {
    @branchHint(.cold);
    switch (msg.tag) {
        .expected_semi_after_decl,
        .expected_semi_after_stmt,
        .expected_comma_after_field,
        .expected_comma_after_arg,
        .expected_comma_after_param,
        .expected_comma_after_initializer,
        .expected_comma_after_switch_prong,
        .expected_comma_after_for_operand,
        .expected_comma_after_capture,
        .expected_semi_or_else,
        .expected_semi_or_lbrace,
        .expected_token,
        .expected_block,
        .expected_block_or_assignment,
        .expected_block_or_expr,
        .expected_block_or_field,
        .expected_expr,
        .expected_expr_or_assignment,
        .expected_fn,
        .expected_inlinable,
        .expected_labelable,
        .expected_param_list,
        .expected_prefix_expr,
        .expected_primary_type_expr,
        .expected_pub_item,
        .expected_return_type,
        .expected_suffix_op,
        .expected_type_expr,
        .expected_var_decl,
        .expected_var_decl_or_fn,
        .expected_loop_payload,
        .expected_container,
        => if (msg.token != 0 and !p.tokensOnSameLine(msg.token - 1, msg.token)) {
            var copy = msg;
            copy.token_is_prev = true;
            copy.token -= 1;
            return p.errors.append(p.gpa, copy);
        },
        else => {},
    }
    try p.errors.append(p.gpa, msg);
}

fn fail(p: *Parse, tag: Ast.Error.Tag) error{ ParseError, OutOfMemory } {
    @branchHint(.cold);
    return p.failMsg(.{ .tag = tag, .token = p.tok_i });
}

fn failExpected(p: *Parse, expected_token: Token.Tag) error{ ParseError, OutOfMemory } {
    @branchHint(.cold);
    return p.failMsg(.{
        .tag = .expected_token,
        .token = p.tok_i,
        .extra = .{ .expected_tag = expected_token },
    });
}

fn failMsg(p: *Parse, msg: Ast.Error) error{ ParseError, OutOfMemory } {
    @branchHint(.cold);
    try p.warnMsg(msg);
    return error.ParseError;
}

/// Root <- skip container_doc_comment? ContainerMembers eof
pub fn parseRoot(p: *Parse) !void {
    // Root node must be index 0.
    p.nodes.appendAssumeCapacity(.{
        .tag = .root,
        .main_token = 0,
        .data = undefined,
    });
    const root_members = try p.parseContainerMembers();
    const root_decls = try root_members.toSpan(p);
    if (p.tokenTag(p.tok_i) != .eof) {
        try p.warnExpected(.eof);
    }
    p.nodes.items(.data)[0] = .{ .extra_range = root_decls };
}

/// Parse in ZON mode. Subset of the language.
/// TODO: set a flag in Parse struct, and honor that flag
/// by emitting compilation errors when non-zon nodes are encountered.
pub fn parseZon(p: *Parse) !void {
    // We must use index 0 so that 0 can be used as null elsewhere.
    p.nodes.appendAssumeCapacity(.{
        .tag = .root,
        .main_token = 0,
        .data = undefined,
    });
    const node_index = p.expectExpr() catch |err| switch (err) {
        error.ParseError => {
            assert(p.errors.items.len > 0);
            return;
        },
        else => |e| return e,
    };
    if (p.tokenTag(p.tok_i) != .eof) {
        try p.warnExpected(.eof);
    }
    p.nodes.items(.data)[0] = .{ .node = node_index };
}

/// ContainerMembers <- ContainerDeclaration* (ContainerField COMMA)* (ContainerField / ContainerDeclaration*)
///
/// ContainerDeclaration <- TestDecl / ComptimeDecl / doc_comment? KEYWORD_pub? Decl
///
/// ComptimeDecl <- KEYWORD_comptime Block
fn parseContainerMembers(p: *Parse) Allocator.Error!Members {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);

    var field_state: union(enum) {
        /// No fields have been seen.
        none,
        /// Currently parsing fields.
        seen,
        /// Saw fields and then a declaration after them.
        /// Payload is first token of previous declaration.
        end: Node.Index,
        /// There was a declaration between fields, don't report more errors.
        err,
    } = .none;

    var last_field: TokenIndex = undefined;

    // Skip container doc comments.
    while (p.eatToken(.container_doc_comment)) |_| {}

    var trailing = false;
    while (true) {
        const doc_comment = try p.eatDocComments();

        switch (p.tokenTag(p.tok_i)) {
            .keyword_test => {
                if (doc_comment) |some| {
                    try p.warnMsg(.{ .tag = .test_doc_comment, .token = some });
                }
                const maybe_test_decl_node = try p.expectTestDeclRecoverable();
                if (maybe_test_decl_node) |test_decl_node| {
                    if (field_state == .seen) {
                        field_state = .{ .end = test_decl_node };
                    }
                    try p.scratch.append(p.gpa, test_decl_node);
                }
                trailing = false;
            },
            .keyword_comptime => switch (p.tokenTag(p.tok_i + 1)) {
                .l_brace => {
                    if (doc_comment) |some| {
                        try p.warnMsg(.{ .tag = .comptime_doc_comment, .token = some });
                    }
                    const comptime_token = p.nextToken();
                    const opt_block = p.parseBlock() catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.ParseError => blk: {
                            p.findNextContainerMember();
                            break :blk null;
                        },
                    };
                    if (opt_block) |block| {
                        const comptime_node = try p.addNode(.{
                            .tag = .@"comptime",
                            .main_token = comptime_token,
                            .data = .{ .node = block },
                        });
                        if (field_state == .seen) {
                            field_state = .{ .end = comptime_node };
                        }
                        try p.scratch.append(p.gpa, comptime_node);
                    }
                    trailing = false;
                },
                else => {
                    const identifier = p.tok_i;
                    defer last_field = identifier;
                    const container_field = p.expectContainerField() catch |err| switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        error.ParseError => {
                            p.findNextContainerMember();
                            continue;
                        },
                    };
                    switch (field_state) {
                        .none => field_state = .seen,
                        .err, .seen => {},
                        .end => |node| {
                            try p.warnMsg(.{
                                .tag = .decl_between_fields,
                                .token = p.nodeMainToken(node),
                            });
                            try p.warnMsg(.{
                                .tag = .previous_field,
                                .is_note = true,
                                .token = last_field,
                            });
                            try p.warnMsg(.{
                                .tag = .next_field,
                                .is_note = true,
                                .token = identifier,
                            });
                            // Continue parsing; error will be reported later.
                            field_state = .err;
                        },
                    }
                    try p.scratch.append(p.gpa, container_field);
                    switch (p.tokenTag(p.tok_i)) {
                        .comma => {
                            p.tok_i += 1;
                            trailing = true;
                            continue;
                        },
                        .r_brace, .eof => {
                            trailing = false;
                            break;
                        },
                        else => {},
                    }
                    // There is not allowed to be a decl after a field with no comma.
                    // Report error but recover parser.
                    try p.warn(.expected_comma_after_field);
                    p.findNextContainerMember();
                },
            },
            .keyword_pub => {
                p.tok_i += 1;
                const opt_top_level_decl = try p.expectTopLevelDeclRecoverable();
                if (opt_top_level_decl) |top_level_decl| {
                    if (field_state == .seen) {
                        field_state = .{ .end = top_level_decl };
                    }
                    try p.scratch.append(p.gpa, top_level_decl);
                }
                trailing = p.tokenTag(p.tok_i - 1) == .semicolon;
            },
            .keyword_usingnamespace => {
                const opt_node = try p.expectUsingNamespaceRecoverable();
                if (opt_node) |node| {
                    if (field_state == .seen) {
                        field_state = .{ .end = node };
                    }
                    try p.scratch.append(p.gpa, node);
                }
                trailing = p.tokenTag(p.tok_i - 1) == .semicolon;
            },
            .keyword_const,
            .keyword_var,
            .keyword_threadlocal,
            .keyword_export,
            .keyword_extern,
            .keyword_inline,
            .keyword_noinline,
            .keyword_fn,
            => {
                const opt_top_level_decl = try p.expectTopLevelDeclRecoverable();
                if (opt_top_level_decl) |top_level_decl| {
                    if (field_state == .seen) {
                        field_state = .{ .end = top_level_decl };
                    }
                    try p.scratch.append(p.gpa, top_level_decl);
                }
                trailing = p.tokenTag(p.tok_i - 1) == .semicolon;
            },
            .eof, .r_brace => {
                if (doc_comment) |tok| {
                    try p.warnMsg(.{
                        .tag = .unattached_doc_comment,
                        .token = tok,
                    });
                }
                break;
            },
            else => {
                const c_container = p.parseCStyleContainer() catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.ParseError => false,
                };
                if (c_container) continue;

                const identifier = p.tok_i;
                defer last_field = identifier;
                const container_field = p.expectContainerField() catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    error.ParseError => {
                        p.findNextContainerMember();
                        continue;
                    },
                };
                switch (field_state) {
                    .none => field_state = .seen,
                    .err, .seen => {},
                    .end => |node| {
                        try p.warnMsg(.{
                            .tag = .decl_between_fields,
                            .token = p.nodeMainToken(node),
                        });
                        try p.warnMsg(.{
                            .tag = .previous_field,
                            .is_note = true,
                            .token = last_field,
                        });
                        try p.warnMsg(.{
                            .tag = .next_field,
                            .is_note = true,
                            .token = identifier,
                        });
                        // Continue parsing; error will be reported later.
                        field_state = .err;
                    },
                }
                try p.scratch.append(p.gpa, container_field);
                switch (p.tokenTag(p.tok_i)) {
                    .comma => {
                        p.tok_i += 1;
                        trailing = true;
                        continue;
                    },
                    .r_brace, .eof => {
                        trailing = false;
                        break;
                    },
                    else => {},
                }
                // There is not allowed to be a decl after a field with no comma.
                // Report error but recover parser.
                try p.warn(.expected_comma_after_field);
                if (p.tokenTag(p.tok_i) == .semicolon and p.tokenTag(identifier) == .identifier) {
                    try p.warnMsg(.{
                        .tag = .var_const_decl,
                        .is_note = true,
                        .token = identifier,
                    });
                }
                p.findNextContainerMember();
                continue;
            },
        }
    }

    const items = p.scratch.items[scratch_top..];
    if (items.len <= 2) {
        return Members{
            .len = items.len,
            .data = .{ .opt_node_and_opt_node = .{
                if (items.len >= 1) items[0].toOptional() else .none,
                if (items.len >= 2) items[1].toOptional() else .none,
            } },
            .trailing = trailing,
        };
    } else {
        return Members{
            .len = items.len,
            .data = .{ .extra_range = try p.listToSpan(items) },
            .trailing = trailing,
        };
    }
}

/// Attempts to find next container member by searching for certain tokens
fn findNextContainerMember(p: *Parse) void {
    var level: u32 = 0;
    while (true) {
        const tok = p.nextToken();
        switch (p.tokenTag(tok)) {
            // Any of these can start a new top level declaration.
            .keyword_test,
            .keyword_comptime,
            .keyword_pub,
            .keyword_export,
            .keyword_extern,
            .keyword_inline,
            .keyword_noinline,
            .keyword_usingnamespace,
            .keyword_threadlocal,
            .keyword_const,
            .keyword_var,
            .keyword_fn,
            => {
                if (level == 0) {
                    p.tok_i -= 1;
                    return;
                }
            },
            .identifier => {
                if (p.tokenTag(tok + 1) == .comma and level == 0) {
                    p.tok_i -= 1;
                    return;
                }
            },
            .comma, .semicolon => {
                // this decl was likely meant to end here
                if (level == 0) {
                    return;
                }
            },
            .l_paren, .l_bracket, .l_brace => level += 1,
            .r_paren, .r_bracket => {
                if (level != 0) level -= 1;
            },
            .r_brace => {
                if (level == 0) {
                    // end of container, exit
                    p.tok_i -= 1;
                    return;
                }
                level -= 1;
            },
            .eof => {
                p.tok_i -= 1;
                return;
            },
            else => {},
        }
    }
}

/// Attempts to find the next statement by searching for a semicolon
fn findNextStmt(p: *Parse) void {
    var level: u32 = 0;
    while (true) {
        const tok = p.nextToken();
        switch (p.tokenTag(tok)) {
            .l_brace => level += 1,
            .r_brace => {
                if (level == 0) {
                    p.tok_i -= 1;
                    return;
                }
                level -= 1;
            },
            .semicolon => {
                if (level == 0) {
                    return;
                }
            },
            .eof => {
                p.tok_i -= 1;
                return;
            },
            else => {},
        }
    }
}

/// TestDecl <- KEYWORD_test (STRINGLITERALSINGLE / IDENTIFIER)? Block
fn expectTestDecl(p: *Parse) Error!Node.Index {
    const test_token = p.assertToken(.keyword_test);
    const name_token: OptionalTokenIndex = switch (p.tokenTag(p.tok_i)) {
        .string_literal, .identifier => .fromToken(p.nextToken()),
        else => .none,
    };
    const block_node = try p.parseBlock() orelse return p.fail(.expected_block);
    return p.addNode(.{
        .tag = .test_decl,
        .main_token = test_token,
        .data = .{ .opt_token_and_node = .{
            name_token,
            block_node,
        } },
    });
}

fn expectTestDeclRecoverable(p: *Parse) error{OutOfMemory}!?Node.Index {
    if (p.expectTestDecl()) |node| {
        return node;
    } else |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseError => {
            p.findNextContainerMember();
            return null;
        },
    }
}

/// Decl
///     <- (KEYWORD_export / KEYWORD_extern STRINGLITERALSINGLE? / KEYWORD_inline / KEYWORD_noinline)? FnProto (SEMICOLON / Block)
///      / (KEYWORD_export / KEYWORD_extern STRINGLITERALSINGLE?)? KEYWORD_threadlocal? VarDecl
///      / KEYWORD_usingnamespace Expr SEMICOLON
fn expectTopLevelDecl(p: *Parse) !?Node.Index {
    const extern_export_inline_token = p.nextToken();
    var is_extern: bool = false;
    var expect_fn: bool = false;
    var expect_var_or_fn: bool = false;
    switch (p.tokenTag(extern_export_inline_token)) {
        .keyword_extern => {
            _ = p.eatToken(.string_literal);
            is_extern = true;
            expect_var_or_fn = true;
        },
        .keyword_export => expect_var_or_fn = true,
        .keyword_inline, .keyword_noinline => expect_fn = true,
        else => p.tok_i -= 1,
    }
    const opt_fn_proto = try p.parseFnProto();
    if (opt_fn_proto) |fn_proto| {
        switch (p.tokenTag(p.tok_i)) {
            .semicolon => {
                p.tok_i += 1;
                return fn_proto;
            },
            .l_brace => {
                if (is_extern) {
                    try p.warnMsg(.{ .tag = .extern_fn_body, .token = extern_export_inline_token });
                    return null;
                }
                const fn_decl_index = try p.reserveNode(.fn_decl);
                errdefer p.unreserveNode(fn_decl_index);

                const body_block = try p.parseBlock();
                return p.setNode(fn_decl_index, .{
                    .tag = .fn_decl,
                    .main_token = p.nodeMainToken(fn_proto),
                    .data = .{ .node_and_node = .{
                        fn_proto,
                        body_block.?,
                    } },
                });
            },
            else => {
                // Since parseBlock only return error.ParseError on
                // a missing '}' we can assume this function was
                // supposed to end here.
                try p.warn(.expected_semi_or_lbrace);
                return null;
            },
        }
    }
    if (expect_fn) {
        try p.warn(.expected_fn);
        return error.ParseError;
    }

    const thread_local_token = p.eatToken(.keyword_threadlocal);
    if (try p.parseGlobalVarDecl()) |var_decl| return var_decl;
    if (thread_local_token != null) {
        return p.fail(.expected_var_decl);
    }
    if (expect_var_or_fn) {
        return p.fail(.expected_var_decl_or_fn);
    }
    if (p.tokenTag(p.tok_i) != .keyword_usingnamespace) {
        return p.fail(.expected_pub_item);
    }
    return try p.expectUsingNamespace();
}

fn expectTopLevelDeclRecoverable(p: *Parse) error{OutOfMemory}!?Node.Index {
    return p.expectTopLevelDecl() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseError => {
            p.findNextContainerMember();
            return null;
        },
    };
}

fn expectUsingNamespace(p: *Parse) !Node.Index {
    const usingnamespace_token = p.assertToken(.keyword_usingnamespace);
    const expr = try p.expectExpr();
    try p.expectSemicolon(.expected_semi_after_decl, false);
    return p.addNode(.{
        .tag = .@"usingnamespace",
        .main_token = usingnamespace_token,
        .data = .{ .node = expr },
    });
}

fn expectUsingNamespaceRecoverable(p: *Parse) error{OutOfMemory}!?Node.Index {
    return p.expectUsingNamespace() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseError => {
            p.findNextContainerMember();
            return null;
        },
    };
}

/// FnProto <- KEYWORD_fn IDENTIFIER? LPAREN ParamDeclList RPAREN ByteAlign? AddrSpace? LinkSection? CallConv? EXCLAMATIONMARK? TypeExpr
fn parseFnProto(p: *Parse) !?Node.Index {
    const fn_token = p.eatToken(.keyword_fn) orelse return null;

    // We want the fn proto node to be before its children in the array.
    const fn_proto_index = try p.reserveNode(.fn_proto);
    errdefer p.unreserveNode(fn_proto_index);

    _ = p.eatToken(.identifier);
    const params = try p.parseParamDeclList();
    const align_expr = try p.parseByteAlign();
    const addrspace_expr = try p.parseAddrSpace();
    const section_expr = try p.parseLinkSection();
    const callconv_expr = try p.parseCallconv();
    _ = p.eatToken(.bang);

    const return_type_expr = try p.parseTypeExpr();
    if (return_type_expr == null) {
        // most likely the user forgot to specify the return type.
        // Mark return type as invalid and try to continue.
        try p.warn(.expected_return_type);
    }

    if (align_expr == null and section_expr == null and callconv_expr == null and addrspace_expr == null) {
        switch (params) {
            .zero_or_one => |param| return p.setNode(fn_proto_index, .{
                .tag = .fn_proto_simple,
                .main_token = fn_token,
                .data = .{ .opt_node_and_opt_node = .{
                    param,
                    .fromOptional(return_type_expr),
                } },
            }),
            .multi => |span| {
                return p.setNode(fn_proto_index, .{
                    .tag = .fn_proto_multi,
                    .main_token = fn_token,
                    .data = .{ .extra_and_opt_node = .{
                        try p.addExtra(Node.SubRange{
                            .start = span.start,
                            .end = span.end,
                        }),
                        .fromOptional(return_type_expr),
                    } },
                });
            },
        }
    }
    switch (params) {
        .zero_or_one => |param| return p.setNode(fn_proto_index, .{
            .tag = .fn_proto_one,
            .main_token = fn_token,
            .data = .{ .extra_and_opt_node = .{
                try p.addExtra(Node.FnProtoOne{
                    .param = param,
                    .align_expr = .fromOptional(align_expr),
                    .addrspace_expr = .fromOptional(addrspace_expr),
                    .section_expr = .fromOptional(section_expr),
                    .callconv_expr = .fromOptional(callconv_expr),
                }),
                .fromOptional(return_type_expr),
            } },
        }),
        .multi => |span| {
            return p.setNode(fn_proto_index, .{
                .tag = .fn_proto,
                .main_token = fn_token,
                .data = .{ .extra_and_opt_node = .{
                    try p.addExtra(Node.FnProto{
                        .params_start = span.start,
                        .params_end = span.end,
                        .align_expr = .fromOptional(align_expr),
                        .addrspace_expr = .fromOptional(addrspace_expr),
                        .section_expr = .fromOptional(section_expr),
                        .callconv_expr = .fromOptional(callconv_expr),
                    }),
                    .fromOptional(return_type_expr),
                } },
            });
        },
    }
}

fn setVarDeclInitExpr(p: *Parse, var_decl: Node.Index, init_expr: Node.OptionalIndex) void {
    const init_expr_result = switch (p.nodeTag(var_decl)) {
        .simple_var_decl => &p.nodes.items(.data)[@intFromEnum(var_decl)].opt_node_and_opt_node[1],
        .aligned_var_decl => &p.nodes.items(.data)[@intFromEnum(var_decl)].node_and_opt_node[1],
        .local_var_decl, .global_var_decl => &p.nodes.items(.data)[@intFromEnum(var_decl)].extra_and_opt_node[1],
        else => unreachable,
    };
    init_expr_result.* = init_expr;
}

/// VarDeclProto <- (KEYWORD_const / KEYWORD_var) IDENTIFIER (COLON TypeExpr)? ByteAlign? AddrSpace? LinkSection?
/// Returns a `*_var_decl` node with its rhs (init expression) initialized to .none.
fn parseVarDeclProto(p: *Parse) !?Node.Index {
    const mut_token = p.eatToken(.keyword_const) orelse
        p.eatToken(.keyword_var) orelse
        return null;

    _ = try p.expectToken(.identifier);
    const opt_type_node = if (p.eatToken(.colon) == null) null else try p.expectTypeExpr();
    const opt_align_node = try p.parseByteAlign();
    const opt_addrspace_node = try p.parseAddrSpace();
    const opt_section_node = try p.parseLinkSection();

    if (opt_section_node == null and opt_addrspace_node == null) {
        const align_node = opt_align_node orelse {
            return try p.addNode(.{
                .tag = .simple_var_decl,
                .main_token = mut_token,
                .data = .{
                    .opt_node_and_opt_node = .{
                        .fromOptional(opt_type_node),
                        .none, // set later with `setVarDeclInitExpr
                    },
                },
            });
        };

        const type_node = opt_type_node orelse {
            return try p.addNode(.{
                .tag = .aligned_var_decl,
                .main_token = mut_token,
                .data = .{
                    .node_and_opt_node = .{
                        align_node,
                        .none, // set later with `setVarDeclInitExpr
                    },
                },
            });
        };

        return try p.addNode(.{
            .tag = .local_var_decl,
            .main_token = mut_token,
            .data = .{
                .extra_and_opt_node = .{
                    try p.addExtra(Node.LocalVarDecl{
                        .type_node = type_node,
                        .align_node = align_node,
                    }),
                    .none, // set later with `setVarDeclInitExpr
                },
            },
        });
    } else {
        return try p.addNode(.{
            .tag = .global_var_decl,
            .main_token = mut_token,
            .data = .{
                .extra_and_opt_node = .{
                    try p.addExtra(Node.GlobalVarDecl{
                        .type_node = .fromOptional(opt_type_node),
                        .align_node = .fromOptional(opt_align_node),
                        .addrspace_node = .fromOptional(opt_addrspace_node),
                        .section_node = .fromOptional(opt_section_node),
                    }),
                    .none, // set later with `setVarDeclInitExpr
                },
            },
        });
    }
}

/// GlobalVarDecl <- VarDeclProto (EQUAL Expr?) SEMICOLON
fn parseGlobalVarDecl(p: *Parse) !?Node.Index {
    const var_decl = try p.parseVarDeclProto() orelse return null;

    const init_node: ?Node.Index = switch (p.tokenTag(p.tok_i)) {
        .equal_equal => blk: {
            try p.warn(.wrong_equal_var_decl);
            p.tok_i += 1;
            break :blk try p.expectExpr();
        },
        .equal => blk: {
            p.tok_i += 1;
            break :blk try p.expectExpr();
        },
        else => null,
    };

    p.setVarDeclInitExpr(var_decl, .fromOptional(init_node));

    try p.expectSemicolon(.expected_semi_after_decl, false);
    return var_decl;
}

/// ContainerField <- doc_comment? KEYWORD_comptime? !KEYWORD_fn (IDENTIFIER COLON)? TypeExpr ByteAlign? (EQUAL Expr)?
fn expectContainerField(p: *Parse) !Node.Index {
    _ = p.eatToken(.keyword_comptime);
    const main_token = p.tok_i;
    _ = p.eatTokens(&.{ .identifier, .colon });
    const type_expr = try p.expectTypeExpr();
    const align_expr = try p.parseByteAlign();
    const value_expr = if (p.eatToken(.equal) == null) null else try p.expectExpr();

    if (align_expr == null) {
        return p.addNode(.{
            .tag = .container_field_init,
            .main_token = main_token,
            .data = .{ .node_and_opt_node = .{
                type_expr,
                .fromOptional(value_expr),
            } },
        });
    } else if (value_expr == null) {
        return p.addNode(.{
            .tag = .container_field_align,
            .main_token = main_token,
            .data = .{ .node_and_node = .{
                type_expr,
                align_expr.?,
            } },
        });
    } else {
        return p.addNode(.{
            .tag = .container_field,
            .main_token = main_token,
            .data = .{ .node_and_extra = .{
                type_expr, try p.addExtra(Node.ContainerField{
                    .align_expr = align_expr.?,
                    .value_expr = value_expr.?,
                }),
            } },
        });
    }
}

/// Statement
///     <- KEYWORD_comptime ComptimeStatement
///      / KEYWORD_nosuspend BlockExprStatement
///      / KEYWORD_suspend BlockExprStatement
///      / KEYWORD_defer BlockExprStatement
///      / KEYWORD_errdefer Payload? BlockExprStatement
///      / IfStatement
///      / LabeledStatement
///      / VarDeclExprStatement
fn expectStatement(p: *Parse, allow_defer_var: bool) Error!Node.Index {
    if (p.eatToken(.keyword_comptime)) |comptime_token| {
        const opt_block_expr = try p.parseBlockExpr();
        if (opt_block_expr) |block_expr| {
            return p.addNode(.{
                .tag = .@"comptime",
                .main_token = comptime_token,
                .data = .{ .node = block_expr },
            });
        }

        if (allow_defer_var) {
            return p.expectVarDeclExprStatement(comptime_token);
        } else {
            const assign = try p.expectAssignExpr();
            try p.expectSemicolon(.expected_semi_after_stmt, true);
            return p.addNode(.{
                .tag = .@"comptime",
                .main_token = comptime_token,
                .data = .{ .node = assign },
            });
        }
    }

    switch (p.tokenTag(p.tok_i)) {
        .keyword_nosuspend => {
            return p.addNode(.{
                .tag = .@"nosuspend",
                .main_token = p.nextToken(),
                .data = .{ .node = try p.expectBlockExprStatement() },
            });
        },
        .keyword_suspend => {
            const token = p.nextToken();
            const block_expr = try p.expectBlockExprStatement();
            return p.addNode(.{
                .tag = .@"suspend",
                .main_token = token,
                .data = .{ .node = block_expr },
            });
        },
        .keyword_defer => if (allow_defer_var) return p.addNode(.{
            .tag = .@"defer",
            .main_token = p.nextToken(),
            .data = .{ .node = try p.expectBlockExprStatement() },
        }),
        .keyword_errdefer => if (allow_defer_var) return p.addNode(.{
            .tag = .@"errdefer",
            .main_token = p.nextToken(),
            .data = .{ .opt_token_and_node = .{
                try p.parsePayload(),
                try p.expectBlockExprStatement(),
            } },
        }),
        .keyword_if => return p.expectIfStatement(),
        .keyword_enum, .keyword_struct, .keyword_union => {
            const identifier = p.tok_i + 1;
            if (try p.parseCStyleContainer()) {
                // Return something so that `expectStatement` is happy.
                return p.addNode(.{
                    .tag = .identifier,
                    .main_token = identifier,
                    .data = undefined,
                });
            }
        },
        else => {},
    }

    if (try p.parseLabeledStatement()) |labeled_statement| return labeled_statement;

    if (allow_defer_var) {
        return p.expectVarDeclExprStatement(null);
    } else {
        const assign = try p.expectAssignExpr();
        try p.expectSemicolon(.expected_semi_after_stmt, true);
        return assign;
    }
}

/// ComptimeStatement
///     <- BlockExpr
///      / VarDeclExprStatement
fn expectComptimeStatement(p: *Parse, comptime_token: TokenIndex) !Node.Index {
    const maybe_block_expr = try p.parseBlockExpr();
    if (maybe_block_expr) |block_expr| {
        return p.addNode(.{
            .tag = .@"comptime",
            .main_token = comptime_token,
            .data = .{
                .lhs = .{ .node = block_expr },
                .rhs = undefined,
            },
        });
    }
    return p.expectVarDeclExprStatement(comptime_token);
}

/// VarDeclExprStatement
///    <- VarDeclProto (COMMA (VarDeclProto / Expr))* EQUAL Expr SEMICOLON
///     / Expr (AssignOp Expr / (COMMA (VarDeclProto / Expr))+ EQUAL Expr)? SEMICOLON
fn expectVarDeclExprStatement(p: *Parse, comptime_token: ?TokenIndex) !Node.Index {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);

    while (true) {
        const opt_var_decl_proto = try p.parseVarDeclProto();
        if (opt_var_decl_proto) |var_decl| {
            try p.scratch.append(p.gpa, var_decl);
        } else {
            const expr = try p.parseExpr() orelse {
                if (p.scratch.items.len == scratch_top) {
                    // We parsed nothing
                    return p.fail(.expected_statement);
                } else {
                    // We've had at least one LHS, but had a bad comma
                    return p.fail(.expected_expr_or_var_decl);
                }
            };
            try p.scratch.append(p.gpa, expr);
        }
        _ = p.eatToken(.comma) orelse break;
    }

    const lhs_count = p.scratch.items.len - scratch_top;
    assert(lhs_count > 0);

    const equal_token = p.eatToken(.equal) orelse eql: {
        if (lhs_count > 1) {
            // Definitely a destructure, so allow recovering from ==
            if (p.eatToken(.equal_equal)) |tok| {
                try p.warnMsg(.{ .tag = .wrong_equal_var_decl, .token = tok });
                break :eql tok;
            }
            return p.failExpected(.equal);
        }
        const lhs = p.scratch.items[scratch_top];
        switch (p.nodeTag(lhs)) {
            .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
                // Definitely a var decl, so allow recovering from ==
                if (p.eatToken(.equal_equal)) |tok| {
                    try p.warnMsg(.{ .tag = .wrong_equal_var_decl, .token = tok });
                    break :eql tok;
                }
                return p.failExpected(.equal);
            },
            else => {},
        }

        const expr = try p.finishAssignExpr(lhs);
        try p.expectSemicolon(.expected_semi_after_stmt, true);
        if (comptime_token) |t| {
            return p.addNode(.{
                .tag = .@"comptime",
                .main_token = t,
                .data = .{ .node = expr },
            });
        } else {
            return expr;
        }
    };

    const rhs = try p.expectExpr();
    try p.expectSemicolon(.expected_semi_after_stmt, true);

    if (lhs_count == 1) {
        const lhs = p.scratch.items[scratch_top];
        switch (p.nodeTag(lhs)) {
            .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => {
                p.setVarDeclInitExpr(lhs, rhs.toOptional());
                // Don't need to wrap in comptime
                return lhs;
            },
            else => {},
        }
        const expr = try p.addNode(.{
            .tag = .assign,
            .main_token = equal_token,
            .data = .{ .node_and_node = .{
                lhs,
                rhs,
            } },
        });
        if (comptime_token) |t| {
            return p.addNode(.{
                .tag = .@"comptime",
                .main_token = t,
                .data = .{ .node = expr },
            });
        } else {
            return expr;
        }
    }

    // An actual destructure! No need for any `comptime` wrapper here.

    const extra_start: ExtraIndex = @enumFromInt(p.extra_data.items.len);
    try p.extra_data.ensureUnusedCapacity(p.gpa, lhs_count + 1);
    p.extra_data.appendAssumeCapacity(@intCast(lhs_count));
    p.extra_data.appendSliceAssumeCapacity(@ptrCast(p.scratch.items[scratch_top..]));

    return p.addNode(.{
        .tag = .assign_destructure,
        .main_token = equal_token,
        .data = .{ .extra_and_node = .{
            extra_start,
            rhs,
        } },
    });
}

/// If a parse error occurs, reports an error, but then finds the next statement
/// and returns that one instead. If a parse error occurs but there is no following
/// statement, returns 0.
fn expectStatementRecoverable(p: *Parse) Error!?Node.Index {
    while (true) {
        return p.expectStatement(true) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ParseError => {
                p.findNextStmt(); // Try to skip to the next statement.
                switch (p.tokenTag(p.tok_i)) {
                    .r_brace => return null,
                    .eof => return error.ParseError,
                    else => continue,
                }
            },
        };
    }
}

/// IfStatement
///     <- IfPrefix BlockExpr ( KEYWORD_else Payload? Statement )?
///      / IfPrefix AssignExpr ( SEMICOLON / KEYWORD_else Payload? Statement )
fn expectIfStatement(p: *Parse) !Node.Index {
    const if_token = p.assertToken(.keyword_if);
    _ = try p.expectToken(.l_paren);
    const condition = try p.expectExpr();
    _ = try p.expectToken(.r_paren);
    _ = try p.parsePtrPayload();

    // TODO propose to change the syntax so that semicolons are always required
    // inside if statements, even if there is an `else`.
    var else_required = false;
    const then_expr = blk: {
        const block_expr = try p.parseBlockExpr();
        if (block_expr) |block| break :blk block;
        const assign_expr = try p.parseAssignExpr() orelse {
            return p.fail(.expected_block_or_assignment);
        };
        if (p.eatToken(.semicolon)) |_| {
            return p.addNode(.{
                .tag = .if_simple,
                .main_token = if_token,
                .data = .{ .node_and_node = .{
                    condition,
                    assign_expr,
                } },
            });
        }
        else_required = true;
        break :blk assign_expr;
    };
    _ = p.eatToken(.keyword_else) orelse {
        if (else_required) {
            try p.warn(.expected_semi_or_else);
        }
        return p.addNode(.{
            .tag = .if_simple,
            .main_token = if_token,
            .data = .{ .node_and_node = .{
                condition,
                then_expr,
            } },
        });
    };
    _ = try p.parsePayload();
    const else_expr = try p.expectStatement(false);
    return p.addNode(.{
        .tag = .@"if",
        .main_token = if_token,
        .data = .{ .node_and_extra = .{
            condition, try p.addExtra(Node.If{
                .then_expr = then_expr,
                .else_expr = else_expr,
            }),
        } },
    });
}

/// LabeledStatement <- BlockLabel? (Block / LoopStatement / SwitchExpr)
fn parseLabeledStatement(p: *Parse) !?Node.Index {
    const opt_label_token = p.parseBlockLabel();

    if (try p.parseBlock()) |block| return block;
    if (try p.parseLoopStatement()) |loop_stmt| return loop_stmt;
    if (try p.parseSwitchExpr(opt_label_token != null)) |switch_expr| return switch_expr;

    const label_token = opt_label_token orelse return null;

    const after_colon = p.tok_i;
    if (try p.parseTypeExpr()) |_| {
        const a = try p.parseByteAlign();
        const b = try p.parseAddrSpace();
        const c = try p.parseLinkSection();
        const d = if (p.eatToken(.equal) == null) null else try p.expectExpr();
        if (a != null or b != null or c != null or d != null) {
            return p.failMsg(.{ .tag = .expected_var_const, .token = label_token });
        }
    }
    return p.failMsg(.{ .tag = .expected_labelable, .token = after_colon });
}

/// LoopStatement <- KEYWORD_inline? (ForStatement / WhileStatement)
fn parseLoopStatement(p: *Parse) !?Node.Index {
    const inline_token = p.eatToken(.keyword_inline);

    if (try p.parseForStatement()) |for_statement| return for_statement;
    if (try p.parseWhileStatement()) |while_statement| return while_statement;

    if (inline_token == null) return null;

    // If we've seen "inline", there should have been a "for" or "while"
    return p.fail(.expected_inlinable);
}

/// ForStatement
///     <- ForPrefix BlockExpr ( KEYWORD_else Statement )?
///      / ForPrefix AssignExpr ( SEMICOLON / KEYWORD_else Statement )
fn parseForStatement(p: *Parse) !?Node.Index {
    const for_token = p.eatToken(.keyword_for) orelse return null;

    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);
    const inputs = try p.forPrefix();

    var else_required = false;
    var seen_semicolon = false;
    const then_expr = blk: {
        const block_expr = try p.parseBlockExpr();
        if (block_expr) |block| break :blk block;
        const assign_expr = try p.parseAssignExpr() orelse {
            return p.fail(.expected_block_or_assignment);
        };
        if (p.eatToken(.semicolon)) |_| {
            seen_semicolon = true;
            break :blk assign_expr;
        }
        else_required = true;
        break :blk assign_expr;
    };
    var has_else = false;
    if (!seen_semicolon and p.eatToken(.keyword_else) != null) {
        try p.scratch.append(p.gpa, then_expr);
        const else_stmt = try p.expectStatement(false);
        try p.scratch.append(p.gpa, else_stmt);
        has_else = true;
    } else if (inputs == 1) {
        if (else_required) try p.warn(.expected_semi_or_else);
        return try p.addNode(.{
            .tag = .for_simple,
            .main_token = for_token,
            .data = .{ .node_and_node = .{
                p.scratch.items[scratch_top],
                then_expr,
            } },
        });
    } else {
        if (else_required) try p.warn(.expected_semi_or_else);
        try p.scratch.append(p.gpa, then_expr);
    }
    return try p.addNode(.{
        .tag = .@"for",
        .main_token = for_token,
        .data = .{ .@"for" = .{
            (try p.listToSpan(p.scratch.items[scratch_top..])).start,
            .{ .inputs = @intCast(inputs), .has_else = has_else },
        } },
    });
}

/// WhilePrefix <- KEYWORD_while LPAREN Expr RPAREN PtrPayload? WhileContinueExpr?
///
/// WhileStatement
///     <- WhilePrefix BlockExpr ( KEYWORD_else Payload? Statement )?
///      / WhilePrefix AssignExpr ( SEMICOLON / KEYWORD_else Payload? Statement )
fn parseWhileStatement(p: *Parse) !?Node.Index {
    const while_token = p.eatToken(.keyword_while) orelse return null;
    _ = try p.expectToken(.l_paren);
    const condition = try p.expectExpr();
    _ = try p.expectToken(.r_paren);
    _ = try p.parsePtrPayload();
    const cont_expr = try p.parseWhileContinueExpr();

    // TODO propose to change the syntax so that semicolons are always required
    // inside while statements, even if there is an `else`.
    var else_required = false;
    const then_expr = blk: {
        const block_expr = try p.parseBlockExpr();
        if (block_expr) |block| break :blk block;
        const assign_expr = try p.parseAssignExpr() orelse {
            return p.fail(.expected_block_or_assignment);
        };
        if (p.eatToken(.semicolon)) |_| {
            if (cont_expr == null) {
                return try p.addNode(.{
                    .tag = .while_simple,
                    .main_token = while_token,
                    .data = .{ .node_and_node = .{
                        condition,
                        assign_expr,
                    } },
                });
            } else {
                return try p.addNode(.{
                    .tag = .while_cont,
                    .main_token = while_token,
                    .data = .{ .node_and_extra = .{
                        condition,
                        try p.addExtra(Node.WhileCont{
                            .cont_expr = cont_expr.?,
                            .then_expr = assign_expr,
                        }),
                    } },
                });
            }
        }
        else_required = true;
        break :blk assign_expr;
    };
    _ = p.eatToken(.keyword_else) orelse {
        if (else_required) {
            try p.warn(.expected_semi_or_else);
        }
        if (cont_expr == null) {
            return try p.addNode(.{
                .tag = .while_simple,
                .main_token = while_token,
                .data = .{ .node_and_node = .{
                    condition,
                    then_expr,
                } },
            });
        } else {
            return try p.addNode(.{
                .tag = .while_cont,
                .main_token = while_token,
                .data = .{ .node_and_extra = .{
                    condition,
                    try p.addExtra(Node.WhileCont{
                        .cont_expr = cont_expr.?,
                        .then_expr = then_expr,
                    }),
                } },
            });
        }
    };
    _ = try p.parsePayload();
    const else_expr = try p.expectStatement(false);
    return try p.addNode(.{
        .tag = .@"while",
        .main_token = while_token,
        .data = .{ .node_and_extra = .{
            condition, try p.addExtra(Node.While{
                .cont_expr = .fromOptional(cont_expr),
                .then_expr = then_expr,
                .else_expr = else_expr,
            }),
        } },
    });
}

/// BlockExprStatement
///     <- BlockExpr
///      / AssignExpr SEMICOLON
fn parseBlockExprStatement(p: *Parse) !?Node.Index {
    const block_expr = try p.parseBlockExpr();
    if (block_expr) |expr| return expr;
    const assign_expr = try p.parseAssignExpr();
    if (assign_expr) |expr| {
        try p.expectSemicolon(.expected_semi_after_stmt, true);
        return expr;
    }
    return null;
}

fn expectBlockExprStatement(p: *Parse) !Node.Index {
    return try p.parseBlockExprStatement() orelse return p.fail(.expected_block_or_expr);
}

/// BlockExpr <- BlockLabel? Block
fn parseBlockExpr(p: *Parse) Error!?Node.Index {
    switch (p.tokenTag(p.tok_i)) {
        .identifier => {
            if (p.tokenTag(p.tok_i + 1) == .colon and
                p.tokenTag(p.tok_i + 2) == .l_brace)
            {
                p.tok_i += 2;
                return p.parseBlock();
            } else {
                return null;
            }
        },
        .l_brace => return p.parseBlock(),
        else => return null,
    }
}

/// AssignExpr <- Expr (AssignOp Expr / (COMMA Expr)+ EQUAL Expr)?
///
/// AssignOp
///     <- ASTERISKEQUAL
///      / ASTERISKPIPEEQUAL
///      / SLASHEQUAL
///      / PERCENTEQUAL
///      / PLUSEQUAL
///      / PLUSPIPEEQUAL
///      / MINUSEQUAL
///      / MINUSPIPEEQUAL
///      / LARROW2EQUAL
///      / LARROW2PIPEEQUAL
///      / RARROW2EQUAL
///      / AMPERSANDEQUAL
///      / CARETEQUAL
///      / PIPEEQUAL
///      / ASTERISKPERCENTEQUAL
///      / PLUSPERCENTEQUAL
///      / MINUSPERCENTEQUAL
///      / EQUAL
fn parseAssignExpr(p: *Parse) !?Node.Index {
    const expr = try p.parseExpr() orelse return null;
    return try p.finishAssignExpr(expr);
}

/// SingleAssignExpr <- Expr (AssignOp Expr)?
fn parseSingleAssignExpr(p: *Parse) !?Node.Index {
    const lhs = try p.parseExpr() orelse return null;
    const tag = assignOpNode(p.tokenTag(p.tok_i)) orelse return lhs;
    return try p.addNode(.{
        .tag = tag,
        .main_token = p.nextToken(),
        .data = .{ .node_and_node = .{
            lhs,
            try p.expectExpr(),
        } },
    });
}

fn finishAssignExpr(p: *Parse, lhs: Node.Index) !Node.Index {
    const tok = p.tokenTag(p.tok_i);
    if (tok == .comma) return p.finishAssignDestructureExpr(lhs);
    const tag = assignOpNode(tok) orelse return lhs;
    return p.addNode(.{
        .tag = tag,
        .main_token = p.nextToken(),
        .data = .{ .node_and_node = .{
            lhs,
            try p.expectExpr(),
        } },
    });
}

fn assignOpNode(tok: Token.Tag) ?Node.Tag {
    return switch (tok) {
        .asterisk_equal => .assign_mul,
        .slash_equal => .assign_div,
        .percent_equal => .assign_mod,
        .plus_equal => .assign_add,
        .minus_equal => .assign_sub,
        .angle_bracket_angle_bracket_left_equal => .assign_shl,
        .angle_bracket_angle_bracket_left_pipe_equal => .assign_shl_sat,
        .angle_bracket_angle_bracket_right_equal => .assign_shr,
        .ampersand_equal => .assign_bit_and,
        .caret_equal => .assign_bit_xor,
        .pipe_equal => .assign_bit_or,
        .asterisk_percent_equal => .assign_mul_wrap,
        .plus_percent_equal => .assign_add_wrap,
        .minus_percent_equal => .assign_sub_wrap,
        .asterisk_pipe_equal => .assign_mul_sat,
        .plus_pipe_equal => .assign_add_sat,
        .minus_pipe_equal => .assign_sub_sat,
        .equal => .assign,
        else => null,
    };
}

fn finishAssignDestructureExpr(p: *Parse, first_lhs: Node.Index) !Node.Index {
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);

    try p.scratch.append(p.gpa, first_lhs);

    while (p.eatToken(.comma)) |_| {
        const expr = try p.expectExpr();
        try p.scratch.append(p.gpa, expr);
    }

    const equal_token = try p.expectToken(.equal);

    const rhs = try p.expectExpr();

    const lhs_count = p.scratch.items.len - scratch_top;
    assert(lhs_count > 1); // we already had first_lhs, and must have at least one more lvalue

    const extra_start: ExtraIndex = @enumFromInt(p.extra_data.items.len);
    try p.extra_data.ensureUnusedCapacity(p.gpa, lhs_count + 1);
    p.extra_data.appendAssumeCapacity(@intCast(lhs_count));
    p.extra_data.appendSliceAssumeCapacity(@ptrCast(p.scratch.items[scratch_top..]));

    return p.addNode(.{
        .tag = .assign_destructure,
        .main_token = equal_token,
        .data = .{ .extra_and_node = .{
            extra_start,
            rhs,
        } },
    });
}

fn expectSingleAssignExpr(p: *Parse) !Node.Index {
    return try p.parseSingleAssignExpr() orelse return p.fail(.expected_expr_or_assignment);
}

fn expectAssignExpr(p: *Parse) !Node.Index {
    return try p.parseAssignExpr() orelse return p.fail(.expected_expr_or_assignment);
}

fn parseExpr(p: *Parse) Error!?Node.Index {
    return p.parseExprPrecedence(0);
}

fn expectExpr(p: *Parse) Error!Node.Index {
    return try p.parseExpr() orelse return p.fail(.expected_expr);
}

const Assoc = enum {
    left,
    none,
};

const OperInfo = struct {
    prec: i8,
    tag: Node.Tag,
    assoc: Assoc = Assoc.left,
};

// A table of binary operator information. Higher precedence numbers are
// stickier. All operators at the same precedence level should have the same
// associativity.
const operTable = std.enums.directEnumArrayDefault(Token.Tag, OperInfo, .{ .prec = -1, .tag = Node.Tag.root }, 0, .{
    .keyword_or = .{ .prec = 10, .tag = .bool_or },

    .keyword_and = .{ .prec = 20, .tag = .bool_and },

    .equal_equal = .{ .prec = 30, .tag = .equal_equal, .assoc = Assoc.none },
    .bang_equal = .{ .prec = 30, .tag = .bang_equal, .assoc = Assoc.none },
    .angle_bracket_left = .{ .prec = 30, .tag = .less_than, .assoc = Assoc.none },
    .angle_bracket_right = .{ .prec = 30, .tag = .greater_than, .assoc = Assoc.none },
    .angle_bracket_left_equal = .{ .prec = 30, .tag = .less_or_equal, .assoc = Assoc.none },
    .angle_bracket_right_equal = .{ .prec = 30, .tag = .greater_or_equal, .assoc = Assoc.none },

    .ampersand = .{ .prec = 40, .tag = .bit_and },
    .caret = .{ .prec = 40, .tag = .bit_xor },
    .pipe = .{ .prec = 40, .tag = .bit_or },
    .keyword_orelse = .{ .prec = 40, .tag = .@"orelse" },
    .keyword_catch = .{ .prec = 40, .tag = .@"catch" },

    .angle_bracket_angle_bracket_left = .{ .prec = 50, .tag = .shl },
    .angle_bracket_angle_bracket_left_pipe = .{ .prec = 50, .tag = .shl_sat },
    .angle_bracket_angle_bracket_right = .{ .prec = 50, .tag = .shr },

    .plus = .{ .prec = 60, .tag = .add },
    .minus = .{ .prec = 60, .tag = .sub },
    .plus_plus = .{ .prec = 60, .tag = .array_cat },
    .plus_percent = .{ .prec = 60, .tag = .add_wrap },
    .minus_percent = .{ .prec = 60, .tag = .sub_wrap },
    .plus_pipe = .{ .prec = 60, .tag = .add_sat },
    .minus_pipe = .{ .prec = 60, .tag = .sub_sat },

    .pipe_pipe = .{ .prec = 70, .tag = .merge_error_sets },
    .asterisk = .{ .prec = 70, .tag = .mul },
    .slash = .{ .prec = 70, .tag = .div },
    .percent = .{ .prec = 70, .tag = .mod },
    .asterisk_asterisk = .{ .prec = 70, .tag = .array_mult },
    .asterisk_percent = .{ .prec = 70, .tag = .mul_wrap },
    .asterisk_pipe = .{ .prec = 70, .tag = .mul_sat },
});

fn parseExprPrecedence(p: *Parse, min_prec: i32) Error!?Node.Index {
    assert(min_prec >= 0);
    var node = try p.parsePrefixExpr() orelse return null;

    var banned_prec: i8 = -1;

    while (true) {
        const tok_tag = p.tokenTag(p.tok_i);
        const info = operTable[@as(usize, @intCast(@intFromEnum(tok_tag)))];
        if (info.prec < min_prec) {
            break;
        }
        if (info.prec == banned_prec) {
            return p.fail(.chained_comparison_operators);
        }

        const oper_token = p.nextToken();
        // Special-case handling for "catch"
        if (tok_tag == .keyword_catch) {
            _ = try p.parsePayload();
        }
        const rhs = try p.parseExprPrecedence(info.prec + 1) orelse {
            try p.warn(.expected_expr);
            return node;
        };

        {
            const tok_len = tok_tag.lexeme().?.len;
            const char_before = p.source[p.tokenStart(oper_token) - 1];
            const char_after = p.source[p.tokenStart(oper_token) + tok_len];
            if (tok_tag == .ampersand and char_after == '&') {
                // without types we don't know if '&&' was intended as 'bitwise_and address_of', or a c-style logical_and
                // The best the parser can do is recommend changing it to 'and' or ' & &'
                try p.warnMsg(.{ .tag = .invalid_ampersand_ampersand, .token = oper_token });
            } else if (std.ascii.isWhitespace(char_before) != std.ascii.isWhitespace(char_after)) {
                try p.warnMsg(.{ .tag = .mismatched_binary_op_whitespace, .token = oper_token });
            }
        }

        node = try p.addNode(.{
            .tag = info.tag,
            .main_token = oper_token,
            .data = .{ .node_and_node = .{ node, rhs } },
        });

        if (info.assoc == Assoc.none) {
            banned_prec = info.prec;
        }
    }

    return node;
}

/// PrefixExpr <- PrefixOp* PrimaryExpr
///
/// PrefixOp
///     <- EXCLAMATIONMARK
///      / MINUS
///      / TILDE
///      / MINUSPERCENT
///      / AMPERSAND
///      / KEYWORD_try
///      / KEYWORD_await
fn parsePrefixExpr(p: *Parse) Error!?Node.Index {
    const tag: Node.Tag = switch (p.tokenTag(p.tok_i)) {
        .bang => .bool_not,
        .minus => .negation,
        .tilde => .bit_not,
        .minus_percent => .negation_wrap,
        .ampersand => .address_of,
        .keyword_try => .@"try",
        .keyword_await => .@"await",
        else => return p.parsePrimaryExpr(),
    };
    return try p.addNode(.{
        .tag = tag,
        .main_token = p.nextToken(),
        .data = .{ .node = try p.expectPrefixExpr() },
    });
}

fn expectPrefixExpr(p: *Parse) Error!Node.Index {
    return try p.parsePrefixExpr() orelse return p.fail(.expected_prefix_expr);
}

/// TypeExpr <- PrefixTypeOp* ErrorUnionExpr
///
/// PrefixTypeOp
///     <- QUESTIONMARK
///      / KEYWORD_anyframe MINUSRARROW
///      / SliceTypeStart (ByteAlign / AddrSpace / KEYWORD_const / KEYWORD_volatile / KEYWORD_allowzero)*
///      / PtrTypeStart (AddrSpace / KEYWORD_align LPAREN Expr (COLON Expr COLON Expr)? RPAREN / KEYWORD_const / KEYWORD_volatile / KEYWORD_allowzero)*
///      / ArrayTypeStart
///
/// SliceTypeStart <- LBRACKET (COLON Expr)? RBRACKET
///
/// PtrTypeStart
///     <- ASTERISK
///      / ASTERISK2
///      / LBRACKET ASTERISK (LETTERC / COLON Expr)? RBRACKET
///
/// ArrayTypeStart <- LBRACKET Expr (COLON Expr)? RBRACKET
fn parseTypeExpr(p: *Parse) Error!?Node.Index {
    switch (p.tokenTag(p.tok_i)) {
        .question_mark => return try p.addNode(.{
            .tag = .optional_type,
            .main_token = p.nextToken(),
            .data = .{ .node = try p.expectTypeExpr() },
        }),
        .keyword_anyframe => switch (p.tokenTag(p.tok_i + 1)) {
            .arrow => return try p.addNode(.{
                .tag = .anyframe_type,
                .main_token = p.nextToken(),
                .data = .{ .token_and_node = .{
                    p.nextToken(),
                    try p.expectTypeExpr(),
                } },
            }),
            else => return try p.parseErrorUnionExpr(),
        },
        .asterisk => {
            const asterisk = p.nextToken();
            const mods = try p.parsePtrModifiers();
            const elem_type = try p.expectTypeExpr();
            if (mods.bit_range_start != .none) {
                return try p.addNode(.{
                    .tag = .ptr_type_bit_range,
                    .main_token = asterisk,
                    .data = .{ .extra_and_node = .{
                        try p.addExtra(Node.PtrTypeBitRange{
                            .sentinel = .none,
                            .align_node = mods.align_node.unwrap().?,
                            .addrspace_node = mods.addrspace_node,
                            .bit_range_start = mods.bit_range_start.unwrap().?,
                            .bit_range_end = mods.bit_range_end.unwrap().?,
                        }),
                        elem_type,
                    } },
                });
            } else if (mods.addrspace_node != .none) {
                return try p.addNode(.{
                    .tag = .ptr_type,
                    .main_token = asterisk,
                    .data = .{ .extra_and_node = .{
                        try p.addExtra(Node.PtrType{
                            .sentinel = .none,
                            .align_node = mods.align_node,
                            .addrspace_node = mods.addrspace_node,
                        }),
                        elem_type,
                    } },
                });
            } else {
                return try p.addNode(.{
                    .tag = .ptr_type_aligned,
                    .main_token = asterisk,
                    .data = .{ .opt_node_and_node = .{
                        mods.align_node,
                        elem_type,
                    } },
                });
            }
        },
        .asterisk_asterisk => {
            const asterisk = p.nextToken();
            const mods = try p.parsePtrModifiers();
            const elem_type = try p.expectTypeExpr();
            const inner: Node.Index = inner: {
                if (mods.bit_range_start != .none) {
                    break :inner try p.addNode(.{
                        .tag = .ptr_type_bit_range,
                        .main_token = asterisk,
                        .data = .{ .extra_and_node = .{
                            try p.addExtra(Node.PtrTypeBitRange{
                                .sentinel = .none,
                                .align_node = mods.align_node.unwrap().?,
                                .addrspace_node = mods.addrspace_node,
                                .bit_range_start = mods.bit_range_start.unwrap().?,
                                .bit_range_end = mods.bit_range_end.unwrap().?,
                            }),
                            elem_type,
                        } },
                    });
                } else if (mods.addrspace_node != .none) {
                    break :inner try p.addNode(.{
                        .tag = .ptr_type,
                        .main_token = asterisk,
                        .data = .{ .extra_and_node = .{
                            try p.addExtra(Node.PtrType{
                                .sentinel = .none,
                                .align_node = mods.align_node,
                                .addrspace_node = mods.addrspace_node,
                            }),
                            elem_type,
                        } },
                    });
                } else {
                    break :inner try p.addNode(.{
                        .tag = .ptr_type_aligned,
                        .main_token = asterisk,
                        .data = .{ .opt_node_and_node = .{
                            mods.align_node,
                            elem_type,
                        } },
                    });
                }
            };
            return try p.addNode(.{
                .tag = .ptr_type_aligned,
                .main_token = asterisk,
                .data = .{ .opt_node_and_node = .{
                    .none,
                    inner,
                } },
            });
        },
        .l_bracket => switch (p.tokenTag(p.tok_i + 1)) {
            .asterisk => {
                const l_bracket = p.nextToken();
                _ = p.nextToken();
                var sentinel: ?Node.Index = null;
                if (p.eatToken(.identifier)) |ident| {
                    const ident_slice = p.source[p.tokenStart(ident)..p.tokenStart(ident + 1)];
                    if (!std.mem.eql(u8, std.mem.trimRight(u8, ident_slice, &std.ascii.whitespace), "c")) {
                        p.tok_i -= 1;
                    }
                } else if (p.eatToken(.colon)) |_| {
                    sentinel = try p.expectExpr();
                }
                _ = try p.expectToken(.r_bracket);
                const mods = try p.parsePtrModifiers();
                const elem_type = try p.expectTypeExpr();
                if (mods.bit_range_start == .none) {
                    if (sentinel == null and mods.addrspace_node == .none) {
                        return try p.addNode(.{
                            .tag = .ptr_type_aligned,
                            .main_token = l_bracket,
                            .data = .{ .opt_node_and_node = .{
                                mods.align_node,
                                elem_type,
                            } },
                        });
                    } else if (mods.align_node == .none and mods.addrspace_node == .none) {
                        return try p.addNode(.{
                            .tag = .ptr_type_sentinel,
                            .main_token = l_bracket,
                            .data = .{ .opt_node_and_node = .{
                                .fromOptional(sentinel),
                                elem_type,
                            } },
                        });
                    } else {
                        return try p.addNode(.{
                            .tag = .ptr_type,
                            .main_token = l_bracket,
                            .data = .{ .extra_and_node = .{
                                try p.addExtra(Node.PtrType{
                                    .sentinel = .fromOptional(sentinel),
                                    .align_node = mods.align_node,
                                    .addrspace_node = mods.addrspace_node,
                                }),
                                elem_type,
                            } },
                        });
                    }
                } else {
                    return try p.addNode(.{
                        .tag = .ptr_type_bit_range,
                        .main_token = l_bracket,
                        .data = .{ .extra_and_node = .{
                            try p.addExtra(Node.PtrTypeBitRange{
                                .sentinel = .fromOptional(sentinel),
                                .align_node = mods.align_node.unwrap().?,
                                .addrspace_node = mods.addrspace_node,
                                .bit_range_start = mods.bit_range_start.unwrap().?,
                                .bit_range_end = mods.bit_range_end.unwrap().?,
                            }),
                            elem_type,
                        } },
                    });
                }
            },
            else => {
                const lbracket = p.nextToken();
                const len_expr = try p.parseExpr();
                const sentinel: ?Node.Index = if (p.eatToken(.colon)) |_|
                    try p.expectExpr()
                else
                    null;
                _ = try p.expectToken(.r_bracket);
                if (len_expr == null) {
                    const mods = try p.parsePtrModifiers();
                    const elem_type = try p.expectTypeExpr();
                    if (mods.bit_range_start.unwrap()) |bit_range_start| {
                        try p.warnMsg(.{
                            .tag = .invalid_bit_range,
                            .token = p.nodeMainToken(bit_range_start),
                        });
                    }
                    if (sentinel == null and mods.addrspace_node == .none) {
                        return try p.addNode(.{
                            .tag = .ptr_type_aligned,
                            .main_token = lbracket,
                            .data = .{ .opt_node_and_node = .{
                                mods.align_node,
                                elem_type,
                            } },
                        });
                    } else if (mods.align_node == .none and mods.addrspace_node == .none) {
                        return try p.addNode(.{
                            .tag = .ptr_type_sentinel,
                            .main_token = lbracket,
                            .data = .{ .opt_node_and_node = .{
                                .fromOptional(sentinel),
                                elem_type,
                            } },
                        });
                    } else {
                        return try p.addNode(.{
                            .tag = .ptr_type,
                            .main_token = lbracket,
                            .data = .{ .extra_and_node = .{
                                try p.addExtra(Node.PtrType{
                                    .sentinel = .fromOptional(sentinel),
                                    .align_node = mods.align_node,
                                    .addrspace_node = mods.addrspace_node,
                                }),
                                elem_type,
                            } },
                        });
                    }
                } else {
                    switch (p.tokenTag(p.tok_i)) {
                        .keyword_align,
                        .keyword_const,
                        .keyword_volatile,
                        .keyword_allowzero,
                        .keyword_addrspace,
                        => return p.fail(.ptr_mod_on_array_child_type),
                        else => {},
                    }
                    const elem_type = try p.expectTypeExpr();
                    if (sentinel == null) {
                        return try p.addNode(.{
                            .tag = .array_type,
                            .main_token = lbracket,
                            .data = .{ .node_and_node = .{
                                len_expr.?,
                                elem_type,
                            } },
                        });
                    } else {
                        return try p.addNode(.{
                            .tag = .array_type_sentinel,
                            .main_token = lbracket,
                            .data = .{ .node_and_extra = .{
                                len_expr.?, try p.addExtra(Node.ArrayTypeSentinel{
                                    .sentinel = sentinel.?,
                                    .elem_type = elem_type,
                                }),
                            } },
                        });
                    }
                }
            },
        },
        else => return p.parseErrorUnionExpr(),
    }
}

fn expectTypeExpr(p: *Parse) Error!Node.Index {
    return try p.parseTypeExpr() orelse return p.fail(.expected_type_expr);
}

/// PrimaryExpr
///     <- AsmExpr
///      / IfExpr
///      / KEYWORD_break BreakLabel? Expr?
///      / KEYWORD_comptime Expr
///      / KEYWORD_nosuspend Expr
///      / KEYWORD_continue BreakLabel? Expr?
///      / KEYWORD_resume Expr
///      / KEYWORD_return Expr?
///      / BlockLabel? LoopExpr
///      / Block
///      / CurlySuffixExpr
fn parsePrimaryExpr(p: *Parse) !?Node.Index {
    switch (p.tokenTag(p.tok_i)) {
        .keyword_asm => return try p.expectAsmExpr(),
        .keyword_if => return try p.parseIfExpr(),
        .keyword_break => {
            return try p.addNode(.{
                .tag = .@"break",
                .main_token = p.nextToken(),
                .data = .{ .opt_token_and_opt_node = .{
                    try p.parseBreakLabel(),
                    .fromOptional(try p.parseExpr()),
                } },
            });
        },
        .keyword_continue => {
            return try p.addNode(.{
                .tag = .@"continue",
                .main_token = p.nextToken(),
                .data = .{ .opt_token_and_opt_node = .{
                    try p.parseBreakLabel(),
                    .fromOptional(try p.parseExpr()),
                } },
            });
        },
        .keyword_comptime => {
            return try p.addNode(.{
                .tag = .@"comptime",
                .main_token = p.nextToken(),
                .data = .{ .node = try p.expectExpr() },
            });
        },
        .keyword_nosuspend => {
            return try p.addNode(.{
                .tag = .@"nosuspend",
                .main_token = p.nextToken(),
                .data = .{ .node = try p.expectExpr() },
            });
        },
        .keyword_resume => {
            return try p.addNode(.{
                .tag = .@"resume",
                .main_token = p.nextToken(),
                .data = .{ .node = try p.expectExpr() },
            });
        },
        .keyword_return => {
            return try p.addNode(.{
                .tag = .@"return",
                .main_token = p.nextToken(),
                .data = .{ .opt_node = .fromOptional(try p.parseExpr()) },
            });
        },
        .identifier => {
            if (p.tokenTag(p.tok_i + 1) == .colon) {
                switch (p.tokenTag(p.tok_i + 2)) {
                    .keyword_inline => {
                        p.tok_i += 3;
                        switch (p.tokenTag(p.tok_i)) {
                            .keyword_for => return try p.parseFor(expectExpr),
                            .keyword_while => return try p.parseWhileExpr(),
                            else => return p.fail(.expected_inlinable),
                        }
                    },
                    .keyword_for => {
                        p.tok_i += 2;
                        return try p.parseFor(expectExpr);
                    },
                    .keyword_while => {
                        p.tok_i += 2;
                        return try p.parseWhileExpr();
                    },
                    .l_brace => {
                        p.tok_i += 2;
                        return try p.parseBlock();
                    },
                    else => return try p.parseCurlySuffixExpr(),
                }
            } else {
                return try p.parseCurlySuffixExpr();
            }
        },
        .keyword_inline => {
            p.tok_i += 1;
            switch (p.tokenTag(p.tok_i)) {
                .keyword_for => return try p.parseFor(expectExpr),
                .keyword_while => return try p.parseWhileExpr(),
                else => return p.fail(.expected_inlinable),
            }
        },
        .keyword_for => return try p.parseFor(expectExpr),
        .keyword_while => return try p.parseWhileExpr(),
        .l_brace => return try p.parseBlock(),
        else => return try p.parseCurlySuffixExpr(),
    }
}

/// IfExpr <- IfPrefix Expr (KEYWORD_else Payload? Expr)?
fn parseIfExpr(p: *Parse) !?Node.Index {
    return try p.parseIf(expectExpr);
}

/// Block <- LBRACE Statement* RBRACE
fn parseBlock(p: *Parse) !?Node.Index {
    const lbrace = p.eatToken(.l_brace) orelse return null;
    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);
    while (true) {
        if (p.tokenTag(p.tok_i) == .r_brace) break;
        const statement = try p.expectStatementRecoverable() orelse break;
        try p.scratch.append(p.gpa, statement);
    }
    _ = try p.expectToken(.r_brace);
    const statements = p.scratch.items[scratch_top..];
    const semicolon = statements.len != 0 and (p.tokenTag(p.tok_i - 2)) == .semicolon;
    if (statements.len <= 2) {
        return try p.addNode(.{
            .tag = if (semicolon) .block_two_semicolon else .block_two,
            .main_token = lbrace,
            .data = .{ .opt_node_and_opt_node = .{
                if (statements.len >= 1) statements[0].toOptional() else .none,
                if (statements.len >= 2) statements[1].toOptional() else .none,
            } },
        });
    } else {
        return try p.addNode(.{
            .tag = if (semicolon) .block_semicolon else .block,
            .main_token = lbrace,
            .data = .{ .extra_range = try p.listToSpan(statements) },
        });
    }
}

/// ForPrefix <- KEYWORD_for LPAREN ForInput (COMMA ForInput)* COMMA? RPAREN ForPayload
///
/// ForInput <- Expr (DOT2 Expr?)?
///
/// ForPayload <- PIPE ASTERISK? IDENTIFIER (COMMA ASTERISK? IDENTIFIER)* PIPE
fn forPrefix(p: *Parse) Error!usize {
    const start = p.scratch.items.len;
    _ = try p.expectToken(.l_paren);

    while (true) {
        var input = try p.expectExpr();
        if (p.eatToken(.ellipsis2)) |ellipsis| {
            input = try p.addNode(.{
                .tag = .for_range,
                .main_token = ellipsis,
                .data = .{ .node_and_opt_node = .{
                    input,
                    .fromOptional(try p.parseExpr()),
                } },
            });
        }

        try p.scratch.append(p.gpa, input);
        switch (p.tokenTag(p.tok_i)) {
            .comma => p.tok_i += 1,
            .r_paren => {
                p.tok_i += 1;
                break;
            },
            .colon, .r_brace, .r_bracket => return p.failExpected(.r_paren),
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_for_operand),
        }
        if (p.eatToken(.r_paren)) |_| break;
    }
    const inputs = p.scratch.items.len - start;

    _ = p.eatToken(.pipe) orelse {
        try p.warn(.expected_loop_payload);
        return inputs;
    };

    var warned_excess = false;
    var captures: u32 = 0;
    while (true) {
        _ = p.eatToken(.asterisk);
        const identifier = try p.expectToken(.identifier);
        captures += 1;
        if (captures > inputs and !warned_excess) {
            try p.warnMsg(.{ .tag = .extra_for_capture, .token = identifier });
            warned_excess = true;
        }
        switch (p.tokenTag(p.tok_i)) {
            .comma => p.tok_i += 1,
            .pipe => {
                p.tok_i += 1;
                break;
            },
            // Likely just a missing comma; give error but continue parsing.
            else => try p.warn(.expected_comma_after_capture),
        }
        if (p.eatToken(.pipe)) |_| break;
    }

    if (captures < inputs) {
        const index = p.scratch.items.len - captures;
        const input = p.nodeMainToken(p.scratch.items[index]);
        try p.warnMsg(.{ .tag = .for_input_not_captured, .token = input });
    }
    return inputs;
}

/// WhilePrefix <- KEYWORD_while LPAREN Expr RPAREN PtrPayload? WhileContinueExpr?
///
/// WhileExpr <- WhilePrefix Expr (KEYWORD_else Payload? Expr)?
fn parseWhileExpr(p: *Parse) !?Node.Index {
    const while_token = p.eatToken(.keyword_while) orelse return null;
    _ = try p.expectToken(.l_paren);
    const condition = try p.expectExpr();
    _ = try p.expectToken(.r_paren);
    _ = try p.parsePtrPayload();
    const cont_expr = try p.parseWhileContinueExpr();

    const then_expr = try p.expectExpr();
    _ = p.eatToken(.keyword_else) orelse {
        if (cont_expr == null) {
            return try p.addNode(.{
                .tag = .while_simple,
                .main_token = while_token,
                .data = .{ .node_and_node = .{
                    condition,
                    then_expr,
                } },
            });
        } else {
            return try p.addNode(.{
                .tag = .while_cont,
                .main_token = while_token,
                .data = .{ .node_and_extra = .{
                    condition,
                    try p.addExtra(Node.WhileCont{
                        .cont_expr = cont_expr.?,
                        .then_expr = then_expr,
                    }),
                } },
            });
        }
    };
    _ = try p.parsePayload();
    const else_expr = try p.expectExpr();
    return try p.addNode(.{
        .tag = .@"while",
        .main_token = while_token,
        .data = .{ .node_and_extra = .{
            condition,
            try p.addExtra(Node.While{
                .cont_expr = .fromOptional(cont_expr),
                .then_expr = then_expr,
                .else_expr = else_expr,
            }),
        } },
    });
}

/// CurlySuffixExpr <- TypeExpr InitList?
///
/// InitList
///     <- LBRACE FieldInit (COMMA FieldInit)* COMMA? RBRACE
///      / LBRACE Expr (COMMA Expr)* COMMA? RBRACE
///      / LBRACE RBRACE
fn parseCurlySuffixExpr(p: *Parse) !?Node.Index {
    const lhs = try p.parseTypeExpr() orelse return null;
    const lbrace = p.eatToken(.l_brace) orelse return lhs;

    // If there are 0 or 1 items, we can use ArrayInitOne/StructInitOne;
    // otherwise we use the full ArrayInit/StructInit.

    const scratch_top = p.scratch.items.len;
    defer p.scratch.shrinkRetainingCapacity(scratch_top);
    const opt_field_init = try p.parseFieldInit();
    if (opt_field_init) |field_init| {
        try p.scratch.append(p.gpa, field_init);
        while (true) {
            switch (p.tokenTag(p.tok_i)) {
                .comma => p.tok_i += 1,
                .r_brace => {
                    p.tok_i += 1;
                    break;
                },
                .colon, .r_paren, .r_bracket => return p.failExpected(.r_brace),
                // Likely just a missing comma; give error but continue parsing.
                else => try p.warn(.expected_comma_after_initializer),
            }
           ```
