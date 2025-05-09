```
{
    NL0 = 0,
    NL1 = 1,
};

pub const CRDLY = enum(u2) {
    CR0 = 0,
    CR1 = 1,
    CR2 = 2,
    CR3 = 3,
};

pub const TABDLY = enum(u2) {
    TAB0 = 0,
    TAB1 = 1,
    TAB2 = 2,
    TAB3 = 3,

    pub const XTABS = TABDLY.TAB3;
};

pub const BSDLY = enum(u1) {
    BS0 = 0,
    BS1 = 1,
};

pub const VTDLY = enum(u1) {
    VT0 = 0,
    VT1 = 1,
};

pub const FFDLY = enum(u1) {
    FF0 = 0,
    FF1 = 1,
};

pub const tc_oflag_t = if (is_ppc) packed struct(tcflag_t) {
    OPOST: bool = false,
    ONLCR: bool = false,
    OLCUC: bool = false,
    OCRNL: bool = false,
    ONOCR: bool = false,
    ONLRET: bool = false,
    OFILL: bool = false,
    OFDEL: bool = false,
    NLDLY: NLDLY = .NL0,
    TABDLY: TABDLY = .TAB0,
    CRDLY: CRDLY = .CR0,
    FFDLY: FFDLY = .FF0,
    BSDLY: BSDLY = .BS0,
    VTDLY: VTDLY = .VT0,
    _17: u15 = 0,
} else if (is_sparc) packed struct(tcflag_t) {
    OPOST: bool = false,
    OLCUC: bool = false,
    ONLCR: bool = false,
    OCRNL: bool = false,
    ONOCR: bool = false,
    ONLRET: bool = false,
    OFILL: bool = false,
    OFDEL: bool = false,
    NLDLY: NLDLY = .NL0,
    CRDLY: CRDLY = .CR0,
    TABDLY: TABDLY = .TAB0,
    BSDLY: BSDLY = .BS0,
    VTDLY: VTDLY = .VT0,
    FFDLY: FFDLY = .FF0,
    PAGEOUT: bool = false,
    WRAP: bool = false,
    _18: u14 = 0,
} else packed struct(tcflag_t) {
    OPOST: bool = false,
    OLCUC: bool = false,
    ONLCR: bool = false,
    OCRNL: bool = false,
    ONOCR: bool = false,
    ONLRET: bool = false,
    OFILL: bool = false,
    OFDEL: bool = false,
    NLDLY: NLDLY = .NL0,
    CRDLY: CRDLY = .CR0,
    TABDLY: TABDLY = .TAB0,
    BSDLY: BSDLY = .BS0,
    VTDLY: VTDLY = .VT0,
    FFDLY: FFDLY = .FF0,
    _16: u16 = 0,
};

pub const CSIZE = enum(u2) {
    CS5 = 0,
    CS6 = 1,
    CS7 = 2,
    CS8 = 3,
};

pub const tc_cflag_t = if (is_ppc) packed struct(tcflag_t) {
    _0: u8 = 0,
    CSIZE: CSIZE = .CS5,
    CSTOPB: bool = false,
    CREAD: bool = false,
    PARENB: bool = false,
    PARODD: bool = false,
    HUPCL: bool = false,
    CLOCAL: bool = false,
    _16: u13 = 0,
    ADDRB: bool = false,
    CMSPAR: bool = false,
    CRTSCTS: bool = false,
} else packed struct(tcflag_t) {
    _0: u4 = 0,
    CSIZE: CSIZE = .CS5,
    CSTOPB: bool = false,
    CREAD: bool = false,
    PARENB: bool = false,
    PARODD: bool = false,
    HUPCL: bool = false,
    CLOCAL: bool = false,
    _12: u17 = 0,
    ADDRB: bool = false,
    CMSPAR: bool = false,
    CRTSCTS: bool = false,
};

pub const tc_lflag_t = if (is_mips) packed struct(tcflag_t) {
    ISIG: bool = false,
    ICANON: bool = false,
    XCASE: bool = false,
    ECHO: bool = false,
    ECHOE: bool = false,
    ECHOK: bool = false,
    ECHONL: bool = false,
    NOFLSH: bool = false,
    IEXTEN: bool = false,
    ECHOCTL: bool = false,
    ECHOPRT: bool = false,
    ECHOKE: bool = false,
    _12: u1 = 0,
    FLUSHO: bool = false,
    PENDIN: bool = false,
    TOSTOP: bool = false,
    EXTPROC: bool = false,
    _17: u15 = 0,
} else if (is_ppc) packed struct(tcflag_t) {
    ECHOKE: bool = false,
    ECHOE: bool = false,
    ECHOK: bool = false,
    ECHO: bool = false,
    ECHONL: bool = false,
    ECHOPRT: bool = false,
    ECHOCTL: bool = false,
    ISIG: bool = false,
    ICANON: bool = false,
    _9: u1 = 0,
    IEXTEN: bool = false,
    _11: u3 = 0,
    XCASE: bool = false,
    _15: u7 = 0,
    TOSTOP: bool = false,
    FLUSHO: bool = false,
    _24: u4 = 0,
    EXTPROC: bool = false,
    PENDIN: bool = false,
    _30: u1 = 0,
    NOFLSH: bool = false,
} else if (is_sparc) packed struct(tcflag_t) {
    ISIG: bool = false,
    ICANON: bool = false,
    XCASE: bool = false,
    ECHO: bool = false,
    ECHOE: bool = false,
    ECHOK: bool = false,
    ECHONL: bool = false,
    NOFLSH: bool = false,
    TOSTOP: bool = false,
    ECHOCTL: bool = false,
    ECHOPRT: bool = false,
    ECHOKE: bool = false,
    DEFECHO: bool = false,
    FLUSHO: bool = false,
    PENDIN: bool = false,
    IEXTEN: bool = false,
    EXTPROC: bool = false,
    _17: u15 = 0,
} else packed struct(tcflag_t) {
    ISIG: bool = false,
    ICANON: bool = false,
    XCASE: bool = false,
    ECHO: bool = false,
    ECHOE: bool = false,
    ECHOK: bool = false,
    ECHONL: bool = false,
    NOFLSH: bool = false,
    TOSTOP: bool = false,
    ECHOCTL: bool = false,
    ECHOPRT: bool = false,
    ECHOKE: bool = false,
    FLUSHO: bool = false,
    _13: u1 = 0,
    PENDIN: bool = false,
    IEXTEN: bool = false,
    EXTPROC: bool = false,
    _17: u15 = 0,
};

pub const cc_t = u8;

/// Indices into the `cc` array in the `termios` struct.
pub const V = if (is_mips) enum(u32) {
    INTR = 0,
    QUIT = 1,
    ERASE = 2,
    KILL = 3,
    MIN = 4,
    TIME = 5,
    EOL2 = 6,
    SWTC = 7,
    START = 8,
    STOP = 9,
    SUSP = 10,
    REPRINT = 12,
    DISCARD = 13,
    WERASE = 14,
    LNEXT = 15,
    EOF = 16,
    EOL = 17,
} else if (is_ppc) enum(u32) {
    INTR = 0,
    QUIT = 1,
    ERASE = 2,
    KILL = 3,
    EOF = 4,
    MIN = 5,
    EOL = 6,
    TIME = 7,
    EOL2 = 8,
    SWTC = 9,
    WERASE = 10,
    REPRINT = 11,
    SUSP = 12,
    START = 13,
    STOP = 14,
    LNEXT = 15,
    DISCARD = 16,
} else enum(u32) {
    INTR = 0,
    QUIT = 1,
    ERASE = 2,
    KILL = 3,
    EOF = 4,
    TIME = 5,
    MIN = 6,
    SWTC = 7,
    START = 8,
    STOP = 9,
    SUSP = 10,
    EOL = 11,
    REPRINT = 12,
    DISCARD = 13,
    WERASE = 14,
    LNEXT = 15,
    EOL2 = 16,
};

pub const TCSA = std.posix.TCSA;

pub const sgttyb = if (is_mips or is_ppc or is_sparc) extern struct {
    ispeed: c_char,
    ospeed: c_char,
    erase: c_char,
    kill: c_char,
    flags: if (is_mips) c_int else c_short,
} else void;

pub const tchars = if (is_mips or is_ppc or is_sparc) extern struct {
    intrc: c_char,
    quitc: c_char,
    startc: c_char,
    stopc: c_char,
    eofc: c_char,
    brkc: c_char,
} else void;

pub const ltchars = if (is_mips or is_ppc or is_sparc) extern struct {
    suspc: c_char,
    dsuspc: c_char,
    rprntc: c_char,
    flushc: c_char,
    werasc: c_char,
    lnextc: c_char,
} else void;

pub const termio = extern struct {
    iflag: c_ushort,
    oflag: c_ushort,
    cflag: c_ushort,
    lflag: c_ushort,
    line: if (is_mips) c_char else u8,
    cc: [if (is_mips) NCCS else NCC]u8,
};

pub const termios = if (is_mips or is_sparc) extern struct {
    iflag: tc_iflag_t,
    oflag: tc_oflag_t,
    cflag: tc_cflag_t,
    lflag: tc_lflag_t,
    line: cc_t,
    cc: [NCCS]cc_t,
} else if (is_ppc) extern struct {
    iflag: tc_iflag_t,
    oflag: tc_oflag_t,
    cflag: tc_cflag_t,
    lflag: tc_lflag_t,
    cc: [NCCS]cc_t,
    line: cc_t,
    ispeed: speed_t,
    ospeed: speed_t,
} else extern struct {
    iflag: tc_iflag_t,
    oflag: tc_oflag_t,
    cflag: tc_cflag_t,
    lflag: tc_lflag_t,
    line: cc_t,
    cc: [NCCS]cc_t,
    ispeed: speed_t,
    ospeed: speed_t,
};

pub const termios2 = if (is_mips) extern struct {
    iflag: tc_iflag_t,
    oflag: tc_oflag_t,
    cflag: tc_cflag_t,
    lflag: tc_lflag_t,
    cc: [NCCS]cc_t,
    line: cc_t,
    ispeed: speed_t,
    ospeed: speed_t,
} else extern struct {
    iflag: tc_iflag_t,
    oflag: tc_oflag_t,
    cflag: tc_cflag_t,
    lflag: tc_lflag_t,
    line: cc_t,
    cc: [NCCS + if (is_sparc) 2 else 0]cc_t,
    ispeed: speed_t,
    ospeed: speed_t,
};

/// Linux-specific socket ioctls
pub const SIOCINQ = T.FIONREAD;

/// Linux-specific socket ioctls
/// output queue size (not sent + not acked)
pub const SIOCOUTQ = T.IOCOUTQ;

pub const SOCK_IOC_TYPE = 0x89;

pub const SIOCGSTAMP_NEW = IOCTL.IOR(SOCK_IOC_TYPE, 0x06, i64[2]);
pub const SIOCGSTAMP_OLD = IOCTL.IOR('s', 100, timeval);

/// Get stamp (timeval)
pub const SIOCGSTAMP = if (native_arch == .x86_64 or @sizeOf(timeval) == 8) SIOCGSTAMP_OLD else SIOCGSTAMP_NEW;

pub const SIOCGSTAMPNS_NEW = IOCTL.IOR(SOCK_IOC_TYPE, 0x07, i64[2]);
pub const SIOCGSTAMPNS_OLD = IOCTL.IOR('s', 101, kernel_timespec);

/// Get stamp (timespec)
pub const SIOCGSTAMPNS = if (native_arch == .x86_64 or @sizeOf(timespec) == 8) SIOCGSTAMPNS_OLD else SIOCGSTAMPNS_NEW;

// Routing table calls.
/// Add routing table entry
pub const SIOCADDRT = 0x890B;

/// Delete routing table entry
pub const SIOCDELRT = 0x890C;

/// Unused
pub const SIOCRTMSG = 0x890D;

// Socket configuration controls.
/// Get iface name
pub const SIOCGIFNAME = 0x8910;

/// Set iface channel
pub const SIOCSIFLINK = 0x8911;

/// Get iface list
pub const SIOCGIFCONF = 0x8912;

/// Get flags
pub const SIOCGIFFLAGS = 0x8913;

/// Set flags
pub const SIOCSIFFLAGS = 0x8914;

/// Get PA address
pub const SIOCGIFADDR = 0x8915;

/// Set PA address
pub const SIOCSIFADDR = 0x8916;

/// Get remote PA address
pub const SIOCGIFDSTADDR = 0x8917;

/// Set remote PA address
pub const SIOCSIFDSTADDR = 0x8918;

/// Get broadcast PA address
pub const SIOCGIFBRDADDR = 0x8919;

/// Set broadcast PA address
pub const SIOCSIFBRDADDR = 0x891a;

/// Get network PA mask
pub const SIOCGIFNETMASK = 0x891b;

/// Set network PA mask
pub const SIOCSIFNETMASK = 0x891c;

/// Get metric
pub const SIOCGIFMETRIC = 0x891d;

/// Set metric
pub const SIOCSIFMETRIC = 0x891e;

/// Get memory address (BSD)
pub const SIOCGIFMEM = 0x891f;

/// Set memory address (BSD)
pub const SIOCSIFMEM = 0x8920;

/// Get MTU size
pub const SIOCGIFMTU = 0x8921;

/// Set MTU size
pub const SIOCSIFMTU = 0x8922;

/// Set interface name
pub const SIOCSIFNAME = 0x8923;

/// Set hardware address
pub const SIOCSIFHWADDR = 0x8924;

/// Get encapsulations
pub const SIOCGIFENCAP = 0x8925;

/// Set encapsulations
pub const SIOCSIFENCAP = 0x8926;

/// Get hardware address
pub const SIOCGIFHWADDR = 0x8927;

/// Driver slaving support
pub const SIOCGIFSLAVE = 0x8929;

/// Driver slaving support
pub const SIOCSIFSLAVE = 0x8930;

/// Add to Multicast address lists
pub const SIOCADDMULTI = 0x8931;

/// Delete from Multicast address lists
pub const SIOCDELMULTI = 0x8932;

/// name -> if_index mapping
pub const SIOCGIFINDEX = 0x8933;

/// Set extended flags set
pub const SIOCSIFPFLAGS = 0x8934;

/// Get extended flags set
pub const SIOCGIFPFLAGS = 0x8935;

/// Delete PA address
pub const SIOCDIFADDR = 0x8936;

/// Set hardware broadcast addr
pub const SIOCSIFHWBROADCAST = 0x8937;

/// Get number of devices
pub const SIOCGIFCOUNT = 0x8938;

/// Bridging support
pub const SIOCGIFBR = 0x8940;

/// Set bridging options
pub const SIOCSIFBR = 0x8941;

/// Get the tx queue length
pub const SIOCGIFTXQLEN = 0x8942;

/// Set the tx queue length
pub const SIOCSIFTXQLEN = 0x8943;

/// Ethtool interface
pub const SIOCETHTOOL = 0x8946;

/// Get address of MII PHY in use.
pub const SIOCGMIIPHY = 0x8947;

/// Read MII PHY register.
pub const SIOCGMIIREG = 0x8948;

/// Write MII PHY register.
pub const SIOCSMIIREG = 0x8949;

/// Get / Set netdev parameters
pub const SIOCWANDEV = 0x894A;

/// Output queue size (not sent only)
pub const SIOCOUTQNSD = 0x894B;

/// Get socket network namespace
pub const SIOCGSKNS = 0x894C;

// ARP cache control calls.
//  0x8950 - 0x8952 obsolete calls.
/// Delete ARP table entry
pub const SIOCDARP = 0x8953;

/// Get ARP table entry
pub const SIOCGARP = 0x8954;

/// Set ARP table entry
pub const SIOCSARP = 0x8955;

// RARP cache control calls.
/// Delete RARP table entry
pub const SIOCDRARP = 0x8960;

/// Get RARP table entry
pub const SIOCGRARP = 0x8961;

/// Set RARP table entry
pub const SIOCSRARP = 0x8962;

// Driver configuration calls
/// Get device parameters
pub const SIOCGIFMAP = 0x8970;

/// Set device parameters
pub const SIOCSIFMAP = 0x8971;

// DLCI configuration calls
/// Create new DLCI device
pub const SIOCADDDLCI = 0x8980;

/// Delete DLCI device
pub const SIOCDELDLCI = 0x8981;

/// 802.1Q VLAN support
pub const SIOCGIFVLAN = 0x8982;

/// Set 802.1Q VLAN options
pub const SIOCSIFVLAN = 0x8983;

// bonding calls
/// Enslave a device to the bond
pub const SIOCBONDENSLAVE = 0x8990;

/// Release a slave from the bond
pub const SIOCBONDRELEASE = 0x8991;

/// Set the hw addr of the bond
pub const SIOCBONDSETHWADDR = 0x8992;

/// rtn info about slave state
pub const SIOCBONDSLAVEINFOQUERY = 0x8993;

/// rtn info about bond state
pub const SIOCBONDINFOQUERY = 0x8994;

/// Update to a new active slave
pub const SIOCBONDCHANGEACTIVE = 0x8995;

// Bridge calls
/// Create new bridge device
pub const SIOCBRADDBR = 0x89a0;

/// Remove bridge device
pub const SIOCBRDELBR = 0x89a1;

/// Add interface to bridge
pub const SIOCBRADDIF = 0x89a2;

/// Remove interface from bridge
pub const SIOCBRDELIF = 0x89a3;

/// Get hardware time stamp config
pub const SIOCSHWTSTAMP = 0x89b0;

/// Set hardware time stamp config
pub const SIOCGHWTSTAMP = 0x89b1;

/// Device private ioctl calls
pub const SIOCDEVPRIVATE = 0x89F0;

/// These 16 ioctl calls are protocol private
pub const SIOCPROTOPRIVATE = 0x89E0;

pub const IFNAMESIZE = 16;

pub const IFF = packed struct(u16) {
    UP: bool = false,
    BROADCAST: bool = false,
    DEBUG: bool = false,
    LOOPBACK: bool = false,
    POINTOPOINT: bool = false,
    NOTRAILERS: bool = false,
    RUNNING: bool = false,
    NOARP: bool = false,
    PROMISC: bool = false,
    _9: u7 = 0,
};

pub const ifmap = extern struct {
    mem_start: usize,
    mem_end: usize,
    base_addr: u16,
    irq: u8,
    dma: u8,
    port: u8,
};

pub const ifreq = extern struct {
    ifrn: extern union {
        name: [IFNAMESIZE]u8,
    },
    ifru: extern union {
        addr: sockaddr,
        dstaddr: sockaddr,
        broadaddr: sockaddr,
        netmask: sockaddr,
        hwaddr: sockaddr,
        flags: IFF,
        ivalue: i32,
        mtu: i32,
        map: ifmap,
        slave: [IFNAMESIZE - 1:0]u8,
        newname: [IFNAMESIZE - 1:0]u8,
        data: ?[*]u8,
    },
};

pub const PACKET = struct {
    pub const HOST = 0;
    pub const BROADCAST = 1;
    pub const MULTICAST = 2;
    pub const OTHERHOST = 3;
    pub const OUTGOING = 4;
    pub const LOOPBACK = 5;
    pub const USER = 6;
    pub const KERNEL = 7;

    pub const ADD_MEMBERSHIP = 1;
    pub const DROP_MEMBERSHIP = 2;
    pub const RECV_OUTPUT = 3;
    pub const RX_RING = 5;
    pub const STATISTICS = 6;
    pub const COPY_THRESH = 7;
    pub const AUXDATA = 8;
    pub const ORIGDEV = 9;
    pub const VERSION = 10;
    pub const HDRLEN = 11;
    pub const RESERVE = 12;
    pub const TX_RING = 13;
    pub const LOSS = 14;
    pub const VNET_HDR = 15;
    pub const TX_TIMESTAMP = 16;
    pub const TIMESTAMP = 17;
    pub const FANOUT = 18;
    pub const TX_HAS_OFF = 19;
    pub const QDISC_BYPASS = 20;
    pub const ROLLOVER_STATS = 21;
    pub const FANOUT_DATA = 22;
    pub const IGNORE_OUTGOING = 23;
    pub const VNET_HDR_SZ = 24;

    pub const FANOUT_HASH = 0;
    pub const FANOUT_LB = 1;
    pub const FANOUT_CPU = 2;
    pub const FANOUT_ROLLOVER = 3;
    pub const FANOUT_RND = 4;
    pub const FANOUT_QM = 5;
    pub const FANOUT_CBPF = 6;
    pub const FANOUT_EBPF = 7;
    pub const FANOUT_FLAG_ROLLOVER = 0x1000;
    pub const FANOUT_FLAG_UNIQUEID = 0x2000;
    pub const FANOUT_FLAG_IGNORE_OUTGOING = 0x4000;
    pub const FANOUT_FLAG_DEFRAG = 0x8000;
};

pub const tpacket_versions = enum(u32) {
    V1 = 0,
    V2 = 1,
    V3 = 2,
};

pub const tpacket_req3 = extern struct {
    block_size: c_uint, // Minimal size of contiguous block
    block_nr: c_uint, // Number of blocks
    frame_size: c_uint, // Size of frame
    frame_nr: c_uint, // Total number of frames
    retire_blk_tov: c_uint, // Timeout in msecs
    sizeof_priv: c_uint, // Offset to private data area
    feature_req_word: c_uint,
};

pub const tpacket_bd_ts = extern struct {
    sec: c_uint,
    frac: extern union {
        usec: c_uint,
        nsec: c_uint,
    },
};

pub const TP_STATUS = extern union {
    rx: packed struct(u32) {
        USER: bool,
        COPY: bool,
        LOSING: bool,
        CSUMNOTREADY: bool,
        VLAN_VALID: bool,
        BLK_TMO: bool,
        VLAN_TPID_VALID: bool,
        CSUM_VALID: bool,
        GSO_TCP: bool,
        _: u20,
        TS_SOFTWARE: bool,
        TS_SYS_HARDWARE: bool,
        TS_RAW_HARDWARE: bool,
    },
    tx: packed struct(u32) {
        SEND_REQUEST: bool,
        SENDING: bool,
        WRONG_FORMAT: bool,
        _: u26,
        TS_SOFTWARE: bool,
        TS_SYS_HARDWARE: bool,
        TS_RAW_HARDWARE: bool,
    },
};

pub const tpacket_hdr_v1 = extern struct {
    block_status: TP_STATUS,
    num_pkts: u32,
    offset_to_first_pkt: u32,
    blk_len: u32,
    seq_num: u64 align(8),
    ts_first_pkt: tpacket_bd_ts,
    ts_last_pkt: tpacket_bd_ts,
};

pub const tpacket_bd_header_u = extern union {
    bh1: tpacket_hdr_v1,
};

pub const tpacket_block_desc = extern struct {
    version: u32,
    offset_to_priv: u32,
    hdr: tpacket_bd_header_u,
};

pub const tpacket_hdr_variant1 = extern struct {
    rxhash: u32,
    vlan_tci: u32,
    vlan_tpid: u16,
    padding: u16,
};

pub const tpacket3_hdr = extern struct {
    next_offset: u32,
    sec: u32,
    nsec: u32,
    snaplen: u32,
    len: u32,
    status: u32,
    mac: u16,
    net: u16,
    variant: extern union {
        hv1: tpacket_hdr_variant1,
    },
    padding: [8]u8,
};

pub const tpacket_stats_v3 = extern struct {
    packets: c_uint,
    drops: c_uint,
    freeze_q_cnt: c_uint,
};

// doc comments copied from musl
pub const rlimit_resource = if (native_arch.isMIPS()) enum(c_int) {
    /// Per-process CPU limit, in seconds.
    CPU = 0,

    /// Largest file that can be created, in bytes.
    FSIZE = 1,

    /// Maximum size of data segment, in bytes.
    DATA = 2,

    /// Maximum size of stack segment, in bytes.
    STACK = 3,

    /// Largest core file that can be created, in bytes.
    CORE = 4,

    /// Number of open files.
    NOFILE = 5,

    /// Address space limit.
    AS = 6,

    /// Largest resident set size, in bytes.
    /// This affects swapping; processes that are exceeding their
    /// resident set size will be more likely to have physical memory
    /// taken from them.
    RSS = 7,

    /// Number of processes.
    NPROC = 8,

    /// Locked-in-memory address space.
    MEMLOCK = 9,

    /// Maximum number of file locks.
    LOCKS = 10,

    /// Maximum number of pending signals.
    SIGPENDING = 11,

    /// Maximum bytes in POSIX message queues.
    MSGQUEUE = 12,

    /// Maximum nice priority allowed to raise to.
    /// Nice levels 19 .. -20 correspond to 0 .. 39
    /// values of this resource limit.
    NICE = 13,

    /// Maximum realtime priority allowed for non-privileged
    /// processes.
    RTPRIO = 14,

    /// Maximum CPU time in µs that a process scheduled under a real-time
    /// scheduling policy may consume without making a blocking system
    /// call before being forcibly descheduled.
    RTTIME = 15,

    _,
} else if (native_arch.isSPARC()) enum(c_int) {
    /// Per-process CPU limit, in seconds.
    CPU = 0,

    /// Largest file that can be created, in bytes.
    FSIZE = 1,

    /// Maximum size of data segment, in bytes.
    DATA = 2,

    /// Maximum size of stack segment, in bytes.
    STACK = 3,

    /// Largest core file that can be created, in bytes.
    CORE = 4,

    /// Largest resident set size, in bytes.
    /// This affects swapping; processes that are exceeding their
    /// resident set size will be more likely to have physical memory
    /// taken from them.
    RSS = 5,

    /// Number of open files.
    NOFILE = 6,

    /// Number of processes.
    NPROC = 7,

    /// Locked-in-memory address space.
    MEMLOCK = 8,

    /// Address space limit.
    AS = 9,

    /// Maximum number of file locks.
    LOCKS = 10,

    /// Maximum number of pending signals.
    SIGPENDING = 11,

    /// Maximum bytes in POSIX message queues.
    MSGQUEUE = 12,

    /// Maximum nice priority allowed to raise to.
    /// Nice levels 19 .. -20 correspond to 0 .. 39
    /// values of this resource limit.
    NICE = 13,

    /// Maximum realtime priority allowed for non-privileged
    /// processes.
    RTPRIO = 14,

    /// Maximum CPU time in µs that a process scheduled under a real-time
    /// scheduling policy may consume without making a blocking system
    /// call before being forcibly descheduled.
    RTTIME = 15,

    _,
} else enum(c_int) {
    /// Per-process CPU limit, in seconds.
    CPU = 0,
    /// Largest file that can be created, in bytes.
    FSIZE = 1,
    /// Maximum size of data segment, in bytes.
    DATA = 2,
    /// Maximum size of stack segment, in bytes.
    STACK = 3,
    /// Largest core file that can be created, in bytes.
    CORE = 4,
    /// Largest resident set size, in bytes.
    /// This affects swapping; processes that are exceeding their
    /// resident set size will be more likely to have physical memory
    /// taken from them.
    RSS = 5,
    /// Number of processes.
    NPROC = 6,
    /// Number of open files.
    NOFILE = 7,
    /// Locked-in-memory address space.
    MEMLOCK = 8,
    /// Address space limit.
    AS = 9,
    /// Maximum number of file locks.
    LOCKS = 10,
    /// Maximum number of pending signals.
    SIGPENDING = 11,
    /// Maximum bytes in POSIX message queues.
    MSGQUEUE = 12,
    /// Maximum nice priority allowed to raise to.
    /// Nice levels 19 .. -20 correspond to 0 .. 39
    /// values of this resource limit.
    NICE = 13,
    /// Maximum realtime priority allowed for non-privileged
    /// processes.
    RTPRIO = 14,
    /// Maximum CPU time in µs that a process scheduled under a real-time
    /// scheduling policy may consume without making a blocking system
    /// call before being forcibly descheduled.
    RTTIME = 15,

    _,
};

pub const rlim_t = u64;

pub const RLIM = struct {
    /// No limit
    pub const INFINITY = ~@as(rlim_t, 0);

    pub const SAVED_MAX = INFINITY;
    pub const SAVED_CUR = INFINITY;
};

pub const rlimit = extern struct {
    /// Soft limit
    cur: rlim_t,
    /// Hard limit
    max: rlim_t,
};

pub const MADV = struct {
    pub const NORMAL = 0;
    pub const RANDOM = 1;
    pub const SEQUENTIAL = 2;
    pub const WILLNEED = 3;
    pub const DONTNEED = 4;
    pub const FREE = 8;
    pub const REMOVE = 9;
    pub const DONTFORK = 10;
    pub const DOFORK = 11;
    pub const MERGEABLE = 12;
    pub const UNMERGEABLE = 13;
    pub const HUGEPAGE = 14;
    pub const NOHUGEPAGE = 15;
    pub const DONTDUMP = 16;
    pub const DODUMP = 17;
    pub const WIPEONFORK = 18;
    pub const KEEPONFORK = 19;
    pub const COLD = 20;
    pub const PAGEOUT = 21;
    pub const HWPOISON = 100;
    pub const SOFT_OFFLINE = 101;
};

pub const POSIX_FADV = switch (native_arch) {
    .s390x => if (@typeInfo(usize).int.bits == 64) struct {
        pub const NORMAL = 0;
        pub const RANDOM = 1;
        pub const SEQUENTIAL = 2;
        pub const WILLNEED = 3;
        pub const DONTNEED = 6;
        pub const NOREUSE = 7;
    } else struct {
        pub const NORMAL = 0;
        pub const RANDOM = 1;
        pub const SEQUENTIAL = 2;
        pub const WILLNEED = 3;
        pub const DONTNEED = 4;
        pub const NOREUSE = 5;
    },
    else => struct {
        pub const NORMAL = 0;
        pub const RANDOM = 1;
        pub const SEQUENTIAL = 2;
        pub const WILLNEED = 3;
        pub const DONTNEED = 4;
        pub const NOREUSE = 5;
    },
};

/// The timespec struct used by the kernel.
pub const kernel_timespec = extern struct {
    sec: i64,
    nsec: i64,
};

// https://github.com/ziglang/zig/issues/4726#issuecomment-2190337877
pub const timespec = if (native_arch == .riscv32) kernel_timespec else extern struct {
    sec: isize,
    nsec: isize,
};

pub const XDP = struct {
    pub const SHARED_UMEM = (1 << 0);
    pub const COPY = (1 << 1);
    pub const ZEROCOPY = (1 << 2);
    pub const UMEM_UNALIGNED_CHUNK_FLAG = (1 << 0);
    pub const USE_NEED_WAKEUP = (1 << 3);

    pub const MMAP_OFFSETS = 1;
    pub const RX_RING = 2;
    pub const TX_RING = 3;
    pub const UMEM_REG = 4;
    pub const UMEM_FILL_RING = 5;
    pub const UMEM_COMPLETION_RING = 6;
    pub const STATISTICS = 7;
    pub const OPTIONS = 8;

    pub const OPTIONS_ZEROCOPY = (1 << 0);

    pub const PGOFF_RX_RING = 0;
    pub const PGOFF_TX_RING = 0x80000000;
    pub const UMEM_PGOFF_FILL_RING = 0x100000000;
    pub const UMEM_PGOFF_COMPLETION_RING = 0x180000000;
};

pub const xdp_ring_offset = extern struct {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
};

pub const xdp_mmap_offsets = extern struct {
    rx: xdp_ring_offset,
    tx: xdp_ring_offset,
    fr: xdp_ring_offset,
    cr: xdp_ring_offset,
};

pub const xdp_umem_reg = extern struct {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
};

pub const xdp_statistics = extern struct {
    rx_dropped: u64,
    rx_invalid_descs: u64,
    tx_invalid_descs: u64,
    rx_ring_full: u64,
    rx_fill_ring_empty_descs: u64,
    tx_ring_empty_descs: u64,
};

pub const xdp_options = extern struct {
    flags: u32,
};

pub const XSK_UNALIGNED_BUF_OFFSET_SHIFT = 48;
pub const XSK_UNALIGNED_BUF_ADDR_MASK = (1 << XSK_UNALIGNED_BUF_OFFSET_SHIFT) - 1;

pub const xdp_desc = extern struct {
    addr: u64,
    len: u32,
    options: u32,
};

fn issecure_mask(comptime x: comptime_int) comptime_int {
    return 1 << x;
}

pub const SECUREBITS_DEFAULT = 0x00000000;

pub const SECURE_NOROOT = 0;
pub const SECURE_NOROOT_LOCKED = 1;

pub const SECBIT_NOROOT = issecure_mask(SECURE_NOROOT);
pub const SECBIT_NOROOT_LOCKED = issecure_mask(SECURE_NOROOT_LOCKED);

pub const SECURE_NO_SETUID_FIXUP = 2;
pub const SECURE_NO_SETUID_FIXUP_LOCKED = 3;

pub const SECBIT_NO_SETUID_FIXUP = issecure_mask(SECURE_NO_SETUID_FIXUP);
pub const SECBIT_NO_SETUID_FIXUP_LOCKED = issecure_mask(SECURE_NO_SETUID_FIXUP_LOCKED);

pub const SECURE_KEEP_CAPS = 4;
pub const SECURE_KEEP_CAPS_LOCKED = 5;

pub const SECBIT_KEEP_CAPS = issecure_mask(SECURE_KEEP_CAPS);
pub const SECBIT_KEEP_CAPS_LOCKED = issecure_mask(SECURE_KEEP_CAPS_LOCKED);

pub const SECURE_NO_CAP_AMBIENT_RAISE = 6;
pub const SECURE_NO_CAP_AMBIENT_RAISE_LOCKED = 7;

pub const SECBIT_NO_CAP_AMBIENT_RAISE = issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE);
pub const SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED = issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE_LOCKED);

pub const SECURE_ALL_BITS = issecure_mask(SECURE_NOROOT) |
    issecure_mask(SECURE_NO_SETUID_FIXUP) |
    issecure_mask(SECURE_KEEP_CAPS) |
    issecure_mask(SECURE_NO_CAP_AMBIENT_RAISE);
pub const SECURE_ALL_LOCKS = SECURE_ALL_BITS << 1;

pub const PR = enum(i32) {
    SET_PDEATHSIG = 1,
    GET_PDEATHSIG = 2,

    GET_DUMPABLE = 3,
    SET_DUMPABLE = 4,

    GET_UNALIGN = 5,
    SET_UNALIGN = 6,

    GET_KEEPCAPS = 7,
    SET_KEEPCAPS = 8,

    GET_FPEMU = 9,
    SET_FPEMU = 10,

    GET_FPEXC = 11,
    SET_FPEXC = 12,

    GET_TIMING = 13,
    SET_TIMING = 14,

    SET_NAME = 15,
    GET_NAME = 16,

    GET_ENDIAN = 19,
    SET_ENDIAN = 20,

    GET_SECCOMP = 21,
    SET_SECCOMP = 22,

    CAPBSET_READ = 23,
    CAPBSET_DROP = 24,

    GET_TSC = 25,
    SET_TSC = 26,

    GET_SECUREBITS = 27,
    SET_SECUREBITS = 28,

    SET_TIMERSLACK = 29,
    GET_TIMERSLACK = 30,

    TASK_PERF_EVENTS_DISABLE = 31,
    TASK_PERF_EVENTS_ENABLE = 32,

    MCE_KILL = 33,

    MCE_KILL_GET = 34,

    SET_MM = 35,

    SET_PTRACER = 0x59616d61,

    SET_CHILD_SUBREAPER = 36,
    GET_CHILD_SUBREAPER = 37,

    SET_NO_NEW_PRIVS = 38,
    GET_NO_NEW_PRIVS = 39,

    GET_TID_ADDRESS = 40,

    SET_THP_DISABLE = 41,
    GET_THP_DISABLE = 42,

    MPX_ENABLE_MANAGEMENT = 43,
    MPX_DISABLE_MANAGEMENT = 44,

    SET_FP_MODE = 45,
    GET_FP_MODE = 46,

    CAP_AMBIENT = 47,

    SVE_SET_VL = 50,
    SVE_GET_VL = 51,

    GET_SPECULATION_CTRL = 52,
    SET_SPECULATION_CTRL = 53,

    _,

    pub const UNALIGN_NOPRINT = 1;
    pub const UNALIGN_SIGBUS = 2;

    pub const FPEMU_NOPRINT = 1;
    pub const FPEMU_SIGFPE = 2;

    pub const FP_EXC_SW_ENABLE = 0x80;
    pub const FP_EXC_DIV = 0x010000;
    pub const FP_EXC_OVF = 0x020000;
    pub const FP_EXC_UND = 0x040000;
    pub const FP_EXC_RES = 0x080000;
    pub const FP_EXC_INV = 0x100000;
    pub const FP_EXC_DISABLED = 0;
    pub const FP_EXC_NONRECOV = 1;
    pub const FP_EXC_ASYNC = 2;
    pub const FP_EXC_PRECISE = 3;

    pub const TIMING_STATISTICAL = 0;
    pub const TIMING_TIMESTAMP = 1;

    pub const ENDIAN_BIG = 0;
    pub const ENDIAN_LITTLE = 1;
    pub const ENDIAN_PPC_LITTLE = 2;

    pub const TSC_ENABLE = 1;
    pub const TSC_SIGSEGV = 2;

    pub const MCE_KILL_CLEAR = 0;
    pub const MCE_KILL_SET = 1;

    pub const MCE_KILL_LATE = 0;
    pub const MCE_KILL_EARLY = 1;
    pub const MCE_KILL_DEFAULT = 2;

    pub const SET_MM_START_CODE = 1;
    pub const SET_MM_END_CODE = 2;
    pub const SET_MM_START_DATA = 3;
    pub const SET_MM_END_DATA = 4;
    pub const SET_MM_START_STACK = 5;
    pub const SET_MM_START_BRK = 6;
    pub const SET_MM_BRK = 7;
    pub const SET_MM_ARG_START = 8;
    pub const SET_MM_ARG_END = 9;
    pub const SET_MM_ENV_START = 10;
    pub const SET_MM_ENV_END = 11;
    pub const SET_MM_AUXV = 12;
    pub const SET_MM_EXE_FILE = 13;
    pub const SET_MM_MAP = 14;
    pub const SET_MM_MAP_SIZE = 15;

    pub const SET_PTRACER_ANY = std.math.maxInt(c_ulong);

    pub const FP_MODE_FR = 1 << 0;
    pub const FP_MODE_FRE = 1 << 1;

    pub const CAP_AMBIENT_IS_SET = 1;
    pub const CAP_AMBIENT_RAISE = 2;
    pub const CAP_AMBIENT_LOWER = 3;
    pub const CAP_AMBIENT_CLEAR_ALL = 4;

    pub const SVE_SET_VL_ONEXEC = 1 << 18;
    pub const SVE_VL_LEN_MASK = 0xffff;
    pub const SVE_VL_INHERIT = 1 << 17;

    pub const SPEC_STORE_BYPASS = 0;
    pub const SPEC_NOT_AFFECTED = 0;
    pub const SPEC_PRCTL = 1 << 0;
    pub const SPEC_ENABLE = 1 << 1;
    pub const SPEC_DISABLE = 1 << 2;
    pub const SPEC_FORCE_DISABLE = 1 << 3;
};

pub const prctl_mm_map = extern struct {
    start_code: u64,
    end_code: u64,
    start_data: u64,
    end_data: u64,
    start_brk: u64,
    brk: u64,
    start_stack: u64,
    arg_start: u64,
    arg_end: u64,
    env_start: u64,
    env_end: u64,
    auxv: *u64,
    auxv_size: u32,
    exe_fd: u32,
};

pub const NETLINK = struct {
    /// Routing/device hook
    pub const ROUTE = 0;

    /// Unused number
    pub const UNUSED = 1;

    /// Reserved for user mode socket protocols
    pub const USERSOCK = 2;

    /// Unused number, formerly ip_queue
    pub const FIREWALL = 3;

    /// socket monitoring
    pub const SOCK_DIAG = 4;

    /// netfilter/iptables ULOG
    pub const NFLOG = 5;

    /// ipsec
    pub const XFRM = 6;

    /// SELinux event notifications
    pub const SELINUX = 7;

    /// Open-iSCSI
    pub const ISCSI = 8;

    /// auditing
    pub const AUDIT = 9;

    pub const FIB_LOOKUP = 10;

    pub const CONNECTOR = 11;

    /// netfilter subsystem
    pub const NETFILTER = 12;

    pub const IP6_FW = 13;

    /// DECnet routing messages
    pub const DNRTMSG = 14;

    /// Kernel messages to userspace
    pub const KOBJECT_UEVENT = 15;

    pub const GENERIC = 16;

    // leave room for NETLINK_DM (DM Events)

    /// SCSI Transports
    pub const SCSITRANSPORT = 18;

    pub const ECRYPTFS = 19;

    pub const RDMA = 20;

    /// Crypto layer
    pub const CRYPTO = 21;

    /// SMC monitoring
    pub const SMC = 22;
};

// Flags values

/// It is request message.
pub const NLM_F_REQUEST = 0x01;

/// Multipart message, terminated by NLMSG_DONE
pub const NLM_F_MULTI = 0x02;

/// Reply with ack, with zero or error code
pub const NLM_F_ACK = 0x04;

/// Echo this request
pub const NLM_F_ECHO = 0x08;

/// Dump was inconsistent due to sequence change
pub const NLM_F_DUMP_INTR = 0x10;

/// Dump was filtered as requested
pub const NLM_F_DUMP_FILTERED = 0x20;

// Modifiers to GET request

/// specify tree root
pub const NLM_F_ROOT = 0x100;

/// return all matching
pub const NLM_F_MATCH = 0x200;

/// atomic GET
pub const NLM_F_ATOMIC = 0x400;
pub const NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH;

// Modifiers to NEW request

/// Override existing
pub const NLM_F_REPLACE = 0x100;

/// Do not touch, if it exists
pub const NLM_F_EXCL = 0x200;

/// Create, if it does not exist
pub const NLM_F_CREATE = 0x400;

/// Add to end of list
pub const NLM_F_APPEND = 0x800;

// Modifiers to DELETE request

/// Do not delete recursively
pub const NLM_F_NONREC = 0x100;

// Flags for ACK message

/// request was capped
pub const NLM_F_CAPPED = 0x100;

/// extended ACK TVLs were included
pub const NLM_F_ACK_TLVS = 0x200;

pub const NetlinkMessageType = enum(u16) {
    /// < 0x10: reserved control messages
    pub const MIN_TYPE = 0x10;

    /// Nothing.
    NOOP = 0x1,

    /// Error
    ERROR = 0x2,

    /// End of a dump
    DONE = 0x3,

    /// Data lost
    OVERRUN = 0x4,

    // rtlink types

    RTM_NEWLINK = 16,
    RTM_DELLINK,
    RTM_GETLINK,
    RTM_SETLINK,

    RTM_NEWADDR = 20,
    RTM_DELADDR,
    RTM_GETADDR,

    RTM_NEWROUTE = 24,
    RTM_DELROUTE,
    RTM_GETROUTE,

    RTM_NEWNEIGH = 28,
    RTM_DELNEIGH,
    RTM_GETNEIGH,

    RTM_NEWRULE = 32,
    RTM_DELRULE,
    RTM_GETRULE,

    RTM_NEWQDISC = 36,
    RTM_DELQDISC,
    RTM_GETQDISC,

    RTM_NEWTCLASS = 40,
    RTM_DELTCLASS,
    RTM_GETTCLASS,

    RTM_NEWTFILTER = 44,
    RTM_DELTFILTER,
    RTM_GETTFILTER,

    RTM_NEWACTION = 48,
    RTM_DELACTION,
    RTM_GETACTION,

    RTM_NEWPREFIX = 52,

    RTM_GETMULTICAST = 58,

    RTM_GETANYCAST = 62,

    RTM_NEWNEIGHTBL = 64,
    RTM_GETNEIGHTBL = 66,
    RTM_SETNEIGHTBL,

    RTM_NEWNDUSEROPT = 68,

    RTM_NEWADDRLABEL = 72,
    RTM_DELADDRLABEL,
    RTM_GETADDRLABEL,

    RTM_GETDCB = 78,
    RTM_SETDCB,

    RTM_NEWNETCONF = 80,
    RTM_DELNETCONF,
    RTM_GETNETCONF = 82,

    RTM_NEWMDB = 84,
    RTM_DELMDB = 85,
    RTM_GETMDB = 86,

    RTM_NEWNSID = 88,
    RTM_DELNSID = 89,
    RTM_GETNSID = 90,

    RTM_NEWSTATS = 92,
    RTM_GETSTATS = 94,

    RTM_NEWCACHEREPORT = 96,

    RTM_NEWCHAIN = 100,
    RTM_DELCHAIN,
    RTM_GETCHAIN,

    RTM_NEWNEXTHOP = 104,
    RTM_DELNEXTHOP,
    RTM_GETNEXTHOP,

    _,
};

/// Netlink message header
/// Specified in RFC 3549 Section 2.3.2
pub const nlmsghdr = extern struct {
    /// Length of message including header
    len: u32,

    /// Message content
    type: NetlinkMessageType,

    /// Additional flags
    flags: u16,

    /// Sequence number
    seq: u32,

    /// Sending process port ID
    pid: u32,
};

pub const ifinfomsg = extern struct {
    family: u8,
    __pad1: u8 = 0,

    /// ARPHRD_*
    type: c_ushort,

    /// Link index
    index: c_int,

    /// IFF_* flags
    flags: c_uint,

    /// IFF_* change mask
    change: c_uint,
};

pub const rtattr = extern struct {
    /// Length of option
    len: c_ushort,

    /// Type of option
    type: extern union {
        /// IFLA_* from linux/if_link.h
        link: IFLA,
        /// IFA_* from linux/if_addr.h
        addr: IFA,
    },

    pub const ALIGNTO = 4;
};

pub const IFA = enum(c_ushort) {
    UNSPEC,
    ADDRESS,
    LOCAL,
    LABEL,
    BROADCAST,
    ANYCAST,
    CACHEINFO,
    MULTICAST,
    FLAGS,
    RT_PRIORITY,
    TARGET_NETNSID,
    PROTO,

    _,
};

pub const IFLA = enum(c_ushort) {
    UNSPEC,
    ADDRESS,
    BROADCAST,
    IFNAME,
    MTU,
    LINK,
    QDISC,
    STATS,
    COST,
    PRIORITY,
    MASTER,

    /// Wireless Extension event
    WIRELESS,

    /// Protocol specific information for a link
    PROTINFO,

    TXQLEN,
    MAP,
    WEIGHT,
    OPERSTATE,
    LINKMODE,
    LINKINFO,
    NET_NS_PID,
    IFALIAS,

    /// Number of VFs if device is SR-IOV PF
    NUM_VF,

    VFINFO_LIST,
    STATS64,
    VF_PORTS,
    PORT_SELF,
    AF_SPEC,

    /// Group the device belongs to
    GROUP,

    NET_NS_FD,

    /// Extended info mask, VFs, etc
    EXT_MASK,

    /// Promiscuity count: > 0 means acts PROMISC
    PROMISCUITY,

    NUM_TX_QUEUES,
    NUM_RX_QUEUES,
    CARRIER,
    PHYS_PORT_ID,
    CARRIER_CHANGES,
    PHYS_SWITCH_ID,
    LINK_NETNSID,
    PHYS_PORT_NAME,
    PROTO_DOWN,
    GSO_MAX_SEGS,
    GSO_MAX_SIZE,
    PAD,
    XDP,
    EVENT,

    NEW_NETNSID,
    IF_NETNSID,

    CARRIER_UP_COUNT,
    CARRIER_DOWN_COUNT,
    NEW_IFINDEX,
    MIN_MTU,
    MAX_MTU,

    _,

    pub const TARGET_NETNSID: IFLA = .IF_NETNSID;
};

pub const rtnl_link_ifmap = extern struct {
    mem_start: u64,
    mem_end: u64,
    base_addr: u64,
    irq: u16,
    dma: u8,
    port: u8,
};

pub const rtnl_link_stats = extern struct {
    /// total packets received
    rx_packets: u32,

    /// total packets transmitted
    tx_packets: u32,

    /// total bytes received
    rx_bytes: u32,

    /// total bytes transmitted
    tx_bytes: u32,

    /// bad packets received
    rx_errors: u32,

    /// packet transmit problems
    tx_errors: u32,

    /// no space in linux buffers
    rx_dropped: u32,

    /// no space available in linux
    tx_dropped: u32,

    /// multicast packets received
    multicast: u32,

    collisions: u32,

    // detailed rx_errors

    rx_length_errors: u32,

    /// receiver ring buff overflow
    rx_over_errors: u32,

    /// recved pkt with crc error
    rx_crc_errors: u32,

    /// recv'd frame alignment error
    rx_frame_errors: u32,

    /// recv'r fifo overrun
    rx_fifo_errors: u32,

    /// receiver missed packet
    rx_missed_errors: u32,

    // detailed tx_errors
    tx_aborted_errors: u32,
    tx_carrier_errors: u32,
    tx_fifo_errors: u32,
    tx_heartbeat_errors: u32,
    tx_window_errors: u32,

    // for cslip etc

    rx_compressed: u32,
    tx_compressed: u32,

    /// dropped, no handler found
    rx_nohandler: u32,
};

pub const rtnl_link_stats64 = extern struct {
    /// total packets received
    rx_packets: u64,

    /// total packets transmitted
    tx_packets: u64,

    /// total bytes received
    rx_bytes: u64,

    /// total bytes transmitted
    tx_bytes: u64,

    /// bad packets received
    rx_errors: u64,

    /// packet transmit problems
    tx_errors: u64,

    /// no space in linux buffers
    rx_dropped: u64,

    /// no space available in linux
    tx_dropped: u64,

    /// multicast packets received
    multicast: u64,

    collisions: u64,

    // detailed rx_errors

    rx_length_errors: u64,

    /// receiver ring buff overflow
    rx_over_errors: u64,

    /// recved pkt with crc error
    rx_crc_errors: u64,

    /// recv'd frame alignment error
    rx_frame_errors: u64,

    /// recv'r fifo overrun
    rx_fifo_errors: u64,

    /// receiver missed packet
    rx_missed_errors: u64,

    // detailed tx_errors
    tx_aborted_errors: u64,
    tx_carrier_errors: u64,
    tx_fifo_errors: u64,
    tx_heartbeat_errors: u64,
    tx_window_errors: u64,

    // for cslip etc

    rx_compressed: u64,
    tx_compressed: u64,

    /// dropped, no handler found
    rx_nohandler: u64,
};

pub const perf_event_attr = extern struct {
    /// Major type: hardware/software/tracepoint/etc.
    type: PERF.TYPE = undefined,
    /// Size of the attr structure, for fwd/bwd compat.
    size: u32 = @sizeOf(perf_event_attr),
    /// Type specific configuration information.
    config: u64 = 0,

    sample_period_or_freq: u64 = 0,
    sample_type: u64 = 0,
    read_format: u64 = 0,

    flags: packed struct {
        /// off by default
        disabled: bool = false,
        /// children inherit it
        inherit: bool = false,
        /// must always be on PMU
        pinned: bool = false,
        /// only group on PMU
        exclusive: bool = false,
        /// don't count user
        exclude_user: bool = false,
        /// ditto kernel
        exclude_kernel: bool = false,
        /// ditto hypervisor
        exclude_hv: bool = false,
        /// don't count when idle
        exclude_idle: bool = false,
        /// include mmap data
        mmap: bool = false,
        /// include comm data
        comm: bool = false,
        /// use freq, not period
        freq: bool = false,
        /// per task counts
        inherit_stat: bool = false,
        /// next exec enables
        enable_on_exec: bool = false,
        /// trace fork/exit
        task: bool = false,
        /// wakeup_watermark
        watermark: bool = false,
        /// precise_ip:
        ///
        ///  0 - SAMPLE_IP can have arbitrary skid
        ///  1 - SAMPLE_IP must have constant skid
        ///  2 - SAMPLE_IP requested to have 0 skid
        ///  3 - SAMPLE_IP must have 0 skid
        ///
        ///  See also PERF_RECORD_MISC_EXACT_IP
        /// skid constraint
        precise_ip: u2 = 0,
        /// non-exec mmap data
        mmap_data: bool = false,
        /// sample_type all events
        sample_id_all: bool = false,

        /// don't count in host
        exclude_host: bool = false,
        /// don't count in guest
        exclude_guest: bool = false,

        /// exclude kernel callchains
        exclude_callchain_kernel: bool = false,
        /// exclude user callchains
        exclude_callchain_user: bool = false,
        /// include mmap with inode data
        mmap2: bool = false,
        /// flag comm events that are due to an exec
        comm_exec: bool = false,
        /// use @clockid for time fields
        use_clockid: bool = false,
        /// context switch data
        context_switch: bool = false,
        /// Write ring buffer from end to beginning
        write_backward: bool = false,
        /// include namespaces data
        namespaces: bool = false,

        __reserved_1: u35 = 0,
    } = .{},
    /// wakeup every n events, or
    /// bytes before wakeup
    wakeup_events_or_watermark: u32 = 0,

    bp_type: u32 = 0,

    /// This field is also used for:
    /// bp_addr
    /// kprobe_func for perf_kprobe
    /// uprobe_path for perf_uprobe
    config1: u64 = 0,
    /// This field is also used for:
    /// bp_len
    /// kprobe_addr when kprobe_func == null
    /// probe_offset for perf_[k,u]probe
    config2: u64 = 0,

    /// enum perf_branch_sample_type
    branch_sample_type: u64 = 0,

    /// Defines set of user regs to dump on samples.
    /// See asm/perf_regs.h for details.
    sample_regs_user: u64 = 0,

    /// Defines size of the user stack to dump on samples.
    sample_stack_user: u32 = 0,

    clockid: clockid_t = .REALTIME,
    /// Defines set of regs to dump for each sample
    /// state captured on:
    ///  - precise = 0: PMU interrupt
    ///  - precise > 0: sampled instruction
    ///
    /// See asm/perf_regs.h for details.
    sample_regs_intr: u64 = 0,

    /// Wakeup watermark for AUX area
    aux_watermark: u32 = 0,
    sample_max_stack: u16 = 0,
    /// Align to u64
    __reserved_2: u16 = 0,
};

pub const PERF = struct {
    pub const TYPE = enum(u32) {
        HARDWARE,
        SOFTWARE,
        TRACEPOINT,
        HW_CACHE,
        RAW,
        BREAKPOINT,
        MAX,
        _,
    };

    pub const COUNT = struct {
        pub const HW = enum(u32) {
            CPU_CYCLES,
            INSTRUCTIONS,
            CACHE_REFERENCES,
            CACHE_MISSES,
            BRANCH_INSTRUCTIONS,
            BRANCH_MISSES,
            BUS_CYCLES,
            STALLED_CYCLES_FRONTEND,
            STALLED_CYCLES_BACKEND,
            REF_CPU_CYCLES,
            MAX,

            pub const CACHE = enum(u32) {
                L1D,
                L1I,
                LL,
                DTLB,
                ITLB,
                BPU,
                NODE,
                MAX,

                pub const OP = enum(u32) {
                    READ,
                    WRITE,
                    PREFETCH,
                    MAX,
                };

                pub const RESULT = enum(u32) {
                    ACCESS,
                    MISS,
                    MAX,
                };
            };
        };

        pub const SW = enum(u32) {
            CPU_CLOCK,
            TASK_CLOCK,
            PAGE_FAULTS,
            CONTEXT_SWITCHES,
            CPU_MIGRATIONS,
            PAGE_FAULTS_MIN,
            PAGE_FAULTS_MAJ,
            ALIGNMENT_FAULTS,
            EMULATION_FAULTS,
            DUMMY,
            BPF_OUTPUT,
            MAX,
        };
    };

    pub const SAMPLE = struct {
        pub const IP = 1;
        pub const TID = 2;
        pub const TIME = 4;
        pub const ADDR = 8;
        pub const READ = 16;
        pub const CALLCHAIN = 32;
        pub const ID = 64;
        pub const CPU = 128;
        pub const PERIOD = 256;
        pub const STREAM_ID = 512;
        pub const RAW = 1024;
        pub const BRANCH_STACK = 2048;
        pub const REGS_USER = 4096;
        pub const STACK_USER = 8192;
        pub const WEIGHT = 16384;
        pub const DATA_SRC = 32768;
        pub const IDENTIFIER = 65536;
        pub const TRANSACTION = 131072;
        pub const REGS_INTR = 262144;
        pub const PHYS_ADDR = 524288;
        pub const MAX = 1048576;

        pub const BRANCH = struct {
            pub const USER = 1 << 0;
            pub const KERNEL = 1 << 1;
            pub const HV = 1 << 2;
            pub const ANY = 1 << 3;
            pub const ANY_CALL = 1 << 4;
            pub const ANY_RETURN = 1 << 5;
            pub const IND_CALL = 1 << 6;
            pub const ABORT_TX = 1 << 7;
            pub const IN_TX = 1 << 8;
            pub const NO_TX = 1 << 9;
            pub const COND = 1 << 10;
            pub const CALL_STACK = 1 << 11;
            pub const IND_JUMP = 1 << 12;
            pub const CALL = 1 << 13;
            pub const NO_FLAGS = 1 << 14;
            pub const NO_CYCLES = 1 << 15;
            pub const TYPE_SAVE = 1 << 16;
            pub const MAX = 1 << 17;
        };
    };

    pub const FLAG = struct {
        pub const FD_NO_GROUP = 1 << 0;
        pub const FD_OUTPUT = 1 << 1;
        pub const PID_CGROUP = 1 << 2;
        pub const FD_CLOEXEC = 1 << 3;
    };

    pub const EVENT_IOC = struct {
        pub const ENABLE = 9216;
        pub const DISABLE = 9217;
        pub const REFRESH = 9218;
        pub const RESET = 9219;
        pub const PERIOD = 1074275332;
        pub const SET_OUTPUT = 9221;
        pub const SET_FILTER = 1074275334;
        pub const SET_BPF = 1074013192;
        pub const PAUSE_OUTPUT = 1074013193;
        pub const QUERY_BPF = 3221758986;
        pub const MODIFY_ATTRIBUTES = 1074275339;
    };

    pub const IOC_FLAG_GROUP = 1;
};

// TODO: Add the rest of the AUDIT defines?
pub const AUDIT = struct {
    pub const ARCH = enum(u32) {
        const CONVENTION_MIPS64_N32 = 0x20000000;
        const @"64BIT" = 0x80000000;
        const LE = 0x40000000;

        AARCH64 = toAudit(.AARCH64, @"64BIT" | LE),
        ALPHA = toAudit(.ALPHA, @"64BIT" | LE),
        ARCOMPACT = toAudit(.ARC_COMPACT, LE),
        ARCOMPACTBE = toAudit(.ARC_COMPACT, 0),
        ARCV2 = toAudit(.ARC_COMPACT2, LE),
        ARCV2BE = toAudit(.ARC_COMPACT2, 0),
        ARM = toAudit(.ARM, LE),
        ARMEB = toAudit(.ARM, 0),
        C6X = toAudit(.TI_C6000, LE),
        C6XBE = toAudit(.TI_C6000, 0),
        CRIS = toAudit(.CRIS, LE),
        CSKY = toAudit(.CSKY, LE),
        FRV = toAudit(.FRV, 0),
        H8300 = toAudit(.H8_300, 0),
        HEXAGON = toAudit(.HEXAGON, 0),
        I386 = toAudit(.@"386", LE),
        IA64 = toAudit(.IA_64, @"64BIT" | LE),
        M32R = toAudit(.M32R, 0),
        M68K = toAudit(.@"68K", 0),
        MICROBLAZE = toAudit(.MICROBLAZE, 0),
        MIPS = toAudit(.MIPS, 0),
        MIPSEL = toAudit(.MIPS, LE),
        MIPS64 = toAudit(.MIPS, @"64BIT"),
        MIPS64N32 = toAudit(.MIPS, @"64BIT" | CONVENTION_MIPS64_N32),
        MIPSEL64 = toAudit(.MIPS, @"64BIT" | LE),
        MIPSEL64N32 = toAudit(.MIPS, @"64BIT" | LE | CONVENTION_MIPS64_N32),
        NDS32 = toAudit(.NDS32, LE),
        NDS32BE = toAudit(.NDS32, 0),
        NIOS2 = toAudit(.ALTERA_NIOS2, LE),
        OPENRISC = toAudit(.OPENRISC, 0),
        PARISC = toAudit(.PARISC, 0),
        PARISC64 = toAudit(.PARISC, @"64BIT"),
        PPC = toAudit(.PPC, 0),
        PPC64 = toAudit(.PPC64, @"64BIT"),
        PPC64LE = toAudit(.PPC64, @"64BIT" | LE),
        RISCV32 = toAudit(.RISCV, LE),
        RISCV64 = toAudit(.RISCV, @"64BIT" | LE),
        S390 = toAudit(.S390, 0),
        S390X = toAudit(.S390, @"64BIT"),
        SH = toAudit(.SH, 0),
        SHEL = toAudit(.SH, LE),
        SH64 = toAudit(.SH, @"64BIT"),
        SHEL64 = toAudit(.SH, @"64BIT" | LE),
        SPARC = toAudit(.SPARC, 0),
        SPARC64 = toAudit(.SPARCV9, @"64BIT"),
        TILEGX = toAudit(.TILEGX, @"64BIT" | LE),
        TILEGX32 = toAudit(.TILEGX, LE),
        TILEPRO = toAudit(.TILEPRO, LE),
        UNICORE = toAudit(.UNICORE, LE),
        X86_64 = toAudit(.X86_64, @"64BIT" | LE),
        XTENSA = toAudit(.XTENSA, 0),
        LOONGARCH32 = toAudit(.LOONGARCH, LE),
        LOONGARCH64 = toAudit(.LOONGARCH, @"64BIT" | LE),

        fn toAudit(em: elf.EM, flags: u32) u32 {
            return @intFromEnum(em) | flags;
        }

        pub const current: AUDIT.ARCH = switch (native_arch) {
            .arm, .thumb => .ARM,
            .armeb, .thumbeb => .ARMEB,
            .aarch64 => .AARCH64,
            .arc => .ARCV2,
            .csky => .CSKY,
            .hexagon => .HEXAGON,
            .loongarch32 => .LOONGARCH32,
            .loongarch64 => .LOONGARCH64,
            .m68k => .M68K,
            .mips => .MIPS,
            .mipsel => .MIPSEL,
            .mips64 => switch (native_abi) {
                .gnuabin32, .muslabin32 => .MIPS64N32,
                else => .MIPS64,
            },
            .mips64el => switch (native_abi) {
                .gnuabin32, .muslabin32 => .MIPSEL64N32,
                else => .MIPSEL64,
            },
            .powerpc => .PPC,
            .powerpc64 => .PPC64,
            .powerpc64le => .PPC64LE,
            .riscv32 => .RISCV32,
            .riscv64 => .RISCV64,
            .sparc => .SPARC,
            .sparc64 => .SPARC64,
            .s390x => .S390X,
            .x86 => .I386,
            .x86_64 => .X86_64,
            .xtensa => .XTENSA,
            else => @compileError("unsupported architecture"),
        };
    };
};

pub const PTRACE = struct {
    pub const TRACEME = 0;
    pub const PEEKTEXT = 1;
    pub const PEEKDATA = 2;
    pub const PEEKUSER = 3;
    pub const POKETEXT = 4;
    pub const POKEDATA = 5;
    pub const POKEUSER = 6;
    pub const CONT = 7;
    pub const KILL = 8;
    pub const SINGLESTEP = 9;
    pub const GETREGS = 12;
    pub const SETREGS = 13;
    pub const GETFPREGS = 14;
    pub const SETFPREGS = 15;
    pub const ATTACH = 16;
    pub const DETACH = 17;
    pub const GETFPXREGS = 18;
    pub const SETFPXREGS = 19;
    pub const SYSCALL = 24;
    pub const SETOPTIONS = 0x4200;
    pub const GETEVENTMSG = 0x4201;
    pub const GETSIGINFO = 0x4202;
    pub const SETSIGINFO = 0x4203;
    pub const GETREGSET = 0x4204;
    pub const SETREGSET = 0x4205;
    pub const SEIZE = 0x4206;
    pub const INTERRUPT = 0x4207;
    pub const LISTEN = 0x4208;
    pub const PEEKSIGINFO = 0x4209;
    pub const GETSIGMASK = 0x420a;
    pub const SETSIGMASK = 0x420b;
    pub const SECCOMP_GET_FILTER = 0x420c;
    pub const SECCOMP_GET_METADATA = 0x420d;
    pub const GET_SYSCALL_INFO = 0x420e;
};

/// A waiter for vectorized wait.
pub const futex_waitv = extern struct {
    // Expected value at uaddr
    val: u64,
    /// User address to wait on.
    uaddr: u64,
    /// Flags for this waiter.
    flags: u32,
    /// Reserved member to preserve alignment.
    /// Should be 0.
    __reserved: u32,
};

pub const cache_stat_range = extern struct {
    off: u64,
    len: u64,
};

pub const cache_stat = extern struct {
    /// Number of cached pages.
    cache: u64,
    /// Number of dirty pages.
    dirty: u64,
    /// Number of pages marked for writeback.
    writeback: u64,
    /// Number of pages evicted from the cache.
    evicted: u64,
    /// Number of recently evicted pages.
    /// A page is recently evicted if its last eviction was recent enough that its
    /// reentry to the cache would indicate that it is actively being used by the
    /// system, and that there is memory pressure on the system.
    recently_evicted: u64,
};

pub const SHADOW_STACK = struct {
    /// Set up a restore token in the shadow stack.
    pub const SET_TOKEN: u64 = 1 << 0;
};
const builtin = @import("builtin");
const std = @import("../../std.zig");
const maxInt = std.math.maxInt;
const linux = std.os.linux;
const SYS = linux.SYS;
const socklen_t = linux.socklen_t;
const sockaddr = linux.sockaddr;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const uid_t = linux.uid_t;
const gid_t = linux.gid_t;
const pid_t = linux.pid_t;
const stack_t = linux.stack_t;
const sigset_t = linux.sigset_t;
const timespec = std.os.linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile ("svc #0"
        : [ret] "={x0}" (-> usize),
        : [number] "{x8}" (@intFromEnum(number)),
        : "memory", "cc"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile ("svc #0"
        : [ret] "={x0}" (-> usize),
        : [number] "{x8}" (@intFromEnum(number)),
          [arg1] "{x0}" (arg1),
        : "memory", "cc"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile ("svc #0"
        : [ret] "={x0}" (-> usize),
        : [number] "{x8}" (@intFromEnum(number)),
          [arg1] "{x0}" (arg1),
          [arg2] "{x1}" (arg2),
        : "memory", "cc"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile ("svc #0"
        : [ret] "={x0}" (-> usize),
        : [number] "{x8}" (@intFromEnum(number)),
          [arg1] "{x0}" (arg1),
          [arg2] "{x1}" (arg2),
          [arg3] "{x2}" (arg3),
        : "memory", "cc"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile ("svc #0"
        : [ret] "={x0}" (-> usize),
        : [number] "{x8}" (@intFromEnum(number)),
          [arg1] "{x0}" (arg1),
          [arg2] "{x1}" (arg2),
          [arg3] "{x2}" (arg3),
          [arg4] "{x3}" (arg4),
        : "memory", "cc"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile ("svc #0"
        : [ret] "={x0}" (-> usize),
        : [number] "{x8}" (@intFromEnum(number)),
          [arg1] "{x0}" (arg1),
          [arg2] "{x1}" (arg2),
          [arg3] "{x2}" (arg3),
          [arg4] "{x3}" (arg4),
          [arg5] "{x4}" (arg5),
        : "memory", "cc"
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
    return asm volatile ("svc #0"
        : [ret] "={x0}" (-> usize),
        : [number] "{x8}" (@intFromEnum(number)),
          [arg1] "{x0}" (arg1),
          [arg2] "{x1}" (arg2),
          [arg3] "{x2}" (arg3),
          [arg4] "{x3}" (arg4),
          [arg5] "{x4}" (arg5),
          [arg6] "{x5}" (arg6),
        : "memory", "cc"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //         x0,   x1,    w2,    x3,  x4,   x5,  x6
    //
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
    //         x8,        x0,    x1,    x2,   x3,  x4
    asm volatile (
        \\      // align stack and save func,arg
        \\      and x1,x1,#-16
        \\      stp x0,x3,[x1,#-16]!
        \\
        \\      // syscall
        \\      uxtw x0,w2
        \\      mov x2,x4
        \\      mov x3,x5
        \\      mov x4,x6
        \\      mov x8,#220 // SYS_clone
        \\      svc #0
        \\
        \\      cbz x0,1f
        \\      // parent
        \\      ret
        \\
        \\      // child
        \\1:
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\     .cfi_undefined lr
    );
    asm volatile (
        \\      mov fp, 0
        \\      mov lr, 0
        \\
        \\      ldp x1,x0,[sp],#16
        \\      blr x1
        \\      mov x8,#93 // SYS_exit
        \\      svc #0
    );
}

pub const restore = restore_rt;

pub fn restore_rt() callconv(.naked) noreturn {
    switch (@import("builtin").zig_backend) {
        .stage2_c => asm volatile (
            \\ mov x8, %[number]
            \\ svc #0
            :
            : [number] "i" (@intFromEnum(SYS.rt_sigreturn)),
            : "memory", "cc"
        ),
        else => asm volatile (
            \\ svc #0
            :
            : [number] "{x8}" (@intFromEnum(SYS.rt_sigreturn)),
            : "memory", "cc"
        ),
    }
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;

    pub const SETOWN = 8;
    pub const GETOWN = 9;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const GETLK = 5;
    pub const SETLK = 6;
    pub const SETLKW = 7;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const VDSO = struct {
    pub const CGT_SYM = "__kernel_clock_gettime";
    pub const CGT_VER = "LINUX_2.6.39";
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
pub const time_t = isize;
pub const mode_t = u32;
pub const off_t = isize;
pub const ino_t = usize;
pub const dev_t = usize;
pub const blkcnt_t = isize;

// The `stat` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    ino: ino_t,
    mode: mode_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    __pad: usize,
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

pub const timeval = extern struct {
    sec: isize,
    usec: isize,
};

pub const timezone = extern struct {
    minuteswest: i32,
    dsttime: i32,
};

pub const mcontext_t = extern struct {
    fault_address: usize,
    regs: [31]usize,
    sp: usize,
    pc: usize,
    pstate: usize,
    // Make sure the field is correctly aligned since this area
    // holds various FP/vector registers
    reserved1: [256 * 16]u8 align(16),
};

pub const ucontext_t = extern struct {
    flags: usize,
    link: ?*ucontext_t,
    stack: stack_t,
    sigmask: sigset_t,
    mcontext: mcontext_t,
};

/// TODO
pub const getcontext = {};

pub const Elf_Symndx = u32;
const std = @import("../../std.zig");
const maxInt = std.math.maxInt;
const linux = std.os.linux;
const SYS = linux.SYS;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const socklen_t = linux.socklen_t;
const stack_t = linux.stack_t;
const sigset_t = linux.sigset_t;
const uid_t = linux.uid_t;
const gid_t = linux.gid_t;
const pid_t = linux.pid_t;
const sockaddr = linux.sockaddr;
const timespec = linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile ("svc #0"
        : [ret] "={r0}" (-> usize),
        : [number] "{r7}" (@intFromEnum(number)),
        : "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile ("svc #0"
        : [ret] "={r0}" (-> usize),
        : [number] "{r7}" (@intFromEnum(number)),
          [arg1] "{r0}" (arg1),
        : "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile ("svc #0"
        : [ret] "={r0}" (-> usize),
        : [number] "{r7}" (@intFromEnum(number)),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
        : "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile ("svc #0"
        : [ret] "={r0}" (-> usize),
        : [number] "{r7}" (@intFromEnum(number)),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
          [arg3] "{r2}" (arg3),
        : "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile ("svc #0"
        : [ret] "={r0}" (-> usize),
        : [number] "{r7}" (@intFromEnum(number)),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
          [arg3] "{r2}" (arg3),
          [arg4] "{r3}" (arg4),
        : "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile ("svc #0"
        : [ret] "={r0}" (-> usize),
        : [number] "{r7}" (@intFromEnum(number)),
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
    return asm volatile ("svc #0"
        : [ret] "={r0}" (-> usize),
        : [number] "{r7}" (@intFromEnum(number)),
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
    //         r0,   r1,    r2,    r3,  +0,   +4,  +8
    //
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
    //         r7         r0,    r1,    r2,   r3,  r4
    asm volatile (
        \\    stmfd sp!,{r4,r5,r6,r7}
        \\    mov r7,#120 // SYS_clone
        \\    mov r6,r3
        \\    mov r5,r0
        \\    mov r0,r2
        \\    and r1,r1,#-16
        \\    ldr r2,[sp,#16]
        \\    ldr r3,[sp,#20]
        \\    ldr r4,[sp,#24]
        \\    svc 0
        \\    tst r0,r0
        \\    beq 1f
        \\    ldmfd sp!,{r4,r5,r6,r7}
        \\    bx lr
        \\
        \\    // https://github.com/llvm/llvm-project/issues/115891
        \\1:  mov r7, #0
        \\    mov r11, #0
        \\    mov lr, #0
        \\
        \\    mov r0,r6
        \\    bl 3f
        \\    mov r7,#1 // SYS_exit
        \\    svc 0
        \\
        \\3:  bx r5
    );
}

pub fn restore() callconv(.naked) noreturn {
    switch (@import("builtin").zig_backend) {
        .stage2_c => asm volatile (
            \\ mov r7, %[number]
            \\ svc #0
            :
            : [number] "I" (@intFromEnum(SYS.sigreturn)),
            : "memory"
        ),
        else => asm volatile (
            \\ svc #0
            :
            : [number] "{r7}" (@intFromEnum(SYS.sigreturn)),
            : "memory"
        ),
    }
}

pub fn restore_rt() callconv(.naked) noreturn {
    switch (@import("builtin").zig_backend) {
        .stage2_c => asm volatile (
            \\ mov r7, %[number]
            \\ svc #0
            :
            : [number] "I" (@intFromEnum(SYS.rt_sigreturn)),
            : "memory"
        ),
        else => asm volatile (
            \\ svc #0
            :
            : [number] "{r7}" (@intFromEnum(SYS.rt_sigreturn)),
            : "memory"
        ),
    }
}

pub const F = struct {
    pub const DUPFD = 0;
    pub const GETFD = 1;
    pub const SETFD = 2;
    pub const GETFL = 3;
    pub const SETFL = 4;

    pub const SETOWN = 8;
    pub const GETOWN = 9;
    pub const SETSIG = 10;
    pub const GETSIG = 11;

    pub const GETLK = 12;
    pub const SETLK = 13;
    pub const SETLKW = 14;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;

    pub const GETOWNER_UIDS = 17;
};

pub const VDSO = struct {
    pub const CGT_SYM = "__vdso_clock_gettime";
    pub const CGT_VER = "LINUX_2.6";
};

pub const HWCAP = struct {
    pub const SWP = 1 << 0;
    pub const HALF = 1 << 1;
    pub const THUMB = 1 << 2;
    pub const @"26BIT" = 1 << 3;
    pub const FAST_MULT = 1 << 4;
    pub const FPA = 1 << 5;
    pub const VFP = 1 << 6;
    pub const EDSP = 1 << 7;
    pub const JAVA = 1 << 8;
    pub const IWMMXT = 1 << 9;
    pub const CRUNCH = 1 << 10;
    pub const THUMBEE = 1 << 11;
    pub const NEON = 1 << 12;
    pub const VFPv3 = 1 << 13;
    pub const VFPv3D16 = 1 << 14;
    pub const TLS = 1 << 15;
    pub const VFPv4 = 1 << 16;
    pub const IDIVA = 1 << 17;
    pub const IDIVT = 1 << 18;
    pub const VFPD32 = 1 << 19;
    pub const IDIV = IDIVA | IDIVT;
    pub const LPAE = 1 << 20;
    pub const EVTSTRM = 1 << 21;
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    __pad0: [4]u8,
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
    control: ?*anyopaque,
    controllen: socklen_t,
    flags: i32,
};

pub const msghdr_const = extern struct {
    name: ?*const sockaddr,
    namelen: socklen_t,
    iov: [*]const iovec_const,
    iovlen: i32,
    control: ?*const anyopaque,
    controllen: socklen_t,
    flags: i32,
};

pub const blksize_t = i32;
pub const nlink_t = u32;
pub const time_t = isize;
pub const mode_t = u32;
pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u64;
pub const blkcnt_t = i64;

// The `stat` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    __dev_padding: u32,
    __ino_truncated: u32,
    mode: mode_t,
    nlink: nlink_t,
    uid: uid_t,
    gid: gid_t,
    rdev: dev_t,
    __rdev_padding: u32,
    size: off_t,
    blksize: blksize_t,
    blocks: blkcnt_t,
    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    ino: ino_t,

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

pub const timeval = extern struct {
    sec: i32,
    usec: i32,
};

pub const timezone = extern struct {
    minuteswest: i32,
    dsttime: i32,
};

pub const mcontext_t = extern struct {
    trap_no: usize,
    error_code: usize,
    oldmask: usize,
    arm_r0: usize,
    arm_r1: usize,
    arm_r2: usize,
    arm_r3: usize,
    arm_r4: usize,
    arm_r5: usize,
    arm_r6: usize,
    arm_r7: usize,
    arm_r8: usize,
    arm_r9: usize,
    arm_r10: usize,
    arm_fp: usize,
    arm_ip: usize,
    arm_sp: usize,
    arm_lr: usize,
    arm_pc: usize,
    arm_cpsr: usize,
    fault_address: usize,
};

pub const ucontext_t = extern struct {
    flags: usize,
    link: ?*ucontext_t,
    stack: stack_t,
    mcontext: mcontext_t,
    sigmask: sigset_t,
    regspace: [64]u64,
};

/// TODO
pub const getcontext = {};

pub const Elf_Symndx = u32;
const std = @import("../../std.zig");
const errno = linux.E.init;
const unexpectedErrno = std.posix.unexpectedErrno;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const expect = std.testing.expect;

const linux = std.os.linux;
const fd_t = linux.fd_t;
const pid_t = linux.pid_t;

pub const btf = @import("bpf/btf.zig");
pub const kern = @import("bpf/kern.zig");

// instruction classes
pub const LD = 0x00;
pub const LDX = 0x01;
pub const ST = 0x02;
pub const STX = 0x03;
pub const ALU = 0x04;
pub const JMP = 0x05;
pub const RET = 0x06;
pub const MISC = 0x07;

/// 32-bit
pub const W = 0x00;
/// 16-bit
pub const H = 0x08;
/// 8-bit
pub const B = 0x10;
/// 64-bit
pub const DW = 0x18;

pub const IMM = 0x00;
pub const ABS = 0x20;
pub const IND = 0x40;
pub const MEM = 0x60;
pub const LEN = 0x80;
pub const MSH = 0xa0;

// alu fields
pub const ADD = 0x00;
pub const SUB = 0x10;
pub const MUL = 0x20;
pub const DIV = 0x30;
pub const OR = 0x40;
pub const AND = 0x50;
pub const LSH = 0x60;
pub const RSH = 0x70;
pub const NEG = 0x80;
pub const MOD = 0x90;
pub const XOR = 0xa0;

// jmp fields
pub const JA = 0x00;
pub const JEQ = 0x10;
pub const JGT = 0x20;
pub const JGE = 0x30;
pub const JSET = 0x40;

//#define BPF_SRC(code)   ((code) & 0x08)
pub const K = 0x00;
pub const X = 0x08;

pub const MAXINSNS = 4096;

// instruction classes
/// jmp mode in word width
pub const JMP32 = 0x06;

/// alu mode in double word width
pub const ALU64 = 0x07;

// ld/ldx fields
/// exclusive add
pub const XADD = 0xc0;

// alu/jmp fields
/// mov reg to reg
pub const MOV = 0xb0;

/// sign extending arithmetic shift right */
pub const ARSH = 0xc0;

// change endianness of a register
/// flags for endianness conversion:
pub const END = 0xd0;

/// convert to little-endian */
pub const TO_LE = 0x00;

/// convert to big-endian
pub const TO_BE = 0x08;
pub const FROM_LE = TO_LE;
pub const FROM_BE = TO_BE;

// jmp encodings
/// jump != *
pub const JNE = 0x50;

/// LT is unsigned, '<'
pub const JLT = 0xa0;

/// LE is unsigned, '<=' *
pub const JLE = 0xb0;

/// SGT is signed '>', GT in x86
pub const JSGT = 0x60;

/// SGE is signed '>=', GE in x86
pub const JSGE = 0x70;

/// SLT is signed, '<'
pub const JSLT = 0xc0;

/// SLE is signed, '<='
pub const JSLE = 0xd0;

/// function call
pub const CALL = 0x80;

/// function return
pub const EXIT = 0x90;

/// Flag for prog_attach command. If a sub-cgroup installs some bpf program, the
/// program in this cgroup yields to sub-cgroup program.
pub const F_ALLOW_OVERRIDE = 0x1;

/// Flag for prog_attach command. If a sub-cgroup installs some bpf program,
/// that cgroup program gets run in addition to the program in this cgroup.
pub const F_ALLOW_MULTI = 0x2;

/// Flag for prog_attach command.
pub const F_REPLACE = 0x4;

/// If BPF_F_STRICT_ALIGNMENT is used in BPF_PROG_LOAD command, the verifier
/// will perform strict alignment checking as if the kernel has been built with
/// CONFIG_EFFICIENT_UNALIGNED_ACCESS not set, and NET_IP_ALIGN defined to 2.
pub const F_STRICT_ALIGNMENT = 0x1;

/// If BPF_F_ANY_ALIGNMENT is used in BPF_PROF_LOAD command, the verifier will
/// allow any alignment whatsoever. On platforms with strict alignment
/// requirements for loads and stores (such as sparc and mips) the verifier
/// validates that all loads and stores provably follow this requirement. This
/// flag turns that checking and enforcement off.
///
/// It is mostly used for testing when we want to validate the context and
/// memory access aspects of the verifier, but because of an unaligned access
/// the alignment check would trigger before the one we are interested in.
pub const F_ANY_ALIGNMENT = 0x2;

/// BPF_F_TEST_RND_HI32 is used in BPF_PROG_LOAD command for testing purpose.
/// Verifier does sub-register def/use analysis and identifies instructions
/// whose def only matters for low 32-bit, high 32-bit is never referenced later
/// through implicit zero extension. Therefore verifier notifies JIT back-ends
/// that it is safe to ignore clearing high 32-bit for these instructions. This
/// saves some back-ends a lot of code-gen. However such optimization is not
/// necessary on some arches, for example x86_64, arm64 etc, whose JIT back-ends
/// hence hasn't used verifier's analysis result. But, we really want to have a
/// way to be able to verify the correctness of the described optimization on
/// x86_64 on which testsuites are frequently exercised.
///
/// So, this flag is introduced. Once it is set, verifier will randomize high
/// 32-bit for those instructions who has been identified as safe to ignore
/// them. Then, if verifier is not doing correct analysis, such randomization
/// will regress tests to expose bugs.
pub const F_TEST_RND_HI32 = 0x4;

/// If BPF_F_SLEEPABLE is used in BPF_PROG_LOAD command, the verifier will
/// restrict map and helper usage for such programs. Sleepable BPF programs can
/// only be attached to hooks where kernel execution context allows sleeping.
/// Such programs are allowed to use helpers that may sleep like
/// bpf_copy_from_user().
pub const F_SLEEPABLE = 0x10;

/// When BPF ldimm64's insn[0].src_reg != 0 then this can have two extensions:
/// insn[0].src_reg:  BPF_PSEUDO_MAP_FD   BPF_PSEUDO_MAP_VALUE
/// insn[0].imm:      map fd              map fd
/// insn[1].imm:      0                   offset into value
/// insn[0].off:      0                   0
/// insn[1].off:      0                   0
/// ldimm64 rewrite:  address of map      address of map[0]+offset
/// verifier type:    CONST_PTR_TO_MAP    PTR_TO_MAP_VALUE
pub const PSEUDO_MAP_FD = 1;
pub const PSEUDO_MAP_VALUE = 2;

/// when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
/// offset to another bpf function
pub const PSEUDO_CALL = 1;

/// flag for BPF_MAP_UPDATE_ELEM command. create new element or update existing
pub const ANY = 0;

/// flag for BPF_MAP_UPDATE_ELEM command. create new element if it didn't exist
pub const NOEXIST = 1;

/// flag for BPF_MAP_UPDATE_ELEM command. update existing element
pub const EXIST = 2;

/// flag for BPF_MAP_UPDATE_ELEM command. spin_lock-ed map_lookup/map_update
pub const F_LOCK = 4;

/// flag for BPF_MAP_CREATE command */
pub const BPF_F_NO_PREALLOC = 0x1;

/// flag for BPF_MAP_CREATE command. Instead of having one common LRU list in
/// the BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list which can
/// scale and perform better. Note, the LRU nodes (including free nodes) cannot
/// be moved across different LRU lists.
pub const BPF_F_NO_COMMON_LRU = 0x2;

/// flag for BPF_MAP_CREATE command. Specify numa node during map creation
pub const BPF_F_NUMA_NODE = 0x4;

/// flag for BPF_MAP_CREATE command. Flags for BPF object read access from
/// syscall side
pub const BPF_F_RDONLY = 0x8;

/// flag for BPF_MAP_CREATE command. Flags for BPF object write access from
/// syscall side
pub const BPF_F_WRONLY = 0x10;

/// flag for BPF_MAP_CREATE command. Flag for stack_map, store build_id+offset
/// instead of pointer
pub const BPF_F_STACK_BUILD_ID = 0x20;

/// flag for BPF_MAP_CREATE command. Zero-initialize hash function seed. This
/// should only be used for testing.
pub const BPF_F_ZERO_SEED = 0x40;

/// flag for BPF_MAP_CREATE command Flags for accessing BPF object from program
/// side.
pub const BPF_F_RDONLY_PROG = 0x80;

/// flag for BPF_MAP_CREATE command. Flags for accessing BPF object from program
/// side.
pub const BPF_F_WRONLY_PROG = 0x100;

/// flag for BPF_MAP_CREATE command. Clone map from listener for newly accepted
/// socket
pub const BPF_F_CLONE = 0x200;

/// flag for BPF_MAP_CREATE command. Enable memory-mapping BPF map
pub const BPF_F_MMAPABLE = 0x400;

/// These values correspond to "syscalls" within the BPF program's environment,
/// each one is documented in std.os.linux.BPF.kern
pub const Helper = enum(i32) {
    unspec,
    map_lookup_elem,
    map_update_elem,
    map_delete_elem,
    probe_read,
    ktime_get_ns,
    trace_printk,
    get_prandom_u32,
    get_smp_processor_id,
    skb_store_bytes,
    l3_csum_replace,
    l4_csum_replace,
    tail_call,
    clone_redirect,
    get_current_pid_tgid,
    get_current_uid_gid,
    get_current_comm,
    get_cgroup_classid,
    skb_vlan_push,
    skb_vlan_pop,
    skb_get_tunnel_key,
    skb_set_tunnel_key,
    perf_event_read,
    redirect,
    get_route_realm,
    perf_event_output,
    skb_load_bytes,
    get_stackid,
    csum_diff,
    skb_get_tunnel_opt,
    skb_set_tunnel_opt,
    skb_change_proto,
    skb_change_type,
    skb_under_cgroup,
    get_hash_recalc,
    get_current_task,
    probe_write_user,
    current_task_under_cgroup,
    skb_change_tail,
    skb_pull_data,
    csum_update,
    set_hash_invalid,
    get_numa_node_id,
    skb_change_head,
    xdp_adjust_head,
    probe_read_str,
    get_socket_cookie,
    get_socket_uid,
    set_hash,
    setsockopt,
    skb_adjust_room,
    redirect_map,
    sk_redirect_map,
    sock_map_update,
    xdp_adjust_meta,
    perf_event_read_value,
    perf_prog_read_value,
    getsockopt,
    override_return,
    sock_ops_cb_flags_set,
    msg_redirect_map,
    msg_apply_bytes,
    msg_cork_bytes,
    msg_pull_data,
    bind,
    xdp_adjust_tail,
    skb_get_xfrm_state,
    get_stack,
    skb_load_bytes_relative,
    fib_lookup,
    sock_hash_update,
    msg_redirect_hash,
    sk_redirect_hash,
    lwt_push_encap,
    lwt_seg6_store_bytes,
    lwt_seg6_adjust_srh,
    lwt_seg6_action,
    rc_repeat,
    rc_keydown,
    skb_cgroup_id,
    get_current_cgroup_id,
    get_local_storage,
    sk_select_reuseport,
    skb_ancestor_cgroup_id,
    sk_lookup_tcp,
    sk_lookup_udp,
    sk_release,
    map_push_elem,
    map_pop_elem,
    map_peek_elem,
    msg_push_data,
    msg_pop_data,
    rc_pointer_rel,
    spin_lock,
    spin_unlock,
    sk_fullsock,
    tcp_sock,
    skb_ecn_set_ce,
    get_listener_sock,
    skc_lookup_tcp,
    tcp_check_syncookie,
    sysctl_get_name,
    sysctl_get_current_value,
    sysctl_get_new_value,
    sysctl_set_new_value,
    strtol,
    strtoul,
    sk_storage_get,
    sk_storage_delete,
    send_signal,
    tcp_gen_syncookie,
    skb_output,
    probe_read_user,
    probe_read_kernel,
    probe_read_user_str,
    probe_read_kernel_str,
    tcp_send_ack,
    send_signal_thread,
    jiffies64,
    read_branch_records,
    get_ns_current_pid_tgid,
    xdp_output,
    get_netns_cookie,
    get_current_ancestor_cgroup_id,
    sk_assign,
    ktime_get_boot_ns,
    seq_printf,
    seq_write,
    sk_cgroup_id,
    sk_ancestor_cgroup_id,
    ringbuf_output,
    ringbuf_reserve,
    ringbuf_submit,
    ringbuf_discard,
    ringbuf_query,
    csum_level,
    skc_to_tcp6_sock,
    skc_to_tcp_sock,
    skc_to_tcp_timewait_sock,
    skc_to_tcp_request_sock,
    skc_to_udp6_sock,
    get_task_stack,
    _,
};

// TODO: determine that this is the expected bit layout for both little and big
// endian systems
/// a single BPF instruction
pub const Insn = packed struct {
    code: u8,
    dst: u4,
    src: u4,
    off: i16,
    imm: i32,

    /// r0 - r9 are general purpose 64-bit registers, r10 points to the stack
    /// frame
    pub const Reg = enum(u4) { r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10 };
    const Source = enum(u1) { reg, imm };

    const Mode = enum(u8) {
        imm = IMM,
        abs = ABS,
        ind = IND,
        mem = MEM,
        len = LEN,
        msh = MSH,
    };

    pub const AluOp = enum(u8) {
        add = ADD,
        sub = SUB,
        mul = MUL,
        div = DIV,
        alu_or = OR,
        alu_and = AND,
        lsh = LSH,
        rsh = RSH,
        neg = NEG,
        mod = MOD,
        xor = XOR,
        mov = MOV,
        arsh = ARSH,
    };

    pub const Size = enum(u8) {
        byte = B,
        half_word = H,
        word = W,
        double_word = DW,
    };

    pub const JmpOp = enum(u8) {
        ja = JA,
        jeq = JEQ,
        jgt = JGT,
        jge = JGE,
        jset = JSET,
        jlt = JLT,
        jle = JLE,
        jne = JNE,
        jsgt = JSGT,
        jsge = JSGE,
        jslt = JSLT,
        jsle = JSLE,
    };

    const ImmOrReg = union(Source) {
        reg: Reg,
        imm: i32,
    };

    fn imm_reg(code: u8, dst: Reg, src: anytype, off: i16) Insn {
        const imm_or_reg = if (@TypeOf(src) == Reg or @typeInfo(@TypeOf(src)) == .enum_literal)
            ImmOrReg{ .reg = @as(Reg, src) }
        else
            ImmOrReg{ .imm = src };

        const src_type: u8 = switch (imm_or_reg) {
            .imm => K,
            .reg => X,
        };

        return Insn{
            .code = code | src_type,
            .dst = @intFromEnum(dst),
            .src = switch (imm_or_reg) {
                .imm => 0,
                .reg => |r| @intFromEnum(r),
            },
            .off = off,
            .imm = switch (imm_or_reg) {
                .imm => |i| i,
                .reg => 0,
            },
        };
    }

    pub fn alu(comptime width: comptime_int, op: AluOp, dst: Reg, src: anytype) Insn {
        const width_bitfield = switch (width) {
            32 => ALU,
            64 => ALU64,
            else => @compileError("width must be 32 or 64"),
        };

        return imm_reg(width_bitfield | @intFromEnum(op), dst, src, 0);
    }

    pub fn mov(dst: Reg, src: anytype) Insn {
        return alu(64, .mov, dst, src);
    }

    pub fn add(dst: Reg, src: anytype) Insn {
        return alu(64, .add, dst, src);
    }

    pub fn sub(dst: Reg, src: anytype) Insn {
        return alu(64, .sub, dst, src);
    }

    pub fn mul(dst: Reg, src: anytype) Insn {
        return alu(64, .mul, dst, src);
    }

    pub fn div(dst: Reg, src: anytype) Insn {
        return alu(64, .div, dst, src);
    }

    pub fn alu_or(dst: Reg, src: anytype) Insn {
        return alu(64, .alu_or, dst, src);
    }

    pub fn alu_and(dst: Reg, src: anytype) Insn {
        return alu(64, .alu_and, dst, src);
    }

    pub fn lsh(dst: Reg, src: anytype) Insn {
        return alu(64, .lsh, dst, src);
    }

    pub fn rsh(dst: Reg, src: anytype) Insn {
        return alu(64, .rsh, dst, src);
    }

    pub fn neg(dst: Reg) Insn {
        return alu(64, .neg, dst, 0);
    }

    pub fn mod(dst: Reg, src: anytype) Insn {
        return alu(64, .mod, dst, src);
    }

    pub fn xor(dst: Reg, src: anytype) Insn {
        return alu(64, .xor, dst, src);
    }

    pub fn arsh(dst: Reg, src: anytype) Insn {
        return alu(64, .arsh, dst, src);
    }

    pub fn jmp(op: JmpOp, dst: Reg, src: anytype, off: i16) Insn {
        return imm_reg(JMP | @intFromEnum(op), dst, src, off);
    }

    pub fn ja(off: i16) Insn {
        return jmp(.ja, .r0, 0, off);
    }

    pub fn jeq(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jeq, dst, src, off);
    }

    pub fn jgt(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jgt, dst, src, off);
    }

    pub fn jge(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jge, dst, src, off);
    }

    pub fn jlt(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jlt, dst, src, off);
    }

    pub fn jle(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jle, dst, src, off);
    }

    pub fn jset(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jset, dst, src, off);
    }

    pub fn jne(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jne, dst, src, off);
    }

    pub fn jsgt(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jsgt, dst, src, off);
    }

    pub fn jsge(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jsge, dst, src, off);
    }

    pub fn jslt(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jslt, dst, src, off);
    }

    pub fn jsle(dst: Reg, src: anytype, off: i16) Insn {
        return jmp(.jsle, dst, src, off);
    }

    pub fn xadd(dst: Reg, src: Reg) Insn {
        return Insn{
            .code = STX | XADD | DW,
            .dst = @intFromEnum(dst),
            .src = @intFromEnum(src),
            .off = 0,
            .imm = 0,
        };
    }

    fn ld(mode: Mode, size: Size, dst: Reg, src: Reg, imm: i32) Insn {
        return Insn{
            .code = @intFromEnum(mode) | @intFromEnum(size) | LD,
            .dst = @intFromEnum(dst),
            .src = @intFromEnum(src),
            .off = 0,
            .imm = imm,
        };
    }

    pub fn ld_abs(size: Size, dst: Reg, src: Reg, imm: i32) Insn {
        return ld(.abs, size, dst, src, imm);
    }

    pub fn ld_ind(size: Size, dst: Reg, src: Reg, imm: i32) Insn {
        return ld(.ind, size, dst, src, imm);
    }

    pub fn ldx(size: Size, dst: Reg, src: Reg, off: i16) Insn {
        return Insn{
            .code = MEM | @intFromEnum(size) | LDX,
            .dst = @intFromEnum(dst),
            .src = @intFromEnum(src),
            .off = off,
            .imm = 0,
        };
    }

    fn ld_imm_impl1(dst: Reg, src: Reg, imm: u64) Insn {
        return Insn{
            .code = LD | DW | IMM,
            .dst = @intFromEnum(dst),
            .src = @intFromEnum(src),
            .off = 0,
            .imm = @as(i32, @intCast(@as(u32, @truncate(imm)))),
        };
    }

    fn ld_imm_impl2(imm: u64) Insn {
        return Insn{
            .code = 0,
            .dst = 0,
            .src = 0,
            .off = 0,
            .imm = @as(i32, @intCast(@as(u32, @truncate(imm >> 32)))),
        };
    }

    pub fn ld_dw1(dst: Reg, imm: u64) Insn {
        return ld_imm_impl1(dst, .r0, imm);
    }

    pub fn ld_dw2(imm: u64) Insn {
        return ld_imm_impl2(imm);
    }

    pub fn ld_map_fd1(dst: Reg, map_fd: fd_t) Insn {
        return ld_imm_impl1(dst, @as(Reg, @enumFromInt(PSEUDO_MAP_FD)), @as(u64, @intCast(map_fd)));
    }

    pub fn ld_map_fd2(map_fd: fd_t) Insn {
        return ld_imm_impl2(@as(u64, @intCast(map_fd)));
    }

    pub fn st(size: Size, dst: Reg, off: i16, imm: i32) Insn {
        return Insn{
            .code = MEM | @intFromEnum(size) | ST,
            .dst = @intFromEnum(dst),
            .src = 0,
            .off = off,
            .imm = imm,
        };
    }

    pub fn stx(size: Size, dst: Reg, off: i16, src: Reg) Insn {
        return Insn{
            .code = MEM | @intFromEnum(size) | STX,
            .dst = @intFromEnum(dst),
            .src = @intFromEnum(src),
            .off = off,
            .imm = 0,
        };
    }

    fn endian_swap(endian: std.builtin.Endian, comptime size: Size, dst: Reg) Insn {
        return Insn{
            .code = switch (endian) {
                .big => 0xdc,
                .little => 0xd4,
            },
            .dst = @intFromEnum(dst),
            .src = 0,
            .off = 0,
            .imm = switch (size) {
                .byte => @compileError("can't swap a single byte"),
                .half_word => 16,
                .word => 32,
                .double_word => 64,
            },
        };
    }

    pub fn le(comptime size: Size, dst: Reg) Insn {
        return endian_swap(.little, size, dst);
    }

    pub fn be(comptime size: Size, dst: Reg) Insn {
        return endian_swap(.big, size, dst);
    }

    pub fn call(helper: Helper) Insn {
        return Insn{
            .code = JMP | CALL,
            .dst = 0,
            .src = 0,
            .off = 0,
            .imm = @intFromEnum(helper),
        };
    }

    /// exit BPF program
    pub fn exit() Insn {
        return Insn{
            .code = JMP | EXIT,
            .dst = 0,
            .src = 0,
            .off = 0,
            .imm = 0,
        };
    }
};

test "insn bitsize" {
    try expectEqual(@bitSizeOf(Insn), 64);
}

fn expect_opcode(code: u8, insn: Insn) !void {
    try expectEqual(code, insn.code);
}

// The opcodes were grabbed from https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
test "opcodes" {
    // instructions that have a name that end with 1 or 2 are consecutive for
    // loading 64-bit immediates (imm is only 32 bits wide)

    // alu instructions
    try expect_opcode(0x07, Insn.add(.r1, 0));
    try expect_opcode(0x0f, Insn.add(.r1, .r2));
    try expect_opcode(0x17, Insn.sub(.r1, 0));
    try expect_opcode(0x1f, Insn.sub(.r1, .r2));
    try expect_opcode(0x27, Insn.mul(.r1, 0));
    try expect_opcode(0x2f, Insn.mul(.r1, .r2));
    try expect_opcode(0x37, Insn.div(.r1, 0));
    try expect_opcode(0x3f, Insn.div(.r1, .r2));
    try expect_opcode(0x47, Insn.alu_or(.r1, 0));
    try expect_opcode(0x4f, Insn.alu_or(.r1, .r2));
    try expect_opcode(0x57, Insn.alu_and(.r1, 0));
    try expect_opcode(0x5f, Insn.alu_and(.r1, .r2));
    try expect_opcode(0x67, Insn.lsh(.r1, 0));
    try expect_opcode(0x6f, Insn.lsh(.r1, .r2));
    try expect_opcode(0x77, Insn.rsh(.r1, 0));
    try expect_opcode(0x7f, Insn.rsh(.r1, .r2));
    try expect_opcode(0x87, Insn.neg(.r1));
    try expect_opcode(0x97, Insn.mod(.r1, 0));
    try expect_opcode(0x9f, Insn.mod(.r1, .r2));
    try expect_opcode(0xa7, Insn.xor(.r1, 0));
    try expect_opcode(0xaf, Insn.xor(.r1, .r2));
    try expect_opcode(0xb7, Insn.mov(.r1, 0));
    try expect_opcode(0xbf, Insn.mov(.r1, .r2));
    try expect_opcode(0xc7, Insn.arsh(.r1, 0));
    try expect_opcode(0xcf, Insn.arsh(.r1, .r2));

    // atomic instructions: might be more of these not documented in the wild
    try expect_opcode(0xdb, Insn.xadd(.r1, .r2));

    // TODO: byteswap instructions
    try expect_opcode(0xd4, Insn.le(.half_word, .r1));
    try expectEqual(@as(i32, @intCast(16)), Insn.le(.half_word, .r1).imm);
    try expect_opcode(0xd4, Insn.le(.word, .r1));
    try expectEqual(@as(i32, @intCast(32)), Insn.le(.word, .r1).imm);
    try expect_opcode(0xd4, Insn.le(.double_word, .r1));
    try expectEqual(@as(i32, @intCast(64)), Insn.le(.double_word, .r1).imm);
    try expect_opcode(0xdc, Insn.be(.half_word, .r1));
    try expectEqual(@as(i32, @intCast(16)), Insn.be(.half_word, .r1).imm);
    try expect_opcode(0xdc, Insn.be(.word, .r1));
    try expectEqual(@as(i32, @intCast(32)), Insn.be(.word, .r1).imm);
    try expect_opcode(0xdc, Insn.be(.double_word, .r1));
    try expectEqual(@as(i32, @intCast(64)), Insn.be(.double_word, .r1).imm);

    // memory instructions
    try expect_opcode(0x18, Insn.ld_dw1(.r1, 0));
    try expect_opcode(0x00, Insn.ld_dw2(0));

    //   loading a map fd
    try expect_opcode(0x18, Insn.ld_map_fd1(.r1, 0));
    try expectEqual(@as(u4, @intCast(PSEUDO_MAP_FD)), Insn.ld_map_fd1(.r1, 0).src);
    try expect_opcode(0x00, Insn.ld_map_fd2(0));

    try expect_opcode(0x38, Insn.ld_abs(.double_word, .r1, .r2, 0));
    try expect_opcode(0x20, Insn.ld_abs(.word, .r1, .r2, 0));
    try expect_opcode(0x28, Insn.ld_abs(.half_word, .r1, .r2, 0));
    try expect_opcode(0x30, Insn.ld_abs(.byte, .r1, .r2, 0));

    try expect_opcode(0x58, Insn.ld_ind(.double_word, .r1, .r2, 0));
    try expect_opcode(0x40, Insn.ld_ind(.word, .r1, .r2, 0));
    try expect_opcode(0x48, Insn.ld_ind(.half_word, .r1, .r2, 0));
    try expect_opcode(0x50, Insn.ld_ind(.byte, .r1, .r2, 0));

    try expect_opcode(0x79, Insn.ldx(.double_word, .r1, .r2, 0));
    try expect_opcode(0x61, Insn.ldx(.word, .r1, .r2, 0));
    try expect_opcode(0x69, Insn.ldx(.half_word, .r1, .r2, 0));
    try expect_opcode(0x71, Insn.ldx(.byte, .r1, .r2, 0));

    try expect_opcode(0x62, Insn.st(.word, .r1, 0, 0));
    try expect_opcode(0x6a, Insn.st(.half_word, .r1, 0, 0));
    try expect_opcode(0x72, Insn.st(.byte, .r1, 0, 0));

    try expect_opcode(0x63, Insn.stx(.word, .r1, 0, .r2));
    try expect_opcode(0x6b, Insn.stx(.half_word, .r1, 0, .r2));
    try expect_opcode(0x73, Insn.stx(.byte, .r1, 0, .r2));
    try expect_opcode(0x7b, Insn.stx(.double_word, .r1, 0, .r2));

    // branch instructions
    try expect_opcode(0x05, Insn.ja(0));
    try expect_opcode(0x15, Insn.jeq(.r1, 0, 0));
    try expect_opcode(0x1d, Insn.jeq(.r1, .r2, 0));
    try expect_opcode(0x25, Insn.jgt(.r1, 0, 0));
    try expect_opcode(0x2d, Insn.jgt(.r1, .r2, 0));
    try expect_opcode(0x35, Insn.jge(.r1, 0, 0));
    try expect_opcode(0x3d, Insn.jge(.r1, .r2, 0));
    try expect_opcode(0xa5, Insn.jlt(.r1, 0, 0));
    try expect_opcode(0xad, Insn.jlt(.r1, .r2, 0));
    try expect_opcode(0xb5, Insn.jle(.r1, 0, 0));
    try expect_opcode(0xbd, Insn.jle(.r1, .r2, 0));
    try expect_opcode(0x45, Insn.jset(.r1, 0, 0));
    try expect_opcode(0x4d, Insn.jset(.r1, .r2, 0));
    try expect_opcode(0x55, Insn.jne(.r1, 0, 0));
    try expect_opcode(0x5d, Insn.jne(.r1, .r2, 0));
    try expect_opcode(0x65, Insn.jsgt(.r1, 0, 0));
    try expect_opcode(0x6d, Insn.jsgt(.r1, .r2, 0));
    try expect_opcode(0x75, Insn.jsge(.r1, 0, 0));
    try expect_opcode(0x7d, Insn.jsge(.r1, .r2, 0));
    try expect_opcode(0xc5, Insn.jslt(.r1, 0, 0));
    try expect_opcode(0xcd, Insn.jslt(.r1, .r2, 0));
    try expect_opcode(0xd5, Insn.jsle(.r1, 0, 0));
    try expect_opcode(0xdd, Insn.jsle(.r1, .r2, 0));
    try expect_opcode(0x85, Insn.call(.unspec));
    try expect_opcode(0x95, Insn.exit());
}

pub const Cmd = enum(usize) {
    /// Create  a map and return a file descriptor that refers to the map. The
    /// close-on-exec file descriptor flag is automatically enabled for the new
    /// file descriptor.
    ///
    /// uses MapCreateAttr
    map_create,

    /// Look up an element by key in a specified map and return its value.
    ///
    /// uses MapElemAttr
    map_lookup_elem,

    /// Create or update an element (key/value pair) in a specified map.
    ///
    /// uses MapElemAttr
    map_update_elem,

    /// Look up and delete an element by key in a specified map.
    ///
    /// uses MapElemAttr
    map_delete_elem,

    /// Look up an element by key in a specified map and return the key of the
    /// next element.
    map_get_next_key,

    /// Verify and load an eBPF program, returning a new file descriptor
    /// associated with the program. The close-on-exec file descriptor flag
    /// is automatically enabled for the new file descriptor.
    ///
    /// uses ProgLoadAttr
    prog_load,

    /// Pin a map or eBPF program to a path within the minimal BPF filesystem
    ///
    /// uses ObjAttr
    obj_pin,

    /// Get the file descriptor of a BPF object pinned to a certain path
    ///
    /// uses ObjAttr
    obj_get,

    /// uses ProgAttachAttr
    prog_attach,

    /// uses ProgAttachAttr
    prog_detach,

    /// uses TestRunAttr
    prog_test_run,

    /// uses GetIdAttr
    prog_get_next_id,

    /// uses GetIdAttr
    map_get_next_id,

    /// uses GetIdAttr
    prog_get_fd_by_id,

    /// uses GetIdAttr
    map_get_fd_by_id,

    /// uses InfoAttr
    obj_get_info_by_fd,

    /// uses QueryAttr
    prog_query,

    /// uses RawTracepointAttr
    raw_tracepoint_open,

    /// uses BtfLoadAttr
    btf_load,

    /// uses GetIdAttr
    btf_get_fd_by_id,

    /// uses TaskFdQueryAttr
    task_fd_query,

    /// uses MapElemAttr
    map_lookup_and_delete_elem,
    map_freeze,

    /// uses GetIdAttr
    btf_get_next_id,

    /// uses MapBatchAttr
    map_lookup_batch,

    /// uses MapBatchAttr
    map_lookup_and_delete_batch,

    /// uses MapBatchAttr
    map_update_batch,

    /// uses MapBatchAttr
    map_delete_batch,

    /// uses LinkCreateAttr
    link_create,

    /// uses LinkUpdateAttr
    link_update,

    /// uses GetIdAttr
    link_get_fd_by_id,

    /// uses GetIdAttr
    link_get_next_id,

    /// uses EnableStatsAttr
    enable_stats,

    /// uses IterCreateAttr
    iter_create,
    link_detach,
    _,
};

pub const MapType = enum(u32) {
    unspec,
    hash,
    array,
    prog_array,
    perf_event_array,
    percpu_hash,
    percpu_array,
    stack_trace,
    cgroup_array,
    lru_hash,
    lru_percpu_hash,
    lpm_trie,
    array_of_maps,
    hash_of_maps,
    devmap,
    sockmap,
    cpumap,
    xskmap,
    sockhash,
    cgroup_storage_deprecated,
    reuseport_sockarray,
    percpu_cgroup_storage,
    queue,
    stack,
    sk_storage,
    devmap_hash,
    struct_ops,

    /// An ordered and shared CPU version of perf_event_array. They have
    /// similar semantics:
    ///     - variable length records
    ///     - no blocking: when full, reservation fails
    ///     - memory mappable for ease and speed
    ///     - epoll notifications for new data, but can busy poll
    ///
    /// Ringbufs give BPF programs two sets of APIs:
    ///     - ringbuf_output() allows copy data from one place to a ring
    ///     buffer, similar to bpf_perf_event_output()
    ///     - ringbuf_reserve()/ringbuf_commit()/ringbuf_discard() split the
    ///     process into two steps. First a fixed amount of space is reserved,
    ///     if that is successful then the program gets a pointer to a chunk of
    ///     memory and can be submitted with commit() or discarded with
    ///     discard()
    ///
    /// ringbuf_output() will incur an extra memory copy, but allows to submit
    /// records of the length that's not known beforehand, and is an easy
    /// replacement for perf_event_output().
    ///
    /// ringbuf_reserve() avoids the extra memory copy but requires a known size
    /// of memory beforehand.
    ///
    /// ringbuf_query() allows to query properties of the map, 4 are currently
    /// supported:
    ///     - BPF_RB_AVAIL_DATA: amount of unconsumed data in ringbuf
    ///     - BPF_RB_RING_SIZE: returns size of ringbuf
    ///     - BPF_RB_CONS_POS/BPF_RB_PROD_POS returns current logical position
    ///     of consumer and producer respectively
    ///
    /// key size: 0
    /// value size: 0
    /// max entries: size of ringbuf, must be power of 2
    ringbuf,
    inode_storage,
    task_storage,
    bloom_filter,
    user_ringbuf,
    cgroup_storage,
    arena,

    _,
};

pub const ProgType = enum(u32) {
    unspec,

    /// context type: __sk_buff
    socket_filter,

    /// context type: bpf_user_pt_regs_t
    kprobe,

    /// context type: __sk_buff
    sched_cls,

    /// context type: __sk_buff
    sched_act,

    /// context type: u64
    tracepoint,

    /// context type: xdp_md
    xdp,

    /// context type: bpf_perf_event_data
    perf_event,

    /// context type: __sk_buff
    cgroup_skb,

    /// context type: bpf_sock
    cgroup_sock,

    /// context type: __sk_buff
    lwt_in,

    /// context type: __sk_buff
    lwt_out,

    /// context type: __sk_buff
    lwt_xmit,

    /// context type: bpf_sock_ops
    sock_ops,

    /// context type: __sk_buff
    sk_skb,

    /// context type: bpf_cgroup_dev_ctx
    cgroup_device,

    /// context type: sk_msg_md
    sk_msg,

    /// context type: bpf_raw_tracepoint_args
    raw_tracepoint,

    /// context type: bpf_sock_addr
    cgroup_sock_addr,

    /// context type: __sk_buff
    lwt_seg6local,

    /// context type: u32
    lirc_mode2,

    /// context type: sk_reuseport_md
    sk_reuseport,

    /// context type: __sk_buff
    flow_dissector,

    /// context type: bpf_sysctl
    cgroup_sysctl,

    /// context type: bpf_raw_tracepoint_args
    raw_tracepoint_writable,

    /// context type: bpf_sockopt
    cgroup_sockopt,

    /// context type: void *
    tracing,

    /// context type: void *
    struct_ops,

    /// context type: void *
    ext,

    /// context type: void *
    lsm,

    /// context type: bpf_sk_lookup
    sk_lookup,

    /// context type: void *
    syscall,

    /// context type: bpf_nf_ctx
    netfilter,

    _,
};

pub const AttachType = enum(u32) {
    cgroup_inet_ingress,
    cgroup_inet_egress,
    cgroup_inet_sock_create,
    cgroup_sock_ops,
    sk_skb_stream_parser,
    sk_skb_stream_verdict,
    cgroup_device,
    sk_msg_verdict,
    cgroup_inet4_bind,
    cgroup_inet6_bind,
    cgroup_inet4_connect,
    cgroup_inet6_connect,
    cgroup_inet4_post_bind,
    cgroup_inet6_post_bind,
    cgroup_udp4_sendmsg,
    cgroup_udp6_sendmsg,
    lirc_mode2,
    flow_dissector,
    cgroup_sysctl,
    cgroup_udp4_recvmsg,
    cgroup_udp6_recvmsg,
    cgroup_getsockopt,
    cgroup_setsockopt,
    trace_raw_tp,
    trace_fentry,
    trace_fexit,
    modify_return,
    lsm_mac,
    trace_iter,
    cgroup_inet4_getpeername,
    cgroup_inet6_getpeername,
    cgroup_inet4_getsockname,
    cgroup_inet6_getsockname,
    xdp_devmap,
    cgroup_inet_sock_release,
    xdp_cpumap,
    sk_lookup,
    xdp,
    sk_skb_verdict,
    sk_reuseport_select,
    sk_reuseport_select_or_migrate,
    perf_event,
    trace_kprobe_multi,
    lsm_cgroup,
```
