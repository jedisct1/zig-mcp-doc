```
Int(0);
    pub const IGN: ?Sigaction.handler_fn = @ptrFromInt(1);
} else struct {
    pub const BLOCK = 0;
    pub const UNBLOCK = 1;
    pub const SETMASK = 2;

    pub const HUP = 1;
    pub const INT = 2;
    pub const QUIT = 3;
    pub const ILL = 4;
    pub const TRAP = 5;
    pub const ABRT = 6;
    pub const IOT = ABRT;
    pub const BUS = 7;
    pub const FPE = 8;
    pub const KILL = 9;
    pub const USR1 = 10;
    pub const SEGV = 11;
    pub const USR2 = 12;
    pub const PIPE = 13;
    pub const ALRM = 14;
    pub const TERM = 15;
    pub const STKFLT = 16;
    pub const CHLD = 17;
    pub const CONT = 18;
    pub const STOP = 19;
    pub const TSTP = 20;
    pub const TTIN = 21;
    pub const TTOU = 22;
    pub const URG = 23;
    pub const XCPU = 24;
    pub const XFSZ = 25;
    pub const VTALRM = 26;
    pub const PROF = 27;
    pub const WINCH = 28;
    pub const IO = 29;
    pub const POLL = 29;
    pub const PWR = 30;
    pub const SYS = 31;
    pub const UNUSED = SIG.SYS;

    pub const ERR: ?Sigaction.handler_fn = @ptrFromInt(maxInt(usize));
    pub const DFL: ?Sigaction.handler_fn = @ptrFromInt(0);
    pub const IGN: ?Sigaction.handler_fn = @ptrFromInt(1);
};

pub const kernel_rwf = u32;

pub const RWF = struct {
    pub const HIPRI: kernel_rwf = 0x00000001;
    pub const DSYNC: kernel_rwf = 0x00000002;
    pub const SYNC: kernel_rwf = 0x00000004;
    pub const NOWAIT: kernel_rwf = 0x00000008;
    pub const APPEND: kernel_rwf = 0x00000010;
};

pub const SEEK = struct {
    pub const SET = 0;
    pub const CUR = 1;
    pub const END = 2;
};

pub const SHUT = struct {
    pub const RD = 0;
    pub const WR = 1;
    pub const RDWR = 2;
};

pub const SOCK = struct {
    pub const STREAM = if (is_mips) 2 else 1;
    pub const DGRAM = if (is_mips) 1 else 2;
    pub const RAW = 3;
    pub const RDM = 4;
    pub const SEQPACKET = 5;
    pub const DCCP = 6;
    pub const PACKET = 10;
    pub const CLOEXEC = if (is_sparc) 0o20000000 else 0o2000000;
    pub const NONBLOCK = if (is_mips) 0o200 else if (is_sparc) 0o40000 else 0o4000;
};

pub const TCP = struct {
    /// Turn off Nagle's algorithm
    pub const NODELAY = 1;
    /// Limit MSS
    pub const MAXSEG = 2;
    /// Never send partially complete segments.
    pub const CORK = 3;
    /// Start keeplives after this period, in seconds
    pub const KEEPIDLE = 4;
    /// Interval between keepalives
    pub const KEEPINTVL = 5;
    /// Number of keepalives before death
    pub const KEEPCNT = 6;
    /// Number of SYN retransmits
    pub const SYNCNT = 7;
    /// Life time of orphaned FIN-WAIT-2 state
    pub const LINGER2 = 8;
    /// Wake up listener only when data arrive
    pub const DEFER_ACCEPT = 9;
    /// Bound advertised window
    pub const WINDOW_CLAMP = 10;
    /// Information about this connection.
    pub const INFO = 11;
    /// Block/reenable quick acks
    pub const QUICKACK = 12;
    /// Congestion control algorithm
    pub const CONGESTION = 13;
    /// TCP MD5 Signature (RFC2385)
    pub const MD5SIG = 14;
    /// Use linear timeouts for thin streams
    pub const THIN_LINEAR_TIMEOUTS = 16;
    /// Fast retrans. after 1 dupack
    pub const THIN_DUPACK = 17;
    /// How long for loss retry before timeout
    pub const USER_TIMEOUT = 18;
    /// TCP sock is under repair right now
    pub const REPAIR = 19;
    pub const REPAIR_QUEUE = 20;
    pub const QUEUE_SEQ = 21;
    pub const REPAIR_OPTIONS = 22;
    /// Enable FastOpen on listeners
    pub const FASTOPEN = 23;
    pub const TIMESTAMP = 24;
    /// limit number of unsent bytes in write queue
    pub const NOTSENT_LOWAT = 25;
    /// Get Congestion Control (optional) info
    pub const CC_INFO = 26;
    /// Record SYN headers for new connections
    pub const SAVE_SYN = 27;
    /// Get SYN headers recorded for connection
    pub const SAVED_SYN = 28;
    /// Get/set window parameters
    pub const REPAIR_WINDOW = 29;
    /// Attempt FastOpen with connect
    pub const FASTOPEN_CONNECT = 30;
    /// Attach a ULP to a TCP connection
    pub const ULP = 31;
    /// TCP MD5 Signature with extensions
    pub const MD5SIG_EXT = 32;
    /// Set the key for Fast Open (cookie)
    pub const FASTOPEN_KEY = 33;
    /// Enable TFO without a TFO cookie
    pub const FASTOPEN_NO_COOKIE = 34;
    pub const ZEROCOPY_RECEIVE = 35;
    /// Notify bytes available to read as a cmsg on read
    pub const INQ = 36;
    pub const CM_INQ = INQ;
    /// delay outgoing packets by XX usec
    pub const TX_DELAY = 37;

    pub const REPAIR_ON = 1;
    pub const REPAIR_OFF = 0;
    /// Turn off without window probes
    pub const REPAIR_OFF_NO_WP = -1;
};

pub const UDP = struct {
    /// Never send partially complete segments
    pub const CORK = 1;
    /// Set the socket to accept encapsulated packets
    pub const ENCAP = 100;
    /// Disable sending checksum for UDP6X
    pub const NO_CHECK6_TX = 101;
    /// Disable accepting checksum for UDP6
    pub const NO_CHECK6_RX = 102;
    /// Set GSO segmentation size
    pub const SEGMENT = 103;
    /// This socket can receive UDP GRO packets
    pub const GRO = 104;
};

pub const UDP_ENCAP = struct {
    pub const ESPINUDP_NON_IKE = 1;
    pub const ESPINUDP = 2;
    pub const L2TPINUDP = 3;
    pub const GTP0 = 4;
    pub const GTP1U = 5;
    pub const RXRPC = 6;
};

pub const PF = struct {
    pub const UNSPEC = 0;
    pub const LOCAL = 1;
    pub const UNIX = LOCAL;
    pub const FILE = LOCAL;
    pub const INET = 2;
    pub const AX25 = 3;
    pub const IPX = 4;
    pub const APPLETALK = 5;
    pub const NETROM = 6;
    pub const BRIDGE = 7;
    pub const ATMPVC = 8;
    pub const X25 = 9;
    pub const INET6 = 10;
    pub const ROSE = 11;
    pub const DECnet = 12;
    pub const NETBEUI = 13;
    pub const SECURITY = 14;
    pub const KEY = 15;
    pub const NETLINK = 16;
    pub const ROUTE = PF.NETLINK;
    pub const PACKET = 17;
    pub const ASH = 18;
    pub const ECONET = 19;
    pub const ATMSVC = 20;
    pub const RDS = 21;
    pub const SNA = 22;
    pub const IRDA = 23;
    pub const PPPOX = 24;
    pub const WANPIPE = 25;
    pub const LLC = 26;
    pub const IB = 27;
    pub const MPLS = 28;
    pub const CAN = 29;
    pub const TIPC = 30;
    pub const BLUETOOTH = 31;
    pub const IUCV = 32;
    pub const RXRPC = 33;
    pub const ISDN = 34;
    pub const PHONET = 35;
    pub const IEEE802154 = 36;
    pub const CAIF = 37;
    pub const ALG = 38;
    pub const NFC = 39;
    pub const VSOCK = 40;
    pub const KCM = 41;
    pub const QIPCRTR = 42;
    pub const SMC = 43;
    pub const XDP = 44;
    pub const MAX = 45;
};

pub const AF = struct {
    pub const UNSPEC = PF.UNSPEC;
    pub const LOCAL = PF.LOCAL;
    pub const UNIX = AF.LOCAL;
    pub const FILE = AF.LOCAL;
    pub const INET = PF.INET;
    pub const AX25 = PF.AX25;
    pub const IPX = PF.IPX;
    pub const APPLETALK = PF.APPLETALK;
    pub const NETROM = PF.NETROM;
    pub const BRIDGE = PF.BRIDGE;
    pub const ATMPVC = PF.ATMPVC;
    pub const X25 = PF.X25;
    pub const INET6 = PF.INET6;
    pub const ROSE = PF.ROSE;
    pub const DECnet = PF.DECnet;
    pub const NETBEUI = PF.NETBEUI;
    pub const SECURITY = PF.SECURITY;
    pub const KEY = PF.KEY;
    pub const NETLINK = PF.NETLINK;
    pub const ROUTE = PF.ROUTE;
    pub const PACKET = PF.PACKET;
    pub const ASH = PF.ASH;
    pub const ECONET = PF.ECONET;
    pub const ATMSVC = PF.ATMSVC;
    pub const RDS = PF.RDS;
    pub const SNA = PF.SNA;
    pub const IRDA = PF.IRDA;
    pub const PPPOX = PF.PPPOX;
    pub const WANPIPE = PF.WANPIPE;
    pub const LLC = PF.LLC;
    pub const IB = PF.IB;
    pub const MPLS = PF.MPLS;
    pub const CAN = PF.CAN;
    pub const TIPC = PF.TIPC;
    pub const BLUETOOTH = PF.BLUETOOTH;
    pub const IUCV = PF.IUCV;
    pub const RXRPC = PF.RXRPC;
    pub const ISDN = PF.ISDN;
    pub const PHONET = PF.PHONET;
    pub const IEEE802154 = PF.IEEE802154;
    pub const CAIF = PF.CAIF;
    pub const ALG = PF.ALG;
    pub const NFC = PF.NFC;
    pub const VSOCK = PF.VSOCK;
    pub const KCM = PF.KCM;
    pub const QIPCRTR = PF.QIPCRTR;
    pub const SMC = PF.SMC;
    pub const XDP = PF.XDP;
    pub const MAX = PF.MAX;
};

pub const SO = if (is_mips) struct {
    pub const DEBUG = 1;
    pub const REUSEADDR = 0x0004;
    pub const KEEPALIVE = 0x0008;
    pub const DONTROUTE = 0x0010;
    pub const BROADCAST = 0x0020;
    pub const LINGER = 0x0080;
    pub const OOBINLINE = 0x0100;
    pub const REUSEPORT = 0x0200;
    pub const SNDBUF = 0x1001;
    pub const RCVBUF = 0x1002;
    pub const SNDLOWAT = 0x1003;
    pub const RCVLOWAT = 0x1004;
    pub const RCVTIMEO = 0x1006;
    pub const SNDTIMEO = 0x1005;
    pub const ERROR = 0x1007;
    pub const TYPE = 0x1008;
    pub const ACCEPTCONN = 0x1009;
    pub const PROTOCOL = 0x1028;
    pub const DOMAIN = 0x1029;
    pub const NO_CHECK = 11;
    pub const PRIORITY = 12;
    pub const BSDCOMPAT = 14;
    pub const PASSCRED = 17;
    pub const PEERCRED = 18;
    pub const PEERSEC = 30;
    pub const SNDBUFFORCE = 31;
    pub const RCVBUFFORCE = 33;
    pub const SECURITY_AUTHENTICATION = 22;
    pub const SECURITY_ENCRYPTION_TRANSPORT = 23;
    pub const SECURITY_ENCRYPTION_NETWORK = 24;
    pub const BINDTODEVICE = 25;
    pub const ATTACH_FILTER = 26;
    pub const DETACH_FILTER = 27;
    pub const GET_FILTER = ATTACH_FILTER;
    pub const PEERNAME = 28;
    pub const TIMESTAMP_OLD = 29;
    pub const PASSSEC = 34;
    pub const TIMESTAMPNS_OLD = 35;
    pub const MARK = 36;
    pub const TIMESTAMPING_OLD = 37;
    pub const RXQ_OVFL = 40;
    pub const WIFI_STATUS = 41;
    pub const PEEK_OFF = 42;
    pub const NOFCS = 43;
    pub const LOCK_FILTER = 44;
    pub const SELECT_ERR_QUEUE = 45;
    pub const BUSY_POLL = 46;
    pub const MAX_PACING_RATE = 47;
    pub const BPF_EXTENSIONS = 48;
    pub const INCOMING_CPU = 49;
    pub const ATTACH_BPF = 50;
    pub const DETACH_BPF = DETACH_FILTER;
    pub const ATTACH_REUSEPORT_CBPF = 51;
    pub const ATTACH_REUSEPORT_EBPF = 52;
    pub const CNX_ADVICE = 53;
    pub const MEMINFO = 55;
    pub const INCOMING_NAPI_ID = 56;
    pub const COOKIE = 57;
    pub const PEERGROUPS = 59;
    pub const ZEROCOPY = 60;
    pub const TXTIME = 61;
    pub const BINDTOIFINDEX = 62;
    pub const TIMESTAMP_NEW = 63;
    pub const TIMESTAMPNS_NEW = 64;
    pub const TIMESTAMPING_NEW = 65;
    pub const RCVTIMEO_NEW = 66;
    pub const SNDTIMEO_NEW = 67;
    pub const DETACH_REUSEPORT_BPF = 68;
} else if (is_ppc) struct {
    pub const DEBUG = 1;
    pub const REUSEADDR = 2;
    pub const TYPE = 3;
    pub const ERROR = 4;
    pub const DONTROUTE = 5;
    pub const BROADCAST = 6;
    pub const SNDBUF = 7;
    pub const RCVBUF = 8;
    pub const KEEPALIVE = 9;
    pub const OOBINLINE = 10;
    pub const NO_CHECK = 11;
    pub const PRIORITY = 12;
    pub const LINGER = 13;
    pub const BSDCOMPAT = 14;
    pub const REUSEPORT = 15;
    pub const RCVLOWAT = 16;
    pub const SNDLOWAT = 17;
    pub const RCVTIMEO = 18;
    pub const SNDTIMEO = 19;
    pub const PASSCRED = 20;
    pub const PEERCRED = 21;
    pub const ACCEPTCONN = 30;
    pub const PEERSEC = 31;
    pub const SNDBUFFORCE = 32;
    pub const RCVBUFFORCE = 33;
    pub const PROTOCOL = 38;
    pub const DOMAIN = 39;
    pub const SECURITY_AUTHENTICATION = 22;
    pub const SECURITY_ENCRYPTION_TRANSPORT = 23;
    pub const SECURITY_ENCRYPTION_NETWORK = 24;
    pub const BINDTODEVICE = 25;
    pub const ATTACH_FILTER = 26;
    pub const DETACH_FILTER = 27;
    pub const GET_FILTER = ATTACH_FILTER;
    pub const PEERNAME = 28;
    pub const TIMESTAMP_OLD = 29;
    pub const PASSSEC = 34;
    pub const TIMESTAMPNS_OLD = 35;
    pub const MARK = 36;
    pub const TIMESTAMPING_OLD = 37;
    pub const RXQ_OVFL = 40;
    pub const WIFI_STATUS = 41;
    pub const PEEK_OFF = 42;
    pub const NOFCS = 43;
    pub const LOCK_FILTER = 44;
    pub const SELECT_ERR_QUEUE = 45;
    pub const BUSY_POLL = 46;
    pub const MAX_PACING_RATE = 47;
    pub const BPF_EXTENSIONS = 48;
    pub const INCOMING_CPU = 49;
    pub const ATTACH_BPF = 50;
    pub const DETACH_BPF = DETACH_FILTER;
    pub const ATTACH_REUSEPORT_CBPF = 51;
    pub const ATTACH_REUSEPORT_EBPF = 52;
    pub const CNX_ADVICE = 53;
    pub const MEMINFO = 55;
    pub const INCOMING_NAPI_ID = 56;
    pub const COOKIE = 57;
    pub const PEERGROUPS = 59;
    pub const ZEROCOPY = 60;
    pub const TXTIME = 61;
    pub const BINDTOIFINDEX = 62;
    pub const TIMESTAMP_NEW = 63;
    pub const TIMESTAMPNS_NEW = 64;
    pub const TIMESTAMPING_NEW = 65;
    pub const RCVTIMEO_NEW = 66;
    pub const SNDTIMEO_NEW = 67;
    pub const DETACH_REUSEPORT_BPF = 68;
} else if (is_sparc) struct {
    pub const DEBUG = 1;
    pub const REUSEADDR = 4;
    pub const TYPE = 4104;
    pub const ERROR = 4103;
    pub const DONTROUTE = 16;
    pub const BROADCAST = 32;
    pub const SNDBUF = 4097;
    pub const RCVBUF = 4098;
    pub const KEEPALIVE = 8;
    pub const OOBINLINE = 256;
    pub const NO_CHECK = 11;
    pub const PRIORITY = 12;
    pub const LINGER = 128;
    pub const BSDCOMPAT = 1024;
    pub const REUSEPORT = 512;
    pub const PASSCRED = 2;
    pub const PEERCRED = 64;
    pub const RCVLOWAT = 2048;
    pub const SNDLOWAT = 4096;
    pub const RCVTIMEO = 8192;
    pub const SNDTIMEO = 16384;
    pub const ACCEPTCONN = 32768;
    pub const PEERSEC = 30;
    pub const SNDBUFFORCE = 4106;
    pub const RCVBUFFORCE = 4107;
    pub const PROTOCOL = 4136;
    pub const DOMAIN = 4137;
    pub const SECURITY_AUTHENTICATION = 20481;
    pub const SECURITY_ENCRYPTION_TRANSPORT = 20482;
    pub const SECURITY_ENCRYPTION_NETWORK = 20484;
    pub const BINDTODEVICE = 13;
    pub const ATTACH_FILTER = 26;
    pub const DETACH_FILTER = 27;
    pub const GET_FILTER = 26;
    pub const PEERNAME = 28;
    pub const TIMESTAMP_OLD = 29;
    pub const PASSSEC = 31;
    pub const TIMESTAMPNS_OLD = 33;
    pub const MARK = 34;
    pub const TIMESTAMPING_OLD = 35;
    pub const RXQ_OVFL = 36;
    pub const WIFI_STATUS = 37;
    pub const PEEK_OFF = 38;
    pub const NOFCS = 39;
    pub const LOCK_FILTER = 40;
    pub const SELECT_ERR_QUEUE = 41;
    pub const BUSY_POLL = 48;
    pub const MAX_PACING_RATE = 49;
    pub const BPF_EXTENSIONS = 50;
    pub const INCOMING_CPU = 51;
    pub const ATTACH_BPF = 52;
    pub const DETACH_BPF = 27;
    pub const ATTACH_REUSEPORT_CBPF = 53;
    pub const ATTACH_REUSEPORT_EBPF = 54;
    pub const CNX_ADVICE = 55;
    pub const MEMINFO = 57;
    pub const INCOMING_NAPI_ID = 58;
    pub const COOKIE = 59;
    pub const PEERGROUPS = 61;
    pub const ZEROCOPY = 62;
    pub const TXTIME = 63;
    pub const BINDTOIFINDEX = 65;
    pub const TIMESTAMP_NEW = 70;
    pub const TIMESTAMPNS_NEW = 66;
    pub const TIMESTAMPING_NEW = 67;
    pub const RCVTIMEO_NEW = 68;
    pub const SNDTIMEO_NEW = 69;
    pub const DETACH_REUSEPORT_BPF = 71;
} else struct {
    pub const DEBUG = 1;
    pub const REUSEADDR = 2;
    pub const TYPE = 3;
    pub const ERROR = 4;
    pub const DONTROUTE = 5;
    pub const BROADCAST = 6;
    pub const SNDBUF = 7;
    pub const RCVBUF = 8;
    pub const KEEPALIVE = 9;
    pub const OOBINLINE = 10;
    pub const NO_CHECK = 11;
    pub const PRIORITY = 12;
    pub const LINGER = 13;
    pub const BSDCOMPAT = 14;
    pub const REUSEPORT = 15;
    pub const PASSCRED = 16;
    pub const PEERCRED = 17;
    pub const RCVLOWAT = 18;
    pub const SNDLOWAT = 19;
    pub const RCVTIMEO = 20;
    pub const SNDTIMEO = 21;
    pub const ACCEPTCONN = 30;
    pub const PEERSEC = 31;
    pub const SNDBUFFORCE = 32;
    pub const RCVBUFFORCE = 33;
    pub const PROTOCOL = 38;
    pub const DOMAIN = 39;
    pub const SECURITY_AUTHENTICATION = 22;
    pub const SECURITY_ENCRYPTION_TRANSPORT = 23;
    pub const SECURITY_ENCRYPTION_NETWORK = 24;
    pub const BINDTODEVICE = 25;
    pub const ATTACH_FILTER = 26;
    pub const DETACH_FILTER = 27;
    pub const GET_FILTER = ATTACH_FILTER;
    pub const PEERNAME = 28;
    pub const TIMESTAMP_OLD = 29;
    pub const PASSSEC = 34;
    pub const TIMESTAMPNS_OLD = 35;
    pub const MARK = 36;
    pub const TIMESTAMPING_OLD = 37;
    pub const RXQ_OVFL = 40;
    pub const WIFI_STATUS = 41;
    pub const PEEK_OFF = 42;
    pub const NOFCS = 43;
    pub const LOCK_FILTER = 44;
    pub const SELECT_ERR_QUEUE = 45;
    pub const BUSY_POLL = 46;
    pub const MAX_PACING_RATE = 47;
    pub const BPF_EXTENSIONS = 48;
    pub const INCOMING_CPU = 49;
    pub const ATTACH_BPF = 50;
    pub const DETACH_BPF = DETACH_FILTER;
    pub const ATTACH_REUSEPORT_CBPF = 51;
    pub const ATTACH_REUSEPORT_EBPF = 52;
    pub const CNX_ADVICE = 53;
    pub const MEMINFO = 55;
    pub const INCOMING_NAPI_ID = 56;
    pub const COOKIE = 57;
    pub const PEERGROUPS = 59;
    pub const ZEROCOPY = 60;
    pub const TXTIME = 61;
    pub const BINDTOIFINDEX = 62;
    pub const TIMESTAMP_NEW = 63;
    pub const TIMESTAMPNS_NEW = 64;
    pub const TIMESTAMPING_NEW = 65;
    pub const RCVTIMEO_NEW = 66;
    pub const SNDTIMEO_NEW = 67;
    pub const DETACH_REUSEPORT_BPF = 68;
};

pub const SCM = struct {
    pub const WIFI_STATUS = SO.WIFI_STATUS;
    pub const TIMESTAMPING_OPT_STATS = 54;
    pub const TIMESTAMPING_PKTINFO = 58;
    pub const TXTIME = SO.TXTIME;
};

pub const SOL = struct {
    pub const SOCKET = if (is_mips or is_sparc) 65535 else 1;

    pub const IP = 0;
    pub const IPV6 = 41;
    pub const ICMPV6 = 58;

    pub const RAW = 255;
    pub const DECNET = 261;
    pub const X25 = 262;
    pub const PACKET = 263;
    pub const ATM = 264;
    pub const AAL = 265;
    pub const IRDA = 266;
    pub const NETBEUI = 267;
    pub const LLC = 268;
    pub const DCCP = 269;
    pub const NETLINK = 270;
    pub const TIPC = 271;
    pub const RXRPC = 272;
    pub const PPPOL2TP = 273;
    pub const BLUETOOTH = 274;
    pub const PNPIPE = 275;
    pub const RDS = 276;
    pub const IUCV = 277;
    pub const CAIF = 278;
    pub const ALG = 279;
    pub const NFC = 280;
    pub const KCM = 281;
    pub const TLS = 282;
    pub const XDP = 283;
};

pub const SOMAXCONN = 128;

pub const IP = struct {
    pub const TOS = 1;
    pub const TTL = 2;
    pub const HDRINCL = 3;
    pub const OPTIONS = 4;
    pub const ROUTER_ALERT = 5;
    pub const RECVOPTS = 6;
    pub const RETOPTS = 7;
    pub const PKTINFO = 8;
    pub const PKTOPTIONS = 9;
    pub const PMTUDISC = 10;
    pub const MTU_DISCOVER = 10;
    pub const RECVERR = 11;
    pub const RECVTTL = 12;
    pub const RECVTOS = 13;
    pub const MTU = 14;
    pub const FREEBIND = 15;
    pub const IPSEC_POLICY = 16;
    pub const XFRM_POLICY = 17;
    pub const PASSSEC = 18;
    pub const TRANSPARENT = 19;
    pub const ORIGDSTADDR = 20;
    pub const RECVORIGDSTADDR = IP.ORIGDSTADDR;
    pub const MINTTL = 21;
    pub const NODEFRAG = 22;
    pub const CHECKSUM = 23;
    pub const BIND_ADDRESS_NO_PORT = 24;
    pub const RECVFRAGSIZE = 25;
    pub const MULTICAST_IF = 32;
    pub const MULTICAST_TTL = 33;
    pub const MULTICAST_LOOP = 34;
    pub const ADD_MEMBERSHIP = 35;
    pub const DROP_MEMBERSHIP = 36;
    pub const UNBLOCK_SOURCE = 37;
    pub const BLOCK_SOURCE = 38;
    pub const ADD_SOURCE_MEMBERSHIP = 39;
    pub const DROP_SOURCE_MEMBERSHIP = 40;
    pub const MSFILTER = 41;
    pub const MULTICAST_ALL = 49;
    pub const UNICAST_IF = 50;

    pub const RECVRETOPTS = IP.RETOPTS;

    pub const PMTUDISC_DONT = 0;
    pub const PMTUDISC_WANT = 1;
    pub const PMTUDISC_DO = 2;
    pub const PMTUDISC_PROBE = 3;
    pub const PMTUDISC_INTERFACE = 4;
    pub const PMTUDISC_OMIT = 5;

    pub const DEFAULT_MULTICAST_TTL = 1;
    pub const DEFAULT_MULTICAST_LOOP = 1;
    pub const MAX_MEMBERSHIPS = 20;
};

/// IPv6 socket options
pub const IPV6 = struct {
    pub const ADDRFORM = 1;
    pub const @"2292PKTINFO" = 2;
    pub const @"2292HOPOPTS" = 3;
    pub const @"2292DSTOPTS" = 4;
    pub const @"2292RTHDR" = 5;
    pub const @"2292PKTOPTIONS" = 6;
    pub const CHECKSUM = 7;
    pub const @"2292HOPLIMIT" = 8;
    pub const NEXTHOP = 9;
    pub const AUTHHDR = 10;
    pub const FLOWINFO = 11;

    pub const UNICAST_HOPS = 16;
    pub const MULTICAST_IF = 17;
    pub const MULTICAST_HOPS = 18;
    pub const MULTICAST_LOOP = 19;
    pub const ADD_MEMBERSHIP = 20;
    pub const DROP_MEMBERSHIP = 21;
    pub const ROUTER_ALERT = 22;
    pub const MTU_DISCOVER = 23;
    pub const MTU = 24;
    pub const RECVERR = 25;
    pub const V6ONLY = 26;
    pub const JOIN_ANYCAST = 27;
    pub const LEAVE_ANYCAST = 28;

    // IPV6.MTU_DISCOVER values
    pub const PMTUDISC_DONT = 0;
    pub const PMTUDISC_WANT = 1;
    pub const PMTUDISC_DO = 2;
    pub const PMTUDISC_PROBE = 3;
    pub const PMTUDISC_INTERFACE = 4;
    pub const PMTUDISC_OMIT = 5;

    // Flowlabel
    pub const FLOWLABEL_MGR = 32;
    pub const FLOWINFO_SEND = 33;
    pub const IPSEC_POLICY = 34;
    pub const XFRM_POLICY = 35;
    pub const HDRINCL = 36;

    // Advanced API (RFC3542) (1)
    pub const RECVPKTINFO = 49;
    pub const PKTINFO = 50;
    pub const RECVHOPLIMIT = 51;
    pub const HOPLIMIT = 52;
    pub const RECVHOPOPTS = 53;
    pub const HOPOPTS = 54;
    pub const RTHDRDSTOPTS = 55;
    pub const RECVRTHDR = 56;
    pub const RTHDR = 57;
    pub const RECVDSTOPTS = 58;
    pub const DSTOPTS = 59;
    pub const RECVPATHMTU = 60;
    pub const PATHMTU = 61;
    pub const DONTFRAG = 62;

    // Advanced API (RFC3542) (2)
    pub const RECVTCLASS = 66;
    pub const TCLASS = 67;

    pub const AUTOFLOWLABEL = 70;

    // RFC5014: Source address selection
    pub const ADDR_PREFERENCES = 72;

    pub const PREFER_SRC_TMP = 0x0001;
    pub const PREFER_SRC_PUBLIC = 0x0002;
    pub const PREFER_SRC_PUBTMP_DEFAULT = 0x0100;
    pub const PREFER_SRC_COA = 0x0004;
    pub const PREFER_SRC_HOME = 0x0400;
    pub const PREFER_SRC_CGA = 0x0008;
    pub const PREFER_SRC_NONCGA = 0x0800;

    // RFC5082: Generalized Ttl Security Mechanism
    pub const MINHOPCOUNT = 73;

    pub const ORIGDSTADDR = 74;
    pub const RECVORIGDSTADDR = IPV6.ORIGDSTADDR;
    pub const TRANSPARENT = 75;
    pub const UNICAST_IF = 76;
    pub const RECVFRAGSIZE = 77;
    pub const FREEBIND = 78;
};

/// IEEE 802.3 Ethernet magic constants. The frame sizes omit the preamble
/// and FCS/CRC (frame check sequence).
pub const ETH = struct {
    /// Octets in one ethernet addr
    pub const ALEN = 6;
    /// Octets in ethernet type field
    pub const TLEN = 2;
    /// Total octets in header
    pub const HLEN = 14;
    /// Min. octets in frame sans FC
    pub const ZLEN = 60;
    /// Max. octets in payload
    pub const DATA_LEN = 1500;
    /// Max. octets in frame sans FCS
    pub const FRAME_LEN = 1514;
    /// Octets in the FCS
    pub const FCS_LEN = 4;

    /// Min IPv4 MTU per RFC791
    pub const MIN_MTU = 68;
    /// 65535, same as IP_MAX_MTU
    pub const MAX_MTU = 0xFFFF;

    /// These are the defined Ethernet Protocol ID's.
    pub const P = struct {
        /// Ethernet Loopback packet
        pub const LOOP = 0x0060;
        /// Xerox PUP packet
        pub const PUP = 0x0200;
        /// Xerox PUP Addr Trans packet
        pub const PUPAT = 0x0201;
        /// TSN (IEEE 1722) packet
        pub const TSN = 0x22F0;
        /// ERSPAN version 2 (type III)
        pub const ERSPAN2 = 0x22EB;
        /// Internet Protocol packet
        pub const IP = 0x0800;
        /// CCITT X.25
        pub const X25 = 0x0805;
        /// Address Resolution packet
        pub const ARP = 0x0806;
        /// G8BPQ AX.25 Ethernet Packet [ NOT AN OFFICIALLY REGISTERED ID ]
        pub const BPQ = 0x08FF;
        /// Xerox IEEE802.3 PUP packet
        pub const IEEEPUP = 0x0a00;
        /// Xerox IEEE802.3 PUP Addr Trans packet
        pub const IEEEPUPAT = 0x0a01;
        /// B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ]
        pub const BATMAN = 0x4305;
        /// DEC Assigned proto
        pub const DEC = 0x6000;
        /// DEC DNA Dump/Load
        pub const DNA_DL = 0x6001;
        /// DEC DNA Remote Console
        pub const DNA_RC = 0x6002;
        /// DEC DNA Routing
        pub const DNA_RT = 0x6003;
        /// DEC LAT
        pub const LAT = 0x6004;
        /// DEC Diagnostics
        pub const DIAG = 0x6005;
        /// DEC Customer use
        pub const CUST = 0x6006;
        /// DEC Systems Comms Arch
        pub const SCA = 0x6007;
        /// Trans Ether Bridging
        pub const TEB = 0x6558;
        /// Reverse Addr Res packet
        pub const RARP = 0x8035;
        /// Appletalk DDP
        pub const ATALK = 0x809B;
        /// Appletalk AARP
        pub const AARP = 0x80F3;
        /// 802.1Q VLAN Extended Header
        pub const P_8021Q = 0x8100;
        /// ERSPAN type II
        pub const ERSPAN = 0x88BE;
        /// IPX over DIX
        pub const IPX = 0x8137;
        /// IPv6 over bluebook
        pub const IPV6 = 0x86DD;
        /// IEEE Pause frames. See 802.3 31B
        pub const PAUSE = 0x8808;
        /// Slow Protocol. See 802.3ad 43B
        pub const SLOW = 0x8809;
        /// Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt
        pub const WCCP = 0x883E;
        /// MPLS Unicast traffic
        pub const MPLS_UC = 0x8847;
        /// MPLS Multicast traffic
        pub const MPLS_MC = 0x8848;
        /// MultiProtocol Over ATM
        pub const ATMMPOA = 0x884c;
        /// PPPoE discovery messages
        pub const PPP_DISC = 0x8863;
        /// PPPoE session messages
        pub const PPP_SES = 0x8864;
        /// HPNA, wlan link local tunnel
        pub const LINK_CTL = 0x886c;
        /// Frame-based ATM Transport over Ethernet
        pub const ATMFATE = 0x8884;
        /// Port Access Entity (IEEE 802.1X)
        pub const PAE = 0x888E;
        /// PROFINET
        pub const PROFINET = 0x8892;
        /// Multiple proprietary protocols
        pub const REALTEK = 0x8899;
        /// ATA over Ethernet
        pub const AOE = 0x88A2;
        /// EtherCAT
        pub const ETHERCAT = 0x88A4;
        /// 802.1ad Service VLAN
        pub const @"8021AD" = 0x88A8;
        /// 802.1 Local Experimental 1.
        pub const @"802_EX1" = 0x88B5;
        /// 802.11 Preauthentication
        pub const PREAUTH = 0x88C7;
        /// TIPC
        pub const TIPC = 0x88CA;
        /// Link Layer Discovery Protocol
        pub const LLDP = 0x88CC;
        /// Media Redundancy Protocol
        pub const MRP = 0x88E3;
        /// 802.1ae MACsec
        pub const MACSEC = 0x88E5;
        /// 802.1ah Backbone Service Tag
        pub const @"8021AH" = 0x88E7;
        /// 802.1Q MVRP
        pub const MVRP = 0x88F5;
        /// IEEE 1588 Timesync
        pub const @"1588" = 0x88F7;
        /// NCSI protocol
        pub const NCSI = 0x88F8;
        /// IEC 62439-3 PRP/HSRv0
        pub const PRP = 0x88FB;
        /// Connectivity Fault Management
        pub const CFM = 0x8902;
        /// Fibre Channel over Ethernet
        pub const FCOE = 0x8906;
        /// Infiniband over Ethernet
        pub const IBOE = 0x8915;
        /// TDLS
        pub const TDLS = 0x890D;
        /// FCoE Initialization Protocol
        pub const FIP = 0x8914;
        /// IEEE 802.21 Media Independent Handover Protocol
        pub const @"80221" = 0x8917;
        /// IEC 62439-3 HSRv1
        pub const HSR = 0x892F;
        /// Network Service Header
        pub const NSH = 0x894F;
        /// Ethernet loopback packet, per IEEE 802.3
        pub const LOOPBACK = 0x9000;
        /// deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
        pub const QINQ1 = 0x9100;
        /// deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
        pub const QINQ2 = 0x9200;
        /// deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ]
        pub const QINQ3 = 0x9300;
        /// Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ]
        pub const EDSA = 0xDADA;
        /// Fake VLAN Header for DSA [ NOT AN OFFICIALLY REGISTERED ID ]
        pub const DSA_8021Q = 0xDADB;
        /// A5PSW Tag Value [ NOT AN OFFICIALLY REGISTERED ID ]
        pub const DSA_A5PSW = 0xE001;
        /// ForCES inter-FE LFB type
        pub const IFE = 0xED3E;
        /// IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ]
        pub const AF_IUCV = 0xFBFB;
        /// If the value in the ethernet type is more than this value then the frame is Ethernet II. Else it is 802.3
        pub const @"802_3_MIN" = 0x0600;

        // Non DIX types. Won't clash for 1500 types.

        /// Dummy type for 802.3 frames
        pub const @"802_3" = 0x0001;
        /// Dummy protocol id for AX.25
        pub const AX25 = 0x0002;
        /// Every packet (be careful!!!)
        pub const ALL = 0x0003;
        /// 802.2 frames
        pub const @"802_2" = 0x0004;
        /// Internal only
        pub const SNAP = 0x0005;
        /// DEC DDCMP: Internal only
        pub const DDCMP = 0x0006;
        /// Dummy type for WAN PPP frames
        pub const WAN_PPP = 0x0007;
        /// Dummy type for PPP MP frames
        pub const PPP_MP = 0x0008;
        /// Localtalk pseudo type
        pub const LOCALTALK = 0x0009;
        /// CAN: Controller Area Network
        pub const CAN = 0x000C;
        /// CANFD: CAN flexible data rate
        pub const CANFD = 0x000D;
        /// CANXL: eXtended frame Length
        pub const CANXL = 0x000E;
        /// Dummy type for Atalk over PPP
        pub const PPPTALK = 0x0010;
        /// 802.2 frames
        pub const TR_802_2 = 0x0011;
        /// Mobitex (kaz@cafe.net)
        pub const MOBITEX = 0x0015;
        /// Card specific control frames
        pub const CONTROL = 0x0016;
        /// Linux-IrDA
        pub const IRDA = 0x0017;
        /// Acorn Econet
        pub const ECONET = 0x0018;
        /// HDLC frames
        pub const HDLC = 0x0019;
        /// 1A for ArcNet :-)
        pub const ARCNET = 0x001A;
        /// Distributed Switch Arch.
        pub const DSA = 0x001B;
        /// Trailer switch tagging
        pub const TRAILER = 0x001C;
        /// Nokia Phonet frames
        pub const PHONET = 0x00F5;
        /// IEEE802.15.4 frame
        pub const IEEE802154 = 0x00F6;
        /// ST-Ericsson CAIF protocol
        pub const CAIF = 0x00F7;
        /// Multiplexed DSA protocol
        pub const XDSA = 0x00F8;
        /// Qualcomm multiplexing and aggregation protocol
        pub const MAP = 0x00F9;
        /// Management component transport protocol packets
        pub const MCTP = 0x00FA;
    };
};

pub const MSG = struct {
    pub const OOB = 0x0001;
    pub const PEEK = 0x0002;
    pub const DONTROUTE = 0x0004;
    pub const CTRUNC = 0x0008;
    pub const PROXY = 0x0010;
    pub const TRUNC = 0x0020;
    pub const DONTWAIT = 0x0040;
    pub const EOR = 0x0080;
    pub const WAITALL = 0x0100;
    pub const FIN = 0x0200;
    pub const SYN = 0x0400;
    pub const CONFIRM = 0x0800;
    pub const RST = 0x1000;
    pub const ERRQUEUE = 0x2000;
    pub const NOSIGNAL = 0x4000;
    pub const MORE = 0x8000;
    pub const WAITFORONE = 0x10000;
    pub const BATCH = 0x40000;
    pub const ZEROCOPY = 0x4000000;
    pub const FASTOPEN = 0x20000000;
    pub const CMSG_CLOEXEC = 0x40000000;
};

pub const DT = struct {
    pub const UNKNOWN = 0;
    pub const FIFO = 1;
    pub const CHR = 2;
    pub const DIR = 4;
    pub const BLK = 6;
    pub const REG = 8;
    pub const LNK = 10;
    pub const SOCK = 12;
    pub const WHT = 14;
};

pub const T = if (is_mips) struct {
    pub const CGETA = 0x5401;
    pub const CSETA = 0x5402;
    pub const CSETAW = 0x5403;
    pub const CSETAF = 0x5404;

    pub const CSBRK = 0x5405;
    pub const CXONC = 0x5406;
    pub const CFLSH = 0x5407;

    pub const CGETS = 0x540d;
    pub const CSETS = 0x540e;
    pub const CSETSW = 0x540f;
    pub const CSETSF = 0x5410;

    pub const IOCEXCL = 0x740d;
    pub const IOCNXCL = 0x740e;
    pub const IOCOUTQ = 0x7472;
    pub const IOCSTI = 0x5472;
    pub const IOCMGET = 0x741d;
    pub const IOCMBIS = 0x741b;
    pub const IOCMBIC = 0x741c;
    pub const IOCMSET = 0x741a;
    pub const IOCPKT = 0x5470;
    pub const IOCPKT_DATA = 0x00;
    pub const IOCPKT_FLUSHREAD = 0x01;
    pub const IOCPKT_FLUSHWRITE = 0x02;
    pub const IOCPKT_STOP = 0x04;
    pub const IOCPKT_START = 0x08;
    pub const IOCPKT_NOSTOP = 0x10;
    pub const IOCPKT_DOSTOP = 0x20;
    pub const IOCPKT_IOCTL = 0x40;
    pub const IOCSWINSZ = IOCTL.IOW('t', 103, winsize);
    pub const IOCGWINSZ = IOCTL.IOR('t', 104, winsize);
    pub const IOCNOTTY = 0x5471;
    pub const IOCSETD = 0x7401;
    pub const IOCGETD = 0x7400;

    pub const FIOCLEX = 0x6601;
    pub const FIONCLEX = 0x6602;
    pub const FIOASYNC = 0x667d;
    pub const FIONBIO = 0x667e;
    pub const FIOQSIZE = 0x667f;

    pub const IOCGLTC = 0x7474;
    pub const IOCSLTC = 0x7475;
    pub const IOCSPGRP = IOCTL.IOW('t', 118, c_int);
    pub const IOCGPGRP = IOCTL.IOR('t', 119, c_int);
    pub const IOCCONS = IOCTL.IOW('t', 120, c_int);

    pub const FIONREAD = 0x467f;
    pub const IOCINQ = FIONREAD;

    pub const IOCGETP = 0x7408;
    pub const IOCSETP = 0x7409;
    pub const IOCSETN = 0x740a;

    pub const IOCSBRK = 0x5427;
    pub const IOCCBRK = 0x5428;
    pub const IOCGSID = 0x7416;
    pub const CGETS2 = IOCTL.IOR('T', 0x2a, termios2);
    pub const CSETS2 = IOCTL.IOW('T', 0x2b, termios2);
    pub const CSETSW2 = IOCTL.IOW('T', 0x2c, termios2);
    pub const CSETSF2 = IOCTL.IOW('T', 0x2d, termios2);
    pub const IOCGRS485 = IOCTL.IOR('T', 0x2e, serial_rs485);
    pub const IOCSRS485 = IOCTL.IOWR('T', 0x2f, serial_rs485);
    pub const IOCGPTN = IOCTL.IOR('T', 0x30, c_uint);
    pub const IOCSPTLCK = IOCTL.IOW('T', 0x31, c_int);
    pub const IOCGDEV = IOCTL.IOR('T', 0x32, c_uint);
    pub const IOCSIG = IOCTL.IOW('T', 0x36, c_int);
    pub const IOCVHANGUP = 0x5437;
    pub const IOCGPKT = IOCTL.IOR('T', 0x38, c_int);
    pub const IOCGPTLCK = IOCTL.IOR('T', 0x39, c_int);
    pub const IOCGEXCL = IOCTL.IOR('T', 0x40, c_int);
    pub const IOCGPTPEER = IOCTL.IO('T', 0x41);
    pub const IOCGISO7816 = IOCTL.IOR('T', 0x42, serial_iso7816);
    pub const IOCSISO7816 = IOCTL.IOWR('T', 0x43, serial_iso7816);

    pub const IOCSCTTY = 0x5480;
    pub const IOCGSOFTCAR = 0x5481;
    pub const IOCSSOFTCAR = 0x5482;
    pub const IOCLINUX = 0x5483;
    pub const IOCGSERIAL = 0x5484;
    pub const IOCSSERIAL = 0x5485;
    pub const CSBRKP = 0x5486;
    pub const IOCSERCONFIG = 0x5488;
    pub const IOCSERGWILD = 0x5489;
    pub const IOCSERSWILD = 0x548a;
    pub const IOCGLCKTRMIOS = 0x548b;
    pub const IOCSLCKTRMIOS = 0x548c;
    pub const IOCSERGSTRUCT = 0x548d;
    pub const IOCSERGETLSR = 0x548e;
    pub const IOCSERGETMULTI = 0x548f;
    pub const IOCSERSETMULTI = 0x5490;
    pub const IOCMIWAIT = 0x5491;
    pub const IOCGICOUNT = 0x5492;
} else if (is_ppc) struct {
    pub const FIOCLEX = IOCTL.IO('f', 1);
    pub const FIONCLEX = IOCTL.IO('f', 2);
    pub const FIOASYNC = IOCTL.IOW('f', 125, c_int);
    pub const FIONBIO = IOCTL.IOW('f', 126, c_int);
    pub const FIONREAD = IOCTL.IOR('f', 127, c_int);
    pub const IOCINQ = FIONREAD;
    pub const FIOQSIZE = IOCTL.IOR('f', 128, c_longlong); // loff_t -> __kernel_loff_t -> long long

    pub const IOCGETP = IOCTL.IOR('t', 8, sgttyb);
    pub const IOCSETP = IOCTL.IOW('t', 9, sgttyb);
    pub const IOCSETN = IOCTL.IOW('t', 10, sgttyb);

    pub const IOCSETC = IOCTL.IOW('t', 17, tchars);
    pub const IOCGETC = IOCTL.IOR('t', 18, tchars);
    pub const CGETS = IOCTL.IOR('t', 19, termios);
    pub const CSETS = IOCTL.IOW('t', 20, termios);
    pub const CSETSW = IOCTL.IOW('t', 21, termios);
    pub const CSETSF = IOCTL.IOW('t', 22, termios);

    pub const CGETA = IOCTL.IOR('t', 23, termio);
    pub const CSETA = IOCTL.IOW('t', 24, termio);
    pub const CSETAW = IOCTL.IOW('t', 25, termio);
    pub const CSETAF = IOCTL.IOW('t', 28, termio);

    pub const CSBRK = IOCTL.IO('t', 29);
    pub const CXONC = IOCTL.IO('t', 30);
    pub const CFLSH = IOCTL.IO('t', 31);

    pub const IOCSWINSZ = IOCTL.IOW('t', 103, winsize);
    pub const IOCGWINSZ = IOCTL.IOR('t', 104, winsize);
    pub const IOCSTART = IOCTL.IO('t', 110);
    pub const IOCSTOP = IOCTL.IO('t', 111);
    pub const IOCOUTQ = IOCTL.IOR('t', 115, c_int);

    pub const IOCGLTC = IOCTL.IOR('t', 116, ltchars);
    pub const IOCSLTC = IOCTL.IOW('t', 117, ltchars);
    pub const IOCSPGRP = IOCTL.IOW('t', 118, c_int);
    pub const IOCGPGRP = IOCTL.IOR('t', 119, c_int);

    pub const IOCEXCL = 0x540c;
    pub const IOCNXCL = 0x540d;
    pub const IOCSCTTY = 0x540e;

    pub const IOCSTI = 0x5412;
    pub const IOCMGET = 0x5415;
    pub const IOCMBIS = 0x5416;
    pub const IOCMBIC = 0x5417;
    pub const IOCMSET = 0x5418;
    pub const IOCM_LE = 0x001;
    pub const IOCM_DTR = 0x002;
    pub const IOCM_RTS = 0x004;
    pub const IOCM_ST = 0x008;
    pub const IOCM_SR = 0x010;
    pub const IOCM_CTS = 0x020;
    pub const IOCM_CAR = 0x040;
    pub const IOCM_RNG = 0x080;
    pub const IOCM_DSR = 0x100;
    pub const IOCM_CD = IOCM_CAR;
    pub const IOCM_RI = IOCM_RNG;
    pub const IOCM_OUT1 = 0x2000;
    pub const IOCM_OUT2 = 0x4000;
    pub const IOCM_LOOP = 0x8000;

    pub const IOCGSOFTCAR = 0x5419;
    pub const IOCSSOFTCAR = 0x541a;
    pub const IOCLINUX = 0x541c;
    pub const IOCCONS = 0x541d;
    pub const IOCGSERIAL = 0x541e;
    pub const IOCSSERIAL = 0x541f;
    pub const IOCPKT = 0x5420;
    pub const IOCPKT_DATA = 0;
    pub const IOCPKT_FLUSHREAD = 1;
    pub const IOCPKT_FLUSHWRITE = 2;
    pub const IOCPKT_STOP = 4;
    pub const IOCPKT_START = 8;
    pub const IOCPKT_NOSTOP = 16;
    pub const IOCPKT_DOSTOP = 32;
    pub const IOCPKT_IOCTL = 64;

    pub const IOCNOTTY = 0x5422;
    pub const IOCSETD = 0x5423;
    pub const IOCGETD = 0x5424;
    pub const CSBRKP = 0x5425;
    pub const IOCSBRK = 0x5427;
    pub const IOCCBRK = 0x5428;
    pub const IOCGSID = 0x5429;
    pub const IOCGRS485 = 0x542e;
    pub const IOCSRS485 = 0x542f;
    pub const IOCGPTN = IOCTL.IOR('T', 0x30, c_uint);
    pub const IOCSPTLCK = IOCTL.IOW('T', 0x31, c_int);
    pub const IOCGDEV = IOCTL.IOR('T', 0x32, c_uint);
    pub const IOCSIG = IOCTL.IOW('T', 0x36, c_int);
    pub const IOCVHANGUP = 0x5437;
    pub const IOCGPKT = IOCTL.IOR('T', 0x38, c_int);
    pub const IOCGPTLCK = IOCTL.IOR('T', 0x39, c_int);
    pub const IOCGEXCL = IOCTL.IOR('T', 0x40, c_int);
    pub const IOCGPTPEER = IOCTL.IO('T', 0x41);
    pub const IOCGISO7816 = IOCTL.IOR('T', 0x42, serial_iso7816);
    pub const IOCSISO7816 = IOCTL.IOWR('T', 0x43, serial_iso7816);

    pub const IOCSERCONFIG = 0x5453;
    pub const IOCSERGWILD = 0x5454;
    pub const IOCSERSWILD = 0x5455;
    pub const IOCGLCKTRMIOS = 0x5456;
    pub const IOCSLCKTRMIOS = 0x5457;
    pub const IOCSERGSTRUCT = 0x5458;
    pub const IOCSERGETLSR = 0x5459;
    pub const IOCSER_TEMT = 0x01;
    pub const IOCSERGETMULTI = 0x545a;
    pub const IOCSERSETMULTI = 0x545b;

    pub const IOCMIWAIT = 0x545c;
    pub const IOCGICOUNT = 0x545d;
} else if (is_sparc) struct {
    // Entries with double-underscore prefix have not been translated as they are unsupported.

    pub const CGETA = IOCTL.IOR('T', 1, termio);
    pub const CSETA = IOCTL.IOW('T', 2, termio);
    pub const CSETAW = IOCTL.IOW('T', 3, termio);
    pub const CSETAF = IOCTL.IOW('T', 4, termio);
    pub const CSBRK = IOCTL.IO('T', 5);
    pub const CXONC = IOCTL.IO('T', 6);
    pub const CFLSH = IOCTL.IO('T', 7);
    pub const CGETS = IOCTL.IOR('T', 8, termios);
    pub const CSETS = IOCTL.IOW('T', 9, termios);
    pub const CSETSW = IOCTL.IOW('T', 10, termios);
    pub const CSETSF = IOCTL.IOW('T', 11, termios);
    pub const CGETS2 = IOCTL.IOR('T', 12, termios2);
    pub const CSETS2 = IOCTL.IOW('T', 13, termios2);
    pub const CSETSW2 = IOCTL.IOW('T', 14, termios2);
    pub const CSETSF2 = IOCTL.IOW('T', 15, termios2);
    pub const IOCGDEV = IOCTL.IOR('T', 0x32, c_uint);
    pub const IOCVHANGUP = IOCTL.IO('T', 0x37);
    pub const IOCGPKT = IOCTL.IOR('T', 0x38, c_int);
    pub const IOCGPTLCK = IOCTL.IOR('T', 0x39, c_int);
    pub const IOCGEXCL = IOCTL.IOR('T', 0x40, c_int);
    pub const IOCGRS485 = IOCTL.IOR('T', 0x41, serial_rs485);
    pub const IOCSRS485 = IOCTL.IOWR('T', 0x42, serial_rs485);
    pub const IOCGISO7816 = IOCTL.IOR('T', 0x43, serial_iso7816);
    pub const IOCSISO7816 = IOCTL.IOWR('T', 0x44, serial_iso7816);

    pub const IOCGETD = IOCTL.IOR('t', 0, c_int);
    pub const IOCSETD = IOCTL.IOW('t', 1, c_int);
    pub const IOCEXCL = IOCTL.IO('t', 13);
    pub const IOCNXCL = IOCTL.IO('t', 14);
    pub const IOCCONS = IOCTL.IO('t', 36);
    pub const IOCGSOFTCAR = IOCTL.IOR('t', 100, c_int);
    pub const IOCSSOFTCAR = IOCTL.IOW('t', 101, c_int);
    pub const IOCSWINSZ = IOCTL.IOW('t', 103, winsize);
    pub const IOCGWINSZ = IOCTL.IOR('t', 104, winsize);
    pub const IOCMGET = IOCTL.IOR('t', 106, c_int);
    pub const IOCMBIC = IOCTL.IOW('t', 107, c_int);
    pub const IOCMBIS = IOCTL.IOW('t', 108, c_int);
    pub const IOCMSET = IOCTL.IOW('t', 109, c_int);
    pub const IOCSTART = IOCTL.IO('t', 110);
    pub const IOCSTOP = IOCTL.IO('t', 111);
    pub const IOCPKT = IOCTL.IOW('t', 112, c_int);
    pub const IOCNOTTY = IOCTL.IO('t', 113);
    pub const IOCSTI = IOCTL.IOW('t', 114, c_char);
    pub const IOCOUTQ = IOCTL.IOR('t', 115, c_int);
    pub const IOCCBRK = IOCTL.IO('t', 122);
    pub const IOCSBRK = IOCTL.IO('t', 123);
    pub const IOCSPGRP = IOCTL.IOW('t', 130, c_int);
    pub const IOCGPGRP = IOCTL.IOR('t', 131, c_int);
    pub const IOCSCTTY = IOCTL.IO('t', 132);
    pub const IOCGSID = IOCTL.IOR('t', 133, c_int);
    pub const IOCGPTN = IOCTL.IOR('t', 134, c_uint);
    pub const IOCSPTLCK = IOCTL.IOW('t', 135, c_int);
    pub const IOCSIG = IOCTL.IOW('t', 136, c_int);
    pub const IOCGPTPEER = IOCTL.IO('t', 137);

    pub const FIOCLEX = IOCTL.IO('f', 1);
    pub const FIONCLEX = IOCTL.IO('f', 2);
    pub const FIOASYNC = IOCTL.IOW('f', 125, c_int);
    pub const FIONBIO = IOCTL.IOW('f', 126, c_int);
    pub const FIONREAD = IOCTL.IOR('f', 127, c_int);
    pub const IOCINQ = FIONREAD;
    pub const FIOQSIZE = IOCTL.IOR('f', 128, c_longlong); // loff_t -> __kernel_loff_t -> long long

    pub const IOCLINUX = 0x541c;
    pub const IOCGSERIAL = 0x541e;
    pub const IOCSSERIAL = 0x541f;
    pub const CSBRKP = 0x5425;
    pub const IOCSERCONFIG = 0x5453;
    pub const IOCSERGWILD = 0x5454;
    pub const IOCSERSWILD = 0x5455;
    pub const IOCGLCKTRMIOS = 0x5456;
    pub const IOCSLCKTRMIOS = 0x5457;
    pub const IOCSERGSTRUCT = 0x5458;
    pub const IOCSERGETLSR = 0x5459;
    pub const IOCSERGETMULTI = 0x545a;
    pub const IOCSERSETMULTI = 0x545b;
    pub const IOCMIWAIT = 0x545c;
    pub const IOCGICOUNT = 0x545d;

    pub const IOCPKT_DATA = 0;
    pub const IOCPKT_FLUSHREAD = 1;
    pub const IOCPKT_FLUSHWRITE = 2;
    pub const IOCPKT_STOP = 4;
    pub const IOCPKT_START = 8;
    pub const IOCPKT_NOSTOP = 16;
    pub const IOCPKT_DOSTOP = 32;
    pub const IOCPKT_IOCTL = 64;
} else struct {
    pub const CGETS = 0x5401;
    pub const CSETS = 0x5402;
    pub const CSETSW = 0x5403;
    pub const CSETSF = 0x5404;
    pub const CGETA = 0x5405;
    pub const CSETA = 0x5406;
    pub const CSETAW = 0x5407;
    pub const CSETAF = 0x5408;
    pub const CSBRK = 0x5409;
    pub const CXONC = 0x540a;
    pub const CFLSH = 0x540b;
    pub const IOCEXCL = 0x540c;
    pub const IOCNXCL = 0x540d;
    pub const IOCSCTTY = 0x540e;
    pub const IOCGPGRP = 0x540f;
    pub const IOCSPGRP = 0x5410;
    pub const IOCOUTQ = 0x5411;
    pub const IOCSTI = 0x5412;
    pub const IOCGWINSZ = 0x5413;
    pub const IOCSWINSZ = 0x5414;
    pub const IOCMGET = 0x5415;
    pub const IOCMBIS = 0x5416;
    pub const IOCMBIC = 0x5417;
    pub const IOCMSET = 0x5418;
    pub const IOCGSOFTCAR = 0x5419;
    pub const IOCSSOFTCAR = 0x541a;
    pub const FIONREAD = 0x541b;
    pub const IOCINQ = FIONREAD;
    pub const IOCLINUX = 0x541c;
    pub const IOCCONS = 0x541d;
    pub const IOCGSERIAL = 0x541e;
    pub const IOCSSERIAL = 0x541f;
    pub const IOCPKT = 0x5420;
    pub const FIONBIO = 0x5421;
    pub const IOCNOTTY = 0x5422;
    pub const IOCSETD = 0x5423;
    pub const IOCGETD = 0x5424;
    pub const CSBRKP = 0x5425;
    pub const IOCSBRK = 0x5427;
    pub const IOCCBRK = 0x5428;
    pub const IOCGSID = 0x5429;
    pub const CGETS2 = IOCTL.IOR('T', 0x2a, termios2);
    pub const CSETS2 = IOCTL.IOW('T', 0x2b, termios2);
    pub const CSETSW2 = IOCTL.IOW('T', 0x2c, termios2);
    pub const CSETSF2 = IOCTL.IOW('T', 0x2d, termios2);
    pub const IOCGRS485 = 0x542e;
    pub const IOCSRS485 = 0x542f;
    pub const IOCGPTN = IOCTL.IOR('T', 0x30, c_uint);
    pub const IOCSPTLCK = IOCTL.IOW('T', 0x31, c_int);
    pub const IOCGDEV = IOCTL.IOR('T', 0x32, c_uint);
    pub const CGETX = 0x5432;
    pub const CSETX = 0x5433;
    pub const CSETXF = 0x5434;
    pub const CSETXW = 0x5435;
    pub const IOCSIG = IOCTL.IOW('T', 0x36, c_int);
    pub const IOCVHANGUP = 0x5437;
    pub const IOCGPKT = IOCTL.IOR('T', 0x38, c_int);
    pub const IOCGPTLCK = IOCTL.IOR('T', 0x39, c_int);
    pub const IOCGEXCL = IOCTL.IOR('T', 0x40, c_int);
    pub const IOCGPTPEER = IOCTL.IO('T', 0x41);
    pub const IOCGISO7816 = IOCTL.IOR('T', 0x42, serial_iso7816);
    pub const IOCSISO7816 = IOCTL.IOWR('T', 0x43, serial_iso7816);

    pub const FIONCLEX = 0x5450;
    pub const FIOCLEX = 0x5451;
    pub const FIOASYNC = 0x5452;
    pub const IOCSERCONFIG = 0x5453;
    pub const IOCSERGWILD = 0x5454;
    pub const IOCSERSWILD = 0x5455;
    pub const IOCGLCKTRMIOS = 0x5456;
    pub const IOCSLCKTRMIOS = 0x5457;
    pub const IOCSERGSTRUCT = 0x5458;
    pub const IOCSERGETLSR = 0x5459;
    pub const IOCSERGETMULTI = 0x545a;
    pub const IOCSERSETMULTI = 0x545b;

    pub const IOCMIWAIT = 0x545c;
    pub const IOCGICOUNT = 0x545d;

    pub const FIOQSIZE = switch (native_arch) {
        .arm,
        .armeb,
        .thumb,
        .thumbeb,
        .m68k,
        .s390x,
        => 0x545e,
        else => 0x5460,
    };

    pub const IOCPKT_DATA = 0;
    pub const IOCPKT_FLUSHREAD = 1;
    pub const IOCPKT_FLUSHWRITE = 2;
    pub const IOCPKT_STOP = 4;
    pub const IOCPKT_START = 8;
    pub const IOCPKT_NOSTOP = 16;
    pub const IOCPKT_DOSTOP = 32;
    pub const IOCPKT_IOCTL = 64;

    pub const IOCSER_TEMT = 0x01;
};

pub const serial_rs485 = extern struct {
    flags: u32,
    delay_rts_before_send: u32,
    delay_rts_after_send: u32,
    extra: extern union {
        _pad1: [5]u32,
        s: extern struct {
            addr_recv: u8,
            addr_dest: u8,
            _pad2: [2]u8,
            _pad3: [4]u32,
        },
    },
};

pub const serial_iso7816 = extern struct {
    flags: u32,
    tg: u32,
    sc_fi: u32,
    sc_di: u32,
    clk: u32,
    _reserved: [5]u32,
};

pub const SER = struct {
    pub const RS485 = struct {
        pub const ENABLED = 1 << 0;
        pub const RTS_ON_SEND = 1 << 1;
        pub const RTS_AFTER_SEND = 1 << 2;
        pub const RX_DURING_TX = 1 << 4;
        pub const TERMINATE_BUS = 1 << 5;
        pub const ADDRB = 1 << 6;
        pub const ADDR_RECV = 1 << 7;
        pub const ADDR_DEST = 1 << 8;
    };

    pub const ISO7816 = struct {
        pub const ENABLED = 1 << 0;
        pub const T_PARAM = 0x0f << 4;

        pub fn T(t: anytype) @TypeOf(t) {
            return (t & 0x0f) << 4;
        }
    };
};

pub const EPOLL = struct {
    pub const CLOEXEC = 1 << @bitOffsetOf(O, "CLOEXEC");

    pub const CTL_ADD = 1;
    pub const CTL_DEL = 2;
    pub const CTL_MOD = 3;

    pub const IN = 0x001;
    pub const PRI = 0x002;
    pub const OUT = 0x004;
    pub const RDNORM = 0x040;
    pub const RDBAND = 0x080;
    pub const WRNORM = if (is_mips) 0x004 else 0x100;
    pub const WRBAND = if (is_mips) 0x100 else 0x200;
    pub const MSG = 0x400;
    pub const ERR = 0x008;
    pub const HUP = 0x010;
    pub const RDHUP = 0x2000;
    pub const EXCLUSIVE = (@as(u32, 1) << 28);
    pub const WAKEUP = (@as(u32, 1) << 29);
    pub const ONESHOT = (@as(u32, 1) << 30);
    pub const ET = (@as(u32, 1) << 31);
};

pub const CLOCK = clockid_t;

pub const clockid_t = enum(u32) {
    REALTIME = 0,
    MONOTONIC = 1,
    PROCESS_CPUTIME_ID = 2,
    THREAD_CPUTIME_ID = 3,
    MONOTONIC_RAW = 4,
    REALTIME_COARSE = 5,
    MONOTONIC_COARSE = 6,
    BOOTTIME = 7,
    REALTIME_ALARM = 8,
    BOOTTIME_ALARM = 9,
    // In the linux kernel header file (time.h) is the following note:
    // * The driver implementing this got removed. The clock ID is kept as a
    // * place holder. Do not reuse!
    // Therefore, calling clock_gettime() with these IDs will result in an error.
    //
    // Some backgrond:
    // - SGI_CYCLE was for Silicon Graphics (SGI) workstations,
    // which are probably no longer in use, so it makes sense to disable
    // - TAI_CLOCK was designed as CLOCK_REALTIME(UTC) + tai_offset,
    // but tai_offset was always 0 in the kernel.
    // So there is no point in using this clock.
    // SGI_CYCLE = 10,
    // TAI = 11,
    _,
};

// For use with posix.timerfd_create()
// Actually, the parameter for the timerfd_create() function is in integer,
// which means that the developer has to figure out which value is appropriate.
// To make this easier and, above all, safer, because an incorrect value leads
// to a panic, an enum is introduced which only allows the values
// that actually work.
pub const TIMERFD_CLOCK = timerfd_clockid_t;
pub const timerfd_clockid_t = enum(u32) {
    REALTIME = 0,
    MONOTONIC = 1,
    BOOTTIME = 7,
    REALTIME_ALARM = 8,
    BOOTTIME_ALARM = 9,
    _,
};

pub const TIMER = packed struct(u32) {
    ABSTIME: bool,
    _: u31 = 0,
};

pub const CSIGNAL = 0x000000ff;

pub const CLONE = struct {
    pub const VM = 0x00000100;
    pub const FS = 0x00000200;
    pub const FILES = 0x00000400;
    pub const SIGHAND = 0x00000800;
    pub const PIDFD = 0x00001000;
    pub const PTRACE = 0x00002000;
    pub const VFORK = 0x00004000;
    pub const PARENT = 0x00008000;
    pub const THREAD = 0x00010000;
    pub const NEWNS = 0x00020000;
    pub const SYSVSEM = 0x00040000;
    pub const SETTLS = 0x00080000;
    pub const PARENT_SETTID = 0x00100000;
    pub const CHILD_CLEARTID = 0x00200000;
    pub const DETACHED = 0x00400000;
    pub const UNTRACED = 0x00800000;
    pub const CHILD_SETTID = 0x01000000;
    pub const NEWCGROUP = 0x02000000;
    pub const NEWUTS = 0x04000000;
    pub const NEWIPC = 0x08000000;
    pub const NEWUSER = 0x10000000;
    pub const NEWPID = 0x20000000;
    pub const NEWNET = 0x40000000;
    pub const IO = 0x80000000;

    // Flags for the clone3() syscall.

    /// Clear any signal handler and reset to SIG_DFL.
    pub const CLEAR_SIGHAND = 0x100000000;
    /// Clone into a specific cgroup given the right permissions.
    pub const INTO_CGROUP = 0x200000000;

    // cloning flags intersect with CSIGNAL so can be used with unshare and clone3 syscalls only.

    /// New time namespace
    pub const NEWTIME = 0x00000080;
};

pub const EFD = struct {
    pub const SEMAPHORE = 1;
    pub const CLOEXEC = 1 << @bitOffsetOf(O, "CLOEXEC");
    pub const NONBLOCK = 1 << @bitOffsetOf(O, "NONBLOCK");
};

pub const MS = struct {
    pub const RDONLY = 1;
    pub const NOSUID = 2;
    pub const NODEV = 4;
    pub const NOEXEC = 8;
    pub const SYNCHRONOUS = 16;
    pub const REMOUNT = 32;
    pub const MANDLOCK = 64;
    pub const DIRSYNC = 128;
    pub const NOATIME = 1024;
    pub const NODIRATIME = 2048;
    pub const BIND = 4096;
    pub const MOVE = 8192;
    pub const REC = 16384;
    pub const SILENT = 32768;
    pub const POSIXACL = (1 << 16);
    pub const UNBINDABLE = (1 << 17);
    pub const PRIVATE = (1 << 18);
    pub const SLAVE = (1 << 19);
    pub const SHARED = (1 << 20);
    pub const RELATIME = (1 << 21);
    pub const KERNMOUNT = (1 << 22);
    pub const I_VERSION = (1 << 23);
    pub const STRICTATIME = (1 << 24);
    pub const LAZYTIME = (1 << 25);
    pub const NOREMOTELOCK = (1 << 27);
    pub const NOSEC = (1 << 28);
    pub const BORN = (1 << 29);
    pub const ACTIVE = (1 << 30);
    pub const NOUSER = (1 << 31);

    pub const RMT_MASK = (RDONLY | SYNCHRONOUS | MANDLOCK | I_VERSION | LAZYTIME);

    pub const MGC_VAL = 0xc0ed0000;
    pub const MGC_MSK = 0xffff0000;
};

pub const MNT = struct {
    pub const FORCE = 1;
    pub const DETACH = 2;
    pub const EXPIRE = 4;
};

pub const UMOUNT_NOFOLLOW = 8;

pub const IN = struct {
    pub const CLOEXEC = 1 << @bitOffsetOf(O, "CLOEXEC");
    pub const NONBLOCK = 1 << @bitOffsetOf(O, "NONBLOCK");

    pub const ACCESS = 0x00000001;
    pub const MODIFY = 0x00000002;
    pub const ATTRIB = 0x00000004;
    pub const CLOSE_WRITE = 0x00000008;
    pub const CLOSE_NOWRITE = 0x00000010;
    pub const CLOSE = CLOSE_WRITE | CLOSE_NOWRITE;
    pub const OPEN = 0x00000020;
    pub const MOVED_FROM = 0x00000040;
    pub const MOVED_TO = 0x00000080;
    pub const MOVE = MOVED_FROM | MOVED_TO;
    pub const CREATE = 0x00000100;
    pub const DELETE = 0x00000200;
    pub const DELETE_SELF = 0x00000400;
    pub const MOVE_SELF = 0x00000800;
    pub const ALL_EVENTS = 0x00000fff;

    pub const UNMOUNT = 0x00002000;
    pub const Q_OVERFLOW = 0x00004000;
    pub const IGNORED = 0x00008000;

    pub const ONLYDIR = 0x01000000;
    pub const DONT_FOLLOW = 0x02000000;
    pub const EXCL_UNLINK = 0x04000000;
    pub const MASK_CREATE = 0x10000000;
    pub const MASK_ADD = 0x20000000;

    pub const ISDIR = 0x40000000;
    pub const ONESHOT = 0x80000000;
};

pub const fanotify = struct {
    pub const InitFlags = packed struct(u32) {
        CLOEXEC: bool = false,
        NONBLOCK: bool = false,
        CLASS: enum(u2) {
            NOTIF = 0,
            CONTENT = 1,
            PRE_CONTENT = 2,
        } = .NOTIF,
        UNLIMITED_QUEUE: bool = false,
        UNLIMITED_MARKS: bool = false,
        ENABLE_AUDIT: bool = false,
        REPORT_PIDFD: bool = false,
        REPORT_TID: bool = false,
        REPORT_FID: bool = false,
        REPORT_DIR_FID: bool = false,
        REPORT_NAME: bool = false,
        REPORT_TARGET_FID: bool = false,
        _: u19 = 0,
    };

    pub const MarkFlags = packed struct(u32) {
        ADD: bool = false,
        REMOVE: bool = false,
        DONT_FOLLOW: bool = false,
        ONLYDIR: bool = false,
        MOUNT: bool = false,
        /// Mutually exclusive with `IGNORE`
        IGNORED_MASK: bool = false,
        IGNORED_SURV_MODIFY: bool = false,
        FLUSH: bool = false,
        FILESYSTEM: bool = false,
        EVICTABLE: bool = false,
        /// Mutually exclusive with `IGNORED_MASK`
        IGNORE: bool = false,
        _: u21 = 0,
    };

    pub const MarkMask = packed struct(u64) {
        /// File was accessed
        ACCESS: bool = false,
        /// File was modified
        MODIFY: bool = false,
        /// Metadata changed
        ATTRIB: bool = false,
        /// Writtable file closed
        CLOSE_WRITE: bool = false,
        /// Unwrittable file closed
        CLOSE_NOWRITE: bool = false,
        /// File was opened
        OPEN: bool = false,
        /// File was moved from X
        MOVED_FROM: bool = false,
        /// File was moved to Y
        MOVED_TO: bool = false,

        /// Subfile was created
        CREATE: bool = false,
        /// Subfile was deleted
        DELETE: bool = false,
        /// Self was deleted
        DELETE_SELF: bool = false,
        /// Self was moved
        MOVE_SELF: bool = false,
        /// File was opened for exec
        OPEN_EXEC: bool = false,
        reserved13: u1 = 0,
        /// Event queued overflowed
        Q_OVERFLOW: bool = false,
        /// Filesystem error
        FS_ERROR: bool = false,

        /// File open in perm check
        OPEN_PERM: bool = false,
        /// File accessed in perm check
        ACCESS_PERM: bool = false,
        /// File open/exec in perm check
        OPEN_EXEC_PERM: bool = false,
        reserved19: u8 = 0,
        /// Interested in child events
        EVENT_ON_CHILD: bool = false,
        /// File was renamed
        RENAME: bool = false,
        reserved30: u1 = 0,
        /// Event occurred against dir
        ONDIR: bool = false,
        reserved31: u33 = 0,
    };

    pub const event_metadata = extern struct {
        event_len: u32,
        vers: u8,
        reserved: u8,
        metadata_len: u16,
        mask: MarkMask align(8),
        fd: i32,
        pid: i32,

        pub const VERSION = 3;
    };

    pub const response = extern struct {
        fd: i32,
        response: u32,
    };

    /// Unique file identifier info record.
    ///
    /// This structure is used for records of types `EVENT_INFO_TYPE.FID`.
    /// `EVENT_INFO_TYPE.DFID` and `EVENT_INFO_TYPE.DFID_NAME`.
    ///
    /// For `EVENT_INFO_TYPE.DFID_NAME` there is additionally a null terminated
    /// name immediately after the file handle.
    pub const event_info_fid = extern struct {
        hdr: event_info_header,
        fsid: kernel_fsid_t,
        /// Following is an opaque struct file_handle that can be passed as
        /// an argument to open_by_handle_at(2).
        handle: [0]u8,
    };

    /// Variable length info record following event metadata.
    pub const event_info_header = extern struct {
        info_type: EVENT_INFO_TYPE,
        pad: u8,
        len: u16,
    };

    pub const EVENT_INFO_TYPE = enum(u8) {
        FID = 1,
        DFID_NAME = 2,
        DFID = 3,
        PIDFD = 4,
        ERROR = 5,
        OLD_DFID_NAME = 10,
        OLD_DFID = 11,
        NEW_DFID_NAME = 12,
        NEW_DFID = 13,
    };
};

pub const file_handle = extern struct {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: [0]u8,
};

pub const kernel_fsid_t = fsid_t;
pub const fsid_t = [2]i32;

pub const S = struct {
    pub const IFMT = 0o170000;

    pub const IFDIR = 0o040000;
    pub const IFCHR = 0o020000;
    pub const IFBLK = 0o060000;
    pub const IFREG = 0o100000;
    pub const IFIFO = 0o010000;
    pub const IFLNK = 0o120000;
    pub const IFSOCK = 0o140000;

    pub const ISUID = 0o4000;
    pub const ISGID = 0o2000;
    pub const ISVTX = 0o1000;
    pub const IRUSR = 0o400;
    pub const IWUSR = 0o200;
    pub const IXUSR = 0o100;
    pub const IRWXU = 0o700;
    pub const IRGRP = 0o040;
    pub const IWGRP = 0o020;
    pub const IXGRP = 0o010;
    pub const IRWXG = 0o070;
    pub const IROTH = 0o004;
    pub const IWOTH = 0o002;
    pub const IXOTH = 0o001;
    pub const IRWXO = 0o007;

    pub fn ISREG(m: mode_t) bool {
        return m & IFMT == IFREG;
    }

    pub fn ISDIR(m: mode_t) bool {
        return m & IFMT == IFDIR;
    }

    pub fn ISCHR(m: mode_t) bool {
        return m & IFMT == IFCHR;
    }

    pub fn ISBLK(m: mode_t) bool {
        return m & IFMT == IFBLK;
    }

    pub fn ISFIFO(m: mode_t) bool {
        return m & IFMT == IFIFO;
    }

    pub fn ISLNK(m: mode_t) bool {
        return m & IFMT == IFLNK;
    }

    pub fn ISSOCK(m: mode_t) bool {
        return m & IFMT == IFSOCK;
    }
};

pub const UTIME = struct {
    pub const NOW = 0x3fffffff;
    pub const OMIT = 0x3ffffffe;
};

const TFD_TIMER = packed struct(u32) {
    ABSTIME: bool = false,
    CANCEL_ON_SET: bool = false,
    _: u30 = 0,
};

pub const TFD = switch (native_arch) {
    .sparc64 => packed struct(u32) {
        _0: u14 = 0,
        NONBLOCK: bool = false,
        _15: u7 = 0,
        CLOEXEC: bool = false,
        _: u9 = 0,

        pub const TIMER = TFD_TIMER;
    },
    .mips, .mipsel, .mips64, .mips64el => packed struct(u32) {
        _0: u7 = 0,
        NONBLOCK: bool = false,
        _8: u11 = 0,
        CLOEXEC: bool = false,
        _: u12 = 0,

        pub const TIMER = TFD_TIMER;
    },
    else => packed struct(u32) {
        _0: u11 = 0,
        NONBLOCK: bool = false,
        _12: u7 = 0,
        CLOEXEC: bool = false,
        _: u12 = 0,

        pub const TIMER = TFD_TIMER;
    },
};

/// NSIG is the total number of signals defined.
/// As signal numbers are sequential, NSIG is one greater than the largest defined signal number.
pub const NSIG = if (is_mips) 128 else 65;

const k_sigaction_funcs = struct {
    const handler = ?*align(1) const fn (i32) callconv(.c) void;
    const restorer = *const fn () callconv(.c) void;
};

pub const k_sigaction = switch (native_arch) {
    .mips, .mipsel => extern struct {
        flags: c_uint,
        handler: k_sigaction_funcs.handler,
        mask: [4]c_ulong,
        restorer: k_sigaction_funcs.restorer,
    },
    .mips64, .mips64el => extern struct {
        flags: c_uint,
        handler: k_sigaction_funcs.handler,
        mask: [2]c_ulong,
        restorer: k_sigaction_funcs.restorer,
    },
    else => extern struct {
        handler: k_sigaction_funcs.handler,
        flags: c_ulong,
        restorer: k_sigaction_funcs.restorer,
        mask: [2]c_uint,
    },
};

/// Renamed from `sigaction` to `Sigaction` to avoid conflict with the syscall.
pub const Sigaction = extern struct {
    pub const handler_fn = *align(1) const fn (i32) callconv(.c) void;
    pub const sigaction_fn = *const fn (i32, *const siginfo_t, ?*anyopaque) callconv(.c) void;

    handler: extern union {
        handler: ?handler_fn,
        sigaction: ?sigaction_fn,
    },
    mask: sigset_t,
    flags: c_uint,
    restorer: ?*const fn () callconv(.c) void = null,
};

pub const SFD = struct {
    pub const CLOEXEC = 1 << @bitOffsetOf(O, "CLOEXEC");
    pub const NONBLOCK = 1 << @bitOffsetOf(O, "NONBLOCK");
};

pub const signalfd_siginfo = extern struct {
    signo: u32,
    errno: i32,
    code: i32,
    pid: u32,
    uid: uid_t,
    fd: i32,
    tid: u32,
    band: u32,
    overrun: u32,
    trapno: u32,
    status: i32,
    int: i32,
    ptr: u64,
    utime: u64,
    stime: u64,
    addr: u64,
    addr_lsb: u16,
    __pad2: u16,
    syscall: i32,
    call_addr: u64,
    native_arch: u32,
    __pad: [28]u8,
};

pub const in_port_t = u16;
pub const sa_family_t = u16;
pub const socklen_t = u32;

pub const sockaddr = extern struct {
    family: sa_family_t,
    data: [14]u8,

    pub const SS_MAXSIZE = 128;
    pub const storage = extern struct {
        family: sa_family_t align(8),
        padding: [SS_MAXSIZE - @sizeOf(sa_family_t)]u8 = undefined,

        comptime {
            assert(@sizeOf(storage) == SS_MAXSIZE);
            assert(@alignOf(storage) == 8);
        }
    };

    /// IPv4 socket address
    pub const in = extern struct {
        family: sa_family_t = AF.INET,
        port: in_port_t,
        addr: u32,
        zero: [8]u8 = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };

    /// IPv6 socket address
    pub const in6 = extern struct {
        family: sa_family_t = AF.INET6,
        port: in_port_t,
        flowinfo: u32,
        addr: [16]u8,
        scope_id: u32,
    };

    /// UNIX domain socket address
    pub const un = extern struct {
        family: sa_family_t = AF.UNIX,
        path: [108]u8,
    };

    /// Packet socket address
    pub const ll = extern struct {
        family: sa_family_t = AF.PACKET,
        protocol: u16,
        ifindex: i32,
        hatype: u16,
        pkttype: u8,
        halen: u8,
        addr: [8]u8,
    };

    /// Netlink socket address
    pub const nl = extern struct {
        family: sa_family_t = AF.NETLINK,
        __pad1: c_ushort = 0,

        /// port ID
        pid: u32,

        /// multicast groups mask
        groups: u32,
    };

    pub const xdp = extern struct {
        family: u16 = AF.XDP,
        flags: u16,
        ifindex: u32,
        queue_id: u32,
        shared_umem_fd: u32,
    };

    /// Address structure for vSockets
    pub const vm = extern struct {
        family: sa_family_t = AF.VSOCK,
        reserved1: u16 = 0,
        port: u32,
        cid: u32,
        flags: u8,

        /// The total size of this structure should be exactly the same as that of struct sockaddr.
        zero: [3]u8 = [_]u8{0} ** 3,
        comptime {
            std.debug.assert(@sizeOf(vm) == @sizeOf(sockaddr));
        }
    };
};

pub const mmsghdr = extern struct {
    hdr: msghdr,
    len: u32,
};

pub const mmsghdr_const = extern struct {
    hdr: msghdr_const,
    len: u32,
};

pub const epoll_data = extern union {
    ptr: usize,
    fd: i32,
    u32: u32,
    u64: u64,
};

pub const epoll_event = extern struct {
    events: u32,
    data: epoll_data align(switch (native_arch) {
        .x86_64 => 4,
        else => @alignOf(epoll_data),
    }),
};

pub const VFS_CAP_REVISION_MASK = 0xFF000000;
pub const VFS_CAP_REVISION_SHIFT = 24;
pub const VFS_CAP_FLAGS_MASK = ~@as(u32, VFS_CAP_REVISION_MASK);
pub const VFS_CAP_FLAGS_EFFECTIVE = 0x000001;

pub const VFS_CAP_REVISION_1 = 0x01000000;
pub const VFS_CAP_U32_1 = 1;
pub const XATTR_CAPS_SZ_1 = @sizeOf(u32) * (1 + 2 * VFS_CAP_U32_1);

pub const VFS_CAP_REVISION_2 = 0x02000000;
pub const VFS_CAP_U32_2 = 2;
pub const XATTR_CAPS_SZ_2 = @sizeOf(u32) * (1 + 2 * VFS_CAP_U32_2);

pub const XATTR_CAPS_SZ = XATTR_CAPS_SZ_2;
pub const VFS_CAP_U32 = VFS_CAP_U32_2;
pub const VFS_CAP_REVISION = VFS_CAP_REVISION_2;

pub const vfs_cap_data = extern struct {
    //all of these are mandated as little endian
    //when on disk.
    const Data = extern struct {
        permitted: u32,
        inheritable: u32,
    };

    magic_etc: u32,
    data: [VFS_CAP_U32]Data,
};

pub const CAP = struct {
    pub const CHOWN = 0;
    pub const DAC_OVERRIDE = 1;
    pub const DAC_READ_SEARCH = 2;
    pub const FOWNER = 3;
    pub const FSETID = 4;
    pub const KILL = 5;
    pub const SETGID = 6;
    pub const SETUID = 7;
    pub const SETPCAP = 8;
    pub const LINUX_IMMUTABLE = 9;
    pub const NET_BIND_SERVICE = 10;
    pub const NET_BROADCAST = 11;
    pub const NET_ADMIN = 12;
    pub const NET_RAW = 13;
    pub const IPC_LOCK = 14;
    pub const IPC_OWNER = 15;
    pub const SYS_MODULE = 16;
    pub const SYS_RAWIO = 17;
    pub const SYS_CHROOT = 18;
    pub const SYS_PTRACE = 19;
    pub const SYS_PACCT = 20;
    pub const SYS_ADMIN = 21;
    pub const SYS_BOOT = 22;
    pub const SYS_NICE = 23;
    pub const SYS_RESOURCE = 24;
    pub const SYS_TIME = 25;
    pub const SYS_TTY_CONFIG = 26;
    pub const MKNOD = 27;
    pub const LEASE = 28;
    pub const AUDIT_WRITE = 29;
    pub const AUDIT_CONTROL = 30;
    pub const SETFCAP = 31;
    pub const MAC_OVERRIDE = 32;
    pub const MAC_ADMIN = 33;
    pub const SYSLOG = 34;
    pub const WAKE_ALARM = 35;
    pub const BLOCK_SUSPEND = 36;
    pub const AUDIT_READ = 37;
    pub const PERFMON = 38;
    pub const BPF = 39;
    pub const CHECKPOINT_RESTORE = 40;
    pub const LAST_CAP = CHECKPOINT_RESTORE;

    pub fn valid(x: u8) bool {
        return x >= 0 and x <= LAST_CAP;
    }

    pub fn TO_MASK(cap: u8) u32 {
        return @as(u32, 1) << @as(u5, @intCast(cap & 31));
    }

    pub fn TO_INDEX(cap: u8) u8 {
        return cap >> 5;
    }
};

pub const cap_t = extern struct {
    hdrp: *cap_user_header_t,
    datap: *cap_user_data_t,
};

pub const cap_user_header_t = extern struct {
    version: u32,
    pid: usize,
};

pub const cap_user_data_t = extern struct {
    effective: u32,
    permitted: u32,
    inheritable: u32,
};

pub const inotify_event = extern struct {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
    //name: [?]u8,

    // if an event is returned for a directory or file inside the directory being watched
    // returns the name of said directory/file
    // returns `null` if the directory/file is the one being watched
    pub fn getName(self: *const inotify_event) ?[:0]const u8 {
        if (self.len == 0) return null;
        return std.mem.span(@as([*:0]const u8, @ptrCast(self)) + @sizeOf(inotify_event));
    }
};

pub const dirent64 = extern struct {
    ino: u64,
    off: u64,
    reclen: u16,
    type: u8,
    name: u8, // field address is the address of first byte of name https://github.com/ziglang/zig/issues/173
};

pub const dl_phdr_info = extern struct {
    addr: usize,
    name: ?[*:0]const u8,
    phdr: [*]std.elf.Phdr,
    phnum: u16,
};

pub const CPU_SETSIZE = 128;
pub const cpu_set_t = [CPU_SETSIZE / @sizeOf(usize)]usize;
pub const cpu_count_t = std.meta.Int(.unsigned, std.math.log2(CPU_SETSIZE * 8));

pub fn CPU_COUNT(set: cpu_set_t) cpu_count_t {
    var sum: cpu_count_t = 0;
    for (set) |x| {
        sum += @popCount(x);
    }
    return sum;
}

pub const MINSIGSTKSZ = switch (native_arch) {
    .arc,
    .arm,
    .armeb,
    .csky,
    .hexagon,
    .m68k,
    .mips,
    .mipsel,
    .mips64,
    .mips64el,
    .powerpc,
    .powerpcle,
    .riscv32,
    .riscv64,
    .s390x,
    .thumb,
    .thumbeb,
    .x86,
    .x86_64,
    .xtensa,
    => 2048,
    .loongarch64,
    .sparc,
    .sparc64,
    => 4096,
    .aarch64,
    .aarch64_be,
    => 5120,
    .powerpc64,
    .powerpc64le,
    => 8192,
    else => @compileError("MINSIGSTKSZ not defined for this architecture"),
};
pub const SIGSTKSZ = switch (native_arch) {
    .arc,
    .arm,
    .armeb,
    .csky,
    .hexagon,
    .m68k,
    .mips,
    .mipsel,
    .mips64,
    .mips64el,
    .powerpc,
    .powerpcle,
    .riscv32,
    .riscv64,
    .s390x,
    .thumb,
    .thumbeb,
    .x86,
    .x86_64,
    .xtensa,
    => 8192,
    .aarch64,
    .aarch64_be,
    .loongarch64,
    .sparc,
    .sparc64,
    => 16384,
    .powerpc64,
    .powerpc64le,
    => 32768,
    else => @compileError("SIGSTKSZ not defined for this architecture"),
};

pub const SS = struct {
    pub const ONSTACK = 1;
    pub const DISABLE = 2;
    pub const AUTODISARM = 1 << 31;
};

pub const stack_t = if (is_mips)
    // IRIX compatible stack_t
    extern struct {
        sp: [*]u8,
        size: usize,
        flags: i32,
    }
else
    extern struct {
        sp: [*]u8,
        flags: i32,
        size: usize,
    };

pub const sigval = extern union {
    int: i32,
    ptr: *anyopaque,
};

const siginfo_fields_union = extern union {
    pad: [128 - 2 * @sizeOf(c_int) - @sizeOf(c_long)]u8,
    common: extern struct {
        first: extern union {
            piduid: extern struct {
                pid: pid_t,
                uid: uid_t,
            },
            timer: extern struct {
                timerid: i32,
                overrun: i32,
            },
        },
        second: extern union {
            value: sigval,
            sigchld: extern struct {
                status: i32,
                utime: clock_t,
                stime: clock_t,
            },
        },
    },
    sigfault: extern struct {
        addr: *allowzero anyopaque,
        addr_lsb: i16,
        first: extern union {
            addr_bnd: extern struct {
                lower: *anyopaque,
                upper: *anyopaque,
            },
            pkey: u32,
        },
    },
    sigpoll: extern struct {
        band: isize,
        fd: i32,
    },
    sigsys: extern struct {
        call_addr: *anyopaque,
        syscall: i32,
        native_arch: u32,
    },
};

pub const siginfo_t = if (is_mips)
    extern struct {
        signo: i32,
        code: i32,
        errno: i32,
        fields: siginfo_fields_union,
    }
else
    extern struct {
        signo: i32,
        errno: i32,
        code: i32,
        fields: siginfo_fields_union,
    };

// io_uring_params.flags

/// io_context is polled
pub const IORING_SETUP_IOPOLL = 1 << 0;

/// SQ poll thread
pub const IORING_SETUP_SQPOLL = 1 << 1;

/// sq_thread_cpu is valid
pub const IORING_SETUP_SQ_AFF = 1 << 2;

/// app defines CQ size
pub const IORING_SETUP_CQSIZE = 1 << 3;

/// clamp SQ/CQ ring sizes
pub const IORING_SETUP_CLAMP = 1 << 4;

/// attach to existing wq
pub const IORING_SETUP_ATTACH_WQ = 1 << 5;

/// start with ring disabled
pub const IORING_SETUP_R_DISABLED = 1 << 6;

/// continue submit on error
pub const IORING_SETUP_SUBMIT_ALL = 1 << 7;

/// Cooperative task running. When requests complete, they often require
/// forcing the submitter to transition to the kernel to complete. If this
/// flag is set, work will be done when the task transitions anyway, rather
/// than force an inter-processor interrupt reschedule. This avoids interrupting
/// a task running in userspace, and saves an IPI.
pub const IORING_SETUP_COOP_TASKRUN = 1 << 8;

/// If COOP_TASKRUN is set, get notified if task work is available for
/// running and a kernel transition would be needed to run it. This sets
/// IORING_SQ_TASKRUN in the sq ring flags. Not valid with COOP_TASKRUN.
pub const IORING_SETUP_TASKRUN_FLAG = 1 << 9;

/// SQEs are 128 byte
pub const IORING_SETUP_SQE128 = 1 << 10;
/// CQEs are 32 byte
pub const IORING_SETUP_CQE32 = 1 << 11;

/// Only one task is allowed to submit requests
pub const IORING_SETUP_SINGLE_ISSUER = 1 << 12;

/// Defer running task work to get events.
/// Rather than running bits of task work whenever the task transitions
/// try to do it just before it is needed.
pub const IORING_SETUP_DEFER_TASKRUN = 1 << 13;

/// Application provides ring memory
pub const IORING_SETUP_NO_MMAP = 1 << 14;

/// Register the ring fd in itself for use with
/// IORING_REGISTER_USE_REGISTERED_RING; return a registered fd index rather
/// than an fd.
pub const IORING_SETUP_REGISTERED_FD_ONLY = 1 << 15;

/// Removes indirection through the SQ index array.
pub const IORING_SETUP_NO_SQARRAY = 1 << 16;

/// IO submission data structure (Submission Queue Entry)
pub const io_uring_sqe = @import("linux/io_uring_sqe.zig").io_uring_sqe;

pub const IoUring = @import("linux/IoUring.zig");

/// If sqe->file_index is set to this for opcodes that instantiate a new
/// direct descriptor (like openat/openat2/accept), then io_uring will allocate
/// an available direct descriptor instead of having the application pass one
/// in. The picked direct descriptor will be returned in cqe->res, or -ENFILE
/// if the space is full.
/// Available since Linux 5.19
pub const IORING_FILE_INDEX_ALLOC = maxInt(u32);

pub const IOSQE_BIT = enum(u8) {
    FIXED_FILE,
    IO_DRAIN,
    IO_LINK,
    IO_HARDLINK,
    ASYNC,
    BUFFER_SELECT,
    CQE_SKIP_SUCCESS,

    _,
};

// io_uring_sqe.flags

/// use fixed fileset
pub const IOSQE_FIXED_FILE = 1 << @intFromEnum(IOSQE_BIT.FIXED_FILE);

/// issue after inflight IO
pub const IOSQE_IO_DRAIN = 1 << @intFromEnum(IOSQE_BIT.IO_DRAIN);

/// links next sqe
pub const IOSQE_IO_LINK = 1 << @intFromEnum(IOSQE_BIT.IO_LINK);

/// like LINK, but stronger
pub const IOSQE_IO_HARDLINK = 1 << @intFromEnum(IOSQE_BIT.IO_HARDLINK);

/// always go async
pub const IOSQE_ASYNC = 1 << @intFromEnum(IOSQE_BIT.ASYNC);

/// select buffer from buf_group
pub const IOSQE_BUFFER_SELECT = 1 << @intFromEnum(IOSQE_BIT.BUFFER_SELECT);

/// don't post CQE if request succeeded
/// Available since Linux 5.17
pub const IOSQE_CQE_SKIP_SUCCESS = 1 << @intFromEnum(IOSQE_BIT.CQE_SKIP_SUCCESS);

pub const IORING_OP = enum(u8) {
    NOP,
    READV,
    WRITEV,
    FSYNC,
    READ_FIXED,
    WRITE_FIXED,
    POLL_ADD,
    POLL_REMOVE,
    SYNC_FILE_RANGE,
    SENDMSG,
    RECVMSG,
    TIMEOUT,
    TIMEOUT_REMOVE,
    ACCEPT,
    ASYNC_CANCEL,
    LINK_TIMEOUT,
    CONNECT,
    FALLOCATE,
    OPENAT,
    CLOSE,
    FILES_UPDATE,
    STATX,
    READ,
    WRITE,
    FADVISE,
    MADVISE,
    SEND,
    RECV,
    OPENAT2,
    EPOLL_CTL,
    SPLICE,
    PROVIDE_BUFFERS,
    REMOVE_BUFFERS,
    TEE,
    SHUTDOWN,
    RENAMEAT,
    UNLINKAT,
    MKDIRAT,
    SYMLINKAT,
    LINKAT,
    MSG_RING,
    FSETXATTR,
    SETXATTR,
    FGETXATTR,
    GETXATTR,
    SOCKET,
    URING_CMD,
    SEND_ZC,
    SENDMSG_ZC,
    READ_MULTISHOT,
    WAITID,
    FUTEX_WAIT,
    FUTEX_WAKE,
    FUTEX_WAITV,
    FIXED_FD_INSTALL,
    FTRUNCATE,
    BIND,
    LISTEN,
    RECV_ZC,

    _,
};
// io_uring_sqe.uring_cmd_flags (rw_flags in the Zig struct)

/// use registered buffer; pass thig flag along with setting sqe->buf_index.
pub const IORING_URING_CMD_FIXED = 1 << 0;

// io_uring_sqe.fsync_flags (rw_flags in the Zig struct)
pub const IORING_FSYNC_DATASYNC = 1 << 0;

// io_uring_sqe.timeout_flags (rw_flags in the Zig struct)
pub const IORING_TIMEOUT_ABS = 1 << 0;
pub const IORING_TIMEOUT_UPDATE = 1 << 1; // Available since Linux 5.11
pub const IORING_TIMEOUT_BOOTTIME = 1 << 2; // Available since Linux 5.15
pub const IORING_TIMEOUT_REALTIME = 1 << 3; // Available since Linux 5.15
pub const IORING_LINK_TIMEOUT_UPDATE = 1 << 4; // Available since Linux 5.15
pub const IORING_TIMEOUT_ETIME_SUCCESS = 1 << 5; // Available since Linux 5.16
pub const IORING_TIMEOUT_CLOCK_MASK = IORING_TIMEOUT_BOOTTIME | IORING_TIMEOUT_REALTIME;
pub const IORING_TIMEOUT_UPDATE_MASK = IORING_TIMEOUT_UPDATE | IORING_LINK_TIMEOUT_UPDATE;

// io_uring_sqe.splice_flags (rw_flags in the Zig struct)
// extends splice(2) flags
pub const IORING_SPLICE_F_FD_IN_FIXED = 1 << 31;

// POLL_ADD flags.
// Note that since sqe->poll_events (rw_flags in the Zig struct) is the flag space, the command flags for POLL_ADD are stored in sqe->len.

/// Multishot poll. Sets IORING_CQE_F_MORE if the poll handler will continue to report CQEs on behalf of the same SQE.
pub const IORING_POLL_ADD_MULTI = 1 << 0;
/// Update existing poll request, matching sqe->addr as the old user_data field.
pub const IORING_POLL_UPDATE_EVENTS = 1 << 1;
pub const IORING_POLL_UPDATE_USER_DATA = 1 << 2;
pub const IORING_POLL_ADD_LEVEL = 1 << 3;

// ASYNC_CANCEL flags.

/// Cancel all requests that match the given key
pub const IORING_ASYNC_CANCEL_ALL = 1 << 0;
/// Key off 'fd' for cancelation rather than the request 'user_data'.
pub const IORING_ASYNC_CANCEL_FD = 1 << 1;
/// Match any request
pub const IORING_ASYNC_CANCEL_ANY = 1 << 2;
/// 'fd' passed in is a fixed descriptor. Available since Linux 6.0
pub const IORING_ASYNC_CANCEL_FD_FIXED = 1 << 3;

// send/sendmsg and recv/recvmsg flags (sqe->ioprio)

/// If set, instead of first attempting to send or receive and arm poll if that yields an -EAGAIN result,
/// arm poll upfront and skip the initial transfer attempt.
pub const IORING_RECVSEND_POLL_FIRST = 1 << 0;
/// Multishot recv. Sets IORING_CQE_F_MORE if the handler will continue to report CQEs on behalf of the same SQE.
pub const IORING_RECV_MULTISHOT = 1 << 1;
/// Use registered buffers, the index is stored in the buf_index field.
pub const IORING_RECVSEND_FIXED_BUF = 1 << 2;
/// If set, SEND[MSG]_ZC should report the zerocopy usage in cqe.res for the IORING_CQE_F_NOTIF cqe.
pub const IORING_SEND_ZC_REPORT_USAGE = 1 << 3;
/// If set, send or recv will grab as many buffers from the buffer group ID given and send them all.
/// The completion result will be the number of buffers send, with the starting buffer ID in cqe as per usual.
/// The buffers be contigious from the starting buffer ID.
/// Used with IOSQE_BUFFER_SELECT.
pub const IORING_RECVSEND_BUNDLE = 1 << 4;
/// CQE.RES FOR IORING_CQE_F_NOTIF if IORING_SEND_ZC_REPORT_USAGE was requested
pub const IORING_NOTIF_USAGE_ZC_COPIED = 1 << 31;

/// accept flags stored in sqe->iopri
pub const IORING_ACCEPT_MULTISHOT = 1 << 0;

/// IORING_OP_MSG_RING command types, stored in sqe->addr
pub const IORING_MSG_RING_COMMAND = enum(u8) {
    /// pass sqe->len as 'res' and off as user_data
    DATA,
    /// send a registered fd to another ring
    SEND_FD,
};

// io_uring_sqe.msg_ring_flags (rw_flags in the Zig struct)

/// Don't post a CQE to the target ring. Not applicable for IORING_MSG_DATA, obviously.
pub const IORING_MSG_RING_CQE_SKIP = 1 << 0;

/// Pass through the flags from sqe->file_index (splice_fd_in in the zig struct) to cqe->flags */
pub const IORING_MSG_RING_FLAGS_PASS = 1 << 1;

// IO completion data structure (Completion Queue Entry)
pub const io_uring_cqe = extern struct {
    /// io_uring_sqe.data submission passed back
    user_data: u64,

    /// result code for this event
    res: i32,
    flags: u32,

    // Followed by 16 bytes of padding if initialized with IORING_SETUP_CQE32, doubling cqe size

    pub fn err(self: io_uring_cqe) E {
        if (self.res > -4096 and self.res < 0) {
            return @as(E, @enumFromInt(-self.res));
        }
        return .SUCCESS;
    }

    // On successful completion of the provided buffers IO request, the CQE flags field
    // will have IORING_CQE_F_BUFFER set and the selected buffer ID will be indicated by
    // the upper 16-bits of the flags field.
    pub fn buffer_id(self: io_uring_cqe) !u16 {
        if (self.flags & IORING_CQE_F_BUFFER != IORING_CQE_F_BUFFER) {
            return error.NoBufferSelected;
        }
        return @as(u16, @intCast(self.flags >> IORING_CQE_BUFFER_SHIFT));
    }
};

// io_uring_cqe.flags

/// If set, the upper 16 bits are the buffer ID
pub const IORING_CQE_F_BUFFER = 1 << 0;
/// If set, parent SQE will generate more CQE entries.
/// Available since Linux 5.13.
pub const IORING_CQE_F_MORE = 1 << 1;
/// If set, more data to read after socket recv
pub const IORING_CQE_F_SOCK_NONEMPTY = 1 << 2;
/// Set for notification CQEs. Can be used to distinct them from sends.
pub const IORING_CQE_F_NOTIF = 1 << 3;
/// If set, the buffer ID set in the completion will get more completions.
pub const IORING_CQE_F_BUF_MORE = 1 << 4;

pub const IORING_CQE_BUFFER_SHIFT = 16;

/// Magic offsets for the application to mmap the data it needs
pub const IORING_OFF_SQ_RING = 0;
pub const IORING_OFF_CQ_RING = 0x8000000;
pub const IORING_OFF_SQES = 0x10000000;

/// Filled with the offset for mmap(2)
pub const io_sqring_offsets = extern struct {
    /// offset of ring head
    head: u32,

    /// offset of ring tail
    tail: u32,

    /// ring mask value
    ring_mask: u32,

    /// entries in ring
    ring_entries: u32,

    /// ring flags
    flags: u32,

    /// number of sqes not submitted
    dropped: u32,

    /// sqe index array
    array: u32,

    resv1: u32,
    user_addr: u64,
};

// io_sqring_offsets.flags

/// needs io_uring_enter wakeup
pub const IORING_SQ_NEED_WAKEUP = 1 << 0;
/// kernel has cqes waiting beyond the cq ring
pub const IORING_SQ_CQ_OVERFLOW = 1 << 1;
/// task should enter the kernel
pub const IORING_SQ_TASKRUN = 1 << 2;

pub const io_cqring_offsets = extern struct {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv: u32,
    user_addr: u64,
};

// io_cqring_offsets.flags

/// disable eventfd notifications
pub const IORING_CQ_EVENTFD_DISABLED = 1 << 0;

// io_uring_enter flags
pub const IORING_ENTER_GETEVENTS = 1 << 0;
pub const IORING_ENTER_SQ_WAKEUP = 1 << 1;
pub const IORING_ENTER_SQ_WAIT = 1 << 2;
pub const IORING_ENTER_EXT_ARG = 1 << 3;
pub const IORING_ENTER_REGISTERED_RING = 1 << 4;

pub const io_uring_params = extern struct {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [3]u32,
    sq_off: io_sqring_offsets,
    cq_off: io_cqring_offsets,
};

// io_uring_params.features flags

pub const IORING_FEAT_SINGLE_MMAP = 1 << 0;
pub const IORING_FEAT_NODROP = 1 << 1;
pub const IORING_FEAT_SUBMIT_STABLE = 1 << 2;
pub const IORING_FEAT_RW_CUR_POS = 1 << 3;
pub const IORING_FEAT_CUR_PERSONALITY = 1 << 4;
pub const IORING_FEAT_FAST_POLL = 1 << 5;
pub const IORING_FEAT_POLL_32BITS = 1 << 6;
pub const IORING_FEAT_SQPOLL_NONFIXED = 1 << 7;
pub const IORING_FEAT_EXT_ARG = 1 << 8;
pub const IORING_FEAT_NATIVE_WORKERS = 1 << 9;
pub const IORING_FEAT_RSRC_TAGS = 1 << 10;
pub const IORING_FEAT_CQE_SKIP = 1 << 11;
pub const IORING_FEAT_LINKED_FILE = 1 << 12;

// io_uring_register opcodes and arguments
pub const IORING_REGISTER = enum(u32) {
    REGISTER_BUFFERS,
    UNREGISTER_BUFFERS,
    REGISTER_FILES,
    UNREGISTER_FILES,
    REGISTER_EVENTFD,
    UNREGISTER_EVENTFD,
    REGISTER_FILES_UPDATE,
    REGISTER_EVENTFD_ASYNC,
    REGISTER_PROBE,
    REGISTER_PERSONALITY,
    UNREGISTER_PERSONALITY,
    REGISTER_RESTRICTIONS,
    REGISTER_ENABLE_RINGS,

    // extended with tagging
    REGISTER_FILES2,
    REGISTER_FILES_UPDATE2,
    REGISTER_BUFFERS2,
    REGISTER_BUFFERS_UPDATE,

    // set/clear io-wq thread affinities
    REGISTER_IOWQ_AFF,
    UNREGISTER_IOWQ_AFF,

    // set/get max number of io-wq workers
    REGISTER_IOWQ_MAX_WORKERS,

    // register/unregister io_uring fd with the ring
    REGISTER_RING_FDS,
    NREGISTER_RING_FDS,

    // register ring based provide buffer group
    REGISTER_PBUF_RING,
    UNREGISTER_PBUF_RING,

    // sync cancelation API
    REGISTER_SYNC_CANCEL,

    // register a range of fixed file slots for automatic slot allocation
    REGISTER_FILE_ALLOC_RANGE,

    // flag added to the opcode to use a registered ring fd
    IORING_REGISTER_USE_REGISTERED_RING = 1 << 31,

    _,
};

/// io_uring_restriction->opcode values
pub const IOWQ_CATEGORIES = enum(u8) {
    BOUND,
    UNBOUND,
};

/// deprecated, see struct io_uring_rsrc_update
pub const io_uring_files_update = extern struct {
    offset: u32,
    resv: u32,
    fds: u64,
};

/// Register a fully sparse file space, rather than pass in an array of all -1 file descriptors.
pub const IORING_RSRC_REGISTER_SPARSE = 1 << 0;

pub const io_uring_rsrc_register = extern struct {
    nr: u32,
    flags: u32,
    resv2: u64,
    data: u64,
    tags: u64,
};

pub const io_uring_rsrc_update = extern struct {
    offset: u32,
    resv: u32,
    data: u64,
};

pub const io_uring_rsrc_update2 = extern struct {
    offset: u32,
    resv: u32,
    data: u64,
    tags: u64,
    nr: u32,
    resv2: u32,
};

pub const io_uring_notification_slot = extern struct {
    tag: u64,
    resv: [3]u64,
};

pub const io_uring_notification_register = extern struct {
    nr_slots: u32,
    resv: u32,
    resv2: u64,
    data: u64,
    resv3: u64,
};

/// Skip updating fd indexes set to this value in the fd table */
pub const IORING_REGISTER_FILES_SKIP = -2;

pub const IO_URING_OP_SUPPORTED = 1 << 0;

pub const io_uring_probe_op = extern struct {
    op: IORING_OP,
    resv: u8,
    /// IO_URING_OP_* flags
    flags: u16,
    resv2: u32,

    pub fn is_supported(self: @This()) bool {
        return self.flags & IO_URING_OP_SUPPORTED != 0;
    }
};

pub const io_uring_probe = extern struct {
    /// Last opcode supported
    last_op: IORING_OP,
    /// Length of ops[] array below
    ops_len: u8,
    resv: u16,
    resv2: [3]u32,
    ops: [256]io_uring_probe_op,

    /// Is the operation supported on the running kernel.
    pub fn is_supported(self: @This(), op: IORING_OP) bool {
        const i = @intFromEnum(op);
        if (i > @intFromEnum(self.last_op) or i >= self.ops_len)
            return false;
        return self.ops[i].is_supported();
    }
};

pub const io_uring_restriction = extern struct {
    opcode: IORING_RESTRICTION,
    arg: extern union {
        /// IORING_RESTRICTION_REGISTER_OP
        register_op: IORING_REGISTER,

        /// IORING_RESTRICTION_SQE_OP
        sqe_op: IORING_OP,

        /// IORING_RESTRICTION_SQE_FLAGS_*
        sqe_flags: u8,
    },
    resv: u8,
    resv2: [3]u32,
};

/// io_uring_restriction->opcode values
pub const IORING_RESTRICTION = enum(u16) {
    /// Allow an io_uring_register(2) opcode
    REGISTER_OP = 0,

    /// Allow an sqe opcode
    SQE_OP = 1,

    /// Allow sqe flags
    SQE_FLAGS_ALLOWED = 2,

    /// Require sqe flags (these flags must be set on each submission)
    SQE_FLAGS_REQUIRED = 3,

    _,
};

pub const IO_URING_SOCKET_OP = enum(u16) {
    SIOCIN = 0,
    SIOCOUTQ = 1,
    GETSOCKOPT = 2,
    SETSOCKOPT = 3,
};

pub const io_uring_buf = extern struct {
    addr: u64,
    len: u32,
    bid: u16,
    resv: u16,
};

pub const io_uring_buf_ring = extern struct {
    resv1: u64,
    resv2: u32,
    resv3: u16,
    tail: u16,
};

/// argument for IORING_(UN)REGISTER_PBUF_RING
pub const io_uring_buf_reg = extern struct {
    ring_addr: u64,
    ring_entries: u32,
    bgid: u16,
    flags: Flags,
    resv: [3]u64,

    pub const Flags = packed struct {
        _0: u1 = 0,
        /// Incremental buffer consumption.
        inc: bool,
        _: u14 = 0,
    };
};

pub const io_uring_getevents_arg = extern struct {
    sigmask: u64,
    sigmask_sz: u32,
    pad: u32,
    ts: u64,
};

/// Argument for IORING_REGISTER_SYNC_CANCEL
pub const io_uring_sync_cancel_reg = extern struct {
    addr: u64,
    fd: i32,
    flags: u32,
    timeout: kernel_timespec,
    pad: [4]u64,
};

/// Argument for IORING_REGISTER_FILE_ALLOC_RANGE
/// The range is specified as [off, off + len)
pub const io_uring_file_index_range = extern struct {
    off: u32,
    len: u32,
    resv: u64,
};

pub const io_uring_recvmsg_out = extern struct {
    namelen: u32,
    controllen: u32,
    payloadlen: u32,
    flags: u32,
};

pub const utsname = extern struct {
    sysname: [64:0]u8,
    nodename: [64:0]u8,
    release: [64:0]u8,
    version: [64:0]u8,
    machine: [64:0]u8,
    domainname: [64:0]u8,
};
pub const HOST_NAME_MAX = 64;

pub const STATX_TYPE = 0x0001;
pub const STATX_MODE = 0x0002;
pub const STATX_NLINK = 0x0004;
pub const STATX_UID = 0x0008;
pub const STATX_GID = 0x0010;
pub const STATX_ATIME = 0x0020;
pub const STATX_MTIME = 0x0040;
pub const STATX_CTIME = 0x0080;
pub const STATX_INO = 0x0100;
pub const STATX_SIZE = 0x0200;
pub const STATX_BLOCKS = 0x0400;
pub const STATX_BASIC_STATS = 0x07ff;

pub const STATX_BTIME = 0x0800;

pub const STATX_ATTR_COMPRESSED = 0x0004;
pub const STATX_ATTR_IMMUTABLE = 0x0010;
pub const STATX_ATTR_APPEND = 0x0020;
pub const STATX_ATTR_NODUMP = 0x0040;
pub const STATX_ATTR_ENCRYPTED = 0x0800;
pub const STATX_ATTR_AUTOMOUNT = 0x1000;

pub const statx_timestamp = extern struct {
    sec: i64,
    nsec: u32,
    __pad1: u32,
};

/// Renamed to `Statx` to not conflict with the `statx` function.
pub const Statx = extern struct {
    /// Mask of bits indicating filled fields
    mask: u32,

    /// Block size for filesystem I/O
    blksize: u32,

    /// Extra file attribute indicators
    attributes: u64,

    /// Number of hard links
    nlink: u32,

    /// User ID of owner
    uid: uid_t,

    /// Group ID of owner
    gid: gid_t,

    /// File type and mode
    mode: u16,
    __pad1: u16,

    /// Inode number
    ino: u64,

    /// Total size in bytes
    size: u64,

    /// Number of 512B blocks allocated
    blocks: u64,

    /// Mask to show what's supported in `attributes`.
    attributes_mask: u64,

    /// Last access file timestamp
    atime: statx_timestamp,

    /// Creation file timestamp
    btime: statx_timestamp,

    /// Last status change file timestamp
    ctime: statx_timestamp,

    /// Last modification file timestamp
    mtime: statx_timestamp,

    /// Major ID, if this file represents a device.
    rdev_major: u32,

    /// Minor ID, if this file represents a device.
    rdev_minor: u32,

    /// Major ID of the device containing the filesystem where this file resides.
    dev_major: u32,

    /// Minor ID of the device containing the filesystem where this file resides.
    dev_minor: u32,

    __pad2: [14]u64,
};

pub const addrinfo = extern struct {
    flags: AI,
    family: i32,
    socktype: i32,
    protocol: i32,
    addrlen: socklen_t,
    addr: ?*sockaddr,
    canonname: ?[*:0]u8,
    next: ?*addrinfo,
};

pub const AI = packed struct(u32) {
    PASSIVE: bool = false,
    CANONNAME: bool = false,
    NUMERICHOST: bool = false,
    V4MAPPED: bool = false,
    ALL: bool = false,
    ADDRCONFIG: bool = false,
    _6: u4 = 0,
    NUMERICSERV: bool = false,
    _: u21 = 0,
};

pub const IPPORT_RESERVED = 1024;

pub const IPPROTO = struct {
    pub const IP = 0;
    pub const HOPOPTS = 0;
    pub const ICMP = 1;
    pub const IGMP = 2;
    pub const IPIP = 4;
    pub const TCP = 6;
    pub const EGP = 8;
    pub const PUP = 12;
    pub const UDP = 17;
    pub const IDP = 22;
    pub const TP = 29;
    pub const DCCP = 33;
    pub const IPV6 = 41;
    pub const ROUTING = 43;
    pub const FRAGMENT = 44;
    pub const RSVP = 46;
    pub const GRE = 47;
    pub const ESP = 50;
    pub const AH = 51;
    pub const ICMPV6 = 58;
    pub const NONE = 59;
    pub const DSTOPTS = 60;
    pub const MTP = 92;
    pub const BEETPH = 94;
    pub const ENCAP = 98;
    pub const PIM = 103;
    pub const COMP = 108;
    pub const SCTP = 132;
    pub const MH = 135;
    pub const UDPLITE = 136;
    pub const MPLS = 137;
    pub const RAW = 255;
    pub const MAX = 256;
};

pub const RR = struct {
    pub const A = 1;
    pub const CNAME = 5;
    pub const AAAA = 28;
};

pub const tcp_repair_opt = extern struct {
    opt_code: u32,
    opt_val: u32,
};

pub const tcp_repair_window = extern struct {
    snd_wl1: u32,
    snd_wnd: u32,
    max_window: u32,
    rcv_wnd: u32,
    rcv_wup: u32,
};

pub const TcpRepairOption = enum {
    TCP_NO_QUEUE,
    TCP_RECV_QUEUE,
    TCP_SEND_QUEUE,
    TCP_QUEUES_NR,
};

/// why fastopen failed from client perspective
pub const tcp_fastopen_client_fail = enum {
    /// catch-all
    TFO_STATUS_UNSPEC,
    /// if not in TFO_CLIENT_NO_COOKIE mode
    TFO_COOKIE_UNAVAILABLE,
    /// SYN-ACK did not ack SYN data
    TFO_DATA_NOT_ACKED,
    /// SYN-ACK did not ack SYN data after timeout
    TFO_SYN_RETRANSMITTED,
};

/// for TCP_INFO socket option
pub const TCPI_OPT_TIMESTAMPS = 1;
pub const TCPI_OPT_SACK = 2;
pub const TCPI_OPT_WSCALE = 4;
/// ECN was negotiated at TCP session init
pub const TCPI_OPT_ECN = 8;
/// we received at least one packet with ECT
pub const TCPI_OPT_ECN_SEEN = 16;
/// SYN-ACK acked data in SYN sent or rcvd
pub const TCPI_OPT_SYN_DATA = 32;

pub const nfds_t = usize;
pub const pollfd = extern struct {
    fd: fd_t,
    events: i16,
    revents: i16,
};

pub const POLL = struct {
    pub const IN = 0x001;
    pub const PRI = 0x002;
    pub const OUT = 0x004;
    pub const ERR = 0x008;
    pub const HUP = 0x010;
    pub const NVAL = 0x020;
    pub const RDNORM = 0x040;
    pub const RDBAND = 0x080;
};

pub const HUGETLB_FLAG_ENCODE_SHIFT = 26;
pub const HUGETLB_FLAG_ENCODE_MASK = 0x3f;
pub const HUGETLB_FLAG_ENCODE_64KB = 16 << HUGETLB_FLAG_ENCODE_SHIFT;
pub const HUGETLB_FLAG_ENCODE_512KB = 19 << HUGETLB_FLAG_ENCODE_SHIFT;
pub const HUGETLB_FLAG_ENCODE_1MB = 20 << HUGETLB_FLAG_ENCODE_SHIFT;
pub const HUGETLB_FLAG_ENCODE_2MB = 21 << HUGETLB_FLAG_ENCODE_SHIFT;
pub const HUGETLB_FLAG_ENCODE_8MB = 23 << HUGETLB_FLAG_ENCODE_SHIFT;
pub const HUGETLB_FLAG_ENCODE_16MB = 24 << HUGETLB_FLAG_ENCODE_SHIFT;
pub const HUGETLB_FLAG_ENCODE_32MB = 25 << HUGETLB_FLAG_ENCODE_SHIFT;
pub const HUGETLB_FLAG_ENCODE_256MB = 28 << HUGETLB_FLAG_ENCODE_SHIFT;
pub const HUGETLB_FLAG_ENCODE_512MB = 29 << HUGETLB_FLAG_ENCODE_SHIFT;
pub const HUGETLB_FLAG_ENCODE_1GB = 30 << HUGETLB_FLAG_ENCODE_SHIFT;
pub const HUGETLB_FLAG_ENCODE_2GB = 31 << HUGETLB_FLAG_ENCODE_SHIFT;
pub const HUGETLB_FLAG_ENCODE_16GB = 34 << HUGETLB_FLAG_ENCODE_SHIFT;

pub const MFD = struct {
    pub const CLOEXEC = 0x0001;
    pub const ALLOW_SEALING = 0x0002;
    pub const HUGETLB = 0x0004;
    pub const ALL_FLAGS = CLOEXEC | ALLOW_SEALING | HUGETLB;

    pub const HUGE_SHIFT = HUGETLB_FLAG_ENCODE_SHIFT;
    pub const HUGE_MASK = HUGETLB_FLAG_ENCODE_MASK;
    pub const HUGE_64KB = HUGETLB_FLAG_ENCODE_64KB;
    pub const HUGE_512KB = HUGETLB_FLAG_ENCODE_512KB;
    pub const HUGE_1MB = HUGETLB_FLAG_ENCODE_1MB;
    pub const HUGE_2MB = HUGETLB_FLAG_ENCODE_2MB;
    pub const HUGE_8MB = HUGETLB_FLAG_ENCODE_8MB;
    pub const HUGE_16MB = HUGETLB_FLAG_ENCODE_16MB;
    pub const HUGE_32MB = HUGETLB_FLAG_ENCODE_32MB;
    pub const HUGE_256MB = HUGETLB_FLAG_ENCODE_256MB;
    pub const HUGE_512MB = HUGETLB_FLAG_ENCODE_512MB;
    pub const HUGE_1GB = HUGETLB_FLAG_ENCODE_1GB;
    pub const HUGE_2GB = HUGETLB_FLAG_ENCODE_2GB;
    pub const HUGE_16GB = HUGETLB_FLAG_ENCODE_16GB;
};

pub const rusage = extern struct {
    utime: timeval,
    stime: timeval,
    maxrss: isize,
    ixrss: isize,
    idrss: isize,
    isrss: isize,
    minflt: isize,
    majflt: isize,
    nswap: isize,
    inblock: isize,
    oublock: isize,
    msgsnd: isize,
    msgrcv: isize,
    nsignals: isize,
    nvcsw: isize,
    nivcsw: isize,
    __reserved: [16]isize = [1]isize{0} ** 16,

    pub const SELF = 0;
    pub const CHILDREN = -1;
    pub const THREAD = 1;
};

pub const NCC = if (is_ppc) 10 else 8;
pub const NCCS = if (is_mips) 32 else if (is_ppc) 19 else if (is_sparc) 17 else 32;

pub const speed_t = if (is_ppc) enum(c_uint) {
    B0 = 0x0000000,
    B50 = 0x0000001,
    B75 = 0x0000002,
    B110 = 0x0000003,
    B134 = 0x0000004,
    B150 = 0x0000005,
    B200 = 0x0000006,
    B300 = 0x0000007,
    B600 = 0x0000008,
    B1200 = 0x0000009,
    B1800 = 0x000000a,
    B2400 = 0x000000b,
    B4800 = 0x000000c,
    B9600 = 0x000000d,
    B19200 = 0x000000e,
    B38400 = 0x000000f,

    B57600 = 0x00000010,
    B115200 = 0x00000011,
    B230400 = 0x00000012,
    B460800 = 0x00000013,
    B500000 = 0x00000014,
    B576000 = 0x00000015,
    B921600 = 0x00000016,
    B1000000 = 0x00000017,
    B1152000 = 0x00000018,
    B1500000 = 0x00000019,
    B2000000 = 0x0000001a,
    B2500000 = 0x0000001b,
    B3000000 = 0x0000001c,
    B3500000 = 0x0000001d,
    B4000000 = 0x0000001e,

    pub const EXTA = speed_t.B19200;
    pub const EXTB = speed_t.B38400;
} else if (is_sparc) enum(c_uint) {
    B0 = 0x0000000,
    B50 = 0x0000001,
    B75 = 0x0000002,
    B110 = 0x0000003,
    B134 = 0x0000004,
    B150 = 0x0000005,
    B200 = 0x0000006,
    B300 = 0x0000007,
    B600 = 0x0000008,
    B1200 = 0x0000009,
    B1800 = 0x000000a,
    B2400 = 0x000000b,
    B4800 = 0x000000c,
    B9600 = 0x000000d,
    B19200 = 0x000000e,
    B38400 = 0x000000f,

    B57600 = 0x00001001,
    B115200 = 0x00001002,
    B230400 = 0x00001003,
    B460800 = 0x00001004,
    B76800 = 0x00001005,
    B153600 = 0x00001006,
    B307200 = 0x00001007,
    B614400 = 0x00001008,
    B921600 = 0x00001009,
    B500000 = 0x0000100a,
    B576000 = 0x0000100b,
    B1000000 = 0x0000100c,
    B1152000 = 0x0000100d,
    B1500000 = 0x0000100e,
    B2000000 = 0x0000100f,

    pub const EXTA = speed_t.B19200;
    pub const EXTB = speed_t.B38400;
} else enum(c_uint) {
    B0 = 0x0000000,
    B50 = 0x0000001,
    B75 = 0x0000002,
    B110 = 0x0000003,
    B134 = 0x0000004,
    B150 = 0x0000005,
    B200 = 0x0000006,
    B300 = 0x0000007,
    B600 = 0x0000008,
    B1200 = 0x0000009,
    B1800 = 0x000000a,
    B2400 = 0x000000b,
    B4800 = 0x000000c,
    B9600 = 0x000000d,
    B19200 = 0x000000e,
    B38400 = 0x000000f,

    B57600 = 0x00001001,
    B115200 = 0x00001002,
    B230400 = 0x00001003,
    B460800 = 0x00001004,
    B500000 = 0x00001005,
    B576000 = 0x00001006,
    B921600 = 0x00001007,
    B1000000 = 0x00001008,
    B1152000 = 0x00001009,
    B1500000 = 0x0000100a,
    B2000000 = 0x0000100b,
    B2500000 = 0x0000100c,
    B3000000 = 0x0000100d,
    B3500000 = 0x0000100e,
    B4000000 = 0x0000100f,

    pub const EXTA = speed_t.B19200;
    pub const EXTB = speed_t.B38400;
};

pub const tcflag_t = if (native_arch == .sparc) c_ulong else c_uint;

pub const tc_iflag_t = if (is_ppc) packed struct(tcflag_t) {
    IGNBRK: bool = false,
    BRKINT: bool = false,
    IGNPAR: bool = false,
    PARMRK: bool = false,
    INPCK: bool = false,
    ISTRIP: bool = false,
    INLCR: bool = false,
    IGNCR: bool = false,
    ICRNL: bool = false,
    IXON: bool = false,
    IXOFF: bool = false,
    IXANY: bool = false,
    IUCLC: bool = false,
    IMAXBEL: bool = false,
    IUTF8: bool = false,
    _15: u17 = 0,
} else packed struct(tcflag_t) {
    IGNBRK: bool = false,
    BRKINT: bool = false,
    IGNPAR: bool = false,
    PARMRK: bool = false,
    INPCK: bool = false,
    ISTRIP: bool = false,
    INLCR: bool = false,
    IGNCR: bool = false,
    ICRNL: bool = false,
    IUCLC: bool = false,
    IXON: bool = false,
    IXANY: bool = false,
    IXOFF: bool = false,
    IMAXBEL: bool = false,
    IUTF8: bool = false,
    _15: u17 = 0,
};

pub const NLDLY = if (is_ppc) enum(u2) {
    NL0 = 0,
    NL1 = 1,
    NL2 = 2,
    NL3 = 3,
} else enum(u1) ```
