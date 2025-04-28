```
ST_LOOP = 11;
pub const IPV6_ADD_MEMBERSHIP = 12;
pub const IPV6_DROP_MEMBERSHIP = 13;
pub const IPV6_DONTFRAG = 14;
pub const IPV6_PKTINFO = 19;
pub const IPV6_HOPLIMIT = 21;
pub const IPV6_PROTECTION_LEVEL = 23;
pub const IPV6_RECVIF = 24;
pub const IPV6_RECVDSTADDR = 25;
pub const IPV6_CHECKSUM = 26;
pub const IPV6_V6ONLY = 27;
pub const IPV6_IFLIST = 28;
pub const IPV6_ADD_IFLIST = 29;
pub const IPV6_DEL_IFLIST = 30;
pub const IPV6_UNICAST_IF = 31;
pub const IPV6_RTHDR = 32;
pub const IPV6_GET_IFLIST = 33;
pub const IPV6_RECVRTHDR = 38;
pub const IPV6_TCLASS = 39;
pub const IPV6_RECVTCLASS = 40;
pub const IPV6_ECN = 50;
pub const IPV6_PKTINFO_EX = 51;
pub const IPV6_WFP_REDIRECT_RECORDS = 60;
pub const IPV6_WFP_REDIRECT_CONTEXT = 70;
pub const IPV6_MTU_DISCOVER = 71;
pub const IPV6_MTU = 72;
pub const IPV6_NRT_INTERFACE = 74;
pub const IPV6_RECVERR = 75;
pub const IPV6_USER_MTU = 76;
pub const IP_UNSPECIFIED_HOP_LIMIT = -1;
pub const PROTECTION_LEVEL_UNRESTRICTED = 10;
pub const PROTECTION_LEVEL_EDGERESTRICTED = 20;
pub const PROTECTION_LEVEL_RESTRICTED = 30;
pub const INET_ADDRSTRLEN = 22;
pub const INET6_ADDRSTRLEN = 65;

pub const TCP = struct {
    pub const NODELAY = 1;
    pub const EXPEDITED_1122 = 2;
    pub const OFFLOAD_NO_PREFERENCE = 0;
    pub const OFFLOAD_NOT_PREFERRED = 1;
    pub const OFFLOAD_PREFERRED = 2;
    pub const KEEPALIVE = 3;
    pub const MAXSEG = 4;
    pub const MAXRT = 5;
    pub const STDURG = 6;
    pub const NOURG = 7;
    pub const ATMARK = 8;
    pub const NOSYNRETRIES = 9;
    pub const TIMESTAMPS = 10;
    pub const OFFLOAD_PREFERENCE = 11;
    pub const CONGESTION_ALGORITHM = 12;
    pub const DELAY_FIN_ACK = 13;
    pub const MAXRTMS = 14;
    pub const FASTOPEN = 15;
    pub const KEEPCNT = 16;
    pub const KEEPINTVL = 17;
    pub const FAIL_CONNECT_ON_ICMP_ERROR = 18;
    pub const ICMP_ERROR_INFO = 19;
    pub const BSDURGENT = 28672;
};

pub const UDP_SEND_MSG_SIZE = 2;
pub const UDP_RECV_MAX_COALESCED_SIZE = 3;
pub const UDP_COALESCED_INFO = 3;

pub const AF = struct {
    pub const UNSPEC = 0;
    pub const UNIX = 1;
    pub const INET = 2;
    pub const IMPLINK = 3;
    pub const PUP = 4;
    pub const CHAOS = 5;
    pub const NS = 6;
    pub const IPX = 6;
    pub const ISO = 7;
    pub const ECMA = 8;
    pub const DATAKIT = 9;
    pub const CCITT = 10;
    pub const SNA = 11;
    pub const DECnet = 12;
    pub const DLI = 13;
    pub const LAT = 14;
    pub const HYLINK = 15;
    pub const APPLETALK = 16;
    pub const NETBIOS = 17;
    pub const VOICEVIEW = 18;
    pub const FIREFOX = 19;
    pub const UNKNOWN1 = 20;
    pub const BAN = 21;
    pub const ATM = 22;
    pub const INET6 = 23;
    pub const CLUSTER = 24;
    pub const @"12844" = 25;
    pub const IRDA = 26;
    pub const NETDES = 28;
    pub const MAX = 29;
    pub const TCNPROCESS = 29;
    pub const TCNMESSAGE = 30;
    pub const ICLFXBM = 31;
    pub const LINK = 33;
    pub const HYPERV = 34;
};

pub const SOCK = struct {
    pub const STREAM = 1;
    pub const DGRAM = 2;
    pub const RAW = 3;
    pub const RDM = 4;
    pub const SEQPACKET = 5;

    /// WARNING: this flag is not supported by windows socket functions directly,
    ///          it is only supported by std.os.socket. Be sure that this value does
    ///          not share any bits with any of the `SOCK` values.
    pub const CLOEXEC = 0x10000;
    /// WARNING: this flag is not supported by windows socket functions directly,
    ///          it is only supported by std.os.socket. Be sure that this value does
    ///          not share any bits with any of the `SOCK` values.
    pub const NONBLOCK = 0x20000;
};

pub const SOL = struct {
    pub const IRLMP = 255;
    pub const SOCKET = 65535;
};

pub const SO = struct {
    pub const DEBUG = 1;
    pub const ACCEPTCONN = 2;
    pub const REUSEADDR = 4;
    pub const KEEPALIVE = 8;
    pub const DONTROUTE = 16;
    pub const BROADCAST = 32;
    pub const USELOOPBACK = 64;
    pub const LINGER = 128;
    pub const OOBINLINE = 256;
    pub const SNDBUF = 4097;
    pub const RCVBUF = 4098;
    pub const SNDLOWAT = 4099;
    pub const RCVLOWAT = 4100;
    pub const SNDTIMEO = 4101;
    pub const RCVTIMEO = 4102;
    pub const ERROR = 4103;
    pub const TYPE = 4104;
    pub const BSP_STATE = 4105;
    pub const GROUP_ID = 8193;
    pub const GROUP_PRIORITY = 8194;
    pub const MAX_MSG_SIZE = 8195;
    pub const CONDITIONAL_ACCEPT = 12290;
    pub const PAUSE_ACCEPT = 12291;
    pub const COMPARTMENT_ID = 12292;
    pub const RANDOMIZE_PORT = 12293;
    pub const PORT_SCALABILITY = 12294;
    pub const REUSE_UNICASTPORT = 12295;
    pub const REUSE_MULTICASTPORT = 12296;
    pub const ORIGINAL_DST = 12303;
    pub const PROTOCOL_INFOA = 8196;
    pub const PROTOCOL_INFOW = 8197;
    pub const CONNDATA = 28672;
    pub const CONNOPT = 28673;
    pub const DISCDATA = 28674;
    pub const DISCOPT = 28675;
    pub const CONNDATALEN = 28676;
    pub const CONNOPTLEN = 28677;
    pub const DISCDATALEN = 28678;
    pub const DISCOPTLEN = 28679;
    pub const OPENTYPE = 28680;
    pub const SYNCHRONOUS_ALERT = 16;
    pub const SYNCHRONOUS_NONALERT = 32;
    pub const MAXDG = 28681;
    pub const MAXPATHDG = 28682;
    pub const UPDATE_ACCEPT_CONTEXT = 28683;
    pub const CONNECT_TIME = 28684;
    pub const UPDATE_CONNECT_CONTEXT = 28688;
};

pub const WSK_SO_BASE = 16384;
pub const IOC_UNIX = 0;
pub const IOC_WS2 = 134217728;
pub const IOC_PROTOCOL = 268435456;
pub const IOC_VENDOR = 402653184;
pub const SIO_GET_EXTENSION_FUNCTION_POINTER = IOC_OUT | IOC_IN | IOC_WS2 | 6;
pub const SIO_BSP_HANDLE = IOC_OUT | IOC_WS2 | 27;
pub const SIO_BSP_HANDLE_SELECT = IOC_OUT | IOC_WS2 | 28;
pub const SIO_BSP_HANDLE_POLL = IOC_OUT | IOC_WS2 | 29;
pub const SIO_BASE_HANDLE = IOC_OUT | IOC_WS2 | 34;
pub const IPPORT_TCPMUX = 1;
pub const IPPORT_ECHO = 7;
pub const IPPORT_DISCARD = 9;
pub const IPPORT_SYSTAT = 11;
pub const IPPORT_DAYTIME = 13;
pub const IPPORT_NETSTAT = 15;
pub const IPPORT_QOTD = 17;
pub const IPPORT_MSP = 18;
pub const IPPORT_CHARGEN = 19;
pub const IPPORT_FTP_DATA = 20;
pub const IPPORT_FTP = 21;
pub const IPPORT_TELNET = 23;
pub const IPPORT_SMTP = 25;
pub const IPPORT_TIMESERVER = 37;
pub const IPPORT_NAMESERVER = 42;
pub const IPPORT_WHOIS = 43;
pub const IPPORT_MTP = 57;
pub const IPPORT_TFTP = 69;
pub const IPPORT_RJE = 77;
pub const IPPORT_FINGER = 79;
pub const IPPORT_TTYLINK = 87;
pub const IPPORT_SUPDUP = 95;
pub const IPPORT_POP3 = 110;
pub const IPPORT_NTP = 123;
pub const IPPORT_EPMAP = 135;
pub const IPPORT_NETBIOS_NS = 137;
pub const IPPORT_NETBIOS_DGM = 138;
pub const IPPORT_NETBIOS_SSN = 139;
pub const IPPORT_IMAP = 143;
pub const IPPORT_SNMP = 161;
pub const IPPORT_SNMP_TRAP = 162;
pub const IPPORT_IMAP3 = 220;
pub const IPPORT_LDAP = 389;
pub const IPPORT_HTTPS = 443;
pub const IPPORT_MICROSOFT_DS = 445;
pub const IPPORT_EXECSERVER = 512;
pub const IPPORT_LOGINSERVER = 513;
pub const IPPORT_CMDSERVER = 514;
pub const IPPORT_EFSSERVER = 520;
pub const IPPORT_BIFFUDP = 512;
pub const IPPORT_WHOSERVER = 513;
pub const IPPORT_ROUTESERVER = 520;
pub const IPPORT_RESERVED = 1024;
pub const IPPORT_REGISTERED_MAX = 49151;
pub const IPPORT_DYNAMIC_MIN = 49152;
pub const IPPORT_DYNAMIC_MAX = 65535;
pub const IN_CLASSA_NET = 4278190080;
pub const IN_CLASSA_NSHIFT = 24;
pub const IN_CLASSA_HOST = 16777215;
pub const IN_CLASSA_MAX = 128;
pub const IN_CLASSB_NET = 4294901760;
pub const IN_CLASSB_NSHIFT = 16;
pub const IN_CLASSB_HOST = 65535;
pub const IN_CLASSB_MAX = 65536;
pub const IN_CLASSC_NET = 4294967040;
pub const IN_CLASSC_NSHIFT = 8;
pub const IN_CLASSC_HOST = 255;
pub const IN_CLASSD_NET = 4026531840;
pub const IN_CLASSD_NSHIFT = 28;
pub const IN_CLASSD_HOST = 268435455;
pub const INADDR_LOOPBACK = 2130706433;
pub const INADDR_NONE = 4294967295;
pub const IOCPARM_MASK = 127;
pub const IOC_VOID = 536870912;
pub const IOC_OUT = 1073741824;
pub const IOC_IN = 2147483648;

pub const MSG = struct {
    pub const TRUNC = 256;
    pub const CTRUNC = 512;
    pub const BCAST = 1024;
    pub const MCAST = 2048;
    pub const ERRQUEUE = 4096;

    pub const PEEK = 2;
    pub const WAITALL = 8;
    pub const PUSH_IMMEDIATE = 32;
    pub const PARTIAL = 32768;
    pub const INTERRUPT = 16;
    pub const MAXIOVLEN = 16;
};

pub const AI = packed struct(u32) {
    PASSIVE: bool = false,
    CANONNAME: bool = false,
    NUMERICHOST: bool = false,
    NUMERICSERV: bool = false,
    DNS_ONLY: bool = false,
    _5: u3 = 0,
    ALL: bool = false,
    _9: u1 = 0,
    ADDRCONFIG: bool = false,
    V4MAPPED: bool = false,
    _12: u2 = 0,
    NON_AUTHORITATIVE: bool = false,
    SECURE: bool = false,
    RETURN_PREFERRED_NAMES: bool = false,
    FQDN: bool = false,
    FILESERVER: bool = false,
    DISABLE_IDN_ENCODING: bool = false,
    _20: u10 = 0,
    RESOLUTION_HANDLE: bool = false,
    EXTENDED: bool = false,
};

pub const FIONBIO = -2147195266;
pub const ADDRINFOEX_VERSION_2 = 2;
pub const ADDRINFOEX_VERSION_3 = 3;
pub const ADDRINFOEX_VERSION_4 = 4;
pub const NS_ALL = 0;
pub const NS_SAP = 1;
pub const NS_NDS = 2;
pub const NS_PEER_BROWSE = 3;
pub const NS_SLP = 5;
pub const NS_DHCP = 6;
pub const NS_TCPIP_LOCAL = 10;
pub const NS_TCPIP_HOSTS = 11;
pub const NS_DNS = 12;
pub const NS_NETBT = 13;
pub const NS_WINS = 14;
pub const NS_NLA = 15;
pub const NS_NBP = 20;
pub const NS_MS = 30;
pub const NS_STDA = 31;
pub const NS_NTDS = 32;
pub const NS_EMAIL = 37;
pub const NS_X500 = 40;
pub const NS_NIS = 41;
pub const NS_NISPLUS = 42;
pub const NS_WRQ = 50;
pub const NS_NETDES = 60;
pub const NI_NOFQDN = 1;
pub const NI_NUMERICHOST = 2;
pub const NI_NAMEREQD = 4;
pub const NI_NUMERICSERV = 8;
pub const NI_DGRAM = 16;
pub const NI_MAXHOST = 1025;
pub const NI_MAXSERV = 32;
pub const INCL_WINSOCK_API_PROTOTYPES = 1;
pub const INCL_WINSOCK_API_TYPEDEFS = 0;
pub const FD_SETSIZE = 64;
pub const IMPLINK_IP = 155;
pub const IMPLINK_LOWEXPER = 156;
pub const IMPLINK_HIGHEXPER = 158;
pub const WSADESCRIPTION_LEN = 256;
pub const WSASYS_STATUS_LEN = 128;
pub const SOCKET_ERROR = -1;
pub const FROM_PROTOCOL_INFO = -1;
pub const PVD_CONFIG = 12289;
pub const SOMAXCONN = 2147483647;
pub const MAXGETHOSTSTRUCT = 1024;
pub const FD_READ_BIT = 0;
pub const FD_WRITE_BIT = 1;
pub const FD_OOB_BIT = 2;
pub const FD_ACCEPT_BIT = 3;
pub const FD_CONNECT_BIT = 4;
pub const FD_CLOSE_BIT = 5;
pub const FD_QOS_BIT = 6;
pub const FD_GROUP_QOS_BIT = 7;
pub const FD_ROUTING_INTERFACE_CHANGE_BIT = 8;
pub const FD_ADDRESS_LIST_CHANGE_BIT = 9;
pub const FD_MAX_EVENTS = 10;
pub const CF_ACCEPT = 0;
pub const CF_REJECT = 1;
pub const CF_DEFER = 2;
pub const SD_RECEIVE = 0;
pub const SD_SEND = 1;
pub const SD_BOTH = 2;
pub const SG_UNCONSTRAINED_GROUP = 1;
pub const SG_CONSTRAINED_GROUP = 2;
pub const MAX_PROTOCOL_CHAIN = 7;
pub const BASE_PROTOCOL = 1;
pub const LAYERED_PROTOCOL = 0;
pub const WSAPROTOCOL_LEN = 255;
pub const PFL_MULTIPLE_PROTO_ENTRIES = 1;
pub const PFL_RECOMMENDED_PROTO_ENTRY = 2;
pub const PFL_HIDDEN = 4;
pub const PFL_MATCHES_PROTOCOL_ZERO = 8;
pub const PFL_NETWORKDIRECT_PROVIDER = 16;
pub const XP1_CONNECTIONLESS = 1;
pub const XP1_GUARANTEED_DELIVERY = 2;
pub const XP1_GUARANTEED_ORDER = 4;
pub const XP1_MESSAGE_ORIENTED = 8;
pub const XP1_PSEUDO_STREAM = 16;
pub const XP1_GRACEFUL_CLOSE = 32;
pub const XP1_EXPEDITED_DATA = 64;
pub const XP1_CONNECT_DATA = 128;
pub const XP1_DISCONNECT_DATA = 256;
pub const XP1_SUPPORT_BROADCAST = 512;
pub const XP1_SUPPORT_MULTIPOINT = 1024;
pub const XP1_MULTIPOINT_CONTROL_PLANE = 2048;
pub const XP1_MULTIPOINT_DATA_PLANE = 4096;
pub const XP1_QOS_SUPPORTED = 8192;
pub const XP1_INTERRUPT = 16384;
pub const XP1_UNI_SEND = 32768;
pub const XP1_UNI_RECV = 65536;
pub const XP1_IFS_HANDLES = 131072;
pub const XP1_PARTIAL_MESSAGE = 262144;
pub const XP1_SAN_SUPPORT_SDP = 524288;
pub const BIGENDIAN = 0;
pub const LITTLEENDIAN = 1;
pub const SECURITY_PROTOCOL_NONE = 0;
pub const JL_SENDER_ONLY = 1;
pub const JL_RECEIVER_ONLY = 2;
pub const JL_BOTH = 4;
pub const WSA_FLAG_OVERLAPPED = 1;
pub const WSA_FLAG_MULTIPOINT_C_ROOT = 2;
pub const WSA_FLAG_MULTIPOINT_C_LEAF = 4;
pub const WSA_FLAG_MULTIPOINT_D_ROOT = 8;
pub const WSA_FLAG_MULTIPOINT_D_LEAF = 16;
pub const WSA_FLAG_ACCESS_SYSTEM_SECURITY = 64;
pub const WSA_FLAG_NO_HANDLE_INHERIT = 128;
pub const WSA_FLAG_REGISTERED_IO = 256;
pub const TH_NETDEV = 1;
pub const TH_TAPI = 2;
pub const SERVICE_MULTIPLE = 1;
pub const NS_LOCALNAME = 19;
pub const RES_UNUSED_1 = 1;
pub const RES_FLUSH_CACHE = 2;
pub const RES_SERVICE = 4;
pub const LUP_DEEP = 1;
pub const LUP_CONTAINERS = 2;
pub const LUP_NOCONTAINERS = 4;
pub const LUP_NEAREST = 8;
pub const LUP_RETURN_NAME = 16;
pub const LUP_RETURN_TYPE = 32;
pub const LUP_RETURN_VERSION = 64;
pub const LUP_RETURN_COMMENT = 128;
pub const LUP_RETURN_ADDR = 256;
pub const LUP_RETURN_BLOB = 512;
pub const LUP_RETURN_ALIASES = 1024;
pub const LUP_RETURN_QUERY_STRING = 2048;
pub const LUP_RETURN_ALL = 4080;
pub const LUP_RES_SERVICE = 32768;
pub const LUP_FLUSHCACHE = 4096;
pub const LUP_FLUSHPREVIOUS = 8192;
pub const LUP_NON_AUTHORITATIVE = 16384;
pub const LUP_SECURE = 32768;
pub const LUP_RETURN_PREFERRED_NAMES = 65536;
pub const LUP_DNS_ONLY = 131072;
pub const LUP_ADDRCONFIG = 1048576;
pub const LUP_DUAL_ADDR = 2097152;
pub const LUP_FILESERVER = 4194304;
pub const LUP_DISABLE_IDN_ENCODING = 8388608;
pub const LUP_API_ANSI = 16777216;
pub const LUP_RESOLUTION_HANDLE = 2147483648;
pub const RESULT_IS_ALIAS = 1;
pub const RESULT_IS_ADDED = 16;
pub const RESULT_IS_CHANGED = 32;
pub const RESULT_IS_DELETED = 64;

pub const POLL = struct {
    pub const RDNORM = 256;
    pub const RDBAND = 512;
    pub const PRI = 1024;
    pub const WRNORM = 16;
    pub const WRBAND = 32;
    pub const ERR = 1;
    pub const HUP = 2;
    pub const NVAL = 4;
    pub const IN = RDNORM | RDBAND;
    pub const OUT = WRNORM;
};

pub const TF_DISCONNECT = 1;
pub const TF_REUSE_SOCKET = 2;
pub const TF_WRITE_BEHIND = 4;
pub const TF_USE_DEFAULT_WORKER = 0;
pub const TF_USE_SYSTEM_THREAD = 16;
pub const TF_USE_KERNEL_APC = 32;
pub const TP_ELEMENT_MEMORY = 1;
pub const TP_ELEMENT_FILE = 2;
pub const TP_ELEMENT_EOP = 4;
pub const NLA_ALLUSERS_NETWORK = 1;
pub const NLA_FRIENDLY_NAME = 2;
pub const WSPDESCRIPTION_LEN = 255;
pub const WSS_OPERATION_IN_PROGRESS = 259;
pub const LSP_SYSTEM = 2147483648;
pub const LSP_INSPECTOR = 1;
pub const LSP_REDIRECTOR = 2;
pub const LSP_PROXY = 4;
pub const LSP_FIREWALL = 8;
pub const LSP_INBOUND_MODIFY = 16;
pub const LSP_OUTBOUND_MODIFY = 32;
pub const LSP_CRYPTO_COMPRESS = 64;
pub const LSP_LOCAL_CACHE = 128;

pub const IPPROTO = struct {
    pub const IP = 0;
    pub const ICMP = 1;
    pub const IGMP = 2;
    pub const GGP = 3;
    pub const TCP = 6;
    pub const PUP = 12;
    pub const UDP = 17;
    pub const IDP = 22;
    pub const ND = 77;
    pub const RM = 113;
    pub const RAW = 255;
    pub const MAX = 256;
};

pub const IP_DEFAULT_MULTICAST_TTL = 1;
pub const IP_DEFAULT_MULTICAST_LOOP = 1;
pub const IP_MAX_MEMBERSHIPS = 20;
pub const FD_READ = 1;
pub const FD_WRITE = 2;
pub const FD_OOB = 4;
pub const FD_ACCEPT = 8;
pub const FD_CONNECT = 16;
pub const FD_CLOSE = 32;
pub const SERVICE_RESOURCE = 1;
pub const SERVICE_SERVICE = 2;
pub const SERVICE_LOCAL = 4;
pub const SERVICE_FLAG_DEFER = 1;
pub const SERVICE_FLAG_HARD = 2;
pub const PROP_COMMENT = 1;
pub const PROP_LOCALE = 2;
pub const PROP_DISPLAY_HINT = 4;
pub const PROP_VERSION = 8;
pub const PROP_START_TIME = 16;
pub const PROP_MACHINE = 32;
pub const PROP_ADDRESSES = 256;
pub const PROP_SD = 512;
pub const PROP_ALL = 2147483648;
pub const SERVICE_ADDRESS_FLAG_RPC_CN = 1;
pub const SERVICE_ADDRESS_FLAG_RPC_DG = 2;
pub const SERVICE_ADDRESS_FLAG_RPC_NB = 4;
pub const NS_DEFAULT = 0;
pub const NS_VNS = 50;
pub const NSTYPE_HIERARCHICAL = 1;
pub const NSTYPE_DYNAMIC = 2;
pub const NSTYPE_ENUMERABLE = 4;
pub const NSTYPE_WORKGROUP = 8;
pub const XP_CONNECTIONLESS = 1;
pub const XP_GUARANTEED_DELIVERY = 2;
pub const XP_GUARANTEED_ORDER = 4;
pub const XP_MESSAGE_ORIENTED = 8;
pub const XP_PSEUDO_STREAM = 16;
pub const XP_GRACEFUL_CLOSE = 32;
pub const XP_EXPEDITED_DATA = 64;
pub const XP_CONNECT_DATA = 128;
pub const XP_DISCONNECT_DATA = 256;
pub const XP_SUPPORTS_BROADCAST = 512;
pub const XP_SUPPORTS_MULTICAST = 1024;
pub const XP_BANDWIDTH_ALLOCATION = 2048;
pub const XP_FRAGMENTATION = 4096;
pub const XP_ENCRYPTS = 8192;
pub const RES_SOFT_SEARCH = 1;
pub const RES_FIND_MULTIPLE = 2;
pub const SET_SERVICE_PARTIAL_SUCCESS = 1;
pub const UDP_NOCHECKSUM = 1;
pub const UDP_CHECKSUM_COVERAGE = 20;
pub const GAI_STRERROR_BUFFER_SIZE = 1024;

pub const LPCONDITIONPROC = *const fn (
    lpCallerId: *WSABUF,
    lpCallerData: *WSABUF,
    lpSQOS: *QOS,
    lpGQOS: *QOS,
    lpCalleeId: *WSABUF,
    lpCalleeData: *WSABUF,
    g: *u32,
    dwCallbackData: usize,
) callconv(.winapi) i32;

pub const LPWSAOVERLAPPED_COMPLETION_ROUTINE = *const fn (
    dwError: u32,
    cbTransferred: u32,
    lpOverlapped: *OVERLAPPED,
    dwFlags: u32,
) callconv(.winapi) void;

pub const FLOWSPEC = extern struct {
    TokenRate: u32,
    TokenBucketSize: u32,
    PeakBandwidth: u32,
    Latency: u32,
    DelayVariation: u32,
    ServiceType: u32,
    MaxSduSize: u32,
    MinimumPolicedSize: u32,
};

pub const QOS = extern struct {
    SendingFlowspec: FLOWSPEC,
    ReceivingFlowspec: FLOWSPEC,
    ProviderSpecific: WSABUF,
};

pub const SOCKET_ADDRESS = extern struct {
    lpSockaddr: *sockaddr,
    iSockaddrLength: i32,
};

pub const SOCKET_ADDRESS_LIST = extern struct {
    iAddressCount: i32,
    Address: [1]SOCKET_ADDRESS,
};

pub const WSADATA = if (@sizeOf(usize) == @sizeOf(u64))
    extern struct {
        wVersion: WORD,
        wHighVersion: WORD,
        iMaxSockets: u16,
        iMaxUdpDg: u16,
        lpVendorInfo: *u8,
        szDescription: [WSADESCRIPTION_LEN + 1]u8,
        szSystemStatus: [WSASYS_STATUS_LEN + 1]u8,
    }
else
    extern struct {
        wVersion: WORD,
        wHighVersion: WORD,
        szDescription: [WSADESCRIPTION_LEN + 1]u8,
        szSystemStatus: [WSASYS_STATUS_LEN + 1]u8,
        iMaxSockets: u16,
        iMaxUdpDg: u16,
        lpVendorInfo: *u8,
    };

pub const WSAPROTOCOLCHAIN = extern struct {
    ChainLen: c_int,
    ChainEntries: [MAX_PROTOCOL_CHAIN]DWORD,
};

pub const WSAPROTOCOL_INFOA = extern struct {
    dwServiceFlags1: DWORD,
    dwServiceFlags2: DWORD,
    dwServiceFlags3: DWORD,
    dwServiceFlags4: DWORD,
    dwProviderFlags: DWORD,
    ProviderId: GUID,
    dwCatalogEntryId: DWORD,
    ProtocolChain: WSAPROTOCOLCHAIN,
    iVersion: c_int,
    iAddressFamily: c_int,
    iMaxSockAddr: c_int,
    iMinSockAddr: c_int,
    iSocketType: c_int,
    iProtocol: c_int,
    iProtocolMaxOffset: c_int,
    iNetworkByteOrder: c_int,
    iSecurityScheme: c_int,
    dwMessageSize: DWORD,
    dwProviderReserved: DWORD,
    szProtocol: [WSAPROTOCOL_LEN + 1]CHAR,
};

pub const WSAPROTOCOL_INFOW = extern struct {
    dwServiceFlags1: DWORD,
    dwServiceFlags2: DWORD,
    dwServiceFlags3: DWORD,
    dwServiceFlags4: DWORD,
    dwProviderFlags: DWORD,
    ProviderId: GUID,
    dwCatalogEntryId: DWORD,
    ProtocolChain: WSAPROTOCOLCHAIN,
    iVersion: c_int,
    iAddressFamily: c_int,
    iMaxSockAddr: c_int,
    iMinSockAddr: c_int,
    iSocketType: c_int,
    iProtocol: c_int,
    iProtocolMaxOffset: c_int,
    iNetworkByteOrder: c_int,
    iSecurityScheme: c_int,
    dwMessageSize: DWORD,
    dwProviderReserved: DWORD,
    szProtocol: [WSAPROTOCOL_LEN + 1]WCHAR,
};

pub const sockproto = extern struct {
    sp_family: u16,
    sp_protocol: u16,
};

pub const linger = extern struct {
    onoff: u16,
    linger: u16,
};

pub const WSANETWORKEVENTS = extern struct {
    lNetworkEvents: i32,
    iErrorCode: [10]i32,
};

pub const addrinfo = addrinfoa;

pub const addrinfoa = extern struct {
    flags: AI,
    family: i32,
    socktype: i32,
    protocol: i32,
    addrlen: usize,
    canonname: ?[*:0]u8,
    addr: ?*sockaddr,
    next: ?*addrinfo,
};

pub const addrinfoexA = extern struct {
    flags: AI,
    family: i32,
    socktype: i32,
    protocol: i32,
    addrlen: usize,
    canonname: [*:0]u8,
    addr: *sockaddr,
    blob: *anyopaque,
    bloblen: usize,
    provider: *GUID,
    next: *addrinfoexA,
};

pub const sockaddr = extern struct {
    family: ADDRESS_FAMILY,
    data: [14]u8,

    pub const SS_MAXSIZE = 128;
    pub const storage = extern struct {
        family: ADDRESS_FAMILY align(8),
        padding: [SS_MAXSIZE - @sizeOf(ADDRESS_FAMILY)]u8 = undefined,

        comptime {
            assert(@sizeOf(storage) == SS_MAXSIZE);
            assert(@alignOf(storage) == 8);
        }
    };

    /// IPv4 socket address
    pub const in = extern struct {
        family: ADDRESS_FAMILY = AF.INET,
        port: USHORT,
        addr: u32,
        zero: [8]u8 = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };

    /// IPv6 socket address
    pub const in6 = extern struct {
        family: ADDRESS_FAMILY = AF.INET6,
        port: USHORT,
        flowinfo: u32,
        addr: [16]u8,
        scope_id: u32,
    };

    /// UNIX domain socket address
    pub const un = extern struct {
        family: ADDRESS_FAMILY = AF.UNIX,
        path: [108]u8,
    };
};

pub const WSABUF = extern struct {
    len: ULONG,
    buf: [*]u8,
};

pub const msghdr = WSAMSG;
pub const msghdr_const = WSAMSG_const;

pub const WSAMSG_const = extern struct {
    name: *const sockaddr,
    namelen: INT,
    lpBuffers: [*]const WSABUF,
    dwBufferCount: DWORD,
    Control: WSABUF,
    dwFlags: DWORD,
};

pub const WSAMSG = extern struct {
    name: *sockaddr,
    namelen: INT,
    lpBuffers: [*]WSABUF,
    dwBufferCount: DWORD,
    Control: WSABUF,
    dwFlags: DWORD,
};

pub const WSAPOLLFD = pollfd;

pub const pollfd = extern struct {
    fd: SOCKET,
    events: SHORT,
    revents: SHORT,
};

pub const TRANSMIT_FILE_BUFFERS = extern struct {
    Head: *anyopaque,
    HeadLength: u32,
    Tail: *anyopaque,
    TailLength: u32,
};

pub const LPFN_TRANSMITFILE = *const fn (
    hSocket: SOCKET,
    hFile: HANDLE,
    nNumberOfBytesToWrite: u32,
    nNumberOfBytesPerSend: u32,
    lpOverlapped: ?*OVERLAPPED,
    lpTransmitBuffers: ?*TRANSMIT_FILE_BUFFERS,
    dwReserved: u32,
) callconv(.winapi) BOOL;

pub const LPFN_ACCEPTEX = *const fn (
    sListenSocket: SOCKET,
    sAcceptSocket: SOCKET,
    lpOutputBuffer: *anyopaque,
    dwReceiveDataLength: u32,
    dwLocalAddressLength: u32,
    dwRemoteAddressLength: u32,
    lpdwBytesReceived: *u32,
    lpOverlapped: *OVERLAPPED,
) callconv(.winapi) BOOL;

pub const LPFN_GETACCEPTEXSOCKADDRS = *const fn (
    lpOutputBuffer: *anyopaque,
    dwReceiveDataLength: u32,
    dwLocalAddressLength: u32,
    dwRemoteAddressLength: u32,
    LocalSockaddr: **sockaddr,
    LocalSockaddrLength: *i32,
    RemoteSockaddr: **sockaddr,
    RemoteSockaddrLength: *i32,
) callconv(.winapi) void;

pub const LPFN_WSASENDMSG = *const fn (
    s: SOCKET,
    lpMsg: *const WSAMSG_const,
    dwFlags: u32,
    lpNumberOfBytesSent: ?*u32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub const LPFN_WSARECVMSG = *const fn (
    s: SOCKET,
    lpMsg: *WSAMSG,
    lpdwNumberOfBytesRecv: ?*u32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub const LPSERVICE_CALLBACK_PROC = *const fn (
    lParam: LPARAM,
    hAsyncTaskHandle: HANDLE,
) callconv(.winapi) void;

pub const SERVICE_ASYNC_INFO = extern struct {
    lpServiceCallbackProc: LPSERVICE_CALLBACK_PROC,
    lParam: LPARAM,
    hAsyncTaskHandle: HANDLE,
};

pub const LPLOOKUPSERVICE_COMPLETION_ROUTINE = *const fn (
    dwError: u32,
    dwBytes: u32,
    lpOverlapped: *OVERLAPPED,
) callconv(.winapi) void;

pub const fd_set = extern struct {
    fd_count: u32,
    fd_array: [64]SOCKET,
};

pub const hostent = extern struct {
    h_name: [*]u8,
    h_aliases: **i8,
    h_addrtype: i16,
    h_length: i16,
    h_addr_list: **i8,
};

pub const timeval = extern struct {
    sec: LONG,
    usec: LONG,
};

// https://docs.microsoft.com/en-au/windows/win32/winsock/windows-sockets-error-codes-2
pub const WinsockError = enum(u16) {
    /// Specified event object handle is invalid.
    /// An application attempts to use an event object, but the specified handle is not valid.
    WSA_INVALID_HANDLE = 6,

    /// Insufficient memory available.
    /// An application used a Windows Sockets function that directly maps to a Windows function.
    /// The Windows function is indicating a lack of required memory resources.
    WSA_NOT_ENOUGH_MEMORY = 8,

    /// One or more parameters are invalid.
    /// An application used a Windows Sockets function which directly maps to a Windows function.
    /// The Windows function is indicating a problem with one or more parameters.
    WSA_INVALID_PARAMETER = 87,

    /// Overlapped operation aborted.
    /// An overlapped operation was canceled due to the closure of the socket, or the execution of the SIO_FLUSH command in WSAIoctl.
    WSA_OPERATION_ABORTED = 995,

    /// Overlapped I/O event object not in signaled state.
    /// The application has tried to determine the status of an overlapped operation which is not yet completed.
    /// Applications that use WSAGetOverlappedResult (with the fWait flag set to FALSE) in a polling mode to determine when an overlapped operation has completed, get this error code until the operation is complete.
    WSA_IO_INCOMPLETE = 996,

    /// The application has initiated an overlapped operation that cannot be completed immediately.
    /// A completion indication will be given later when the operation has been completed.
    WSA_IO_PENDING = 997,

    /// Interrupted function call.
    /// A blocking operation was interrupted by a call to WSACancelBlockingCall.
    WSAEINTR = 10004,

    /// File handle is not valid.
    /// The file handle supplied is not valid.
    WSAEBADF = 10009,

    /// Permission denied.
    /// An attempt was made to access a socket in a way forbidden by its access permissions.
    /// An example is using a broadcast address for sendto without broadcast permission being set using setsockopt(SO.BROADCAST).
    /// Another possible reason for the WSAEACCES error is that when the bind function is called (on Windows NT 4.0 with SP4 and later), another application, service, or kernel mode driver is bound to the same address with exclusive access.
    /// Such exclusive access is a new feature of Windows NT 4.0 with SP4 and later, and is implemented by using the SO.EXCLUSIVEADDRUSE option.
    WSAEACCES = 10013,

    /// Bad address.
    /// The system detected an invalid pointer address in attempting to use a pointer argument of a call.
    /// This error occurs if an application passes an invalid pointer value, or if the length of the buffer is too small.
    /// For instance, if the length of an argument, which is a sockaddr structure, is smaller than the sizeof(sockaddr).
    WSAEFAULT = 10014,

    /// Invalid argument.
    /// Some invalid argument was supplied (for example, specifying an invalid level to the setsockopt function).
    /// In some instances, it also refers to the current state of the socket—for instance, calling accept on a socket that is not listening.
    WSAEINVAL = 10022,

    /// Too many open files.
    /// Too many open sockets. Each implementation may have a maximum number of socket handles available, either globally, per process, or per thread.
    WSAEMFILE = 10024,

    /// Resource temporarily unavailable.
    /// This error is returned from operations on nonblocking sockets that cannot be completed immediately, for example recv when no data is queued to be read from the socket.
    /// It is a nonfatal error, and the operation should be retried later.
    /// It is normal for WSAEWOULDBLOCK to be reported as the result from calling connect on a nonblocking SOCK.STREAM socket, since some time must elapse for the connection to be established.
    WSAEWOULDBLOCK = 10035,

    /// Operation now in progress.
    /// A blocking operation is currently executing.
    /// Windows Sockets only allows a single blocking operation—per- task or thread—to be outstanding, and if any other function call is made (whether or not it references that or any other socket) the function fails with the WSAEINPROGRESS error.
    WSAEINPROGRESS = 10036,

    /// Operation already in progress.
    /// An operation was attempted on a nonblocking socket with an operation already in progress—that is, calling connect a second time on a nonblocking socket that is already connecting, or canceling an asynchronous request (WSAAsyncGetXbyY) that has already been canceled or completed.
    WSAEALREADY = 10037,

    /// Socket operation on nonsocket.
    /// An operation was attempted on something that is not a socket.
    /// Either the socket handle parameter did not reference a valid socket, or for select, a member of an fd_set was not valid.
    WSAENOTSOCK = 10038,

    /// Destination address required.
    /// A required address was omitted from an operation on a socket.
    /// For example, this error is returned if sendto is called with the remote address of ADDR_ANY.
    WSAEDESTADDRREQ = 10039,

    /// Message too long.
    /// A message sent on a datagram socket was larger than the internal message buffer or some other network limit, or the buffer used to receive a datagram was smaller than the datagram itself.
    WSAEMSGSIZE = 10040,

    /// Protocol wrong type for socket.
    /// A protocol was specified in the socket function call that does not support the semantics of the socket type requested.
    /// For example, the ARPA Internet UDP protocol cannot be specified with a socket type of SOCK.STREAM.
    WSAEPROTOTYPE = 10041,

    /// Bad protocol option.
    /// An unknown, invalid or unsupported option or level was specified in a getsockopt or setsockopt call.
    WSAENOPROTOOPT = 10042,

    /// Protocol not supported.
    /// The requested protocol has not been configured into the system, or no implementation for it exists.
    /// For example, a socket call requests a SOCK.DGRAM socket, but specifies a stream protocol.
    WSAEPROTONOSUPPORT = 10043,

    /// Socket type not supported.
    /// The support for the specified socket type does not exist in this address family.
    /// For example, the optional type SOCK.RAW might be selected in a socket call, and the implementation does not support SOCK.RAW sockets at all.
    WSAESOCKTNOSUPPORT = 10044,

    /// Operation not supported.
    /// The attempted operation is not supported for the type of object referenced.
    /// Usually this occurs when a socket descriptor to a socket that cannot support this operation is trying to accept a connection on a datagram socket.
    WSAEOPNOTSUPP = 10045,

    /// Protocol family not supported.
    /// The protocol family has not been configured into the system or no implementation for it exists.
    /// This message has a slightly different meaning from WSAEAFNOSUPPORT.
    /// However, it is interchangeable in most cases, and all Windows Sockets functions that return one of these messages also specify WSAEAFNOSUPPORT.
    WSAEPFNOSUPPORT = 10046,

    /// Address family not supported by protocol family.
    /// An address incompatible with the requested protocol was used.
    /// All sockets are created with an associated address family (that is, AF.INET for Internet Protocols) and a generic protocol type (that is, SOCK.STREAM).
    /// This error is returned if an incorrect protocol is explicitly requested in the socket call, or if an address of the wrong family is used for a socket, for example, in sendto.
    WSAEAFNOSUPPORT = 10047,

    /// Address already in use.
    /// Typically, only one usage of each socket address (protocol/IP address/port) is permitted.
    /// This error occurs if an application attempts to bind a socket to an IP address/port that has already been used for an existing socket, or a socket that was not closed properly, or one that is still in the process of closing.
    /// For server applications that need to bind multiple sockets to the same port number, consider using setsockopt (SO.REUSEADDR).
    /// Client applications usually need not call bind at all—connect chooses an unused port automatically.
    /// When bind is called with a wildcard address (involving ADDR_ANY), a WSAEADDRINUSE error could be delayed until the specific address is committed.
    /// This could happen with a call to another function later, including connect, listen, WSAConnect, or WSAJoinLeaf.
    WSAEADDRINUSE = 10048,

    /// Cannot assign requested address.
    /// The requested address is not valid in its context.
    /// This normally results from an attempt to bind to an address that is not valid for the local computer.
    /// This can also result from connect, sendto, WSAConnect, WSAJoinLeaf, or WSASendTo when the remote address or port is not valid for a remote computer (for example, address or port 0).
    WSAEADDRNOTAVAIL = 10049,

    /// Network is down.
    /// A socket operation encountered a dead network.
    /// This could indicate a serious failure of the network system (that is, the protocol stack that the Windows Sockets DLL runs over), the network interface, or the local network itself.
    WSAENETDOWN = 10050,

    /// Network is unreachable.
    /// A socket operation was attempted to an unreachable network.
    /// This usually means the local software knows no route to reach the remote host.
    WSAENETUNREACH = 10051,

    /// Network dropped connection on reset.
    /// The connection has been broken due to keep-alive activity detecting a failure while the operation was in progress.
    /// It can also be returned by setsockopt if an attempt is made to set SO.KEEPALIVE on a connection that has already failed.
    WSAENETRESET = 10052,

    /// Software caused connection abort.
    /// An established connection was aborted by the software in your host computer, possibly due to a data transmission time-out or protocol error.
    WSAECONNABORTED = 10053,

    /// Connection reset by peer.
    /// An existing connection was forcibly closed by the remote host.
    /// This normally results if the peer application on the remote host is suddenly stopped, the host is rebooted, the host or remote network interface is disabled, or the remote host uses a hard close (see setsockopt for more information on the SO.LINGER option on the remote socket).
    /// This error may also result if a connection was broken due to keep-alive activity detecting a failure while one or more operations are in progress.
    /// Operations that were in progress fail with WSAENETRESET. Subsequent operations fail with WSAECONNRESET.
    WSAECONNRESET = 10054,

    /// No buffer space available.
    /// An operation on a socket could not be performed because the system lacked sufficient buffer space or because a queue was full.
    WSAENOBUFS = 10055,

    /// Socket is already connected.
    /// A connect request was made on an already-connected socket.
    /// Some implementations also return this error if sendto is called on a connected SOCK.DGRAM socket (for SOCK.STREAM sockets, the to parameter in sendto is ignored) although other implementations treat this as a legal occurrence.
    WSAEISCONN = 10056,

    /// Socket is not connected.
    /// A request to send or receive data was disallowed because the socket is not connected and (when sending on a datagram socket using sendto) no address was supplied.
    /// Any other type of operation might also return this error—for example, setsockopt setting SO.KEEPALIVE if the connection has been reset.
    WSAENOTCONN = 10057,

    /// Cannot send after socket shutdown.
    /// A request to send or receive data was disallowed because the socket had already been shut down in that direction with a previous shutdown call.
    /// By calling shutdown a partial close of a socket is requested, which is a signal that sending or receiving, or both have been discontinued.
    WSAESHUTDOWN = 10058,

    /// Too many references.
    /// Too many references to some kernel object.
    WSAETOOMANYREFS = 10059,

    /// Connection timed out.
    /// A connection attempt failed because the connected party did not properly respond after a period of time, or the established connection failed because the connected host has failed to respond.
    WSAETIMEDOUT = 10060,

    /// Connection refused.
    /// No connection could be made because the target computer actively refused it.
    /// This usually results from trying to connect to a service that is inactive on the foreign host—that is, one with no server application running.
    WSAECONNREFUSED = 10061,

    /// Cannot translate name.
    /// Cannot translate a name.
    WSAELOOP = 10062,

    /// Name too long.
    /// A name component or a name was too long.
    WSAENAMETOOLONG = 10063,

    /// Host is down.
    /// A socket operation failed because the destination host is down. A socket operation encountered a dead host.
    /// Networking activity on the local host has not been initiated.
    /// These conditions are more likely to be indicated by the error WSAETIMEDOUT.
    WSAEHOSTDOWN = 10064,

    /// No route to host.
    /// A socket operation was attempted to an unreachable host. See WSAENETUNREACH.
    WSAEHOSTUNREACH = 10065,

    /// Directory not empty.
    /// Cannot remove a directory that is not empty.
    WSAENOTEMPTY = 10066,

    /// Too many processes.
    /// A Windows Sockets implementation may have a limit on the number of applications that can use it simultaneously.
    /// WSAStartup may fail with this error if the limit has been reached.
    WSAEPROCLIM = 10067,

    /// User quota exceeded.
    /// Ran out of user quota.
    WSAEUSERS = 10068,

    /// Disk quota exceeded.
    /// Ran out of disk quota.
    WSAEDQUOT = 10069,

    /// Stale file handle reference.
    /// The file handle reference is no longer available.
    WSAESTALE = 10070,

    /// Item is remote.
    /// The item is not available locally.
    WSAEREMOTE = 10071,

    /// Network subsystem is unavailable.
    /// This error is returned by WSAStartup if the Windows Sockets implementation cannot function at this time because the underlying system it uses to provide network services is currently unavailable.
    /// Users should check:
    ///   - That the appropriate Windows Sockets DLL file is in the current path.
    ///   - That they are not trying to use more than one Windows Sockets implementation simultaneously.
    ///   - If there is more than one Winsock DLL on your system, be sure the first one in the path is appropriate for the network subsystem currently loaded.
    ///   - The Windows Sockets implementation documentation to be sure all necessary components are currently installed and configured correctly.
    WSASYSNOTREADY = 10091,

    /// Winsock.dll version out of range.
    /// The current Windows Sockets implementation does not support the Windows Sockets specification version requested by the application.
    /// Check that no old Windows Sockets DLL files are being accessed.
    WSAVERNOTSUPPORTED = 10092,

    /// Successful WSAStartup not yet performed.
    /// Either the application has not called WSAStartup or WSAStartup failed.
    /// The application may be accessing a socket that the current active task does not own (that is, trying to share a socket between tasks), or WSACleanup has been called too many times.
    WSANOTINITIALISED = 10093,

    /// Graceful shutdown in progress.
    /// Returned by WSARecv and WSARecvFrom to indicate that the remote party has initiated a graceful shutdown sequence.
    WSAEDISCON = 10101,

    /// No more results.
    /// No more results can be returned by the WSALookupServiceNext function.
    WSAENOMORE = 10102,

    /// Call has been canceled.
    /// A call to the WSALookupServiceEnd function was made while this call was still processing. The call has been canceled.
    WSAECANCELLED = 10103,

    /// Procedure call table is invalid.
    /// The service provider procedure call table is invalid.
    /// A service provider returned a bogus procedure table to Ws2_32.dll.
    /// This is usually caused by one or more of the function pointers being NULL.
    WSAEINVALIDPROCTABLE = 10104,

    /// Service provider is invalid.
    /// The requested service provider is invalid.
    /// This error is returned by the WSCGetProviderInfo and WSCGetProviderInfo32 functions if the protocol entry specified could not be found.
    /// This error is also returned if the service provider returned a version number other than 2.0.
    WSAEINVALIDPROVIDER = 10105,

    /// Service provider failed to initialize.
    /// The requested service provider could not be loaded or initialized.
    /// This error is returned if either a service provider's DLL could not be loaded (LoadLibrary failed) or the provider's WSPStartup or NSPStartup function failed.
    WSAEPROVIDERFAILEDINIT = 10106,

    /// System call failure.
    /// A system call that should never fail has failed.
    /// This is a generic error code, returned under various conditions.
    /// Returned when a system call that should never fail does fail.
    /// For example, if a call to WaitForMultipleEvents fails or one of the registry functions fails trying to manipulate the protocol/namespace catalogs.
    /// Returned when a provider does not return SUCCESS and does not provide an extended error code.
    /// Can indicate a service provider implementation error.
    WSASYSCALLFAILURE = 10107,

    /// Service not found.
    /// No such service is known. The service cannot be found in the specified name space.
    WSASERVICE_NOT_FOUND = 10108,

    /// Class type not found.
    /// The specified class was not found.
    WSATYPE_NOT_FOUND = 10109,

    /// No more results.
    /// No more results can be returned by the WSALookupServiceNext function.
    WSA_E_NO_MORE = 10110,

    /// Call was canceled.
    /// A call to the WSALookupServiceEnd function was made while this call was still processing. The call has been canceled.
    WSA_E_CANCELLED = 10111,

    /// Database query was refused.
    /// A database query failed because it was actively refused.
    WSAEREFUSED = 10112,

    /// Host not found.
    /// No such host is known. The name is not an official host name or alias, or it cannot be found in the database(s) being queried.
    /// This error may also be returned for protocol and service queries, and means that the specified name could not be found in the relevant database.
    WSAHOST_NOT_FOUND = 11001,

    /// Nonauthoritative host not found.
    /// This is usually a temporary error during host name resolution and means that the local server did not receive a response from an authoritative server. A retry at some time later may be successful.
    WSATRY_AGAIN = 11002,

    /// This is a nonrecoverable error.
    /// This indicates that some sort of nonrecoverable error occurred during a database lookup.
    /// This may be because the database files (for example, BSD-compatible HOSTS, SERVICES, or PROTOCOLS files) could not be found, or a DNS request was returned by the server with a severe error.
    WSANO_RECOVERY = 11003,

    /// Valid name, no data record of requested type.
    /// The requested name is valid and was found in the database, but it does not have the correct associated data being resolved for.
    /// The usual example for this is a host name-to-address translation attempt (using gethostbyname or WSAAsyncGetHostByName) which uses the DNS (Domain Name Server).
    /// An MX record is returned but no A record—indicating the host itself exists, but is not directly reachable.
    WSANO_DATA = 11004,

    /// QoS receivers.
    /// At least one QoS reserve has arrived.
    WSA_QOS_RECEIVERS = 11005,

    /// QoS senders.
    /// At least one QoS send path has arrived.
    WSA_QOS_SENDERS = 11006,

    /// No QoS senders.
    /// There are no QoS senders.
    WSA_QOS_NO_SENDERS = 11007,

    /// QoS no receivers.
    /// There are no QoS receivers.
    WSA_QOS_NO_RECEIVERS = 11008,

    /// QoS request confirmed.
    /// The QoS reserve request has been confirmed.
    WSA_QOS_REQUEST_CONFIRMED = 11009,

    /// QoS admission error.
    /// A QoS error occurred due to lack of resources.
    WSA_QOS_ADMISSION_FAILURE = 11010,

    /// QoS policy failure.
    /// The QoS request was rejected because the policy system couldn't allocate the requested resource within the existing policy.
    WSA_QOS_POLICY_FAILURE = 11011,

    /// QoS bad style.
    /// An unknown or conflicting QoS style was encountered.
    WSA_QOS_BAD_STYLE = 11012,

    /// QoS bad object.
    /// A problem was encountered with some part of the filterspec or the provider-specific buffer in general.
    WSA_QOS_BAD_OBJECT = 11013,

    /// QoS traffic control error.
    /// An error with the underlying traffic control (TC) API as the generic QoS request was converted for local enforcement by the TC API.
    /// This could be due to an out of memory error or to an internal QoS provider error.
    WSA_QOS_TRAFFIC_CTRL_ERROR = 11014,

    /// QoS generic error.
    /// A general QoS error.
    WSA_QOS_GENERIC_ERROR = 11015,

    /// QoS service type error.
    /// An invalid or unrecognized service type was found in the QoS flowspec.
    WSA_QOS_ESERVICETYPE = 11016,

    /// QoS flowspec error.
    /// An invalid or inconsistent flowspec was found in the QOS structure.
    WSA_QOS_EFLOWSPEC = 11017,

    /// Invalid QoS provider buffer.
    /// An invalid QoS provider-specific buffer.
    WSA_QOS_EPROVSPECBUF = 11018,

    /// Invalid QoS filter style.
    /// An invalid QoS filter style was used.
    WSA_QOS_EFILTERSTYLE = 11019,

    /// Invalid QoS filter type.
    /// An invalid QoS filter type was used.
    WSA_QOS_EFILTERTYPE = 11020,

    /// Incorrect QoS filter count.
    /// An incorrect number of QoS FILTERSPECs were specified in the FLOWDESCRIPTOR.
    WSA_QOS_EFILTERCOUNT = 11021,

    /// Invalid QoS object length.
    /// An object with an invalid ObjectLength field was specified in the QoS provider-specific buffer.
    WSA_QOS_EOBJLENGTH = 11022,

    /// Incorrect QoS flow count.
    /// An incorrect number of flow descriptors was specified in the QoS structure.
    WSA_QOS_EFLOWCOUNT = 11023,

    /// Unrecognized QoS object.
    /// An unrecognized object was found in the QoS provider-specific buffer.
    WSA_QOS_EUNKOWNPSOBJ = 11024,

    /// Invalid QoS policy object.
    /// An invalid policy object was found in the QoS provider-specific buffer.
    WSA_QOS_EPOLICYOBJ = 11025,

    /// Invalid QoS flow descriptor.
    /// An invalid QoS flow descriptor was found in the flow descriptor list.
    WSA_QOS_EFLOWDESC = 11026,

    /// Invalid QoS provider-specific flowspec.
    /// An invalid or inconsistent flowspec was found in the QoS provider-specific buffer.
    WSA_QOS_EPSFLOWSPEC = 11027,

    /// Invalid QoS provider-specific filterspec.
    /// An invalid FILTERSPEC was found in the QoS provider-specific buffer.
    WSA_QOS_EPSFILTERSPEC = 11028,

    /// Invalid QoS shape discard mode object.
    /// An invalid shape discard mode object was found in the QoS provider-specific buffer.
    WSA_QOS_ESDMODEOBJ = 11029,

    /// Invalid QoS shaping rate object.
    /// An invalid shaping rate object was found in the QoS provider-specific buffer.
    WSA_QOS_ESHAPERATEOBJ = 11030,

    /// Reserved policy QoS element type.
    /// A reserved policy element was found in the QoS provider-specific buffer.
    WSA_QOS_RESERVED_PETYPE = 11031,

    _,
};

pub extern "ws2_32" fn accept(
    s: SOCKET,
    addr: ?*sockaddr,
    addrlen: ?*i32,
) callconv(.winapi) SOCKET;

pub extern "ws2_32" fn bind(
    s: SOCKET,
    name: *const sockaddr,
    namelen: i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn closesocket(
    s: SOCKET,
) callconv(.winapi) i32;

pub extern "ws2_32" fn connect(
    s: SOCKET,
    name: *const sockaddr,
    namelen: i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn ioctlsocket(
    s: SOCKET,
    cmd: i32,
    argp: *u32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn getpeername(
    s: SOCKET,
    name: *sockaddr,
    namelen: *i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn getsockname(
    s: SOCKET,
    name: *sockaddr,
    namelen: *i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn getsockopt(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: [*]u8,
    optlen: *i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn htonl(
    hostlong: u32,
) callconv(.winapi) u32;

pub extern "ws2_32" fn htons(
    hostshort: u16,
) callconv(.winapi) u16;

pub extern "ws2_32" fn inet_addr(
    cp: ?[*]const u8,
) callconv(.winapi) u32;

pub extern "ws2_32" fn listen(
    s: SOCKET,
    backlog: i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn ntohl(
    netlong: u32,
) callconv(.winapi) u32;

pub extern "ws2_32" fn ntohs(
    netshort: u16,
) callconv(.winapi) u16;

pub extern "ws2_32" fn recv(
    s: SOCKET,
    buf: [*]u8,
    len: i32,
    flags: i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn recvfrom(
    s: SOCKET,
    buf: [*]u8,
    len: i32,
    flags: i32,
    from: ?*sockaddr,
    fromlen: ?*i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn select(
    nfds: i32,
    readfds: ?*fd_set,
    writefds: ?*fd_set,
    exceptfds: ?*fd_set,
    timeout: ?*const timeval,
) callconv(.winapi) i32;

pub extern "ws2_32" fn send(
    s: SOCKET,
    buf: [*]const u8,
    len: i32,
    flags: u32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn sendto(
    s: SOCKET,
    buf: [*]const u8,
    len: i32,
    flags: i32,
    to: *const sockaddr,
    tolen: i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn setsockopt(
    s: SOCKET,
    level: i32,
    optname: i32,
    optval: ?[*]const u8,
    optlen: i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn shutdown(
    s: SOCKET,
    how: i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn socket(
    af: i32,
    @"type": i32,
    protocol: i32,
) callconv(.winapi) SOCKET;

pub extern "ws2_32" fn WSAStartup(
    wVersionRequired: WORD,
    lpWSAData: *WSADATA,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSACleanup() callconv(.winapi) i32;

pub extern "ws2_32" fn WSASetLastError(iError: i32) callconv(.winapi) void;

pub extern "ws2_32" fn WSAGetLastError() callconv(.winapi) WinsockError;

pub extern "ws2_32" fn WSAIsBlocking() callconv(.winapi) BOOL;

pub extern "ws2_32" fn WSAUnhookBlockingHook() callconv(.winapi) i32;

pub extern "ws2_32" fn WSASetBlockingHook(lpBlockFunc: FARPROC) callconv(.winapi) FARPROC;

pub extern "ws2_32" fn WSACancelBlockingCall() callconv(.winapi) i32;

pub extern "ws2_32" fn WSAAsyncGetServByName(
    hWnd: HWND,
    wMsg: u32,
    name: [*:0]const u8,
    proto: ?[*:0]const u8,
    buf: [*]u8,
    buflen: i32,
) callconv(.winapi) HANDLE;

pub extern "ws2_32" fn WSAAsyncGetServByPort(
    hWnd: HWND,
    wMsg: u32,
    port: i32,
    proto: ?[*:0]const u8,
    buf: [*]u8,
    buflen: i32,
) callconv(.winapi) HANDLE;

pub extern "ws2_32" fn WSAAsyncGetProtoByName(
    hWnd: HWND,
    wMsg: u32,
    name: [*:0]const u8,
    buf: [*]u8,
    buflen: i32,
) callconv(.winapi) HANDLE;

pub extern "ws2_32" fn WSAAsyncGetProtoByNumber(
    hWnd: HWND,
    wMsg: u32,
    number: i32,
    buf: [*]u8,
    buflen: i32,
) callconv(.winapi) HANDLE;

pub extern "ws2_32" fn WSACancelAsyncRequest(hAsyncTaskHandle: HANDLE) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAAsyncSelect(
    s: SOCKET,
    hWnd: HWND,
    wMsg: u32,
    lEvent: i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAAccept(
    s: SOCKET,
    addr: ?*sockaddr,
    addrlen: ?*i32,
    lpfnCondition: ?LPCONDITIONPROC,
    dwCallbackData: usize,
) callconv(.winapi) SOCKET;

pub extern "ws2_32" fn WSACloseEvent(hEvent: HANDLE) callconv(.winapi) BOOL;

pub extern "ws2_32" fn WSAConnect(
    s: SOCKET,
    name: *const sockaddr,
    namelen: i32,
    lpCallerData: ?*WSABUF,
    lpCalleeData: ?*WSABUF,
    lpSQOS: ?*QOS,
    lpGQOS: ?*QOS,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAConnectByNameW(
    s: SOCKET,
    nodename: [*:0]const u16,
    servicename: [*:0]const u16,
    LocalAddressLength: ?*u32,
    LocalAddress: ?*sockaddr,
    RemoteAddressLength: ?*u32,
    RemoteAddress: ?*sockaddr,
    timeout: ?*const timeval,
    Reserved: *OVERLAPPED,
) callconv(.winapi) BOOL;

pub extern "ws2_32" fn WSAConnectByNameA(
    s: SOCKET,
    nodename: [*:0]const u8,
    servicename: [*:0]const u8,
    LocalAddressLength: ?*u32,
    LocalAddress: ?*sockaddr,
    RemoteAddressLength: ?*u32,
    RemoteAddress: ?*sockaddr,
    timeout: ?*const timeval,
    Reserved: *OVERLAPPED,
) callconv(.winapi) BOOL;

pub extern "ws2_32" fn WSAConnectByList(
    s: SOCKET,
    SocketAddress: *SOCKET_ADDRESS_LIST,
    LocalAddressLength: ?*u32,
    LocalAddress: ?*sockaddr,
    RemoteAddressLength: ?*u32,
    RemoteAddress: ?*sockaddr,
    timeout: ?*const timeval,
    Reserved: *OVERLAPPED,
) callconv(.winapi) BOOL;

pub extern "ws2_32" fn WSACreateEvent() callconv(.winapi) HANDLE;

pub extern "ws2_32" fn WSADuplicateSocketA(
    s: SOCKET,
    dwProcessId: u32,
    lpProtocolInfo: *WSAPROTOCOL_INFOA,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSADuplicateSocketW(
    s: SOCKET,
    dwProcessId: u32,
    lpProtocolInfo: *WSAPROTOCOL_INFOW,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAEnumNetworkEvents(
    s: SOCKET,
    hEventObject: HANDLE,
    lpNetworkEvents: *WSANETWORKEVENTS,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAEnumProtocolsA(
    lpiProtocols: ?*i32,
    lpProtocolBuffer: ?*WSAPROTOCOL_INFOA,
    lpdwBufferLength: *u32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAEnumProtocolsW(
    lpiProtocols: ?*i32,
    lpProtocolBuffer: ?*WSAPROTOCOL_INFOW,
    lpdwBufferLength: *u32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAEventSelect(
    s: SOCKET,
    hEventObject: HANDLE,
    lNetworkEvents: i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAGetOverlappedResult(
    s: SOCKET,
    lpOverlapped: *OVERLAPPED,
    lpcbTransfer: *u32,
    fWait: BOOL,
    lpdwFlags: *u32,
) callconv(.winapi) BOOL;

pub extern "ws2_32" fn WSAGetQOSByName(
    s: SOCKET,
    lpQOSName: *WSABUF,
    lpQOS: *QOS,
) callconv(.winapi) BOOL;

pub extern "ws2_32" fn WSAHtonl(
    s: SOCKET,
    hostlong: u32,
    lpnetlong: *u32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAHtons(
    s: SOCKET,
    hostshort: u16,
    lpnetshort: *u16,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAIoctl(
    s: SOCKET,
    dwIoControlCode: u32,
    lpvInBuffer: ?*const anyopaque,
    cbInBuffer: u32,
    lpvOutbuffer: ?*anyopaque,
    cbOutbuffer: u32,
    lpcbBytesReturned: *u32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAJoinLeaf(
    s: SOCKET,
    name: *const sockaddr,
    namelen: i32,
    lpCallerdata: ?*WSABUF,
    lpCalleeData: ?*WSABUF,
    lpSQOS: ?*QOS,
    lpGQOS: ?*QOS,
    dwFlags: u32,
) callconv(.winapi) SOCKET;

pub extern "ws2_32" fn WSANtohl(
    s: SOCKET,
    netlong: u32,
    lphostlong: *u32,
) callconv(.winapi) u32;

pub extern "ws2_32" fn WSANtohs(
    s: SOCKET,
    netshort: u16,
    lphostshort: *u16,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSARecv(
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBufferCouynt: u32,
    lpNumberOfBytesRecv: ?*u32,
    lpFlags: *u32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSARecvDisconnect(
    s: SOCKET,
    lpInboundDisconnectData: ?*WSABUF,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSARecvFrom(
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBuffercount: u32,
    lpNumberOfBytesRecvd: ?*u32,
    lpFlags: *u32,
    lpFrom: ?*sockaddr,
    lpFromlen: ?*i32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAResetEvent(hEvent: HANDLE) callconv(.winapi) i32;

pub extern "ws2_32" fn WSASend(
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesSent: ?*u32,
    dwFlags: u32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSASendMsg(
    s: SOCKET,
    lpMsg: *WSAMSG_const,
    dwFlags: u32,
    lpNumberOfBytesSent: ?*u32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSARecvMsg(
    s: SOCKET,
    lpMsg: *WSAMSG,
    lpdwNumberOfBytesRecv: ?*u32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSASendDisconnect(
    s: SOCKET,
    lpOutboundDisconnectData: ?*WSABUF,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSASendTo(
    s: SOCKET,
    lpBuffers: [*]WSABUF,
    dwBufferCount: u32,
    lpNumberOfBytesSent: ?*u32,
    dwFlags: u32,
    lpTo: ?*const sockaddr,
    iToLen: i32,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRounte: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSASetEvent(
    hEvent: HANDLE,
) callconv(.winapi) BOOL;

pub extern "ws2_32" fn WSASocketA(
    af: i32,
    @"type": i32,
    protocol: i32,
    lpProtocolInfo: ?*WSAPROTOCOL_INFOA,
    g: u32,
    dwFlags: u32,
) callconv(.winapi) SOCKET;

pub extern "ws2_32" fn WSASocketW(
    af: i32,
    @"type": i32,
    protocol: i32,
    lpProtocolInfo: ?*WSAPROTOCOL_INFOW,
    g: u32,
    dwFlags: u32,
) callconv(.winapi) SOCKET;

pub extern "ws2_32" fn WSAWaitForMultipleEvents(
    cEvents: u32,
    lphEvents: [*]const HANDLE,
    fWaitAll: BOOL,
    dwTimeout: u32,
    fAlertable: BOOL,
) callconv(.winapi) u32;

pub extern "ws2_32" fn WSAAddressToStringA(
    lpsaAddress: *sockaddr,
    dwAddressLength: u32,
    lpProtocolInfo: ?*WSAPROTOCOL_INFOA,
    lpszAddressString: [*]u8,
    lpdwAddressStringLength: *u32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAAddressToStringW(
    lpsaAddress: *sockaddr,
    dwAddressLength: u32,
    lpProtocolInfo: ?*WSAPROTOCOL_INFOW,
    lpszAddressString: [*]u16,
    lpdwAddressStringLength: *u32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAStringToAddressA(
    AddressString: [*:0]const u8,
    AddressFamily: i32,
    lpProtocolInfo: ?*WSAPROTOCOL_INFOA,
    lpAddress: *sockaddr,
    lpAddressLength: *i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAStringToAddressW(
    AddressString: [*:0]const u16,
    AddressFamily: i32,
    lpProtocolInfo: ?*WSAPROTOCOL_INFOW,
    lpAddrses: *sockaddr,
    lpAddressLength: *i32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAProviderConfigChange(
    lpNotificationHandle: *HANDLE,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub extern "ws2_32" fn WSAPoll(
    fdArray: [*]WSAPOLLFD,
    fds: u32,
    timeout: i32,
) callconv(.winapi) i32;

pub extern "mswsock" fn WSARecvEx(
    s: SOCKET,
    buf: [*]u8,
    len: i32,
    flags: *i32,
) callconv(.winapi) i32;

pub extern "mswsock" fn TransmitFile(
    hSocket: SOCKET,
    hFile: HANDLE,
    nNumberOfBytesToWrite: u32,
    nNumberOfBytesPerSend: u32,
    lpOverlapped: ?*OVERLAPPED,
    lpTransmitBuffers: ?*TRANSMIT_FILE_BUFFERS,
    dwReserved: u32,
) callconv(.winapi) BOOL;

pub extern "mswsock" fn AcceptEx(
    sListenSocket: SOCKET,
    sAcceptSocket: SOCKET,
    lpOutputBuffer: *anyopaque,
    dwReceiveDataLength: u32,
    dwLocalAddressLength: u32,
    dwRemoteAddressLength: u32,
    lpdwBytesReceived: *u32,
    lpOverlapped: *OVERLAPPED,
) callconv(.winapi) BOOL;

pub extern "mswsock" fn GetAcceptExSockaddrs(
    lpOutputBuffer: *anyopaque,
    dwReceiveDataLength: u32,
    dwLocalAddressLength: u32,
    dwRemoteAddressLength: u32,
    LocalSockaddr: **sockaddr,
    LocalSockaddrLength: *i32,
    RemoteSockaddr: **sockaddr,
    RemoteSockaddrLength: *i32,
) callconv(.winapi) void;

pub extern "ws2_32" fn WSAProviderCompleteAsyncCall(
    hAsyncCall: HANDLE,
    iRetCode: i32,
) callconv(.winapi) i32;

pub extern "mswsock" fn EnumProtocolsA(
    lpiProtocols: ?*i32,
    lpProtocolBuffer: *anyopaque,
    lpdwBufferLength: *u32,
) callconv(.winapi) i32;

pub extern "mswsock" fn EnumProtocolsW(
    lpiProtocols: ?*i32,
    lpProtocolBuffer: *anyopaque,
    lpdwBufferLength: *u32,
) callconv(.winapi) i32;

pub extern "mswsock" fn GetAddressByNameA(
    dwNameSpace: u32,
    lpServiceType: *GUID,
    lpServiceName: ?[*:0]u8,
    lpiProtocols: ?*i32,
    dwResolution: u32,
    lpServiceAsyncInfo: ?*SERVICE_ASYNC_INFO,
    lpCsaddrBuffer: *anyopaque,
    lpAliasBuffer: ?[*:0]const u8,
    lpdwAliasBufferLength: *u32,
) callconv(.winapi) i32;

pub extern "mswsock" fn GetAddressByNameW(
    dwNameSpace: u32,
    lpServiceType: *GUID,
    lpServiceName: ?[*:0]u16,
    lpiProtocols: ?*i32,
    dwResolution: u32,
    lpServiceAsyncInfo: ?*SERVICE_ASYNC_INFO,
    lpCsaddrBuffer: *anyopaque,
    ldwBufferLEngth: *u32,
    lpAliasBuffer: ?[*:0]u16,
    lpdwAliasBufferLength: *u32,
) callconv(.winapi) i32;

pub extern "mswsock" fn GetTypeByNameA(
    lpServiceName: [*:0]u8,
    lpServiceType: *GUID,
) callconv(.winapi) i32;

pub extern "mswsock" fn GetTypeByNameW(
    lpServiceName: [*:0]u16,
    lpServiceType: *GUID,
) callconv(.winapi) i32;

pub extern "mswsock" fn GetNameByTypeA(
    lpServiceType: *GUID,
    lpServiceName: [*:0]u8,
    dwNameLength: u32,
) callconv(.winapi) i32;

pub extern "mswsock" fn GetNameByTypeW(
    lpServiceType: *GUID,
    lpServiceName: [*:0]u16,
    dwNameLength: u32,
) callconv(.winapi) i32;

pub extern "ws2_32" fn getaddrinfo(
    pNodeName: ?[*:0]const u8,
    pServiceName: ?[*:0]const u8,
    pHints: ?*const addrinfoa,
    ppResult: *?*addrinfoa,
) callconv(.winapi) i32;

pub extern "ws2_32" fn GetAddrInfoExA(
    pName: ?[*:0]const u8,
    pServiceName: ?[*:0]const u8,
    dwNameSapce: u32,
    lpNspId: ?*GUID,
    hints: ?*const addrinfoexA,
    ppResult: **addrinfoexA,
    timeout: ?*timeval,
    lpOverlapped: ?*OVERLAPPED,
    lpCompletionRoutine: ?LPLOOKUPSERVICE_COMPLETION_ROUTINE,
) callconv(.winapi) i32;

pub extern "ws2_32" fn GetAddrInfoExCancel(
    lpHandle: *HANDLE,
) callconv(.winapi) i32;

pub extern "ws2_32" fn GetAddrInfoExOverlappedResult(
    lpOverlapped: *OVERLAPPED,
) callconv(.winapi) i32;

pub extern "ws2_32" fn freeaddrinfo(
    pAddrInfo: ?*addrinfoa,
) callconv(.winapi) void;

pub extern "ws2_32" fn FreeAddrInfoEx(
    pAddrInfoEx: ?*addrinfoexA,
) callconv(.winapi) void;

pub extern "ws2_32" fn getnameinfo(
    pSockaddr: *const sockaddr,
    SockaddrLength: i32,
    pNodeBuffer: ?[*]u8,
    NodeBufferSize: u32,
    pServiceBuffer: ?[*]u8,
    ServiceBufferName: u32,
    Flags: i32,
) callconv(.winapi) i32;

pub extern "iphlpapi" fn if_nametoindex(
    InterfaceName: [*:0]const u8,
) callconv(.winapi) u32;
//! Program Data Base debugging information format.
//!
//! This namespace contains unopinionated types and data definitions only. For
//! an implementation of parsing and caching PDB information, see
//! `std.debug.Pdb`.
//!
//! Most of this is based on information gathered from LLVM source code,
//! documentation and/or contributors.

const std = @import("std.zig");
const io = std.io;
const math = std.math;
const mem = std.mem;
const coff = std.coff;
const fs = std.fs;
const File = std.fs.File;
const debug = std.debug;

const ArrayList = std.ArrayList;

/// https://llvm.org/docs/PDB/DbiStream.html#stream-header
pub const DbiStreamHeader = extern struct {
    version_signature: i32,
    version_header: u32,
    age: u32,
    global_stream_index: u16,
    build_number: u16,
    public_stream_index: u16,
    pdb_dll_version: u16,
    sym_record_stream: u16,
    pdb_dll_rbld: u16,
    mod_info_size: u32,
    section_contribution_size: u32,
    section_map_size: u32,
    source_info_size: i32,
    type_server_size: i32,
    mfc_type_server_index: u32,
    optional_dbg_header_size: i32,
    ec_substream_size: i32,
    flags: u16,
    machine: u16,
    padding: u32,
};

pub const SectionContribEntry = extern struct {
    /// COFF Section index, 1-based
    section: u16,
    padding1: [2]u8,
    offset: u32,
    size: u32,
    characteristics: u32,
    module_index: u16,
    padding2: [2]u8,
    data_crc: u32,
    reloc_crc: u32,
};

pub const ModInfo = extern struct {
    unused1: u32,
    section_contr: SectionContribEntry,
    flags: u16,
    module_sym_stream: u16,
    sym_byte_size: u32,
    c11_byte_size: u32,
    c13_byte_size: u32,
    source_file_count: u16,
    padding: [2]u8,
    unused2: u32,
    source_file_name_index: u32,
    pdb_file_path_name_index: u32,
    // These fields are variable length
    //module_name: char[],
    //obj_file_name: char[],
};

pub const SectionMapHeader = extern struct {
    /// Number of segment descriptors
    count: u16,

    /// Number of logical segment descriptors
    log_count: u16,
};

pub const SectionMapEntry = extern struct {
    /// See the SectionMapEntryFlags enum below.
    flags: u16,

    /// Logical overlay number
    ovl: u16,

    /// Group index into descriptor array.
    group: u16,
    frame: u16,

    /// Byte index of segment / group name in string table, or 0xFFFF.
    section_name: u16,

    /// Byte index of class in string table, or 0xFFFF.
    class_name: u16,

    /// Byte offset of the logical segment within physical segment.  If group is set in flags, this is the offset of the group.
    offset: u32,

    /// Byte count of the segment or group.
    section_length: u32,
};

pub const StreamType = enum(u16) {
    pdb = 1,
    tpi = 2,
    dbi = 3,
    ipi = 4,
};

/// Duplicate copy of SymbolRecordKind, but using the official CV names. Useful
/// for reference purposes and when dealing with unknown record types.
pub const SymbolKind = enum(u16) {
    compile = 1,
    register_16t = 2,
    constant_16t = 3,
    udt_16t = 4,
    ssearch = 5,
    skip = 7,
    cvreserve = 8,
    objname_st = 9,
    endarg = 10,
    coboludt_16t = 11,
    manyreg_16t = 12,
    @"return" = 13,
    entrythis = 14,
    bprel16 = 256,
    ldata16 = 257,
    gdata16 = 258,
    pub16 = 259,
    lproc16 = 260,
    gproc16 = 261,
    thunk16 = 262,
    block16 = 263,
    with16 = 264,
    label16 = 265,
    cexmodel16 = 266,
    vftable16 = 267,
    regrel16 = 268,
    bprel32_16t = 512,
    ldata32_16t = 513,
    gdata32_16t = 514,
    pub32_16t = 515,
    lproc32_16t = 516,
    gproc32_16t = 517,
    thunk32_st = 518,
    block32_st = 519,
    with32_st = 520,
    label32_st = 521,
    cexmodel32 = 522,
    vftable32_16t = 523,
    regrel32_16t = 524,
    lthread32_16t = 525,
    gthread32_16t = 526,
    slink32 = 527,
    lprocmips_16t = 768,
    gprocmips_16t = 769,
    procref_st = 1024,
    dataref_st = 1025,
    @"align" = 1026,
    lprocref_st = 1027,
    oem = 1028,
    ti16_max = 4096,
    register_st = 4097,
    constant_st = 4098,
    udt_st = 4099,
    coboludt_st = 4100,
    manyreg_st = 4101,
    bprel32_st = 4102,
    ldata32_st = 4103,
    gdata32_st = 4104,
    pub32_st = 4105,
    lproc32_st = 4106,
    gproc32_st = 4107,
    vftable32 = 4108,
    regrel32_st = 4109,
    lthread32_st = 4110,
    gthread32_st = 4111,
    lprocmips_st = 4112,
    gprocmips_st = 4113,
    compile2_st = 4115,
    manyreg2_st = 4116,
    lprocia64_st = 4117,
    gprocia64_st = 4118,
    localslot_st = 4119,
    paramslot_st = 4120,
    annotation = 4121,
    gmanproc_st = 4122,
    lmanproc_st = 4123,
    reserved1 = 4124,
    reserved2 = 4125,
    reserved3 = 4126,
    reserved4 = 4127,
    lmandata_st = 4128,
    gmandata_st = 4129,
    manframerel_st = 4130,
    manregister_st = 4131,
    manslot_st = 4132,
    manmanyreg_st = 4133,
    manregrel_st = 4134,
    manmanyreg2_st = 4135,
    mantypref = 4136,
    unamespace_st = 4137,
    st_max = 4352,
    with32 = 4356,
    manyreg = 4362,
    lprocmips = 4372,
    gprocmips = 4373,
    manyreg2 = 4375,
    lprocia64 = 4376,
    gprocia64 = 4377,
    localslot = 4378,
    paramslot = 4379,
    manframerel = 4382,
    manregister = 4383,
    manslot = 4384,
    manmanyreg = 4385,
    manregrel = 4386,
    manmanyreg2 = 4387,
    unamespace = 4388,
    dataref = 4390,
    annotationref = 4392,
    tokenref = 4393,
    gmanproc = 4394,
    lmanproc = 4395,
    attr_framerel = 4398,
    attr_register = 4399,
    attr_regrel = 4400,
    attr_manyreg = 4401,
    sepcode = 4402,
    local_2005 = 4403,
    defrange_2005 = 4404,
    defrange2_2005 = 4405,
    discarded = 4411,
    lprocmips_id = 4424,
    gprocmips_id = 4425,
    lprocia64_id = 4426,
    gprocia64_id = 4427,
    defrange_hlsl = 4432,
    gdata_hlsl = 4433,
    ldata_hlsl = 4434,
    local_dpc_groupshared = 4436,
    defrange_dpc_ptr_tag = 4439,
    dpc_sym_tag_map = 4440,
    armswitchtable = 4441,
    pogodata = 4444,
    inlinesite2 = 4445,
    mod_typeref = 4447,
    ref_minipdb = 4448,
    pdbmap = 4449,
    gdata_hlsl32 = 4450,
    ldata_hlsl32 = 4451,
    gdata_hlsl32_ex = 4452,
    ldata_hlsl32_ex = 4453,
    fastlink = 4455,
    inlinees = 4456,
    end = 6,
    inlinesite_end = 4430,
    proc_id_end = 4431,
    thunk32 = 4354,
    trampoline = 4396,
    section = 4406,
    coffgroup = 4407,
    @"export" = 4408,
    lproc32 = 4367,
    gproc32 = 4368,
    lproc32_id = 4422,
    gproc32_id = 4423,
    lproc32_dpc = 4437,
    lproc32_dpc_id = 4438,
    register = 4358,
    pub32 = 4366,
    procref = 4389,
    lprocref = 4391,
    envblock = 4413,
    inlinesite = 4429,
    local = 4414,
    defrange = 4415,
    defrange_subfield = 4416,
    defrange_register = 4417,
    defrange_framepointer_rel = 4418,
    defrange_subfield_register = 4419,
    defrange_framepointer_rel_full_scope = 4420,
    defrange_register_rel = 4421,
    block32 = 4355,
    label32 = 4357,
    objname = 4353,
    compile2 = 4374,
    compile3 = 4412,
    frameproc = 4114,
    callsiteinfo = 4409,
    filestatic = 4435,
    heapallocsite = 4446,
    framecookie = 4410,
    callees = 4442,
    callers = 4443,
    udt = 4360,
    coboludt = 4361,
    buildinfo = 4428,
    bprel32 = 4363,
    regrel32 = 4369,
    constant = 4359,
    manconstant = 4397,
    ldata32 = 4364,
    gdata32 = 4365,
    lmandata = 4380,
    gmandata = 4381,
    lthread32 = 4370,
    gthread32 = 4371,
};

pub const TypeIndex = u32;

// TODO According to this header:
// https://github.com/microsoft/microsoft-pdb/blob/082c5290e5aff028ae84e43affa8be717aa7af73/include/cvinfo.h#L3722
// we should define RecordPrefix as part of the ProcSym structure.
// This might be important when we start generating PDB in self-hosted with our own PE linker.
pub const ProcSym = extern struct {
    parent: u32,
    end: u32,
    next: u32,
    code_size: u32,
    dbg_start: u32,
    dbg_end: u32,
    function_type: TypeIndex,
    code_offset: u32,
    segment: u16,
    flags: ProcSymFlags,
    name: [1]u8, // null-terminated
};

pub const ProcSymFlags = packed struct {
    has_fp: bool,
    has_iret: bool,
    has_fret: bool,
    is_no_return: bool,
    is_unreachable: bool,
    has_custom_calling_conv: bool,
    is_no_inline: bool,
    has_optimized_debug_info: bool,
};

pub const SectionContrSubstreamVersion = enum(u32) {
    Ver60 = 0xeffe0000 + 19970605,
    V2 = 0xeffe0000 + 20140516,
    _,
};

pub const RecordPrefix = extern struct {
    /// Record length, starting from &record_kind.
    record_len: u16,

    /// Record kind enum (SymRecordKind or TypeRecordKind)
    record_kind: SymbolKind,
};

/// The following variable length array appears immediately after the header.
/// The structure definition follows.
/// LineBlockFragmentHeader Blocks[]
/// Each `LineBlockFragmentHeader` as specified below.
pub const LineFragmentHeader = extern struct {
    /// Code offset of line contribution.
    reloc_offset: u32,

    /// Code segment of line contribution.
    reloc_segment: u16,
    flags: LineFlags,

    /// Code size of this line contribution.
    code_size: u32,
};

pub const LineFlags = packed struct {
    /// CV_LINES_HAVE_COLUMNS
    have_columns: bool,
    unused: u15,
};

/// The following two variable length arrays appear immediately after the
/// header.  The structure definitions follow.
/// LineNumberEntry   Lines[NumLines];
/// ColumnNumberEntry Columns[NumLines];
pub const LineBlockFragmentHeader = extern struct {
    /// Offset of FileChecksum entry in File
    /// checksums buffer.  The checksum entry then
    /// contains another offset into the string
    /// table of the actual name.
    name_index: u32,
    num_lines: u32,

    /// code size of block, in bytes
    block_size: u32,
};

pub const LineNumberEntry = extern struct {
    /// Offset to start of code bytes for line number
    offset: u32,
    flags: Flags,

    pub const Flags = packed struct(u32) {
        /// Start line number
        start: u24,
        /// Delta of lines to the end of the expression. Still unclear.
        // TODO figure out the point of this field.
        end: u7,
        is_statement: bool,
    };
};

pub const ColumnNumberEntry = extern struct {
    start_column: u16,
    end_column: u16,
};

/// Checksum bytes follow.
pub const FileChecksumEntryHeader = extern struct {
    /// Byte offset of filename in global string table.
    file_name_offset: u32,
    /// Number of bytes of checksum.
    checksum_size: u8,
    /// FileChecksumKind
    checksum_kind: u8,
};

pub const DebugSubsectionKind = enum(u32) {
    none = 0,
    symbols = 0xf1,
    lines = 0xf2,
    string_table = 0xf3,
    file_checksums = 0xf4,
    frame_data = 0xf5,
    inlinee_lines = 0xf6,
    cross_scope_imports = 0xf7,
    cross_scope_exports = 0xf8,

    // These appear to relate to .Net assembly info.
    il_lines = 0xf9,
    func_md_token_map = 0xfa,
    type_md_token_map = 0xfb,
    merged_assembly_input = 0xfc,

    coff_symbol_rva = 0xfd,
};

pub const DebugSubsectionHeader = extern struct {
    /// codeview::DebugSubsectionKind enum
    kind: DebugSubsectionKind,

    /// number of bytes occupied by this record.
    length: u32,
};

pub const StringTableHeader = extern struct {
    /// PDBStringTableSignature
    signature: u32,
    /// 1 or 2
    hash_version: u32,
    /// Number of bytes of names buffer.
    byte_size: u32,
};

// https://llvm.org/docs/PDB/MsfFile.html#the-superblock
pub const SuperBlock = extern struct {
    /// The LLVM docs list a space between C / C++ but empirically this is not the case.
    pub const expect_magic = "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";

    file_magic: [expect_magic.len]u8,

    /// The block size of the internal file system. Valid values are 512, 1024,
    /// 2048, and 4096 bytes. Certain aspects of the MSF file layout vary depending
    /// on the block sizes. For the purposes of LLVM, we handle only block sizes of
    /// 4KiB, and all further discussion assumes a block size of 4KiB.
    block_size: u32,

    /// The index of a block within the file, at which begins a bitfield representing
    /// the set of all blocks within the file which are “free” (i.e. the data within
    /// that block is not used). See The Free Block Map for more information. Important:
    /// FreeBlockMapBlock can only be 1 or 2!
    free_block_map_block: u32,

    /// The total number of blocks in the file. NumBlocks * BlockSize should equal the
    /// size of the file on disk.
    num_blocks: u32,

    /// The size of the stream directory, in bytes. The stream directory contains
    /// information about each stream’s size and the set of blocks that it occupies.
    /// It will be described in more detail later.
    num_directory_bytes: u32,

    unknown: u32,
    /// The index of a block within the MSF file. At this block is an array of
    /// ulittle32_t’s listing the blocks that the stream directory resides on.
    /// For large MSF files, the stream directory (which describes the block
    /// layout of each stream) may not fit entirely on a single block. As a
    /// result, this extra layer of indirection is introduced, whereby this
    /// block contains the list of blocks that the stream directory occupies,
    /// and the stream directory itself can be stitched together accordingly.
    /// The number of ulittle32_t’s in this array is given by
    /// ceil(NumDirectoryBytes / BlockSize).
    // Note: microsoft-pdb code actually suggests this is a variable-length
    // array. If the indices of blocks occupied by the Stream Directory didn't
    // fit in one page, there would be other u32 following it.
    // This would mean the Stream Directory is bigger than BlockSize / sizeof(u32)
    // blocks. We're not even close to this with a 1GB pdb file, and LLVM didn't
    // implement it so we're kind of safe making this assumption for now.
    block_map_addr: u32,
};
//! POSIX API layer.
//!
//! This is more cross platform than using OS-specific APIs, however, it is
//! lower-level and less portable than other namespaces such as `std.fs` and
//! `std.process`.
//!
//! These APIs are generally lowered to libc function calls if and only if libc
//! is linked. Most operating systems other than Windows, Linux, and WASI
//! require always linking libc because they use it as the stable syscall ABI.
//!
//! Operating systems that are not POSIX-compliant are sometimes supported by
//! this API layer; sometimes not. Generally, an implementation will be
//! provided only if such implementation is straightforward on that operating
//! system. Otherwise, programmers are expected to use OS-specific logic to
//! deal with the exception.

const builtin = @import("builtin");
const root = @import("root");
const std = @import("std.zig");
const mem = std.mem;
const fs = std.fs;
const max_path_bytes = fs.max_path_bytes;
const maxInt = std.math.maxInt;
const cast = std.math.cast;
const assert = std.debug.assert;
const native_os = builtin.os.tag;
const page_size_min = std.heap.page_size_min;

test {
    _ = @import("posix/test.zig");
}

/// Whether to use libc for the POSIX API layer.
const use_libc = builtin.link_libc or switch (native_os) {
    .windows, .wasi => true,
    else => false,
};

const linux = std.os.linux;
const windows = std.os.windows;
const wasi = std.os.wasi;

/// A libc-compatible API layer.
pub const system = if (use_libc)
    std.c
else switch (native_os) {
    .linux => linux,
    .plan9 => std.os.plan9,
    else => struct {
        pub const ucontext_t = void;
        pub const pid_t = void;
        pub const pollfd = void;
        pub const fd_t = void;
        pub const uid_t = void;
        pub const gid_t = void;
    },
};

pub const AF = system.AF;
pub const AF_SUN = system.AF_SUN;
pub const AI = system.AI;
pub const ARCH = system.ARCH;
pub const AT = system.AT;
pub const AT_SUN = system.AT_SUN;
pub const CLOCK = system.CLOCK;
pub const CPU_COUNT = system.CPU_COUNT;
pub const CTL = system.CTL;
pub const DT = system.DT;
pub const E = system.E;
pub const Elf_Symndx = system.Elf_Symndx;
pub const F = system.F;
pub const FD_CLOEXEC = system.FD_CLOEXEC;
pub const Flock = system.Flock;
pub const HOST_NAME_MAX = system.HOST_NAME_MAX;
pub const HW = system.HW;
pub const IFNAMESIZE = system.IFNAMESIZE;
pub const IOV_MAX = system.IOV_MAX;
pub const IPPROTO = system.IPPROTO;
pub const KERN = system.KERN;
pub const Kevent = system.Kevent;
pub const MADV = system.MADV;
pub const MAP = system.MAP;
pub const MAX_ADDR_LEN = system.MAX_ADDR_LEN;
pub const MFD = system.MFD;
pub const MREMAP = system.MREMAP;
pub const MSF = system.MSF;
pub const MSG = system.MSG;
pub const NAME_MAX = system.NAME_MAX;
pub const O = system.O;
pub const PATH_MAX = system.PATH_MAX;
pub const POLL = system.POLL;
pub const POSIX_FADV = system.POSIX_FADV;
pub const PR = system.PR;
pub const PROT = system.PROT;
pub const REG = system.REG;
pub const RLIM = system.RLIM;
pub const RR = system.RR;
pub const S = system.S;
pub const SA = system.SA;
pub const SC = system.SC;
pub const SEEK = system.SEEK;
pub const SHUT = system.SHUT;
pub const SIG = system.SIG;
pub const SIOCGIFINDEX = system.SIOCGIFINDEX;
pub const SO = system.SO;
pub const SOCK = system.SOCK;
pub const SOL = system.SOL;
pub const IFF = system.IFF;
pub const STDERR_FILENO = system.STDERR_FILENO;
pub const STDIN_FILENO = system.STDIN_FILENO;
pub const STDOUT_FILENO = system.STDOUT_FILENO;
pub const SYS = system.SYS;
pub const Sigaction = system.Sigaction;
pub const Stat = system.Stat;
pub const T = system.T;
pub const TCP = system.TCP;
pub const VDSO = system.VDSO;
pub const W = system.W;
pub const _SC = system._SC;
pub const addrinfo = system.addrinfo;
pub const blkcnt_t = system.blkcnt_t;
pub const blksize_t = system.blksize_t;
pub const clock_t = system.clock_t;
pub const clockid_t = system.clockid_t;
pub const timerfd_clockid_t = system.timerfd_clockid_t;
pub const cpu_set_t = system.cpu_set_t;
pub const dev_t = system.dev_t;
pub const dl_phdr_info = system.dl_phdr_info;
pub const empty_sigset = system.empty_sigset;
pub const fd_t = system.fd_t;
pub const file_obj = system.file_obj;
pub const filled_sigset = system.filled_sigset;
pub const gid_t = system.gid_t;
pub const ifreq = system.ifreq;
pub const ino_t = system.ino_t;
pub const mcontext_t = system.mcontext_t;
pub const mode_t = system.mode_t;
pub const msghdr = system.msghdr;
pub const msghdr_const = system.msghdr_const;
pub const nfds_t = system.nfds_t;
pub const nlink_t = system.nlink_t;
pub const off_t = system.off_t;
pub const pid_t = system.pid_t;
pub const pollfd = system.pollfd;
pub const port_event = system.port_event;
pub const port_notify = system.port_notify;
pub const port_t = system.port_t;
pub const rlim_t = system.rlim_t;
pub const rlimit = system.rlimit;
pub const rlimit_resource = system.rlimit_resource;
pub const rusage = system.rusage;
pub const sa_family_t = system.sa_family_t;
pub const siginfo_t = system.siginfo_t;
pub const sigset_t = system.sigset_t;
pub const sockaddr = system.sockaddr;
pub const socklen_t = system.socklen_t;
pub const stack_t = system.stack_t;
pub const time_t = system.time_t;
pub const timespec = system.timespec;
pub const timestamp_t = system.timestamp_t;
pub const timeval = system.timeval;
pub const timezone = system.timezone;
pub const ucontext_t = system.ucontext_t;
pub const uid_t = system.uid_t;
pub const user_desc = system.user_desc;
pub const utsname = system.utsname;

pub const termios = system.termios;
pub const CSIZE = system.CSIZE;
pub const NCCS = system.NCCS;
pub const cc_t = system.cc_t;
pub const V = system.V;
pub const speed_t = system.speed_t;
pub const tc_iflag_t = system.tc_iflag_t;
pub const tc_oflag_t = system.tc_oflag_t;
pub const tc_cflag_t = system.tc_cflag_t;
pub const tc_lflag_t = system.tc_lflag_t;

pub const F_OK = system.F_OK;
pub const R_OK = system.R_OK;
pub const W_OK = system.W_OK;
pub const X_OK = system.X_OK;

pub const iovec = extern struct {
    base: [*]u8,
    len: usize,
};

pub const iovec_const = extern struct {
    base: [*]const u8,
    len: usize,
};

pub const ACCMODE = enum(u2) {
    RDONLY = 0,
    WRONLY = 1,
    RDWR = 2,
};

pub const TCSA = enum(c_uint) {
    NOW,
    DRAIN,
    FLUSH,
    _,
};

pub const winsize = extern struct {
    row: u16,
    col: u16,
    xpixel: u16,
    ypixel: u16,
};

pub const LOCK = struct {
    pub const SH = 1;
    pub const EX = 2;
    pub const NB = 4;
    pub const UN = 8;
};

pub const LOG = struct {
    /// system is unusable
    pub const EMERG = 0;
    /// action must be taken immediately
    pub const ALERT = 1;
    /// critical conditions
    pub const CRIT = 2;
    /// error conditions
    pub const ERR = 3;
    /// warning conditions
    pub const WARNING = 4;
    /// normal but significant condition
    pub const NOTICE = 5;
    /// informational
    pub const INFO = 6;
    /// debug-level messages
    pub const DEBUG = 7;
};

pub const socket_t = if (native_os == .windows) windows.ws2_32.SOCKET else fd_t;

/// Obtains errno from the return value of a system function call.
///
/// For some systems this will obtain the value directly from the syscall return value;
/// for others it will use a thread-local errno variable. Therefore, this
/// function only returns a well-defined value when it is called directly after
/// the system function call whose errno value is intended to be observed.
pub fn errno(rc: anytype) E {
    if (use_libc) {
        return if (rc == -1) @enumFromInt(std.c._errno().*) else .SUCCESS;
    }
    const signed: isize = @bitCast(rc);
    const int = if (signed > -4096 and signed < 0) -signed else 0;
    return @enumFromInt(int);
}

/// Closes the file descriptor.
///
/// Asserts the file descriptor is open.
///
/// This function is not capable of returning any indication of failure. An
/// application which wants to ensure writes have succeeded before closing must
/// call `fsync` before `close`.
///
/// The Zig standard library does not support POSIX thread cancellation.
pub fn close(fd: fd_t) void {
    if (native_os == .windows) {
        return windows.CloseHandle(fd);
    }
    if (native_os == .wasi and !builtin.link_libc) {
        _ = std.os.wasi.fd_close(fd);
        return;
    }
    switch (errno(system.close(fd))) {
        .BADF => unreachable, // Always a race condition.
        .INTR => return, // This is still a success. See https://github.com/ziglang/zig/issues/2425
        else => return,
    }
}

pub const FChmodError = error{
    AccessDenied,
    PermissionDenied,
    InputOutput,
    SymLinkLoop,
    FileNotFound,
    SystemResources,
    ReadOnlyFileSystem,
} || UnexpectedError;

/// Changes the mode of the file referred to by the file descriptor.
///
/// The process must have the correct privileges in order to do this
/// successfully, or must have the effective user ID matching the owner
/// of the file.
pub fn fchmod(fd: fd_t, mode: mode_t) FChmodError!void {
    if (!fs.has_executable_bit) @compileError("fchmod unsupported by target OS");

    while (true) {
        const res = system.fchmod(fd, mode);
        switch (errno(res)) {
            .SUCCESS => return,
            .INTR => continue,
            .BADF => unreachable,
            .FAULT => unreachable,
            .INVAL => unreachable,
            .ACCES => return error.AccessDenied,
            .IO => return error.InputOutput,
            .LOOP => return error.SymLinkLoop,
            .NOENT => return error.FileNotFound,
            .NOMEM => return error.SystemResources,
            .NOTDIR => return error.FileNotFound,
            .PERM => return error.PermissionDenied,
            .ROFS => return error.ReadOnlyFileSystem,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const FChmodAtError = FChmodError || error{
    /// A component of `path` exceeded `NAME_MAX`, or the entire path exceeded
    /// `PATH_MAX`.
    NameTooLong,
    /// `path` resolves to a symbolic link, and `AT.SYMLINK_NOFOLLOW` was set
    /// in `flags`. This error only occurs on Linux, where changing the mode of
    /// a symbolic link has no meaning and can cause undefined behaviour on
    /// certain filesystems.
    ///
    /// The procfs fallback was used but procfs was not mounted.
    OperationNotSupported,
    /// The procfs fallback was used but the process exceeded its open file
    /// limit.
    ProcessFdQuotaExceeded,
    /// The procfs fallback was used but the system exceeded it open file limit.
    SystemFdQuotaExceeded,
};

/// Changes the `mode` of `path` relative to the directory referred to by
/// `dirfd`. The process must have the correct privileges in order to do this
/// successfully, or must have the effective user ID matching the owner of the
/// file.
///
/// On Linux the `fchmodat2` syscall will be used if available, otherwise a
/// workaround using procfs will be employed. Changing the mode of a symbolic
/// link with `AT.SYMLINK_NOFOLLOW` set will also return
/// `OperationNotSupported`, as:
///
///  1. Permissions on the link are ignored when resolving its target.
///  2. This operation has been known to invoke undefined behaviour across
///     different filesystems[1].
///
/// [1]: https://sourceware.org/legacy-ml/libc-alpha/2020-02/msg00467.html.
pub inline fn fchmodat(dirfd: fd_t, path: []const u8, mode: mode_t, flags: u32) FChmodAtError!void {
    if (!fs.has_executable_bit) @compileError("fchmodat unsupported by target OS");

    // No special handling for linux is needed if we can use the libc fallback
    // or `flags` is empty. Glibc only added the fallback in 2.32.
    const skip_fchmodat_fallback = native_os != .linux or
        std.c.versionCheck(.{ .major = 2, .minor = 32, .patch = 0 }) or
        flags == 0;

    // This function is marked inline so that when flags is comptime-known,
    // skip_fchmodat_fallback will be comptime-known true.
    if (skip_fchmodat_fallback)
        return fchmodat1(dirfd, path, mode, flags);

    return fchmodat2(dirfd, path, mode, flags);
}

fn fchmodat1(dirfd: fd_t, path: []const u8, mode: mode_t, flags: u32) FChmodAtError!void {
    const path_c = try toPosixPath(path);
    while (true) {
        const res = system.fchmodat(dirfd, &path_c, mode, flags);
        switch (errno(res)) {
            .SUCCESS => return,
            .INTR => continue,
            .BADF => unreachable,
            .FAULT => unreachable,
            .INVAL => unreachable,
            .ACCES => return error.AccessDenied,
            .IO => return error.InputOutput,
            .LOOP => return error.SymLinkLoop,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NAMETOOLONG => return error.NameTooLong,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOENT => return error.FileNotFound,
            .NOTDIR => return error.FileNotFound,
            .NOMEM => return error.SystemResources,
            .OPNOTSUPP => return error.OperationNotSupported,
            .PERM => return error.PermissionDenied,
            .ROFS => return error.ReadOnlyFileSystem,
            else => |err| return unexpectedErrno(err),
        }
    }
}

fn fchmodat2(dirfd: fd_t, path: []const u8, mode: mode_t, flags: u32) FChmodAtError!void {
    const global = struct {
        var has_fchmodat2: bool = true;
    };
    const path_c = try toPosixPath(path);
    const use_fchmodat2 = (builtin.os.isAtLeast(.linux, .{ .major = 6, .minor = 6, .patch = 0 }) orelse false) and
        @atomicLoad(bool, &global.has_fchmodat2, .monotonic);
    while (use_fchmodat2) {
        // Later on this should be changed to `system.fchmodat2`
        // when the musl/glibc add a wrapper.
        const res = linux.fchmodat2(dirfd, &path_c, mode, flags);
        switch (E.init(res)) {
            .SUCCESS => return,
            .INTR => continue,
            .BADF => unreachable,
            .FAULT => unreachable,
            .INVAL => unreachable,
            .ACCES => return error.AccessDenied,
            .IO => return error.InputOutput,
            .LOOP => return error.SymLinkLoop,
            .NOENT => return error.FileNotFound,
            .NOMEM => return error.SystemResources,
            .NOTDIR => return error.FileNotFound,
            .OPNOTSUPP => return error.OperationNotSupported,
            .PERM => return error.PermissionDenied,
            .ROFS => return error.ReadOnlyFileSystem,

            .NOSYS => {
                @atomicStore(bool, &global.has_fchmodat2, false, .monotonic);
                break;
            },
            else => |err| return unexpectedErrno(err),
        }
    }

    // Fallback to changing permissions using procfs:
    //
    // 1. Open `path` as a `PATH` descriptor.
    // 2. Stat the fd and check if it isn't a symbolic link.
    // 3. Generate the procfs reference to the fd via `/proc/self/fd/{fd}`.
    // 4. Pass the procfs path to `chmod` with the `mode`.
    var pathfd: fd_t = undefined;
    while (true) {
        const rc = system.openat(dirfd, &path_c, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(mode_t, 0));
        switch (errno(rc)) {
            .SUCCESS => {
                pathfd = @intCast(rc);
                break;
            },
            .INTR => continue,
            .FAULT => unreachable,
            .INVAL => unreachable,
            .ACCES => return error.AccessDenied,
            .PERM => return error.PermissionDenied,
            .LOOP => return error.SymLinkLoop,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NAMETOOLONG => return error.NameTooLong,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOENT => return error.FileNotFound,
            .NOMEM => return error.SystemResources,
            else => |err| return unexpectedErrno(err),
        }
    }
    defer close(pathfd);

    const stat = fstatatZ(pathfd, "", AT.EMPTY_PATH) catch |err| switch (err) {
        error.NameTooLong => unreachable,
        error.FileNotFound => unreachable,
        error.InvalidUtf8 => unreachable,
        else => |e| return e,
    };
    if ((stat.mode & S.IFMT) == S.IFLNK)
        return error.OperationNotSupported;

    var procfs_buf: ["/proc/self/fd/-2147483648\x00".len]u8 = undefined;
    const proc_path = std.fmt.bufPrintZ(procfs_buf[0..], "/proc/self/fd/{d}", .{pathfd}) catch unreachable;
    while (true) {
        const res = system.chmod(proc_path, mode);
        switch (errno(res)) {
            // Getting NOENT here means that procfs isn't mounted.
            .NOENT => return error.OperationNotSupported,

            .SUCCESS => return,
            .INTR => continue,
            .BADF => unreachable,
            .FAULT => unreachable,
            .INVAL => unreachable,
            .ACCES => return error.AccessDenied,
            .IO => return error.InputOutput,
            .LOOP => return error.SymLinkLoop,
            .NOMEM => return error.SystemResources,
            .NOTDIR => return error.FileNotFound,
            .PERM => return error.PermissionDenied,
            .ROFS => return error.ReadOnlyFileSystem,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const FChownError = error{
    AccessDenied,
    PermissionDenied,
    InputOutput,
    SymLinkLoop,
    FileNotFound,
    SystemResources,
    ReadOnlyFileSystem,
} || UnexpectedError;

/// Changes the owner and group of the file referred to by the file descriptor.
/// The process must have the correct privileges in order to do this
/// successfully. The group may be changed by the owner of the directory to
/// any group of which the owner is a member. If the owner or group is
/// specified as `null`, the ID is not changed.
pub fn fchown(fd: fd_t, owner: ?uid_t, group: ?gid_t) FChownError!void {
    switch (native_os) {
        .windows, .wasi => @compileError("Unsupported OS"),
        else => {},
    }

    while (true) {
        const res = system.fchown(fd, owner orelse ~@as(uid_t, 0), group orelse ~@as(gid_t, 0));

        switch (errno(res)) {
            .SUCCESS => return,
            .INTR => continue,
            .BADF => unreachable, // Can be reached if the fd refers to a directory opened without `Dir.OpenOptions{ .iterate = true }`

            .FAULT => unreachable,
            .INVAL => unreachable,
            .ACCES => return error.AccessDenied,
            .IO => return error.InputOutput,
            .LOOP => return error.SymLinkLoop,
            .NOENT => return error.FileNotFound,
            .NOMEM => return error.SystemResources,
            .NOTDIR => return error.FileNotFound,
            .PERM => return error.PermissionDenied,
            .ROFS => return error.ReadOnlyFileSystem,
            else => |err| return unexpectedErrno(err),
        }
    }
}

pub const RebootError = error{
    PermissionDenied,
} || UnexpectedError;

pub const RebootCommand = switch (native_os) {
    .linux => union(linux.LINUX_REBOOT.CMD) {
        RESTART: void,
        HALT: void,
        CAD_ON: void,
        CAD_OFF: void,
        POWER_OFF: void,
        RESTART2: [*:0]const u8,
        SW_SUSPEND: void,
        KEXEC: void,
    },
    else => @compileError("Unsupported OS"),
};

pub fn reboot(cmd: RebootCommand) RebootError!void {
    switch (native_os) {
        .linux => {
            switch (linux.E.init(linux.reboot(
                .MAGIC1,
                .MAGIC2,
                cmd,
                switch (cmd) {
                    .RESTART2 => |s| s,
                    else => null,
                },
            ))) {
                .SUCCESS => {},
                .PERM => return error.PermissionDenied,
                else => |err| return std.posix.unexpectedErrno(err),
            }
            switch (cmd) {
                .CAD_OFF => {},
                .CAD_ON => {},
                .SW_SUSPEND => {},

                .HALT => unreachable,
                .KEXEC => unreachable,
                .POWER_OFF => unreachable,
                .RESTART => unreachable,
                .RESTART2 => unreachable,
            }
        },
        else => @compileError("Unsupported OS"),
    }
}

pub const GetRandomError = OpenError;

/// Obtain a series of random bytes. These bytes can be used to seed user-space
/// random number generators or for cryptographic purposes.
/// When linking against libc, this calls the
/// appropriate OS-specific library call. Otherwise it uses the zig standard
/// library implementation.
pub fn getrandom(buffer: []u8) GetRandomError!void {
    if (native_os == .windows) {
        return windows.RtlGenRandom(buffer);
    }
    if (builtin.link_libc and @TypeOf(system.arc4random_buf) != void) {
        system.arc4random_buf(buffer.ptr, buffer.len);
        return;
    }
    if (native_os == .wasi) switch (wasi.random_get(buffer.ptr, buffer.len)) {
        .SUCCESS => return,
        else => |err| return unexpectedErrno(err),
    };
    if (@TypeOf(system.getrandom) != void) {
        var buf = buffer;
        const use_c = native_os != .linux or
            std.c.versionCheck(std.SemanticVersion{ .major = 2, .minor = 25, .patch = 0 });

        while (buf.len != 0) {
            const num_read: usize, const err = if (use_c) res: {
                const rc = std.c.getrandom(buf.ptr, buf.len, 0);
                break :res .{ @bitCast(rc), errno(rc) };
            } else res: {
                const rc = linux.getrandom(buf.ptr, buf.len, 0);
                break :res .{ rc, linux.E.init(rc) };
            };

            switch (err) {
                .SUCCESS => buf = buf[num_read..],
                .INVAL => unreachable,
                .FAULT => unreachable,
                .INTR => continue,
                else => return unexpectedErrno(err),
            }
        }
        return;
    }
    if (native_os == .emscripten) {
        const err = errno(std.c.getentropy(buffer.ptr, buffer.len));
        switch (err) {
            .SUCCESS => return,
            else => return unexpectedErrno(err),
        }
    }
    return getRandomBytesDevURandom(buffer);
}

fn getRandomBytesDevURandom(buf: []u8) !void {
    const fd = try openZ("/dev/urandom", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer close(fd);

    const st = try fstat(fd);
    if (!S.ISCHR(st.mode)) {
        return error.NoDevice;
    }

    const file: fs.File = .{ .handle = fd };
    const stream = file.reader();
    stream.readNoEof(buf) catch return error.Unexpected;
}

/// Causes abnormal process termination.
/// If linking against libc, this calls the ab```
