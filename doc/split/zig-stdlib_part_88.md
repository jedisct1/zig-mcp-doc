```
txattr = 13,
    removexattr = 14,
    lremovexattr = 15,
    fremovexattr = 16,
    getcwd = 17,
    lookup_dcookie = 18,
    eventfd2 = 19,
    epoll_create1 = 20,
    epoll_ctl = 21,
    epoll_pwait = 22,
    dup = 23,
    dup3 = 24,
    fcntl = 25,
    inotify_init1 = 26,
    inotify_add_watch = 27,
    inotify_rm_watch = 28,
    ioctl = 29,
    ioprio_set = 30,
    ioprio_get = 31,
    flock = 32,
    mknodat = 33,
    mkdirat = 34,
    unlinkat = 35,
    symlinkat = 36,
    linkat = 37,
    umount2 = 39,
    mount = 40,
    pivot_root = 41,
    nfsservctl = 42,
    statfs = 43,
    fstatfs = 44,
    truncate = 45,
    ftruncate = 46,
    fallocate = 47,
    faccessat = 48,
    chdir = 49,
    fchdir = 50,
    chroot = 51,
    fchmod = 52,
    fchmodat = 53,
    fchownat = 54,
    fchown = 55,
    openat = 56,
    close = 57,
    vhangup = 58,
    pipe2 = 59,
    quotactl = 60,
    getdents64 = 61,
    lseek = 62,
    read = 63,
    write = 64,
    readv = 65,
    writev = 66,
    pread64 = 67,
    pwrite64 = 68,
    preadv = 69,
    pwritev = 70,
    sendfile64 = 71,
    pselect6 = 72,
    ppoll = 73,
    signalfd4 = 74,
    vmsplice = 75,
    splice = 76,
    tee = 77,
    readlinkat = 78,
    sync = 81,
    fsync = 82,
    fdatasync = 83,
    sync_file_range = 84,
    timerfd_create = 85,
    timerfd_settime = 86,
    timerfd_gettime = 87,
    utimensat = 88,
    acct = 89,
    capget = 90,
    capset = 91,
    personality = 92,
    exit = 93,
    exit_group = 94,
    waitid = 95,
    set_tid_address = 96,
    unshare = 97,
    futex = 98,
    set_robust_list = 99,
    get_robust_list = 100,
    nanosleep = 101,
    getitimer = 102,
    setitimer = 103,
    kexec_load = 104,
    init_module = 105,
    delete_module = 106,
    timer_create = 107,
    timer_gettime = 108,
    timer_getoverrun = 109,
    timer_settime = 110,
    timer_delete = 111,
    clock_settime = 112,
    clock_gettime = 113,
    clock_getres = 114,
    clock_nanosleep = 115,
    syslog = 116,
    ptrace = 117,
    sched_setparam = 118,
    sched_setscheduler = 119,
    sched_getscheduler = 120,
    sched_getparam = 121,
    sched_setaffinity = 122,
    sched_getaffinity = 123,
    sched_yield = 124,
    sched_get_priority_max = 125,
    sched_get_priority_min = 126,
    sched_rr_get_interval = 127,
    restart_syscall = 128,
    kill = 129,
    tkill = 130,
    tgkill = 131,
    sigaltstack = 132,
    rt_sigsuspend = 133,
    rt_sigaction = 134,
    rt_sigprocmask = 135,
    rt_sigpending = 136,
    rt_sigtimedwait = 137,
    rt_sigqueueinfo = 138,
    rt_sigreturn = 139,
    setpriority = 140,
    getpriority = 141,
    reboot = 142,
    setregid = 143,
    setgid = 144,
    setreuid = 145,
    setuid = 146,
    setresuid = 147,
    getresuid = 148,
    setresgid = 149,
    getresgid = 150,
    setfsuid = 151,
    setfsgid = 152,
    times = 153,
    setpgid = 154,
    getpgid = 155,
    getsid = 156,
    setsid = 157,
    getgroups = 158,
    setgroups = 159,
    uname = 160,
    sethostname = 161,
    setdomainname = 162,
    getrusage = 165,
    umask = 166,
    prctl = 167,
    getcpu = 168,
    gettimeofday = 169,
    settimeofday = 170,
    adjtimex = 171,
    getpid = 172,
    getppid = 173,
    getuid = 174,
    geteuid = 175,
    getgid = 176,
    getegid = 177,
    gettid = 178,
    sysinfo = 179,
    mq_open = 180,
    mq_unlink = 181,
    mq_timedsend = 182,
    mq_timedreceive = 183,
    mq_notify = 184,
    mq_getsetattr = 185,
    msgget = 186,
    msgctl = 187,
    msgrcv = 188,
    msgsnd = 189,
    semget = 190,
    semctl = 191,
    semtimedop = 192,
    semop = 193,
    shmget = 194,
    shmctl = 195,
    shmat = 196,
    shmdt = 197,
    socket = 198,
    socketpair = 199,
    bind = 200,
    listen = 201,
    accept = 202,
    connect = 203,
    getsockname = 204,
    getpeername = 205,
    sendto = 206,
    recvfrom = 207,
    setsockopt = 208,
    getsockopt = 209,
    shutdown = 210,
    sendmsg = 211,
    recvmsg = 212,
    readahead = 213,
    brk = 214,
    munmap = 215,
    mremap = 216,
    add_key = 217,
    request_key = 218,
    keyctl = 219,
    clone = 220,
    execve = 221,
    mmap = 222,
    fadvise64_64 = 223,
    swapon = 224,
    swapoff = 225,
    mprotect = 226,
    msync = 227,
    mlock = 228,
    munlock = 229,
    mlockall = 230,
    munlockall = 231,
    mincore = 232,
    madvise = 233,
    remap_file_pages = 234,
    mbind = 235,
    get_mempolicy = 236,
    set_mempolicy = 237,
    migrate_pages = 238,
    move_pages = 239,
    rt_tgsigqueueinfo = 240,
    perf_event_open = 241,
    accept4 = 242,
    recvmmsg = 243,
    wait4 = 260,
    prlimit64 = 261,
    fanotify_init = 262,
    fanotify_mark = 263,
    name_to_handle_at = 264,
    open_by_handle_at = 265,
    clock_adjtime = 266,
    syncfs = 267,
    setns = 268,
    sendmmsg = 269,
    process_vm_readv = 270,
    process_vm_writev = 271,
    kcmp = 272,
    finit_module = 273,
    sched_setattr = 274,
    sched_getattr = 275,
    renameat2 = 276,
    seccomp = 277,
    getrandom = 278,
    memfd_create = 279,
    bpf = 280,
    execveat = 281,
    userfaultfd = 282,
    membarrier = 283,
    mlock2 = 284,
    copy_file_range = 285,
    preadv2 = 286,
    pwritev2 = 287,
    pkey_mprotect = 288,
    pkey_alloc = 289,
    pkey_free = 290,
    statx = 291,
    io_pgetevents = 292,
    rseq = 293,
    kexec_file_load = 294,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    clone3 = 435,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
    quotactl_fd = 443,
    landlock_create_ruleset = 444,
    landlock_add_rule = 445,
    landlock_restrict_self = 446,
    process_mrelease = 448,
    futex_waitv = 449,
    set_mempolicy_home_node = 450,
    cachestat = 451,
    fchmodat2 = 452,
    map_shadow_stack = 453,
    futex_wake = 454,
    futex_wait = 455,
    futex_requeue = 456,
    statmount = 457,
    listmount = 458,
    lsm_get_self_attr = 459,
    lsm_set_self_attr = 460,
    lsm_list_modules = 461,
    mseal = 462,
};

pub const Arc = enum(usize) {
    io_setup = 0,
    io_destroy = 1,
    io_submit = 2,
    io_cancel = 3,
    io_getevents_time32 = 4,
    setxattr = 5,
    lsetxattr = 6,
    fsetxattr = 7,
    getxattr = 8,
    lgetxattr = 9,
    fgetxattr = 10,
    listxattr = 11,
    llistxattr = 12,
    flistxattr = 13,
    removexattr = 14,
    lremovexattr = 15,
    fremovexattr = 16,
    getcwd = 17,
    lookup_dcookie = 18,
    eventfd2 = 19,
    epoll_create1 = 20,
    epoll_ctl = 21,
    epoll_pwait = 22,
    dup = 23,
    dup3 = 24,
    fcntl64 = 25,
    inotify_init1 = 26,
    inotify_add_watch = 27,
    inotify_rm_watch = 28,
    ioctl = 29,
    ioprio_set = 30,
    ioprio_get = 31,
    flock = 32,
    mknodat = 33,
    mkdirat = 34,
    unlinkat = 35,
    symlinkat = 36,
    linkat = 37,
    renameat = 38,
    umount2 = 39,
    mount = 40,
    pivot_root = 41,
    nfsservctl = 42,
    statfs64 = 43,
    fstatfs64 = 44,
    truncate64 = 45,
    ftruncate64 = 46,
    fallocate = 47,
    faccessat = 48,
    chdir = 49,
    fchdir = 50,
    chroot = 51,
    fchmod = 52,
    fchmodat = 53,
    fchownat = 54,
    fchown = 55,
    openat = 56,
    close = 57,
    vhangup = 58,
    pipe2 = 59,
    quotactl = 60,
    getdents64 = 61,
    llseek = 62,
    read = 63,
    write = 64,
    readv = 65,
    writev = 66,
    pread64 = 67,
    pwrite64 = 68,
    preadv = 69,
    pwritev = 70,
    sendfile64 = 71,
    pselect6_time32 = 72,
    ppoll_time32 = 73,
    signalfd4 = 74,
    vmsplice = 75,
    splice = 76,
    tee = 77,
    readlinkat = 78,
    fstatat64 = 79,
    fstat64 = 80,
    sync = 81,
    fsync = 82,
    fdatasync = 83,
    sync_file_range = 84,
    timerfd_create = 85,
    timerfd_settime32 = 86,
    timerfd_gettime32 = 87,
    utimensat_time32 = 88,
    acct = 89,
    capget = 90,
    capset = 91,
    personality = 92,
    exit = 93,
    exit_group = 94,
    waitid = 95,
    set_tid_address = 96,
    unshare = 97,
    futex_time32 = 98,
    set_robust_list = 99,
    get_robust_list = 100,
    nanosleep_time32 = 101,
    getitimer = 102,
    setitimer = 103,
    kexec_load = 104,
    init_module = 105,
    delete_module = 106,
    timer_create = 107,
    timer_gettime32 = 108,
    timer_getoverrun = 109,
    timer_settime32 = 110,
    timer_delete = 111,
    clock_settime32 = 112,
    clock_gettime32 = 113,
    clock_getres_time32 = 114,
    clock_nanosleep_time32 = 115,
    syslog = 116,
    ptrace = 117,
    sched_setparam = 118,
    sched_setscheduler = 119,
    sched_getscheduler = 120,
    sched_getparam = 121,
    sched_setaffinity = 122,
    sched_getaffinity = 123,
    sched_yield = 124,
    sched_get_priority_max = 125,
    sched_get_priority_min = 126,
    sched_rr_get_interval_time32 = 127,
    restart_syscall = 128,
    kill = 129,
    tkill = 130,
    tgkill = 131,
    sigaltstack = 132,
    rt_sigsuspend = 133,
    rt_sigaction = 134,
    rt_sigprocmask = 135,
    rt_sigpending = 136,
    rt_sigtimedwait_time32 = 137,
    rt_sigqueueinfo = 138,
    rt_sigreturn = 139,
    setpriority = 140,
    getpriority = 141,
    reboot = 142,
    setregid = 143,
    setgid = 144,
    setreuid = 145,
    setuid = 146,
    setresuid = 147,
    getresuid = 148,
    setresgid = 149,
    getresgid = 150,
    setfsuid = 151,
    setfsgid = 152,
    times = 153,
    setpgid = 154,
    getpgid = 155,
    getsid = 156,
    setsid = 157,
    getgroups = 158,
    setgroups = 159,
    uname = 160,
    sethostname = 161,
    setdomainname = 162,
    getrlimit = 163,
    setrlimit = 164,
    getrusage = 165,
    umask = 166,
    prctl = 167,
    getcpu = 168,
    gettimeofday = 169,
    settimeofday = 170,
    adjtimex_time32 = 171,
    getpid = 172,
    getppid = 173,
    getuid = 174,
    geteuid = 175,
    getgid = 176,
    getegid = 177,
    gettid = 178,
    sysinfo = 179,
    mq_open = 180,
    mq_unlink = 181,
    mq_timedsend_time32 = 182,
    mq_timedreceive_time32 = 183,
    mq_notify = 184,
    mq_getsetattr = 185,
    msgget = 186,
    msgctl = 187,
    msgrcv = 188,
    msgsnd = 189,
    semget = 190,
    semctl = 191,
    semtimedop_time32 = 192,
    semop = 193,
    shmget = 194,
    shmctl = 195,
    shmat = 196,
    shmdt = 197,
    socket = 198,
    socketpair = 199,
    bind = 200,
    listen = 201,
    accept = 202,
    connect = 203,
    getsockname = 204,
    getpeername = 205,
    sendto = 206,
    recvfrom = 207,
    setsockopt = 208,
    getsockopt = 209,
    shutdown = 210,
    sendmsg = 211,
    recvmsg = 212,
    readahead = 213,
    brk = 214,
    munmap = 215,
    mremap = 216,
    add_key = 217,
    request_key = 218,
    keyctl = 219,
    clone = 220,
    execve = 221,
    mmap2 = 222,
    fadvise64_64 = 223,
    swapon = 224,
    swapoff = 225,
    mprotect = 226,
    msync = 227,
    mlock = 228,
    munlock = 229,
    mlockall = 230,
    munlockall = 231,
    mincore = 232,
    madvise = 233,
    remap_file_pages = 234,
    mbind = 235,
    get_mempolicy = 236,
    set_mempolicy = 237,
    migrate_pages = 238,
    move_pages = 239,
    rt_tgsigqueueinfo = 240,
    perf_event_open = 241,
    accept4 = 242,
    recvmmsg_time32 = 243,
    wait4 = 260,
    prlimit64 = 261,
    fanotify_init = 262,
    fanotify_mark = 263,
    name_to_handle_at = 264,
    open_by_handle_at = 265,
    clock_adjtime32 = 266,
    syncfs = 267,
    setns = 268,
    sendmmsg = 269,
    process_vm_readv = 270,
    process_vm_writev = 271,
    kcmp = 272,
    finit_module = 273,
    sched_setattr = 274,
    sched_getattr = 275,
    renameat2 = 276,
    seccomp = 277,
    getrandom = 278,
    memfd_create = 279,
    bpf = 280,
    execveat = 281,
    userfaultfd = 282,
    membarrier = 283,
    mlock2 = 284,
    copy_file_range = 285,
    preadv2 = 286,
    pwritev2 = 287,
    pkey_mprotect = 288,
    pkey_alloc = 289,
    pkey_free = 290,
    statx = 291,
    io_pgetevents_time32 = 292,
    rseq = 293,
    kexec_file_load = 294,
    clock_gettime = 403,
    clock_settime = 404,
    clock_adjtime = 405,
    clock_getres = 406,
    clock_nanosleep = 407,
    timer_gettime = 408,
    timer_settime = 409,
    timerfd_gettime = 410,
    timerfd_settime = 411,
    utimensat = 412,
    pselect6 = 413,
    ppoll = 414,
    io_pgetevents = 416,
    recvmmsg = 417,
    mq_timedsend = 418,
    mq_timedreceive = 419,
    semtimedop = 420,
    rt_sigtimedwait = 421,
    futex = 422,
    sched_rr_get_interval = 423,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    clone3 = 435,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
    quotactl_fd = 443,
    landlock_create_ruleset = 444,
    landlock_add_rule = 445,
    landlock_restrict_self = 446,
    process_mrelease = 448,
    futex_waitv = 449,
    set_mempolicy_home_node = 450,
    cachestat = 451,
    fchmodat2 = 452,
    map_shadow_stack = 453,
    futex_wake = 454,
    futex_wait = 455,
    futex_requeue = 456,
    statmount = 457,
    listmount = 458,
    lsm_get_self_attr = 459,
    lsm_set_self_attr = 460,
    lsm_list_modules = 461,
    mseal = 462,
    cacheflush = (244 + 0),
    arc_settls = (244 + 1),
    arc_gettls = (244 + 2),
    arc_usr_cmpxchg = (244 + 4),
    sysfs = (244 + 3),
};

pub const CSky = enum(usize) {
    io_setup = 0,
    io_destroy = 1,
    io_submit = 2,
    io_cancel = 3,
    io_getevents_time32 = 4,
    setxattr = 5,
    lsetxattr = 6,
    fsetxattr = 7,
    getxattr = 8,
    lgetxattr = 9,
    fgetxattr = 10,
    listxattr = 11,
    llistxattr = 12,
    flistxattr = 13,
    removexattr = 14,
    lremovexattr = 15,
    fremovexattr = 16,
    getcwd = 17,
    lookup_dcookie = 18,
    eventfd2 = 19,
    epoll_create1 = 20,
    epoll_ctl = 21,
    epoll_pwait = 22,
    dup = 23,
    dup3 = 24,
    fcntl64 = 25,
    inotify_init1 = 26,
    inotify_add_watch = 27,
    inotify_rm_watch = 28,
    ioctl = 29,
    ioprio_set = 30,
    ioprio_get = 31,
    flock = 32,
    mknodat = 33,
    mkdirat = 34,
    unlinkat = 35,
    symlinkat = 36,
    linkat = 37,
    umount2 = 39,
    mount = 40,
    pivot_root = 41,
    nfsservctl = 42,
    statfs64 = 43,
    fstatfs64 = 44,
    truncate64 = 45,
    ftruncate64 = 46,
    fallocate = 47,
    faccessat = 48,
    chdir = 49,
    fchdir = 50,
    chroot = 51,
    fchmod = 52,
    fchmodat = 53,
    fchownat = 54,
    fchown = 55,
    openat = 56,
    close = 57,
    vhangup = 58,
    pipe2 = 59,
    quotactl = 60,
    getdents64 = 61,
    llseek = 62,
    read = 63,
    write = 64,
    readv = 65,
    writev = 66,
    pread64 = 67,
    pwrite64 = 68,
    preadv = 69,
    pwritev = 70,
    sendfile64 = 71,
    pselect6_time32 = 72,
    ppoll_time32 = 73,
    signalfd4 = 74,
    vmsplice = 75,
    splice = 76,
    tee = 77,
    readlinkat = 78,
    fstatat64 = 79,
    fstat64 = 80,
    sync = 81,
    fsync = 82,
    fdatasync = 83,
    sync_file_range = 84,
    timerfd_create = 85,
    timerfd_settime32 = 86,
    timerfd_gettime32 = 87,
    utimensat_time32 = 88,
    acct = 89,
    capget = 90,
    capset = 91,
    personality = 92,
    exit = 93,
    exit_group = 94,
    waitid = 95,
    set_tid_address = 96,
    unshare = 97,
    futex_time32 = 98,
    set_robust_list = 99,
    get_robust_list = 100,
    nanosleep_time32 = 101,
    getitimer = 102,
    setitimer = 103,
    kexec_load = 104,
    init_module = 105,
    delete_module = 106,
    timer_create = 107,
    timer_gettime32 = 108,
    timer_getoverrun = 109,
    timer_settime32 = 110,
    timer_delete = 111,
    clock_settime32 = 112,
    clock_gettime32 = 113,
    clock_getres_time32 = 114,
    clock_nanosleep_time32 = 115,
    syslog = 116,
    ptrace = 117,
    sched_setparam = 118,
    sched_setscheduler = 119,
    sched_getscheduler = 120,
    sched_getparam = 121,
    sched_setaffinity = 122,
    sched_getaffinity = 123,
    sched_yield = 124,
    sched_get_priority_max = 125,
    sched_get_priority_min = 126,
    sched_rr_get_interval_time32 = 127,
    restart_syscall = 128,
    kill = 129,
    tkill = 130,
    tgkill = 131,
    sigaltstack = 132,
    rt_sigsuspend = 133,
    rt_sigaction = 134,
    rt_sigprocmask = 135,
    rt_sigpending = 136,
    rt_sigtimedwait_time32 = 137,
    rt_sigqueueinfo = 138,
    rt_sigreturn = 139,
    setpriority = 140,
    getpriority = 141,
    reboot = 142,
    setregid = 143,
    setgid = 144,
    setreuid = 145,
    setuid = 146,
    setresuid = 147,
    getresuid = 148,
    setresgid = 149,
    getresgid = 150,
    setfsuid = 151,
    setfsgid = 152,
    times = 153,
    setpgid = 154,
    getpgid = 155,
    getsid = 156,
    setsid = 157,
    getgroups = 158,
    setgroups = 159,
    uname = 160,
    sethostname = 161,
    setdomainname = 162,
    getrlimit = 163,
    setrlimit = 164,
    getrusage = 165,
    umask = 166,
    prctl = 167,
    getcpu = 168,
    gettimeofday = 169,
    settimeofday = 170,
    adjtimex_time32 = 171,
    getpid = 172,
    getppid = 173,
    getuid = 174,
    geteuid = 175,
    getgid = 176,
    getegid = 177,
    gettid = 178,
    sysinfo = 179,
    mq_open = 180,
    mq_unlink = 181,
    mq_timedsend_time32 = 182,
    mq_timedreceive_time32 = 183,
    mq_notify = 184,
    mq_getsetattr = 185,
    msgget = 186,
    msgctl = 187,
    msgrcv = 188,
    msgsnd = 189,
    semget = 190,
    semctl = 191,
    semtimedop_time32 = 192,
    semop = 193,
    shmget = 194,
    shmctl = 195,
    shmat = 196,
    shmdt = 197,
    socket = 198,
    socketpair = 199,
    bind = 200,
    listen = 201,
    accept = 202,
    connect = 203,
    getsockname = 204,
    getpeername = 205,
    sendto = 206,
    recvfrom = 207,
    setsockopt = 208,
    getsockopt = 209,
    shutdown = 210,
    sendmsg = 211,
    recvmsg = 212,
    readahead = 213,
    brk = 214,
    munmap = 215,
    mremap = 216,
    add_key = 217,
    request_key = 218,
    keyctl = 219,
    clone = 220,
    execve = 221,
    mmap2 = 222,
    fadvise64_64 = 223,
    swapon = 224,
    swapoff = 225,
    mprotect = 226,
    msync = 227,
    mlock = 228,
    munlock = 229,
    mlockall = 230,
    munlockall = 231,
    mincore = 232,
    madvise = 233,
    remap_file_pages = 234,
    mbind = 235,
    get_mempolicy = 236,
    set_mempolicy = 237,
    migrate_pages = 238,
    move_pages = 239,
    rt_tgsigqueueinfo = 240,
    perf_event_open = 241,
    accept4 = 242,
    recvmmsg_time32 = 243,
    wait4 = 260,
    prlimit64 = 261,
    fanotify_init = 262,
    fanotify_mark = 263,
    name_to_handle_at = 264,
    open_by_handle_at = 265,
    clock_adjtime32 = 266,
    syncfs = 267,
    setns = 268,
    sendmmsg = 269,
    process_vm_readv = 270,
    process_vm_writev = 271,
    kcmp = 272,
    finit_module = 273,
    sched_setattr = 274,
    sched_getattr = 275,
    renameat2 = 276,
    seccomp = 277,
    getrandom = 278,
    memfd_create = 279,
    bpf = 280,
    execveat = 281,
    userfaultfd = 282,
    membarrier = 283,
    mlock2 = 284,
    copy_file_range = 285,
    preadv2 = 286,
    pwritev2 = 287,
    pkey_mprotect = 288,
    pkey_alloc = 289,
    pkey_free = 290,
    statx = 291,
    io_pgetevents_time32 = 292,
    rseq = 293,
    kexec_file_load = 294,
    clock_gettime = 403,
    clock_settime = 404,
    clock_adjtime = 405,
    clock_getres = 406,
    clock_nanosleep = 407,
    timer_gettime = 408,
    timer_settime = 409,
    timerfd_gettime = 410,
    timerfd_settime = 411,
    utimensat = 412,
    pselect6 = 413,
    ppoll = 414,
    io_pgetevents = 416,
    recvmmsg = 417,
    mq_timedsend = 418,
    mq_timedreceive = 419,
    semtimedop = 420,
    rt_sigtimedwait = 421,
    futex = 422,
    sched_rr_get_interval = 423,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    clone3 = 435,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
    quotactl_fd = 443,
    landlock_create_ruleset = 444,
    landlock_add_rule = 445,
    landlock_restrict_self = 446,
    process_mrelease = 448,
    futex_waitv = 449,
    set_mempolicy_home_node = 450,
    cachestat = 451,
    fchmodat2 = 452,
    map_shadow_stack = 453,
    futex_wake = 454,
    futex_wait = 455,
    futex_requeue = 456,
    statmount = 457,
    listmount = 458,
    lsm_get_self_attr = 459,
    lsm_set_self_attr = 460,
    lsm_list_modules = 461,
    mseal = 462,
    set_thread_area = (244 + 0),
    cacheflush = (244 + 1),
};

pub const Hexagon = enum(usize) {
    io_setup = 0,
    io_destroy = 1,
    io_submit = 2,
    io_cancel = 3,
    io_getevents_time32 = 4,
    setxattr = 5,
    lsetxattr = 6,
    fsetxattr = 7,
    getxattr = 8,
    lgetxattr = 9,
    fgetxattr = 10,
    listxattr = 11,
    llistxattr = 12,
    flistxattr = 13,
    removexattr = 14,
    lremovexattr = 15,
    fremovexattr = 16,
    getcwd = 17,
    lookup_dcookie = 18,
    eventfd2 = 19,
    epoll_create1 = 20,
    epoll_ctl = 21,
    epoll_pwait = 22,
    dup = 23,
    dup3 = 24,
    fcntl64 = 25,
    inotify_init1 = 26,
    inotify_add_watch = 27,
    inotify_rm_watch = 28,
    ioctl = 29,
    ioprio_set = 30,
    ioprio_get = 31,
    flock = 32,
    mknodat = 33,
    mkdirat = 34,
    unlinkat = 35,
    symlinkat = 36,
    linkat = 37,
    renameat = 38,
    umount2 = 39,
    mount = 40,
    pivot_root = 41,
    nfsservctl = 42,
    statfs64 = 43,
    fstatfs64 = 44,
    truncate64 = 45,
    ftruncate64 = 46,
    fallocate = 47,
    faccessat = 48,
    chdir = 49,
    fchdir = 50,
    chroot = 51,
    fchmod = 52,
    fchmodat = 53,
    fchownat = 54,
    fchown = 55,
    openat = 56,
    close = 57,
    vhangup = 58,
    pipe2 = 59,
    quotactl = 60,
    getdents64 = 61,
    llseek = 62,
    read = 63,
    write = 64,
    readv = 65,
    writev = 66,
    pread64 = 67,
    pwrite64 = 68,
    preadv = 69,
    pwritev = 70,
    sendfile64 = 71,
    pselect6_time32 = 72,
    ppoll_time32 = 73,
    signalfd4 = 74,
    vmsplice = 75,
    splice = 76,
    tee = 77,
    readlinkat = 78,
    fstatat64 = 79,
    fstat64 = 80,
    sync = 81,
    fsync = 82,
    fdatasync = 83,
    sync_file_range = 84,
    timerfd_create = 85,
    timerfd_settime32 = 86,
    timerfd_gettime32 = 87,
    utimensat_time32 = 88,
    acct = 89,
    capget = 90,
    capset = 91,
    personality = 92,
    exit = 93,
    exit_group = 94,
    waitid = 95,
    set_tid_address = 96,
    unshare = 97,
    futex_time32 = 98,
    set_robust_list = 99,
    get_robust_list = 100,
    nanosleep_time32 = 101,
    getitimer = 102,
    setitimer = 103,
    kexec_load = 104,
    init_module = 105,
    delete_module = 106,
    timer_create = 107,
    timer_gettime32 = 108,
    timer_getoverrun = 109,
    timer_settime32 = 110,
    timer_delete = 111,
    clock_settime32 = 112,
    clock_gettime32 = 113,
    clock_getres_time32 = 114,
    clock_nanosleep_time32 = 115,
    syslog = 116,
    ptrace = 117,
    sched_setparam = 118,
    sched_setscheduler = 119,
    sched_getscheduler = 120,
    sched_getparam = 121,
    sched_setaffinity = 122,
    sched_getaffinity = 123,
    sched_yield = 124,
    sched_get_priority_max = 125,
    sched_get_priority_min = 126,
    sched_rr_get_interval_time32 = 127,
    restart_syscall = 128,
    kill = 129,
    tkill = 130,
    tgkill = 131,
    sigaltstack = 132,
    rt_sigsuspend = 133,
    rt_sigaction = 134,
    rt_sigprocmask = 135,
    rt_sigpending = 136,
    rt_sigtimedwait_time32 = 137,
    rt_sigqueueinfo = 138,
    rt_sigreturn = 139,
    setpriority = 140,
    getpriority = 141,
    reboot = 142,
    setregid = 143,
    setgid = 144,
    setreuid = 145,
    setuid = 146,
    setresuid = 147,
    getresuid = 148,
    setresgid = 149,
    getresgid = 150,
    setfsuid = 151,
    setfsgid = 152,
    times = 153,
    setpgid = 154,
    getpgid = 155,
    getsid = 156,
    setsid = 157,
    getgroups = 158,
    setgroups = 159,
    uname = 160,
    sethostname = 161,
    setdomainname = 162,
    getrlimit = 163,
    setrlimit = 164,
    getrusage = 165,
    umask = 166,
    prctl = 167,
    getcpu = 168,
    gettimeofday = 169,
    settimeofday = 170,
    adjtimex_time32 = 171,
    getpid = 172,
    getppid = 173,
    getuid = 174,
    geteuid = 175,
    getgid = 176,
    getegid = 177,
    gettid = 178,
    sysinfo = 179,
    mq_open = 180,
    mq_unlink = 181,
    mq_timedsend_time32 = 182,
    mq_timedreceive_time32 = 183,
    mq_notify = 184,
    mq_getsetattr = 185,
    msgget = 186,
    msgctl = 187,
    msgrcv = 188,
    msgsnd = 189,
    semget = 190,
    semctl = 191,
    semtimedop_time32 = 192,
    semop = 193,
    shmget = 194,
    shmctl = 195,
    shmat = 196,
    shmdt = 197,
    socket = 198,
    socketpair = 199,
    bind = 200,
    listen = 201,
    accept = 202,
    connect = 203,
    getsockname = 204,
    getpeername = 205,
    sendto = 206,
    recvfrom = 207,
    setsockopt = 208,
    getsockopt = 209,
    shutdown = 210,
    sendmsg = 211,
    recvmsg = 212,
    readahead = 213,
    brk = 214,
    munmap = 215,
    mremap = 216,
    add_key = 217,
    request_key = 218,
    keyctl = 219,
    clone = 220,
    execve = 221,
    mmap2 = 222,
    fadvise64_64 = 223,
    swapon = 224,
    swapoff = 225,
    mprotect = 226,
    msync = 227,
    mlock = 228,
    munlock = 229,
    mlockall = 230,
    munlockall = 231,
    mincore = 232,
    madvise = 233,
    remap_file_pages = 234,
    mbind = 235,
    get_mempolicy = 236,
    set_mempolicy = 237,
    migrate_pages = 238,
    move_pages = 239,
    rt_tgsigqueueinfo = 240,
    perf_event_open = 241,
    accept4 = 242,
    recvmmsg_time32 = 243,
    wait4 = 260,
    prlimit64 = 261,
    fanotify_init = 262,
    fanotify_mark = 263,
    name_to_handle_at = 264,
    open_by_handle_at = 265,
    clock_adjtime32 = 266,
    syncfs = 267,
    setns = 268,
    sendmmsg = 269,
    process_vm_readv = 270,
    process_vm_writev = 271,
    kcmp = 272,
    finit_module = 273,
    sched_setattr = 274,
    sched_getattr = 275,
    renameat2 = 276,
    seccomp = 277,
    getrandom = 278,
    memfd_create = 279,
    bpf = 280,
    execveat = 281,
    userfaultfd = 282,
    membarrier = 283,
    mlock2 = 284,
    copy_file_range = 285,
    preadv2 = 286,
    pwritev2 = 287,
    pkey_mprotect = 288,
    pkey_alloc = 289,
    pkey_free = 290,
    statx = 291,
    io_pgetevents_time32 = 292,
    rseq = 293,
    kexec_file_load = 294,
    clock_gettime = 403,
    clock_settime = 404,
    clock_adjtime = 405,
    clock_getres = 406,
    clock_nanosleep = 407,
    timer_gettime = 408,
    timer_settime = 409,
    timerfd_gettime = 410,
    timerfd_settime = 411,
    utimensat = 412,
    pselect6 = 413,
    ppoll = 414,
    io_pgetevents = 416,
    recvmmsg = 417,
    mq_timedsend = 418,
    mq_timedreceive = 419,
    semtimedop = 420,
    rt_sigtimedwait = 421,
    futex = 422,
    sched_rr_get_interval = 423,
    pidfd_send_signal = 424,
    io_uring_setup = 425,
    io_uring_enter = 426,
    io_uring_register = 427,
    open_tree = 428,
    move_mount = 429,
    fsopen = 430,
    fsconfig = 431,
    fsmount = 432,
    fspick = 433,
    pidfd_open = 434,
    close_range = 436,
    openat2 = 437,
    pidfd_getfd = 438,
    faccessat2 = 439,
    process_madvise = 440,
    epoll_pwait2 = 441,
    mount_setattr = 442,
    quotactl_fd = 443,
    landlock_create_ruleset = 444,
    landlock_add_rule = 445,
    landlock_restrict_self = 446,
    process_mrelease = 448,
    futex_waitv = 449,
    set_mempolicy_home_node = 450,
    cachestat = 451,
    fchmodat2 = 452,
    map_shadow_stack = 453,
    futex_wake = 454,
    futex_wait = 455,
    futex_requeue = 456,
    statmount = 457,
    listmount = 458,
    lsm_get_self_attr = 459,
    lsm_set_self_attr = 460,
    lsm_list_modules = 461,
    mseal = 462,
};
const std = @import("../../std.zig");
const builtin = @import("builtin");
const linux = std.os.linux;
const mem = std.mem;
const elf = std.elf;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const fs = std.fs;

test "fallocate" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = "test_fallocate";
    const file = try tmp.dir.createFile(path, .{ .truncate = true, .mode = 0o666 });
    defer file.close();

    try expect((try file.stat()).size == 0);

    const len: i64 = 65536;
    switch (linux.E.init(linux.fallocate(file.handle, 0, 0, len))) {
        .SUCCESS => {},
        .NOSYS => return error.SkipZigTest,
        .OPNOTSUPP => return error.SkipZigTest,
        else => |errno| std.debug.panic("unhandled errno: {}", .{errno}),
    }

    try expect((try file.stat()).size == len);
}

test "getpid" {
    try expect(linux.getpid() != 0);
}

test "getppid" {
    try expect(linux.getppid() != 0);
}

test "timer" {
    const epoll_fd = linux.epoll_create();
    var err: linux.E = linux.E.init(epoll_fd);
    try expect(err == .SUCCESS);

    const timer_fd = linux.timerfd_create(linux.TIMERFD_CLOCK.MONOTONIC, .{});
    try expect(linux.E.init(timer_fd) == .SUCCESS);

    const time_interval = linux.timespec{
        .sec = 0,
        .nsec = 2000000,
    };

    const new_time = linux.itimerspec{
        .it_interval = time_interval,
        .it_value = time_interval,
    };

    err = linux.E.init(linux.timerfd_settime(@as(i32, @intCast(timer_fd)), .{}, &new_time, null));
    try expect(err == .SUCCESS);

    var event = linux.epoll_event{
        .events = linux.EPOLL.IN | linux.EPOLL.OUT | linux.EPOLL.ET,
        .data = linux.epoll_data{ .ptr = 0 },
    };

    err = linux.E.init(linux.epoll_ctl(@as(i32, @intCast(epoll_fd)), linux.EPOLL.CTL_ADD, @as(i32, @intCast(timer_fd)), &event));
    try expect(err == .SUCCESS);

    const events_one: linux.epoll_event = undefined;
    var events = [_]linux.epoll_event{events_one} ** 8;

    err = linux.E.init(linux.epoll_wait(@as(i32, @intCast(epoll_fd)), &events, 8, -1));
    try expect(err == .SUCCESS);
}

test "statx" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "just_a_temporary_file.txt";
    var file = try tmp.dir.createFile(tmp_file_name, .{});
    defer file.close();

    var statx_buf: linux.Statx = undefined;
    switch (linux.E.init(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, linux.STATX_BASIC_STATS, &statx_buf))) {
        .SUCCESS => {},
        else => unreachable,
    }

    if (builtin.cpu.arch == .riscv32 or builtin.cpu.arch.isLoongArch()) return error.SkipZigTest; // No fstatat, so the rest of the test is meaningless.

    var stat_buf: linux.Stat = undefined;
    switch (linux.E.init(linux.fstatat(file.handle, "", &stat_buf, linux.AT.EMPTY_PATH))) {
        .SUCCESS => {},
        else => unreachable,
    }

    try expect(stat_buf.mode == statx_buf.mode);
    try expect(@as(u32, @bitCast(stat_buf.uid)) == statx_buf.uid);
    try expect(@as(u32, @bitCast(stat_buf.gid)) == statx_buf.gid);
    try expect(@as(u64, @bitCast(@as(i64, stat_buf.size))) == statx_buf.size);
    try expect(@as(u64, @bitCast(@as(i64, stat_buf.blksize))) == statx_buf.blksize);
    try expect(@as(u64, @bitCast(@as(i64, stat_buf.blocks))) == statx_buf.blocks);
}

test "user and group ids" {
    if (builtin.link_libc) return error.SkipZigTest;
    try expectEqual(linux.getauxval(elf.AT_UID), linux.getuid());
    try expectEqual(linux.getauxval(elf.AT_GID), linux.getgid());
    try expectEqual(linux.getauxval(elf.AT_EUID), linux.geteuid());
    try expectEqual(linux.getauxval(elf.AT_EGID), linux.getegid());
}

test "fadvise" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_file_name = "temp_posix_fadvise.txt";
    var file = try tmp.dir.createFile(tmp_file_name, .{});
    defer file.close();

    var buf: [2048]u8 = undefined;
    try file.writeAll(&buf);

    const ret = linux.fadvise(file.handle, 0, 0, linux.POSIX_FADV.SEQUENTIAL);
    try expectEqual(@as(usize, 0), ret);
}

test "sigset_t" {
    var sigset = linux.empty_sigset;

    // See that none are set, then set each one, see that they're all set, then
    // remove them all, and then see that none are set.
    for (1..linux.NSIG) |i| {
        try expectEqual(linux.sigismember(&sigset, @truncate(i)), false);
    }
    for (1..linux.NSIG) |i| {
        linux.sigaddset(&sigset, @truncate(i));
    }
    for (1..linux.NSIG) |i| {
        try expectEqual(linux.sigismember(&sigset, @truncate(i)), true);
        try expectEqual(linux.sigismember(&linux.empty_sigset, @truncate(i)), false);
    }
    for (1..linux.NSIG) |i| {
        linux.sigdelset(&sigset, @truncate(i));
    }
    for (1..linux.NSIG) |i| {
        try expectEqual(linux.sigismember(&sigset, @truncate(i)), false);
    }

    linux.sigaddset(&sigset, 1);
    try expectEqual(sigset[0], 1);
    try expectEqual(sigset[1], 0);

    linux.sigaddset(&sigset, 31);
    try expectEqual(sigset[0], 0x4000_0001);
    try expectEqual(sigset[1], 0);

    linux.sigaddset(&sigset, 36);
    try expectEqual(sigset[0], 0x4000_0001);
    try expectEqual(sigset[1], 0x8);

    linux.sigaddset(&sigset, 64);
    try expectEqual(sigset[0], 0x4000_0001);
    try expectEqual(sigset[1], 0x8000_0008);
    try expectEqual(sigset[2], 0);
}

test "sysinfo" {
    var info: linux.Sysinfo = undefined;
    const result: usize = linux.sysinfo(&info);
    try expect(std.os.linux.E.init(result) == .SUCCESS);

    try expect(info.mem_unit > 0);
    try expect(info.mem_unit <= std.heap.page_size_max);
}

test {
    _ = linux.IoUring;
}
//! The syscall interface is identical to the ARM one but we're facing an extra
//! challenge: r7, the register where the syscall number is stored, may be
//! reserved for the frame pointer.
//! Save and restore r7 around the syscall without touching the stack pointer not
//! to break the frame chain.
const std = @import("../../std.zig");
const linux = std.os.linux;
const SYS = linux.SYS;

pub fn syscall0(number: SYS) usize {
    @setRuntimeSafety(false);

    var buf: [2]usize = .{ @intFromEnum(number), undefined };
    return asm volatile (
        \\ str r7, [%[tmp], #4]
        \\ ldr r7, [%[tmp]]
        \\ svc #0
        \\ ldr r7, [%[tmp], #4]
        : [ret] "={r0}" (-> usize),
        : [tmp] "{r1}" (&buf),
        : "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    @setRuntimeSafety(false);

    var buf: [2]usize = .{ @intFromEnum(number), undefined };
    return asm volatile (
        \\ str r7, [%[tmp], #4]
        \\ ldr r7, [%[tmp]]
        \\ svc #0
        \\ ldr r7, [%[tmp], #4]
        : [ret] "={r0}" (-> usize),
        : [tmp] "{r1}" (&buf),
          [arg1] "{r0}" (arg1),
        : "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    @setRuntimeSafety(false);

    var buf: [2]usize = .{ @intFromEnum(number), undefined };
    return asm volatile (
        \\ str r7, [%[tmp], #4]
        \\ ldr r7, [%[tmp]]
        \\ svc #0
        \\ ldr r7, [%[tmp], #4]
        : [ret] "={r0}" (-> usize),
        : [tmp] "{r2}" (&buf),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
        : "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    @setRuntimeSafety(false);

    var buf: [2]usize = .{ @intFromEnum(number), undefined };
    return asm volatile (
        \\ str r7, [%[tmp], #4]
        \\ ldr r7, [%[tmp]]
        \\ svc #0
        \\ ldr r7, [%[tmp], #4]
        : [ret] "={r0}" (-> usize),
        : [tmp] "{r3}" (&buf),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
          [arg3] "{r2}" (arg3),
        : "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    @setRuntimeSafety(false);

    var buf: [2]usize = .{ @intFromEnum(number), undefined };
    return asm volatile (
        \\ str r7, [%[tmp], #4]
        \\ ldr r7, [%[tmp]]
        \\ svc #0
        \\ ldr r7, [%[tmp], #4]
        : [ret] "={r0}" (-> usize),
        : [tmp] "{r4}" (&buf),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
          [arg3] "{r2}" (arg3),
          [arg4] "{r3}" (arg4),
        : "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    @setRuntimeSafety(false);

    var buf: [2]usize = .{ @intFromEnum(number), undefined };
    return asm volatile (
        \\ str r7, [%[tmp], #4]
        \\ ldr r7, [%[tmp]]
        \\ svc #0
        \\ ldr r7, [%[tmp], #4]
        : [ret] "={r0}" (-> usize),
        : [tmp] "{r5}" (&buf),
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
    @setRuntimeSafety(false);

    var buf: [2]usize = .{ @intFromEnum(number), undefined };
    return asm volatile (
        \\ str r7, [%[tmp], #4]
        \\ ldr r7, [%[tmp]]
        \\ svc #0
        \\ ldr r7, [%[tmp], #4]
        : [ret] "={r0}" (-> usize),
        : [tmp] "{r6}" (&buf),
          [arg1] "{r0}" (arg1),
          [arg2] "{r1}" (arg2),
          [arg3] "{r2}" (arg3),
          [arg4] "{r3}" (arg4),
          [arg5] "{r4}" (arg5),
          [arg6] "{r5}" (arg6),
        : "memory"
    );
}

pub const clone = @import("arm.zig").clone;

pub fn restore() callconv(.naked) noreturn {
    asm volatile (
        \\ mov r7, %[number]
        \\ svc #0
        :
        : [number] "I" (@intFromEnum(SYS.sigreturn)),
    );
}

pub fn restore_rt() callconv(.naked) noreturn {
    asm volatile (
        \\ mov r7, %[number]
        \\ svc #0
        :
        : [number] "I" (@intFromEnum(SYS.rt_sigreturn)),
        : "memory"
    );
}
//! This file implements the two TLS variants [1] used by ELF-based systems. Note that, in reality,
//! Variant I has two sub-variants.
//!
//! It is important to understand that the term TCB (Thread Control Block) is overloaded here.
//! Official ABI documentation uses it simply to mean the ABI TCB, i.e. a small area of ABI-defined
//! data, usually one or two words (see the `AbiTcb` type below). People will also often use TCB to
//! refer to the libc TCB, which can be any size and contain anything. (One could even omit it!) We
//! refer to the latter as the Zig TCB; see the `ZigTcb` type below.
//!
//! [1] https://www.akkadia.org/drepper/tls.pdf

const std = @import("std");
const mem = std.mem;
const elf = std.elf;
const math = std.math;
const assert = std.debug.assert;
const native_arch = @import("builtin").cpu.arch;
const linux = std.os.linux;
const posix = std.posix;
const page_size_min = std.heap.page_size_min;

/// Represents an ELF TLS variant.
///
/// In all variants, the TP and the TLS blocks must be aligned to the `p_align` value in the
/// `PT_TLS` ELF program header. Everything else has natural alignment.
///
/// The location of the DTV does not actually matter. For simplicity, we put it in the TLS area, but
/// there is no actual ABI requirement that it reside there.
const Variant = enum {
    /// The original Variant I:
    ///
    /// ----------------------------------------
    /// | DTV | Zig TCB | ABI TCB | TLS Blocks |
    /// ----------------^-----------------------
    ///                 `-- The TP register points here.
    ///
    /// The layout in this variant necessitates separate alignment of both the TP and the TLS
    /// blocks.
    ///
    /// The first word in the ABI TCB points to the DTV. For some architectures, there may be a
    /// second word with an unspecified meaning.
    I_original,
    /// The modified Variant I:
    ///
    /// ---------------------------------------------------
    /// | DTV | Zig TCB | ABI TCB | [Offset] | TLS Blocks |
    /// -------------------------------------^-------------
    ///                                      `-- The TP register points here.
    ///
    /// The offset (which can be zero) is applied to the TP only; there is never physical gap
    /// between the ABI TCB and the TLS blocks. This implies that we only need to align the TP.
    ///
    /// The first (and only) word in the ABI TCB points to the DTV.
    I_modified,
    /// Variant II:
    ///
    /// ----------------------------------------
    /// | TLS Blocks | ABI TCB | Zig TCB | DTV |
    /// -------------^--------------------------
    ///              `-- The TP register points here.
    ///
    /// The first (and only) word in the ABI TCB points to the ABI TCB itself.
    II,
};

const current_variant: Variant = switch (native_arch) {
    .arc,
    .arm,
    .armeb,
    .aarch64,
    .aarch64_be,
    .csky,
    .thumb,
    .thumbeb,
    => .I_original,
    .loongarch32,
    .loongarch64,
    .m68k,
    .mips,
    .mipsel,
    .mips64,
    .mips64el,
    .powerpc,
    .powerpcle,
    .powerpc64,
    .powerpc64le,
    .riscv32,
    .riscv64,
    => .I_modified,
    .hexagon,
    .s390x,
    .sparc,
    .sparc64,
    .x86,
    .x86_64,
    => .II,
    else => @compileError("undefined TLS variant for this architecture"),
};

/// The Offset value for the modified Variant I.
const current_tp_offset = switch (native_arch) {
    .m68k,
    .mips,
    .mipsel,
    .mips64,
    .mips64el,
    .powerpc,
    .powerpcle,
    .powerpc64,
    .powerpc64le,
    => 0x7000,
    else => 0,
};

/// Usually only used by the modified Variant I.
const current_dtv_offset = switch (native_arch) {
    .m68k,
    .mips,
    .mipsel,
    .mips64,
    .mips64el,
    .powerpc,
    .powerpcle,
    .powerpc64,
    .powerpc64le,
    => 0x8000,
    .riscv32,
    .riscv64,
    => 0x800,
    else => 0,
};

/// Per-thread storage for the ELF TLS ABI.
const AbiTcb = switch (current_variant) {
    .I_original, .I_modified => switch (native_arch) {
        // ARM EABI mandates enough space for two pointers: the first one points to the DTV as
        // usual, while the second one is unspecified.
        .aarch64,
        .aarch64_be,
        .arm,
        .armeb,
        .thumb,
        .thumbeb,
        => extern struct {
            /// This is offset by `current_dtv_offset`.
            dtv: usize,
            reserved: ?*anyopaque,
        },
        else => extern struct {
            /// This is offset by `current_dtv_offset`.
            dtv: usize,
        },
    },
    .II => extern struct {
        /// This is self-referential.
        self: *AbiTcb,
    },
};

/// Per-thread storage for Zig's use. Currently unused.
const ZigTcb = struct {
    dummy: usize,
};

/// Dynamic Thread Vector as specified in the ELF TLS ABI. Ordinarily, there is a block pointer per
/// dynamically-loaded module, but since we only support static TLS, we only need one block pointer.
const Dtv = extern struct {
    len: usize = 1,
    tls_block: [*]u8,
};

/// Describes a process's TLS area. The area encompasses the DTV, both TCBs, and the TLS block, with
/// the exact layout of these being dependent primarily on `current_variant`.
const AreaDesc = struct {
    size: usize,
    alignment: usize,

    dtv: struct {
        /// Offset into the TLS area.
        offset: usize,
    },

    abi_tcb: struct {
        /// Offset into the TLS area.
        offset: usize,
    },

    block: struct {
        /// The initial data to be copied into the TLS block. Note that this may be smaller than
        /// `size`, in which case any remaining data in the TLS block is simply left uninitialized.
        init: []const u8,
        /// Offset into the TLS area.
        offset: usize,
        /// This is the effective size of the TLS block, which may be greater than `init.len`.
        size: usize,
    },

    /// Only used on the 32-bit x86 architecture (not x86_64, nor x32).
    gdt_entry_number: usize,
};

pub var area_desc: AreaDesc = undefined;

pub fn setThreadPointer(addr: usize) void {
    @setRuntimeSafety(false);
    @disableInstrumentation();

    switch (native_arch) {
        .x86 => {
            var user_desc: linux.user_desc = .{
                .entry_number = area_desc.gdt_entry_number,
                .base_addr = addr,
                .limit = 0xfffff,
                .flags = .{
                    .seg_32bit = 1,
                    .contents = 0, // Data
                    .read_exec_only = 0,
                    .limit_in_pages = 1,
                    .seg_not_present = 0,
                    .useable = 1,
                },
            };
            const rc = @call(.always_inline, linux.syscall1, .{ .set_thread_area, @intFromPtr(&user_desc) });
            assert(rc == 0);

            const gdt_entry_number = user_desc.entry_number;
            // We have to keep track of our slot as it's also needed for clone()
            area_desc.gdt_entry_number = gdt_entry_number;
            // Update the %gs selector
            asm volatile ("movl %[gs_val], %%gs"
                :
                : [gs_val] "r" (gdt_entry_number << 3 | 3),
            );
        },
        .x86_64 => {
            const rc = @call(.always_inline, linux.syscall2, .{ .arch_prctl, linux.ARCH.SET_FS, addr });
            assert(rc == 0);
        },
        .aarch64, .aarch64_be => {
            asm volatile (
                \\ msr tpidr_el0, %[addr]
                :
                : [addr] "r" (addr),
            );
        },
        .arc => {
            // We apparently need to both set r25 (TP) *and* inform the kernel...
            asm volatile (
                \\ mov r25, %[addr]
                :
                : [addr] "r" (addr),
            );
            const rc = @call(.always_inline, linux.syscall1, .{ .arc_settls, addr });
            assert(rc == 0);
        },
        .arm, .armeb, .thumb, .thumbeb => {
            const rc = @call(.always_inline, linux.syscall1, .{ .set_tls, addr });
            assert(rc == 0);
        },
        .m68k => {
            const rc = linux.syscall1(.set_thread_area, addr);
            assert(rc == 0);
        },
        .hexagon => {
            asm volatile (
                \\ ugp = %[addr]
                :
                : [addr] "r" (addr),
            );
        },
        .loongarch32, .loongarch64 => {
            asm volatile (
                \\ move $tp, %[addr]
                :
                : [addr] "r" (addr),
            );
        },
        .riscv32, .riscv64 => {
            asm volatile (
                \\ mv tp, %[addr]
                :
                : [addr] "r" (addr),
            );
        },
        .csky, .mips, .mipsel, .mips64, .mips64el => {
            const rc = @call(.always_inline, linux.syscall1, .{ .set_thread_area, addr });
            assert(rc == 0);
        },
        .powerpc, .powerpcle => {
            asm volatile (
                \\ mr 2, %[addr]
                :
                : [addr] "r" (addr),
            );
        },
        .powerpc64, .powerpc64le => {
            asm volatile (
                \\ mr 13, %[addr]
                :
                : [addr] "r" (addr),
            );
        },
        .s390x => {
            asm volatile (
                \\ lgr %%r0, %[addr]
                \\ sar %%a1, %%r0
                \\ srlg %%r0, %%r0, 32
                \\ sar %%a0, %%r0
                :
                : [addr] "r" (addr),
                : "r0"
            );
        },
        .sparc, .sparc64 => {
            asm volatile (
                \\ mov %[addr], %%g7
                :
                : [addr] "r" (addr),
            );
        },
        else => @compileError("Unsupported architecture"),
    }
}

fn computeAreaDesc(phdrs: []elf.Phdr) void {
    @setRuntimeSafety(false);
    @disableInstrumentation();

    var tls_phdr: ?*elf.Phdr = null;
    var img_base: usize = 0;

    for (phdrs) |*phdr| {
        switch (phdr.p_type) {
            elf.PT_PHDR => img_base = @intFromPtr(phdrs.ptr) - phdr.p_vaddr,
            elf.PT_TLS => tls_phdr = phdr,
            else => {},
        }
    }

    var align_factor: usize = undefined;
    var block_init: []const u8 = undefined;
    var block_size: usize = undefined;

    if (tls_phdr) |phdr| {
        align_factor = phdr.p_align;

        // The effective size in memory is represented by `p_memsz`; the length of the data stored
        // in the `PT_TLS` segment is `p_filesz` and may be less than the former.
        block_init = @as([*]u8, @ptrFromInt(img_base + phdr.p_vaddr))[0..phdr.p_filesz];
        block_size = phdr.p_memsz;
    } else {
        align_factor = @alignOf(usize);

        block_init = &[_]u8{};
        block_size = 0;
    }

    // Offsets into the allocated TLS area.
    var dtv_offset: usize = undefined;
    var abi_tcb_offset: usize = undefined;
    var block_offset: usize = undefined;

    // Compute the total size of the ABI-specific data plus our own `ZigTcb` structure. All the
    // offsets calculated here assume a well-aligned base address.
    const area_size = switch (current_variant) {
        .I_original => blk: {
            var l: usize = 0;
            dtv_offset = l;
            l += @sizeOf(Dtv);
            // Add some padding here so that the TP (`abi_tcb_offset`) is aligned to `align_factor`
            // and the `ZigTcb` structure can be found by simply subtracting `@sizeOf(ZigTcb)` from
            // the TP.
            const delta = (l + @sizeOf(ZigTcb)) & (align_factor - 1);
            if (delta > 0)
                l += align_factor - delta;
            l += @sizeOf(ZigTcb);
            abi_tcb_offset = l;
            l += alignForward(@sizeOf(AbiTcb), align_factor);
            block_offset = l;
            l += block_size;
            break :blk l;
        },
        .I_modified => blk: {
            var l: usize = 0;
            dtv_offset = l;
            l += @sizeOf(Dtv);
            // In this variant, the TLS blocks must begin immediately after the end of the ABI TCB,
            // with the TP pointing to the beginning of the TLS blocks. Add padding so that the TP
            // (`abi_tcb_offset`) is aligned to `align_factor` and the `ZigTcb` structure can be
            // found by subtracting `@sizeOf(AbiTcb) + @sizeOf(ZigTcb)` from the TP.
            const delta = (l + @sizeOf(ZigTcb) + @sizeOf(AbiTcb)) & (align_factor - 1);
            if (delta > 0)
                l += align_factor - delta;
            l += @sizeOf(ZigTcb);
            abi_tcb_offset = l;
            l += @sizeOf(AbiTcb);
            block_offset = l;
            l += block_size;
            break :blk l;
        },
        .II => blk: {
            var l: usize = 0;
            block_offset = l;
            l += alignForward(block_size, align_factor);
            // The TP is aligned to `align_factor`.
            abi_tcb_offset = l;
            l += @sizeOf(AbiTcb);
            // The `ZigTcb` structure is right after the `AbiTcb` with no padding in between so it
            // can be easily found.
            l += @sizeOf(ZigTcb);
            // It doesn't really matter where we put the DTV, so give it natural alignment.
            l = alignForward(l, @alignOf(Dtv));
            dtv_offset = l;
            l += @sizeOf(Dtv);
            break :blk l;
        },
    };

    area_desc = .{
        .size = area_size,
        .alignment = align_factor,

        .dtv = .{
            .offset = dtv_offset,
        },

        .abi_tcb = .{
            .offset = abi_tcb_offset,
        },

        .block = .{
            .init = block_init,
            .offset = block_offset,
            .size = block_size,
        },

        .gdt_entry_number = @as(usize, @bitCast(@as(isize, -1))),
    };
}

/// Inline because TLS is not set up yet.
inline fn alignForward(addr: usize, alignment: usize) usize {
    return alignBackward(addr + (alignment - 1), alignment);
}

/// Inline because TLS is not set up yet.
inline fn alignBackward(addr: usize, alignment: usize) usize {
    return addr & ~(alignment - 1);
}

/// Inline because TLS is not set up yet.
inline fn alignPtrCast(comptime T: type, ptr: [*]u8) *T {
    return @ptrCast(@alignCast(ptr));
}

/// Initializes all the fields of the static TLS area and returns the computed architecture-specific
/// value of the TP register.
pub fn prepareArea(area: []u8) usize {
    @setRuntimeSafety(false);
    @disableInstrumentation();

    // Clear the area we're going to use, just to be safe.
    @memset(area, 0);

    // Prepare the ABI TCB.
    const abi_tcb = alignPtrCast(AbiTcb, area.ptr + area_desc.abi_tcb.offset);
    switch (current_variant) {
        .I_original, .I_modified => abi_tcb.dtv = @intFromPtr(area.ptr + area_desc.dtv.offset),
        .II => abi_tcb.self = abi_tcb,
    }

    // Prepare the DTV.
    const dtv = alignPtrCast(Dtv, area.ptr + area_desc.dtv.offset);
    dtv.len = 1;
    dtv.tls_block = area.ptr + current_dtv_offset + area_desc.block.offset;

    // Copy the initial data.
    @memcpy(area[area_desc.block.offset..][0..area_desc.block.init.len], area_desc.block.init);

    // Return the corrected value (if needed) for the TP register. Overflow here is not a problem;
    // the pointer arithmetic involving the TP is done with wrapping semantics.
    return @intFromPtr(area.ptr) +% switch (current_variant) {
        .I_original, .II => area_desc.abi_tcb.offset,
        .I_modified => area_desc.block.offset +% current_tp_offset,
    };
}

/// The main motivation for the size chosen here is that this is how much ends up being requested for
/// the thread-local variables of the `std.crypto.random` implementation. I'm not sure why it ends up
/// being so much; the struct itself is only 64 bytes. I think it has to do with being page-aligned
/// and LLVM or LLD is not smart enough to lay out the TLS data in a space-conserving way. Anyway, I
/// think it's fine because it's less than 3 pages of memory, and putting it in the ELF like this is
/// equivalent to moving the `mmap` call below into the kernel, avoiding syscall overhead.
var main_thread_area_buffer: [0x2100]u8 align(page_size_min) = undefined;

/// Computes the layout of the static TLS area, allocates the area, initializes all of its fields,
/// and assigns the architecture-specific value to the TP register.
pub fn initStatic(phdrs: []elf.Phdr) void {
    @setRuntimeSafety(false);
    @disableInstrumentation();

    computeAreaDesc(phdrs);

    const area = blk: {
        // Fast path for the common case where the TLS data is really small, avoid an allocation and
        // use our local buffer.
        if (area_desc.alignment <= page_size_min and area_desc.size <= main_thread_area_buffer.len) {
            break :blk main_thread_area_buffer[0..area_desc.size];
        }

        const begin_addr = mmap_tls(area_desc.size + area_desc.alignment - 1);
        if (@call(.always_inline, linux.E.init, .{begin_addr}) != .SUCCESS) @trap();

        const area_ptr: [*]align(page_size_min) u8 = @ptrFromInt(begin_addr);

        // Make sure the slice is correctly aligned.
        const begin_aligned_addr = alignForward(begin_addr, area_desc.alignment);
        const start = begin_aligned_addr - begin_addr;
        break :blk area_ptr[start..][0..area_desc.size];
    };

    const tp_value = prepareArea(area);
    setThreadPointer(tp_value);
}

inline fn mmap_tls(length: usize) usize {
    const prot = posix.PROT.READ | posix.PROT.WRITE;
    const flags: linux.MAP = .{ .TYPE = .PRIVATE, .ANONYMOUS = true };

    if (@hasField(linux.SYS, "mmap2")) {
        return @call(.always_inline, linux.syscall6, .{
            .mmap2,
            0,
            length,
            prot,
            @as(u32, @bitCast(flags)),
            @as(usize, @bitCast(@as(isize, -1))),
            0,
        });
    } else {
        // The s390x mmap() syscall existed before Linux supported syscalls with 5+ parameters, so
        // it takes a single pointer to an array of arguments instead.
        return if (native_arch == .s390x) @call(.always_inline, linux.syscall1, .{
            .mmap,
            @intFromPtr(&[_]usize{
                0,
                length,
                prot,
                @as(u32, @bitCast(flags)),
                @as(usize, @bitCast(@as(isize, -1))),
                0,
            }),
        }) else @call(.always_inline, linux.syscall6, .{
            .mmap,
            0,
            length,
            prot,
            @as(u32, @bitCast(flags)),
            @as(usize, @bitCast(@as(isize, -1))),
            0,
        });
    }
}
const std = @import("../../std.zig");
const elf = std.elf;
const linux = std.os.linux;
const mem = std.mem;
const maxInt = std.math.maxInt;

pub fn lookup(vername: []const u8, name: []const u8) usize {
    const vdso_addr = linux.getauxval(std.elf.AT_SYSINFO_EHDR);
    if (vdso_addr == 0) return 0;

    const eh = @as(*elf.Ehdr, @ptrFromInt(vdso_addr));
    var ph_addr: usize = vdso_addr + eh.e_phoff;

    var maybe_dynv: ?[*]usize = null;
    var base: usize = maxInt(usize);
    {
        var i: usize = 0;
        while (i < eh.e_phnum) : ({
            i += 1;
            ph_addr += eh.e_phentsize;
        }) {
            const this_ph = @as(*elf.Phdr, @ptrFromInt(ph_addr));
            switch (this_ph.p_type) {
                // On WSL1 as well as older kernels, the VDSO ELF image is pre-linked in the upper half
                // of the memory space (e.g. p_vaddr = 0xffffffffff700000 on WSL1).
                // Wrapping operations are used on this line as well as subsequent calculations relative to base
                // (lines 47, 78) to ensure no overflow check is tripped.
                elf.PT_LOAD => base = vdso_addr +% this_ph.p_offset -% this_ph.p_vaddr,
                elf.PT_DYNAMIC => maybe_dynv = @as([*]usize, @ptrFromInt(vdso_addr + this_ph.p_offset)),
                else => {},
            }
        }
    }
    const dynv = maybe_dynv orelse return 0;
    if (base == maxInt(usize)) return 0;

    var maybe_strings: ?[*:0]u8 = null;
    var maybe_syms: ?[*]elf.Sym = null;
    var maybe_hashtab: ?[*]linux.Elf_Symndx = null;
    var maybe_versym: ?[*]elf.Versym = null;
    var maybe_verdef: ?*elf.Verdef = null;

    {
        var i: usize = 0;
        while (dynv[i] != 0) : (i += 2) {
            const p = base +% dynv[i + 1];
            switch (dynv[i]) {
                elf.DT_STRTAB => maybe_strings = @ptrFromInt(p),
                elf.DT_SYMTAB => maybe_syms = @ptrFromInt(p),
                elf.DT_HASH => maybe_hashtab = @ptrFromInt(p),
                elf.DT_VERSYM => maybe_versym = @ptrFromInt(p),
                elf.DT_VERDEF => maybe_verdef = @ptrFromInt(p),
                else => {},
            }
        }
    }

    const strings = maybe_strings orelse return 0;
    const syms = maybe_syms orelse return 0;
    const hashtab = maybe_hashtab orelse return 0;
    if (maybe_verdef == null) maybe_versym = null;

    const OK_TYPES = (1 << elf.STT_NOTYPE | 1 << elf.STT_OBJECT | 1 << elf.STT_FUNC | 1 << elf.STT_COMMON);
    const OK_BINDS = (1 << elf.STB_GLOBAL | 1 << elf.STB_WEAK | 1 << elf.STB_GNU_UNIQUE);

    var i: usize = 0;
    while (i < hashtab[1]) : (i += 1) {
        if (0 == (@as(u32, 1) << @as(u5, @intCast(syms[i].st_info & 0xf)) & OK_TYPES)) continue;
        if (0 == (@as(u32, 1) << @as(u5, @intCast(syms[i].st_info >> 4)) & OK_BINDS)) continue;
        if (0 == syms[i].st_shndx) continue;
        const sym_name = @as([*:0]u8, @ptrCast(strings + syms[i].st_name));
        if (!mem.eql(u8, name, mem.sliceTo(sym_name, 0))) continue;
        if (maybe_versym) |versym| {
            if (!checkver(maybe_verdef.?, versym[i], vername, strings))
                continue;
        }
        return base +% syms[i].st_value;
    }

    return 0;
}

fn checkver(def_arg: *elf.Verdef, vsym_arg: elf.Versym, vername: []const u8, strings: [*:0]u8) bool {
    var def = def_arg;
    const vsym_index = vsym_arg.VERSION;
    while (true) {
        if (0 == (def.flags & elf.VER_FLG_BASE) and @intFromEnum(def.ndx) == vsym_index) break;
        if (def.next == 0) return false;
        def = @ptrFromInt(@intFromPtr(def) + def.next);
    }
    const aux: *elf.Verdaux = @ptrFromInt(@intFromPtr(def) + def.aux);
    return mem.eql(u8, vername, mem.sliceTo(strings + aux.name, 0));
}
const builtin = @import("builtin");
const std = @import("../../std.zig");
const maxInt = std.math.maxInt;
const linux = std.os.linux;
const SYS = linux.SYS;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;

const pid_t = linux.pid_t;
const uid_t = linux.uid_t;
const gid_t = linux.gid_t;
const clock_t = linux.clock_t;
const stack_t = linux.stack_t;
const sigset_t = linux.sigset_t;
const sockaddr = linux.sockaddr;
const socklen_t = linux.socklen_t;
const timespec = linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
        : "rcx", "r11", "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
        : "rcx", "r11", "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
        : "rcx", "r11", "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
        : "rcx", "r11", "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
          [arg4] "{r10}" (arg4),
        : "rcx", "r11", "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
          [arg4] "{r10}" (arg4),
          [arg5] "{r8}" (arg5),
        : "rcx", "r11", "memory"
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
    return asm volatile ("syscall"
        : [ret] "={rax}" (-> usize),
        : [number] "{rax}" (@intFromEnum(number)),
          [arg1] "{rdi}" (arg1),
          [arg2] "{rsi}" (arg2),
          [arg3] "{rdx}" (arg3),
          [arg4] "{r10}" (arg4),
          [arg5] "{r8}" (arg5),
          [arg6] "{r9}" (arg6),
        : "rcx", "r11", "memory"
    );
}

pub fn clone() callconv(.naked) usize {
    asm volatile (
        \\      movl $56,%%eax // SYS_clone
        \\      movq %%rdi,%%r11
        \\      movq %%rdx,%%rdi
        \\      movq %%r8,%%rdx
        \\      movq %%r9,%%r8
        \\      movq 8(%%rsp),%%r10
        \\      movq %%r11,%%r9
        \\      andq $-16,%%rsi
        \\      subq $8,%%rsi
        \\      movq %%rcx,(%%rsi)
        \\      syscall
        \\      testq %%rax,%%rax
        \\      jz 1f
        \\      retq
        \\
        \\1:
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\      .cfi_undefined %%rip
    );
    asm volatile (
        \\      xorl %%ebp,%%ebp
        \\
        \\      popq %%rdi
        \\      callq *%%r9
        \\      movl %%eax,%%edi
        \\      movl $60,%%eax // SYS_exit
        \\      syscall
        \\
    );
}

pub const restore = restore_rt;

pub fn restore_rt() callconv(.naked) noreturn {
    switch (@import("builtin").zig_backend) {
        .stage2_c => asm volatile (
            \\ movl %[number], %%eax
            \\ syscall
            :
            : [number] "i" (@intFromEnum(SYS.rt_sigreturn)),
            : "rcx", "r11", "memory"
        ),
        else => asm volatile (
            \\ syscall
            :
            : [number] "{rax}" (@intFromEnum(SYS.rt_sigreturn)),
            : "rcx", "r11", "memory"
        ),
    }
}

pub const mode_t = usize;
pub const time_t = isize;
pub const nlink_t = usize;
pub const blksize_t = isize;
pub const blkcnt_t = isize;

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

    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;
    pub const GETOWNER_UIDS = 17;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;
};

pub const VDSO = struct {
    pub const CGT_SYM = "__vdso_clock_gettime";
    pub const CGT_VER = "LINUX_2.6";

    pub const GETCPU_SYM = "__vdso_getcpu";
    pub const GETCPU_VER = "LINUX_2.6";
};

pub const ARCH = struct {
    pub const SET_GS = 0x1001;
    pub const SET_FS = 0x1002;
    pub const GET_FS = 0x1003;
    pub const GET_GS = 0x1004;
};

pub const REG = struct {
    pub const R8 = 0;
    pub const R9 = 1;
    pub const R10 = 2;
    pub const R11 = 3;
    pub const R12 = 4;
    pub const R13 = 5;
    pub const R14 = 6;
    pub const R15 = 7;
    pub const RDI = 8;
    pub const RSI = 9;
    pub const RBP = 10;
    pub const RBX = 11;
    pub const RDX = 12;
    pub const RAX = 13;
    pub const RCX = 14;
    pub const RSP = 15;
    pub const RIP = 16;
    pub const EFL = 17;
    pub const CSGSFS = 18;
    pub const ERR = 19;
    pub const TRAPNO = 20;
    pub const OLDMASK = 21;
    pub const CR2 = 22;
};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    start: off_t,
    len: off_t,
    pid: pid_t,
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

pub const off_t = i64;
pub const ino_t = u64;
pub const dev_t = u64;

// The `stat` definition used by the Linux kernel.
pub const Stat = extern struct {
    dev: dev_t,
    ino: ino_t,
    nlink: usize,

    mode: u32,
    uid: uid_t,
    gid: gid_t,
    __pad0: u32,
    rdev: dev_t,
    size: off_t,
    blksize: isize,
    blocks: i64,

    atim: timespec,
    mtim: timespec,
    ctim: timespec,
    __unused: [3]isize,

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

pub const Elf_Symndx = u32;

pub const greg_t = usize;
pub const gregset_t = [23]greg_t;
pub const fpstate = extern struct {
    cwd: u16,
    swd: u16,
    ftw: u16,
    fop: u16,
    rip: usize,
    rdp: usize,
    mxcsr: u32,
    mxcr_mask: u32,
    st: [8]extern struct {
        significand: [4]u16,
        exponent: u16,
        padding: [3]u16 = undefined,
    },
    xmm: [16]extern struct {
        element: [4]u32,
    },
    padding: [24]u32 = undefined,
};
pub const fpregset_t = *fpstate;
pub const sigcontext = extern struct {
    r8: usize,
    r9: usize,
    r10: usize,
    r11: usize,
    r12: usize,
    r13: usize,
    r14: usize,
    r15: usize,

    rdi: usize,
    rsi: usize,
    rbp: usize,
    rbx: usize,
    rdx: usize,
    rax: usize,
    rcx: usize,
    rsp: usize,
    rip: usize,
    eflags: usize,

    cs: u16,
    gs: u16,
    fs: u16,
    pad0: u16 = undefined,

    err: usize,
    trapno: usize,
    oldmask: usize,
    cr2: usize,

    fpstate: *fpstate,
    reserved1: [8]usize = undefined,
};

pub const mcontext_t = extern struct {
    gregs: gregset_t,
    fpregs: fpregset_t,
    reserved1: [8]usize = undefined,
};

pub const ucontext_t = extern struct {
    flags: usize,
    link: ?*ucontext_t,
    stack: stack_t,
    mcontext: mcontext_t,
    sigmask: sigset_t,
    fpregs_mem: [64]usize,
};

fn gpRegisterOffset(comptime reg_index: comptime_int) usize {
    return @offsetOf(ucontext_t, "mcontext") + @offsetOf(mcontext_t, "gregs") + @sizeOf(usize) * reg_index;
}

fn getContextInternal() callconv(.naked) usize {
    // TODO: Read GS/FS registers?
    asm volatile (
        \\ movq $0, %[flags_offset:c](%%rdi)
        \\ movq $0, %[link_offset:c](%%rdi)
        \\ movq %%r8, %[r8_offset:c](%%rdi)
        \\ movq %%r9, %[r9_offset:c](%%rdi)
        \\ movq %%r10, %[r10_offset:c](%%rdi)
        \\ movq %%r11, %[r11_offset:c](%%rdi)
        \\ movq %%r12, %[r12_offset:c](%%rdi)
        \\ movq %%r13, %[r13_offset:c](%%rdi)
        \\ movq %%r14, %[r14_offset:c](%%rdi)
        \\ movq %%r15, %[r15_offset:c](%%rdi)
        \\ movq %%rdi, %[rdi_offset:c](%%rdi)
        \\ movq %%rsi, %[rsi_offset:c](%%rdi)
        \\ movq %%rbp, %[rbp_offset:c](%%rdi)
        \\ movq %%rbx, %[rbx_offset:c](%%rdi)
        \\ movq %%rdx, %[rdx_offset:c](%%rdi)
        \\ movq %%rax, %[rax_offset:c](%%rdi)
        \\ movq %%rcx, %[rcx_offset:c](%%rdi)
        \\ movq (%%rsp), %%rcx
        \\ movq %%rcx, %[rip_offset:c](%%rdi)
        \\ leaq 8(%%rsp), %%rcx
        \\ movq %%rcx, %[rsp_offset:c](%%rdi)
        \\ pushfq
        \\ popq %[efl_offset:c](%%rdi)
        \\ leaq %[fpmem_offset:c](%%rdi), %%rcx
        \\ movq %%rcx, %[fpstate_offset:c](%%rdi)
        \\ fnstenv (%%rcx)
        \\ fldenv (%%rcx)
        \\ stmxcsr %[mxcsr_offset:c](%%rdi)
        \\ leaq %[stack_offset:c](%%rdi), %%rsi
        \\ movq %%rdi, %%r8
        \\ xorl %%edi, %%edi
        \\ movl %[sigaltstack], %%eax
        \\ syscall
        \\ testq %%rax, %%rax
        \\ jnz 0f
        \\ movl %[sigprocmask], %%eax
        \\ xorl %%esi, %%esi
        \\ leaq %[sigmask_offset:c](%%r8), %%rdx
        \\ movl %[sigset_size], %%r10d
        \\ syscall
        \\0:
        \\ retq
        :
        : [flags_offset] "i" (@offsetOf(ucontext_t, "flags")),
          [link_offset] "i" (@offsetOf(ucontext_t, "link")),
          [r8_offset] "i" (comptime gpRegisterOffset(REG.R8)),
          [r9_offset] "i" (comptime gpRegisterOffset(REG.R9)),
          [r10_offset] "i" (comptime gpRegisterOffset(REG.R10)),
          [r11_offset] "i" (comptime gpRegisterOffset(REG.R11)),
          [r12_offset] "i" (comptime gpRegisterOffset(REG.R12)),
          [r13_offset] "i" (comptime gpRegisterOffset(REG.R13)),
          [r14_offset] "i" (comptime gpRegisterOffset(REG.R14)),
          [r15_offset] "i" (comptime gpRegisterOffset(REG.R15)),
          [rdi_offset] "i" (comptime gpRegisterOffset(REG.RDI)),
          [rsi_offset] "i" (comptime gpRegisterOffset(REG.RSI)),
          [rbp_offset] "i" (comptime gpRegisterOffset(REG.RBP)),
          [rbx_offset] "i" (comptime gpRegisterOffset(REG.RBX)),
          [rdx_offset] "i" (comptime gpRegisterOffset(REG.RDX)),
          [rax_offset] "i" (comptime gpRegisterOffset(REG.RAX)),
          [rcx_offset] "i" (comptime gpRegisterOffset(REG.RCX)),
          [rsp_offset] "i" (comptime gpRegisterOffset(REG.RSP)),
          [rip_offset] "i" (comptime gpRegisterOffset(REG.RIP)),
          [efl_offset] "i" (comptime gpRegisterOffset(REG.EFL)),
          [fpstate_offset] "i" (@offsetOf(ucontext_t, "mcontext") + @offsetOf(mcontext_t, "fpregs")),
          [fpmem_offset] "i" (@offsetOf(ucontext_t, "fpregs_mem")),
          [mxcsr_offset] "i" (@offsetOf(ucontext_t, "fpregs_mem") + @offsetOf(fpstate, "mxcsr")),
          [sigaltstack] "i" (@intFromEnum(linux.SYS.sigaltstack)),
          [stack_offset] "i" (@offsetOf(ucontext_t, "stack")),
          [sigprocmask] "i" (@intFromEnum(linux.SYS.rt_sigprocmask)),
          [sigmask_offset] "i" (@offsetOf(ucontext_t, "sigmask")),
          [sigset_size] "i" (linux.NSIG / 8),
        : "cc", "memory", "rax", "rcx", "rdx", "rdi", "rsi", "r8", "r10", "r11"
    );
}

pub inline fn getcontext(context: *ucontext_t) usize {
    // This method is used so that getContextInternal can control
    // its prologue in order to read RSP from a constant offset
    // An aligned stack is not needed for getContextInternal.
    var clobber_rdi: usize = undefined;
    return asm volatile (
        \\ callq %[getContextInternal:P]
        : [_] "={rax}" (-> usize),
          [_] "={rdi}" (clobber_rdi),
        : [_] "{rdi}" (context),
          [getContextInternal] "X" (&getContextInternal),
        : "cc", "memory", "rcx", "rdx", "rsi", "r8", "r10", "r11"
    );
}
const builtin = @import("builtin");
const std = @import("../../std.zig");
const maxInt = std.math.maxInt;
const linux = std.os.linux;
const SYS = linux.SYS;
const socklen_t = linux.socklen_t;
const iovec = std.posix.iovec;
const iovec_const = std.posix.iovec_const;
const uid_t = linux.uid_t;
const gid_t = linux.gid_t;
const pid_t = linux.pid_t;
const stack_t = linux.stack_t;
const sigset_t = linux.sigset_t;
const sockaddr = linux.sockaddr;
const timespec = linux.timespec;

pub fn syscall0(number: SYS) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize),
        : [number] "{eax}" (@intFromEnum(number)),
        : "memory"
    );
}

pub fn syscall1(number: SYS, arg1: usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize),
        : [number] "{eax}" (@intFromEnum(number)),
          [arg1] "{ebx}" (arg1),
        : "memory"
    );
}

pub fn syscall2(number: SYS, arg1: usize, arg2: usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize),
        : [number] "{eax}" (@intFromEnum(number)),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
        : "memory"
    );
}

pub fn syscall3(number: SYS, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize),
        : [number] "{eax}" (@intFromEnum(number)),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
        : "memory"
    );
}

pub fn syscall4(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize),
        : [number] "{eax}" (@intFromEnum(number)),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
          [arg4] "{esi}" (arg4),
        : "memory"
    );
}

pub fn syscall5(number: SYS, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize),
        : [number] "{eax}" (@intFromEnum(number)),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
          [arg4] "{esi}" (arg4),
          [arg5] "{edi}" (arg5),
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
    // arg5/arg6 are passed via memory as we're out of registers if ebp is used as frame pointer, or
    // if we're compiling with PIC. We push arg5/arg6 on the stack before changing ebp/esp as the
    // compiler may reference arg5/arg6 as an offset relative to ebp/esp.
    return asm volatile (
        \\ push %[arg5]
        \\ push %[arg6]
        \\ push %%edi
        \\ push %%ebp
        \\ mov  12(%%esp), %%edi
        \\ mov  8(%%esp), %%ebp
        \\ int  $0x80
        \\ pop  %%ebp
        \\ pop  %%edi
        \\ add  $8, %%esp
        : [ret] "={eax}" (-> usize),
        : [number] "{eax}" (@intFromEnum(number)),
          [arg1] "{ebx}" (arg1),
          [arg2] "{ecx}" (arg2),
          [arg3] "{edx}" (arg3),
          [arg4] "{esi}" (arg4),
          [arg5] "rm" (arg5),
          [arg6] "rm" (arg6),
        : "memory"
    );
}

pub fn socketcall(call: usize, args: [*]const usize) usize {
    return asm volatile ("int $0x80"
        : [ret] "={eax}" (-> usize),
        : [number] "{eax}" (@intFromEnum(SYS.socketcall)),
          [arg1] "{ebx}" (call),
          [arg2] "{ecx}" (@intFromPtr(args)),
        : "memory"
    );
}

pub fn clone() callconv(.naked) usize {
    // __clone(func, stack, flags, arg, ptid, tls, ctid)
    //         +8,   +12,   +16,   +20, +24,  +28, +32
    //
    // syscall(SYS_clone, flags, stack, ptid, tls, ctid)
    //         eax,       ebx,   ecx,   edx,  esi, edi
    asm volatile (
        \\  pushl %%ebp
        \\  movl %%esp,%%ebp
        \\  pushl %%ebx
        \\  pushl %%esi
        \\  pushl %%edi
        \\  // Setup the arguments
        \\  movl 16(%%ebp),%%ebx
        \\  movl 12(%%ebp),%%ecx
        \\  andl $-16,%%ecx
        \\  subl $20,%%ecx
        \\  movl 20(%%ebp),%%eax
        \\  movl %%eax,4(%%ecx)
        \\  movl 8(%%ebp),%%eax
        \\  movl %%eax,0(%%ecx)
        \\  movl 24(%%ebp),%%edx
        \\  movl 28(%%ebp),%%esi
        \\  movl 32(%%ebp),%%edi
        \\  movl $120,%%eax // SYS_clone
        \\  int $128
        \\  testl %%eax,%%eax
        \\  jz 1f
        \\  popl %%edi
        \\  popl %%esi
        \\  popl %%ebx
        \\  popl %%ebp
        \\  retl
        \\
        \\1:
    );
    if (builtin.unwind_tables != .none or !builtin.strip_debug_info) asm volatile (
        \\  .cfi_undefined %%eip
    );
    asm volatile (
        \\  xorl %%ebp,%%ebp
        \\
        \\  popl %%eax
        \\  calll *%%eax
        \\  movl %%eax,%%ebx
        \\  movl $1,%%eax // SYS_exit
        \\  int $128
    );
}

pub fn restore() callconv(.naked) noreturn {
    switch (@import("builtin").zig_backend) {
        .stage2_c => asm volatile (
            \\ movl %[number], %%eax
            \\ int $0x80
            :
            : [number] "i" (@intFromEnum(SYS.sigreturn)),
            : "memory"
        ),
        else => asm volatile (
            \\ int $0x80
            :
            : [number] "{eax}" (@intFromEnum(SYS.sigreturn)),
            : "memory"
        ),
    }
}

pub fn restore_rt() callconv(.naked) noreturn {
    switch (@import("builtin").zig_backend) {
        .stage2_c => asm volatile (
            \\ movl %[number], %%eax
            \\ int $0x80
            :
            : [number] "i" (@intFromEnum(SYS.rt_sigreturn)),
            : "memory"
        ),
        else => asm volatile (
            \\ int $0x80
            :
            : [number] "{eax}" (@intFromEnum(SYS.rt_sigreturn)),
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
    pub const SETOWN_EX = 15;
    pub const GETOWN_EX = 16;
    pub const GETOWNER_UIDS = 17;

    pub const RDLCK = 0;
    pub const WRLCK = 1;
    pub const UNLCK = 2;
};

pub const VDSO = struct {
    pub const CGT_SYM = "__vdso_clock_gettime";
    pub const CGT_VER = "LINUX_2.6";
};

pub const ARCH = struct {};

pub const Flock = extern struct {
    type: i16,
    whence: i16,
    start: off_t,
    len: off_t,
    pid: pid_t,
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
    gregs: [19]usize,
    fpregs: [*]u8,
    oldmask: usize,
    cr2: usize,
};

pub const REG = struct {
    pub const GS = 0;
    pub const FS = 1;
    pub const ES = 2;
    pub const DS = 3;
    pub const EDI = 4;
    pub const ESI = 5;
    pub const EBP = 6;
    pub const ESP = 7;
    pub const EBX = 8;
    pub const EDX = 9;
    pub const ECX = 10;
    pub const EAX = 11;
    pub const TRAPNO = 12;
    pub const ERR = 13;
    pub const EIP = 14;
    pub const CS = 15;
    pub const EFL = 16;
    pub const UESP = 17;
    pub const SS = 18;
};

pub const ucontext_t = extern struct {
    flags: usize,
    link: ?*ucontext_t,
    stack: stack_t,
    mcontext: mcontext_t,
    sigmask: sigset_t,
    regspace: [64]u64,
};

pub const Elf_Symndx = u32;

pub const user_desc = extern struct {
    entry_number: u32,
    base_addr: u32,
    limit: u32,
    flags: packed struct(u32) {
        seg_32bit: u1,
        contents: u2,
        read_exec_only: u1,
        limit_in_pages: u1,
        seg_not_present: u1,
        useable: u1,
        _: u25 = undefined,
    },
};

/// socketcall() call numbers
pub const SC = struct {
    pub const socket = 1;
    pub const bind = 2;
    pub const connect = 3;
    pub const listen = 4;
    pub const accept = 5;
    pub const getsockname = 6;
    pub const getpeername = 7;
    pub const socketpair = 8;
    pub const send = 9;
    pub const recv = 10;
    pub const sendto = 11;
    pub const recvfrom = 12;
    pub const shutdown = 13;
    pub const setsockopt = 14;
    pub const getsockopt = 15;
    pub const sendmsg = 16;
    pub const recvmsg = 17;
    pub const accept4 = 18;
    pub const recvmmsg = 19;
    pub const sendmmsg = 20;
};

fn gpRegisterOffset(comptime reg_index: comptime_int) usize {
    return @offsetOf(ucontext_t, "mcontext") + @offsetOf(mcontext_t, "gregs") + @sizeOf(usize) * reg_index;
}

noinline fn getContextReturnAddress() usize {
    return @returnAddress();
}

pub fn getContextInternal() callconv(.naked) usize {
    asm volatile (
        \\ movl $0, %[flags_offset:c](%%edx)
        \\ movl $0, %[link_offset:c](%%edx)
        \\ movl %%edi, %[edi_offset:c](%%edx)
        \\ movl %%esi, %[esi_offset:c](%%edx)
        \\ movl %%ebp, %[ebp_offset:c](%%edx)
        \\ movl %%ebx, %[ebx_offset:c](%%edx)
        \\ movl %%edx, %[edx_offset:c](%%edx)
        \\ movl %%ecx, %[ecx_offset:c](%%edx)
        \\ movl %%eax, %[eax_offset:c](%%edx)
        \\ movl (%%esp), %%ecx
        \\ movl %%ecx, %[eip_offset:c](%%edx)
        \\ leal 4(%%esp), %%ecx
        \\ movl %%ecx, %[esp_offset:c](%%edx)
        \\ xorl %%ecx, %%ecx
        \\ movw %%fs, %%cx
        \\ movl %%ecx, %[fs_offset:c](%%edx)
        \\ leal %[regspace_offset:c](%%edx), %%ecx
        \\ movl %%ecx, %[fpregs_offset:c](%%edx)
        \\ fnstenv (%%ecx)
        \\ fldenv (%%ecx)
        \\ pushl %%ebx
        \\ pushl %%esi
        \\ xorl %%ebx, %%ebx
        \\ movl %[sigaltstack], %%eax
        \\ leal %[stack_offset:c](%%edx), %%ecx
        \\ int $0x80
        \\ testl %%eax, %%eax
        \\ jnz 0f
        \\ movl %[sigprocmask], %%eax
        \\ xorl %%ecx, %%ecx
        \\ leal %[sigmask_offset:c](%%edx), %%edx
        \\ movl %[sigset_size], %%esi
        \\ int $0x80
        \\0:
        \\ popl %%esi
        \\ popl %%ebx
        \\ retl
        :
        : [flags_offset] "i" (@offsetOf(ucontext_t, "flags")),
          [link_offset] "i" (@offsetOf(ucontext_t, "link")),
          [edi_offset] "i" (comptime gpRegisterOffset(REG.EDI)),
          [esi_offset] "i" (comptime gpRegisterOffset(REG.ESI)),
          [ebp_offset] "i" (comptime gpRegisterOffset(REG.EBP)),
          [esp_offset] "i" (comptime gpRegisterOffset(REG.ESP)),
          [ebx_offset] "i" (comptime gpRegisterOffset(REG.EBX)),
          [edx_offset] "i" (comptime gpRegisterOffset(REG.EDX)),
          [ecx_offset] "i" (comptime gpRegisterOffset(REG.ECX)),
          [eax_offset] "i" (comptime gpRegisterOffset(REG.EAX)),
          [eip_offset] "i" (comptime gpRegisterOffset(REG.EIP)),
          [fs_offset] "i" (comptime gpRegisterOffset(REG.FS)),
          [fpregs_offset] "i" (@offsetOf(ucontext_t, "mcontext") + @offsetOf(mcontext_t, "fpregs")),
          [regspace_offset] "i" (@offsetOf(ucontext_t, "regspace")),
          [sigaltstack] "i" (@intFromEnum(linux.SYS.sigaltstack)),
          [stack_offset] "i" (@offsetOf(ucontext_t, "stack")),
          [sigprocmask] "i" (@intFromEnum(linux.SYS.rt_sigprocmask)),
          [sigmask_offset] "i" (@offsetOf(ucontext_t, "sigmask")),
          [sigset_size] "i" (linux.NSIG / 8),
        : "cc", "memory", "eax", "ecx", "edx"
    );
}

pub inline fn getcontext(context: *ucontext_t) usize {
    // This method is used so that getContextInternal can control
    // its prologue in order to read ESP from a constant offset.
    // An aligned stack is not needed for getContextInternal.
    var clobber_edx: usize = undefined;
    return asm volatile (
        \\ calll %[getContextInternal:P]
        : [_] "={eax}" (-> usize),
          [_] "={edx}" (clobber_edx),
        : [_] "{edx}" (context),
          [getContextInternal] "X" (&getContextInternal),
        : "cc", "memory", "ecx"
    );
}
const std = @import("../std.zig");
const builtin = @import("builtin");

pub const fd_t = i32;

pub const STDIN_FILENO = 0;
pub const STDOUT_FILENO = 1;
pub const STDERR_FILENO = 2;
pub const PATH_MAX = 1023;
pub const syscall_bits = switch (builtin.cpu.arch) {
    .x86_64 => @import("plan9/x86_64.zig"),
    else => @compileError("more plan9 syscall implementations (needs more inline asm in stage2"),
};
/// Ported from /sys/include/ape/errno.h
pub const E = enum(u16) {
    SUCCESS = 0,
    DOM = 1000,
    RANGE = 1001,
    PLAN9 = 1002,

    @"2BIG" = 1,
    ACCES = 2,
    AGAIN = 3,
    // WOULDBLOCK = 3, // TODO errno.h has 2 names for 3
    BADF = 4,
    BUSY = 5,
    CHILD = 6,
    DEADLK = 7,
    EXIST = 8,
    FAULT = 9,
    FBIG = 10,
    INTR = 11,
    INVAL = 12,
    IO = 13,
    ISDIR = 14,
    MFILE = 15,
    MLINK = 16,
    NAMETOOLONG = 17,
    NFILE = 18,
    NODEV = 19,
    NOENT = 20,
    NOEXEC = 21,
    NOLCK = 22,
    NOMEM = 23,
    NOSPC = 24,
    NOSYS = 25,
    NOTDIR = 26,
    NOTEMPTY = 27,
    NOTTY = 28,
    NXIO = 29,
    PERM = 30,
    PIPE = 31,
    ROFS = 32,
    SPIPE = 33,
    SRCH = 34,
    XDEV = 35,

    // bsd networking software
    NOTSOCK = 36,
    PROTONOSUPPORT = 37,
    // PROTOTYPE = 37, // TODO errno.h has two names for 37
    CONNREFUSED = 38,
    AFNOSUPPORT = 39,
    NOBUFS = 40,
    OPNOTSUPP = 41,
    ADDRINUSE = 42,
    DESTADDRREQ = 43,
    MSGSIZE = 44,
    NOPROTOOPT = 45,
    SOCKTNOSUPPORT = 46,
    PFNOSUPPORT = 47,
    ADDRNOTAVAIL = 48,
    NETDOWN = 49,
    NETUNREACH = 50,
    NETRESET = 51,
    CONNABORTED = 52,
    ISCONN = 53,
    NOTCONN = 54,
    SHUTDOWN = 55,
    TOOMANYREFS = 56,
    TIMEDOUT = 57,
    HOSTDOWN = 58,
    HOSTUNREACH = 59,
    GREG = 60,

    // These added in 1003.1b-1993
    CANCELED = 61,
    INPROGRESS = 62,

    // We just add these to be compatible with std.os, which uses them,
    // They should never get used.
    DQUOT,
    CONNRESET,
    OVERFLOW,
    LOOP,
    TXTBSY,

    pub fn init(r: usize) E {
        const signed_r: isize = @bitCast(r);
        const int = if (signed_r > -4096 and signed_r < 0) -signed_r else 0;
        return @enumFromInt(int);
    }
};
// The max bytes that can be in the errstr buff
pub const ERRMAX = 128;
var errstr_buf: [ERRMAX]u8 = undefined;
/// Gets whatever the last errstr was
pub fn errstr() []const u8 {
    _ = syscall_bits.syscall2(.ERRSTR, @intFromPtr(&errstr_buf), ERRMAX);
    return std.mem.span(@as([*:0]u8, @ptrCast(&errstr_buf)));
}
pub const Plink = anyopaque;
pub const Tos = extern struct {
    /// Per process profiling
    prof: extern struct {
        /// known to be 0(ptr)
        pp: *Plink,
        /// known to be 4(ptr)
        next: *Plink,
        last: *Plink,
        first: *Plink,
        pid: u32,
        what: u32,
    },
    /// cycle clock frequency if there is one, 0 otherwise
    cyclefreq: u64,
    /// cycles spent in kernel
    kcycles: i64,
    /// cycles spent in process (kernel + user)
    pcycles: i64,
    /// might as well put the pid here
    pid: u32,
    clock: u32,
    // top of stack is here
};

pub var tos: *Tos = undefined; // set in start.zig
pub fn getpid() u32 {
    return tos.pid;
}
pub const SIG = struct {
    /// hangup
    pub const HUP = 1;
    /// interrupt
    pub const INT = 2;
    /// quit
    pub const QUIT = 3;
    /// illegal instruction (not reset when caught)
    pub const ILL = 4;
    /// used by abort
    pub const ABRT = 5;
    /// floating point exception
    pub const FPE = 6;
    /// kill (cannot be caught or ignored)
    pub const KILL = 7;
    /// segmentation violation
    pub const SEGV = 8;
    /// write on a pipe with no one to read it
    pub const PIPE = 9;
    /// alarm clock
    pub const ALRM = 10;
    /// software termination signal from kill
    pub const TERM = 11;
    /// user defined signal 1
    pub const USR1 = 12;
    /// user defined signal 2
    pub const USR2 = 13;
    /// bus error
    pub const BUS = 14;
    // The following symbols must be defined, but the signals needn't be supported
    /// child process terminated or stopped
    pub const CHLD = 15;
    /// continue if stopped
    pub const CONT = 16;
    /// stop
    pub const STOP = 17;
    /// interactive stop
    pub const TSTP = 18;
    /// read from ctl tty by member of background
    pub const TTIN = 19;
    /// write to ctl tty by member of background
    pub const TTOU = 20;
};
pub const sigset_t = c_long;
pub const empty_sigset = 0;
pub const siginfo_t = c_long;
// TODO plan9 doesn't have sigaction_fn. Sigaction is not a union, but we include it here to be compatible.
pub const Sigaction = extern struct {
    pub const handler_fn = *const fn (i32) callconv(.c) void;
    pub const sigaction_fn = *const fn (i32, *const siginfo_t, ?*anyopaque) callconv(.c) void;

    handler: extern union {
        handler: ?handler_fn,
        sigaction: ?sigaction_fn,
    },
    mask: sigset_t,
    flags: c_int,
};
pub const AT = struct {
    pub const FDCWD = -100; // we just make up a constant; FDCWD and openat don't actually exist in plan9
};
// TODO implement sigaction
// right now it is just a shim to allow using start.zig code
pub fn sigaction(sig: u6, noalias act: ?*const Sigaction, noalias oact: ?*Sigaction) usize {
    _ = oact;
    _ = act;
    _ = sig;
    return 0;
}
pub const SYS = enum(usize) {
    SYSR1 = 0,
    _ERRSTR = 1,
    BIND = 2,
    CHDIR = 3,
    CLOSE = 4,
    DUP = 5,
    ALARM = 6,
    EXEC = 7,
    EXITS = 8,
    _FSESSION = 9,
    FAUTH = 10,
    _FSTAT = 11,
    SEGBRK = 12,
    _MOUNT = 13,
    OPEN = 14,
    _READ = 15,
    OSEEK = 16,
    SLEEP = 17,
    _STAT = 18,
    RFORK = 19,
    _WRITE = 20,
    PIPE = 21,
    CREATE = 22,
    FD2PATH = 23,
    BRK_ = 24,
    REMOVE = 25,
    _WSTAT = 26,
    _FWSTAT = 27,
    NOTIFY = 28,
    NOTED = 29,
    SEGATTACH = 30,
    SEGDETACH = 31,
    SEGFREE = 32,
    SEGFLUSH = 33,
    RENDEZVOUS = 34,
    UNMOUNT = 35,
    _WAIT = 36,
    SEMACQUIRE = 37,
    SEMRELEASE = 38,
    SEEK = 39,
    FVERSION = 40,
    ERRSTR = 41,
    STAT = 42,
    FSTAT = 43,
    WSTAT = 44,
    FWSTAT = 45,
    MOUNT = 46,
    AWAIT = 47,
    PREAD = 50,
    PWRITE = 51,
    TSEMACQUIRE = 52,
    _NSEC = 53,
};

pub fn write(fd: i32, buf: [*]const u8, count: usize) usize {
    return syscall_bits.syscall4(.PWRITE, @bitCast(@as(isize, fd)), @intFromPtr(buf), count, @bitCast(@as(isize, -1)));
}
pub fn pwrite(fd: i32, buf: [*]const u8, count: usize, offset: isize) usize {
    return syscall_bits.syscall4(.PWRITE, @bitCast(@as(isize, fd)), @intFromPtr(buf), count, @bitCast(offset));
}

pub fn read(fd: i32, buf: [*]const u8, count: usize) usize {
    return syscall_bits.syscall4(.PREAD, @bitCast(@as(isize, fd)), @intFromPtr(buf), count, @bitCast(@as(isize, -1)));
}
pub fn pread(fd: i32, buf: [*]const u8, count: usize, offset: isize) usize {
    return syscall_bits.syscall4(.PREAD, @bitCast(@as(isize, fd)), @intFromPtr(buf), count, @bitCast(offset));
}

pub fn open(path: [*:0]const u8, flags: u32) usize {
    return syscall_bits.syscall2(.OPEN, @intFromPtr(path), @bitCast(@as(isize, flags)));
}

pub fn openat(dirfd: i32, path: [*:0]const u8, flags: u32, _: mode_t) usize {
    // we skip perms because only create supports perms
    if (dirfd == AT.FDCWD) { // openat(AT_FDCWD, ...) == open(...)
        return open(path, flags);
    }
    var dir_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var total_path_buf: [std.fs.max_path_bytes + 1]u8 = undefined;
    const rc = fd2path(dirfd, &dir_path_buf, std.fs.max_path_bytes);
    if (rc != 0) return rc;
    var fba = std.heap.FixedBufferAllocator.init(&total_path_buf);
    var alloc = fba.allocator();
    const dir_path = std.mem.span(@as([*:0]u8, @ptrCast(&dir_path_buf)));
    const total_path = std.fs.path.join(alloc, &.{ dir_path, std.mem.span(path) }) catch unreachable; // the allocation shouldn't fail because it should not exceed max_path_bytes
    fba.reset();
    const total_path_z = alloc.dupeZ(u8, total_path) catch unreachable; // should not exceed max_path_bytes + 1
    return open(total_path_z.ptr, flags);
}

pub fn fd2path(fd: i32, buf: [*]u8, nbuf: usize) usize {
    return syscall_bits.syscall3(.FD2PATH, @bitCast(@as(isize, fd)), @intFromPtr(buf), nbuf);
}

pub fn create(path: [*:0]const u8, omode: mode_t, perms: usize) usize {
    return syscall_bits.syscall3(.CREATE, @intFromPtr(path), @bitCast(@as(isize, omode)), perms);
}

pub fn exit(status: u8) noreturn {
    if (status == 0) {
        exits(null);
    } else {
        // TODO plan9 does not have exit codes. You either exit with 0 or a string
        const arr: [1:0]u8 = .{status};
        exits(&arr);
    }
}

pub fn exits(status: ?[*:0]const u8) noreturn {
    _ = syscall_bits.syscall1(.EXITS, if (status) |s| @intFromPtr(s) else 0);
    unreachable;
}

pub fn close(fd: i32) usize {
    return syscall_bits.syscall1(.CLOSE, @bitCast(@as(isize, fd)));
}
pub const mode_t = i32;

pub const AccessMode = enum(u2) {
    RDONLY,
    WRONLY,
    RDWR,
    EXEC,
};

pub const O = packed struct(u32) {
    access: AccessMode,
    _2: u2 = 0,
    TRUNC: bool = false,
    CEXEC: bool = false,
    RCLOSE: bool = false,
    _7: u5 = 0,
    EXCL: bool = false,
    _: u19 = 0,
};

pub const ExecData = struct {
    pub extern const etext: anyopaque;
    pub extern const edata: anyopaque;
    pub extern const end: anyopaque;
};

/// Brk sets the system's idea of the lowest bss location not
/// used by the program (called the break) to addr rounded up to
/// the next multiple of 8 bytes.  Locations not less than addr
/// and below the stack pointer may cause a memory violation if
/// accessed. -9front brk(2)
pub fn brk_(addr: usize) i32 {
    return @intCast(syscall_bits.syscall1(.BRK_, addr));
}
var bloc: usize = 0;
var bloc_max: usize = 0;

pub fn sbrk(n: usize) usize {
    if (bloc == 0) {
        // we are at the start
        bloc = @intFromPtr(&ExecData.end);
        bloc_max = @intFromPtr(&ExecData.end);
    }
    const bl = std.mem.alignForward(usize, bloc, std.heap.pageSize());
    const n_aligned = std.mem.alignForward(usize, n, std.heap.pageSize());
    if (bl + n_aligned > bloc_max) {
        // we need to allocate
        if (brk_(bl + n_aligned) < 0) return 0;
        bloc_max = bl + n_aligned;
    }
    bloc = bloc + n_aligned;
    return bl;
}
const plan9 = @import("../plan9.zig");
// TODO better inline asm

pub fn syscall1(sys: plan9.SYS, arg0: usize) usize {
    return asm volatile (
        \\push %%r8
        \\push $0
        \\syscall
        \\pop %%r11
        \\pop %%r11
        : [ret] "={rax}" (-> usize),
        : [arg0] "{r8}" (arg0),
          [syscall_number] "{rbp}" (@intFromEnum(sys)),
        : "rcx", "rax", "rbp", "r11", "memory"
    );
}
pub fn syscall2(sys: plan9.SYS, arg0: usize, arg1: usize) usize {
    return asm volatile (
        \\push %%r9
        \\push %%r8
        \\push $0
        \\syscall
        \\pop %%r11
        \\pop %%r11
        \\pop %%r11
        : [ret] "={rax}" (-> usize),
        : [arg0] "{r8}" (arg0),
          [arg1] "{r9}" (arg1),
          [syscall_number] "{rbp}" (@intFromEnum(sys)),
        : "rcx", "rax", "rbp", "r11", "memory"
    );
}
pub fn syscall3(sys: plan9.SYS, arg0: usize, arg1: usize, arg2: usize) usize {
    return asm volatile (
        \\push %%r10
        \\push %%r9
        \\push %%r8
        \\push $0
        \\syscall
        \\pop %%r11
        \\pop %%r11
        \\pop %%r11
        \\pop %%r11
        : [ret] "={rax}" (-> usize),
        : [arg0] "{r8}" (arg0),
          [arg1] "{r9}" (arg1),
          [arg2] "{r10}" (arg2),
          [syscall_number] "{rbp}" (@intFromEnum(sys)),
        : "rcx", "rax", "rbp", "r11", "memory"
    );
}
pub fn syscall4(sys: plan9.SYS, arg0: usize, arg1: usize, arg2: usize, arg3: usize) usize {
    return asm volatile (
        \\push %%r11
        \\push %%r10
        \\push %%r9
        \\push %%r8
        \\push $0
        \\syscall
        \\pop %%r11
        \\pop %%r11
        \\pop %%r11
        \\pop %%r11
        \\pop %%r11
        : [ret] "={rax}" (-> usize),
        : [arg0] "{r8}" (arg0),
          [arg1] "{r9}" (arg1),
          [arg2] "{r10}" (arg2),
          [arg3] "{r11}" (arg3),
          [syscall_number] "{rbp}" (@intFromEnum(sys)),
        : "rcx", "rax", "rbp", "r11", "memory"
    );
}
const std = @import("../std.zig");

/// A protocol is an interface identified by a GUID.
pub const protocol = @import("uefi/protocol.```
