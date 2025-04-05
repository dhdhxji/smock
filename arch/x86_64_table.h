#define SMOCK_ARCH_SYSCALL_TABLE \
    [0  ] = (syscall_def){.name = "read"},                                    \
    [1  ] = (syscall_def){.name = "write"},                                   \
    [2  ] = (syscall_def){.name = "open"},                                    \
    [3  ] = (syscall_def){.name = "close"},                                   \
    [4  ] = (syscall_def){.name = "stat"},                                    \
    [5  ] = (syscall_def){.name = "fstat"},                                   \
    [6  ] = (syscall_def){.name = "lstat"},                                   \
    [7  ] = (syscall_def){.name = "poll"},                                    \
    [8  ] = (syscall_def){.name = "lseek"},                                   \
    [9  ] = (syscall_def){.name = "mmap"},                                    \
    [10 ] = (syscall_def){.name = "mprotect"},                                \
    [11 ] = (syscall_def){.name = "munmap"},                                  \
    [12 ] = (syscall_def){.name = "brk"},                                     \
    [13 ] = (syscall_def){.name = "rt_sigaction"},                            \
    [14 ] = (syscall_def){.name = "rt_sigprocmask"},                          \
    [15 ] = (syscall_def){.name = "rt_sigreturn"},                            \
    [16 ] = (syscall_def){.name = "ioctl"},                                   \
    [17 ] = (syscall_def){.name = "pread64"},                                 \
    [18 ] = (syscall_def){.name = "pwrite64"},                                \
    [19 ] = (syscall_def){.name = "readv"},                                   \
    [20 ] = (syscall_def){.name = "writev"},                                  \
    [21 ] = (syscall_def){.name = "access"},                                  \
    [22 ] = (syscall_def){.name = "pipe"},                                    \
    [23 ] = (syscall_def){.name = "select"},                                  \
    [24 ] = (syscall_def){.name = "sched_yield"},                             \
    [25 ] = (syscall_def){.name = "mremap"},                                  \
    [26 ] = (syscall_def){.name = "msync"},                                   \
    [27 ] = (syscall_def){.name = "mincore"},                                 \
    [28 ] = (syscall_def){.name = "madvise"},                                 \
    [29 ] = (syscall_def){.name = "shmget"},                                  \
    [30 ] = (syscall_def){.name = "shmat"},                                   \
    [31 ] = (syscall_def){.name = "shmctl"},                                  \
    [32 ] = (syscall_def){.name = "dup"},                                     \
    [33 ] = (syscall_def){.name = "dup2"},                                    \
    [34 ] = (syscall_def){.name = "pause"},                                   \
    [35 ] = (syscall_def){.name = "nanosleep"},                               \
    [36 ] = (syscall_def){.name = "getitimer"},                               \
    [37 ] = (syscall_def){.name = "alarm"},                                   \
    [38 ] = (syscall_def){.name = "setitimer"},                               \
    [39 ] = (syscall_def){.name = "getpid"},                                  \
    [40 ] = (syscall_def){.name = "sendfile"},                                \
    [41 ] = (syscall_def){.name = "socket"},                                  \
    [42 ] = (syscall_def){.name = "connect"},                                 \
    [43 ] = (syscall_def){.name = "accept"},                                  \
    [44 ] = (syscall_def){.name = "sendto"},                                  \
    [45 ] = (syscall_def){.name = "recvfrom"},                                \
    [46 ] = (syscall_def){.name = "sendmsg"},                                 \
    [47 ] = (syscall_def){.name = "recvmsg"},                                 \
    [48 ] = (syscall_def){.name = "shutdown"},                                \
    [49 ] = (syscall_def){.name = "bind"},                                    \
    [50 ] = (syscall_def){.name = "listen"},                                  \
    [51 ] = (syscall_def){.name = "getsockname"},                             \
    [52 ] = (syscall_def){.name = "getpeername"},                             \
    [53 ] = (syscall_def){.name = "socketpair"},                              \
    [54 ] = (syscall_def){.name = "setsockopt"},                              \
    [55 ] = (syscall_def){.name = "getsockopt"},                              \
    [56 ] = (syscall_def){.name = "clone"},                                   \
    [57 ] = (syscall_def){.name = "fork"},                                    \
    [58 ] = (syscall_def){.name = "vfork"},                                   \
    [59 ] = (syscall_def){.name = "execve"},                                  \
    [60 ] = (syscall_def){.name = "exit"},                                    \
    [61 ] = (syscall_def){.name = "wait4"},                                   \
    [62 ] = (syscall_def){.name = "kill"},                                    \
    [63 ] = (syscall_def){.name = "uname"},                                   \
    [64 ] = (syscall_def){.name = "semget"},                                  \
    [65 ] = (syscall_def){.name = "semop"},                                   \
    [66 ] = (syscall_def){.name = "semctl"},                                  \
    [67 ] = (syscall_def){.name = "shmdt"},                                   \
    [68 ] = (syscall_def){.name = "msgget"},                                  \
    [69 ] = (syscall_def){.name = "msgsnd"},                                  \
    [70 ] = (syscall_def){.name = "msgrcv"},                                  \
    [71 ] = (syscall_def){.name = "msgctl"},                                  \
    [72 ] = (syscall_def){.name = "fcntl"},                                   \
    [73 ] = (syscall_def){.name = "flock"},                                   \
    [74 ] = (syscall_def){.name = "fsync"},                                   \
    [75 ] = (syscall_def){.name = "fdatasync"},                               \
    [76 ] = (syscall_def){.name = "truncate"},                                \
    [77 ] = (syscall_def){.name = "ftruncate"},                               \
    [78 ] = (syscall_def){.name = "getdents"},                                \
    [79 ] = (syscall_def){.name = "getcwd"},                                  \
    [80 ] = (syscall_def){.name = "chdir"},                                   \
    [81 ] = (syscall_def){.name = "fchdir"},                                  \
    [82 ] = (syscall_def){.name = "rename"},                                  \
    [83 ] = (syscall_def){.name = "mkdir"},                                   \
    [84 ] = (syscall_def){.name = "rmdir"},                                   \
    [85 ] = (syscall_def){.name = "creat"},                                   \
    [86 ] = (syscall_def){.name = "link"},                                    \
    [87 ] = (syscall_def){.name = "unlink"},                                  \
    [88 ] = (syscall_def){.name = "symlink"},                                 \
    [89 ] = (syscall_def){.name = "readlink"},                                \
    [90 ] = (syscall_def){.name = "chmod"},                                   \
    [91 ] = (syscall_def){.name = "fchmod"},                                  \
    [92 ] = (syscall_def){.name = "chown"},                                   \
    [93 ] = (syscall_def){.name = "fchown"},                                  \
    [94 ] = (syscall_def){.name = "lchown"},                                  \
    [95 ] = (syscall_def){.name = "umask"},                                   \
    [96 ] = (syscall_def){.name = "gettimeofday"},                            \
    [97 ] = (syscall_def){.name = "getrlimit"},                               \
    [98 ] = (syscall_def){.name = "getrusage"},                               \
    [99 ] = (syscall_def){.name = "sysinfo"},                                 \
    [100] = (syscall_def){.name = "times"},                                   \
    [101] = (syscall_def){.name = "ptrace"},                                  \
    [102] = (syscall_def){.name = "getuid"},                                  \
    [103] = (syscall_def){.name = "syslog"},                                  \
    [104] = (syscall_def){.name = "getgid"},                                  \
    [105] = (syscall_def){.name = "setuid"},                                  \
    [106] = (syscall_def){.name = "setgid"},                                  \
    [107] = (syscall_def){.name = "geteuid"},                                 \
    [108] = (syscall_def){.name = "getegid"},                                 \
    [109] = (syscall_def){.name = "setpgid"},                                 \
    [110] = (syscall_def){.name = "getppid"},                                 \
    [111] = (syscall_def){.name = "getpgrp"},                                 \
    [112] = (syscall_def){.name = "setsid"},                                  \
    [113] = (syscall_def){.name = "setreuid"},                                \
    [114] = (syscall_def){.name = "setregid"},                                \
    [115] = (syscall_def){.name = "getgroups"},                               \
    [116] = (syscall_def){.name = "setgroups"},                               \
    [117] = (syscall_def){.name = "setresuid"},                               \
    [118] = (syscall_def){.name = "getresuid"},                               \
    [119] = (syscall_def){.name = "setresgid"},                               \
    [120] = (syscall_def){.name = "getresgid"},                               \
    [121] = (syscall_def){.name = "getpgid"},                                 \
    [122] = (syscall_def){.name = "setfsuid"},                                \
    [123] = (syscall_def){.name = "setfsgid"},                                \
    [124] = (syscall_def){.name = "getsid"},                                  \
    [125] = (syscall_def){.name = "capget"},                                  \
    [126] = (syscall_def){.name = "capset"},                                  \
    [127] = (syscall_def){.name = "rt_sigpending"},                           \
    [128] = (syscall_def){.name = "rt_sigtimedwait"},                         \
    [129] = (syscall_def){.name = "rt_sigqueueinfo"},                         \
    [130] = (syscall_def){.name = "rt_sigsuspend"},                           \
    [131] = (syscall_def){.name = "sigaltstack"},                             \
    [132] = (syscall_def){.name = "utime"},                                   \
    [133] = (syscall_def){.name = "mknod"},                                   \
    [134] = (syscall_def){.name = "uselib"},                                  \
    [135] = (syscall_def){.name = "personality"},                             \
    [136] = (syscall_def){.name = "ustat"},                                   \
    [137] = (syscall_def){.name = "statfs"},                                  \
    [138] = (syscall_def){.name = "fstatfs"},                                 \
    [139] = (syscall_def){.name = "sysfs"},                                   \
    [140] = (syscall_def){.name = "getpriority"},                             \
    [141] = (syscall_def){.name = "setpriority"},                             \
    [142] = (syscall_def){.name = "sched_setparam"},                          \
    [143] = (syscall_def){.name = "sched_getparam"},                          \
    [144] = (syscall_def){.name = "sched_setscheduler"},                      \
    [145] = (syscall_def){.name = "sched_getscheduler"},                      \
    [146] = (syscall_def){.name = "sched_get_priority_max"},                  \
    [147] = (syscall_def){.name = "sched_get_priority_min"},                  \
    [148] = (syscall_def){.name = "sched_rr_get_interval"},                   \
    [149] = (syscall_def){.name = "mlock"},                                   \
    [150] = (syscall_def){.name = "munlock"},                                 \
    [151] = (syscall_def){.name = "mlockall"},                                \
    [152] = (syscall_def){.name = "munlockall"},                              \
    [153] = (syscall_def){.name = "vhangup"},                                 \
    [154] = (syscall_def){.name = "modify_ldt"},                              \
    [155] = (syscall_def){.name = "pivot_root"},                              \
    [156] = (syscall_def){.name = "_sysctl"},                                 \
    [157] = (syscall_def){.name = "prctl"},                                   \
    [158] = (syscall_def){.name = "arch_prctl"},                              \
    [159] = (syscall_def){.name = "adjtimex"},                                \
    [160] = (syscall_def){.name = "setrlimit"},                               \
    [161] = (syscall_def){.name = "chroot"},                                  \
    [162] = (syscall_def){.name = "sync"},                                    \
    [163] = (syscall_def){.name = "acct"},                                    \
    [164] = (syscall_def){.name = "settimeofday"},                            \
    [165] = (syscall_def){.name = "mount"},                                   \
    [166] = (syscall_def){.name = "umount2"},                                 \
    [167] = (syscall_def){.name = "swapon"},                                  \
    [168] = (syscall_def){.name = "swapoff"},                                 \
    [169] = (syscall_def){.name = "reboot"},                                  \
    [170] = (syscall_def){.name = "sethostname"},                             \
    [171] = (syscall_def){.name = "setdomainname"},                           \
    [172] = (syscall_def){.name = "iopl"},                                    \
    [173] = (syscall_def){.name = "ioperm"},                                  \
    [174] = (syscall_def){.name = "create_module"},                           \
    [175] = (syscall_def){.name = "init_module"},                             \
    [176] = (syscall_def){.name = "delete_module"},                           \
    [177] = (syscall_def){.name = "get_kernel_syms"},                         \
    [178] = (syscall_def){.name = "query_module"},                            \
    [179] = (syscall_def){.name = "quotactl"},                                \
    [180] = (syscall_def){.name = "nfsservctl"},                              \
    [181] = (syscall_def){.name = "getpmsg"},                                 \
    [182] = (syscall_def){.name = "putpmsg"},                                 \
    [183] = (syscall_def){.name = "afs_syscall"},                             \
    [184] = (syscall_def){.name = "tuxcall"},                                 \
    [185] = (syscall_def){.name = "security"},                                \
    [186] = (syscall_def){.name = "gettid"},                                  \
    [187] = (syscall_def){.name = "readahead"},                               \
    [188] = (syscall_def){.name = "setxattr"},                                \
    [189] = (syscall_def){.name = "lsetxattr"},                               \
    [190] = (syscall_def){.name = "fsetxattr"},                               \
    [191] = (syscall_def){.name = "getxattr"},                                \
    [192] = (syscall_def){.name = "lgetxattr"},                               \
    [193] = (syscall_def){.name = "fgetxattr"},                               \
    [194] = (syscall_def){.name = "listxattr"},                               \
    [195] = (syscall_def){.name = "llistxattr"},                              \
    [196] = (syscall_def){.name = "flistxattr"},                              \
    [197] = (syscall_def){.name = "removexattr"},                             \
    [198] = (syscall_def){.name = "lremovexattr"},                            \
    [199] = (syscall_def){.name = "fremovexattr"},                            \
    [200] = (syscall_def){.name = "tkill"},                                   \
    [201] = (syscall_def){.name = "time"},                                    \
    [202] = (syscall_def){.name = "futex"},                                   \
    [203] = (syscall_def){.name = "sched_setaffinity"},                       \
    [204] = (syscall_def){.name = "sched_getaffinity"},                       \
    [205] = (syscall_def){.name = "set_thread_area"},                         \
    [206] = (syscall_def){.name = "io_setup"},                                \
    [207] = (syscall_def){.name = "io_destroy"},                              \
    [208] = (syscall_def){.name = "io_getevents"},                            \
    [209] = (syscall_def){.name = "io_submit"},                               \
    [210] = (syscall_def){.name = "io_cancel"},                               \
    [211] = (syscall_def){.name = "get_thread_area"},                         \
    [212] = (syscall_def){.name = "lookup_dcookie"},                          \
    [213] = (syscall_def){.name = "epoll_create"},                            \
    [214] = (syscall_def){.name = "epoll_ctl_old"},                           \
    [215] = (syscall_def){.name = "epoll_wait_old"},                          \
    [216] = (syscall_def){.name = "remap_file_pages"},                        \
    [217] = (syscall_def){.name = "getdents64"},                              \
    [218] = (syscall_def){.name = "set_tid_address"},                         \
    [219] = (syscall_def){.name = "restart_syscall"},                         \
    [220] = (syscall_def){.name = "semtimedop"},                              \
    [221] = (syscall_def){.name = "fadvise64"},                               \
    [222] = (syscall_def){.name = "timer_create"},                            \
    [223] = (syscall_def){.name = "timer_settime"},                           \
    [224] = (syscall_def){.name = "timer_gettime"},                           \
    [225] = (syscall_def){.name = "timer_getoverrun"},                        \
    [226] = (syscall_def){.name = "timer_delete"},                            \
    [227] = (syscall_def){.name = "clock_settime"},                           \
    [228] = (syscall_def){.name = "clock_gettime"},                           \
    [229] = (syscall_def){.name = "clock_getres"},                            \
    [230] = (syscall_def){.name = "clock_nanosleep"},                         \
    [231] = (syscall_def){.name = "exit_group"},                              \
    [232] = (syscall_def){.name = "epoll_wait"},                              \
    [233] = (syscall_def){.name = "epoll_ctl"},                               \
    [234] = (syscall_def){.name = "tgkill"},                                  \
    [235] = (syscall_def){.name = "utimes"},                                  \
    [236] = (syscall_def){.name = "vserver"},                                 \
    [237] = (syscall_def){.name = "mbind"},                                   \
    [238] = (syscall_def){.name = "set_mempolicy"},                           \
    [239] = (syscall_def){.name = "get_mempolicy"},                           \
    [240] = (syscall_def){.name = "mq_open"},                                 \
    [241] = (syscall_def){.name = "mq_unlink"},                               \
    [242] = (syscall_def){.name = "mq_timedsend"},                            \
    [243] = (syscall_def){.name = "mq_timedreceive"},                         \
    [244] = (syscall_def){.name = "mq_notify"},                               \
    [245] = (syscall_def){.name = "mq_getsetattr"},                           \
    [246] = (syscall_def){.name = "kexec_load"},                              \
    [247] = (syscall_def){.name = "waitid"},                                  \
    [248] = (syscall_def){.name = "add_key"},                                 \
    [249] = (syscall_def){.name = "request_key"},                             \
    [250] = (syscall_def){.name = "keyctl"},                                  \
    [251] = (syscall_def){.name = "ioprio_set"},                              \
    [252] = (syscall_def){.name = "ioprio_get"},                              \
    [253] = (syscall_def){.name = "inotify_init"},                            \
    [254] = (syscall_def){.name = "inotify_add_watch"},                       \
    [255] = (syscall_def){.name = "inotify_rm_watch"},                        \
    [256] = (syscall_def){.name = "migrate_pages"},                           \
    [257] = (syscall_def){.name = "openat"},                                  \
    [258] = (syscall_def){.name = "mkdirat"},                                 \
    [259] = (syscall_def){.name = "mknodat"},                                 \
    [260] = (syscall_def){.name = "fchownat"},                                \
    [261] = (syscall_def){.name = "futimesat"},                               \
    [262] = (syscall_def){.name = "newfstatat"},                              \
    [263] = (syscall_def){.name = "unlinkat"},                                \
    [264] = (syscall_def){.name = "renameat"},                                \
    [265] = (syscall_def){.name = "linkat"},                                  \
    [266] = (syscall_def){.name = "symlinkat"},                               \
    [267] = (syscall_def){.name = "readlinkat"},                              \
    [268] = (syscall_def){.name = "fchmodat"},                                \
    [269] = (syscall_def){.name = "faccessat"},                               \
    [270] = (syscall_def){.name = "pselect6"},                                \
    [271] = (syscall_def){.name = "ppoll"},                                   \
    [272] = (syscall_def){.name = "unshare"},                                 \
    [273] = (syscall_def){.name = "set_robust_list"},                         \
    [274] = (syscall_def){.name = "get_robust_list"},                         \
    [275] = (syscall_def){.name = "splice"},                                  \
    [276] = (syscall_def){.name = "tee"},                                     \
    [277] = (syscall_def){.name = "sync_file_range"},                         \
    [278] = (syscall_def){.name = "vmsplice"},                                \
    [279] = (syscall_def){.name = "move_pages"},                              \
    [280] = (syscall_def){.name = "utimensat"},                               \
    [281] = (syscall_def){.name = "epoll_pwait"},                             \
    [282] = (syscall_def){.name = "signalfd"},                                \
    [283] = (syscall_def){.name = "timerfd_create"},                          \
    [284] = (syscall_def){.name = "eventfd"},                                 \
    [285] = (syscall_def){.name = "fallocate"},                               \
    [286] = (syscall_def){.name = "timerfd_settime"},                         \
    [287] = (syscall_def){.name = "timerfd_gettime"},                         \
    [288] = (syscall_def){.name = "accept4"},                                 \
    [289] = (syscall_def){.name = "signalfd4"},                               \
    [290] = (syscall_def){.name = "eventfd2"},                                \
    [291] = (syscall_def){.name = "epoll_create1"},                           \
    [292] = (syscall_def){.name = "dup3"},                                    \
    [293] = (syscall_def){.name = "pipe2"},                                   \
    [294] = (syscall_def){.name = "inotify_init1"},                           \
    [295] = (syscall_def){.name = "preadv"},                                  \
    [296] = (syscall_def){.name = "pwritev"},                                 \
    [297] = (syscall_def){.name = "rt_tgsigqueueinfo"},                       \
    [298] = (syscall_def){.name = "perf_event_open"},                         \
    [299] = (syscall_def){.name = "recvmmsg"},                                \
    [300] = (syscall_def){.name = "fanotify_init"},                           \
    [301] = (syscall_def){.name = "fanotify_mark"},                           \
    [302] = (syscall_def){.name = "prlimit64"},                               \
    [303] = (syscall_def){.name = "name_to_handle_at"},                       \
    [304] = (syscall_def){.name = "open_by_handle_at"},                       \
    [305] = (syscall_def){.name = "clock_adjtime"},                           \
    [306] = (syscall_def){.name = "syncfs"},                                  \
    [307] = (syscall_def){.name = "sendmmsg"},                                \
    [308] = (syscall_def){.name = "setns"},                                   \
    [309] = (syscall_def){.name = "getcpu"},                                  \
    [310] = (syscall_def){.name = "process_vm_readv"},                        \
    [311] = (syscall_def){.name = "process_vm_writev"},                       \
    [312] = (syscall_def){.name = "kcmp"},                                    \
    [313] = (syscall_def){.name = "finit_module"},                            \
    [314] = (syscall_def){.name = "sched_setattr"},                           \
    [315] = (syscall_def){.name = "sched_getattr"},                           \
    [316] = (syscall_def){.name = "renameat2"},                               \
    [317] = (syscall_def){.name = "seccomp"},                                 \
    [318] = (syscall_def){.name = "getrandom"},                               \
    [319] = (syscall_def){.name = "memfd_create"},                            \
    [320] = (syscall_def){.name = "kexec_file_load"},                         \
    [321] = (syscall_def){.name = "bpf"},                                     \
    [322] = (syscall_def){.name = "execveat"},                                \
    [323] = (syscall_def){.name = "userfaultfd"},                             \
    [324] = (syscall_def){.name = "membarrier"},                              \
    [325] = (syscall_def){.name = "mlock2"},                                  \
    [326] = (syscall_def){.name = "copy_file_range"},                         \
    [327] = (syscall_def){.name = "preadv2"},                                 \
    [328] = (syscall_def){.name = "pwritev2"},                                \
    [329] = (syscall_def){.name = "pkey_mprotect"},                           \
    [330] = (syscall_def){.name = "pkey_alloc"},                              \
    [331] = (syscall_def){.name = "pkey_free"},                               \
    [332] = (syscall_def){.name = "statx"},                                   \
    [333] = (syscall_def){.name = "io_pgetevents"},                           \
    [334] = (syscall_def){.name = "rseq"},                                    \
    [424] = (syscall_def){.name = "pidfd_send_signal"},                       \
    [425] = (syscall_def){.name = "io_uring_setup"},                          \
    [426] = (syscall_def){.name = "io_uring_enter"},                          \
    [427] = (syscall_def){.name = "io_uring_register"},                       \
    [428] = (syscall_def){.name = "open_tree"},                               \
    [429] = (syscall_def){.name = "move_mount"},                              \
    [430] = (syscall_def){.name = "fsopen"},                                  \
    [431] = (syscall_def){.name = "fsconfig"},                                \
    [432] = (syscall_def){.name = "fsmount"},                                 \
    [433] = (syscall_def){.name = "fspick"},                                  \
    [434] = (syscall_def){.name = "pidfd_open"},                              \
    [435] = (syscall_def){.name = "clone3"},                                  \
    [436] = (syscall_def){.name = "close_range"},                             \
    [437] = (syscall_def){.name = "openat2"},                                 \
    [438] = (syscall_def){.name = "pidfd_getfd"},                             \
    [439] = (syscall_def){.name = "faccessat2"},                              \
    [440] = (syscall_def){.name = "process_madvise"},                         \
    [441] = (syscall_def){.name = "epoll_pwait2"},                            \
    [442] = (syscall_def){.name = "mount_setattr"},                           \
    [443] = (syscall_def){.name = "quotactl_fd"},                             \
    [444] = (syscall_def){.name = "landlock_create_ruleset"},                 \
    [445] = (syscall_def){.name = "landlock_add_rule"},                       \
    [446] = (syscall_def){.name = "landlock_restrict_self"},                  \
    [447] = (syscall_def){.name = "memfd_secret"},                            \
    [448] = (syscall_def){.name = "process_mrelease"},                        \
    [449] = (syscall_def){.name = "futex_waitv"},                             \
    [450] = (syscall_def){.name = "set_mempolicy_home_node"},                 \
    [451] = (syscall_def){.name = "cachestat"},                               \
    [452] = (syscall_def){.name = "fchmodat2"},                               \
    [453] = (syscall_def){.name = "map_shadow_stack"},                        \
    [454] = (syscall_def){.name = "futex_wake"},                              \
    [455] = (syscall_def){.name = "futex_wait"},                              \
    [456] = (syscall_def){.name = "futex_requeue"},                           \
    [457] = (syscall_def){.name = "statmount"},                               \
    [458] = (syscall_def){.name = "listmount"},                               \
    [459] = (syscall_def){.name = "lsm_get_self_attr"},                       \
    [460] = (syscall_def){.name = "lsm_set_self_attr"},                       \
    [461] = (syscall_def){.name = "lsm_list_modules"},                        \
    [462] = (syscall_def){.name = "mseal"},                                   \
    [512] = (syscall_def){.name = "rt_sigaction"},                            \
    [513] = (syscall_def){.name = "rt_sigreturn"},                            \
    [514] = (syscall_def){.name = "ioctl"},                                   \
    [515] = (syscall_def){.name = "readv"},                                   \
    [516] = (syscall_def){.name = "writev"},                                  \
    [517] = (syscall_def){.name = "recvfrom"},                                \
    [518] = (syscall_def){.name = "sendmsg"},                                 \
    [519] = (syscall_def){.name = "recvmsg"},                                 \
    [520] = (syscall_def){.name = "execve"},                                  \
    [521] = (syscall_def){.name = "ptrace"},                                  \
    [522] = (syscall_def){.name = "rt_sigpending"},                           \
    [523] = (syscall_def){.name = "rt_sigtimedwait"},                         \
    [524] = (syscall_def){.name = "rt_sigqueueinfo"},                         \
    [525] = (syscall_def){.name = "sigaltstack"},                             \
    [526] = (syscall_def){.name = "timer_create"},                            \
    [527] = (syscall_def){.name = "mq_notify"},                               \
    [528] = (syscall_def){.name = "kexec_load"},                              \
    [529] = (syscall_def){.name = "waitid"},                                  \
    [530] = (syscall_def){.name = "set_robust_list"},                         \
    [531] = (syscall_def){.name = "get_robust_list"},                         \
    [532] = (syscall_def){.name = "vmsplice"},                                \
    [533] = (syscall_def){.name = "move_pages"},                              \
    [534] = (syscall_def){.name = "preadv"},                                  \
    [535] = (syscall_def){.name = "pwritev"},                                 \
    [536] = (syscall_def){.name = "rt_tgsigqueueinfo"},                       \
    [537] = (syscall_def){.name = "recvmmsg"},                                \
    [538] = (syscall_def){.name = "sendmmsg"},                                \
    [539] = (syscall_def){.name = "process_vm_readv"},                        \
    [540] = (syscall_def){.name = "process_vm_writev"},                       \
    [541] = (syscall_def){.name = "setsockopt"},                              \
    [542] = (syscall_def){.name = "getsockopt"},                              \
    [543] = (syscall_def){.name = "io_setup"},                                \
    [544] = (syscall_def){.name = "io_submit"},                               \
    [545] = (syscall_def){.name = "execveat"},                                \
    [546] = (syscall_def){.name = "preadv2"},                                 \
    [547] = (syscall_def){.name = "pwritev2"},                                \

