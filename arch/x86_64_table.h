#define SMOCK_ARCH_SYSCALL_TABLE \
    [0  ] = {                                                                   \
        .name = "read",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [1  ] = {                                                                   \
        .name = "write",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [2  ] = {                                                                   \
        .name = "open",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [3  ] = {                                                                   \
        .name = "close",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [4  ] = {                                                                   \
        .name = "stat",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [5  ] = {                                                                   \
        .name = "fstat",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [6  ] = {                                                                   \
        .name = "lstat",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [7  ] = {                                                                   \
        .name = "poll",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [8  ] = {                                                                   \
        .name = "lseek",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [9  ] = {                                                                   \
        .name = "mmap",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [10 ] = {                                                                   \
        .name = "mprotect",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [11 ] = {                                                                   \
        .name = "munmap",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [12 ] = {                                                                   \
        .name = "brk",                                                          \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [13 ] = {                                                                   \
        .name = "rt_sigaction",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [14 ] = {                                                                   \
        .name = "rt_sigprocmask",                                               \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [15 ] = {                                                                   \
        .name = "rt_sigreturn",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [16 ] = {                                                                   \
        .name = "ioctl",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [17 ] = {                                                                   \
        .name = "pread64",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [18 ] = {                                                                   \
        .name = "pwrite64",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [19 ] = {                                                                   \
        .name = "readv",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [20 ] = {                                                                   \
        .name = "writev",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [21 ] = {                                                                   \
        .name = "access",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [22 ] = {                                                                   \
        .name = "pipe",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [23 ] = {                                                                   \
        .name = "select",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [24 ] = {                                                                   \
        .name = "sched_yield",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [25 ] = {                                                                   \
        .name = "mremap",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [26 ] = {                                                                   \
        .name = "msync",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [27 ] = {                                                                   \
        .name = "mincore",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [28 ] = {                                                                   \
        .name = "madvise",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [29 ] = {                                                                   \
        .name = "shmget",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [30 ] = {                                                                   \
        .name = "shmat",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [31 ] = {                                                                   \
        .name = "shmctl",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [32 ] = {                                                                   \
        .name = "dup",                                                          \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [33 ] = {                                                                   \
        .name = "dup2",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [34 ] = {                                                                   \
        .name = "pause",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [35 ] = {                                                                   \
        .name = "nanosleep",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [36 ] = {                                                                   \
        .name = "getitimer",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [37 ] = {                                                                   \
        .name = "alarm",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [38 ] = {                                                                   \
        .name = "setitimer",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [39 ] = {                                                                   \
        .name = "getpid",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [40 ] = {                                                                   \
        .name = "sendfile",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [41 ] = {                                                                   \
        .name = "socket",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [42 ] = {                                                                   \
        .name = "connect",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [43 ] = {                                                                   \
        .name = "accept",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [44 ] = {                                                                   \
        .name = "sendto",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [45 ] = {                                                                   \
        .name = "recvfrom",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [46 ] = {                                                                   \
        .name = "sendmsg",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [47 ] = {                                                                   \
        .name = "recvmsg",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [48 ] = {                                                                   \
        .name = "shutdown",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [49 ] = {                                                                   \
        .name = "bind",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [50 ] = {                                                                   \
        .name = "listen",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [51 ] = {                                                                   \
        .name = "getsockname",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [52 ] = {                                                                   \
        .name = "getpeername",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [53 ] = {                                                                   \
        .name = "socketpair",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [54 ] = {                                                                   \
        .name = "setsockopt",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [55 ] = {                                                                   \
        .name = "getsockopt",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [56 ] = {                                                                   \
        .name = "clone",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [57 ] = {                                                                   \
        .name = "fork",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [58 ] = {                                                                   \
        .name = "vfork",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [59 ] = {                                                                   \
        .name = "execve",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [60 ] = {                                                                   \
        .name = "exit",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [61 ] = {                                                                   \
        .name = "wait4",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [62 ] = {                                                                   \
        .name = "kill",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [63 ] = {                                                                   \
        .name = "uname",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [64 ] = {                                                                   \
        .name = "semget",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [65 ] = {                                                                   \
        .name = "semop",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [66 ] = {                                                                   \
        .name = "semctl",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [67 ] = {                                                                   \
        .name = "shmdt",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [68 ] = {                                                                   \
        .name = "msgget",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [69 ] = {                                                                   \
        .name = "msgsnd",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [70 ] = {                                                                   \
        .name = "msgrcv",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [71 ] = {                                                                   \
        .name = "msgctl",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [72 ] = {                                                                   \
        .name = "fcntl",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [73 ] = {                                                                   \
        .name = "flock",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [74 ] = {                                                                   \
        .name = "fsync",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [75 ] = {                                                                   \
        .name = "fdatasync",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [76 ] = {                                                                   \
        .name = "truncate",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [77 ] = {                                                                   \
        .name = "ftruncate",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [78 ] = {                                                                   \
        .name = "getdents",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [79 ] = {                                                                   \
        .name = "getcwd",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [80 ] = {                                                                   \
        .name = "chdir",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [81 ] = {                                                                   \
        .name = "fchdir",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [82 ] = {                                                                   \
        .name = "rename",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [83 ] = {                                                                   \
        .name = "mkdir",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [84 ] = {                                                                   \
        .name = "rmdir",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [85 ] = {                                                                   \
        .name = "creat",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [86 ] = {                                                                   \
        .name = "link",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [87 ] = {                                                                   \
        .name = "unlink",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [88 ] = {                                                                   \
        .name = "symlink",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [89 ] = {                                                                   \
        .name = "readlink",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [90 ] = {                                                                   \
        .name = "chmod",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [91 ] = {                                                                   \
        .name = "fchmod",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [92 ] = {                                                                   \
        .name = "chown",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [93 ] = {                                                                   \
        .name = "fchown",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [94 ] = {                                                                   \
        .name = "lchown",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [95 ] = {                                                                   \
        .name = "umask",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [96 ] = {                                                                   \
        .name = "gettimeofday",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [97 ] = {                                                                   \
        .name = "getrlimit",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [98 ] = {                                                                   \
        .name = "getrusage",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [99 ] = {                                                                   \
        .name = "sysinfo",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [100] = {                                                                   \
        .name = "times",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [101] = {                                                                   \
        .name = "ptrace",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [102] = {                                                                   \
        .name = "getuid",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [103] = {                                                                   \
        .name = "syslog",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [104] = {                                                                   \
        .name = "getgid",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [105] = {                                                                   \
        .name = "setuid",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [106] = {                                                                   \
        .name = "setgid",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [107] = {                                                                   \
        .name = "geteuid",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [108] = {                                                                   \
        .name = "getegid",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [109] = {                                                                   \
        .name = "setpgid",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [110] = {                                                                   \
        .name = "getppid",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [111] = {                                                                   \
        .name = "getpgrp",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [112] = {                                                                   \
        .name = "setsid",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [113] = {                                                                   \
        .name = "setreuid",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [114] = {                                                                   \
        .name = "setregid",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [115] = {                                                                   \
        .name = "getgroups",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [116] = {                                                                   \
        .name = "setgroups",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [117] = {                                                                   \
        .name = "setresuid",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [118] = {                                                                   \
        .name = "getresuid",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [119] = {                                                                   \
        .name = "setresgid",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [120] = {                                                                   \
        .name = "getresgid",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [121] = {                                                                   \
        .name = "getpgid",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [122] = {                                                                   \
        .name = "setfsuid",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [123] = {                                                                   \
        .name = "setfsgid",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [124] = {                                                                   \
        .name = "getsid",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [125] = {                                                                   \
        .name = "capget",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [126] = {                                                                   \
        .name = "capset",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [127] = {                                                                   \
        .name = "rt_sigpending",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [128] = {                                                                   \
        .name = "rt_sigtimedwait",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [129] = {                                                                   \
        .name = "rt_sigqueueinfo",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [130] = {                                                                   \
        .name = "rt_sigsuspend",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [131] = {                                                                   \
        .name = "sigaltstack",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [132] = {                                                                   \
        .name = "utime",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [133] = {                                                                   \
        .name = "mknod",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [134] = {                                                                   \
        .name = "uselib",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [135] = {                                                                   \
        .name = "personality",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [136] = {                                                                   \
        .name = "ustat",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [137] = {                                                                   \
        .name = "statfs",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [138] = {                                                                   \
        .name = "fstatfs",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [139] = {                                                                   \
        .name = "sysfs",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [140] = {                                                                   \
        .name = "getpriority",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [141] = {                                                                   \
        .name = "setpriority",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [142] = {                                                                   \
        .name = "sched_setparam",                                               \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [143] = {                                                                   \
        .name = "sched_getparam",                                               \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [144] = {                                                                   \
        .name = "sched_setscheduler",                                           \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [145] = {                                                                   \
        .name = "sched_getscheduler",                                           \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [146] = {                                                                   \
        .name = "sched_get_priority_max",                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [147] = {                                                                   \
        .name = "sched_get_priority_min",                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [148] = {                                                                   \
        .name = "sched_rr_get_interval",                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [149] = {                                                                   \
        .name = "mlock",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [150] = {                                                                   \
        .name = "munlock",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [151] = {                                                                   \
        .name = "mlockall",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [152] = {                                                                   \
        .name = "munlockall",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [153] = {                                                                   \
        .name = "vhangup",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [154] = {                                                                   \
        .name = "modify_ldt",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [155] = {                                                                   \
        .name = "pivot_root",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [156] = {                                                                   \
        .name = "_sysctl",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [157] = {                                                                   \
        .name = "prctl",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [158] = {                                                                   \
        .name = "arch_prctl",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [159] = {                                                                   \
        .name = "adjtimex",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [160] = {                                                                   \
        .name = "setrlimit",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [161] = {                                                                   \
        .name = "chroot",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [162] = {                                                                   \
        .name = "sync",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [163] = {                                                                   \
        .name = "acct",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [164] = {                                                                   \
        .name = "settimeofday",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [165] = {                                                                   \
        .name = "mount",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [166] = {                                                                   \
        .name = "umount2",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [167] = {                                                                   \
        .name = "swapon",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [168] = {                                                                   \
        .name = "swapoff",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [169] = {                                                                   \
        .name = "reboot",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [170] = {                                                                   \
        .name = "sethostname",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [171] = {                                                                   \
        .name = "setdomainname",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [172] = {                                                                   \
        .name = "iopl",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [173] = {                                                                   \
        .name = "ioperm",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [174] = {                                                                   \
        .name = "create_module",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [175] = {                                                                   \
        .name = "init_module",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [176] = {                                                                   \
        .name = "delete_module",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [177] = {                                                                   \
        .name = "get_kernel_syms",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [178] = {                                                                   \
        .name = "query_module",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [179] = {                                                                   \
        .name = "quotactl",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [180] = {                                                                   \
        .name = "nfsservctl",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [181] = {                                                                   \
        .name = "getpmsg",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [182] = {                                                                   \
        .name = "putpmsg",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [183] = {                                                                   \
        .name = "afs_syscall",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [184] = {                                                                   \
        .name = "tuxcall",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [185] = {                                                                   \
        .name = "security",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [186] = {                                                                   \
        .name = "gettid",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [187] = {                                                                   \
        .name = "readahead",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [188] = {                                                                   \
        .name = "setxattr",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [189] = {                                                                   \
        .name = "lsetxattr",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [190] = {                                                                   \
        .name = "fsetxattr",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [191] = {                                                                   \
        .name = "getxattr",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [192] = {                                                                   \
        .name = "lgetxattr",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [193] = {                                                                   \
        .name = "fgetxattr",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [194] = {                                                                   \
        .name = "listxattr",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [195] = {                                                                   \
        .name = "llistxattr",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [196] = {                                                                   \
        .name = "flistxattr",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [197] = {                                                                   \
        .name = "removexattr",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [198] = {                                                                   \
        .name = "lremovexattr",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [199] = {                                                                   \
        .name = "fremovexattr",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [200] = {                                                                   \
        .name = "tkill",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [201] = {                                                                   \
        .name = "time",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [202] = {                                                                   \
        .name = "futex",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [203] = {                                                                   \
        .name = "sched_setaffinity",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [204] = {                                                                   \
        .name = "sched_getaffinity",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [205] = {                                                                   \
        .name = "set_thread_area",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [206] = {                                                                   \
        .name = "io_setup",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [207] = {                                                                   \
        .name = "io_destroy",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [208] = {                                                                   \
        .name = "io_getevents",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [209] = {                                                                   \
        .name = "io_submit",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [210] = {                                                                   \
        .name = "io_cancel",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [211] = {                                                                   \
        .name = "get_thread_area",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [212] = {                                                                   \
        .name = "lookup_dcookie",                                               \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [213] = {                                                                   \
        .name = "epoll_create",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [214] = {                                                                   \
        .name = "epoll_ctl_old",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [215] = {                                                                   \
        .name = "epoll_wait_old",                                               \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [216] = {                                                                   \
        .name = "remap_file_pages",                                             \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [217] = {                                                                   \
        .name = "getdents64",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [218] = {                                                                   \
        .name = "set_tid_address",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [219] = {                                                                   \
        .name = "restart_syscall",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [220] = {                                                                   \
        .name = "semtimedop",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [221] = {                                                                   \
        .name = "fadvise64",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [222] = {                                                                   \
        .name = "timer_create",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [223] = {                                                                   \
        .name = "timer_settime",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [224] = {                                                                   \
        .name = "timer_gettime",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [225] = {                                                                   \
        .name = "timer_getoverrun",                                             \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [226] = {                                                                   \
        .name = "timer_delete",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [227] = {                                                                   \
        .name = "clock_settime",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [228] = {                                                                   \
        .name = "clock_gettime",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [229] = {                                                                   \
        .name = "clock_getres",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [230] = {                                                                   \
        .name = "clock_nanosleep",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [231] = {                                                                   \
        .name = "exit_group",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [232] = {                                                                   \
        .name = "epoll_wait",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [233] = {                                                                   \
        .name = "epoll_ctl",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [234] = {                                                                   \
        .name = "tgkill",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [235] = {                                                                   \
        .name = "utimes",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [236] = {                                                                   \
        .name = "vserver",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [237] = {                                                                   \
        .name = "mbind",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [238] = {                                                                   \
        .name = "set_mempolicy",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [239] = {                                                                   \
        .name = "get_mempolicy",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [240] = {                                                                   \
        .name = "mq_open",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [241] = {                                                                   \
        .name = "mq_unlink",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [242] = {                                                                   \
        .name = "mq_timedsend",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [243] = {                                                                   \
        .name = "mq_timedreceive",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [244] = {                                                                   \
        .name = "mq_notify",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [245] = {                                                                   \
        .name = "mq_getsetattr",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [246] = {                                                                   \
        .name = "kexec_load",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [247] = {                                                                   \
        .name = "waitid",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [248] = {                                                                   \
        .name = "add_key",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [249] = {                                                                   \
        .name = "request_key",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [250] = {                                                                   \
        .name = "keyctl",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [251] = {                                                                   \
        .name = "ioprio_set",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [252] = {                                                                   \
        .name = "ioprio_get",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [253] = {                                                                   \
        .name = "inotify_init",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [254] = {                                                                   \
        .name = "inotify_add_watch",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [255] = {                                                                   \
        .name = "inotify_rm_watch",                                             \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [256] = {                                                                   \
        .name = "migrate_pages",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [257] = {                                                                   \
        .name = "openat",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [258] = {                                                                   \
        .name = "mkdirat",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [259] = {                                                                   \
        .name = "mknodat",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [260] = {                                                                   \
        .name = "fchownat",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [261] = {                                                                   \
        .name = "futimesat",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [262] = {                                                                   \
        .name = "newfstatat",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [263] = {                                                                   \
        .name = "unlinkat",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [264] = {                                                                   \
        .name = "renameat",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [265] = {                                                                   \
        .name = "linkat",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [266] = {                                                                   \
        .name = "symlinkat",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [267] = {                                                                   \
        .name = "readlinkat",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [268] = {                                                                   \
        .name = "fchmodat",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [269] = {                                                                   \
        .name = "faccessat",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [270] = {                                                                   \
        .name = "pselect6",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [271] = {                                                                   \
        .name = "ppoll",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [272] = {                                                                   \
        .name = "unshare",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [273] = {                                                                   \
        .name = "set_robust_list",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [274] = {                                                                   \
        .name = "get_robust_list",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [275] = {                                                                   \
        .name = "splice",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [276] = {                                                                   \
        .name = "tee",                                                          \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [277] = {                                                                   \
        .name = "sync_file_range",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [278] = {                                                                   \
        .name = "vmsplice",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [279] = {                                                                   \
        .name = "move_pages",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [280] = {                                                                   \
        .name = "utimensat",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [281] = {                                                                   \
        .name = "epoll_pwait",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [282] = {                                                                   \
        .name = "signalfd",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [283] = {                                                                   \
        .name = "timerfd_create",                                               \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [284] = {                                                                   \
        .name = "eventfd",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [285] = {                                                                   \
        .name = "fallocate",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [286] = {                                                                   \
        .name = "timerfd_settime",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [287] = {                                                                   \
        .name = "timerfd_gettime",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [288] = {                                                                   \
        .name = "accept4",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [289] = {                                                                   \
        .name = "signalfd4",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [290] = {                                                                   \
        .name = "eventfd2",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [291] = {                                                                   \
        .name = "epoll_create1",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [292] = {                                                                   \
        .name = "dup3",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [293] = {                                                                   \
        .name = "pipe2",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [294] = {                                                                   \
        .name = "inotify_init1",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [295] = {                                                                   \
        .name = "preadv",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [296] = {                                                                   \
        .name = "pwritev",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [297] = {                                                                   \
        .name = "rt_tgsigqueueinfo",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [298] = {                                                                   \
        .name = "perf_event_open",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [299] = {                                                                   \
        .name = "recvmmsg",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [300] = {                                                                   \
        .name = "fanotify_init",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [301] = {                                                                   \
        .name = "fanotify_mark",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [302] = {                                                                   \
        .name = "prlimit64",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [303] = {                                                                   \
        .name = "name_to_handle_at",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [304] = {                                                                   \
        .name = "open_by_handle_at",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [305] = {                                                                   \
        .name = "clock_adjtime",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [306] = {                                                                   \
        .name = "syncfs",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [307] = {                                                                   \
        .name = "sendmmsg",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [308] = {                                                                   \
        .name = "setns",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [309] = {                                                                   \
        .name = "getcpu",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [310] = {                                                                   \
        .name = "process_vm_readv",                                             \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [311] = {                                                                   \
        .name = "process_vm_writev",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [312] = {                                                                   \
        .name = "kcmp",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [313] = {                                                                   \
        .name = "finit_module",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [314] = {                                                                   \
        .name = "sched_setattr",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [315] = {                                                                   \
        .name = "sched_getattr",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [316] = {                                                                   \
        .name = "renameat2",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [317] = {                                                                   \
        .name = "seccomp",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [318] = {                                                                   \
        .name = "getrandom",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [319] = {                                                                   \
        .name = "memfd_create",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [320] = {                                                                   \
        .name = "kexec_file_load",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [321] = {                                                                   \
        .name = "bpf",                                                          \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [322] = {                                                                   \
        .name = "execveat",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [323] = {                                                                   \
        .name = "userfaultfd",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [324] = {                                                                   \
        .name = "membarrier",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [325] = {                                                                   \
        .name = "mlock2",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [326] = {                                                                   \
        .name = "copy_file_range",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [327] = {                                                                   \
        .name = "preadv2",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [328] = {                                                                   \
        .name = "pwritev2",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [329] = {                                                                   \
        .name = "pkey_mprotect",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [330] = {                                                                   \
        .name = "pkey_alloc",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [331] = {                                                                   \
        .name = "pkey_free",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [332] = {                                                                   \
        .name = "statx",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [333] = {                                                                   \
        .name = "io_pgetevents",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [334] = {                                                                   \
        .name = "rseq",                                                         \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [424] = {                                                                   \
        .name = "pidfd_send_signal",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [425] = {                                                                   \
        .name = "io_uring_setup",                                               \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [426] = {                                                                   \
        .name = "io_uring_enter",                                               \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [427] = {                                                                   \
        .name = "io_uring_register",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [428] = {                                                                   \
        .name = "open_tree",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [429] = {                                                                   \
        .name = "move_mount",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [430] = {                                                                   \
        .name = "fsopen",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [431] = {                                                                   \
        .name = "fsconfig",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [432] = {                                                                   \
        .name = "fsmount",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [433] = {                                                                   \
        .name = "fspick",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [434] = {                                                                   \
        .name = "pidfd_open",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [435] = {                                                                   \
        .name = "clone3",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [436] = {                                                                   \
        .name = "close_range",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [437] = {                                                                   \
        .name = "openat2",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [438] = {                                                                   \
        .name = "pidfd_getfd",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [439] = {                                                                   \
        .name = "faccessat2",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [440] = {                                                                   \
        .name = "process_madvise",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [441] = {                                                                   \
        .name = "epoll_pwait2",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [442] = {                                                                   \
        .name = "mount_setattr",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [443] = {                                                                   \
        .name = "quotactl_fd",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [444] = {                                                                   \
        .name = "landlock_create_ruleset",                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [445] = {                                                                   \
        .name = "landlock_add_rule",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [446] = {                                                                   \
        .name = "landlock_restrict_self",                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [447] = {                                                                   \
        .name = "memfd_secret",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [448] = {                                                                   \
        .name = "process_mrelease",                                             \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [449] = {                                                                   \
        .name = "futex_waitv",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [450] = {                                                                   \
        .name = "set_mempolicy_home_node",                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [451] = {                                                                   \
        .name = "cachestat",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [452] = {                                                                   \
        .name = "fchmodat2",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [453] = {                                                                   \
        .name = "map_shadow_stack",                                             \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [454] = {                                                                   \
        .name = "futex_wake",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [455] = {                                                                   \
        .name = "futex_wait",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [456] = {                                                                   \
        .name = "futex_requeue",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [457] = {                                                                   \
        .name = "statmount",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [458] = {                                                                   \
        .name = "listmount",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [459] = {                                                                   \
        .name = "lsm_get_self_attr",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [460] = {                                                                   \
        .name = "lsm_set_self_attr",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [461] = {                                                                   \
        .name = "lsm_list_modules",                                             \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [462] = {                                                                   \
        .name = "mseal",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [512] = {                                                                   \
        .name = "rt_sigaction",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [513] = {                                                                   \
        .name = "rt_sigreturn",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [514] = {                                                                   \
        .name = "ioctl",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [515] = {                                                                   \
        .name = "readv",                                                        \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [516] = {                                                                   \
        .name = "writev",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [517] = {                                                                   \
        .name = "recvfrom",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [518] = {                                                                   \
        .name = "sendmsg",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [519] = {                                                                   \
        .name = "recvmsg",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [520] = {                                                                   \
        .name = "execve",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [521] = {                                                                   \
        .name = "ptrace",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [522] = {                                                                   \
        .name = "rt_sigpending",                                                \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [523] = {                                                                   \
        .name = "rt_sigtimedwait",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [524] = {                                                                   \
        .name = "rt_sigqueueinfo",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [525] = {                                                                   \
        .name = "sigaltstack",                                                  \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [526] = {                                                                   \
        .name = "timer_create",                                                 \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [527] = {                                                                   \
        .name = "mq_notify",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [528] = {                                                                   \
        .name = "kexec_load",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [529] = {                                                                   \
        .name = "waitid",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [530] = {                                                                   \
        .name = "set_robust_list",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [531] = {                                                                   \
        .name = "get_robust_list",                                              \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [532] = {                                                                   \
        .name = "vmsplice",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [533] = {                                                                   \
        .name = "move_pages",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [534] = {                                                                   \
        .name = "preadv",                                                       \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [535] = {                                                                   \
        .name = "pwritev",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [536] = {                                                                   \
        .name = "rt_tgsigqueueinfo",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [537] = {                                                                   \
        .name = "recvmmsg",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [538] = {                                                                   \
        .name = "sendmmsg",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [539] = {                                                                   \
        .name = "process_vm_readv",                                             \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [540] = {                                                                   \
        .name = "process_vm_writev",                                            \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [541] = {                                                                   \
        .name = "setsockopt",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [542] = {                                                                   \
        .name = "getsockopt",                                                   \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [543] = {                                                                   \
        .name = "io_setup",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [544] = {                                                                   \
        .name = "io_submit",                                                    \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [545] = {                                                                   \
        .name = "execveat",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [546] = {                                                                   \
        .name = "preadv2",                                                      \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    },                                                                          \
    [547] = {                                                                   \
        .name = "pwritev2",                                                     \
        .args = (syscall_arg_def[]) {                                           \
            { 0 }                                                               \
        },                                                                      \
        .ret = { 0 }                                                            \
    }                                                                           \

