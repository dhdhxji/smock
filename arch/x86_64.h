#include <sys/user.h>

#define SMOCK_ARCH_SYSCALL_NR(regs) (regs).orig_rax
#define SMOCK_ARCH_SYSCALL_RET(egs) (regs).rax
#define SMOCK_ARCH_SYSCALL_ARG0(regs) (regs).rdi
#define SMOCK_ARCH_SYSCALL_ARG1(regs) (regs).rsi
#define SMOCK_ARCH_SYSCALL_ARG2(regs) (regs).rdx
#define SMOCK_ARCH_SYSCALL_ARG3(regs) (regs).r10
#define SMOCK_ARCH_SYSCALL_ARG4(regs) (regs).r8
#define SMOCK_ARCH_SYSCALL_ARG5(regs) (regs).r9

typedef long long int smock_arch_word_t;
typedef struct user_regs_struct smock_arch_regs_t;

#include "x86_64_table.h"

