#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>

#define SMOCK_IMPLEMENTATION
#include "../smock.h"

const char spoofed_message[16] = "Spoofed ya!\n";

void example_handle_write_entry(pid_t pid, int syscall)
{
    // Intercept stdout write
    regs_t regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (1 == SYSCALL_ARG0(regs))
    {
        word_t size = SYSCALL_ARG2(regs);

        char *local_message = malloc(size); 
        char *tracee_message_addr = (void*)SYSCALL_ARG1(regs);

        smock_memcpy_from(pid, local_message, tracee_message_addr, size);

        printf("tracer: Got printf with size %lld: %s\n", size, local_message);
        
        smock_memcpy_to(pid, tracee_message_addr, spoofed_message, sizeof(spoofed_message));
        SYSCALL_ARG2(regs) = (word_t)sizeof(spoofed_message);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    }
}

void example_handle_write_exit(pid_t pid, int syscall)
{
    regs_t regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (1 == SYSCALL_ARG0(regs))
    {
        SYSCALL_RET(regs) = 34;
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    }
    smock_dump_syscall(pid, false);
}



int main()
{
    struct smock_context *ctx = smock_child_process("./test", NULL);

    // Example with write(=1) syscall spoofing
    smock_set_syscall_handler(ctx, 1, (smock_syscall_hook){
        .entered = example_handle_write_entry,
        .exited = example_handle_write_exit
    });

    return smock_run(ctx);
}
