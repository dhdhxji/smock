#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>

#define SMOCK_IMPLEMENTATION
#include "../smock.h"

const char spoofed_message[] = "Spoofed ya!\n";

typedef struct {
    char *message;
    word_t length;
} sniffed_message;

typedef struct {
    pid_t key;
    sniffed_message value;
} sniffed_message_map;

sniffed_message_map *sniffed_messages = NULL;

void example_handle_write_entry(pid_t pid, int syscall)
{
    (void) syscall;

    regs_t regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (1 == SYSCALL_ARG0(regs))
    {
        const word_t size = SYSCALL_ARG2(regs);
        const word_t tracee_message_addr = SYSCALL_ARG1(regs);

        char *original_message = malloc(size); 
        smock_memcpy_from(pid, original_message, tracee_message_addr, size);
        printf("original message of size %lld from %d: %s", size, pid, original_message);

        sniffed_message msg = {original_message, size};
        hmput(sniffed_messages, pid, msg);

        smock_memcpy_to(pid, tracee_message_addr, spoofed_message, sizeof(spoofed_message));
        SYSCALL_ARG2(regs) = (word_t)sizeof(spoofed_message);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    }
}

void example_handle_write_exit(pid_t pid, int syscall)
{
    (void) syscall;
    regs_t regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    if (1 == SYSCALL_ARG0(regs))
    {
        word_t tracee_message_addr = SYSCALL_ARG1(regs);
        sniffed_message msg = hmgetp_null(sniffed_messages, pid)->value;

        smock_memcpy_to(pid, tracee_message_addr, msg.message, msg.length);
        SYSCALL_RET(regs) = msg.length;
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);

        free(msg.message);
        (void)hmdel(sniffed_messages, pid);
    }
}



int main(int argc, char const **argv)
{
    if (argc != 2)
    {
        printf("Usage: %s (executable)\n", argv[0]);
        return -1;
    }

    struct smock_context *ctx = smock_child_process(argv[1], NULL);

    // Example with write(=1) syscall spoofing
    smock_set_syscall_handler(ctx, 1, (smock_syscall_hook){
        .entered = example_handle_write_entry,
        .exited = example_handle_write_exit
    });

    return smock_run(ctx);
}

