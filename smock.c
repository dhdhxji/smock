#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/reg.h>
    
#define BIT(n) (1 << (n))
#define PTRACE_EVT(status) ((status) >> 16)
#define DIEIF(condition, message) assert(( !(condition) ) && (message))

typedef long word_t;

void dump_regs(pid_t process)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, process, NULL, &regs);
    
    printf("ORIG_RAX: %lld\n", regs.orig_rax);
    printf("RAX: %lld\n", regs.rax);
    printf("RDI: %lld\n", regs.rdi);
    printf("RSI: %lld\n", regs.rsi);
    printf("RDX: %lld\n", regs.rdx);
}

void *pmemcpy_from(pid_t pid, void *dst, const void *src, size_t nbytes)
{
    for(size_t i = 0; i < nbytes; i += sizeof(void*))
    {
        ((word_t *)dst)[i / sizeof(void*)] = ptrace(PTRACE_PEEKTEXT, pid, src + i, NULL);
    }

    return dst;
}

void *pmemcpy_to(pid_t pid, void *dst, const void *src, size_t nbytes)
{
    for(size_t i = 0; i < nbytes; i += sizeof(void*))
    {
        long ret = ptrace(PTRACE_POKETEXT, pid, dst + i, ((word_t *)src)[i / sizeof(void*)]);
    }

    return dst;
}

typedef struct {
    pid_t tracee_pid;
} tracer_context;

typedef enum {
    TRACEE_EVT_INIT                 = BIT(1),
    TRACEE_EVT_SYSCALL              = BIT(2),
    TRACEE_EVT_EXEC_NOTIFICATION    = BIT(3),
    TRACEE_EVT_SIGNALED             = BIT(4),
    TRACEE_EVT_EXITED               = BIT(5),
    TRACEE_EVT_DISAPPEARED          = BIT(6)
} tracee_event_type;

typedef struct {
    tracee_event_type type;
    union {
        int termination_signal;
        int exit_code;
    };
} tracee_event;

const char *tracee_evt_str(tracee_event_type type)
{
    switch(type)
    {
    case TRACEE_EVT_INIT:
        return "TRACEE_EVT_INIT";
    case TRACEE_EVT_SYSCALL:
        return "TRACEE_EVT_SYSCALL";
    case TRACEE_EVT_EXEC_NOTIFICATION:
        return "TRACEE_EVT_EXEC_NOTIFICATION";
    case TRACEE_EVT_SIGNALED:
        return "TRACEE_EVT_SIGNALED";
    case TRACEE_EVT_EXITED:
        return "TRACEE_EVT_EXITED";
    case TRACEE_EVT_DISAPPEARED:
        return "TRACEE_EVT_DISAPPEARED";
    default:
        return "UNKNOWN";
    };
}

int expect_tracee_evt(tracer_context *ctx, tracee_event_type event_mask, tracee_event *catched_event)
{
    int tracee_status = -1;
    int status = waitpid(ctx->tracee_pid, &tracee_status, 0);

    // DIEIF(status != ctx->tracee_pid, "waitpid() returned an error");
    if (ECHILD == status)
    {
        catched_event->type = TRACEE_EVT_DISAPPEARED;
    }
    else if (ctx->tracee_pid != status)
    {
        printf("Unhandled waitpid error %d\n", status);
        DIEIF(true, "^^");
    }
    else if (WIFEXITED(tracee_status))
    {
        catched_event->type = TRACEE_EVT_EXITED;
        catched_event->termination_signal = WEXITSTATUS(tracee_status);
    }
    else if (WIFSIGNALED(tracee_status))
    {
        catched_event->type = TRACEE_EVT_SIGNALED;
        catched_event->termination_signal = WTERMSIG(tracee_status);
    }
    else if (WIFSTOPPED(tracee_status)) 
    {
        const int stop_signal = WSTOPSIG(tracee_status) & ~BIT(7);
        switch (stop_signal) 
        {
        case SIGTRAP:
            if (PTRACE_EVT(tracee_status) == PTRACE_EVENT_EXEC) 
            {
                catched_event->type = TRACEE_EVT_EXEC_NOTIFICATION;
            }
            else if (PTRACE_EVT(tracee_status) == PTRACE_EVENT_EXIT)
            {
                catched_event->type = TRACEE_EVT_EXITED;
                ptrace(PTRACE_GETEVENTMSG, ctx->tracee_pid, NULL, &catched_event->exit_code);
            }
            else if (WSTOPSIG(tracee_status) & BIT(7))
            {
                catched_event->type = TRACEE_EVT_SYSCALL;
            }
            break;

        case SIGSTOP:
            catched_event->type = TRACEE_EVT_INIT;
            break;

        default: 
            printf("Received unhandled stop %d signal\n", stop_signal);
            DIEIF(true, "Unexpected stop signal ^");
        };
    }
    else
    {
        printf("Unhandled tracee event %d\n", tracee_status);
        DIEIF(true, "^^");
    }
    
    status = ptrace(PTRACE_SETOPTIONS, ctx->tracee_pid, NULL,
          PTRACE_O_TRACEEXEC 
        | PTRACE_O_TRACEEXIT 
        | PTRACE_O_TRACESYSGOOD
    ); 
    if (status) goto ptrace_fail;
    
    status = ptrace(PTRACE_SYSCALL, ctx->tracee_pid, NULL, 0);
    if (status) goto ptrace_fail;
    
    return (catched_event->type & event_mask) != 0 ? 0 : -1;

ptrace_fail:
    printf("ptrace returned an error %d, errno=%d\n", status, errno);
    DIEIF(true, "^^");

    return -1;
}

int expect_tracee_evt_or_exit(tracer_context *ctx, tracee_event_type event_mask, tracee_event *catched_evt)
{
    int status = expect_tracee_evt(ctx, event_mask, catched_evt);
    
    if (TRACEE_EVT_EXITED == catched_evt->type)
    {
        printf("Tracee exited with exit code %d\n", catched_evt->exit_code);
        exit(0);
    }
    else if (TRACEE_EVT_SIGNALED == catched_evt->type)
    {
        printf("Tracee has been terminated by signal %d\n", catched_evt->termination_signal);
        exit(0);
    }
    else if (TRACEE_EVT_DISAPPEARED == catched_evt->type)
    {
        printf("Tracee disappeared\n");
        exit(1);
    }
    else
    {
        return status;
    }
}

void handle_tracee_syscall_entry(pid_t pid, word_t syscall, tracer_context *ctx)
{
    if (1 == syscall && 1 == ptrace(PTRACE_PEEKUSER, pid, (8 * RDI)))
    {
        word_t size = ptrace(PTRACE_PEEKUSER, pid, (8 * RDX), NULL);

        char *local_message = malloc(size); 
        char *tracee_message_addr = (void*)ptrace(PTRACE_PEEKUSER, pid, (8 * RSI), NULL);

        pmemcpy_from(pid, local_message, tracee_message_addr, size);

        printf("Got printf with size %ld: %s\n", size, local_message);
        const char spoofed_message[16] = "spoofed ya\n";
        
        pmemcpy_to(pid, tracee_message_addr, spoofed_message, sizeof(spoofed_message));
        ptrace(PTRACE_POKEUSER, pid, (8 * RDX), sizeof(spoofed_message));
    }
}

void handle_tracee_syscall_exit(pid_t pid, word_t syscall, tracer_context *ctx)
{
    (void) ctx;

    if (1 == syscall && 1 == ptrace(PTRACE_PEEKUSER, pid, (8 * RDI)))
    {
        ptrace(PTRACE_POKEUSER, pid, (8 * RAX), 34);
    }
}

int run_tracer(pid_t tracee_pid)
{
    tracer_context ctx = {
        .tracee_pid = tracee_pid
    };

    tracee_event event;
    int status = expect_tracee_evt(&ctx, TRACEE_EVT_INIT, &event);
    if (status)
    {
        printf("Expected TRACEE_EVT_INIT, got %d\n", event.type);
        exit(1);
    }

    // Our own exec doesn't counts as a traceable/interceptable syscall
    status = expect_tracee_evt(&ctx, TRACEE_EVT_SYSCALL, &event);
    if (status)
    {
        printf("Expected exec sysall entry event, got %s\n", tracee_evt_str(event.type));
        exit(1);
    }

    status = expect_tracee_evt(&ctx, TRACEE_EVT_EXEC_NOTIFICATION, &event);
    if (status)
    {
        printf("Expected exec notification, got %s\n", tracee_evt_str(event.type));
        exit(1);
    }

    status = expect_tracee_evt(&ctx, TRACEE_EVT_SYSCALL, &event);
    if (status)
    {
        printf("Expected exec sysall exit event, got %s\n", tracee_evt_str(event.type));
        exit(1);
    }

    tracee_event_type all_event_mask = 
        TRACEE_EVT_SYSCALL;

    for(;;)
    {
        status = expect_tracee_evt_or_exit(&ctx, all_event_mask, &event);
        if (status)
        {
            // This should no happen as all of possible events should be covered in this loop
            printf("Unexpected tracee event %d\n", event.type);
            exit(1);
        }

        printf("Received tracee event %s\n", tracee_evt_str(event.type));
    }
    
    // int tracee_status;
    // while (waitpid(tracee_pid, &tracee_status, 0))
    // {
    //     
    //     ptrace(PTRACE_SYSCALL, tracee_pid, NULL, 0);
    // }

    return 0;
}

int run_tracee(const char* exec_path, char* const* args)
{
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    raise(SIGSTOP);

    return execv(exec_path, args);
}

int main()
{
    pid_t tracee_pid = fork();

    if (tracee_pid == 0)
    {
        return run_tracee(
            // "/usr/bin/cat",
            // (char*[]){
            //     "cat",
            //     "bnrun.sh",
            //     NULL
            // }
            "./test",
            NULL
        );
    }
    else
    {
        return run_tracer(tracee_pid);
    }

    return 0;
}
