#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/reg.h>
    


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

void *pmemcpy_from(pid_t pid, void *src, void *dst, size_t nbytes)
{
    for(size_t i = 0; i < nbytes; i += sizeof(void*))
    {
        ((word_t *)dst)[i / sizeof(void*)] = ptrace(PTRACE_PEEKTEXT, pid, src + i, NULL);
    }

    return dst;
}



typedef enum {
    TRACER_INIT,
    TRACER_SYSCALL_START,
    TRACER_SYSCALL_END,
    TRACER_EXEC_NOTIFY,
} tracer_state;

typedef struct {
    tracer_state state;
} tracer_context;



void handle_tracee_syscall_entry(pid_t pid, word_t syscall, tracer_context *ctx)
{
    if (1 == syscall && 1 == ptrace(PTRACE_PEEKUSER, pid, (8 * RDI)))
    {
        word_t size = ptrace(PTRACE_PEEKUSER, pid, (8 * RDX), NULL);
        char *data = malloc(size); 
        pmemcpy_from(pid, (void*)ptrace(PTRACE_PEEKUSER, pid, (8 * RSI), NULL), data, size);
        printf("Got printf with size %ld: %s\n", size, data);
    }
}

void handle_tracee_syscall_exit(pid_t pid, word_t syscall, tracer_context *ctx)
{
    (void) pid;
    (void) syscall;
    (void) ctx;
}

int handle_tracee_stop(pid_t pid, int waitpid_status, tracer_context *ctx)
{
    /* Note that there are *three* reasons why the child might stop
    * with SIGTRAP:
    *  1) syscall entry
    *  2) syscall exit
    *  3) child calls exec
    * TODO: breakpoint reached
    */
    const word_t syscall = ptrace(PTRACE_PEEKUSER, pid, (8 * ORIG_RAX), NULL);
    // const word_t syscall_ret = ptrace(PTRACE_PEEKUSER, pid, (8 * RAX), NULL);
    
    switch(ctx->state)
    {
    case TRACER_SYSCALL_START:
        // printf("Entered syscall = %ld ret = %ld\n", syscall, syscall_ret);
        ctx->state = TRACER_SYSCALL_END;

        handle_tracee_syscall_entry(pid, syscall, ctx);
        break;

    case TRACER_SYSCALL_END:
        // printf("Exited syscall = %ld ret = %ld\n", syscall, syscall_ret);
        
        // Exec will generate a notification which we need to handle
        if (59 == syscall) 
        {
            ctx->state = TRACER_EXEC_NOTIFY;
        }
        else
        {
            ctx->state = TRACER_SYSCALL_START;
        }
        
        handle_tracee_syscall_exit(pid, syscall, ctx);
        break;

    case TRACER_EXEC_NOTIFY:
        if (59 != syscall)
        {
            printf("Expected exec notification, got syscall = %ld\n", syscall);
            return -1;
        }

        ctx->state = TRACER_SYSCALL_START;
        break;

    default:
        printf("Unhandled state %d\n", ctx->state);
        return -1;
    };

    return 0;
}

int run_tracer(pid_t tracee_pid)
{
    tracer_context ctx = {
        .state = TRACER_INIT
    };

    int tracee_status;
    while (waitpid(tracee_pid, &tracee_status, 0))
    {
        if (WIFEXITED(tracee_status))
        {
            return 0;
        }
        else if (WIFSIGNALED(tracee_status))
        {
            printf("Received signal: %d\n", WTERMSIG(tracee_status));
            return -1;
        }
        else if (WIFSTOPPED(tracee_status)) 
        {
            const int stop_signal = WSTOPSIG(tracee_status);
            switch (stop_signal)
            {
            case SIGTRAP:
                if (handle_tracee_stop(tracee_pid, tracee_status, &ctx))
                {
                    return -1;
                }
                break;

            case SIGSTOP:
                if (TRACER_INIT != ctx.state)
                {
                    printf("Unexpected SIGSTOP\n");
                    return -1;
                }
                ctx.state = TRACER_SYSCALL_START;
                break;

            default: 
                printf("Unexpected stop signal: %d\n", stop_signal);
                return -1;
            }
        }
        else
        {
            printf("Unhandled trace event %d\n", tracee_status);
            return -1;
        }
        
        ptrace(PTRACE_SYSCALL, tracee_pid, NULL, 0);
    }

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
