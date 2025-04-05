#ifndef SMOCK_H
#define SMOCK_H

#include <unistd.h>

#include "arch/arch.h"
#define SYSCALL_NR(regs) SMOCK_ARCH_SYSCALL_NR(regs)
#define SYSCALL_RET(egs) SMOCK_ARCH_SYSCALL_RET(regs)
#define SYSCALL_ARG0(regs) SMOCK_ARCH_SYSCALL_ARG0(regs)
#define SYSCALL_ARG1(regs) SMOCK_ARCH_SYSCALL_ARG1(regs)
#define SYSCALL_ARG2(regs) SMOCK_ARCH_SYSCALL_ARG2(regs)
#define SYSCALL_ARG3(regs) SMOCK_ARCH_SYSCALL_ARG3(regs)
#define SYSCALL_ARG4(regs) SMOCK_ARCH_SYSCALL_ARG4(regs)
#define SYSCALL_ARG5(regs) SMOCK_ARCH_SYSCALL_ARG5(regs)

typedef smock_arch_word_t word_t;
typedef smock_arch_regs_t regs_t;

typedef struct {
    void (*entered)(pid_t pid, int syscall);
    void (*exited)(pid_t pid, int syscall);
} smock_syscall_hook;

struct smock_context;

struct smock_context* smock_child_process(char const *executable, char *const *args);
int smock_set_syscall_handler(struct smock_context *ctx, int syscall_nr, smock_syscall_hook hook);
void* smock_memcpy_to(pid_t pid, void *dst, const void *src, size_t nbytes);
void* smock_memcpy_from(pid_t pid, void *dst, const void *src, size_t nbytes);
void smock_dump_syscall(pid_t process, bool is_entry);
int smock_run(struct smock_context *ctx);

#endif  // SMOCK_H



#ifdef SMOCK_IMPLEMENTATION

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <string.h>

#define BIT(n) (1 << (n))
#define PTRACE_EVT(status) ((status) >> 16)
#define DIEIF(condition, message) assert(( !(condition) ) && (message))


typedef enum {
    SYSCALL_ARG_TYPE_SWORD,
    SYSCALL_ARG_TYPE_UWORD,
    SYSCALL_ARG_TYPE_BYTE,
    // TODO: structs
} syscall_arg_type;

typedef enum {
    SYSCALL_ARG_FLAG_POINTER    = BIT(0),
    SYSCALL_ARG_FLAG_ARRAY      = BIT(1)
} syscall_arg_flags;

typedef struct {
    char const *name;
    syscall_arg_type type;
    syscall_arg_flags flags;
    union {
        int array_size_arg;
        // TODO: struct defs
    };
} syscall_arg_def;

typedef struct {
    char const *name;
    syscall_arg_def *args;
    syscall_arg_def ret;
} syscall_def;

// TODO: This table should contain meta info
//       about syscalls, including human-readable names,
//       info about its parameters and structs which will
//       be user later for convinient lua API (or not), basically
//       to call user defined syscall handlers with syscall parameters
//       represented by lua tables.
//       In any case, I should revisit this table on later stages of development.
static const syscall_def syscall_table[] = {
    SMOCK_ARCH_SYSCALL_TABLE
};
#define SYSCALL_NR_MAX ((sizeof(syscall_table) / sizeof(syscall_def)) - 1)



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

typedef struct {
    smock_syscall_hook syscall_hooks[SYSCALL_NR_MAX + 1];
} tracer_config;

struct smock_context{
    pid_t tracee_pid;
    tracer_config cfg;
};

void print_syscall_arg_value(syscall_arg_type type, word_t value)
{
    switch(type)
    {
    case SYSCALL_ARG_TYPE_SWORD:
        printf("%lld", value);
        break;

    case SYSCALL_ARG_TYPE_UWORD:
        printf("%llu", value);
        break;

    case SYSCALL_ARG_TYPE_BYTE:
        printf("%X", (char)value);
        break;

    default:
        // Fallback to signed word...
        printf("%lld", value);
    }
}

static inline word_t get_syscall_arg_raw_value(regs_t *regs, int number)
{
    switch(number)
    {
    case 0:
        return SYSCALL_ARG0(*regs);

    case 1:
        return SYSCALL_ARG1(*regs);

    case 2:
        return SYSCALL_ARG2(*regs);

    case 3:
        return SYSCALL_ARG3(*regs);

    case 4:
        return SYSCALL_ARG4(*regs);

    case 5:
        return SYSCALL_ARG5(*regs);

    default:
        printf("Invalid syscall arg number %d\n", number);
        DIEIF(true, "^^");
    }
    return -1;
}

void smock_dump_syscall(pid_t process, bool is_entry)
{
    regs_t regs;
    ptrace(PTRACE_GETREGS, process, NULL, &regs);

    int syscall_nr = SYSCALL_NR(regs);
    if (syscall_nr < 0 || syscall_nr > SYSCALL_NR_MAX)
    {
        printf("Invalid syscall number %d\n", syscall_nr);
        return;
    }

    const syscall_def *syscall = &syscall_table[syscall_nr];
    
    printf("syscall %s %s(%d)\n", is_entry ? "entry" : "exit", syscall->name, syscall_nr);
    
    const syscall_arg_def zero_arg = { 0 };
    for (int i = 0; memcmp(&zero_arg, &syscall->args[i], sizeof(zero_arg)); ++i)
    {
        const syscall_arg_def *arg = &syscall->args[i];
        word_t raw_value = get_syscall_arg_raw_value(&regs, i);
  
        if (SYSCALL_ARG_FLAG_ARRAY & arg->flags)
        {
            const word_t size = get_syscall_arg_raw_value(&regs, arg->array_size_arg);
            printf("  %d: %p: Array of size %llu\n", i, (void*)raw_value, size);
        }
        else if (SYSCALL_ARG_FLAG_POINTER & arg->flags)
        {
            printf("  %d: %lld: Pointer\n", i, raw_value);
        }
        else
        {
            //printf("  %d: %lld: Primitive value (probably)\n", i, raw_value);
            printf("  %d: ", i); 
            print_syscall_arg_value(arg->type, raw_value);
            printf("\n");
        }
    }
    
    if (!is_entry) printf("  ret: %lld\n", SYSCALL_RET(regs));
}

void *smock_memcpy_from(pid_t pid, void *dst, const void *src, size_t nbytes)
{
    for(size_t i = 0; i < nbytes; i += sizeof(void*))
    {
        ((word_t *)dst)[i / sizeof(void*)] = ptrace(PTRACE_PEEKTEXT, pid, src + i, NULL);
    }

    return dst;
}

void *smock_memcpy_to(pid_t pid, void *dst, const void *src, size_t nbytes)
{
    for(size_t i = 0; i < nbytes; i += sizeof(void*))
    {
        long ret = ptrace(PTRACE_POKETEXT, pid, dst + i, ((word_t *)src)[i / sizeof(void*)]);
    }

    return dst;
}

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

int set_tracing_traps(struct smock_context *ctx)
{
    int status = ptrace(PTRACE_SETOPTIONS, ctx->tracee_pid, NULL,
          PTRACE_O_TRACEEXEC 
        | PTRACE_O_TRACEEXIT 
        | PTRACE_O_TRACESYSGOOD
    ); 
    if (status) goto ptrace_fail;
    
    status = ptrace(PTRACE_SYSCALL, ctx->tracee_pid, NULL, 0);
    if (status) goto ptrace_fail;

    return status;

ptrace_fail:
    printf("ptrace returned an error %d, errno=%d\n", status, errno);
    DIEIF(true, "^^");

    return -1;
}

int expect_tracee_evt(struct smock_context *ctx, tracee_event_type event_mask, tracee_event *catched_event)
{
    int tracee_status = -1;
    int status = set_tracing_traps(ctx);
    if (status)
    {
        printf("Failed to set tracing traps %d\n", status);
        return -1;
    }

    status = waitpid(ctx->tracee_pid, &tracee_status, 0);

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
    
    return (catched_event->type & event_mask) != 0 ? 0 : -1;
}

int expect_tracee_evt_or_exit(struct smock_context *ctx, tracee_event_type event_mask, tracee_event *catched_evt)
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

void handle_tracee_syscall_evt(struct smock_context *ctx)
{
    const word_t syscall = ptrace(PTRACE_PEEKUSER, ctx->tracee_pid, (8 * ORIG_RAX), NULL);
    if (syscall < 0 || syscall > SYSCALL_NR_MAX)
    {
        printf("Invaliid syscall number %lld, there is nothing we can do in this hopeless situation...\n", syscall);
        DIEIF(true, "^^");
    }

    const smock_syscall_hook *hook = &ctx->cfg.syscall_hooks[syscall];
    if (hook->entered)
    {
        hook->entered(ctx->tracee_pid, syscall);
    }

    tracee_event event;
    int status = expect_tracee_evt(
        ctx,
        TRACEE_EVT_SYSCALL | TRACEE_EVT_EXEC_NOTIFICATION | TRACEE_EVT_EXITED,
        &event);

    if (status)
    {
        printf("Expected syscall end event, exec notification or exit event got %s\n", tracee_evt_str(event.type));
        DIEIF(true, "^^");
    }

    if (TRACEE_EVT_EXEC_NOTIFICATION == event.type)
    {
        status = expect_tracee_evt(ctx, TRACEE_EVT_SYSCALL, &event);
        if (status)
        {
            printf("Expected syscall end event, got %s\n", tracee_evt_str(event.type));
            DIEIF(true, "^^");
        }
    }
    else if (TRACEE_EVT_EXITED == event.type)
    {
        printf("Tracee exited by exit(%d) syscall\n", event.exit_code);
        exit(0);
    }

    if (hook->exited)
    {
        hook->exited(ctx->tracee_pid, syscall);
    }
}

int smock_run(struct smock_context *ctx)
{
    int wait_status;
    waitpid(ctx->tracee_pid, &wait_status, 0);
    DIEIF(!WIFSTOPPED(wait_status) || WSTOPSIG(wait_status) != SIGSTOP, "Expected SIGSTOP");

    // Our own exec doesn't counts as a traceable/interceptable syscall
    tracee_event event;
    int status = expect_tracee_evt(ctx, TRACEE_EVT_SYSCALL, &event);
    if (status)
    {
        printf("Expected exec sysall entry event, got %s\n", tracee_evt_str(event.type));
        exit(1);
    }

    status = expect_tracee_evt(ctx, TRACEE_EVT_EXEC_NOTIFICATION, &event);
    if (status)
    {
        printf("Expected exec notification, got %s\n", tracee_evt_str(event.type));
        exit(1);
    }

    status = expect_tracee_evt(ctx, TRACEE_EVT_SYSCALL, &event);
    if (status)
    {
        printf("Expected exec sysall exit event, got %s\n", tracee_evt_str(event.type));
        exit(1);
    }

    tracee_event_type all_event_mask = 
        TRACEE_EVT_SYSCALL;

    for(;;)
    {
        status = expect_tracee_evt_or_exit(ctx, all_event_mask, &event);
        if (status)
        {
            // This should no happen as all of possible events should be covered in this loop
            printf("Unexpected tracee event %d\n", event.type);
            exit(1);
        }

        switch(event.type)
        {
        case TRACEE_EVT_SYSCALL:
            handle_tracee_syscall_evt(ctx);
            break;
        default:
            printf("Received tracee event %s\n", tracee_evt_str(event.type));
        };
    }

    return 0;
}

int run_tracee(const char* exec_path, char* const* args)
{
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    raise(SIGSTOP);

    return execv(exec_path, args);
}

struct smock_context* smock_child_process(char const *executable, char *const *args)
{
    struct smock_context *ctx = malloc(sizeof(struct smock_context));
    memset(ctx, sizeof(struct smock_context), 0);

    pid_t tracee_pid = fork();
    
    if (tracee_pid == 0)
    {
        run_tracee(
            executable,
            args
        );

        // This function will return only in case execv fails
        return NULL;
    }
    else
    {
        ctx->tracee_pid = tracee_pid;
        return ctx;
    }
}

int smock_set_syscall_handler(struct smock_context *ctx, int syscall_nr, smock_syscall_hook hook)
{
    if (syscall_nr >= SYSCALL_NR_MAX)
    {
        return -1;
    }

    ctx->cfg.syscall_hooks[syscall_nr] = hook;

    return 0;
}

#endif  // SMOCK_IMPLEMENTATION
