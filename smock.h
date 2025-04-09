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
word_t smock_memcpy_to(pid_t pid, word_t tracee_dst_addr, const void *src, size_t nbytes);
void* smock_memcpy_from(pid_t pid, void *dst, word_t tracee_src_addr, size_t nbytes);
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

#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"

#define BIT(n) (1 << (n))
#define PTRACE_EVT(status) ((status) >> 16)
#define DIEIF(condition, message) assert(( !(condition) ) && (message))

#ifdef SMOCK_DEBUG
#define DBGMSG(...) printf(__VA_ARGS__)
#else
#define DBGMSG(...)
#endif

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
    TRACEE_EVT_EXITING              = BIT(5),
    TRACEE_EVT_EXITED               = BIT(6),
    TRACEE_EVT_DISAPPEARED          = BIT(7),
    TRACEE_EVT_NEW_THREAD           = BIT(8),
    TRACEE_EVT_ALL                  = (TRACEE_EVT_NEW_THREAD << 1) - 1
} tracee_event_type;

typedef struct {
    tracee_event_type type;
    union {
        word_t termination_signal;
        word_t exit_code;
        pid_t pid;
    };
} tracee_event;

typedef struct {
    smock_syscall_hook syscall_hooks[SYSCALL_NR_MAX + 1];
} tracer_config;

typedef enum {
    STATE_IDLE,
    STATE_ENTERED_SYSCALL
} tracee_state_type;

typedef struct {
    tracee_state_type state;
    union {
        int syscall_nr;
    };
} tracee_ctx;

typedef struct {
    pid_t key;
    tracee_ctx value;
} tracee_ctx_map;

struct smock_context{
    pid_t tracee_pid;
    size_t num_active_threads;
    tracer_config cfg;

    tracee_ctx_map *tracee_ctxs;
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
    
    printf("(%d): syscall %s %s(%d)\n", process, is_entry ? "entry" : "exit", syscall->name, syscall_nr);
    
    const syscall_arg_def zero_arg = { 0 };
    // TODO: fix syscall definitions to include zero-terminated arg
    // for (int i = 0; memcmp(&zero_arg, &syscall->args[i], sizeof(zero_arg)); ++i)
    // {
    //     const syscall_arg_def *arg = &syscall->args[i];
    //     word_t raw_value = get_syscall_arg_raw_value(&regs, i);
  
    //     if (SYSCALL_ARG_FLAG_ARRAY & arg->flags)
    //     {
    //         const word_t size = get_syscall_arg_raw_value(&regs, arg->array_size_arg);
    //         printf("  %d: %p: Array of size %llu\n", i, (void*)raw_value, size);
    //     }
    //     else if (SYSCALL_ARG_FLAG_POINTER & arg->flags)
    //     {
    //         printf("  %d: %lld: Pointer\n", i, raw_value);
    //     }
    //     else
    //     {
    //         //printf("  %d: %lld: Primitive value (probably)\n", i, raw_value);
    //         printf("  %d: ", i); 
    //         print_syscall_arg_value(arg->type, raw_value);
    //         printf("\n");
    //     }
    // }
    
    if (!is_entry) printf("  ret: %lld\n", SYSCALL_RET(regs));
}

void *smock_memcpy_from(pid_t pid, void *dst, word_t tracee_src_addr, size_t nbytes)
{
    const word_t complete_word_count = nbytes / sizeof(word_t);
    for (int word = 0; word < complete_word_count; word++)
    {
        const word_t offset = word * sizeof(word_t);
        char *dst_word = (char*)dst + offset;
        *(word_t*)dst_word = ptrace(PTRACE_PEEKTEXT, pid, tracee_src_addr + offset, NULL);
    }

    if (nbytes % sizeof(word_t) != 0)
    {
        const word_t offset = nbytes - sizeof(word_t);
        const word_t bytes_left = nbytes - offset;
        word_t last_word = ptrace(PTRACE_PEEKTEXT, pid,  tracee_src_addr + offset);
        memcpy((char*)dst + offset, &last_word, bytes_left);
    }

    return dst;
}

word_t smock_memcpy_to(pid_t pid, word_t tracee_dst_addr, const void *src, size_t nbytes)
{
    const word_t complete_word_count = nbytes / sizeof(word_t);
    for (int word = 0; word < complete_word_count; word++)
    {
        const word_t offset = word * sizeof(word_t);
        char *src_word = (char*)src + offset;
        ptrace(PTRACE_POKETEXT, pid, tracee_dst_addr + offset, *(word_t*)src_word);
    }

    if (nbytes % sizeof(word_t) != 0)
    {
        const word_t offset = nbytes - sizeof(word_t);
        const word_t bytes_left = nbytes - offset;
        word_t last_word = ptrace(PTRACE_PEEKTEXT, pid,  tracee_dst_addr + offset);
        memcpy(&last_word, (char*)src + offset, bytes_left);
        ptrace(PTRACE_POKETEXT, pid, tracee_dst_addr + offset, last_word);
    }

    return tracee_dst_addr;
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
    case TRACEE_EVT_EXITING:
        return "TRACEE_EVT_EXITING";
    case TRACEE_EVT_EXITED:
        return "TRACEE_EVT_EXITED";
    case TRACEE_EVT_DISAPPEARED:
        return "TRACEE_EVT_DISAPPEARED";
    case TRACEE_EVT_NEW_THREAD:
        return "TRACEE_EVT_NEW_THREAD";	
    default:
        return "UNKNOWN";
    };
}

int set_tracing_traps(pid_t pid)
{
    int status = ptrace(PTRACE_SETOPTIONS, pid, NULL,
          PTRACE_O_TRACEEXEC 
        | PTRACE_O_TRACEEXIT 
        | PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACECLONE
    ); 
    if (status) goto ptrace_fail;
    
    status = ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
    if (status) goto ptrace_fail;

    return status;

ptrace_fail:
    printf("(%d) ptrace returned an error %d, errno=%d\n", pid, status, errno);
    DIEIF(true, "^^");

    return -1;
}

int expect_tracee_evt(struct smock_context *ctx, pid_t pid, tracee_event_type event_mask, tracee_event *catched_event)
{
    int tracee_status = -1;
    int producer_pid = waitpid(pid, &tracee_status, 0);

    if (ECHILD == producer_pid)
    {
        catched_event->type = TRACEE_EVT_DISAPPEARED;
    }
    else if ((pid != producer_pid) && (pid != -1))
    {
        printf("Unhandled waitpid error %d\n", producer_pid);
        DIEIF(true, "^^");
    }
    else if (WIFEXITED(tracee_status))
    {
        catched_event->type = TRACEE_EVT_EXITED;
        catched_event->exit_code = WEXITSTATUS(tracee_status);
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
                catched_event->type = TRACEE_EVT_EXITING;
                ptrace(PTRACE_GETEVENTMSG, producer_pid, NULL, &catched_event->exit_code);
            }
            else if (PTRACE_EVT(tracee_status) == PTRACE_EVENT_CLONE)
            {
                word_t new_thread_pid = -1;
                ptrace(PTRACE_GETEVENTMSG, producer_pid, NULL, &new_thread_pid);
                catched_event->type = TRACEE_EVT_NEW_THREAD;
                catched_event->pid = new_thread_pid;
            }
            else if (WSTOPSIG(tracee_status) & BIT(7))
            {
                catched_event->type = TRACEE_EVT_SYSCALL;
            }
            else 
            {
                printf("Got unexpected SIGTRAP evt: %x\n", stop_signal);
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
    

    if (catched_event->type & event_mask == 0)
    {
        printf("Critical: Expectected one of following events:\n");
        for (tracee_event_type event = 1; event < TRACEE_EVT_ALL; event <<= 1)
        {
            if (event & event_mask) printf(" - %s\n", tracee_evt_str(event));
        }
        printf("Got: %s\n", tracee_evt_str(catched_event->type));
        exit(1);
    }

    return producer_pid;
}

void handle_tracee_new_thread_evt(struct smock_context *ctx, pid_t parent, pid_t pid)
{
    DBGMSG("(%d): Started\n", pid);
    ctx->num_active_threads++;

    tracee_ctx tracee_ctx = {
        .state = STATE_IDLE
    };

    hmput(ctx->tracee_ctxs, pid, tracee_ctx);
}

void handle_tracee_syscall_evt(struct smock_context *ctx, pid_t pid)
{
    regs_t regs = {}; 
    int status = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    const word_t syscall = SYSCALL_NR(regs);

    if (syscall < 0 || syscall > SYSCALL_NR_MAX)
    {
        printf("Invaliid syscall number %lld, there is nothing we can do in this hopeless situation...\n", syscall);
        DIEIF(true, "^^");
    }

    const smock_syscall_hook *hook = &ctx->cfg.syscall_hooks[syscall];

    tracee_ctx *tracee_ctx = &(hmgetp(ctx->tracee_ctxs, pid)->value);
    if (tracee_ctx->state == STATE_IDLE)
    {
#ifdef SMOCK_DEBUG
        smock_dump_syscall(pid, true);
#endif

        tracee_ctx->state = STATE_ENTERED_SYSCALL;
        tracee_ctx->syscall_nr = syscall;

        if (hook->entered) hook->entered(pid, syscall);
    }
    else if (tracee_ctx->state == STATE_ENTERED_SYSCALL)
    {
#ifdef SMOCK_DEBUG
        smock_dump_syscall(pid, false);
#endif

        tracee_ctx->state = STATE_IDLE;

        if (hook->exited) hook->exited(pid, syscall);
    }
    else
    {
        printf("Unknown state %d\n", (int)tracee_ctx->state);
        exit(1);
    }
}

int smock_run(struct smock_context *ctx)
{
    tracee_event event;
    expect_tracee_evt(ctx, ctx->tracee_pid, TRACEE_EVT_INIT, &event);

    // Our own exec doesn't counts as a traceable/interceptable syscall
    int status = set_tracing_traps(ctx->tracee_pid);
    if (status) goto set_traps_error;

    expect_tracee_evt(ctx, ctx->tracee_pid, TRACEE_EVT_SYSCALL, &event);

    status = set_tracing_traps(ctx->tracee_pid);
    if (status) goto set_traps_error;

    expect_tracee_evt(ctx, ctx->tracee_pid, TRACEE_EVT_EXEC_NOTIFICATION, &event);

    status = set_tracing_traps(ctx->tracee_pid);
    if (status) goto set_traps_error;

    expect_tracee_evt(ctx, ctx->tracee_pid, TRACEE_EVT_SYSCALL, &event);

    status = set_tracing_traps(ctx->tracee_pid);
    if (status) goto set_traps_error;

    while (ctx->num_active_threads != 0)
    {
        pid_t pid = expect_tracee_evt(ctx, -1, TRACEE_EVT_ALL, &event);
        DBGMSG("(%d): Event %s\n", pid, tracee_evt_str(event.type));

        switch(event.type)
        {
        case TRACEE_EVT_SYSCALL:
            handle_tracee_syscall_evt(ctx, pid);
            break;

        case TRACEE_EVT_NEW_THREAD:
            handle_tracee_new_thread_evt(ctx, pid, event.pid);
            break;

        case TRACEE_EVT_INIT:
        case TRACEE_EVT_EXEC_NOTIFICATION:
        case TRACEE_EVT_EXITING:
            //TODO
            break;

        case TRACEE_EVT_SIGNALED:
        case TRACEE_EVT_EXITED:
        case TRACEE_EVT_DISAPPEARED:
            ctx->num_active_threads--;
            DBGMSG("(%d) exited with code %lld\n", pid, event.exit_code);
            continue;
        };

        set_tracing_traps(pid);
    }

    return 0;

set_traps_error:
    printf("Unable to set up child traps with error: %d\n", status);
    exit(-1);
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
        ctx->num_active_threads = 1;
        tracee_ctx tracee_ctx = {
            .state = STATE_IDLE,
        };
        hmput(ctx->tracee_ctxs, tracee_pid, tracee_ctx);
        return ctx;
    }

    return ctx;
}

int smock_set_syscall_handler(struct smock_context *ctx, int syscall_nr, smock_syscall_hook hook)
{
    if (syscall_nr >= SYSCALL_NR_MAX || syscall_nr < 0)
    {
        return -1;
    }

    ctx->cfg.syscall_hooks[syscall_nr] = hook;

    return 0;
}

#endif  // SMOCK_IMPLEMENTATION
