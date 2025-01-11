#ifndef WW_PROC_H_
#define WW_PROC_H_

#include "wplatform.h"

typedef struct proc_ctx_s {
    pid_t           pid; // tid in Windows
    time_t          start_time;
    int             spawn_cnt;
    procedure_t     init;
    void*           init_userdata;
    procedure_t     proc;
    void*           proc_userdata;
    procedure_t     exit;
    void*           exit_userdata;
} proc_ctx_t;

static inline void procRun(proc_ctx_t* ctx) {
    if (ctx->init) {
        ctx->init(ctx->init_userdata);
    }
    if (ctx->proc) {
        ctx->proc(ctx->proc_userdata);
    }
    if (ctx->exit) {
        ctx->exit(ctx->exit_userdata);
    }
}

#ifdef OS_UNIX
// unix use multi-processes
static inline int procSpawn(proc_ctx_t* ctx) {
    ++ctx->spawn_cnt;
    ctx->start_time = time(NULL);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    } else if (pid == 0) {
        // child process
        ctx->pid = getpid();
        procRun(ctx);
        exit(0);
    } else if (pid > 0) {
        // parent process
        ctx->pid = pid;
    }
    return pid;
}
#elif defined(OS_WIN)
// win32 use multi-threads
static void win_thread(void* userdata) {
    proc_ctx_t* ctx = (proc_ctx_t*)userdata;
    ctx->pid = GetCurrentThreadId(); // tid in Windows
    procRun(ctx);
}
static inline int procSpawn(proc_ctx_t* ctx) {
    ++ctx->spawn_cnt;
    ctx->start_time = time(NULL);
    HANDLE h = (HANDLE)_beginthread(win_thread, 0, ctx);
    if (h == NULL) {
        return -1;
    }
    ctx->pid = GetThreadId(h); // tid in Windows
    return ctx->pid;
}
#endif

#endif // WW_PROC_H_
