#ifndef WW_PROC_H_
#define WW_PROC_H_

#include "wlibc.h"

typedef struct proc_ctx_s
{
    pid_t       pid; // tid in Windows
    time_t      start_time;
    int         spawn_cnt;
    procedure_t init;
    void       *init_userdata;
    procedure_t proc;
    void       *proc_userdata;
    procedure_t exit;
    void       *exit_userdata;
} proc_ctx_t;

static inline void procRun(proc_ctx_t *ctx)
{
    if (ctx->init)
    {
        ctx->init(ctx->init_userdata);
    }
    if (ctx->proc)
    {
        ctx->proc(ctx->proc_userdata);
    }
    if (ctx->exit)
    {
        ctx->exit(ctx->exit_userdata);
    }
}

#ifdef OS_UNIX
// unix use multi-processes
static inline int procSpawn(proc_ctx_t *ctx)
{
    ++ctx->spawn_cnt;
    ctx->start_time = time(NULL);
    pid_t pid       = fork();
    if (pid < 0)
    {
        printError("fork");
        return -1;
    }
    else if (pid == 0)
    {
        // child process
        ctx->pid = getpid();
        procRun(ctx);
        exit(0);
    }
    else if (pid > 0)
    {
        // parent process
        ctx->pid = pid;
    }
    return pid;
}
#elif defined(OS_WIN)
// win32 use multi-threads
static void win_thread(void *userdata)
{
    proc_ctx_t *ctx = (proc_ctx_t *) userdata;
    ctx->pid        = GetCurrentThreadId(); // tid in Windows
    procRun(ctx);
}
static inline int procSpawn(proc_ctx_t *ctx)
{
    ++ctx->spawn_cnt;
    ctx->start_time = time(NULL);
    HANDLE h        = (HANDLE) _beginthread(win_thread, 0, ctx);
    if (h == NULL)
    {
        return -1;
    }
    ctx->pid = GetThreadId(h); // tid in Windows
    return ctx->pid;
}
#endif

typedef struct
{
    char output[2048]; // if you modify this, update the coed below (fscanf)
    int  exit_code;
} cmd_result_t;

// blocking io
static cmd_result_t execCmd(const char *str)
{
    FILE        *fp;
    cmd_result_t result = (cmd_result_t){{0}, -1};
    char        *buf    = &(result.output[0]);
    /* Open the command for reading. */
#if defined(OS_UNIX)
    fp = popen(str, "r");
#else
    fp               = _popen(str, "r");
#endif

    if (fp == NULL)
    {
        printf("Failed to run command \"%s\"\n", str);
        return (cmd_result_t){{0}, -1};
    }

    int read = fscanf(fp, "%2047s", buf);
    (void) read;
#if defined(OS_UNIX)
    result.exit_code = pclose(fp);
#else
    result.exit_code = _pclose(fp);
#endif

    return result;
    /* close */
    // return 0 == pclose(fp);
}

static bool checkCommandAvailable(const char *app)
{
    char b[300];
    sprintf(b, "command -v %288s", app);
    cmd_result_t result = execCmd(b);
    return (result.exit_code == 0 && strlen(result.output) > 0);
}

/**
* @brief Attempts to elevate the privileges of the current process.
*
* @param app_name The executable name of the application.
* @param fail_msg The error message to display if elevation fails.
* @return bool true on success, false otherwise.
*/
bool windowsElevatePrivileges(const char *app_name, char *fail_msg);

bool isAdmin(void);

#endif // WW_PROC_H_
