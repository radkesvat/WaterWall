#ifndef WW_THREAD_H_
#define WW_THREAD_H_

#include "wlibc.h"

typedef long tid_t;

#if defined(OS_WIN) && ! HAVE_SYS_TYPES_H
typedef int pid_t;
#endif

#ifdef OS_WIN
#define getProcessID (pid_t) GetCurrentProcessId
#else
#define getProcessID (pid_t) getpid
#endif

#if defined(OS_WIN)
#define getTID (tid_t) GetCurrentThreadId
#elif HAVE_GETTID || defined(OS_ANDROID)
#define getTID (tid_t) gettid
#elif defined(OS_LINUX)
#include <sys/syscall.h>
#define getTID(void) (tid_t) syscall(SYS_gettid)
#elif defined(OS_DARWIN)
static inline tid_t getTID(void)
{
    uint64_t tid = 0;
    pthread_threadid_np(NULL, &tid);
    return (tid_t) tid;
}
#elif HAVE_PTHREAD_H
#define getTID (tid_t) pthread_self
#else
#define getTID getProcessID
#endif

/*
#include "wthread.h"

WTHREAD_ROUTINE(thread_demo) {
    printf("thread[%ld] start\n", getTID());
    ww_delay(3000);
    printf("thread[%ld] end\n", getTID());
    return 0;
}

int main() {
    wthread_t th = threadCreate(thread_demo, NULL);
    threadJoin(th);
    return 0;
}
 */

#ifdef OS_WIN
typedef HANDLE wthread_t;
typedef DWORD(WINAPI *wthread_routine)(void *);
#define HTHREAD_RETTYPE        DWORD
#define WTHREAD_ROUTINE(fname) DWORD WINAPI fname(void *userdata)
static inline wthread_t threadCreate(wthread_routine fn, void *userdata)
{
    return CreateThread(NULL, 0, fn, userdata, 0, NULL);
}

static inline int threadJoin(wthread_t th)
{
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    return 0;
}

#else

typedef pthread_t wthread_t;
typedef void *(*wthread_routine)(void *);
#define HTHREAD_RETTYPE        void *
#define WTHREAD_ROUTINE(fname) void *fname(void *userdata)
static inline wthread_t threadCreate(wthread_routine fn, void *userdata)
{
    pthread_t th;
    pthread_create(&th, NULL, fn, userdata);
    return th;
}

static inline int threadJoin(wthread_t th)
{
    return pthread_join(th, NULL);
}

#endif

#endif // WW_THREAD_H_
