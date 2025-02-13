#ifndef WW_THREAD_H_
#define WW_THREAD_H_

#include "wlibc.h"

#ifdef OS_WIN
#define getProcessID (long) GetCurrentProcessId
#else
#define getProcessID (long) getpid
#endif

#ifdef __CYGWIN__
long gettid(void);
#elif defined (OS_WIN)
#define getTID (long) GetCurrentThreadId
#elif HAVE_GETTID || defined(OS_ANDROID)
#define getTID (long) gettid
#elif defined(OS_LINUX)
#include <sys/syscall.h>
#define getTID(void) (long) syscall(SYS_gettid)
#elif defined(OS_DARWIN)
static inline long getTID(void)
{
    uint64_t tid = 0;
    pthread_threadid_np(NULL, &tid);
    return (long)tid;
}
#elif HAVE_PTHREAD_H
#define getTID (long) pthread_self
#else
#define getTID getProcessID
#endif

/*
#include "wthread.h"

WTHREAD_ROUTINE(thread_demo) {
    printf("thread[%ld] start\n", getTID());
    hv_delay(3000);
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
