#ifndef HV_THREAD_H_
#define HV_THREAD_H_

#include "hplatform.h"

#ifdef OS_WIN
#define hv_getpid   (long)GetCurrentProcessId
#else
#define hv_getpid   (long)getpid
#endif

#ifdef OS_WIN
#define hv_gettid   (long)GetCurrentThreadId
#elif HAVE_GETTID || defined(OS_ANDROID)
#define hv_gettid   (long)gettid
#elif defined(OS_LINUX)
#include <sys/syscall.h>
#define hv_gettid(void) (long)syscall(SYS_gettid)
#elif defined(OS_DARWIN)
static inline long hv_gettid(void) {
    uint64_t tid = 0;
    pthread_threadid_np(NULL, &tid);
    return tid;
}
#elif HAVE_PTHREAD_H
#define hv_gettid   (long)pthread_self
#else
#define hv_gettid   hv_getpid
#endif

/*
#include "hthread.h"

HTHREAD_ROUTINE(thread_demo) {
    printf("thread[%ld] start\n", hv_gettid());
    hv_delay(3000);
    printf("thread[%ld] end\n", hv_gettid());
    return 0;
}

int main() {
    hthread_t th = hthread_create(thread_demo, NULL);
    hthread_join(th);
    return 0;
}
 */

#ifdef OS_WIN
typedef HANDLE      hthread_t;
typedef DWORD (WINAPI *hthread_routine)(void*);
#define HTHREAD_RETTYPE DWORD
#define HTHREAD_ROUTINE(fname) DWORD WINAPI fname(void* userdata)
static inline hthread_t hthread_create(hthread_routine fn, void* userdata) {
    return CreateThread(NULL, 0, fn, userdata, 0, NULL);
}

static inline int hthread_join(hthread_t th) {
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    return 0;
}

#else

typedef pthread_t   hthread_t;
typedef void* (*hthread_routine)(void*);
#define HTHREAD_RETTYPE void*
#define HTHREAD_ROUTINE(fname) void* fname(void* userdata)
static inline hthread_t hthread_create(hthread_routine fn, void* userdata) {
    pthread_t th;
    pthread_create(&th, NULL, fn, userdata);
    return th;
}

static inline int hthread_join(hthread_t th) {
    return pthread_join(th, NULL);
}

#endif



#endif // HV_THREAD_H_
