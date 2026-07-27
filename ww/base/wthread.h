#ifndef WW_THREAD_H_
#define WW_THREAD_H_

/**
 * @file wthread.h
 * @brief Cross-platform thread and thread-id helpers.
 *
 * This header normalizes basic threading operations (create/join/current id)
 * between POSIX and Windows.
 */

#include "wlibc.h"

typedef long     tid_t;
typedef uint32_t wthread_error_t;

enum
{
    kWThreadErrorNone = 0
};

#if defined(OS_WIN) && ! HAVE_SYS_TYPES_H
typedef int pid_t;
#endif

#ifdef OS_WIN
#define getProcessID (pid_t) GetCurrentProcessId
#else
#define getProcessID (pid_t) getpid
#endif

// Returns the current thread id in a platform-appropriate format.
#if defined(OS_WIN)
#define getTID (tid_t) GetCurrentThreadId
#elif HAVE_GETTID || defined(OS_ANDROID)
#define getTID (tid_t) gettid
#elif defined(OS_LINUX)
#include <sys/syscall.h>
#define getTID(void) (tid_t) syscall(SYS_gettid)
#elif defined(OS_DARWIN)
/**
 * @brief Get current thread id on Darwin.
 *
 * @return Numeric thread id.
 */
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
    wwDelay(3000);
    printf("thread[%ld] end\n", getTID());
    return 0;
}

int main() {
    wthread_t th;
    if (threadCreate(&th, thread_demo, NULL) != kWThreadErrorNone) {
        return 1;
    }
    threadJoin(th);
    return 0;
}
 */

#ifdef OS_WIN
typedef HANDLE wthread_t;
/**
 * @brief Windows thread entry routine signature.
 */
typedef DWORD(WINAPI *wthread_routine)(void *);
#define HTHREAD_RETTYPE        DWORD
#define WTHREAD_ROUTINE(fname) DWORD WINAPI fname(void *userdata)
/**
 * @brief Create a thread.
 *
 * @param out Receives the native thread handle on success.
 * @param fn Entry routine.
 * @param userdata Pointer passed to the entry routine.
 * @return `kWThreadErrorNone` on success, otherwise a nonzero Windows error.
 */
static inline wthread_error_t threadCreate(wthread_t *out, wthread_routine fn, void *userdata)
{
    assert(out != NULL);
    HANDLE thread = CreateThread(NULL, 0, fn, userdata, 0, NULL);
    if (thread == NULL)
    {
        DWORD error = GetLastError();
        return error == ERROR_SUCCESS ? ERROR_GEN_FAILURE : (wthread_error_t) error;
    }
    *out = thread;
    return kWThreadErrorNone;
}

/**
 * @brief Join a thread and release its handle.
 *
 * @param th Thread handle to join.
 * @return Always `0`.
 */
static int threadJoin(wthread_t th)
{
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    return 0;
}

/**
 * @brief Join a thread unless it is the current thread.
 *
 * @param th Thread handle to join.
 * @return `true` if joined, `false` when self-join was avoided.
 */
static bool safeThreadJoin(wthread_t th)
{
    if (GetCurrentThreadId() == GetThreadId(th))
    {
        return false;
    }
    WaitForSingleObject(th, INFINITE);
    CloseHandle(th);
    return true;
}

#define terminateCurrentThread() ExitThread(0)

#else

typedef pthread_t wthread_t;
/**
 * @brief POSIX thread entry routine signature.
 */
typedef void *(*wthread_routine)(void *);
#define HTHREAD_RETTYPE        void *
#define WTHREAD_ROUTINE(fname) void *fname(void *userdata)
/**
 * @brief Create a POSIX thread.
 *
 * @param out Receives the native thread handle on success.
 * @param fn Entry routine.
 * @param userdata Pointer passed to the entry routine.
 * @return `kWThreadErrorNone` on success, otherwise `pthread_create`'s error code.
 */
/**
 * @brief Build the set of async stop signals WaterWall routes to the main thread.
 *
 * Deliberately self-contained (no signal-manager dependency): these are the
 * signals the shutdown design requires to be delivered on the main thread only.
 * Blocking one that the signal manager does not handle is harmless — it simply
 * gets delivered to the main thread and keeps its default disposition there.
 */
static inline void buildThreadBlockedStopSignalSet(sigset_t *set)
{
    sigemptyset(set);
#ifdef SIGINT
    sigaddset(set, SIGINT);
#endif
#ifdef SIGTERM
    sigaddset(set, SIGTERM);
#endif
#ifdef SIGQUIT
    sigaddset(set, SIGQUIT);
#endif
#ifdef SIGHUP
    sigaddset(set, SIGHUP);
#endif
#ifdef SIGALRM
    sigaddset(set, SIGALRM);
#endif
}

/**
 * @brief Create a POSIX thread with the graceful stop signals blocked.
 *
 * Shutdown policy: only the main thread has the handled stop signals unblocked;
 * every application-owned thread keeps them blocked. Blocking them in the
 * parent around pthread_create() makes the new thread inherit that mask with no
 * delivery window, and covers threads spawned after signalmanagerStart() (later
 * device threads, lwIP, TUN/raw/capture) without each of them opting in.
 *
 * @param out Receives the native thread handle on success.
 * @param fn Entry routine.
 * @param userdata Pointer passed to the entry routine.
 * @return `kWThreadErrorNone` on success, otherwise `pthread_create`'s error code.
 */
static inline wthread_error_t threadCreate(wthread_t *out, wthread_routine fn, void *userdata)
{
    assert(out != NULL);

    sigset_t blocked;
    sigset_t previous;
    buildThreadBlockedStopSignalSet(&blocked);
    const bool mask_saved = (pthread_sigmask(SIG_BLOCK, &blocked, &previous) == 0);

    pthread_t th;
    int       error = pthread_create(&th, NULL, fn, userdata);

    if (mask_saved)
    {
        pthread_sigmask(SIG_SETMASK, &previous, NULL);
    }

    if (error != 0)
    {
        return (wthread_error_t) error;
    }
    *out = th;
    return kWThreadErrorNone;
}

/**
 * @brief Join a POSIX thread.
 *
 * @param th Thread id to join.
 * @return `pthread_join` return value.
 */
static int threadJoin(wthread_t th)
{
    return pthread_join(th, NULL);
}

/**
 * @brief Join a POSIX thread unless it is the caller thread.
 *
 * @param th Thread id to join.
 * @return `true` if joined, `false` when self-join was avoided.
 */
static bool safeThreadJoin(wthread_t th)
{
    if (pthread_self() == th)
    {
        return false;
    }
    pthread_join(th, NULL);
    return true;
}

// NOTE: was previously `pthread_exit()` (missing the required void* argument),
// which would not compile if ever used; the main-thread shutdown handoff is the
// first caller, so it is corrected to pass NULL here.
#define terminateCurrentThread() pthread_exit(NULL)
#endif

#endif // WW_THREAD_H_
