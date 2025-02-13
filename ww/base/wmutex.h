#ifndef WW_MUTEX_H_
#define WW_MUTEX_H_

#include "wlibc.h"

#ifdef OS_WIN // Windows-specific definitions

#define wmutex_t     CRITICAL_SECTION
#define mutexInit    InitializeCriticalSection
#define mutexDestroy DeleteCriticalSection
#define mutexLock    EnterCriticalSection
#define mutexUnlock  LeaveCriticalSection

#define wrecursive_mutex_t    CRITICAL_SECTION
#define recursivemutexInit    InitializeCriticalSection
#define recursivemutexDestroy DeleteCriticalSection
#define recursivemutexLock    EnterCriticalSection
#define recursivemutexUnlock  LeaveCriticalSection

#define WSPINLOCK_COUNT     -1
#define wspinlock_t         CRITICAL_SECTION
#define spinlockInit(pspin) InitializeCriticalSectionAndSpinCount(pspin, WSPINLOCK_COUNT)
#define spinlockDestroy     DeleteCriticalSection
#define spinlockLock        EnterCriticalSection
#define spinlockUnlock      LeaveCriticalSection

#define wrwlock_t  SRWLOCK
#define rwlockinit InitializeSRWLock
#define rwlockDestroy(plock)
#define rwlockReadLock    AcquireSRWLockShared
#define rwlockReadUnlock  ReleaseSRWLockShared
#define rwlockWriteLock   AcquireSRWLockExclusive
#define rwlockWriteUnlock ReleaseSRWLockExclusive

#define wtimed_mutex_t            HANDLE
#define timedmutexInit(pmutex)    *(pmutex) = CreateMutex(NULL, FALSE, NULL)
#define timedmutexDestroy(pmutex) CloseHandle(*(pmutex))
#define timedmutexLock(pmutex)    WaitForSingleObject(*(pmutex), INFINITE)
#define timedmutexUnlock(pmutex)  ReleaseMutex(*(pmutex))
// true:  WAIT_OBJECT_0
// false: WAIT_OBJECT_TIMEOUT
#define timedmutexLockFor(pmutex, ms) (WaitForSingleObject(*(pmutex), ms) == WAIT_OBJECT_0)

#define wcondvar_t  CONDITION_VARIABLE
#define condvarInit InitializeConditionVariable
#define contvarDestroy(pcond)
#define condvarWait(pcond, pmutex)        SleepConditionVariableCS(pcond, pmutex, INFINITE)
#define condvarWaitFor(pcond, pmutex, ms) SleepConditionVariableCS(pcond, pmutex, ms)
#define condvarSignal                     WakeConditionVariable
#define condvarBroadCast                  WakeAllConditionVariable

#define wonce_t    INIT_ONCE
#define WONCE_INIT INIT_ONCE_STATIC_INIT
typedef void (*wonce_fn)(void);
static inline BOOL WINAPI s_once_func(INIT_ONCE *once, PVOID arg, PVOID *_)
{
    (void) once;
    (void) _;
    wonce_fn fn      = NULL;
    *(void **) (&fn) = arg;
    fn();
    return TRUE;
}
static inline void wonce(wonce_t *once, wonce_fn fn)
{
    PVOID dummy = NULL;
    InitOnceExecuteOnce(once, s_once_func, *(void **) (&fn), &dummy);
}

#define wsem_t                     HANDLE
#define semaphoreInit(psem, value) (*(psem) = CreateSemaphore(NULL, value, value + 100000, NULL))
#define semaphoreDestroy(psem)     CloseHandle(*(psem))
#define semaphoreWait(psem)        WaitForSingleObject(*(psem), INFINITE)
#define semaphorePost(psem)        ReleaseSemaphore(*(psem), 1, NULL)
// true:  WAIT_OBJECT_0
// false: WAIT_OBJECT_TIMEOUT
#define semaphoreWaitFor(psem, ms) (WaitForSingleObject(*(psem), ms) == WAIT_OBJECT_0)

#else // POSIX-specific definitions

#define wmutex_t          pthread_mutex_t
#define mutexInit(pmutex) pthread_mutex_init(pmutex, NULL)
#define mutexDestroy      pthread_mutex_destroy
#define mutexLock         pthread_mutex_lock
#define mutexUnlock       pthread_mutex_unlock

#define wrecursive_mutex_t pthread_mutex_t
#define recursivemutexInit(pmutex)                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        pthread_mutexattr_t attr;                                                                                      \
        pthread_mutexattr_init(&attr);                                                                                 \
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);                                                     \
        pthread_mutex_init(pmutex, &attr);                                                                             \
    } while (0)
#define recursivemutexDestroy pthread_mutex_destroy
#define recursivemutexLock    pthread_mutex_lock
#define recursivemutexUnlock  pthread_mutex_unlock

#if HAVE_PTHREAD_SPIN_LOCK
#define wspinlock_t         pthread_spinlock_t
#define spinlockInit(pspin) pthread_spin_init(pspin, PTHREAD_PROCESS_PRIVATE)
#define spinlockDestroy     pthread_spin_destroy
#define spinlockLock        pthread_spin_lock
#define spinlockUnlock      pthread_spin_unlock
#else
#define wspinlock_t          pthread_mutex_t
#define spinlockInit(pmutex) pthread_mutex_init(pmutex, NULL)
#define spinlockDestroy      pthread_mutex_destroy
#define spinlockLock         pthread_mutex_lock
#define spinlockUnlock       pthread_mutex_unlock
#endif // HAVE_PTHREAD_SPIN_LOCK

#define wrwlock_t           pthread_rwlock_t
#define rwlockinit(prwlock) pthread_rwlock_init(prwlock, NULL)
#define rwlockDestroy       pthread_rwlock_destroy
#define rwlockReadLock      pthread_rwlock_rdlock
#define rwlockReadUnlock    pthread_rwlock_unlock
#define rwlockWriteLock     pthread_rwlock_wrlock
#define rwlockWriteUnlock   pthread_rwlock_unlock

#define wtimed_mutex_t         pthread_mutex_t
#define timedmutexInit(pmutex) pthread_mutex_init(pmutex, NULL)
#define timedmutexDestroy      pthread_mutex_destroy
#define timedmutexLock         pthread_mutex_lock
#define timedmutexUnlock       pthread_mutex_unlock
static inline void timespec_after(struct timespec *ts, unsigned int ms)
{
    struct timeval tv;
    getTimeOfDay(&tv, NULL);
    ts->tv_sec  = tv.tv_sec + ((long)ms / 1000);
    ts->tv_nsec = tv.tv_usec * 1000 + (long)ms % 1000 * 1000000;
    if (ts->tv_nsec >= 1000000000)
    {
        ts->tv_nsec -= 1000000000;
        ts->tv_sec += 1;
    }
}
// true:  OK
// false: ETIMEDOUT
static inline int timedmutexLockFor(wtimed_mutex_t *mutex, unsigned int ms)
{
#if HAVE_PTHREAD_MUTEX_TIMEDLOCK
    struct timespec ts;
    timespec_after(&ts, ms);
    return pthread_mutex_timedlock(mutex, &ts) != ETIMEDOUT;
#else
    int          ret = 0;
    unsigned int end = getTickMS() + ms;
    while ((ret = pthread_mutex_trylock(mutex)) != 0)
    {
        if (getTickMS() >= end)
        {
            break;
        }
        hv_msleep(1);
    }
    return ret == 0;
#endif
}

#define wcondvar_t         pthread_cond_t
#define condvarInit(pcond) pthread_cond_init(pcond, NULL)
#define contvarDestroy     pthread_cond_destroy
#define condvarWait        pthread_cond_wait
#define condvarSignal      pthread_cond_signal
#define condvarBroadCast   pthread_cond_broadcast
// true:  OK
// false: ETIMEDOUT
static inline int condvarWaitFor(wcondvar_t *cond, wmutex_t *mutex, unsigned int ms)
{
    struct timespec ts;
    timespec_after(&ts, ms);
    return pthread_cond_timedwait(cond, mutex, &ts) != ETIMEDOUT;
}

#define wonce_t    pthread_once_t
#define WONCE_INIT PTHREAD_ONCE_INIT
#define wonce      pthread_once

// Apple semaphore is not POSIX!
#if defined(__MACH__) // macOS-specific semaphore implementation

#include <mach/mach.h>
#define wsem_t semaphore_t
#define semaphoreInit(psem, value)                                                                                     \
    semaphore_create(mach_task_self(), psem, SYNC_POLICY_FIFO, value) // (KERN_SUCCESS == 0 like linux)
#define semaphoreDestroy(psem) semaphore_destroy(mach_task_self(), *psem);

static bool semaphoreWait(wsem_t *sp)
{
    semaphore_t s = *sp;
    while (1)
    {
        kern_return_t rc = semaphore_wait(s);
        if (rc != KERN_ABORTED)
            return rc == KERN_SUCCESS;
    }
}

static bool semaphorePost(wsem_t *sp)
{
    uint32_t      count = 1;
    semaphore_t   s     = *(semaphore_t *) sp;
    kern_return_t rc    = 0; // KERN_SUCCESS
    while (count-- > 0)
    {
        rc += semaphore_signal(s); // == ...
                                   // auto rc1 = semaphore_signal(s);
                                   // if (rc1 != KERN_SUCCESS) {
                                   //   rc = rc1;
                                   // }
    }
    return rc == KERN_SUCCESS;
}
#define USECS_IN_1_SEC         1000000
#define NSECS_IN_1_SEC         1000000000
static bool semaphoreWaitFor(wsem_t *sp, uint64_t timeout_usecs)
{
    mach_timespec_t ts;
    ts.tv_sec  = (uint32_t) (timeout_usecs / USECS_IN_1_SEC);
    ts.tv_nsec = (int) ((timeout_usecs % USECS_IN_1_SEC) * 1000);
    // Note:
    // semaphore_wait_deadline was introduced in macOS 10.6
    // semaphore_timedwait was introduced in macOS 10.10
    // https://developer.apple.com/library/prerelease/mac/documentation/General/Reference/
    //   APIDiffsMacOSX10_10SeedDiff/modules/Darwin.html
    semaphore_t s = *sp;
    while (1)
    {
        kern_return_t rc = semaphore_timedwait(s, ts);
        if (rc != KERN_ABORTED)
            return rc == KERN_SUCCESS;
        // TODO: update ts; subtract time already waited and retry (loop).
        // For now, let's just return with an error:
        return false;
    }
}
#undef USECS_IN_1_SEC
#undef NSECS_IN_1_SEC

#else // Linux-specific semaphore implementation

#include <semaphore.h>
#define wsem_t                     sem_t
#define semaphoreInit(psem, value) sem_init(psem, 0, value)
#define semaphoreDestroy           sem_destroy

static bool semaphoreWait(wsem_t *sp)
{
    // http://stackoverflow.com/questions/2013181/gdb-causes-sem-wait-to-fail-with-eintr-error
    int rc;
    do
    {
        rc = sem_wait((sem_t *) sp);
    } while (rc == -1 && errno == EINTR);
    return rc == 0;
}

#define semaphorePost sem_post
// true:  OK
// false: ETIMEDOUT
static inline int semaphoreWaitFor(wsem_t *sem, unsigned int ms)
{
#if HAVE_SEM_TIMEDWAIT
    struct timespec ts;
    timespec_after(&ts, ms);
    return sem_timedwait(sem, &ts) != ETIMEDOUT;
#else
    int          ret = 0;
    unsigned int end = getTickMS() + ms;
    while ((ret = sem_trywait(sem)) != 0)
    {
        if (getTickMS() >= end)
        {
            break;
        }
        hv_msleep(1);
    }
    return ret == 0;
#endif
}

#endif // macOS semaphore

#endif // OS_WIN

// YIELD_THREAD() yields for other threads to be scheduled on the current CPU by the OS
#if (defined(WIN32) || defined(_WIN32))
#define YIELD_THREAD() ((void) 0)
#else
#include <sched.h>
#define YIELD_THREAD() sched_yield()
#endif

// YIELD_CPU() yields for other work on a CPU core
#if defined(__i386) || defined(__i386__) || defined(__x86_64__)
#define YIELD_CPU() __asm__ __volatile__("pause")
#elif defined(__arm__) || defined(__arm64__) || defined(__aarch64__)
#define YIELD_CPU() __asm__ __volatile__("yield")
#elif defined(mips) || defined(__mips__) || defined(MIPS) || defined(_MIPS_) || defined(__mips64)
#if defined(_ABI64) && (_MIPS_SIM == _ABI64)
#define YIELD_CPU() __asm__ __volatile__("pause")
#else
// comment from WebKit source:
//   The MIPS32 docs state that the PAUSE instruction is a no-op on older
//   architectures (first added in MIPS32r2). To avoid assembler errors when
//   targeting pre-r2, we must encode the instruction manually.
#define YIELD_CPU() __asm__ __volatile__(".word 0x00000140")
#endif
#elif (defined(WIN32) || defined(_WIN32))
#if defined(_M_ARM) || defined(_M_ARM64)
#include <intrin.h>
#define YIELD_CPU() __yield()
#else
#include <immintrin.h>
#define YIELD_CPU() _mm_pause()
#endif


#else
// GCC & clang intrinsic
#define YIELD_CPU() __builtin_ia32_pause()
#endif

// wlsem_t is a "light-weight" semaphore which is more efficient than Sema under
// high-contention condition, by avoiding syscalls.
// Waiting when there's already a signal available is extremely cheap and involves
// no syscalls. If there's no signal the implementation will retry by spinning for
// a short while before eventually falling back to Sema.
typedef struct hlsem_s
{
    atomic_long count;
    wsem_t      sema;
} wlsem_t;

bool   leightweightsemaphoreInit(wlsem_t *, uint32_t initcount); // returns false if system impl failed (rare)
void   leightweightsemaphoreDestroy(wlsem_t *);
bool   leightweightsemaphoreWait(wlsem_t *);
bool   leightweightsemaphoreTryWait(wlsem_t *);
bool   leightweightsemaphoreTimedWait(wlsem_t *, uint64_t timeout_usecs);
void   leightweightsemaphoreSignal(wlsem_t *, uint32_t count /*must be >0*/);
size_t leightweightsemaphoreApproxAvail(wlsem_t *);

#define kYieldProcessorTries 1000

// whybrid_mutex_t is a mutex that will spin for a short while and then block
typedef struct
{
    atomic_bool flag;
    atomic_int  nwait;
    wsem_t      sema;
} whybrid_mutex_t;

// static bool hybridmutexInit(whybrid_mutex_t* m); // returns false if system failed to init semaphore
// static void hybridmutexDestroy(whybrid_mutex_t* m);
// static void hybridmutexLock(whybrid_mutex_t* m);
// static void hybridmutexUnlock(whybrid_mutex_t* m);

static inline bool hybridmutexInit(whybrid_mutex_t *m)
{
    m->flag  = false;
    m->nwait = 0;
    return semaphoreInit(&m->sema, 0);
}

static inline void hybridmutexDestroy(whybrid_mutex_t *m)
{
    semaphoreDestroy(&m->sema);
}

static inline void hybridmutexLock(whybrid_mutex_t *m)
{
    if (atomicExchangeExplicit(&m->flag, true, memory_order_acquire))
    {
        // already locked -- slow path
        while (1)
        {
            if (! atomicExchangeExplicit(&m->flag, true, memory_order_acquire))
            {
                break;
            }
            size_t n = kYieldProcessorTries;
            while (atomicLoadExplicit(&m->flag, memory_order_relaxed))
            {
                if (--n == 0)
                {
                    atomicAddExplicit(&m->nwait, 1, memory_order_relaxed);
                    while (atomicLoadExplicit(&m->flag, memory_order_relaxed))
                    {
                        semaphoreWait(&m->sema);
                    }
                    atomicSubExplicit(&m->nwait, 1, memory_order_relaxed);
                }
                else
                {
                    // avoid starvation on hyper-threaded CPUs
                    YIELD_CPU();
                }
            }
        }
    }
}

static inline bool hybridmutexTryLock(whybrid_mutex_t *m)
{
    return 0 == atomicExchangeExplicit(&m->flag, true, memory_order_acquire);
}

static inline void hybridmutexUnlock(whybrid_mutex_t *m)
{
    atomic_exchange(&m->flag, false);
    if (atomic_load(&m->nwait) != 0)
    {
        // at least one thread waiting on a semaphore signal -- wake one thread
        semaphorePost(&m->sema); // TODO: should we check the return value?
    }
}

#undef kYieldProcessorTries

//  if you want to test, helgrind won't detect atomic flag
// #define TEST_HELGRIND   // will transform hybrid mutex to a regular mutex

// according to microsoft docs, windows mutex uses atomic operation by default
// and our implementation cannt be beter than the system one

#if ! defined (TEST_HELGRIND) && ! defined (COMPILER_MSVC)

#undef wmutex_t
#undef mutexInit
#undef mutexDestroy
#undef mutexLock
#undef mutexTryLock
#undef mutexUnlock

#define wmutex_t     whybrid_mutex_t
#define mutexInit    hybridmutexInit
#define mutexDestroy hybridmutexDestroy
#define mutexLock    hybridmutexLock
#define mutexTryLock hybridmutexTryLock
#define mutexUnlock  hybridmutexUnlock

#endif // TEST_HELGRIND

#endif // WW_MUTEX_H_
