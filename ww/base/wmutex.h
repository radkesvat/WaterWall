#ifndef WW_MUTEX_H_
#define WW_MUTEX_H_

#include "watomic.h"
#include "wexport.h"
#include "wplatform.h"
#include "wtime.h"


#ifdef OS_WIN
#define wmutex_t     CRITICAL_SECTION
#define initMutex    InitializeCriticalSection
#define destroyMutex DeleteCriticalSection
#define lockMutex    EnterCriticalSection
#define unlockMutex  LeaveCriticalSection

#define wrecursive_mutex_t    CRITICAL_SECTION
#define initRecursiveMutex    InitializeCriticalSection
#define destroyRecursiveMutex DeleteCriticalSection
#define lockRecursiveMutex    EnterCriticalSection
#define unlockRecursiveMutex  LeaveCriticalSection

#define WSPINLOCK_COUNT     -1
#define wspinlock_t         CRITICAL_SECTION
#define initSpinlock(pspin) InitializeCriticalSectionAndSpinCount(pspin, WSPINLOCK_COUNT)
#define destroySpinlock     DeleteCriticalSection
#define lockSpinlock        EnterCriticalSection
#define unlockSpinlock      LeaveCriticalSection

#define wrwlock_t  SRWLOCK
#define initRWLock InitializeSRWLock
#define destroyRWLock(plock)
#define lockReadRWLock    AcquireSRWLockShared
#define unlockReadRWLock  ReleaseSRWLockShared
#define lockWriteRWLock   AcquireSRWLockExclusive
#define unlockWriteRWLock ReleaseSRWLockExclusive

#define wtimed_mutex_t            HANDLE
#define initTimedMutex(pmutex)    *(pmutex) = CreateMutex(NULL, FALSE, NULL)
#define destroyTimedMutex(pmutex) CloseHandle(*(pmutex))
#define lockTimedMutex(pmutex)    WaitForSingleObject(*(pmutex), INFINITE)
#define unlockTimedMutex(pmutex)  ReleaseMutex(*(pmutex))
// true:  WAIT_OBJECT_0
// false: WAIT_OBJECT_TIMEOUT
#define lockTimedMutexFor(pmutex, ms) (WaitForSingleObject(*(pmutex), ms) == WAIT_OBJECT_0)

#define wcondvar_t  CONDITION_VARIABLE
#define initCondVar InitializeConditionVariable
#define destroyCondVar(pcond)
#define waitCondVar(pcond, pmutex)        SleepConditionVariableCS(pcond, pmutex, INFINITE)
#define waitCondVarFor(pcond, pmutex, ms) SleepConditionVariableCS(pcond, pmutex, ms)
#define signalCondVar                     WakeConditionVariable
#define broadcastCondVar                  WakeAllConditionVariable

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
#define InitSemaPhore(psem, value) (*(psem) = CreateSemaphore(NULL, value, value + 100000, NULL))
#define destroySemaPhore(psem)     CloseHandle(*(psem))
#define waitSemaPhore(psem)        WaitForSingleObject(*(psem), INFINITE)
#define postSemaPhore(psem)        ReleaseSemaphore(*(psem), 1, NULL)
// true:  WAIT_OBJECT_0
// false: WAIT_OBJECT_TIMEOUT
#define waitSemaPhoreFor(psem, ms) (WaitForSingleObject(*(psem), ms) == WAIT_OBJECT_0)

#else
#define wmutex_t          pthread_mutex_t
#define initMutex(pmutex) pthread_mutex_init(pmutex, NULL)
#define destroyMutex      pthread_mutex_destroy
#define lockMutex         pthread_mutex_lock
#define unlockMutex       pthread_mutex_unlock

#define wrecursive_mutex_t pthread_mutex_t
#define initRecursiveMutex(pmutex)                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        pthread_mutexattr_t attr;                                                                                      \
        pthread_mutexattr_init(&attr);                                                                                 \
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);                                                     \
        pthread_mutex_init(pmutex, &attr);                                                                             \
    } while (0)
#define destroyRecursiveMutex pthread_mutex_destroy
#define lockRecursiveMutex    pthread_mutex_lock
#define unlockRecursiveMutex  pthread_mutex_unlock

#if HAVE_PTHREAD_SPIN_LOCK
#define wspinlock_t         pthread_spinlock_t
#define initSpinlock(pspin) pthread_spin_init(pspin, PTHREAD_PROCESS_PRIVATE)
#define destroySpinlock     pthread_spin_destroy
#define lockSpinlock        pthread_spin_lock
#define unlockSpinlock      pthread_spin_unlock
#else
#define wspinlock_t          pthread_mutex_t
#define initSpinlock(pmutex) pthread_mutex_init(pmutex, NULL)
#define destroySpinlock      pthread_mutex_destroy
#define lockSpinlock         pthread_mutex_lock
#define unlockSpinlock       pthread_mutex_unlock
#endif // OS_WIN

#define wrwlock_t           pthread_rwlock_t
#define initRWLock(prwlock) pthread_rwlock_init(prwlock, NULL)
#define destroyRWLock       pthread_rwlock_destroy
#define lockReadRWLock      pthread_rwlock_rdlock
#define unlockReadRWLock    pthread_rwlock_unlock
#define lockWriteRWLock     pthread_rwlock_wrlock
#define unlockWriteRWLock   pthread_rwlock_unlock

#define wtimed_mutex_t         pthread_mutex_t
#define initTimedMutex(pmutex) pthread_mutex_init(pmutex, NULL)
#define destroyTimedMutex      pthread_mutex_destroy
#define lockTimedMutex         pthread_mutex_lock
#define unlockTimedMutex       pthread_mutex_unlock
static inline void timespec_after(struct timespec *ts, unsigned int ms)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ts->tv_sec  = tv.tv_sec + ms / 1000;
    ts->tv_nsec = tv.tv_usec * 1000 + ms % 1000 * 1000000;
    if (ts->tv_nsec >= 1000000000)
    {
        ts->tv_nsec -= 1000000000;
        ts->tv_sec += 1;
    }
}
// true:  OK
// false: ETIMEDOUT
static inline int lockTimedMutexFor(wtimed_mutex_t *mutex, unsigned int ms)
{
#if HAVE_PTHREAD_MUTEX_TIMEDLOCK
    struct timespec ts;
    timespec_after(&ts, ms);
    return pthread_mutex_timedlock(mutex, &ts) != ETIMEDOUT;
#else
    int          ret = 0;
    unsigned int end = gettick_ms() + ms;
    while ((ret = pthread_mutex_trylock(mutex)) != 0)
    {
        if (gettick_ms() >= end)
        {
            break;
        }
        hv_msleep(1);
    }
    return ret == 0;
#endif
}

#define wcondvar_t         pthread_cond_t
#define initCondVar(pcond) pthread_cond_init(pcond, NULL)
#define destroyCondVar     pthread_cond_destroy
#define waitCondVar        pthread_cond_wait
#define signalCondVar      pthread_cond_signal
#define broadcastCondVar   pthread_cond_broadcast
// true:  OK
// false: ETIMEDOUT
static inline int waitCondVarFor(wcondvar_t *cond, wmutex_t *mutex, unsigned int ms)
{
    struct timespec ts;
    timespec_after(&ts, ms);
    return pthread_cond_timedwait(cond, mutex, &ts) != ETIMEDOUT;
}

#define wonce_t    pthread_once_t
#define WONCE_INIT PTHREAD_ONCE_INIT
#define wonce      pthread_once

// apple semaphore is not posix!

#if defined(__MACH__)
// Can't use POSIX semaphores due to
// https://web.archive.org/web/20140109214515/
// http://lists.apple.com/archives/darwin-kernel/2009/Apr/msg00010.html
#include <mach/mach.h>
#define wsem_t semaphore_t
#define InitSemaPhore(psem, value)                                                                                     \
    semaphore_create(mach_task_self(), psem, SYNC_POLICY_FIFO, value) // (KERN_SUCCESS == 0 like linux)
#define destroySemaPhore(psem) semaphore_destroy(mach_task_self(), *psem);

static bool waitSemaPhore(wsem_t *sp)
{
    semaphore_t s = *sp;
    while (1)
    {
        kern_return_t rc = semaphore_wait(s);
        if (rc != KERN_ABORTED)
            return rc == KERN_SUCCESS;
    }
}

static bool postSemaPhore(wsem_t *sp)
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
static bool waitSemaPhoreFor(wsem_t *sp, uint64_t timeout_usecs)
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

#else // linux semaphore

#include <semaphore.h>
#define wsem_t                     sem_t
#define InitSemaPhore(psem, value) sem_init(psem, 0, value)
#define destroySemaPhore           sem_destroy

static bool waitSemaPhore(wsem_t *sp)
{
    // http://stackoverflow.com/questions/2013181/gdb-causes-sem-wait-to-fail-with-eintr-error
    int rc;
    do
    {
        rc = sem_wait((sem_t *) sp);
    } while (rc == -1 && errno == EINTR);
    return rc == 0;
}

#define postSemaPhore sem_post
// true:  OK
// false: ETIMEDOUT
static inline int waitSemaPhoreFor(wsem_t *sem, unsigned int ms)
{
#if HAVE_SEM_TIMEDWAIT
    struct timespec ts;
    timespec_after(&ts, ms);
    return sem_timedwait(sem, &ts) != ETIMEDOUT;
#else
    int          ret = 0;
    unsigned int end = gettick_ms() + ms;
    while ((ret = sem_trywait(sem)) != 0)
    {
        if (gettick_ms() >= end)
        {
            break;
        }
        hv_msleep(1);
    }
    return ret == 0;
#endif
}

#endif // linux semaphore

#endif // ! OS_WIN

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
#include <immintrin.h>
#define YIELD_CPU() _mm_pause()
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

bool   initLightWeightSemaPhore(wlsem_t *, uint32_t initcount); // returns false if system impl failed (rare)
void   destroyLightWeightSemaPhore(wlsem_t *);
bool   waitLightWeightSemaPhore(wlsem_t *);
bool   tryWaitLightWeightSemaPhore(wlsem_t *);
bool   timedWaitLightWeightSemaPhore(wlsem_t *, uint64_t timeout_usecs);
void   signalLightWeightSemaPhore(wlsem_t *, uint32_t count /*must be >0*/);
size_t approxAvailLeightWaitSemaPhore(wlsem_t *);

#define kYieldProcessorTries 1000

// whybrid_mutex_t is a mutex that will spin for a short while and then block
typedef struct
{
    atomic_bool flag;
    atomic_int  nwait;
    wsem_t      sema;
} whybrid_mutex_t;

// static bool initHybridMutex(whybrid_mutex_t* m); // returns false if system failed to init semaphore
// static void destroyHybridMutex(whybrid_mutex_t* m);
// static void lockHybridMutex(whybrid_mutex_t* m);
// static void unLockHybridMutex(whybrid_mutex_t* m);

static inline bool initHybridMutex(whybrid_mutex_t *m)
{
    m->flag  = false;
    m->nwait = 0;
    return InitSemaPhore(&m->sema, 0);
}

static inline void destroyHybridMutex(whybrid_mutex_t *m)
{
    destroySemaPhore(&m->sema);
}

static inline void lockHybridMutex(whybrid_mutex_t *m)
{
    if (atomic_exchange_explicit(&m->flag, true, memory_order_acquire))
    {
        // already locked -- slow path
        while (1)
        {
            if (! atomic_exchange_explicit(&m->flag, true, memory_order_acquire))
                break;
            size_t n = kYieldProcessorTries;
            while (atomicLoadExplicit(&m->flag, memory_order_relaxed))
            {
                if (--n == 0)
                {
                    atomicAddExplicit(&m->nwait, 1, memory_order_relaxed);
                    while (atomicLoadExplicit(&m->flag, memory_order_relaxed))
                    {
                        waitSemaPhore(&m->sema);
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

static inline bool tryLockHybridMutex(whybrid_mutex_t *m)
{
    return 0 == atomic_exchange_explicit(&m->flag, true, memory_order_acquire);
}

static inline void unLockHybridMutex(whybrid_mutex_t *m)
{
    atomic_exchange(&m->flag, false);
    if (atomic_load(&m->nwait) != 0)
    {
        // at least one thread waiting on a semaphore signal -- wake one thread
        postSemaPhore(&m->sema); // TODO: should we check the return value?
    }
}

#undef kYieldProcessorTries

//  if you want to test, helgrind won't detect atomic flag
// #define TEST_HELGRIND   // will transform hybrid mutex to a regular mutex

#ifndef TEST_HELGRIND

#undef wmutex_t
#undef initMutex
#undef destroyMutex
#undef lockMutex
#undef mutexTryLock
#undef unlockMutex

#define wmutex_t      whybrid_mutex_t
#define initMutex     initHybridMutex
#define destroyMutex  destroyHybridMutex
#define lockMutex     lockHybridMutex
#define mutexTryLock tryLockHybridMutex
#define unlockMutex   unLockHybridMutex

#endif

#endif // WW_MUTEX_H_
