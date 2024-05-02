#ifndef HV_MUTEX_H_
#define HV_MUTEX_H_

#include "hexport.h"
#include "hplatform.h"
#include "hatomic.h"
#include "htime.h"
#include <stdatomic.h>

BEGIN_EXTERN_C

#ifdef OS_WIN
#define hmutex_t                CRITICAL_SECTION
#define hmutex_init             InitializeCriticalSection
#define hmutex_destroy          DeleteCriticalSection
#define hmutex_lock             EnterCriticalSection
#define hmutex_unlock           LeaveCriticalSection

#define hrecursive_mutex_t          CRITICAL_SECTION
#define hrecursive_mutex_init       InitializeCriticalSection
#define hrecursive_mutex_destroy    DeleteCriticalSection
#define hrecursive_mutex_lock       EnterCriticalSection
#define hrecursive_mutex_unlock     LeaveCriticalSection

#define HSPINLOCK_COUNT         -1
#define hspinlock_t             CRITICAL_SECTION
#define hspinlock_init(pspin)   InitializeCriticalSectionAndSpinCount(pspin, HSPINLOCK_COUNT)
#define hspinlock_destroy       DeleteCriticalSection
#define hspinlock_lock          EnterCriticalSection
#define hspinlock_unlock        LeaveCriticalSection

#define hrwlock_t               SRWLOCK
#define hrwlock_init            InitializeSRWLock
#define hrwlock_destroy(plock)
#define hrwlock_rdlock          AcquireSRWLockShared
#define hrwlock_rdunlock        ReleaseSRWLockShared
#define hrwlock_wrlock          AcquireSRWLockExclusive
#define hrwlock_wrunlock        ReleaseSRWLockExclusive

#define htimed_mutex_t                  HANDLE
#define htimed_mutex_init(pmutex)       *(pmutex) = CreateMutex(NULL, FALSE, NULL)
#define htimed_mutex_destroy(pmutex)    CloseHandle(*(pmutex))
#define htimed_mutex_lock(pmutex)       WaitForSingleObject(*(pmutex), INFINITE)
#define htimed_mutex_unlock(pmutex)     ReleaseMutex(*(pmutex))
// true:  WAIT_OBJECT_0
// false: WAIT_OBJECT_TIMEOUT
#define htimed_mutex_lock_for(pmutex, ms)   ( WaitForSingleObject(*(pmutex), ms) == WAIT_OBJECT_0 )

#define hcondvar_t                      CONDITION_VARIABLE
#define hcondvar_init                   InitializeConditionVariable
#define hcondvar_destroy(pcond)
#define hcondvar_wait(pcond, pmutex)            SleepConditionVariableCS(pcond, pmutex, INFINITE)
#define hcondvar_wait_for(pcond, pmutex, ms)    SleepConditionVariableCS(pcond, pmutex, ms)
#define hcondvar_signal                 WakeConditionVariable
#define hcondvar_broadcast              WakeAllConditionVariable

#define honce_t                 INIT_ONCE
#define HONCE_INIT              INIT_ONCE_STATIC_INIT
typedef void (*honce_fn)();
static inline BOOL WINAPI s_once_func(INIT_ONCE* once, PVOID arg, PVOID* _) {
    honce_fn fn = (honce_fn)arg;
    fn();
    return TRUE;
}
static inline void honce(honce_t* once, honce_fn fn) {
    PVOID dummy = NULL;
    InitOnceExecuteOnce(once, s_once_func, (PVOID)fn, &dummy);
}

#define hsem_t                      HANDLE
#define hsem_init(psem, value)      *(psem) = CreateSemaphore(NULL, value, value+100000, NULL)
#define hsem_destroy(psem)          CloseHandle(*(psem))
#define hsem_wait(psem)             WaitForSingleObject(*(psem), INFINITE)
#define hsem_post(psem)             ReleaseSemaphore(*(psem), 1, NULL)
// true:  WAIT_OBJECT_0
// false: WAIT_OBJECT_TIMEOUT
#define hsem_wait_for(psem, ms)     ( WaitForSingleObject(*(psem), ms) == WAIT_OBJECT_0 )

#else
#define hmutex_t                pthread_mutex_t
#define hmutex_init(pmutex)     pthread_mutex_init(pmutex, NULL)
#define hmutex_destroy          pthread_mutex_destroy
#define hmutex_lock             pthread_mutex_lock
#define hmutex_unlock           pthread_mutex_unlock

#define hrecursive_mutex_t          pthread_mutex_t
#define hrecursive_mutex_init(pmutex) \
    do {\
        pthread_mutexattr_t attr;\
        pthread_mutexattr_init(&attr);\
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);\
        pthread_mutex_init(pmutex, &attr);\
    } while(0)
#define hrecursive_mutex_destroy    pthread_mutex_destroy
#define hrecursive_mutex_lock       pthread_mutex_lock
#define hrecursive_mutex_unlock     pthread_mutex_unlock

#if HAVE_PTHREAD_SPIN_LOCK
#define hspinlock_t             pthread_spinlock_t
#define hspinlock_init(pspin)   pthread_spin_init(pspin, PTHREAD_PROCESS_PRIVATE)
#define hspinlock_destroy       pthread_spin_destroy
#define hspinlock_lock          pthread_spin_lock
#define hspinlock_unlock        pthread_spin_unlock
#else
#define hspinlock_t             pthread_mutex_t
#define hspinlock_init(pmutex)  pthread_mutex_init(pmutex, NULL)
#define hspinlock_destroy       pthread_mutex_destroy
#define hspinlock_lock          pthread_mutex_lock
#define hspinlock_unlock        pthread_mutex_unlock
#endif

#define hrwlock_t               pthread_rwlock_t
#define hrwlock_init(prwlock)   pthread_rwlock_init(prwlock, NULL)
#define hrwlock_destroy         pthread_rwlock_destroy
#define hrwlock_rdlock          pthread_rwlock_rdlock
#define hrwlock_rdunlock        pthread_rwlock_unlock
#define hrwlock_wrlock          pthread_rwlock_wrlock
#define hrwlock_wrunlock        pthread_rwlock_unlock

#define htimed_mutex_t              pthread_mutex_t
#define htimed_mutex_init(pmutex)   pthread_mutex_init(pmutex, NULL)
#define htimed_mutex_destroy        pthread_mutex_destroy
#define htimed_mutex_lock           pthread_mutex_lock
#define htimed_mutex_unlock         pthread_mutex_unlock
static inline void timespec_after(struct timespec* ts, unsigned int ms) {
    struct timeval  tv;
    gettimeofday(&tv, NULL);
    ts->tv_sec = tv.tv_sec + ms / 1000;
    ts->tv_nsec = tv.tv_usec * 1000 + ms % 1000 * 1000000;
    if (ts->tv_nsec >= 1000000000) {
        ts->tv_nsec -= 1000000000;
        ts->tv_sec += 1;
    }
}
// true:  OK
// false: ETIMEDOUT
static inline int htimed_mutex_lock_for(htimed_mutex_t* mutex, unsigned int ms) {
#if HAVE_PTHREAD_MUTEX_TIMEDLOCK
    struct timespec ts;
    timespec_after(&ts, ms);
    return pthread_mutex_timedlock(mutex, &ts) != ETIMEDOUT;
#else
    int ret = 0;
    unsigned int end = gettick_ms() + ms;
    while ((ret = pthread_mutex_trylock(mutex)) != 0) {
        if (gettick_ms() >= end) {
            break;
        }
        hv_msleep(1);
    }
    return ret == 0;
#endif
}

#define hcondvar_t              pthread_cond_t
#define hcondvar_init(pcond)    pthread_cond_init(pcond, NULL)
#define hcondvar_destroy        pthread_cond_destroy
#define hcondvar_wait           pthread_cond_wait
#define hcondvar_signal         pthread_cond_signal
#define hcondvar_broadcast      pthread_cond_broadcast
// true:  OK
// false: ETIMEDOUT
static inline int hcondvar_wait_for(hcondvar_t* cond, hmutex_t* mutex, unsigned int ms) {
    struct timespec ts;
    timespec_after(&ts, ms);
    return pthread_cond_timedwait(cond, mutex, &ts) != ETIMEDOUT;
}

#define honce_t                 pthread_once_t
#define HONCE_INIT              PTHREAD_ONCE_INIT
#define honce                   pthread_once

#include <semaphore.h>
#define hsem_t                  sem_t
#define hsem_init(psem, value)  sem_init(psem, 0, value)
#define hsem_destroy            sem_destroy
#define hsem_wait               sem_wait
#define hsem_post               sem_post
// true:  OK
// false: ETIMEDOUT
static inline int hsem_wait_for(hsem_t* sem, unsigned int ms) {
#if HAVE_SEM_TIMEDWAIT
    struct timespec ts;
    timespec_after(&ts, ms);
    return sem_timedwait(sem, &ts) != ETIMEDOUT;
#else
    int ret = 0;
    unsigned int end = gettick_ms() + ms;
    while ((ret = sem_trywait(sem)) != 0) {
        if (gettick_ms() >= end) {
            break;
        }
        hv_msleep(1);
    }
    return ret == 0;
#endif
}

#endif



// YIELD_THREAD() yields for other threads to be scheduled on the current CPU by the OS
#if (defined(WIN32) || defined(_WIN32))
  #define YIELD_THREAD() ((void)0)
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


// hlsem_t is a "light-weight" semaphore which is more efficient than Sema under
// high-contention condition, by avoiding syscalls.
// Waiting when there's already a signal available is extremely cheap and involves
// no syscalls. If there's no signal the implementation will retry by spinning for
// a short while before eventually falling back to Sema.
typedef struct hlsem_s {
  atomic_long count;
  hsem_t         sema;
} hlsem_t;

bool LSemaInit(hlsem_t*, uint32_t initcount); // returns false if system impl failed (rare)
void LSemaDispose(hlsem_t*);
bool LSemaWait(hlsem_t*);
bool LSemaTryWait(hlsem_t*);
bool LSemaTimedWait(hlsem_t*, uint64_t timeout_usecs);
void LSemaSignal(hlsem_t*, uint32_t count /*must be >0*/);
size_t LSemaApproxAvail(hlsem_t*);



#define kYieldProcessorTries 1000

// hybrid_mutex_t is a mutex that will spin for a short while and then block
typedef struct  {
    atomic_bool flag;
    atomic_int  nwait;
    hsem_t      sema;
} hybrid_mutex_t;

static bool HybridMutexInit(hybrid_mutex_t* m); // returns false if system failed to init semaphore
static void HybridMutexDestroy(hybrid_mutex_t* m);
static void HybridMutexLock(hybrid_mutex_t* m);
static void HybridMutexUnlock(hybrid_mutex_t* m);


static inline  bool HybridMutexInit(hybrid_mutex_t* m) {
    m->flag = false;
    m->nwait = 0;
    return hsem_init(&m->sema, 0);
}

static inline  void HybridMutexDestroy(hybrid_mutex_t* m) {
    hsem_destroy(&m->sema);
}

static inline  void HybridMutexLock(hybrid_mutex_t* m) {
    if (atomic_exchange_explicit(&m->flag, true, memory_order_acquire)) {
        // already locked -- slow path
        while (1)
        {
            if (! atomic_exchange_explicit(&m->flag, true, memory_order_acquire))
                break;
            size_t n = kYieldProcessorTries;
            while (atomic_load_explicit(&m->flag, memory_order_relaxed))
            {
                if (--n == 0)
                {
                    atomic_fetch_add_explicit(&m->nwait, 1,memory_order_relaxed );
                    while (atomic_load_explicit(&m->flag, memory_order_relaxed))
                    {
                      hsem_wait(&m->sema);
                    }
                    atomic_fetch_sub_explicit(&m->nwait, 1,memory_order_relaxed);
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

static inline  bool HybridMutexTryLock(hybrid_mutex_t* m) {
    return  0 == atomic_exchange_explicit(&m->flag, true, memory_order_acquire); 
}
static inline  void HybridMutexUnlock(hybrid_mutex_t* m) {
    atomic_exchange(&m->flag, false);
    if (atomic_load(&m->nwait) != 0) {
        // at least one thread waiting on a semaphore signal -- wake one thread
        hsem_post(&m->sema); // TODO: should we check the return value?
    }
}

#undef kYieldProcessorTries 

//  if you want to test, helgrind won't detect atomic flag
#define TEST_HELGRIND   // will transform hybrid mutex to a regular mutex


#ifdef TEST_HELGRIND
#define hhybridmutex_t              hmutex_t
#define hhybridmutex_init           hmutex_init
#define hhybridmutex_destroy        hmutex_destroy
#define hhybridmutex_lock           hmutex_lock
#define hhybridmutex_trylock        hmutex_trylock
#define hhybridmutex_unlock         hmutex_unlock


#else
#define hhybridmutex_t              hybrid_mutex_t
#define hhybridmutex_init           HybridMutexInit
#define hhybridmutex_destroy        HybridMutexDestroy
#define hhybridmutex_lock           HybridMutexLock
#define hhybridmutex_trylock        HybridMutexTryLock
#define hhybridmutex_unlock         HybridMutexUnlock


#endif



END_EXTERN_C


#endif // HV_MUTEX_H_
