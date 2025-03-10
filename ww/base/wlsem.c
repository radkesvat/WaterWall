#include "wlibc.h"
#include "wmutex.h"
#include "wplatform.h"

// This implementation is based on of Jeff Preshing's "lightweight semaphore"
// https://github.com/preshing/cpp11-on-multicore/blob/master/common/sema.h
// zlib license:
//
// Copyright (c) 2015 Jeff Preshing
//
// This software is provided 'as-is', without any express or implied
// warranty. In no event will the authors be held liable for any damages
// arising from the use of this software.
//
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
//
// 1. The origin of this software must not be misrepresented; you must not
//  claim that you wrote the original software. If you use this software
//  in a product, an acknowledgement in the product documentation would be
//  appreciated but is not required.
// 2. Altered source versions must be plainly marked as such, and must not be
//  misrepresented as being the original software.
// 3. This notice may not be removed or altered from any source distribution.
/*
    Radkesvat: few changes made to this file, forexample the oldcount variable type is changed
    by me on windows, to match our watomic.h implementation.

    function names changed to camelBack
*/

// #define USE_UNIX_SEMA

#if defined(_WIN32) && ! defined(USE_UNIX_SEMA)

#undef min
#undef max
#elif defined(__MACH__) && ! defined(USE_UNIX_SEMA)
#undef panic // mach/mach.h defines a function called panic()
#include <mach/mach.h>
// redefine panic
#define panic(fmt, ...) _panic(__FILE__, __LINE__, __FUNCTION__, fmt, ##__VA_ARGS__)
#elif defined(__unix__) || defined(USE_UNIX_SEMA)
#include <semaphore.h>
#else
#error Unsupported platform
#endif

#define USECS_IN_1_SEC 1000000
#define NSECS_IN_1_SEC 1000000000

//---------------------------------------------------------------------------------------------
#if defined(_WIN32) && ! defined(USE_UNIX_SEMA)

static bool semaInit(wsem_t *sp, uint32_t initcount)
{
    assert(initcount <= 0x7fffffff);
    *sp = (wsem_t) CreateSemaphoreW(NULL, (int) initcount, 0x7fffffff, NULL);
    return *sp != NULL;
}

static void semaDispose(wsem_t *sp)
{
    CloseHandle(*sp);
}

static bool semaWait(wsem_t *sp)
{
    const unsigned long infinite = 0xffffffff;
    return WaitForSingleObject(*sp, infinite) == 0;
}

static bool semaTryWait(wsem_t *sp)
{
    return WaitForSingleObject(*sp, 0) == 0;
}

static bool semaTimedWait(wsem_t *sp, uint64_t timeout_usecs)
{
    return WaitForSingleObject(*sp, (unsigned long) (timeout_usecs / 1000)) == 0;
}

static bool semaSignal(wsem_t *sp, uint32_t count)
{
    assert(count > 0);
    // while (!ReleaseSemaphore(*sp, count, NULL)) {
    // }
    return ReleaseSemaphore(*sp, (LONG) count, NULL);
}

//---------------------------------------------------------------------------------------------
#elif defined(__MACH__) && ! defined(USE_UNIX_SEMA)
// Can't use POSIX semaphores due to
// https://web.archive.org/web/20140109214515/
// http://lists.apple.com/archives/darwin-kernel/2009/Apr/msg00010.html

static bool semaInit(wsem_t *sp, uint32_t initcount)
{
    assert(initcount <= 0x7fffffff);
    kern_return_t rc = semaphore_create(mach_task_self(), (semaphore_t *) sp, SYNC_POLICY_FIFO, (int) initcount);
    return rc == KERN_SUCCESS;
}

static void semaDispose(wsem_t *sp)
{
    semaphore_destroy(mach_task_self(), *(semaphore_t *) sp);
}

static bool semaWait(wsem_t *sp)
{
    semaphore_t s = *(semaphore_t *) sp;
    while (1)
    {
        kern_return_t rc = semaphore_wait(s);
        if (rc != KERN_ABORTED)
        {
            return rc == KERN_SUCCESS;
        }
    }
}

static bool semaTimedWait(wsem_t *sp, uint64_t timeout_usecs)
{
    mach_timespec_t ts;
    ts.tv_sec  = (uint32_t) (timeout_usecs / USECS_IN_1_SEC);
    ts.tv_nsec = (int) ((timeout_usecs % USECS_IN_1_SEC) * 1000);
    // Note:
    // semaphore_wait_deadline was introduced in macOS 10.6
    // semaphore_timedwait was introduced in macOS 10.10
    // https://developer.apple.com/library/prerelease/mac/documentation/General/Reference/
    //   APIDiffsMacOSX10_10SeedDiff/modules/Darwin.html
    semaphore_t s = *(semaphore_t *) sp;
    while (1)
    {
        kern_return_t rc = semaphore_timedwait(s, ts);
        if (rc != KERN_ABORTED)
        {
            return rc == KERN_SUCCESS;
        }
        // TODO: update ts; subtract time already waited and retry (loop).
        // For now, let's just return with an error:
        return false;
    }
}

static bool semaTryWait(wsem_t *sp)
{
    return semaTimedWait(sp, 0);
}

static bool semaSignal(wsem_t *sp, uint32_t count)
{
    assert(count > 0);
    semaphore_t   s  = *(semaphore_t *) sp;
    kern_return_t rc = 0; // KERN_SUCCESS
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

//---------------------------------------------------------------------------------------------
#elif defined(__unix__) || defined(USE_UNIX_SEMA)

// TODO: implementation based on futex (for Linux and OpenBSD). See "__TBB_USE_FUTEX" of oneTBB

static bool semaInit(wsem_t *sp, uint32_t initcount)
{
    return sem_init((sem_t *) sp, 0, initcount) == 0;
}

static void semaDispose(wsem_t *sp)
{
    sem_destroy((sem_t *) sp);
}

static bool semaWait(wsem_t *sp)
{
    // http://stackoverflow.com/questions/2013181/gdb-causes-sem-wait-to-fail-with-eintr-error
    int rc;
    do
    {
        rc = sem_wait((sem_t *) sp);
    } while (rc == -1 && errno == EINTR);
    return rc == 0;
}

static bool semaTryWait(wsem_t *sp)
{
    int rc;
    do
    {
        rc = sem_trywait((sem_t *) sp);
    } while (rc == -1 && errno == EINTR);
    return rc == 0;
}

static bool semaTimedWait(wsem_t *sp, uint64_t timeout_usecs)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (time_t) (timeout_usecs / USECS_IN_1_SEC);
    ts.tv_nsec += (timeout_usecs % USECS_IN_1_SEC) * 1000;
    // sem_timedwait bombs if you have more than 1e9 in tv_nsec
    // so we have to clean things up before passing it in
    if (ts.tv_nsec >= NSECS_IN_1_SEC)
    {
        ts.tv_nsec -= NSECS_IN_1_SEC;
        ++ts.tv_sec;
    }
    int rc;
    do
    {
        rc = sem_timedwait((sem_t *) sp, &ts);
    } while (rc == -1 && errno == EINTR);
    return rc == 0;
}

static bool semaSignal(wsem_t *sp, uint32_t count)
{
    assert(count > 0);
    while (count-- > 0)
    {
        while (sem_post((sem_t *) sp) == -1)
        {
            return false;
        }
    }
    return true;
}

//---------------------------------------------------------------------------------------------
#endif /* system */
// end of wsem_t implementations

//---------------------------------------------------------------------------------------------
// wlsem_t

// LSEMA_MAX_SPINS is the upper limit of how many times to retry a CAS while spinning.
// After LSEMA_MAX_SPINS CAS attempts has failed (not gotten a signal), the implementation
// falls back on calling semaWait.
//
// The number 10000 has been choosen by looking at contention between a few threads competing
// for signal & wait on macOS 10.15 x86_64. In most observed cases two threads with zero overhead
// racing to wait usually spends around 200–3000 loop cycles before succeeding. (clang -O0)
//
#define LSEMA_MAX_SPINS 10000

static bool _leightweightsemaphoreWaitPartialSpin(wlsem_t *s, uint64_t timeout_usecs)
{
#if defined(OS_WIN) && ! HAVE_STDATOMIC_H
    atomic_llong old_count;
#else
    long long old_count;
#endif
    int spin = LSEMA_MAX_SPINS;
    while (--spin >= 0)
    {
        old_count = atomicLoadExplicit(&s->count, memory_order_relaxed);
        if (old_count > 0 && atomicCompareExchangeExplicit(&s->count, &old_count, old_count - 1, memory_order_acq_rel,
                                                           memory_order_relaxed))
        {
            return true;
        }
        // Prevent the compiler from collapsing the loop
        // [rsms]: Is this really needed? Find out. I think both clang and gcc will avoid
        //         messing with loops that contain atomic ops,
        //__asm__ volatile("" ::: "memory");
        atomicThreadFence(memory_order_acquire);
    }
    old_count = atomicSubExplicit(&s->count, 1, memory_order_acquire);
    if (old_count > 0)
    {
        return true;
    }
    if (timeout_usecs == 0)
    {
        if (semaWait(&s->sema))
        {
            return true;
        }
    }
    if (timeout_usecs > 0 && semaTimedWait(&s->sema, timeout_usecs))
    {
        return true;
    }
    // At this point, we've timed out waiting for the semaphore, but the
    // count is still decremented indicating we may still be waiting on
    // it. So we have to re-adjust the count, but only if the semaphore
    // wasn't signaled enough times for us too since then. If it was, we
    // need to release the semaphore too.
    while (1)
    {
        old_count = atomicLoadExplicit(&s->count, memory_order_acquire);
        if (old_count >= 0 && semaTryWait(&s->sema))
        {
            return true;
        }
        if (old_count < 0 && atomicCompareExchangeExplicit(&s->count, &old_count, old_count + 1, memory_order_relaxed,
                                                           memory_order_relaxed))
        {
            return false;
        }
    }
}

bool leightweightsemaphoreInit(wlsem_t *s, uint32_t initcount)
{
    s->count = initcount;
    return semaInit(&s->sema, initcount);
}

void leightweightsemaphoreDestroy(wlsem_t *s)
{
    semaDispose(&s->sema);
}

bool leightweightsemaphoreWait(wlsem_t *s)
{
    return leightweightsemaphoreTryWait(s) || _leightweightsemaphoreWaitPartialSpin(s, 0);
}

bool leightweightsemaphoreTryWait(wlsem_t *s)
{
#if defined(OS_WIN) && ! HAVE_STDATOMIC_H
    atomic_llong old_count;
#else
    long long old_count;
#endif
    old_count = atomicLoadExplicit(&s->count, memory_order_relaxed);

    while (old_count > 0)
    {
        if (atomic_compare_exchange_weak_explicit(&s->count, &old_count, old_count - 1, memory_order_acquire,
                                                  memory_order_relaxed))
        {
            return true;
        }
    }
    return false;
}

bool leightweightsemaphoreTimedWait(wlsem_t *s, uint64_t timeout_usecs)
{
    return leightweightsemaphoreTryWait(s) || _leightweightsemaphoreWaitPartialSpin(s, timeout_usecs);
}

void leightweightsemaphoreSignal(wlsem_t *s, uint32_t count)
{
    assert(count > 0);

    long long old_count = atomicAddExplicit(&s->count, count, memory_order_release);
    long long toRelease = -old_count < count ? -old_count : count;
    if (toRelease > 0)
    {
        semaSignal(&s->sema, (uint32_t) toRelease);
    }
}

size_t leightweightsemaphoreApproxAvail(wlsem_t *s)
{

#ifdef OS_UNIX
    ssize_t count = atomicLoadExplicit(&s->count, memory_order_relaxed);
#else
    long long count = atomicLoadExplicit(&s->count, memory_order_relaxed);
#endif
    return count > 0 ? (size_t) (count) : 0;
}
