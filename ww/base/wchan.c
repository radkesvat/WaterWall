/**
 * @file wchan.c
 * @brief Implementation of CSP-style synchronous/buffered channels.
 *
 * Provides channel allocation, send/recv operations, waiting queues,
 * and channel close semantics for multi-threaded message passing.
 */

#include "wchan.h"
#include "watomic.h"
#include "wmutex.h"

/* DEBUG_CHAN_LOG traces channel operations. DEBUG_CHAN_LOCK traces lock ownership. */
#if defined(DEBUG) && (defined(DEBUG_CHAN_LOG) || defined(DEBUG_CHAN_LOCK))
#include "wlog.h"
#include "wthread.h"

/* A single write keeps debug records together without acquiring a logger or stdio lock. */
static void chanDebugTrace(const char *operation, const void *object)
{
    static atomic_ullong sequence;
    char                 record[128];
    const int            length = snprintf(record,
                                sizeof(record),
                                "channel %llu thread %ld %s %p\n",
                                (unsigned long long) atomicIncU64Relaxed(&sequence) + 1U,
                                getTID(),
                                operation,
                                (void *) object);
    if (length > 0)
        stderrLogger(LOG_LEVEL_DEBUG, record, min(length, (int) sizeof(record) - 1));
}
#endif

#if defined(DEBUG) && defined(DEBUG_CHAN_LOG)
#define chan_trace(operation, channel) chanDebugTrace(operation, channel)
#else
#define chan_trace(operation, channel) ((void) 0)
#endif

#define CHAN_LOCK_T             wmutex_t
#define chan_lock_init(lock)    mutexInit(lock)
#define chan_lock_destroy(lock) mutexDestroy(lock)

#if defined(DEBUG) && defined(DEBUG_CHAN_LOCK)
static inline void chan_lock(wmutex_t *lock)
{
    chanDebugTrace("lock requested", lock);
    mutexLock(lock);
    chanDebugTrace("lock acquired", lock);
}

static inline void chan_unlock(wmutex_t *lock)
{
    chanDebugTrace("unlock", lock);
    mutexUnlock(lock);
}
#else
#define chan_lock(lock)   mutexLock(lock)
#define chan_unlock(lock) mutexUnlock(lock)
#endif

typedef struct Thr Thr;

// Thr holds thread-specific data and is owned by thread-local storage

struct Thr
{
    bool                                   init;
    atomic_bool                            closed;
    atomic_int                             signals; // thr_signal() calls that have not returned yet
    wlsem_t                                sema;
    MSVC_ATTR_ALIGNED_LINE_CACHE Thr *next GNU_ATTR_ALIGNED_LINE_CACHE;
    atomic_ptr_t                           elemptr;
};

typedef struct WaitQ
{
    atomic_ptr_t first; // head of linked list of parked threads
    atomic_ptr_t last;  // tail of linked list of parked threads
} WaitQ;

typedef MSVC_ATTR_ALIGNED_LINE_CACHE struct wchan_s
{
    // These fields don't change after wchan_Open
    size_t   elemsize; // size in bytes of elements sent on the channel
    uint32_t qcap;     // size of the circular queue buf (immutable)

    // These fields are frequently accessed and stored to.
    // There's a perf opportunity here with a different more cache-efficient layout.
    atomic_u32_t qlen;   // number of messages currently queued in buf
    atomic_bool  closed; // one way switch (once it becomes true, never becomes false again)
    CHAN_LOCK_T  lock;   // guards the wchan_t struct

    // sendq is accessed on every call to chan_recv and only in some cases by chan_send,
    // when parking a thread when there's no waiting receiver nor queued message.
    // recvq is accessed on every call to chan_send and like sendq, only when parking a thread
    // in chan_recv.
    WaitQ sendq; // list of waiting send callers
    WaitQ recvq; // list of waiting recv callers

    // sendx and recvx are serialized by lock. qlen stays atomic because the
    // non-blocking full/empty probes read it without taking lock.
    uint32_t sendx;

    MSVC_ATTR_ALIGNED_LINE_CACHE uint32_t recvx GNU_ATTR_ALIGNED_LINE_CACHE;

    // uint8_t pad[kCpuLineCacheSize];
    uint8_t buf[]; // queue storage
} GNU_ATTR_ALIGNED_LINE_CACHE wchan_t;

#ifdef WCHAN_TEST_HOOKS
static WchanAfterTrySendFastFullHook wchan_after_try_send_fast_full_hook;
static void                         *wchan_after_try_send_fast_full_context;

void chanInstallAfterTrySendFastFullHook(WchanAfterTrySendFastFullHook hook, void *context)
{
    wchan_after_try_send_fast_full_hook    = hook;
    wchan_after_try_send_fast_full_context = context;
}
#endif

// Waits until no thr_signal() call is still inside t's semaphore. Publishing the wakeup and
// returning from the call that published it are not the same instant: the woken thread can
// run to completion, exit, and tear its Thr down while the waker is still touching the
// semaphore. A waiter is only ever signaled while it is parked, so by the time its thread
// exits the wake that released it is the only one that can still be in flight.
static void thr_drain_signals(Thr *t)
{
    while (atomicLoadExplicit(&t->signals, memory_order_acquire) != 0)
    {
        YIELD_CPU();
        YIELD_THREAD();
    }
}

// The wait semaphore of a Thr is owned by an OS object on Windows (a HANDLE) and macOS
// (a Mach port), so letting the thread die without disposing of it leaks that object once
// per thread that ever parked on a channel -- which is once per device writer restart.
// Thread-local storage has no destructor hook of its own, so the Thr is registered with a
// key/slot whose callback runs on thread exit.
#ifdef OS_WIN
static DWORD thr_tls_slot = FLS_OUT_OF_INDEXES;

// Releases the wait semaphore of an exiting thread (fiber-local slots run callbacks on
// thread exit, plain TLS slots do not).
static void WINAPI thr_tls_release(void *value)
{
    Thr *t = (Thr *) value;
    if (t != NULL)
    {
        thr_drain_signals(t);
        // Clearing init keeps a channel used after this point (from another thread-exit
        // callback, say) re-initializing instead of waiting on a destroyed semaphore.
        t->init = false;
        leightweightsemaphoreDestroy(&t->sema);
    }
}

static void thr_tls_create(void)
{
    thr_tls_slot = FlsAlloc(thr_tls_release);
}

// Arranges for t's wait semaphore to be disposed of when the calling thread exits.
static void thr_register_cleanup(Thr *t)
{
    static wonce_t once = WONCE_INIT;

    wonce(&once, thr_tls_create);
    if (thr_tls_slot == FLS_OUT_OF_INDEXES || ! FlsSetValue(thr_tls_slot, t))
    {
        // Continuing here would silently reinstate the per-thread semaphore leak this
        // registration exists to prevent.
        printError("failed to register channel wait semaphore cleanup");
        abortProgramNow(1);
    }
}
#else
static pthread_key_t thr_tls_key;
static bool          thr_tls_key_ok = false;

// Releases the wait semaphore of an exiting thread.
static void thr_tls_release(void *value)
{
    Thr *t = (Thr *) value;
    if (t != NULL)
    {
        thr_drain_signals(t);
        // Clearing init keeps a channel used after this point (from a later thread-exit
        // destructor, say) re-initializing instead of waiting on a destroyed semaphore.
        t->init = false;
        leightweightsemaphoreDestroy(&t->sema);
    }
}

static void thr_tls_create(void)
{
    thr_tls_key_ok = (pthread_key_create(&thr_tls_key, thr_tls_release) == 0);
}

// Arranges for t's wait semaphore to be disposed of when the calling thread exits.
// Note that pthread does not run key destructors for the main thread; that bounded
// case costs one semaphore for the lifetime of the process.
static void thr_register_cleanup(Thr *t)
{
    static wonce_t once = WONCE_INIT;

    discard wonce(&once, thr_tls_create);
    if (! thr_tls_key_ok || pthread_setspecific(thr_tls_key, t) != 0)
    {
        // Continuing here would silently reinstate the per-thread semaphore leak this
        // registration exists to prevent.
        printError("failed to register channel wait semaphore cleanup");
        abortProgramNow(1);
    }
}
#endif

// Initializes thread-local channel wait context.
static void thr_init(Thr *t)
{
    if (UNLIKELY(! leightweightsemaphoreInit(&t->sema, 0)))
    {
        // Without a usable semaphore every park would return immediately, silently
        // corrupting every channel this thread touches.
        printError("failed to create channel wait semaphore");
        abortProgramNow(1);
    }
    thr_register_cleanup(t);
    t->init = true; // set last: thr_current() gates first use on it
}

// Returns thread-local wait context, initializing it on first use.
inline static Thr *thr_current(void)
{
    static thread_local Thr _thr = {0};

    Thr *t = &_thr;
    if (UNLIKELY(! t->init))
        thr_init(t);
    return t;
}

// Wakes a parked sender/receiver thread.
inline static void thr_signal(Thr *t)
{
    // Registered before the wake and cleared as the last access to t, so a thread woken here
    // cannot destroy its semaphore from under this call. t is still parked at this point,
    // which is what makes reaching it safe in the first place.
    atomicAddExplicit(&t->signals, 1, memory_order_relaxed);
    leightweightsemaphoreSignal(&t->sema, 1); // wake
    atomicSubExplicit(&t->signals, 1, memory_order_release);
}

// Blocks current sender/receiver thread until signaled.
inline static void thr_wait(Thr *t)
{
    if (UNLIKELY(! leightweightsemaphoreWait(&t->sema))) // sleep
    {
        // A failed wait returns without a wakeup while this thread is still linked into a
        // channel wait queue, which is exactly the state that lets a later operation write
        // through a waiter that has already gone. There is no way back from here.
        printError("channel wait failed");
        abortProgramNow(1);
    }
}

// Enqueues a waiting participant into a channel wait queue.
static void wq_enqueue(WaitQ *wq, Thr *t)
{
    // note: atomic loads & stores for cache reasons, not thread safety; c->lock is held.
    if (atomicLoadPtrExplicit(&wq->first, memory_order_acquire))
    {
        // Note: compare first instead of last as we don't clear wq->last in wq_dequeue
        Thr *last  = atomicLoadPtrExplicit(&wq->last, memory_order_acquire);
        last->next = t;
    }
    else
    {
        atomicStorePtrExplicit(&wq->first, t, memory_order_release);
    }
    atomicStorePtrExplicit(&wq->last, t, memory_order_release);
}

// Dequeues one waiting participant from a channel wait queue.
static inline Thr *wq_dequeue(WaitQ *wq)
{
    Thr *t = atomicLoadPtrExplicit(&wq->first, memory_order_acquire);
    if (t)
    {
        atomicStorePtrExplicit(&wq->first, t->next, memory_order_release);
        t->next = NULL;
        // Note: intentionally not clearing wq->last in case wq->first==wq->last as we can
        // avoid that branch by not checking wq->last in wq_enqueue.
    }
    return t;
}

// chan_bufptr returns the pointer to the i'th slot in the buffer
inline static void *chan_bufptr(wchan_t *c, uint32_t i)
{
    return (void *) &c->buf[(uintptr_t) i * (uintptr_t) c->elemsize];
}

// Cancels every waiter of wq and detaches it from the queue.
// Caller must hold the lock of the channel that owns wq.
static void wq_cancel_all(WaitQ *wq)
{
    Thr *t = atomicLoadPtrExplicit(&wq->first, memory_order_acquire);

    // The queue must be emptied, not just walked: a woken waiter returns to its caller and
    // its Thr (thread-local) along with the elemptr it parked with (usually a stack address)
    // stop being valid to touch. A leftover link would let a later recv hand out the canceled
    // message, write through that stale pointer, or signal a thread parked elsewhere.
    atomicStorePtrExplicit(&wq->first, NULL, memory_order_release);
    atomicStorePtrExplicit(&wq->last, NULL, memory_order_release);

    while (t)
    {
        Thr *next = t->next;
        t->next   = NULL;
        atomicStorePtrExplicit(&t->elemptr, NULL, memory_order_relaxed);
        atomicStoreExplicit(&t->closed, true, memory_order_relaxed);
        thr_signal(t); // the semaphore pair orders the two stores above against the wakeup
        t = next;
    }
}

// chan_park adds elemptr to wait queue wq, unlocks channel c and blocks the calling thread
static Thr *chan_park(wchan_t *c, WaitQ *wq, void *elemptr)
{
    // caller must hold lock on channel that owns wq
    Thr *t = thr_current();

    // Reset the wait state of a previous park: closing a channel leaves "closed" set on
    // every waiter it cancels, and wq_enqueue requires next to be NULL. Both are stale here.
    t->next = NULL;
    atomicStoreExplicit(&t->closed, false, memory_order_relaxed);
    atomicStorePtrExplicit(&t->elemptr, elemptr, memory_order_relaxed);
    chan_trace("park", c);
    wq_enqueue(wq, t);
    chan_unlock(&c->lock);
    thr_wait(t);
    return t;
}

inline static bool chan_full(wchan_t *c)
{
    // c.qcap is immutable (never written after the channel is created)
    // so it is safe to read at any time during channel operation.
    if (c->qcap == 0)
        return atomicLoadPtrExplicit(&c->recvq.first, memory_order_relaxed) == NULL;
    return atomicLoadU32Explicit(&c->qlen, memory_order_relaxed) == c->qcap;
}

// Copies sender payload directly into a waiting receiver and wakes it.
static bool chan_send_direct(wchan_t *c, void *srcelemptr, Thr *recvt)
{
    // chan_send_direct processes a send operation on an empty channel c.
    // element sent by the sender is copied to the receiver recvt.
    // The receiver is then woken up to go on its merry way.
    // wchan_nel c must be empty and locked. This function unlocks c with chan_unlock.
    // recvt must already be dequeued from c.

    void *dstelemptr = atomicLoadPtrExplicit(&recvt->elemptr, memory_order_acquire);
    assert(dstelemptr != NULL);
    //  store to address provided with chan_recv call
    memoryCopy(dstelemptr, srcelemptr, c->elemsize);
    atomicStorePtrExplicit(&recvt->elemptr, NULL, memory_order_relaxed); // clear pointer (TODO: is this really needed?)

    chan_unlock(&c->lock);
    thr_signal(recvt); // wake up chan_recv caller
    return true;
}

// Internal send implementation used by blocking and try-send APIs.
inline static bool chan_send(wchan_t *c, void *srcelemptr, bool *closed)
{
    bool block = closed == NULL;
    chan_trace(block ? "send" : "try send", c);

    // fast path for non-blocking send on full channel
    //
    // From Go's chan implementation from which this logic is borrowed:
    // After observing that the channel is not closed, we observe that the channel is
    // not ready for sending. Each of these observations is a single word-sized read
    // (first c.closed and second chan_full()).
    // Because a closed channel cannot transition from 'ready for sending' to
    // 'not ready for sending', even if the channel is closed between the two observations,
    // they imply a moment between the two when the channel was both not yet closed
    // and not ready for sending. We behave as if we observed the channel at that moment,
    // and report that the send cannot proceed.
    //
    // It is okay if the reads are reordered here: if we observe that the channel is not
    // ready for sending and then observe that it is not closed, that implies that the
    // channel wasn't closed during the first observation. However, nothing here
    // guarantees forward progress. We rely on the side effects of lock release in
    // chan_recv() and wchan_Close() to update this thread's view of c.closed and chan_full().
    if (! block && ! atomicLoadExplicit(&c->closed, memory_order_relaxed) && chan_full(c))
    {
#ifdef WCHAN_TEST_HOOKS
        if (wchan_after_try_send_fast_full_hook != NULL)
        {
            wchan_after_try_send_fast_full_hook(c, wchan_after_try_send_fast_full_context);
        }
#endif
        return false;
    }

    chan_lock(&c->lock);

    if (UNLIKELY(atomicLoadExplicit(&c->closed, memory_order_relaxed)))
    {
        chan_unlock(&c->lock);
        if (block)
        {
            printError("send on closed channel");
            abortProgramNow(1);
        }
        else
        {
            *closed = true;
        }
        return false;
    }

    Thr *recvt = wq_dequeue(&c->recvq);
    if (recvt)
    {
        // Found a waiting receiver. recvt is blocked, waiting in chan_recv.
        // We pass the value we want to send directly to the receiver,
        // bypassing the channel buffer (if any).
        // Note that chan_send_direct calls chan_unlock(&c->lock).
        assert(recvt->init);
        return chan_send_direct(c, srcelemptr, recvt);
    }

    const uint32_t qlen = atomicLoadU32Explicit(&c->qlen, memory_order_relaxed);
    if (qlen < c->qcap)
    {
        // space available in message buffer -- enqueue
        const uint32_t i = c->sendx;
        // copy *srcelemptr -> *dstelemptr
        void *dstelemptr = chan_bufptr(c, i);
        memoryCopy(dstelemptr, srcelemptr, c->elemsize);
        c->sendx = i == c->qcap - 1 ? 0 : i + 1;
        // Publish the copied ring element after it is fully initialized.
        atomicStoreU32Explicit(&c->qlen, qlen + 1, memory_order_relaxed);
        chan_unlock(&c->lock);
        return true;
    }

    // buffer is full and there is no waiting receiver
    if (! block)
    {
        chan_unlock(&c->lock);
        return false;
    }

    // park the calling thread. Some recv caller will wake us up.
    // Note that chan_park calls chan_unlock(&c->lock)
    Thr *t = chan_park(c, &c->sendq, srcelemptr);

    // woken up by a receiver or by close. Like chan_recv, check "closed" on the Thr and not
    // on the wchan_t: a message handed to a receiver right before the close still counts as
    // sent, while a canceled send never delivered anything and must not report success.
    if (UNLIKELY(atomicLoadExplicit(&t->closed, memory_order_relaxed)))
    {
        if (! block)
        {
            *closed = true;
        }
        return false;
    }

    return true;
}

// chan_empty reports whether a read from c would block (that is, the channel is empty).
// It uses a single atomic read of mutable state.
inline static bool chan_empty(wchan_t *c)
{
    // Note: qcap is immutable
    if (c->qcap == 0)
        return atomicLoadPtrExplicit(&c->sendq.first, memory_order_relaxed) == NULL;
    return atomicLoadU32Explicit(&c->qlen, memory_order_relaxed) == 0;
}

// chan_empty_ordered is chan_empty for the lock-free try-recv path, where the result has to
// be ordered against the c->closed observation made next to it. Relaxed loads carry no such
// order: a weakly ordered CPU may satisfy the closed load ahead of the queue load, and the
// compiler is free to reuse one queue load for both calls, either of which would report
// "closed and empty" while a buffered message is still there. Sequentially consistent loads
// are plain loads on x86 and a load-acquire on arm64, so the fast path stays cheap.
inline static bool chan_empty_ordered(wchan_t *c)
{
    if (c->qcap == 0)
        return atomicLoadPtrExplicit(&c->sendq.first, memory_order_seq_cst) == NULL;
    return atomicLoadU32Explicit(&c->qlen, memory_order_seq_cst) == 0;
}

static bool chan_recv_direct(wchan_t *c, void *dstelemptr, Thr *st);

// Internal receive implementation used by blocking and try-recv APIs.
inline static bool chan_recv(wchan_t *c, void *dstelemptr, bool *closed)
{
    bool block = closed == NULL; // TODO: non-blocking path
    chan_trace(block ? "receive" : "try receive", c);

    // Fast path: check for failed non-blocking operation without acquiring the lock.
    if (! block && chan_empty_ordered(c))
    {
        // After observing that the channel is not ready for receiving, we observe whether the
        // channel is closed.
        //
        // Reordering of these checks could lead to incorrect behavior when racing with a close.
        // For example, if the channel was open and not empty, was closed, and then drained,
        // reordered reads could incorrectly indicate "open and empty". To prevent reordering,
        // we use atomic loads for both checks, and rely on emptying and closing to happen in
        // separate critical sections under the same lock.  This assumption fails when closing
        // an unbuffered channel with a blocked send, but that is an error condition anyway.
        if (atomicLoadExplicit(&c->closed, memory_order_seq_cst) == false)
        {
            // Because a channel cannot be reopened, the later observation of the channel
            // being not closed implies that it was also not closed at the moment of the
            // first observation. We behave as if we observed the channel at that moment
            // and report that the receive cannot proceed.
            return false;
        }
        // The channel is irreversibly closed. Re-check whether the channel has any pending data
        // to receive, which could have arrived between the empty and closed checks above.
        // Sequential consistency is also required here, when racing with such a send.
        if (chan_empty_ordered(c))
        {
            // The channel is irreversibly closed and empty
            memoryZero(dstelemptr, c->elemsize);
            *closed = true;
            return false;
        }
    }

    chan_lock(&c->lock);

    if (atomicLoadExplicit(&c->closed, memory_order_relaxed) &&
        (atomicLoadU32Explicit(&c->qlen, memory_order_relaxed) == 0))
    {
        // channel is closed and the buffer queue is empty
        chan_unlock(&c->lock);
        memoryZero(dstelemptr, c->elemsize);
        if (closed)
            *closed = true;
        return false;
    }

    Thr *t = wq_dequeue(&c->sendq);
    if (t)
    {
        // Found a waiting sender.
        // If buffer is size 0, receive value directly from sender.
        // Otherwise, receive from head of queue and add sender's value to the tail of the queue
        // (both map to the same buffer slot because the queue is full).
        // Note that chan_recv_direct calls chan_unlock(&c->lock).
        assert(t->init);
        return chan_recv_direct(c, dstelemptr, t);
    }

    const uint32_t qlen = atomicLoadU32Explicit(&c->qlen, memory_order_relaxed);
    if (qlen > 0)
    {
        // Receive directly from queue
        const uint32_t i = c->recvx;
        c->recvx         = i == c->qcap - 1 ? 0 : i + 1;

        // copy *srcelemptr -> *dstelemptr
        void *srcelemptr = chan_bufptr(c, i);
        memoryCopy(dstelemptr, srcelemptr, c->elemsize);
#ifdef DEBUG
        memoryZero(srcelemptr, c->elemsize); // zero buffer memory
#endif

        // The item has been copied before a lockless probe may observe space.
        atomicStoreU32Explicit(&c->qlen, qlen - 1, memory_order_relaxed);

        chan_unlock(&c->lock);
        return true;
    }

    // No message available -- nothing queued and no waiting senders
    if (! block)
    {
        chan_unlock(&c->lock);
        return false;
    }

    // Check if the channel is closed.
    if (atomicLoadExplicit(&c->closed, memory_order_relaxed))
    {
        chan_unlock(&c->lock);
        goto ret_closed;
    }

    // Block by parking the thread. Some send caller will wake us up.
    // Note that chan_park calls chan_unlock(&c->lock)
    t = chan_park(c, &c->recvq, dstelemptr);

    // woken up by sender or close call
    if (atomicLoadExplicit(&t->closed, memory_order_relaxed))
    {
        // Note that we check "closed" on the Thr, not the wchan_t.
        // This is important since c->closed may be true even as we receive a message.
        goto ret_closed;
    }

    // message was delivered by storing to elemptr by some sender
    return true;

ret_closed:
    memoryZero(dstelemptr, c->elemsize);
    return false;
}

// chan_recv_direct processes a receive operation on a full channel c
// Receives from a waiting sender, with special handling for buffered channels.
static bool chan_recv_direct(wchan_t *c, void *dstelemptr, Thr *sendert)
{
    // There are 2 parts:
    // 1) The value sent by the sender sg is put into the channel and the sender
    //    is woken up to go on its merry way.
    // 2) The value received by the receiver (the current G) is written to ep.
    // For synchronous (unbuffered) channels, both values are the same.
    // For asynchronous (buffered) channels, the receiver gets its data from
    // the channel buffer and the sender's data is put in the channel buffer.
    // wchan_nel c must be full and locked.
    // sendert must already be dequeued from c.sendq.
    bool ok = true;

    if (atomicLoadU32Explicit(&c->qlen, memory_order_relaxed) == 0)
    {
        // Copy data from sender
        void *srcelemptr = atomicLoadPtrExplicit(&sendert->elemptr, memory_order_consume);
        assert(srcelemptr != NULL);
        memoryCopy(dstelemptr, srcelemptr, c->elemsize);
    }
    else
    {
        // Queue is full. Take the item at the head of the queue.
        // Make the sender enqueue its item at the tail of the queue.
        // Since the queue is full, those are both the same slot.

        // copy element from queue to receiver
        const uint32_t i = c->recvx;
        if (i == c->qcap - 1)
        {
            c->recvx = 0;
            c->sendx = 0;
        }
        else
        {
            c->recvx = i + 1;
            c->sendx = i + 1;
        }

        // copy c->buf[i] -> *dstelemptr
        void *bufelemptr = chan_bufptr(c, i);
        assert(bufelemptr != NULL);
        memoryCopy(dstelemptr, bufelemptr, c->elemsize);

        // copy *sendert->elemptr -> c->buf[i]
        void *srcelemptr = atomicLoadPtrExplicit(&sendert->elemptr, memory_order_consume);
        assert(srcelemptr != NULL);
        memoryCopy(bufelemptr, srcelemptr, c->elemsize);
    }

    chan_unlock(&c->lock);
    thr_signal(sendert); // wake up chan_send caller
    return ok;
}

wchan_t *chanTryOpen(size_t elemsize, uint32_t cap)
{
    if (elemsize != 0 && (size_t) cap > (SIZE_MAX / elemsize))
    {
        return NULL;
    }
    const size_t buffer_size = ((size_t) cap) * elemsize;

    if (buffer_size > (SIZE_MAX - sizeof(wchan_t)))
    {
        return NULL;
    }
    const size_t required_size = sizeof(wchan_t) + buffer_size;

    // allocate memory, placing wchan_t at a line cache address boundary
    wchan_t *c = memoryAllocateCacheAlignedZero(required_size);
    if (c == NULL)
    {
        return NULL;
    }

    c->elemsize = elemsize;
    c->qcap     = cap;
    chan_lock_init(&c->lock);

    chan_trace("open", c);

    return c;
}

wchan_t *chanOpen(size_t elemsize, uint32_t cap)
{
    wchan_t *channel = chanTryOpen(elemsize, cap);
    if (UNLIKELY(channel == NULL))
    {
        printError("channel geometry is unrepresentable");
        abortProgramNow(1);
    }
    return channel;
}

void chanClose(wchan_t *c)
{
    chan_trace("close", c);

    chan_lock(&c->lock);

    // Sequentially consistent, not acquire: the acquire half of an exchange orders nothing
    // for the store, and lock-free readers of c->closed observe this store without taking
    // the lock, so they need it ordered against the queue state written before the close.
    if (atomicExchangeExplicit(&c->closed, 1, memory_order_seq_cst) != 0)
    {
        printError("close of closed channel");
        abortProgramNow(1);
    }

    wq_cancel_all(&c->recvq);
    wq_cancel_all(&c->sendq);

    chan_unlock(&c->lock);
}

void chanFree(wchan_t *c)
{
    const bool closed = atomicLoadExplicit(&c->closed, memory_order_acquire);
    assert(closed); // must close channel before freeing its memory
    if (UNLIKELY(! closed))
    {
        printError("chanFree: channel must be closed before freeing its memory");
        abortProgramNow(1);
    }
    chan_lock_destroy(&c->lock);
    memoryFreeAligned(c);
}

uint32_t chanCap(const wchan_t *c)
{
    return c->qcap;
}
bool chanSend(wchan_t *c, void *elemptr)
{
    return chan_send(c, elemptr, NULL);
}
bool chanRecv(wchan_t *c, void *elemptr)
{
    return chan_recv(c, elemptr, NULL);
}
bool chanTrySend(wchan_t *c, void *elemptr, bool *closed)
{
    return chan_send(c, elemptr, closed);
}
bool chanTryRecv(wchan_t *c, void *elemptr, bool *closed)
{
    return chan_recv(c, elemptr, closed);
}

#ifdef WCHAN_TEST_HOOKS
uint32_t chanWaiterCount(wchan_t *c, bool senders)
{
    chan_lock(&c->lock);
    uint32_t count = 0;
    Thr     *t     = atomicLoadPtrExplicit(senders ? &c->sendq.first : &c->recvq.first, memory_order_acquire);
    while (t)
    {
        count++;
        t = t->next;
    }
    chan_unlock(&c->lock);
    return count;
}
#endif
