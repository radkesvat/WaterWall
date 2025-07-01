#include "wchan.h"
#include "watomic.h"
#include "wmutex.h"

// DEBUG_CHAN_LOG: define to enable debug logging of send and recv
// #define DEBUG_CHAN_LOG

// DEBUG_CHAN_LOCK: define to enable debug logging of channel locks
// #define DEBUG_CHAN_LOCK

// kCpuLineCacheSize is the size of a cache line of the target CPU.
// The value 64 covers i386, x86_64, arm32, arm64.
// Note that Intel TBB uses 128 (max_nfs_size).
// TODO: set value depending on target preprocessor information.

typedef _Atomic(unsigned int)       atomic_uint32_t;
typedef _Atomic(unsigned long long) atomic_uint64_t;
typedef _Atomic(unsigned long long) atomic_size_t_t;
typedef _Atomic(long long)          atomic_ssize_t;
typedef _Atomic(unsigned char)      atomic_uint8_t;

// ----------------------------------------------------------------------------
// debugging

#if defined(DEBUG_CHAN_LOG) && ! defined(DEBUG)
#undef DEBUG_CHAN_LOG
#endif
#ifdef DEBUG_CHAN_LOG
#define THREAD_ID_INVALID SIZE_MAX

static size_t thread_id()
{
    static thread_local size_t _thread_id         = THREAD_ID_INVALID;
    static atomic_size         _thread_id_counter = (0);
    size_t                     tid                = _thread_id;
    if (tid == THREAD_ID_INVALID)
    {
        tid        = atomicAddExplicit(&_thread_id_counter, 1);
        _thread_id = tid;
    }
    return tid;
}

static const char *tcolor()
{
    static const char *colors[] = {
        //"\x1b[1m",  // bold (white)
        "\x1b[93m", // yellow
        "\x1b[92m", // green
        "\x1b[91m", // red
        "\x1b[94m", // blue
        "\x1b[96m", // cyan
        "\x1b[95m", // magenta
    };
    return colors[thread_id() % countof(colors)];
}

// _//dlog_chan writes a log message to stderr along with a globally unique "causality"
// sequence number. It does not use libc FILEs as those use mutex locks which would alter
// the behavior of multi-threaded channel operations. Instead it uses a buffer on the stack,
// which of course is local per thread and then calls the write syscall with the one buffer.
// This all means that log messages may be out of order; use the "causality" sequence number
// to understand what other messages were produced according to the CPU.
ATTR_FORMAT(printf, 2, 3)
static void _                             // dlog_chan(const char* fname, const char* fmt, ...) {
    static atomic_uint32_t seqnext = (1); // start at 1 to map to line nubmers

uint32_t seq = atomic_fetch_add_explicitx(&seqnext, 1, memory_order_acquire);

char          buf[256];
const ssize_t sbufGetTotalCapacity = (ssize_t) sizeof(buf);
ssize_t       buflen               = 0;

buflen += (ssize_t) snprintf(&buf[buflen], sbufGetTotalCapacity - buflen, "%04u \x1b[1m%sT%02zu ", seq, tcolor(),
                             thread_id());

va_list ap;
va_start(ap, fmt);
buflen += (ssize_t) vsnprintf(&buf[buflen], sbufGetTotalCapacity - buflen, fmt, ap);
va_end(ap);

if (buflen > 0)
{
    buflen += (ssize_t) snprintf(&buf[buflen], sbufGetTotalCapacity - buflen, "\x1b[0m (%s)\n", fname);
    if (buflen >= sbufGetTotalCapacity)
    {
        // truncated; make sure to end the line
        buf[buflen - 1] = '\n';
    }
}

#undef FMT
write(STDERR_FILENO, buf, buflen);
}

#define dlog_chan(fmt, ...) _ // dlog_chan(__FUNCTION__, fmt, ##__VA_ARGS__)
#define dlog_send(fmt, ...)   // dlog_chan("send: " fmt, ##__VA_ARGS__)
#define dlog_recv(fmt, ...)   // dlog_chan("recv: " fmt, ##__VA_ARGS__)
// #define dlog_send(fmt, ...) do{}while(0)
// #define dlog_recv(fmt, ...) do{}while(0)
#else
#define dlog_chan(fmt, ...)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#define dlog_send(fmt, ...)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#define dlog_recv(fmt, ...)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#endif

// ----------------------------------------------------------------------------
// misc utils

#define is_power_of_two(intval) (intval) && (0 == ((intval) & ((intval) -1)))

// is_aligned checks if passed in pointer is aligned on a specific border.
// bool is_aligned<T>(T* pointer, uintptr_t alignment)
#define is_aligned(pointer, alignment) (0 == ((uintptr_t) (pointer) & (((uintptr_t) alignment) - 1)))

// -------------------------------------------------------------------------
// channel lock

#ifdef DEBUG_CHAN_LOCK
static uint32_t chlock_count = 0;

#define CHAN_LOCK_T             wmutex_t
#define chan_lock_init(lock)    mutexInit((lock), wmutex_plain)
#define chan_lock_destroy(lock) mutexDestroy(lock)

#define chan_lock(lock)                                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        uint32_t n = chlock_count++;                                                                                   \
        dlog("CL #%u LOCK %s:%d", n, __FILE__, __LINE__);                                                              \
        mutexLock(lock);                                                                                               \
        dlog("CL #%u UNLOCK %s:%d", n, __FILE__, __LINE__);                                                            \
    } while (0)

#define chan_unlock(lock)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        /*dlog("CL UNLOCK %s:%d", __FILE__, __LINE__);*/                                                               \
        mutexUnlock(lock);                                                                                             \
    } while (0)
#else
// // wmutex_t
// #define CHAN_LOCK_T             wmutex_t
// #define chan_lock_init(lock)    mutexInit((lock), wmutex_plain)
// #define chan_lock_destroy(lock) mutexDestroy(lock)
// #define chan_lock(lock)         mutexLock(lock)
// #define chan_unlock(lock)       mutexUnlock(lock)

// wmutex_
#define CHAN_LOCK_T             wmutex_t
#define chan_lock_init(lock)    mutexInit(lock)
#define chan_lock_destroy(lock) mutexDestroy(lock)
#define chan_lock(lock)         mutexLock(lock)
#define chan_unlock(lock)       mutexUnlock(lock)
#endif

// -------------------------------------------------------------------------

typedef struct Thr Thr;

// Thr holds thread-specific data and is owned by thread-local storage

#ifdef COMPILER_MSVC
struct Thr
{
    size_t                            id;
    bool                              init;
    atomic_bool                       closed;
    wlsem_t                           sema;
    MSVC_ATTR_ALIGNED_LINE_CACHE Thr *next; // list link
    void                             *elemptr;
};

typedef struct WaitQ
{
    Thr *first; // head of linked list of parked threads
    Thr *last;  // tail of linked list of parked threads
} WaitQ;
#else

struct Thr
{
    size_t          id;
    bool            init;
    atomic_bool     closed;
    wlsem_t         sema;
    Thr *next       GNU_ATTR_ALIGNED_LINE_CACHE; // list link
    _Atomic(void *) elemptr;
};

typedef struct WaitQ
{
    _Atomic(Thr *) first; // head of linked list of parked threads
    _Atomic(Thr *) last;  // tail of linked list of parked threads
} WaitQ;

#endif

typedef MSVC_ATTR_ALIGNED_LINE_CACHE struct wchan_s
{
    // These fields don't change after wchan_Open
    uintptr_t memptr;   // memory allocation pointer
    size_t    elemsize; // size in bytes of elements sent on the channel
    uint32_t  qcap;     // size of the circular queue buf (immutable)

    // These fields are frequently accessed and stored to.
    // There's a perf opportunity here with a different more cache-efficient layout.
    atomic_uint32_t qlen;   // number of messages currently queued in buf
    atomic_bool     closed; // one way switch (once it becomes true, never becomes false again)
    CHAN_LOCK_T     lock;   // guards the wchan_t struct

    // sendq is accessed on every call to chan_recv and only in some cases by chan_send,
    // when parking a thread when there's no waiting receiver nor queued message.
    // recvq is accessed on every call to chan_send and like sendq, only when parking a thread
    // in chan_recv.
    WaitQ sendq; // list of waiting send callers
    WaitQ recvq; // list of waiting recv callers

    // sendx & recvx are likely to be falsely shared between threads.
    // - sendx is loaded & stored by both chan_send and chan_recv
    //   - chan_send for buffered channels when no receiver is waiting
    //   - chan_recv when there's a waiting sender
    // - recvx is only used by chan_recv
    // So we make sure recvx ends up on a separate cache line.
    atomic_uint32_t sendx;

    // send index in buf
    MSVC_ATTR_ALIGNED_LINE_CACHE atomic_uint32_t recvx GNU_ATTR_ALIGNED_LINE_CACHE; // receive index in buf

    // uint8_t pad[kCpuLineCacheSize];
    uint8_t buf[]; // queue storage
} GNU_ATTR_ALIGNED_LINE_CACHE wchan_t;

static void thr_init(Thr *t)
{
    static atomic_size_t _thread_id_counter = (0);

    t->id   = atomicAddExplicit(&_thread_id_counter, 1, memory_order_relaxed);
    t->init = true;
    leightweightsemaphoreInit(&t->sema, 0); // TODO: Semadestroy?
}

inline static Thr *thr_current(void)
{
    static thread_local Thr _thr = {0};

    Thr *t = &_thr;
    if (UNLIKELY(! t->init))
        thr_init(t);
    return t;
}

inline static void thr_signal(Thr *t)
{
    leightweightsemaphoreSignal(&t->sema, 1); // wake
}

inline static void thr_wait(Thr *t)
{
    // dlog_chan("thr_wait ...");
    leightweightsemaphoreWait(&t->sema); // sleep
}

static void wq_enqueue(WaitQ *wq, Thr *t)
{
    // note: atomic loads & stores for cache reasons, not thread safety; c->lock is held.
    if (atomicLoadExplicit(&wq->first, memory_order_acquire))
    {
        // Note: compare first instead of last as we don't clear wq->last in wq_dequeue
        atomicLoadExplicit(&wq->last, memory_order_acquire)->next = t;
    }
    else
    {
        atomicStoreExplicit(&wq->first, t, memory_order_release);
    }
    atomicStoreExplicit(&wq->last, t, memory_order_release);
}

static inline Thr *wq_dequeue(WaitQ *wq)
{
    Thr *t = atomicLoadExplicit(&wq->first, memory_order_acquire);
    if (t)
    {
        atomicStoreExplicit(&wq->first, t->next, memory_order_release);
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

// chan_park adds elemptr to wait queue wq, unlocks channel c and blocks the calling thread
static Thr *chan_park(wchan_t *c, WaitQ *wq, void *elemptr)
{
    // caller must hold lock on channel that owns wq
    Thr *t = thr_current();
    atomicStoreExplicit(&t->elemptr, elemptr, memory_order_relaxed);
    // dlog_chan("park: elemptr %p", elemptr);
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
        return atomicLoadExplicit(&c->recvq.first, memory_order_relaxed) == NULL;
    return atomicLoadExplicit(&c->qlen, memory_order_relaxed) == c->qcap;
}

static bool chan_send_direct(wchan_t *c, void *srcelemptr, Thr *recvt)
{
    // chan_send_direct processes a send operation on an empty channel c.
    // element sent by the sender is copied to the receiver recvt.
    // The receiver is then woken up to go on its merry way.
    // wchan_nel c must be empty and locked. This function unlocks c with chan_unlock.
    // recvt must already be dequeued from c.

    void *dstelemptr = atomicLoadExplicit(&recvt->elemptr, memory_order_acquire);
    assert(dstelemptr != NULL);
    // dlog_send("direct send of srcelemptr %p to [%zu] (dstelemptr %p)", srcelemptr, recvt->id, dstelemptr);
    //  store to address provided with chan_recv call
    memoryCopy(dstelemptr, srcelemptr, c->elemsize);
    atomicStoreExplicit(&recvt->elemptr, NULL, memory_order_relaxed); // clear pointer (TODO: is this really needed?)

    chan_unlock(&c->lock);
    thr_signal(recvt); // wake up chan_recv caller
    return true;
}

inline static bool chan_send(wchan_t *c, void *srcelemptr, bool *closed)
{
    bool block = closed == NULL;
    // dlog_send("srcelemptr %p", srcelemptr);

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
    if (! block && ! c->closed && chan_full(c))
        return false;

    chan_lock(&c->lock);

    if (UNLIKELY(atomicLoadExplicit(&c->closed, memory_order_relaxed)))
    {
        chan_unlock(&c->lock);
        if (block)
        {
            printError("send on closed channel");
            terminateProgram(1);
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

    if (atomicLoadExplicit(&c->qlen, memory_order_relaxed) < c->qcap)
    {
        // space available in message buffer -- enqueue
        uint32_t i = (uint32_t) atomicAddExplicit(&c->sendx, 1, memory_order_relaxed);
        // copy *srcelemptr -> *dstelemptr
        void *dstelemptr = chan_bufptr(c, i);
        memoryCopy(dstelemptr, srcelemptr, c->elemsize);
        // dlog_send("enqueue elemptr %p at buf[%u]", srcelemptr, i);
        if (i == c->qcap - 1)
            atomicStoreExplicit(&c->sendx, 0, memory_order_relaxed);
        atomicAddExplicit(&c->qlen, 1, memory_order_relaxed);
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
    // dlog_send("wait... (elemptr %p)", srcelemptr);
    chan_park(c, &c->sendq, srcelemptr);
    // dlog_send("woke up -- sent elemptr %p", srcelemptr);
    return true;
}

// chan_empty reports whether a read from c would block (that is, the channel is empty).
// It uses a single atomic read of mutable state.
inline static bool chan_empty(wchan_t *c)
{
    // Note: qcap is immutable
    if (c->qcap == 0)
        return atomicLoadExplicit(&c->sendq.first, memory_order_relaxed) == NULL;
    return atomicLoadExplicit(&c->qlen, memory_order_relaxed) == 0;
}

static bool chan_recv_direct(wchan_t *c, void *dstelemptr, Thr *st);

inline static bool chan_recv(wchan_t *c, void *dstelemptr, bool *closed)
{
    bool block = closed == NULL; // TODO: non-blocking path
    // dlog_recv("dstelemptr %p", dstelemptr);

    // Fast path: check for failed non-blocking operation without acquiring the lock.
    if (! block && chan_empty(c))
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
        if (atomicLoadExplicit(&c->closed, memory_order_relaxed) == false)
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
        if (chan_empty(c))
        {
            // The channel is irreversibly closed and empty
            memorySet(dstelemptr, 0, c->elemsize);
            *closed = true;
            return false;
        }
    }

    chan_lock(&c->lock);

    if (atomicLoadExplicit(&c->closed, memory_order_relaxed) &&
        (atomicLoadExplicit(&c->qlen, memory_order_relaxed) == 0))
    {
        // channel is closed and the buffer queue is empty
        // dlog_recv("channel closed & empty queue");
        chan_unlock(&c->lock);
        memorySet(dstelemptr, 0, c->elemsize);
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

    if (atomicLoadExplicit(&c->qlen, memory_order_relaxed) > 0)
    {
        // Receive directly from queue
        uint32_t i = (uint32_t) atomicAddExplicit(&c->recvx, 1, memory_order_relaxed);
        if (i == c->qcap - 1)
            atomicStoreExplicit(&c->recvx, 0, memory_order_relaxed);
        atomicSubExplicit(&c->qlen, 1, memory_order_relaxed);

        // copy *srcelemptr -> *dstelemptr
        void *srcelemptr = chan_bufptr(c, i);
        memoryCopy(dstelemptr, srcelemptr, c->elemsize);
#ifdef DEBUG
        memorySet(srcelemptr, 0, c->elemsize); // zero buffer memory
#endif

        // dlog_recv("dequeue elemptr %p from buf[%u]", srcelemptr, i);

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
    // dlog_recv("wait... (elemptr %p)", dstelemptr);
    t = chan_park(c, &c->recvq, dstelemptr);

    // woken up by sender or close call
    if (atomicLoadExplicit(&t->closed, memory_order_relaxed))
    {
        // Note that we check "closed" on the Thr, not the wchan_t.
        // This is important since c->closed may be true even as we receive a message.
        // dlog_recv("woke up -- channel closed");
        goto ret_closed;
    }

    // message was delivered by storing to elemptr by some sender
    // dlog_recv("woke up -- received to elemptr %p", dstelemptr);
    return true;

ret_closed:
    // dlog_recv("channel closed");
    memorySet(dstelemptr, 0, c->elemsize);
    return false;
}

// chan_recv_direct processes a receive operation on a full channel c
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

    if (atomicLoadExplicit(&c->qlen, memory_order_relaxed) == 0)
    {
        // Copy data from sender
        void *srcelemptr = atomicLoadExplicit(&sendert->elemptr, memory_order_consume);
        // dlog_recv("direct recv of srcelemptr %p from [%zu] (dstelemptr %p, buffer empty)", srcelemptr, sendert->id,
        // dstelemptr);
        assert(srcelemptr != NULL);
        memoryCopy(dstelemptr, srcelemptr, c->elemsize);
    }
    else
    {
        // Queue is full. Take the item at the head of the queue.
        // Make the sender enqueue its item at the tail of the queue.
        // Since the queue is full, those are both the same slot.
        // dlog_recv("direct recv from [%zu] (dstelemptr %p, buffer full)", sendert->id, dstelemptr);
        // assert_debug(atomicLoadExplicit(&c->qlen) == c->qcap); // queue is full

        // copy element from queue to receiver
        uint32_t i = (uint32_t) atomicAddExplicit(&c->recvx, 1, memory_order_relaxed);
        if (i == c->qcap - 1)
        {
            atomicStoreExplicit(&c->recvx, 0, memory_order_relaxed);
            atomicStoreExplicit(&c->sendx, 0, memory_order_relaxed);
        }
        else
        {
            atomicStoreExplicit(&c->sendx, i + 1, memory_order_relaxed);
        }

        // copy c->buf[i] -> *dstelemptr
        void *bufelemptr = chan_bufptr(c, i);
        assert(bufelemptr != NULL);
        memoryCopy(dstelemptr, bufelemptr, c->elemsize);
        // dlog_recv("dequeue srcelemptr %p from buf[%u]", bufelemptr, i);

        // copy *sendert->elemptr -> c->buf[i]
        void *srcelemptr = atomicLoadExplicit(&sendert->elemptr, memory_order_consume);
        assert(srcelemptr != NULL);
        memoryCopy(bufelemptr, srcelemptr, c->elemsize);
        // dlog_recv("enqueue srcelemptr %p to buf[%u]", srcelemptr, i);
    }

    chan_unlock(&c->lock);
    thr_signal(sendert); // wake up chan_send caller
    return ok;
}

wchan_t *chanOpen(size_t elemsize, uint32_t cap)
{
    size_t memsize = sizeof(wchan_t) + (cap * elemsize);

    // ensure we have enough space to offset the allocation by line cache (for alignment)
    memsize = ALIGN2(memsize + ((kCpuLineCacheSize + 1) / 2), kCpuLineCacheSize);

    // check for overflow
    if (memsize < sizeof(wchan_t))
    {
        printError("buffer size out of range");
        terminateProgram(1);
    }

    // allocate memory, placing wchan_t at a line cache address boundary
    uintptr_t ptr = (uintptr_t) memoryAllocate(memsize);
    memorySet((void *) ptr, 0, memsize);

    // align c to line cache boundary
    wchan_t *c = (wchan_t *) ALIGN2(ptr, kCpuLineCacheSize);

    c->memptr   = ptr;
    c->elemsize = elemsize;
    c->qcap     = cap;
    chan_lock_init(&c->lock);

// make sure that the thread setting up the channel gets a low thread_id
#ifdef DEBUG_CHAN_LOG
    thread_id();
#endif

    return c;
}

void chanClose(wchan_t *c)
{
    // dlog_chan("--- close ---");

    chan_lock(&c->lock);
    // dlog_chan("close: channel locked");

    if (atomicExchangeExplicit(&c->closed, 1, memory_order_acquire) != 0)
    {
        printError("close of closed channel");
        terminateProgram(1);
    }
    atomic_thread_fence(memory_order_seq_cst);

    Thr *t = atomicLoadExplicit(&c->recvq.first, memory_order_acquire);
    while (t)
    {
        // dlog_chan("close: wake recv [%zu]", t->id);
        Thr *next = t->next;
        atomicStoreExplicit(&t->closed, true, memory_order_relaxed);
        thr_signal(t);
        t = next;
    }

    t = atomicLoadExplicit(&c->sendq.first, memory_order_acquire);
    while (t)
    {
        // dlog_chan("close: wake send [%zu]", t->id);
        Thr *next = t->next;
        atomicStoreExplicit(&t->closed, true, memory_order_relaxed);
        thr_signal(t);
        t = next;
    }

    chan_unlock(&c->lock);
    // dlog_chan("close: done");
}

void chanFree(wchan_t *c)
{
    assert(atomicLoadExplicit(&c->closed, memory_order_acquire)); // must close channel before freeing its memory
    chan_lock_destroy(&c->lock);
    memoryFree((void *) c->memptr);
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
