#ifndef WW_EVENT_H_
#define WW_EVENT_H_

#include "iowatcher.h"
#include "wloop.h"

#include "hbuf.h"
#include "wmutex.h"

#include "array.h"
#include "buffer_pool.h"
#include "heap.h"
#include "list.h"
#include "queue.h"

// #define WLOOP_READ_BUFSIZE          (1U << 15)  // 32K
#define READ_BUFSIZE_HIGH_WATER  (1U << 20) // 1M
#define WRITE_BUFSIZE_HIGH_WATER (1U << 23) // 8M
#define MAX_WRITE_BUFSIZE        (1U << 24) // 16M

// wio_read_flags
#define WIO_READ_ONCE         0x1
#define WIO_READ_UNTIL_LENGTH 0x2
#define WIO_READ_UNTIL_DELIM  0x4

ARRAY_DECL(wio_t *, io_array)
QUEUE_DECL(wevent_t, event_queue)

#ifdef EVENT_IOCP
// Forward declaration to avoid an include cycle with overlapio.h; the concrete
// woverlapped_t layout lives there.
struct woverlapped_s;
#endif

struct wloop_s
{
    uint32_t   flags;
    atomic_int status;
    // Shutdown-control level trigger. The worker control mutex publishes the
    // lifecycle context; the wake descriptor supplies progress only.
    atomic_bool stop_requested;
    atomic_bool normal_admission_open;
    uint64_t    start_ms;     // ms
    uint64_t    start_hrtime; // us
    uint64_t    end_hrtime;
    uint64_t    cur_hrtime;
    uint64_t    cur_time;    // s
    uint64_t    cur_time_ms; // ms
    uint64_t    cur_time_us; // us
    uint64_t    loop_cnt;
    long        pid;
    long        wid;
    void       *userdata;
    // private:
    //  events
    uint32_t intern_nevents;
    uint32_t nactives;
    uint32_t npendings;
    // pendings: with priority as array.index
    wevent_t *pendings[WEVENT_PRIORITY_SIZE];
    // idles
    struct list_head idles;
    uint32_t         nidles;
    // timers
    struct heap      timers;     // monotonic time
    struct heap      realtimers; // realtime
    struct list_head quiesced_timers;
    uint32_t         ntimers;
    // ios: with fd as array.index
    struct io_array ios;
    uint32_t        nios;
    // one loop per thread, so one readbuf per loop is OK. operates on large mode by default.
    buffer_pool_t *bufpool;
    void          *iowatcher;
#ifdef EVENT_IOCP
    // Native IOCP loop-wide accounting. Used by loop shutdown to drain kernel
    // references before freeing memory, and by tests to assert a clean baseline.
    uint32_t iocp_live_operations;   // records still referenced by the kernel or dispatch
    uint32_t iocp_posted_operations; // records currently posted to the kernel
#endif
    // custom_events
    // custom_events_mutex protects eventfds, both custom event queues,
    // control_admission_open, wakeup_pending, and wake-channel initialization.
    // wakeup_pending means that one readiness notification is armed for the
    // loop; it is not a count of queued events.
    int         eventfds[2];
    bool        wakeup_pending;
    bool        control_admission_open;
    event_queue custom_events;
    event_queue control_events;
    // Serializes the final positive decision for every normal asynchronous
    // root with admission closure.
    wmutex_t normal_admission_mutex;
    wmutex_t custom_events_mutex;
};

uint64_t wloopGetNextEventID(void);

struct widle_s
{
    WEVENT_FIELDS
    uint32_t repeat;
    // private:
    struct list_node node;
};

/* `fallible_allocation` records the matching release family for the internal
 * recoverable timer path. Normal public timers are zero-initialized here. */
#define WTIMER_FIELDS                                                                                                  \
    WEVENT_FIELDS                                                                                                      \
    uint32_t         repeat;                                                                                           \
    uint64_t         next_timeout;                                                                                     \
    struct heap_node node;                                                                                             \
    struct list_node quiesced_node;                                                                                    \
    unsigned         quiesced : 1;                                                                                     \
    unsigned         fallible_allocation : 1;

struct wtimer_s
{
    WTIMER_FIELDS
};

struct wtimeout_s
{
    WTIMER_FIELDS
    uint32_t timeout;
};

struct wperiod_s
{
    WTIMER_FIELDS
    int8_t minute;
    int8_t hour;
    int8_t day;
    int8_t week;
    int8_t month;
};

QUEUE_DECL(sbuf_t *, write_queue)

// sizeof(struct wio_s)=416 on linux-x64
struct wio_s
{
    WEVENT_FIELDS
    // flags
    unsigned ready : 1;
    unsigned connected : 1;
    unsigned closed : 1;
    unsigned accept : 1;
    unsigned connect : 1;
    unsigned connectex : 1; // for ConnectEx/DisconnectEx
    unsigned recv : 1;
    unsigned send : 1;
    unsigned recvfrom : 1;
    unsigned sendto : 1;
    unsigned close : 1;
    unsigned release_no_close : 1;
    // public:
    wio_type_e io_type;
    uint32_t   id; // fd cannot be used as unique identifier, so we provide an id
    // Descriptors are stored as int and used as dense-array indexes. Windows
    // SOCKET is unsigned and only documented to fit 32 bits -- not the positive
    // signed range -- so socketToFd() validates the signed range and wioGet()
    // rejects values above WIO_MAX_FD before storing or indexing them. Widen
    // back to SOCKET explicitly at any call taking the handle *by address* --
    // see SO_UPDATE_ACCEPT_CONTEXT in overlapio.c, where the option length is
    // derived from the value's type.
    int fd;
    // #if defined(OS_LINUX) && defined(HAVE_PIPE)
    //     int         pfd_r; // pipe read file descriptor for splice, (empty by default)
    //     int         pfd_w; // pipe read file descriptor for splice, (empty by default)
    // #endif
    int error;
    int events;
    int revents;

    union {
        struct sockaddr *localaddr;
        sockaddr_u      *localaddr_u;
    };
    union {
        struct sockaddr *peeraddr;
        sockaddr_u      *peeraddr_u;
    };

    uint64_t last_read_hrtime;
    uint64_t last_write_hrtime;
    // read
    unsigned int read_flags;
    // write
    struct write_queue write_queue;
    // wrecursive_mutex_t  write_mutex; // lock write and write_queue
    uint32_t write_bufsize;
    uint32_t max_write_bufsize;
    // callbacks
    wread_cb    read_cb;
    wwrite_cb   write_cb;
    wclose_cb   close_cb;
    waccept_cb  accept_cb;
    wconnect_cb connect_cb;
    // timers
    int                   connect_timeout;    // ms
    int                   close_timeout;      // ms
    int                   read_timeout;       // ms
    int                   write_timeout;      // ms
    int                   keepalive_timeout;  // ms
    int                   heartbeat_interval; // ms
    wio_send_heartbeat_fn heartbeat_fn;
    wtimer_t             *connect_timer;
    wtimer_t             *close_timer;
    wtimer_t             *read_timer;
    wtimer_t             *write_timer;
    wtimer_t             *keepalive_timer;
    wtimer_t             *heartbeat_timer;

// private:
#if defined(EVENT_POLL) || defined(EVENT_KQUEUE)
    int event_index[2]; // for poll,kqueue
#endif

#ifdef EVENT_IOCP
    // Native IOCP record tracking (replaces the old singleton io->hovlp).
    // Every posted overlapped operation owns one woverlapped_t. Records keep this
    // wio_t alive until their completion is dequeued and retired, so a callback
    // that closes/frees the io cannot invalidate an operation the kernel still
    // owns.
    struct woverlapped_s *iocp_posted_head; // doubly linked list: records in the kernel
    struct woverlapped_s *iocp_posted_tail;
    struct woverlapped_s *iocp_completed_head; // FIFO: dequeued, awaiting dispatch
    struct woverlapped_s *iocp_completed_tail;
    struct woverlapped_s *iocp_send_active;  // sole TCP send, posted or locally dispatching
    uint32_t              iocp_live_records; // records holding this wio_t alive
    uint32_t              iocp_posted_count; // records currently posted to the kernel
    // Listener-private AcceptEx capacity tracking. A transient immediate AcceptEx
    // failure must not permanently retire one of the listener's accept slots, so
    // the live slot count is tracked separately from the loop-wide record
    // counters (which also cover connect/receive/send work) and a bounded backoff
    // timer replenishes whatever is missing.
    uint32_t  iocp_accept_records;        // live AcceptEx records: posted, completed or dispatching
    wtimer_t *iocp_accept_retry_timer;    // one-shot replenishment timer, NULL when none is scheduled
    uint32_t  iocp_accept_retry_attempts; // consecutive failed replenishment rounds (backoff/budget)
    int       iocp_accept_last_error;     // last AcceptEx submission error, published on fatal failure
    unsigned  iocp_deferred_finalize : 1; // return to pool once records retire
    unsigned  iocp_pending_dispatch : 1;  // generic pending loop still holds its cursor
    unsigned  iocp_close_in_progress : 1; // wioClose still owns a stack reference
    unsigned  iocp_associated : 1;        // socket handle is already bound to this loop's IOCP
#endif
};
/*
 * wio lifeline:
 *
 * fd =>
 * wioGet => EVENTLOOP_ALLOC_SIZEOF(io) => wioInit => wioReady
 *
 * wioRead  => wioAdd(WW_READ) => wioReadCallBack
 * wioWrite => wioAdd(WW_WRITE) => wioWriteCallBack
 * wioClose => wioDone => wioDel(WW_RDWR) => wioCloseCallBack
 *
 * wloopStop => wloopDestroy => wioFree => EVENTLOOP_FREE(io)
 */
void     wioInit(wio_t *io);
void     wioReady(wio_t *io);
void     wioDone(wio_t *io);
void     wioFree(wio_t *io);
uint32_t wioSetNextID(void);
#ifdef EVENT_IOCP
// Return a deferred-finalized wio_t (closed, detached, all IOCP records retired)
// to its worker pool. Called from the native IOCP retire path once the last
// operation record referencing this io has been dequeued and released.
void wioFinalizeNow(wio_t *io);
#endif

void wioAcceptCallBack(wio_t *io);
void wioConnectCallBack(wio_t *io);
void wioHandleRead(wio_t *io, sbuf_t *buf);
void wioReadCallBack(wio_t *io, sbuf_t *buf);
void wioWriteCallBack(wio_t *io);
void wioCloseCallBack(wio_t *io);

void wioDelConnectTimer(wio_t *io);
void wioDelCloseTimer(wio_t *io);
void wioDelReadTimer(wio_t *io);
void wioDelWriteTimer(wio_t *io);
void wioDelKeepaliveTimer(wio_t *io);
void wioDelHeartBeatTimer(wio_t *io);

#define EVENT_ENTRY(p) container_of(p, wevent_t, pending_node)
#define IDLE_ENTRY(p)  container_of(p, widle_t, node)
#define TIMER_ENTRY(p) container_of(p, wtimer_t, node)

#define EVENT_ACTIVE(ev)                                                                                               \
    if (! ev->active)                                                                                                  \
    {                                                                                                                  \
        ev->active = 1;                                                                                                \
        ev->loop->nactives++;                                                                                          \
    }

#define EVENT_INACTIVE(ev)                                                                                             \
    if (ev->active)                                                                                                    \
    {                                                                                                                  \
        ev->active = 0;                                                                                                \
        ev->loop->nactives--;                                                                                          \
    }

#define EVENT_PENDING(ev)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! ev->pending)                                                                                             \
        {                                                                                                              \
            ev->pending = 1;                                                                                           \
            ev->loop->npendings++;                                                                                     \
            wevent_t **phead = &ev->loop->pendings[WEVENT_PRIORITY_INDEX(ev->priority)];                               \
            ev->pending_next = *phead;                                                                                 \
            *phead           = (wevent_t *) ev;                                                                        \
        }                                                                                                              \
    } while (0)

#define EVENT_ADD(loop, ev, cb)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        ev->loop     = loop;                                                                                           \
        ev->event_id = wloopGetNextEventID();                                                                          \
        ev->cb       = (wevent_cb) cb;                                                                                 \
        EVENT_ACTIVE(ev);                                                                                              \
    } while (0)

#define EVENT_DEL(ev)                                                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        EVENT_INACTIVE(ev);                                                                                            \
        if (! ev->pending)                                                                                             \
        {                                                                                                              \
            EVENTLOOP_FREE(ev);                                                                                        \
        }                                                                                                              \
    } while (0)

#define EVENT_RESET(ev)                                                                                                \
    do                                                                                                                 \
    {                                                                                                                  \
        ev->destroy = 0;                                                                                               \
        EVENT_ACTIVE(ev);                                                                                              \
        ev->pending = 0;                                                                                               \
    } while (0)

#define EVENT_UNPENDING(ev)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        if (ev->pending)                                                                                               \
        {                                                                                                              \
            ev->pending = 0;                                                                                           \
            ev->loop->npendings--;                                                                                     \
        }                                                                                                              \
    } while (0)

#endif // WW_EVENT_H_
