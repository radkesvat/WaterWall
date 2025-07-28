#ifndef WW_EVENT_H_
#define WW_EVENT_H_

#include "wloop.h"
#include "iowatcher.h"

#include "hbuf.h"
#include "wmutex.h"

#include "array.h"
#include "list.h"
#include "heap.h"
#include "queue.h"
#include "buffer_pool.h"


// #define WLOOP_READ_BUFSIZE          (1U << 15)  // 32K
#define READ_BUFSIZE_HIGH_WATER     (1U << 20)  // 1M
#define WRITE_BUFSIZE_HIGH_WATER    (1U << 23)  // 8M
#define MAX_WRITE_BUFSIZE           (1U << 24)  // 16M

// wio_read_flags
#define WIO_READ_ONCE           0x1
#define WIO_READ_UNTIL_LENGTH   0x2
#define WIO_READ_UNTIL_DELIM    0x4

ARRAY_DECL(wio_t*, io_array)
QUEUE_DECL(wevent_t, event_queue)

struct wloop_s {
    uint32_t                    flags;
    wloop_status_e              status;
    uint64_t                    start_ms;       // ms
    uint64_t                    start_hrtime;   // us
    uint64_t                    end_hrtime;
    uint64_t                    cur_hrtime;
    uint64_t                    loop_cnt;
    long                        pid;
    long                        wid;
    void*                       userdata;
//private:
    // events
    uint32_t                    intern_nevents;
    uint32_t                    nactives;
    uint32_t                    npendings;
    // pendings: with priority as array.index
    wevent_t*                   pendings[WEVENT_PRIORITY_SIZE];
    // idles
    struct list_head            idles;
    uint32_t                    nidles;
    // timers
    struct heap                 timers;     // monotonic time
    struct heap                 realtimers; // realtime
    uint32_t                    ntimers;
    // ios: with fd as array.index
    struct io_array             ios;
    uint32_t                    nios;
    // one loop per thread, so one readbuf per loop is OK. operates on large mode by default.
    buffer_pool_t*              bufpool;
    void*                       iowatcher;
    // custom_events
    int                         eventfds[2];
    event_queue                 custom_events;
    wmutex_t                    custom_events_mutex;
};

uint64_t wloopGetNextEventID(void);

struct widle_s {
    WEVENT_FIELDS
    uint32_t    repeat;
//private:
    struct list_node node;
};

#define WTIMER_FIELDS                   \
    WEVENT_FIELDS                       \
    uint32_t    repeat;                 \
    uint64_t    next_timeout;           \
    struct heap_node node;

struct wtimer_s {
    WTIMER_FIELDS
};

struct htimeout_s {
    WTIMER_FIELDS
    uint32_t    timeout;                \
};

struct hperiod_s {
    WTIMER_FIELDS
    int8_t      minute;
    int8_t      hour;
    int8_t      day;
    int8_t      week;
    int8_t      month;
};

QUEUE_DECL(sbuf_t*, write_queue)

// sizeof(struct wio_s)=416 on linux-x64
struct wio_s {
    WEVENT_FIELDS
    // flags
    unsigned    ready       :1;
    unsigned    connected   :1;
    unsigned    closed      :1;
    unsigned    accept      :1;
    unsigned    connect     :1;
    unsigned    connectex   :1; // for ConnectEx/DisconnectEx
    unsigned    recv        :1;
    unsigned    send        :1;
    unsigned    recvfrom    :1;
    unsigned    sendto      :1;
    unsigned    close       :1;
// public:
    wio_type_e  io_type;
    uint32_t    id; // fd cannot be used as unique identifier, so we provide an id
    int         fd;
// #if defined(OS_LINUX) && defined(HAVE_PIPE)
//     int         pfd_r; // pipe read file descriptor for splice, (empty by default)
//     int         pfd_w; // pipe read file descriptor for splice, (empty by default)
// #endif
    int         error;
    int         events;
    int         revents;

    union{
        struct sockaddr*   localaddr;
        sockaddr_u* localaddr_u;
    };
    union{
        struct sockaddr*   peeraddr;
        sockaddr_u* peeraddr_u;
    };
    
    uint64_t            last_read_hrtime;
    uint64_t            last_write_hrtime;
    // read
    unsigned int        read_flags;
    // write
    struct write_queue  write_queue;
    // wrecursive_mutex_t  write_mutex; // lock write and write_queue
    uint32_t            write_bufsize;
    uint32_t            max_write_bufsize;
    // callbacks
    wread_cb    read_cb;
    wwrite_cb   write_cb;
    wclose_cb   close_cb;
    waccept_cb  accept_cb;
    wconnect_cb connect_cb;
    // timers
    int         connect_timeout;    // ms
    int         close_timeout;      // ms
    int         read_timeout;       // ms
    int         write_timeout;      // ms
    int         keepalive_timeout;  // ms
    int         heartbeat_interval; // ms
    wio_send_heartbeat_fn heartbeat_fn;
    wtimer_t*   connect_timer;
    wtimer_t*   close_timer;
    wtimer_t*   read_timer;
    wtimer_t*   write_timer;
    wtimer_t*   keepalive_timer;
    wtimer_t*   heartbeat_timer;

// private:
#if defined(EVENT_POLL) || defined(EVENT_KQUEUE)
    int         event_index[2]; // for poll,kqueue
#endif

#ifdef EVENT_IOCP
    void*       hovlp;          // for iocp/overlapio
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
void wioInit(wio_t* io);
void wioReady(wio_t* io);
void wioDone(wio_t* io);
void wioFree(wio_t* io);
uint32_t wioSetNextID(void);

void wioAcceptCallBack(wio_t* io);
void wioConnectCallBack(wio_t* io);
void wioHandleRead(wio_t* io,sbuf_t* buf);
void wioReadCallBack(wio_t* io, sbuf_t* buf);
void wioWriteCallBack(wio_t* io);
void wioCloseCallBack(wio_t* io);

void wioDelConnectTimer(wio_t* io);
void wioDelCloseTimer(wio_t* io);
void wioDelReadTimer(wio_t* io);
void wioDelWriteTimer(wio_t* io);
void wioDelKeepaliveTimer(wio_t* io);
void wioDelHeartBeatTimer(wio_t* io);



#define EVENT_ENTRY(p)          container_of(p, wevent_t, pending_node)
#define IDLE_ENTRY(p)           container_of(p, widle_t,  node)
#define TIMER_ENTRY(p)          container_of(p, wtimer_t, node)

#define EVENT_ACTIVE(ev) \
    if (!ev->active) {\
        ev->active = 1;\
        ev->loop->nactives++;\
    }\

#define EVENT_INACTIVE(ev) \
    if (ev->active) {\
        ev->active = 0;\
        ev->loop->nactives--;\
    }\

#define EVENT_PENDING(ev) \
    do {\
        if (!ev->pending) {\
            ev->pending = 1;\
            ev->loop->npendings++;\
            wevent_t** phead = &ev->loop->pendings[WEVENT_PRIORITY_INDEX(ev->priority)];\
            ev->pending_next = *phead;\
            *phead = (wevent_t*)ev;\
        }\
    } while(0)

#define EVENT_ADD(loop, ev, cb) \
    do {\
        ev->loop = loop;\
        ev->event_id = wloopGetNextEventID();\
        ev->cb = (wevent_cb)cb;\
        EVENT_ACTIVE(ev);\
    } while(0)

#define EVENT_DEL(ev) \
    do {\
        EVENT_INACTIVE(ev);\
        if (!ev->pending) {\
            EVENTLOOP_FREE(ev);\
        }\
    } while(0)

#define EVENT_RESET(ev) \
    do {\
        ev->destroy = 0;\
        EVENT_ACTIVE(ev);\
        ev->pending = 0;\
    } while(0)

#define EVENT_UNPENDING(ev) \
    do {\
        if (ev->pending) {\
            ev->pending = 0;\
            ev->loop->npendings--;\
        }\
    } while(0)

#endif // WW_EVENT_H_
