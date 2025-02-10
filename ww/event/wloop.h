#ifndef WW_LOOP_H_
#define WW_LOOP_H_

#include "wexport.h"
#include "wplatform.h"
#include "wdef.h"

#include "wsocket.h"
#include "buffer_pool.h"

typedef struct wloop_s wloop_t;
typedef struct wevent_s wevent_t;

// NOTE: The following structures are subclasses of wevent_t,
// inheriting wevent_t data members and function members.
typedef struct widle_s widle_t;
typedef struct wtimer_s wtimer_t;
typedef struct htimeout_s htimeout_t;
typedef struct hperiod_s hperiod_t;
typedef struct wio_s wio_t;

typedef void (*wevent_cb)(wevent_t* ev);
typedef void (*widle_cb)(widle_t* idle);
typedef void (*wtimer_cb)(wtimer_t* timer);
typedef void (*wio_cb)(wio_t* io);

typedef void (*waccept_cb)(wio_t* io);
typedef void (*wconnect_cb)(wio_t* io);
typedef void (*wread_cb)(wio_t* io, sbuf_t* buf);
typedef void (*wwrite_cb)(wio_t* io);
typedef void (*wclose_cb)(wio_t* io);

typedef enum { WLOOP_STATUS_STOP, WLOOP_STATUS_RUNNING, WLOOP_STATUS_PAUSE, WLOOP_STATUS_DESTROY } wloop_status_e;

typedef enum {
    WEVENT_TYPE_NONE = 0,
    WEVENT_TYPE_IO = 0x00000001,
    WEVENT_TYPE_TIMEOUT = 0x00000010,
    WEVENT_TYPE_PERIOD = 0x00000020,
    WEVENT_TYPE_TIMER = WEVENT_TYPE_TIMEOUT | WEVENT_TYPE_PERIOD,
    WEVENT_TYPE_IDLE = 0x00000100,
    WEVENT_TYPE_CUSTOM = 0x00000400, // 1024
} wevent_type_e;

#define WEVENT_LOWEST_PRIORITY (-5)
#define WEVENT_LOW_PRIORITY (-3)
#define WEVENT_NORMAL_PRIORITY 0
#define WEVENT_HIGH_PRIORITY 3
#define WEVENT_HIGHEST_PRIORITY 5
#define WEVENT_PRIORITY_SIZE (WEVENT_HIGHEST_PRIORITY - WEVENT_LOWEST_PRIORITY + 1)
#define WEVENT_PRIORITY_INDEX(priority) (priority - WEVENT_LOWEST_PRIORITY)

#define WEVENT_FLAGS      \
    unsigned destroy : 1; \
    unsigned active : 1;  \
    unsigned pending : 1;

#define WEVENT_FIELDS              \
    wloop_t* loop;                 \
    wevent_type_e event_type;      \
    uint64_t event_id;             \
    wevent_cb cb;                  \
    void* userdata;                \
    void* privdata;                \
    struct wevent_s* pending_next; \
    int priority;                  \
    WEVENT_FLAGS

// sizeof(struct wevent_s)=64 on x64
struct wevent_s {
    WEVENT_FIELDS
};

#define weventSetID(ev, id) ((wevent_t*)(ev))->event_id = id
#define weventSetCallBack(ev, cb) ((wevent_t*)(ev))->cb = cb
#define weventSetPriority(ev, prio) ((wevent_t*)(ev))->priority = prio
#define weventSetUserData(ev, udata) ((wevent_t*)(ev))->userdata = (void*)udata

#define weventGetLoop(ev) (((wevent_t*)(ev))->loop)
#define weventGetEventType(ev) (((wevent_t*)(ev))->event_type)
#define weventGetId(ev) (((wevent_t*)(ev))->event_id)
#define weventGetCallBack(ev) (((wevent_t*)(ev))->cb)
#define weventGetPriority(ev) (((wevent_t*)(ev))->priority)
#define weventGetUserdata(ev) (((wevent_t*)(ev))->userdata)

typedef enum {
    WIO_TYPE_UNKNOWN = 0,
    WIO_TYPE_STDIN = 0x00000001,
    WIO_TYPE_STDOUT = 0x00000002,
    WIO_TYPE_STDERR = 0x00000004,
    WIO_TYPE_STDIO = 0x0000000F,

    WIO_TYPE_FILE = 0x00000010,

    WIO_TYPE_IP = 0x00000100,
    WIO_TYPE_SOCK_RAW = 0x00000F00,

    WIO_TYPE_UDP = 0x00001000,
    // WIO_TYPE_KCP        = 0x00002000,
    WIO_TYPE_DTLS = 0x00010000,
    WIO_TYPE_SOCK_DGRAM = 0x000FF000,

    WIO_TYPE_TCP = 0x00100000,
    // WIO_TYPE_SSL        = 0x01000000,
    // WIO_TYPE_TLS        = WIO_TYPE_SSL,
    WIO_TYPE_SOCK_STREAM = 0x0FF00000,

    WIO_TYPE_SOCKET = 0x0FFFFF00,
} wio_type_e;

typedef enum {
    WIO_SERVER_SIDE = 0,
    WIO_CLIENT_SIDE = 1,
} wio_side_e;

#define WIO_DEFAULT_CONNECT_TIMEOUT 10000    // ms
#define WIO_DEFAULT_CLOSE_TIMEOUT 60000      // ms
#define WIO_DEFAULT_KEEPALIVE_TIMEOUT 75000  // ms
#define WIO_DEFAULT_HEARTBEAT_INTERVAL 10000 // ms



// loop
#define WLOOP_FLAG_RUN_ONCE 0x00000001
#define WLOOP_FLAG_AUTO_FREE 0x00000002
#define WLOOP_FLAG_QUIT_WHEN_NO_ACTIVE_EVENTS 0x00000004
WW_EXPORT wloop_t* wloopCreate(int flags DEFAULT(WLOOP_FLAG_AUTO_FREE),buffer_pool_t* swimmingpool, long wid);

// WARN: Forbid to call wloopDestroy if WLOOP_FLAG_AUTO_FREE set.
WW_EXPORT void wloopDestroy(wloop_t** pp);

WW_EXPORT int wloopProcessEvents(wloop_t* loop, int timeout_ms DEFAULT(0));

// NOTE: when no active events, loop will quit if WLOOP_FLAG_QUIT_WHEN_NO_ACTIVE_EVENTS set.
WW_EXPORT int wloopRun(wloop_t* loop);
// NOTE: wloopStop called in loop-thread just set flag to quit in next loop,
// if called in other thread, it will wakeup loop-thread from blocking poll system call,
// then you should join loop thread to safely exit loop thread.
WW_EXPORT int wloopStop(wloop_t* loop);
WW_EXPORT int wloopPause(wloop_t* loop);
WW_EXPORT int wloopResume(wloop_t* loop);
WW_EXPORT int wloopWakeup(wloop_t* loop);
WW_EXPORT wloop_status_e wloopStatus(wloop_t* loop);

WW_EXPORT void wloopUpdateTime(wloop_t* loop);
WW_EXPORT uint64_t wloopNow(wloop_t* loop);        // s
WW_EXPORT uint64_t wloopNowMS(wloop_t* loop);     // ms
WW_EXPORT uint64_t wloopNowUS(wloop_t* loop);     // us
WW_EXPORT uint64_t wloopNowLoopRunTime(wloop_t* loop); // us

// export some hloop's members
// @return pid of wloopRun
WW_EXPORT long wloopPID(wloop_t* loop);
// @return tid of wloopRun
WW_EXPORT long wloopTID(wloop_t* loop);
// @return count of loop
WW_EXPORT uint64_t wloopCount(wloop_t* loop);
// @return number of ios
WW_EXPORT uint32_t wloopNIOS(wloop_t* loop);
// @return number of timers
WW_EXPORT uint32_t wloopNTimers(wloop_t* loop);
// @return number of idles
WW_EXPORT uint32_t wloopNIdles(wloop_t* loop);
// @return number of active events
WW_EXPORT uint32_t wloopNActives(wloop_t* loop);

// @return the loop threadlocal buffer pool
WW_EXPORT buffer_pool_t* wloopGetBufferPool(wloop_t* loop);

// @return the loop thread id
WW_EXPORT long wloopGetWID(wloop_t* loop);

// userdata
WW_EXPORT void wloopSetUserData(wloop_t* loop, void* userdata);
WW_EXPORT void* wloopGetUserData(wloop_t* loop);

// custom_event
/*
 * wevent_t ev;
 * memorySet(&ev, 0, sizeof(wevent_t));
 * ev.event_type = (wevent_type_e)(WEVENT_TYPE_CUSTOM + 1);
 * ev.cb = custom_event_cb;
 * ev.userdata = userdata;
 * wloopPostEvent(loop, &ev);
 */
// NOTE: wloopPostEvent is thread-safe, used to post event from other thread to loop thread.
WW_EXPORT void wloopPostEvent(wloop_t* loop, wevent_t* ev);

// idle
WW_EXPORT widle_t* widleAdd(wloop_t* loop, widle_cb cb, uint32_t repeat DEFAULT(INFINITE));
WW_EXPORT void widleDelete(widle_t* idle);

// timer
WW_EXPORT wtimer_t* wtimerAdd(wloop_t* loop, wtimer_cb cb, uint32_t timeout_ms, uint32_t repeat DEFAULT(INFINITE));
/*
 * minute   hour    day     week    month       cb
 * 0~59     0~23    1~31    0~6     1~12
 *  -1      -1      -1      -1      -1          cron.minutely
 *  30      -1      -1      -1      -1          cron.hourly
 *  30      1       -1      -1      -1          cron.daily
 *  30      1       15      -1      -1          cron.monthly
 *  30      1       -1       5      -1          cron.weekly
 *  30      1        1      -1      10          cron.yearly
 */
WW_EXPORT wtimer_t* wtimerAddPeriod(wloop_t* loop, wtimer_cb cb, int8_t minute DEFAULT(0), int8_t hour DEFAULT(-1), int8_t day DEFAULT(-1),
                                      int8_t week DEFAULT(-1), int8_t month DEFAULT(-1), uint32_t repeat DEFAULT(INFINITE));

WW_EXPORT void wtimerDelete(wtimer_t* timer);
WW_EXPORT void wtimerReset(wtimer_t* timer, uint32_t timeout_ms DEFAULT(0));

// io
//-----------------------low-level apis---------------------------------------
#define WW_READ 0x0001
#define WW_WRITE 0x0004
#define WW_RDWR (WW_READ | WW_WRITE)
/*
const char* wioGetEngine() {
#ifdef EVENT_SELECT
    return  "select";
#elif defined(EVENT_POLL)
    return  "poll";
#elif defined(EVENT_EPOLL)
    return  "epoll";
#elif defined(EVENT_KQUEUE)
    return  "kqueue";
#elif defined(EVENT_IOCP)
    return  "iocp";
#elif defined(EVENT_PORT)
    return  "evport";
#else
    return  "noevent";
#endif
}
*/
WW_EXPORT const char* wioGetEngine(void);

WW_EXPORT wio_t* wioGet(wloop_t* loop, int fd);
WW_EXPORT int wioAdd(wio_t* io, wio_cb cb, int events DEFAULT(WW_READ));
WW_EXPORT int wioDel(wio_t* io, int events DEFAULT(WW_RDWR));

// NOTE: io detach from old loop and attach to new loop
/* @see examples/multi-thread/one-acceptor-multi-workers.c
void new_conn_event(wevent_t* ev) {
    wloop_t* loop = ev->loop;
    wio_t* io = (wio_t*)weventGetUserdata(ev);
    wioAttach(loop, io);
}

void on_accpet(wio_t* io) {
    wioDetach(io);

    wloop_t* worker_loop = get_one_loop();
    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.loop = worker_loop;
    ev.cb = new_conn_event;
    ev.userdata = io;
    wloopPostEvent(worker_loop, &ev);
}
 */
WW_EXPORT void wioDetach(/*wloop_t* loop,*/ wio_t* io);
WW_EXPORT void wioAttach(wloop_t* loop, wio_t* io);
WW_EXPORT bool wioExists(wloop_t* loop, int fd);

// wio_t fields
// NOTE: fd cannot be used as unique identifier, so we provide an id.
WW_EXPORT uint32_t wioGetID(wio_t* io);
WW_EXPORT int wioGetFD(wio_t* io);
WW_EXPORT int wioGetError(wio_t* io);
WW_EXPORT int wioGetEvents(wio_t* io);
WW_EXPORT int wioGetREvents(wio_t* io);
WW_EXPORT wio_type_e wioGetType(wio_t* io);
WW_EXPORT sockaddr_u* wioGetLocaladdrU(wio_t* io);
WW_EXPORT sockaddr_u* wioGetPeerAddrU(wio_t* io);
WW_EXPORT struct sockaddr* wioGetLocaladdr(wio_t* io);
WW_EXPORT struct sockaddr* wioGetPeerAddr(wio_t* io);
WW_EXPORT void wioSetContext(wio_t* io, void* ctx);
WW_EXPORT void* wioGetContext(wio_t* io);
WW_EXPORT bool wioIsOpened(wio_t* io);
WW_EXPORT bool wioIsConnected(wio_t* io);
WW_EXPORT bool wioIsClosed(wio_t* io);

// iobuf
// #include "hbuf.h"
typedef struct fifo_buf_s wio_readbuf_t;
// NOTE: One loop per thread, one readbuf per loop.
// But you can pass in your own readbuf instead of the default readbuf to avoid memcopy.
WW_EXPORT void wioSetMaxWriteBufSize(wio_t* io, uint32_t size);


// NOTE: wioWrite is non-blocking, so there is a write queue inside wio_t to cache unwritten data and wait for writable.
// @return current buffer size of write queue.
WW_EXPORT size_t wioGetWriteBufSize(wio_t* io);
#define wioCheckWriteComplete(io) (wioGetWriteBufSize(io) == 0)

WW_EXPORT uint64_t wioGetLastReadTime(wio_t* io);  // ms
WW_EXPORT uint64_t wioGetLastWriteTime(wio_t* io); // ms

// set callbacks
WW_EXPORT void wioSetCallBackAccept(wio_t* io, waccept_cb accept_cb);
WW_EXPORT void wioSetCallBackConnect(wio_t* io, wconnect_cb connect_cb);
WW_EXPORT void wioSetCallBackRead(wio_t* io, wread_cb read_cb);
WW_EXPORT void wioSetCallBackWrite(wio_t* io, wwrite_cb write_cb);
WW_EXPORT void wioSetCallBackClose(wio_t* io, wclose_cb close_cb);
// get callbacks
WW_EXPORT waccept_cb wioGetCallBackAccept(wio_t* io);
WW_EXPORT wconnect_cb wioGetCallBackConnect(wio_t* io);
WW_EXPORT wread_cb wioGetCallBackRead(wio_t* io);
WW_EXPORT wwrite_cb wioGetCallBackWrite(wio_t* io);
WW_EXPORT wclose_cb wioGetCallBackClose(wio_t* io);

// connect timeout => wclose_cb
WW_EXPORT void wioSetConnectTimeout(wio_t* io, int timeout_ms DEFAULT(WIO_DEFAULT_CONNECT_TIMEOUT));
// close timeout => wclose_cb
WW_EXPORT void wioSetCloseTimeout(wio_t* io, int timeout_ms DEFAULT(WIO_DEFAULT_CLOSE_TIMEOUT));
// read timeout => wclose_cb
WW_EXPORT void wioSetReadTimeout(wio_t* io, int timeout_ms);
// write timeout => wclose_cb
WW_EXPORT void wiosSetWriteTimeout(wio_t* io, int timeout_ms);
// keepalive timeout => wclose_cb
WW_EXPORT void wioSetKeepaliveTimeout(wio_t* io, int timeout_ms DEFAULT(WIO_DEFAULT_KEEPALIVE_TIMEOUT));
/*
void send_heartbeat(wio_t* io) {
    static char buf[] = "PING\r\n";
    wioWrite(io, buf, 6);
}
wioSetHeartBeat(io, 3000, send_heartbeat);
*/
typedef void (*wio_send_heartbeat_fn)(wio_t* io);
// heartbeat interval => wio_send_heartbeat_fn
WW_EXPORT void wioSetHeartBeat(wio_t* io, int interval_ms, wio_send_heartbeat_fn fn);

// Nonblocking, poll IO events in the loop to call corresponding callback.
// wioAdd(io, WW_READ) => accept => waccept_cb
WW_EXPORT int wioAccept(wio_t* io);

// connect => wioAdd(io, WW_WRITE) => wconnect_cb
WW_EXPORT int wioConnect(wio_t* io);

// wioAdd(io, WW_READ) => read => wread_cb
WW_EXPORT int wioRead(wio_t* io);
#define wioReadStart(io) wioRead(io)
#define wioReadStop(io) wioDel(io, WW_READ)

// wioReadStart => wread_cb => wioReadStop
WW_EXPORT int wioReadOnce(wio_t* io);
// wioReadOnce => wread_cb(len)
// WW_EXPORT int wioReadUntillLength(wio_t* io, unsigned int len);
// wioReadOnce => wread_cb(...delim)
// WW_EXPORT int wio_read_until_delim (wio_t* io, unsigned char delim);
WW_EXPORT int wioReadRemain(wio_t* io);
// @see examples/tinyhttpd.c examples/tinyproxyd.c
// #define wio_readline(io)        wio_read_until_delim(io, '\n')
// #define wio_readstring(io)      wio_read_until_delim(io, '\0')
#define wioReadBytes(io, len) wioReadUntillLength(io, len)
#define wioReadUntill(io, len) wioReadUntillLength(io, len)

// NOTE: wioWrite is thread-safe, locked by recursive_mutex, allow to be called by other threads.
// wio_try_write => wioAdd(io, WW_WRITE) => write => wwrite_cb
WW_EXPORT int wioWrite(wio_t* io, sbuf_t* buf);

// NOTE: wioClose is thread-safe, wioCloseAsync will be called actually in other thread.
// wioDel(io, WW_RDWR) => close => wclose_cb
WW_EXPORT int wioClose(wio_t* io);
// NOTE: wloopPostEvent(wio_close_event)
WW_EXPORT int wioCloseAsync(wio_t* io);

//------------------high-level apis-------------------------------------------
// wioGet -> wioSetReadBuf -> wioSetCallBackRead -> wioRead
WW_EXPORT wio_t* wRead(wloop_t* loop, int fd, wread_cb read_cb);
// wioGet -> wioSetCallBackWrite -> wioWrite
WW_EXPORT wio_t* wWrite(wloop_t* loop, int fd, sbuf_t* buf, wwrite_cb write_cb DEFAULT(NULL));
// wioGet -> wioClose
WW_EXPORT void wClose(wloop_t* loop, int fd);

// tcp
// wioGet -> wioSetCallBackAccept -> wioAccept
WW_EXPORT wio_t* waccept(wloop_t* loop, int listenfd, waccept_cb accept_cb);
// wioGet -> wioSetCallBackConnect -> wioConnect
WW_EXPORT wio_t* wconnect(wloop_t* loop, int connfd, wconnect_cb connect_cb);
// wioGet -> wioSetReadBuf -> wioSetCallBackRead -> wioRead
WW_EXPORT wio_t* wRecv(wloop_t* loop, int connfd, wread_cb read_cb);
// wioGet -> wioSetCallBackWrite -> wioWrite
WW_EXPORT wio_t* wSend(wloop_t* loop, int connfd, sbuf_t* buf, wwrite_cb write_cb DEFAULT(NULL));

// udp
WW_EXPORT void wioSetType(wio_t* io, wio_type_e type);
WW_EXPORT void wioSetLocaladdr(wio_t* io, struct sockaddr* addr, int addrlen);
WW_EXPORT void wioSetPeerAddr(wio_t* io, struct sockaddr* addr, int addrlen);
// NOTE: must call wioSetPeerAddr before wRecvFrom/wSendTo
// wioGet -> wioSetReadBuf -> wioSetCallBackRead -> wioRead
WW_EXPORT wio_t* wRecvFrom(wloop_t* loop, int sockfd, wread_cb read_cb);
// wioGet -> wioSetCallBackWrite -> wioWrite
WW_EXPORT wio_t* wSendTo(wloop_t* loop, int sockfd, sbuf_t* buf,  wwrite_cb write_cb DEFAULT(NULL));

//-----------------top-level apis---------------------------------------------
// @wioCreateSocket: socket -> bind -> listen
// sockaddr_set_ipport -> socket -> wioGet(loop, sockfd) ->
// side == WIO_SERVER_SIDE ? bind ->
// type & WIO_TYPE_SOCK_STREAM ? listen ->
WW_EXPORT wio_t* wioCreateSocket(wloop_t* loop, const char* host, int port, wio_type_e type DEFAULT(WIO_TYPE_TCP), wio_side_e side DEFAULT(WIO_SERVER_SIDE));

// @tcp_server: wioCreateSocket(loop, host, port, WIO_TYPE_TCP, WIO_SERVER_SIDE) -> wioSetCallBackAccept -> wioAccept
// @see examples/tcp_echo_server.c
WW_EXPORT wio_t* wloopCreateTcpServer(wloop_t* loop, const char* host, int port, waccept_cb accept_cb);

// @tcp_client: wioCreateSocket(loop, host, port, WIO_TYPE_TCP, WIO_CLIENT_SIDE) -> wioSetCallBackConnect -> wioSetCallBackClose -> wioConnect
// @see examples/nc.c
WW_EXPORT wio_t* wloopCreateTcpClient(wloop_t* loop, const char* host, int port, wconnect_cb connect_cb, wclose_cb close_cb);

// @udp_server: wioCreateSocket(loop, host, port, WIO_TYPE_UDP, WIO_SERVER_SIDE)
// @see examples/udp_echo_server.c
WW_EXPORT wio_t* wloopCreateUdpServer(wloop_t* loop, const char* host, int port);

// @udp_server: wioCreateSocket(loop, host, port, WIO_TYPE_UDP, WIO_CLIENT_SIDE)
// @see examples/nc.c
WW_EXPORT wio_t* wloopCreateUdpClient(wloop_t* loop, const char* host, int port);



//-----------------reconnect----------------------------------------
#define DEFAULT_RECONNECT_MIN_DELAY 1000  // ms
#define DEFAULT_RECONNECT_MAX_DELAY 60000 // ms
#define DEFAULT_RECONNECT_DELAY_POLICY 2  // exponential
#define DEFAULT_RECONNECT_MAX_RETRY_CNT INFINITE
typedef struct reconn_setting_s {
    uint32_t min_delay; // ms
    uint32_t max_delay; // ms
    uint32_t cur_delay; // ms
    /*
     * @delay_policy
     * 0: fixed
     * min_delay=3s => 3,3,3...
     * 1: linear
     * min_delay=3s max_delay=10s => 3,6,9,10,10...
     * other: exponential
     * min_delay=3s max_delay=60s delay_policy=2 => 3,6,12,24,48,60,60...
     */
    uint32_t delay_policy;
    uint32_t max_retry_cnt;
    uint32_t cur_retry_cnt;

} reconn_setting_t;

WW_INLINE void reconnSettingInit(reconn_setting_t* reconn) {
    reconn->min_delay = DEFAULT_RECONNECT_MIN_DELAY;
    reconn->max_delay = DEFAULT_RECONNECT_MAX_DELAY;
    reconn->cur_delay = 0;
    // 1,2,4,8,16,32,60,60...
    reconn->delay_policy = DEFAULT_RECONNECT_DELAY_POLICY;
    reconn->max_retry_cnt = DEFAULT_RECONNECT_MAX_RETRY_CNT;
    reconn->cur_retry_cnt = 0;
}

WW_INLINE void reconnSettingReset(reconn_setting_t* reconn) {
    reconn->cur_delay = 0;
    reconn->cur_retry_cnt = 0;
}

WW_INLINE bool reconnSettingCanRetry(reconn_setting_t* reconn) {
    ++reconn->cur_retry_cnt;
    return reconn->max_retry_cnt == INFINITE || reconn->cur_retry_cnt < reconn->max_retry_cnt;
}

WW_INLINE uint32_t reconnSettingCalcDelay(reconn_setting_t* reconn) {
    if (reconn->delay_policy == 0) {
        // fixed
        reconn->cur_delay = reconn->min_delay;
    }
    else if (reconn->delay_policy == 1) {
        // linear
        reconn->cur_delay += reconn->min_delay;
    }
    else {
        // exponential
        reconn->cur_delay *= reconn->delay_policy;
    }
    reconn->cur_delay = max(reconn->cur_delay, reconn->min_delay);
    reconn->cur_delay = min(reconn->cur_delay, reconn->max_delay);
    return reconn->cur_delay;
}

//-----------------LoadBalance-------------------------------------
typedef enum {
    LB_RoundRobin,
    LB_Random,
    LB_LeastConnections,
    LB_IpHash,
    LB_UrlHash,
} load_balance_e;



#endif // WW_LOOP_H_
