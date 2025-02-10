#include "wevent.h"
#include "wsocket.h"
#include "watomic.h"
#include "loggers/internal_logger.h"
#include "werr.h"
// todo (invesitage) how a dynamic node can have these?
uint64_t wloopGetNextEventID(void) {
    static atomic_long s_id = (0);
    return ++s_id;
}

uint32_t wioSetNextID(void) {
    static atomic_long s_id = (0);
    return ++s_id;
}

static void fillIoType(wio_t* io) {
    int type = 0;
    socklen_t optlen = sizeof(int);
    int ret = getsockopt(io->fd, SOL_SOCKET, SO_TYPE, (char*)&type, &optlen);
    printd("getsockopt SO_TYPE fd=%d ret=%d type=%d errno=%d\n", io->fd, ret, type, socketERRNO());
    if (ret == 0) {
        switch (type) {
        case SOCK_STREAM: io->io_type = WIO_TYPE_TCP; break;
        case SOCK_DGRAM: io->io_type = WIO_TYPE_UDP; break;
        case SOCK_RAW: io->io_type = WIO_TYPE_IP; break;
        default: io->io_type = WIO_TYPE_SOCKET; break;
        }
    }
    else if (socketERRNO() == ENOTSOCK) {
        switch (io->fd) {
        case 0: io->io_type = WIO_TYPE_STDIN; break;
        case 1: io->io_type = WIO_TYPE_STDOUT; break;
        case 2: io->io_type = WIO_TYPE_STDERR; break;
        default: io->io_type = WIO_TYPE_FILE; break;
        }
    }
    else {
        io->io_type = WIO_TYPE_TCP;
    }
}

static void wioSocketInit(wio_t* io) {
    if ((io->io_type & WIO_TYPE_SOCK_DGRAM) || (io->io_type & WIO_TYPE_SOCK_RAW)) {
        // NOTE: sendto multiple peeraddr cannot use io->write_queue
        blocking(io->fd);
    }
    else {
        nonBlocking(io->fd);
    }
    // fill io->localaddr io->peeraddr
    if (io->localaddr == NULL) {
        EVENTLOOP_ALLOC(io->localaddr, sizeof(sockaddr_u));
    }
    if (io->peeraddr == NULL) {
        EVENTLOOP_ALLOC(io->peeraddr, sizeof(sockaddr_u));
    }
    socklen_t addrlen = sizeof(sockaddr_u);
    int ret = getsockname(io->fd, io->localaddr, &addrlen);
    (void)ret;
    printd("getsockname fd=%d ret=%d errno=%d\n", io->fd, ret, socketERRNO());
    // NOTE: udp peeraddr set by recvfrom/sendto
    if (io->io_type & WIO_TYPE_SOCK_STREAM) {
        addrlen = sizeof(sockaddr_u);
        ret = getpeername(io->fd, io->peeraddr, &addrlen);
        printd("getpeername fd=%d ret=%d errno=%d\n", io->fd, ret, socketERRNO());
    }
}

void wioInit(wio_t* io) {
    // alloc localaddr,peeraddr when wioSocketInit
    /*
    if (io->localaddr == NULL) {
        EVENTLOOP_ALLOC(io->localaddr, sizeof(sockaddr_u));
    }
    if (io->peeraddr == NULL) {
        EVENTLOOP_ALLOC(io->peeraddr, sizeof(sockaddr_u));
    }
    */

    // write_queue init when wWrite try_write failed
    // write_queue_init(&io->write_queue, 4);

    // recursivemutexInit(&io->write_mutex);
    (void)io;
}

void wioReady(wio_t* io) {
    if (io->ready) return;
    // flags
    io->ready = 1;
    io->connected = 0;
    io->closed = 0;
    io->accept = io->connect = io->connectex = 0;
    io->recv = io->send = 0;
    io->recvfrom = io->sendto = 0;
    io->close = 0;
    // public:
    io->id = wioSetNextID();
    io->io_type = WIO_TYPE_UNKNOWN;
    io->error = 0;
    io->events = io->revents = 0;
    io->last_read_hrtime = io->last_write_hrtime = io->loop->cur_hrtime;

    io->read_flags = 0;
    // write_queue
    io->write_bufsize = 0;
    io->max_write_bufsize = MAX_WRITE_BUFSIZE;
    // callbacks
    io->read_cb = NULL;
    io->write_cb = NULL;
    io->close_cb = NULL;
    io->accept_cb = NULL;
    io->connect_cb = NULL;
    // timers
    io->connect_timeout = 0;
    io->connect_timer = NULL;
    io->close_timeout = 0;
    io->close_timer = NULL;
    io->read_timeout = 0;
    io->read_timer = NULL;
    io->write_timeout = 0;
    io->write_timer = NULL;
    io->keepalive_timeout = 0;
    io->keepalive_timer = NULL;
    io->heartbeat_interval = 0;
    io->heartbeat_fn = NULL;
    io->heartbeat_timer = NULL;

    // private:
#if defined(EVENT_POLL) || defined(EVENT_KQUEUE)
    io->event_index[0] = io->event_index[1] = -1;
#endif
#ifdef EVENT_IOCP
    io->hovlp = NULL;

#endif

    // io_type
    fillIoType(io);
    if (io->io_type & WIO_TYPE_SOCKET) {
        wioSocketInit(io);
    }
}

void wioDone(wio_t* io) {
    if (!io->ready) return;
    io->ready = 0;

    wioDel(io, WW_RDWR);

    // write_queue
    sbuf_t* buf = NULL;
    //
    while (!write_queue_empty(&io->write_queue)) {
        buf = *write_queue_front(&io->write_queue);
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        write_queue_pop_front(&io->write_queue);
    }
    write_queue_cleanup(&io->write_queue);
    io->write_queue.ptr = NULL;
}

void wioFree(wio_t* io) {
    if (io == NULL || io->destroy) return;
    io->destroy = 1;
    wioClose(io);
    EVENTLOOP_FREE(io->localaddr);
    EVENTLOOP_FREE(io->peeraddr);
    EVENTLOOP_FREE(io);
}

bool wioIsOpened(wio_t* io) {
    if (io == NULL) return false;
    return io->ready == 1 && io->closed == 0;
}

bool wioIsConnected(wio_t* io) {
    if (io == NULL) return false;
    return io->ready == 1 && io->connected == 1 && io->closed == 0;
}

bool wioIsClosed(wio_t* io) {
    if (io == NULL) return true;
    return io->ready == 0 && io->closed == 1;
}

uint32_t wioGetID(wio_t* io) {
    return io->id;
}

int wioGetFD(wio_t* io) {
    return io->fd;
}

wio_type_e wioGetType(wio_t* io) {
    return io->io_type;
}

int wioGetError(wio_t* io) {
    return io->error;
}

int wioGetEvents(wio_t* io) {
    return io->events;
}

int wioGetREvents(wio_t* io) {
    return io->revents;
}

sockaddr_u* wioGetLocaladdrU(wio_t* io) {
    return io->localaddr_u;
}

sockaddr_u* wioGetPeerAddrU(wio_t* io) {
    return io->peeraddr_u;
}

struct sockaddr* wioGetLocaladdr(wio_t* io) {
    return io->localaddr;
}

struct sockaddr* wioGetPeerAddr(wio_t* io) {
    return io->peeraddr;
}

waccept_cb wioGetCallBackAccept(wio_t* io) {
    return io->accept_cb;
}

wconnect_cb wioGetCallBackConnect(wio_t* io) {
    return io->connect_cb;
}

wread_cb wioGetCallBackRead(wio_t* io) {
    return io->read_cb;
}

wwrite_cb wioGetCallBackWrite(wio_t* io) {
    return io->write_cb;
}

wclose_cb wioGetCallBackClose(wio_t* io) {
    return io->close_cb;
}

void wioSetCallBackAccept(wio_t* io, waccept_cb accept_cb) {
    io->accept_cb = accept_cb;
}

void wioSetCallBackConnect(wio_t* io, wconnect_cb connect_cb) {
    io->connect_cb = connect_cb;
}

void wioSetCallBackRead(wio_t* io, wread_cb read_cb) {
    io->read_cb = read_cb;
}

void wioSetCallBackWrite(wio_t* io, wwrite_cb write_cb) {
    io->write_cb = write_cb;
}

void wioSetCallBackClose(wio_t* io, wclose_cb close_cb) {
    io->close_cb = close_cb;
}

void wioAcceptCallBack(wio_t* io) {
    /*
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};
    printd("accept connfd=%d [%s] <= [%s]\n", io->fd,
            SOCKADDR_STR(io->localaddr, localaddrstr),
            SOCKADDR_STR(io->peeraddr, peeraddrstr));
    */
    if (io->accept_cb) {
        // printd("accept_cb------\n");
        io->accept_cb(io);
        // printd("accept_cb======\n");
    }
}

void wioConnectCallBack(wio_t* io) {
    /*
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};
    printd("connect connfd=%d [%s] => [%s]\n", io->fd,
            SOCKADDR_STR(io->localaddr, localaddrstr),
            SOCKADDR_STR(io->peeraddr, peeraddrstr));
    */
    io->connected = 1;
    if (io->connect_cb) {
        // printd("connect_cb------\n");
        io->connect_cb(io);
        // printd("connect_cb======\n");
    }
}

void wioHandleRead(wio_t* io, sbuf_t* buf) {
    // wioRead
    wioReadCallBack(io, buf);
}

void wioReadCallBack(wio_t* io, sbuf_t* buf) {
    if (io->read_flags & WIO_READ_ONCE) {
        io->read_flags &= ~WIO_READ_ONCE;
        wioReadStop(io);
    }

    if (io->read_cb) {
        // printd("read_cb------\n");
        io->read_cb(io, buf);
        // printd("read_cb======\n");
    }
}

void wioWriteCallBack(wio_t* io) {
    if (io->write_cb) {
        // printd("write_cb------\n");
        io->write_cb(io);
        // printd("write_cb======\n");
    }
}

void wioCloseCallBack(wio_t* io) {
    io->connected = 0;
    io->closed = 1;
    if (io->close_cb) {
        // printd("close_cb------\n");
        io->close_cb(io);
        // printd("close_cb======\n");
    }
}

void wioSetType(wio_t* io, wio_type_e type) {
    io->io_type = type;
}

void wioSetLocaladdr(wio_t* io, struct sockaddr* addr, int addrlen) {
    if (io->localaddr == NULL) {
        EVENTLOOP_ALLOC(io->localaddr, sizeof(sockaddr_u));
    }
    memoryCopy(io->localaddr, addr, addrlen);
}

void wioSetPeerAddr(wio_t* io, struct sockaddr* addr, int addrlen) {
    if (io->peeraddr == NULL) {
        EVENTLOOP_ALLOC(io->peeraddr, sizeof(sockaddr_u));
    }
    memoryCopy(io->peeraddr, addr, addrlen);
}

void wioDelConnectTimer(wio_t* io) {
    if (io->connect_timer) {
        wtimerDelete(io->connect_timer);
        io->connect_timer = NULL;
        io->connect_timeout = 0;
    }
}

void wioDelCloseTimer(wio_t* io) {
    if (io->close_timer) {
        wtimerDelete(io->close_timer);
        io->close_timer = NULL;
        io->close_timeout = 0;
    }
}

void wioDelReadTimer(wio_t* io) {
    if (io->read_timer) {
        wtimerDelete(io->read_timer);
        io->read_timer = NULL;
        io->read_timeout = 0;
    }
}

void wioDelWriteTimer(wio_t* io) {
    if (io->write_timer) {
        wtimerDelete(io->write_timer);
        io->write_timer = NULL;
        io->write_timeout = 0;
    }
}

void wioDelKeepaliveTimer(wio_t* io) {
    if (io->keepalive_timer) {
        wtimerDelete(io->keepalive_timer);
        io->keepalive_timer = NULL;
        io->keepalive_timeout = 0;
    }
}

void wioDelHeartBeatTimer(wio_t* io) {
    if (io->heartbeat_timer) {
        wtimerDelete(io->heartbeat_timer);
        io->heartbeat_timer = NULL;
        io->heartbeat_interval = 0;
        io->heartbeat_fn = NULL;
    }
}

void wioSetConnectTimeout(wio_t* io, int timeout_ms) {
    io->connect_timeout = timeout_ms;
}

void wioSetCloseTimeout(wio_t* io, int timeout_ms) {
    io->close_timeout = timeout_ms;
}

static void __read_timeout_cb(wtimer_t* timer) {
    wio_t* io = (wio_t*)timer->privdata;
    uint64_t inactive_ms = (io->loop->cur_hrtime - io->last_read_hrtime) / 1000;
    if (inactive_ms + 100 < (uint64_t)io->read_timeout) {
        wtimerReset(io->read_timer, io->read_timeout - inactive_ms);
    }
    else {
        if (io->io_type & WIO_TYPE_SOCKET) {
            char localaddrstr[SOCKADDR_STRLEN] = {0};
            char peeraddrstr[SOCKADDR_STRLEN] = {0};
            wlogw("read timeout [%s] <=> [%s]", SOCKADDR_STR(io->localaddr, localaddrstr), SOCKADDR_STR(io->peeraddr, peeraddrstr));
        }
        io->error = ETIMEDOUT;
        wioClose(io);
    }
}

void wioSetReadTimeout(wio_t* io, int timeout_ms) {
    if (timeout_ms <= 0) {
        // del
        wioDelReadTimer(io);
        return;
    }

    if (io->read_timer) {
        // reset
        wtimerReset(io->read_timer, timeout_ms);
    }
    else {
        // add
        io->read_timer = wtimerAdd(io->loop, __read_timeout_cb, timeout_ms, 1);
        io->read_timer->privdata = io;
    }
    io->read_timeout = timeout_ms;
}

static void __write_timeout_cb(wtimer_t* timer) {
    wio_t* io = (wio_t*)timer->privdata;
    uint64_t inactive_ms = (io->loop->cur_hrtime - io->last_write_hrtime) / 1000;
    if (inactive_ms + 100 < (uint64_t)io->write_timeout) {
        wtimerReset(io->write_timer, io->write_timeout - inactive_ms);
    }
    else {
        if (io->io_type & WIO_TYPE_SOCKET) {
            char localaddrstr[SOCKADDR_STRLEN] = {0};
            char peeraddrstr[SOCKADDR_STRLEN] = {0};
            wlogw("write timeout [%s] <=> [%s]", SOCKADDR_STR(io->localaddr, localaddrstr), SOCKADDR_STR(io->peeraddr, peeraddrstr));
        }
        io->error = ETIMEDOUT;
        wioClose(io);
    }
}

void wiosSetWriteTimeout(wio_t* io, int timeout_ms) {
    if (timeout_ms <= 0) {
        // del
        wioDelWriteTimer(io);
        return;
    }

    if (io->write_timer) {
        // reset
        wtimerReset(io->write_timer, timeout_ms);
    }
    else {
        // add
        io->write_timer = wtimerAdd(io->loop, __write_timeout_cb, timeout_ms, 1);
        io->write_timer->privdata = io;
    }
    io->write_timeout = timeout_ms;
}

static void __keepalive_timeout_cb(wtimer_t* timer) {
    wio_t* io = (wio_t*)timer->privdata;
    uint64_t last_rw_hrtime = max(io->last_read_hrtime, io->last_write_hrtime);
    uint64_t inactive_ms = (io->loop->cur_hrtime - last_rw_hrtime) / 1000;
    if (inactive_ms + 100 < (uint64_t)io->keepalive_timeout) {
        wtimerReset(io->keepalive_timer, io->keepalive_timeout - inactive_ms);
    }
    else {
        if (io->io_type & WIO_TYPE_SOCKET) {
            char localaddrstr[SOCKADDR_STRLEN] = {0};
            char peeraddrstr[SOCKADDR_STRLEN] = {0};
            wlogd("keepalive timeout [%s] <=> [%s]", SOCKADDR_STR(io->localaddr, localaddrstr), SOCKADDR_STR(io->peeraddr, peeraddrstr));
        }
        io->error = ETIMEDOUT;
        wioClose(io);
    }
}

void wioSetKeepaliveTimeout(wio_t* io, int timeout_ms) {
    if (timeout_ms <= 0) {
        // del
        wioDelKeepaliveTimer(io);
        return;
    }

    if (io->keepalive_timer) {
        // reset
        wtimerReset(io->keepalive_timer, timeout_ms);
    }
    else {
        // add
        io->keepalive_timer = wtimerAdd(io->loop, __keepalive_timeout_cb, timeout_ms, 1);
        io->keepalive_timer->privdata = io;
    }
    io->keepalive_timeout = timeout_ms;
}

static void __heartbeat_timer_cb(wtimer_t* timer) {
    wio_t* io = (wio_t*)timer->privdata;
    if (io && io->heartbeat_fn) {
        io->heartbeat_fn(io);
    }
}

void wioSetHeartBeat(wio_t* io, int interval_ms, wio_send_heartbeat_fn fn) {
    if (interval_ms <= 0) {
        // del
        wioDelHeartBeatTimer(io);
        return;
    }

    if (io->heartbeat_timer) {
        // reset
        wtimerReset(io->heartbeat_timer, interval_ms);
    }
    else {
        // add
        io->heartbeat_timer = wtimerAdd(io->loop, __heartbeat_timer_cb, interval_ms, INFINITE);
        io->heartbeat_timer->privdata = io;
    }
    io->heartbeat_interval = interval_ms;
    io->heartbeat_fn = fn;
}

//-----------------iobuf---------------------------------------------

void wioSetMaxWriteBufSize(wio_t* io, uint32_t size) {
    io->max_write_bufsize = size;
}

size_t wioGetWriteBufSize(wio_t* io) {
    return io->write_bufsize;
}

int wioReadOnce(wio_t* io) {
    io->read_flags |= WIO_READ_ONCE;
    return wioReadStart(io);
}

//-----------------upstream---------------------------------------------
// void wio_read_upstream(wio_t* io) {
//     wio_t* upstream_io = io->upstream_io;
//     if (upstream_io) {
//         wioRead(io);
//         wioRead(upstream_io);
//     }
// }

// void wio_read_upstream_on_write_complete(wio_t* io, const void* buf, int writebytes) {
//     wio_t* upstream_io = io->upstream_io;
//     if (upstream_io && wioCheckWriteComplete(io)) {
//         wioSetCallBackWrite(io, NULL);
//         wioRead(upstream_io);
//     }
// }

// void wio_write_upstream(wio_t* io, void* buf, int bytes) {
//     wio_t* upstream_io = io->upstream_io;
//     if (upstream_io) {
//         int nwrite = wioWrite(upstream_io, buf, bytes);
//         // if (!wioCheckWriteComplete(upstream_io)) {
//         if (nwrite >= 0 && nwrite < bytes) {
//             wioReadStop(io);
//             wioSetCallBackWrite(upstream_io, wio_read_upstream_on_write_complete);
//         }
//     }
// }
// #if defined(OS_LINUX) && defined(HAVE_PIPE)

// void wio_close_upstream(wio_t* io) {
//     wio_t* upstream_io = io->upstream_io;
//     if(io->pfd_w != 0x0){
//         close(io->pfd_w);
//         close(io->pfd_r);
//     }
//     if (upstream_io) {
//         wioClose(upstream_io);
//     }
// }

// static bool wio_setup_pipe(wio_t* io) {
//     int fds[2];
//     int r = pipe(fds);
//     if (r != 0)
//         return false;
//     io->pfd_r = fds[0];
//     io->pfd_w = fds[1];
//     return true;

// }

// void wio_setup_upstream_splice(wio_t* restrict io1, wio_t* restrict io2) {
//     io1->upstream_io = io2;
//     io2->upstream_io = io1;
//     assert (io1->io_type == WIO_TYPE_TCP && io2->io_type == WIO_TYPE_TCP);
//     if (!wio_setup_pipe(io1))
//         return;

//     if (!wio_setup_pipe(io2)){
//         close(io1->pfd_w);
//         close(io1->pfd_r);
//         io1->pfd_w = io1->pfd_r = 0;
//         return;
//     }
//     const int tmp_fd = io1->pfd_w;
//     io1->pfd_w = io2->pfd_w;
//     io2->pfd_w = tmp_fd;
// }
// #else

// void wio_close_upstream(wio_t* io) {
//     wio_t* upstream_io = io->upstream_io;
//     if (upstream_io) {
//         wioClose(upstream_io);
//     }
// }

// #endif

// void wio_setup_upstream(wio_t* restrict io1, wio_t* restrict io2) {
//     io1->upstream_io = io2;
//     io2->upstream_io = io1;
// }

// wio_t* wio_get_upstream(wio_t* io) {
//     return io->upstream_io;
// }

// wio_t* wio_setup_tcp_upstream(wio_t* io, const char* host, int port) {
//     wio_t* upstream_io = wioCreateSocket(io->loop, host, port, WIO_TYPE_TCP, WIO_CLIENT_SIDE);
//     if (upstream_io == NULL) return NULL;
//     // #if defined(OS_LINUX) && defined(HAVE_PIPE)
//     //     wio_setup_upstream_splice(io, upstream_io);
//     // #else
//     wio_setup_upstream(io, upstream_io);
//     // #endif

//     wioSetCallBackRead(io, wio_write_upstream);
//     wioSetCallBackRead(upstream_io, wio_write_upstream);

//     wioSetCallBackClose(io, wio_close_upstream);
//     wioSetCallBackClose(upstream_io, wio_close_upstream);
//     wioSetCallBackConnect(upstream_io, wio_read_upstream);
//     wioConnect(upstream_io);
//     return upstream_io;
// }

// wio_t* wio_setup_udp_upstream(wio_t* io, const char* host, int port) {
//     wio_t* upstream_io = wioCreateSocket(io->loop, host, port, WIO_TYPE_UDP, WIO_CLIENT_SIDE);
//     if (upstream_io == NULL) return NULL;
//     wio_setup_upstream(io, upstream_io);
//     wioSetCallBackRead(io, wio_write_upstream);
//     wioSetCallBackRead(upstream_io, wio_write_upstream);
//     wio_read_upstream(io);
//     return upstream_io;
// }
