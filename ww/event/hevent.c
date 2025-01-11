#include "hevent.h"
#include "wsocket.h"
#include "watomic.h"
#include "wlog.h"
#include "werr.h"
// todo (invesitage) how a dynamic node can have these?
uint64_t hloop_next_event_id(void) {
    static atomic_long s_id = (0);
    return ++s_id;
}

uint32_t hio_next_id(void) {
    static atomic_long s_id = (0);
    return ++s_id;
}

static void fill_io_type(hio_t* io) {
    int type = 0;
    socklen_t optlen = sizeof(int);
    int ret = getsockopt(io->fd, SOL_SOCKET, SO_TYPE, (char*)&type, &optlen);
    printd("getsockopt SO_TYPE fd=%d ret=%d type=%d errno=%d\n", io->fd, ret, type, socket_errno());
    if (ret == 0) {
        switch (type) {
        case SOCK_STREAM: io->io_type = HIO_TYPE_TCP; break;
        case SOCK_DGRAM: io->io_type = HIO_TYPE_UDP; break;
        case SOCK_RAW: io->io_type = HIO_TYPE_IP; break;
        default: io->io_type = HIO_TYPE_SOCKET; break;
        }
    }
    else if (socketERRNO() == ENOTSOCK) {
        switch (io->fd) {
        case 0: io->io_type = HIO_TYPE_STDIN; break;
        case 1: io->io_type = HIO_TYPE_STDOUT; break;
        case 2: io->io_type = HIO_TYPE_STDERR; break;
        default: io->io_type = HIO_TYPE_FILE; break;
        }
    }
    else {
        io->io_type = HIO_TYPE_TCP;
    }
}

static void hio_socket_init(hio_t* io) {
    if ((io->io_type & HIO_TYPE_SOCK_DGRAM) || (io->io_type & HIO_TYPE_SOCK_RAW)) {
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
    printd("getsockname fd=%d ret=%d errno=%d\n", io->fd, ret, socket_errno());
    // NOTE: udp peeraddr set by recvfrom/sendto
    if (io->io_type & HIO_TYPE_SOCK_STREAM) {
        addrlen = sizeof(sockaddr_u);
        ret = getpeername(io->fd, io->peeraddr, &addrlen);
        printd("getpeername fd=%d ret=%d errno=%d\n", io->fd, ret, socket_errno());
    }
}

void hio_init(hio_t* io) {
    // alloc localaddr,peeraddr when hio_socket_init
    /*
    if (io->localaddr == NULL) {
        EVENTLOOP_ALLOC(io->localaddr, sizeof(sockaddr_u));
    }
    if (io->peeraddr == NULL) {
        EVENTLOOP_ALLOC(io->peeraddr, sizeof(sockaddr_u));
    }
    */

    // write_queue init when hwrite try_write failed
    // write_queue_init(&io->write_queue, 4);

    // initRecursiveMutex(&io->write_mutex);
    (void)io;
}

void hio_ready(hio_t* io) {
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
    io->id = hio_next_id();
    io->io_type = HIO_TYPE_UNKNOWN;
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
    fill_io_type(io);
    if (io->io_type & HIO_TYPE_SOCKET) {
        hio_socket_init(io);
    }
}

void hio_done(hio_t* io) {
    if (!io->ready) return;
    io->ready = 0;

    hio_del(io, WW_RDWR);

    // write_queue
    shift_buffer_t* buf = NULL;
    //
    while (!write_queue_empty(&io->write_queue)) {
        buf = *write_queue_front(&io->write_queue);
        reuseBuffer(io->loop->bufpool, buf);
        write_queue_pop_front(&io->write_queue);
    }
    write_queue_cleanup(&io->write_queue);
    io->write_queue.ptr = NULL;
}

void hio_free(hio_t* io) {
    if (io == NULL || io->destroy) return;
    io->destroy = 1;
    hio_close(io);
    EVENTLOOP_FREE(io->localaddr);
    EVENTLOOP_FREE(io->peeraddr);
    EVENTLOOP_FREE(io);
}

bool hio_is_opened(hio_t* io) {
    if (io == NULL) return false;
    return io->ready == 1 && io->closed == 0;
}

bool hio_is_connected(hio_t* io) {
    if (io == NULL) return false;
    return io->ready == 1 && io->connected == 1 && io->closed == 0;
}

bool hio_is_closed(hio_t* io) {
    if (io == NULL) return true;
    return io->ready == 0 && io->closed == 1;
}

uint32_t hio_id(hio_t* io) {
    return io->id;
}

int hio_fd(hio_t* io) {
    return io->fd;
}

hio_type_e hio_type(hio_t* io) {
    return io->io_type;
}

int hio_error(hio_t* io) {
    return io->error;
}

int hio_events(hio_t* io) {
    return io->events;
}

int hio_revents(hio_t* io) {
    return io->revents;
}

struct sockaddr_u* hio_localaddr_u(hio_t* io) {
    return io->localaddr_u;
}

struct sockaddr_u* hio_peeraddr_u(hio_t* io) {
    return io->peeraddr_u;
}

struct sockaddr* hio_localaddr(hio_t* io) {
    return io->localaddr;
}

struct sockaddr* hio_peeraddr(hio_t* io) {
    return io->peeraddr;
}

haccept_cb hio_getcb_accept(hio_t* io) {
    return io->accept_cb;
}

hconnect_cb hio_getcb_connect(hio_t* io) {
    return io->connect_cb;
}

hread_cb hio_getcb_read(hio_t* io) {
    return io->read_cb;
}

hwrite_cb hio_getcb_write(hio_t* io) {
    return io->write_cb;
}

hclose_cb hio_getcb_close(hio_t* io) {
    return io->close_cb;
}

void hio_setcb_accept(hio_t* io, haccept_cb accept_cb) {
    io->accept_cb = accept_cb;
}

void hio_setcb_connect(hio_t* io, hconnect_cb connect_cb) {
    io->connect_cb = connect_cb;
}

void hio_setcb_read(hio_t* io, hread_cb read_cb) {
    io->read_cb = read_cb;
}

void hio_setcb_write(hio_t* io, hwrite_cb write_cb) {
    io->write_cb = write_cb;
}

void hio_setcb_close(hio_t* io, hclose_cb close_cb) {
    io->close_cb = close_cb;
}

void hio_accept_cb(hio_t* io) {
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

void hio_connect_cb(hio_t* io) {
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

void hio_handle_read(hio_t* io, shift_buffer_t* buf) {
    // hio_read
    hio_read_cb(io, buf);
}

void hio_read_cb(hio_t* io, shift_buffer_t* buf) {
    if (io->read_flags & HIO_READ_ONCE) {
        io->read_flags &= ~HIO_READ_ONCE;
        hio_read_stop(io);
    }

    if (io->read_cb) {
        // printd("read_cb------\n");
        io->read_cb(io, buf);
        // printd("read_cb======\n");
    }
}

void hio_write_cb(hio_t* io) {
    if (io->write_cb) {
        // printd("write_cb------\n");
        io->write_cb(io);
        // printd("write_cb======\n");
    }
}

void hio_close_cb(hio_t* io) {
    io->connected = 0;
    io->closed = 1;
    if (io->close_cb) {
        // printd("close_cb------\n");
        io->close_cb(io);
        // printd("close_cb======\n");
    }
}

void hio_set_type(hio_t* io, hio_type_e type) {
    io->io_type = type;
}

void hio_set_localaddr(hio_t* io, struct sockaddr* addr, int addrlen) {
    if (io->localaddr == NULL) {
        EVENTLOOP_ALLOC(io->localaddr, sizeof(sockaddr_u));
    }
    memcpy(io->localaddr, addr, addrlen);
}

void hio_set_peeraddr(hio_t* io, struct sockaddr* addr, int addrlen) {
    if (io->peeraddr == NULL) {
        EVENTLOOP_ALLOC(io->peeraddr, sizeof(sockaddr_u));
    }
    memcpy(io->peeraddr, addr, addrlen);
}

void hio_del_connect_timer(hio_t* io) {
    if (io->connect_timer) {
        htimer_del(io->connect_timer);
        io->connect_timer = NULL;
        io->connect_timeout = 0;
    }
}

void hio_del_close_timer(hio_t* io) {
    if (io->close_timer) {
        htimer_del(io->close_timer);
        io->close_timer = NULL;
        io->close_timeout = 0;
    }
}

void hio_del_read_timer(hio_t* io) {
    if (io->read_timer) {
        htimer_del(io->read_timer);
        io->read_timer = NULL;
        io->read_timeout = 0;
    }
}

void hio_del_write_timer(hio_t* io) {
    if (io->write_timer) {
        htimer_del(io->write_timer);
        io->write_timer = NULL;
        io->write_timeout = 0;
    }
}

void hio_del_keepalive_timer(hio_t* io) {
    if (io->keepalive_timer) {
        htimer_del(io->keepalive_timer);
        io->keepalive_timer = NULL;
        io->keepalive_timeout = 0;
    }
}

void hio_del_heartbeat_timer(hio_t* io) {
    if (io->heartbeat_timer) {
        htimer_del(io->heartbeat_timer);
        io->heartbeat_timer = NULL;
        io->heartbeat_interval = 0;
        io->heartbeat_fn = NULL;
    }
}

void hio_set_connect_timeout(hio_t* io, int timeout_ms) {
    io->connect_timeout = timeout_ms;
}

void hio_set_close_timeout(hio_t* io, int timeout_ms) {
    io->close_timeout = timeout_ms;
}

static void __read_timeout_cb(htimer_t* timer) {
    hio_t* io = (hio_t*)timer->privdata;
    uint64_t inactive_ms = (io->loop->cur_hrtime - io->last_read_hrtime) / 1000;
    if (inactive_ms + 100 < (uint64_t)io->read_timeout) {
        htimer_reset(io->read_timer, io->read_timeout - inactive_ms);
    }
    else {
        if (io->io_type & HIO_TYPE_SOCKET) {
            char localaddrstr[SOCKADDR_STRLEN] = {0};
            char peeraddrstr[SOCKADDR_STRLEN] = {0};
            wlogw("read timeout [%s] <=> [%s]", SOCKADDR_STR(io->localaddr, localaddrstr), SOCKADDR_STR(io->peeraddr, peeraddrstr));
        }
        io->error = ETIMEDOUT;
        hio_close(io);
    }
}

void hio_set_read_timeout(hio_t* io, int timeout_ms) {
    if (timeout_ms <= 0) {
        // del
        hio_del_read_timer(io);
        return;
    }

    if (io->read_timer) {
        // reset
        htimer_reset(io->read_timer, timeout_ms);
    }
    else {
        // add
        io->read_timer = htimer_add(io->loop, __read_timeout_cb, timeout_ms, 1);
        io->read_timer->privdata = io;
    }
    io->read_timeout = timeout_ms;
}

static void __write_timeout_cb(htimer_t* timer) {
    hio_t* io = (hio_t*)timer->privdata;
    uint64_t inactive_ms = (io->loop->cur_hrtime - io->last_write_hrtime) / 1000;
    if (inactive_ms + 100 < (uint64_t)io->write_timeout) {
        htimer_reset(io->write_timer, io->write_timeout - inactive_ms);
    }
    else {
        if (io->io_type & HIO_TYPE_SOCKET) {
            char localaddrstr[SOCKADDR_STRLEN] = {0};
            char peeraddrstr[SOCKADDR_STRLEN] = {0};
            wlogw("write timeout [%s] <=> [%s]", SOCKADDR_STR(io->localaddr, localaddrstr), SOCKADDR_STR(io->peeraddr, peeraddrstr));
        }
        io->error = ETIMEDOUT;
        hio_close(io);
    }
}

void hio_set_write_timeout(hio_t* io, int timeout_ms) {
    if (timeout_ms <= 0) {
        // del
        hio_del_write_timer(io);
        return;
    }

    if (io->write_timer) {
        // reset
        htimer_reset(io->write_timer, timeout_ms);
    }
    else {
        // add
        io->write_timer = htimer_add(io->loop, __write_timeout_cb, timeout_ms, 1);
        io->write_timer->privdata = io;
    }
    io->write_timeout = timeout_ms;
}

static void __keepalive_timeout_cb(htimer_t* timer) {
    hio_t* io = (hio_t*)timer->privdata;
    uint64_t last_rw_hrtime = max(io->last_read_hrtime, io->last_write_hrtime);
    uint64_t inactive_ms = (io->loop->cur_hrtime - last_rw_hrtime) / 1000;
    if (inactive_ms + 100 < (uint64_t)io->keepalive_timeout) {
        htimer_reset(io->keepalive_timer, io->keepalive_timeout - inactive_ms);
    }
    else {
        if (io->io_type & HIO_TYPE_SOCKET) {
            char localaddrstr[SOCKADDR_STRLEN] = {0};
            char peeraddrstr[SOCKADDR_STRLEN] = {0};
            wlogd("keepalive timeout [%s] <=> [%s]", SOCKADDR_STR(io->localaddr, localaddrstr), SOCKADDR_STR(io->peeraddr, peeraddrstr));
        }
        io->error = ETIMEDOUT;
        hio_close(io);
    }
}

void hio_set_keepalive_timeout(hio_t* io, int timeout_ms) {
    if (timeout_ms <= 0) {
        // del
        hio_del_keepalive_timer(io);
        return;
    }

    if (io->keepalive_timer) {
        // reset
        htimer_reset(io->keepalive_timer, timeout_ms);
    }
    else {
        // add
        io->keepalive_timer = htimer_add(io->loop, __keepalive_timeout_cb, timeout_ms, 1);
        io->keepalive_timer->privdata = io;
    }
    io->keepalive_timeout = timeout_ms;
}

static void __heartbeat_timer_cb(htimer_t* timer) {
    hio_t* io = (hio_t*)timer->privdata;
    if (io && io->heartbeat_fn) {
        io->heartbeat_fn(io);
    }
}

void hio_set_heartbeat(hio_t* io, int interval_ms, hio_send_heartbeat_fn fn) {
    if (interval_ms <= 0) {
        // del
        hio_del_heartbeat_timer(io);
        return;
    }

    if (io->heartbeat_timer) {
        // reset
        htimer_reset(io->heartbeat_timer, interval_ms);
    }
    else {
        // add
        io->heartbeat_timer = htimer_add(io->loop, __heartbeat_timer_cb, interval_ms, INFINITE);
        io->heartbeat_timer->privdata = io;
    }
    io->heartbeat_interval = interval_ms;
    io->heartbeat_fn = fn;
}

//-----------------iobuf---------------------------------------------

void hio_set_max_write_bufsize(hio_t* io, uint32_t size) {
    io->max_write_bufsize = size;
}

size_t hio_write_bufsize(hio_t* io) {
    return io->write_bufsize;
}

int hio_read_once(hio_t* io) {
    io->read_flags |= HIO_READ_ONCE;
    return hio_read_start(io);
}

//-----------------upstream---------------------------------------------
// void hio_read_upstream(hio_t* io) {
//     hio_t* upstream_io = io->upstream_io;
//     if (upstream_io) {
//         hio_read(io);
//         hio_read(upstream_io);
//     }
// }

// void hio_read_upstream_on_write_complete(hio_t* io, const void* buf, int writebytes) {
//     hio_t* upstream_io = io->upstream_io;
//     if (upstream_io && hio_write_is_complete(io)) {
//         hio_setcb_write(io, NULL);
//         hio_read(upstream_io);
//     }
// }

// void hio_write_upstream(hio_t* io, void* buf, int bytes) {
//     hio_t* upstream_io = io->upstream_io;
//     if (upstream_io) {
//         int nwrite = hio_write(upstream_io, buf, bytes);
//         // if (!hio_write_is_complete(upstream_io)) {
//         if (nwrite >= 0 && nwrite < bytes) {
//             hio_read_stop(io);
//             hio_setcb_write(upstream_io, hio_read_upstream_on_write_complete);
//         }
//     }
// }
// #if defined(OS_LINUX) && defined(HAVE_PIPE)

// void hio_close_upstream(hio_t* io) {
//     hio_t* upstream_io = io->upstream_io;
//     if(io->pfd_w != 0x0){
//         close(io->pfd_w);
//         close(io->pfd_r);
//     }
//     if (upstream_io) {
//         hio_close(upstream_io);
//     }
// }

// static bool hio_setup_pipe(hio_t* io) {
//     int fds[2];
//     int r = pipe(fds);
//     if (r != 0)
//         return false;
//     io->pfd_r = fds[0];
//     io->pfd_w = fds[1];
//     return true;

// }

// void hio_setup_upstream_splice(hio_t* restrict io1, hio_t* restrict io2) {
//     io1->upstream_io = io2;
//     io2->upstream_io = io1;
//     assert (io1->io_type == HIO_TYPE_TCP && io2->io_type == HIO_TYPE_TCP);
//     if (!hio_setup_pipe(io1))
//         return;

//     if (!hio_setup_pipe(io2)){
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

// void hio_close_upstream(hio_t* io) {
//     hio_t* upstream_io = io->upstream_io;
//     if (upstream_io) {
//         hio_close(upstream_io);
//     }
// }

// #endif

// void hio_setup_upstream(hio_t* restrict io1, hio_t* restrict io2) {
//     io1->upstream_io = io2;
//     io2->upstream_io = io1;
// }

// hio_t* hio_get_upstream(hio_t* io) {
//     return io->upstream_io;
// }

// hio_t* hio_setup_tcp_upstream(hio_t* io, const char* host, int port) {
//     hio_t* upstream_io = hio_create_socket(io->loop, host, port, HIO_TYPE_TCP, HIO_CLIENT_SIDE);
//     if (upstream_io == NULL) return NULL;
//     // #if defined(OS_LINUX) && defined(HAVE_PIPE)
//     //     hio_setup_upstream_splice(io, upstream_io);
//     // #else
//     hio_setup_upstream(io, upstream_io);
//     // #endif

//     hio_setcb_read(io, hio_write_upstream);
//     hio_setcb_read(upstream_io, hio_write_upstream);

//     hio_setcb_close(io, hio_close_upstream);
//     hio_setcb_close(upstream_io, hio_close_upstream);
//     hio_setcb_connect(upstream_io, hio_read_upstream);
//     hio_connect(upstream_io);
//     return upstream_io;
// }

// hio_t* hio_setup_udp_upstream(hio_t* io, const char* host, int port) {
//     hio_t* upstream_io = hio_create_socket(io->loop, host, port, HIO_TYPE_UDP, HIO_CLIENT_SIDE);
//     if (upstream_io == NULL) return NULL;
//     hio_setup_upstream(io, upstream_io);
//     hio_setcb_read(io, hio_write_upstream);
//     hio_setcb_read(upstream_io, hio_write_upstream);
//     hio_read_upstream(io);
//     return upstream_io;
// }
