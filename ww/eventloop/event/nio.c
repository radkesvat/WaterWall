#include "iowatcher.h"
#include "ww.h"
#ifndef EVENT_IOCP
#include "hevent.h"
#include "hsocket.h"
#include "hlog.h"
#include "herr.h"
#include "hthread.h"

static void __connect_timeout_cb(htimer_t* timer) {
    hio_t* io = (hio_t*)timer->privdata;
    if (io) {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        hlogw("connect timeout [%s] <=> [%s]", SOCKADDR_STR(io->localaddr, localaddrstr), SOCKADDR_STR(io->peeraddr, peeraddrstr));
        io->error = ETIMEDOUT;
        hio_close(io);
    }
}

static void __close_timeout_cb(htimer_t* timer) {
    hio_t* io = (hio_t*)timer->privdata;
    if (io) {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        hlogw("close timeout [%s] <=> [%s]", SOCKADDR_STR(io->localaddr, localaddrstr), SOCKADDR_STR(io->peeraddr, peeraddrstr));
        io->error = ETIMEDOUT;
        hio_close(io);
    }
}

static void __accept_cb(hio_t* io) {
    hio_accept_cb(io);
}

static void __connect_cb(hio_t* io) {
    hio_del_connect_timer(io);
    hio_connect_cb(io);
}

static void __read_cb(hio_t* io, shift_buffer_t* buf) {
    // printd("> %.*s\n", readbytes, buf);
    io->last_read_hrtime = io->loop->cur_hrtime;
    hio_handle_read(io, buf);
}

static void __write_cb(hio_t* io) {
    // printd("< %.*s\n", writebytes, buf);
    io->last_write_hrtime = io->loop->cur_hrtime;
    hio_write_cb(io);
}

static void __close_cb(hio_t* io) {
    // printd("close fd=%d\n", io->fd);
    hio_del_connect_timer(io);
    hio_del_close_timer(io);
    hio_del_read_timer(io);
    hio_del_write_timer(io);
    hio_del_keepalive_timer(io);
    hio_del_heartbeat_timer(io);
    hio_close_cb(io);
}

static void nio_accept(hio_t* io) {
    // printd("nio_accept listenfd=%d\n", io->fd);
    int connfd = 0, err = 0, accept_cnt = 0;
    socklen_t addrlen;
    hio_t* connio = NULL;
    while (accept_cnt++ < 3) {
        addrlen = sizeof(sockaddr_u);
        connfd = accept(io->fd, io->peeraddr, &addrlen);
        if (connfd < 0) {
            err = socket_errno();
            if (err == EAGAIN || err == EINTR) {
                return;
            }
            else {
                perror("accept");
                io->error = err;
                goto accept_error;
            }
        }
        addrlen = sizeof(sockaddr_u);
        getsockname(connfd, io->localaddr, &addrlen);
        connio = hio_get(io->loop, connfd);
        // NOTE: inherit from listenio
        connio->accept_cb = io->accept_cb;
        connio->userdata = io->userdata;

        __accept_cb(connio);
    }
    return;

accept_error:
    hloge("listenfd=%d accept error: %s:%d", io->fd, socket_strerror(io->error), io->error);
    // NOTE: Don't close listen fd automatically anyway.
    // hio_close(io);
}

static void nio_connect(hio_t* io) {
    // printd("nio_connect connfd=%d\n", io->fd);
    socklen_t addrlen = sizeof(sockaddr_u);
    int ret = getpeername(io->fd, io->peeraddr, &addrlen);
    if (ret < 0) {
        io->error = socket_errno();
        goto connect_error;
    }
    else {
        addrlen = sizeof(sockaddr_u);
        getsockname(io->fd, io->localaddr, &addrlen);

        __connect_cb(io);

        return;
    }

connect_error:
    hlogw("connfd=%d connect error: %s:%d", io->fd, socket_strerror(io->error), io->error);
    hio_close(io);
}

static void nio_connect_event_cb(hevent_t* ev) {
    hio_t* io = (hio_t*)ev->userdata;
    uint32_t id = (uintptr_t)ev->privdata;
    if (io->id != id) return;
    nio_connect(io);
}

static int nio_connect_async(hio_t* io) {
    hevent_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.cb = nio_connect_event_cb;
    ev.userdata = io;
    ev.privdata = (void*)(uintptr_t)io->id;
    hloop_post_event(io->loop, &ev);
    return 0;
}

static int __nio_read(hio_t* io, void* buf, int len) {
    int nread = 0;
    switch (io->io_type) {

    case HIO_TYPE_TCP:
        // #if defined(OS_LINUX) && defined(HAVE_PIPE)
        //         if(io->pfd_w){
        //             nread = splice(io->fd, NULL,io->pfd_w,0, len, SPLICE_F_NONBLOCK);
        //         }else
        // #endif
        nread = recv(io->fd, buf, len, 0);
        break;
    case HIO_TYPE_UDP:
    case HIO_TYPE_IP: {
        socklen_t addrlen = sizeof(sockaddr_u);
        nread = recvfrom(io->fd, buf, len, 0, io->peeraddr, &addrlen);
    } break;
    default: nread = read(io->fd, buf, len); break;
    }
    // hlogd("read retval=%d", nread);
    return nread;
}

static int __nio_write(hio_t* io, const void* buf, int len) {
    int nwrite = 0;
    switch (io->io_type) {
    case HIO_TYPE_TCP: {
        // #if defined(OS_LINUX) && defined(HAVE_PIPE)
        //     if(io->pfd_r){
        //         nwrite = splice(io->pfd_r, NULL,io->fd,0, len, SPLICE_F_NONBLOCK);
        //         break;
        //     }
        // #endif
        int flag = 0;
#ifdef MSG_NOSIGNAL
        flag |= MSG_NOSIGNAL;
#endif
        nwrite = send(io->fd, buf, len, flag);
    } break;
    case HIO_TYPE_UDP:
    case HIO_TYPE_IP: nwrite = sendto(io->fd, buf, len, 0, io->peeraddr, SOCKADDR_LEN(io->peeraddr)); break;
    default: nwrite = write(io->fd, buf, len); break;
    }
    // hlogd("write retval=%d", nwrite);
    return nwrite;
}

static void nio_read(hio_t* io) {
    // printd("nio_read fd=%d\n", io->fd);
    int nread = 0, err = 0;
    //  read:;

    // #if defined(OS_LINUX) && defined(HAVE_PIPE)
    //     if(io->pfd_w){
    //         len = (1U << 20); // 1 MB
    //     }else
    // #endif
    shift_buffer_t* buf;

    switch (io->io_type) {
    default:
    case HIO_TYPE_TCP: buf = popBuffer(io->loop->bufpool); break;
    case HIO_TYPE_UDP:
    case HIO_TYPE_IP: buf = popSmallBuffer(io->loop->bufpool); break;
    }

    unsigned int available = rCap(buf);
    if (available > (1U << 15)) {
        available = (1U << 15);
    }
    else if (WW_UNLIKELY(available < 1024)) {
        reserveBufSpace(buf, 1024);
    }
    nread = __nio_read(io, rawBufMut(buf), available);

    // printd("read retval=%d\n", nread);
    if (nread < 0) {
        err = socket_errno();
        if (err == EAGAIN || err == EINTR) {
            // goto read_done;
            reuseBuffer(io->loop->bufpool, buf);
            return;
        }
        else if (err == EMSGSIZE) {
            // ignore
            reuseBuffer(io->loop->bufpool, buf);
            return;
        }
        else {
            // perror("read");
            reuseBuffer(io->loop->bufpool, buf);
            io->error = err;
            goto read_error;
        }
    }
    if (nread == 0) {
        reuseBuffer(io->loop->bufpool, buf);
        goto disconnect;
    }
    // printf("%d \n",nread);
    // #if defined(OS_LINUX) && defined(HAVE_PIPE)
    //     if(io->pfd_w == 0x0 && nread < len){
    //         // NOTE: make string friendly
    //         ((char*)buf)[nread] = '\0';
    //     }
    // #else

    // if (nread < len) {
    //     // NOTE: make string friendly
    //     ((char*)buf)[nread] = '\0';
    // }
    // #endif

    setLen(buf, nread);
    __read_cb(io, buf);
    // user consumed buffer
    return;
read_error:
disconnect:
    if (io->io_type & HIO_TYPE_SOCK_STREAM) {
        hio_close(io);
    }
}

static void nio_write(hio_t* io) {
    // printd("nio_write fd=%d\n", io->fd);
    int nwrite = 0, err = 0;
    //
write:
    if (write_queue_empty(&io->write_queue)) {

        if (io->close) {
            io->close = 0;
            hio_close(io);
        }
        return;
    }
    shift_buffer_t* buf = *write_queue_front(&io->write_queue);
    int len = (int)bufLen(buf);
    // char* base = pbuf->base;
    nwrite = __nio_write(io, rawBufMut(buf), len);
    // printd("write retval=%d\n", nwrite);
    if (nwrite < 0) {
        err = socket_errno();
        if (err == EAGAIN || err == EINTR) {

            return;
        }
        else {
            // perror("write");
            io->error = err;
            goto write_error;
        }
    }
    if (nwrite == 0) {
        goto disconnect;
    }
    shiftr(buf, nwrite);
    io->write_bufsize -= nwrite;
    if (nwrite == len) {
        // NOTE: after write_cb, pbuf maybe invalid.
        // HV_FREE(pbuf->base);
        // #if defined(OS_LINUX) && defined(HAVE_PIPE)
        //     if(io->pfd_w == 0)
        //         HV_FREE(base);
        // #else
        reuseBuffer(io->loop->bufpool, buf);
        // #endif
        write_queue_pop_front(&io->write_queue);
        __write_cb(io);

        if (!io->closed) {
            // write continue
            goto write;
        }
    }
    else {
        __write_cb(io);
    }

    return;
write_error:
disconnect:

    if (io->io_type & HIO_TYPE_SOCK_STREAM) {
        hio_close(io);
    }
}

static void hio_handle_events(hio_t* io) {
    if ((io->events & HV_READ) && (io->revents & HV_READ)) {
        if (io->accept) {
            nio_accept(io);
        }
        else {
            nio_read(io);
        }
    }

    if ((io->events & HV_WRITE) && (io->revents & HV_WRITE)) {
        // NOTE: del HV_WRITE, if write_queue empty
        //
        if (write_queue_empty(&io->write_queue)) {
            hio_del(io, HV_WRITE);
        }

        if (io->connect) {
            // NOTE: connect just do once
            // ONESHOT
            io->connect = 0;

            nio_connect(io);
        }
        else {
            nio_write(io);
        }
    }

    io->revents = 0;
}

int hio_accept(hio_t* io) {
    io->accept = 1;
    return hio_add(io, hio_handle_events, HV_READ);
}

int hio_connect(hio_t* io) {
    int ret = connect(io->fd, io->peeraddr, SOCKADDR_LEN(io->peeraddr));
#ifdef OS_WIN
    if (ret < 0 && socket_errno() != WSAEWOULDBLOCK) {
#else
    if (ret < 0 && socket_errno() != EINPROGRESS) {
#endif
        perror("connect");
        io->error = socket_errno();
        hio_close_async(io);
        return ret;
    }
    if (ret == 0) {
        // connect ok
        nio_connect_async(io);
        return 0;
    }
    int timeout = io->connect_timeout ? io->connect_timeout : HIO_DEFAULT_CONNECT_TIMEOUT;
    io->connect_timer = htimer_add(io->loop, __connect_timeout_cb, timeout, 1);
    io->connect_timer->privdata = io;
    io->connect = 1;
    return hio_add(io, hio_handle_events, HV_WRITE);
}

int hio_read(hio_t* io) {
    if (io->closed) {
        hloge("hio_read called but fd[%d] already closed!", io->fd);
        return -1;
    }
    hio_add(io, hio_handle_events, HV_READ);

    return 0;
}

int hio_write(hio_t* io, shift_buffer_t* buf) {
    if (io->closed) {
        hloge("hio_write called but fd[%d] already closed!", io->fd);
        reuseBuffer(io->loop->bufpool, buf);
        return -1;
    }
    int nwrite = 0, err = 0;
    //
    int len = (int)bufLen(buf);
    if (write_queue_empty(&io->write_queue)) {
        //    try_write:
        nwrite = __nio_write(io, rawBufMut(buf), len);
        // printd("write retval=%d\n", nwrite);
        if (nwrite < 0) {
            err = socket_errno();
            if (err == EAGAIN || err == EINTR) {
                nwrite = 0;
                hlogd("try_write failed, enqueue!");
                goto enqueue;
            }
            else {
                // perror("write");
                io->error = err;
                goto write_error;
            }
        }
        if (nwrite == 0) {
            goto disconnect;
        }
        if (nwrite == len) {
            goto write_done;
        }
    enqueue:
        hio_add(io, hio_handle_events, HV_WRITE);
    }

    if (nwrite < len) {
        if (io->write_bufsize + len - nwrite > io->max_write_bufsize) {
            hloge("write bufsize > %u, close it!", io->max_write_bufsize);
            io->error = ERR_OVER_LIMIT;
            goto write_error;
        }
        shiftr(buf, nwrite);
        // #if defined(OS_LINUX) && defined(HAVE_PIPE)
        //         if(io->pfd_w != 0){
        //             remain.base = 0X0; // skips globalFree()

        //         }else
        //         {
        //             // NOTE: free in nio_write
        //             HV_ALLOC(remain.base, remain.len);
        //             memcpy(remain.base, ((char*)buf) + nwrite, remain.len);
        //         }
        // #else
        // NOTE: free in nio_write

        // HV_ALLOC(remain.base, remain.len);
        // memcpy(remain.base, ((char*)buf) + nwrite, remain.len);

        // #endif
        if (io->write_queue.maxsize == 0) {
            write_queue_init(&io->write_queue, 4);
        }
        write_queue_push_back(&io->write_queue, &buf);
        io->write_bufsize += bufLen(buf);
        if (io->write_bufsize > WRITE_BUFSIZE_HIGH_WATER) {
            hlogw("write len=%u enqueue %u, bufsize=%u over high water %u", (unsigned int)len, (unsigned int)(bufLen(buf)), (unsigned int)io->write_bufsize,
                  (unsigned int)WRITE_BUFSIZE_HIGH_WATER);
        }
    }

write_done:

    if (nwrite > 0) {
        if (nwrite == len) {
            reuseBuffer(io->loop->bufpool, buf);
        }
        __write_cb(io);
    }
    return nwrite;
write_error:
disconnect:

    /* NOTE:
     * We usually free resources in hclose_cb,
     * if hio_close_sync, we have to be very careful to avoid using freed resources.
     * But if hio_close_async, we do not have to worry about this.
     */
    reuseBuffer(io->loop->bufpool, buf);
    if (io->io_type & HIO_TYPE_SOCK_STREAM) {
        hio_close_async(io);
    }
    return nwrite < 0 ? nwrite : -1;
}

// This must only be called from the same thread that created the loop
int hio_close(hio_t* io) {
    if (io->closed) return 0;

    // if (io->destroy == 0 && hv_gettid() != io->loop->tid) {
    //     return hio_close_async(io); /*  tid lost its meaning, its now ww tid */
    // }

    if (io->closed) {

        return 0;
    }
    if (!write_queue_empty(&io->write_queue) && io->error == 0 && io->close == 0 && io->destroy == 0) {
        io->close = 1;

        hlogd("write_queue not empty, close later.");
        int timeout_ms = io->close_timeout ? io->close_timeout : HIO_DEFAULT_CLOSE_TIMEOUT;
        io->close_timer = htimer_add(io->loop, __close_timeout_cb, timeout_ms, 1);
        io->close_timer->privdata = io;
        return 0;
    }
    io->closed = 1;

    hio_done(io);
    __close_cb(io);
    // SAFE_FREE(io->hostname);
    if (io->io_type & HIO_TYPE_SOCKET) {
        closesocket(io->fd);
    }
    return 0;
}
#endif
