#include "iowatcher.h"
#include "worker.h"
#ifndef EVENT_IOCP
#include "wevent.h"
#include "wsocket.h"
#include "wlog.h"
#include "werr.h"
#include "wthread.h"

static void __connect_timeout_cb(wtimer_t* timer) {
    wio_t* io = (wio_t*)timer->privdata;
    if (io) {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        wlogw("connect timeout [%s] <=> [%s]", SOCKADDR_STR(io->localaddr, localaddrstr), SOCKADDR_STR(io->peeraddr, peeraddrstr));
        io->error = ETIMEDOUT;
        wioClose(io);
    }
}

static void __close_timeout_cb(wtimer_t* timer) {
    wio_t* io = (wio_t*)timer->privdata;
    if (io) {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        wlogw("close timeout [%s] <=> [%s]", SOCKADDR_STR(io->localaddr, localaddrstr), SOCKADDR_STR(io->peeraddr, peeraddrstr));
        io->error = ETIMEDOUT;
        wioClose(io);
    }
}

static void __accept_cb(wio_t* io) {
    wioAcceptCallBack(io);
}

static void __connect_cb(wio_t* io) {
    wioDelConnectTimer(io);
    wioConnectCallBack(io);
}

static void __read_cb(wio_t* io, sbuf_t* buf) {
    // printd("> %.*s\n", readbytes, buf);
    io->last_read_hrtime = io->loop->cur_hrtime;
    wioHandleRead(io, buf);
}

static void __write_cb(wio_t* io) {
    // printd("< %.*s\n", writebytes, buf);
    io->last_write_hrtime = io->loop->cur_hrtime;
    wioWriteCallBack(io);
}

static void __close_cb(wio_t* io) {
    // printd("close fd=%d\n", io->fd);
    wioDelConnectTimer(io);
    wioDelCloseTimer(io);
    wioDelReadTimer(io);
    wioDelWriteTimer(io);
    wioDelKeepaliveTimer(io);
    wioDelHeartBeatTimer(io);
    wioCloseCallBack(io);
}

static void nio_accept(wio_t* io) {
    // printd("nio_accept listenfd=%d\n", io->fd);
    int connfd = 0, err = 0, accept_cnt = 0;
    socklen_t addrlen;
    wio_t* connio = NULL;
    while (accept_cnt++ < 3) {
        addrlen = sizeof(sockaddr_u);
        connfd = accept(io->fd, io->peeraddr, &addrlen);
        if (connfd < 0) {
            err = socketERRNO();
            if (err == EAGAIN || err == EINTR) {
                return;
            }
            else {
                printError("accept");
                io->error = err;
                goto accept_error;
            }
        }
        addrlen = sizeof(sockaddr_u);
        getsockname(connfd, io->localaddr, &addrlen);
        connio = wioGet(io->loop, connfd);
        // NOTE: inherit from listenio
        connio->accept_cb = io->accept_cb;
        connio->userdata = io->userdata;

        __accept_cb(connio);
    }
    return;

accept_error:
    wloge("listenfd=%d accept error: %s:%d", io->fd, socketStrError(io->error), io->error);
    // NOTE: Don't close listen fd automatically anyway.
    // wioClose(io);
}

static void nio_connect(wio_t* io) {
    // printd("nio_connect connfd=%d\n", io->fd);
    socklen_t addrlen = sizeof(sockaddr_u);
    int ret = getpeername(io->fd, io->peeraddr, &addrlen);
    if (ret < 0) {
        io->error = socketERRNO();
        goto connect_error;
    }
    else {
        addrlen = sizeof(sockaddr_u);
        getsockname(io->fd, io->localaddr, &addrlen);

        __connect_cb(io);

        return;
    }

connect_error:
    wlogw("connfd=%d connect error: %s:%d", io->fd, socketStrError(io->error), io->error);
    wioClose(io);
}

static void nio_connect_event_cb(wevent_t* ev) {
    wio_t* io = (wio_t*)ev->userdata;
    uint32_t id = (uintptr_t)ev->privdata;
    if (io->id != id) return;
    nio_connect(io);
}

static int nio_connect_async(wio_t* io) {
    wevent_t ev;
    memorySet(&ev, 0, sizeof(ev));
    ev.cb = nio_connect_event_cb;
    ev.userdata = io;
    ev.privdata = (void*)(uintptr_t)io->id;
    wloopPostEvent(io->loop, &ev);
    return 0;
}

static int __nio_read(wio_t* io, void* buf, int len) {
    int nread = 0;
    switch (io->io_type) {

    case WIO_TYPE_TCP:
        // #if defined(OS_LINUX) && defined(HAVE_PIPE)
        //         if(io->pfd_w){
        //             nread = splice(io->fd, NULL,io->pfd_w,0, len, SPLICE_F_NONBLOCK);
        //         }else
        // #endif
        nread = recv(io->fd, buf, len, 0);
        break;
    case WIO_TYPE_UDP:
    case WIO_TYPE_IP: {
        socklen_t addrlen = sizeof(sockaddr_u);
        nread = recvfrom(io->fd, buf, len, 0, io->peeraddr, &addrlen);
    } break;
    default: nread = read(io->fd, buf, len); break;
    }
    // wlogd("read retval=%d", nread);
    return nread;
}

static int __nio_write(wio_t* io, const void* buf, int len) {
    int nwrite = 0;
    switch (io->io_type) {
    case WIO_TYPE_TCP: {
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
    case WIO_TYPE_UDP:
    case WIO_TYPE_IP: nwrite = sendto(io->fd, buf, len, 0, io->peeraddr, SOCKADDR_LEN(io->peeraddr)); break;
    default: nwrite = write(io->fd, buf, len); break;
    }
    // wlogd("write retval=%d", nwrite);
    return nwrite;
}

static void nio_read(wio_t* io) {
    // printd("nio_read fd=%d\n", io->fd);
    int nread = 0, err = 0;
    //  read:;

    // #if defined(OS_LINUX) && defined(HAVE_PIPE)
    //     if(io->pfd_w){
    //         len = (1U << 20); // 1 MB
    //     }else
    // #endif
    sbuf_t* buf;

    switch (io->io_type) {
    default:
    case WIO_TYPE_TCP: buf = bufferpoolPop(io->loop->bufpool); break;
    case WIO_TYPE_UDP:
    case WIO_TYPE_IP: buf = bufferpoolPopSmall(io->loop->bufpool); break;
    }

    unsigned int available = sbufGetRightCapacityNoPadding(buf);
    assert(available >= 1024);

    if (available > (1U << 15)) {
        available = (1U << 15);
    }
  
  
    nread = __nio_read(io, sbufGetMutablePtr(buf), available);

    // printd("read retval=%d\n", nread);
    if (nread < 0) {
        err = socketERRNO();
        if (err == EAGAIN || err == EINTR) {
            // goto read_done;
            bufferpoolResuesBuf(io->loop->bufpool, buf);
            return;
        }
        else if (err == EMSGSIZE) {
            // ignore
            bufferpoolResuesBuf(io->loop->bufpool, buf);
            return;
        }
        else {
            // printError("read");
            bufferpoolResuesBuf(io->loop->bufpool, buf);
            io->error = err;
            goto read_error;
        }
    }
    if (nread == 0) {
        bufferpoolResuesBuf(io->loop->bufpool, buf);
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

    sbufSetLength(buf, nread);
    __read_cb(io, buf);
    // user consumed buffer
    return;
read_error:
disconnect:
    if (io->io_type & WIO_TYPE_SOCK_STREAM) {
        wioClose(io);
    }
}

static void nio_write(wio_t* io) {
    // printd("nio_write fd=%d\n", io->fd);
    int nwrite = 0, err = 0;
    //
write:
    if (write_queue_empty(&io->write_queue)) {

        if (io->close) {
            io->close = 0;
            wioClose(io);
        }
        return;
    }
    sbuf_t* buf = *write_queue_front(&io->write_queue);
    int len = (int)sbufGetBufLength(buf);
    // char* base = pbuf->base;
    nwrite = __nio_write(io, sbufGetMutablePtr(buf), len);
    // printd("write retval=%d\n", nwrite);
    if (nwrite < 0) {
        err = socketERRNO();
        if (err == EAGAIN || err == EINTR) {

            return;
        }
        else {
            // printError("write");
            io->error = err;
            goto write_error;
        }
    }
    if (nwrite == 0) {
        goto disconnect;
    }
    sbufShiftRight(buf, nwrite);
    io->write_bufsize -= nwrite;
    if (nwrite == len) {
        // NOTE: after write_cb, pbuf maybe invalid.
        // EVENTLOOP_FREE(pbuf->base);
        // #if defined(OS_LINUX) && defined(HAVE_PIPE)
        //     if(io->pfd_w == 0)
        //         EVENTLOOP_FREE(base);
        // #else
        bufferpoolResuesBuf(io->loop->bufpool, buf);
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

    if (io->io_type & WIO_TYPE_SOCK_STREAM) {
        wioClose(io);
    }
}

static void wio_handle_events(wio_t* io) {
    if ((io->events & WW_READ) && (io->revents & WW_READ)) {
        if (io->accept) {
            nio_accept(io);
        }
        else {
            nio_read(io);
        }
    }

    if ((io->events & WW_WRITE) && (io->revents & WW_WRITE)) {
        // NOTE: del WW_WRITE, if write_queue empty
        //
        if (write_queue_empty(&io->write_queue)) {
            wioDel(io, WW_WRITE);
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

int wioAccept(wio_t* io) {
    io->accept = 1;
    return wioAdd(io, wio_handle_events, WW_READ);
}

int wioConnect(wio_t* io) {
    int ret = connect(io->fd, io->peeraddr, SOCKADDR_LEN(io->peeraddr));
#ifdef OS_WIN
    if (ret < 0 && socketERRNO() != WSAEWOULDBLOCK) {
#else
    if (ret < 0 && socket_errno() != EINPROGRESS) {
#endif
        printError("connect");
        io->error = socketERRNO();
        wioCloseAsync(io);
        return ret;
    }
    if (ret == 0) {
        // connect ok
        nio_connect_async(io);
        return 0;
    }
    int timeout = io->connect_timeout ? io->connect_timeout : WIO_DEFAULT_CONNECT_TIMEOUT;
    io->connect_timer = wtimerAdd(io->loop, __connect_timeout_cb, timeout, 1);
    io->connect_timer->privdata = io;
    io->connect = 1;
    return wioAdd(io, wio_handle_events, WW_WRITE);
}

int wioRead(wio_t* io) {
    if (io->closed) {
        wloge("wioRead called but fd[%d] already closed!", io->fd);
        return -1;
    }
    wioAdd(io, wio_handle_events, WW_READ);

    return 0;
}

int wioWrite(wio_t* io, sbuf_t* buf) {
    if (io->closed) {
        wloge("wioWrite called but fd[%d] already closed!", io->fd);
        bufferpoolResuesBuf(io->loop->bufpool, buf);
        return -1;
    }
    int nwrite = 0, err = 0;
    //
    int len = (int)sbufGetBufLength(buf);
    if (write_queue_empty(&io->write_queue)) {
        //    try_write:
        nwrite = __nio_write(io, sbufGetMutablePtr(buf), len);
        // printd("write retval=%d\n", nwrite);
        if (nwrite < 0) {
            err = socketERRNO();
            if (err == EAGAIN || err == EINTR) {
                nwrite = 0;
                wlogd("try_write failed, enqueue!");
                goto enqueue;
            }
            else {
                // printError("write");
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
        wioAdd(io, wio_handle_events, WW_WRITE);
    }

    if (nwrite < len) {
        if (io->write_bufsize + len - nwrite > io->max_write_bufsize) {
            wloge("write bufsize > %u, close it!", io->max_write_bufsize);
            io->error = ERR_OVER_LIMIT;
            goto write_error;
        }
        sbufShiftRight(buf, nwrite);
        // #if defined(OS_LINUX) && defined(HAVE_PIPE)
        //         if(io->pfd_w != 0){
        //             remain.base = 0X0; // skips memoryFree()

        //         }else
        //         {
        //             // NOTE: free in nio_write
        //             EVENTLOOP_ALLOC(remain.base, remain.len);
        //             memoryCopy(remain.base, ((char*)buf) + nwrite, remain.len);
        //         }
        // #else
        // NOTE: free in nio_write

        // EVENTLOOP_ALLOC(remain.base, remain.len);
        // memoryCopy(remain.base, ((char*)buf) + nwrite, remain.len);

        // #endif
        if (io->write_queue.maxsize == 0) {
            write_queue_init(&io->write_queue, 4);
        }
        write_queue_push_back(&io->write_queue, &buf);
        io->write_bufsize += sbufGetBufLength(buf);
        if (io->write_bufsize > WRITE_BUFSIZE_HIGH_WATER) {
            wlogw("write len=%u enqueue %u, bufsize=%u over high water %u", (unsigned int)len, (unsigned int)(sbufGetBufLength(buf)), (unsigned int)io->write_bufsize,
                  (unsigned int)WRITE_BUFSIZE_HIGH_WATER);
        }
    }

write_done:

    if (nwrite > 0) {
        if (nwrite == len) {
            bufferpoolResuesBuf(io->loop->bufpool, buf);
        }
        __write_cb(io);
    }
    return nwrite;
write_error:
disconnect:

    /* NOTE:
     * We usually free resources in wclose_cb,
     * if wio_close_sync, we have to be very careful to avoid using freed resources.
     * But if wioCloseAsync, we do not have to worry about this.
     */
    bufferpoolResuesBuf(io->loop->bufpool, buf);
    if (io->io_type & WIO_TYPE_SOCK_STREAM) {
        wioCloseAsync(io);
    }
    return nwrite < 0 ? nwrite : -1;
}

// This must only be called from the same thread that created the loop
int wioClose(wio_t* io) {
    if (io->closed) return 0;

    // if (io->destroy == 0 && getTID() != io->loop->tid) {
    //     return wioCloseAsync(io); /*  tid lost its meaning, its now ww tid */
    // }

    if (io->closed) {

        return 0;
    }
    if (!write_queue_empty(&io->write_queue) && io->error == 0 && io->close == 0 && io->destroy == 0) {
        io->close = 1;

        wlogd("write_queue not empty, close later.");
        int timeout_ms = io->close_timeout ? io->close_timeout : WIO_DEFAULT_CLOSE_TIMEOUT;
        io->close_timer = wtimerAdd(io->loop, __close_timeout_cb, timeout_ms, 1);
        io->close_timer->privdata = io;
        return 0;
    }
    io->closed = 1;

    wioDone(io);
    __close_cb(io);
    // SAFE_FREE(io->hostname);
    if (io->io_type & WIO_TYPE_SOCKET) {
        closesocket(io->fd);
    }
    return 0;
}
#endif
