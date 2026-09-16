#include "iowatcher.h"
#include "splice_buffer.h"
#include "wloop_internal.h"
#include "worker.h"
#ifndef EVENT_IOCP
#include "loggers/internal_logger.h"
#include "werr.h"
#include "wevent.h"
#include "wsocket.h"
#include "wthread.h"
#if WW_HAVE_SPLICE
#include <sys/ioctl.h>
#endif

enum
{
    kNioReadDropped = -2
};

static void __connect_timeout_cb(wtimer_t *timer)
{
    wio_t *io = (wio_t *) timer->privdata;
    if (io)
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};
        wlogw("connect timeout [%s] <=> [%s]",
              SOCKADDR_STR(io->localaddr, localaddrstr),
              SOCKADDR_STR(io->peeraddr, peeraddrstr));
        io->error = ETIMEDOUT;
        wioClose(io);
    }
}

static void __close_timeout_cb(wtimer_t *timer)
{
    wio_t *io = (wio_t *) timer->privdata;
    if (io)
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};
        wlogw("close timeout [%s] <=> [%s]",
              SOCKADDR_STR(io->localaddr, localaddrstr),
              SOCKADDR_STR(io->peeraddr, peeraddrstr));
        io->error = ETIMEDOUT;
        wioClose(io);
    }
}

static void __close_pending_cb(wevent_t *ev)
{
    int fd = (int) (uintptr_t) weventGetUserdata(ev);

    if (fd < (int) ev->loop->ios.maxsize)
    {

        if (ev->loop->ios.ptr[fd] && ev->loop->ios.ptr[fd]->pending)
        {
            LOGE("__close_pending_cb: pending io fd=%d !\n", fd);
            abortProgramNow(1);
        }
    }

    closesocket(fd);
}

static void __accept_cb(wio_t *io)
{
    wioAcceptCallBack(io);
}

static void __connect_cb(wio_t *io)
{
    wioDelConnectTimer(io);
    wioConnectCallBack(io);
}

static void __read_cb(wio_t *io, sbuf_t *buf)
{
    // printd("> %.*s\n", readbytes, buf);
    io->last_read_hrtime = io->loop->cur_hrtime;
    wioHandleRead(io, buf);
}

static void __write_cb(wio_t *io)
{
    // printd("< %.*s\n", writebytes, buf);
    io->last_write_hrtime = io->loop->cur_hrtime;
    discard wloopInvokeWriteCallback(io, io->write_cb);
}

static void __close_cb(wio_t *io)
{
    // printd("close fd=%d\n", wioGetFD(io));
    wioDelConnectTimer(io);
    wioDelCloseTimer(io);
    wioDelReadTimer(io);
    wioDelWriteTimer(io);
    wioDelKeepaliveTimer(io);
    wioDelHeartBeatTimer(io);
    wioCloseCallBack(io);
}

static void nio_accept(wio_t *io)
{
    // printd("nio_accept listenfd=%d\n", wioGetFD(io));
    int       connfd = 0, err = 0, accept_cnt = 0;
    socklen_t addrlen;
    wio_t    *connio = NULL;
    while (accept_cnt++ < 3)
    {
        if (UNLIKELY(! wloopNormalDispatchAllowed(io->loop)))
        {
            return;
        }
        addrlen = sizeof(sockaddr_u);
        connfd  = socketToFd(accept(wioGetFD(io), io->peeraddr, &addrlen));
        if (connfd < 0)
        {
            err = socketERRNO();
            if (err == EAGAIN || err == EINTR)
            {
                return;
            }
            else
            {
                LOGE("listenfd=%d accept error: %s:%d", wioGetFD(io), socketStrError(err), err);
                io->error = err;
                goto accept_error;
            }
        }
        addrlen = sizeof(sockaddr_u);
        getsockname(connfd, io->localaddr, &addrlen);
        connio = wioGet(io->loop, connfd);
        if (UNLIKELY(connio == NULL || wioIsClosed(connio)))
        {
            if (connio == NULL)
            {
                // No event io took ownership of the accepted socket.
                closesocket(connfd);
            }
            // A closed event io already released the socket.
            continue;
        }
        // NOTE: inherit from listenio
        connio->accept_cb = io->accept_cb;
        connio->userdata  = io->userdata;

        if (UNLIKELY(! wloopNormalDispatchAllowed(io->loop)))
        {
            wioClose(connio);
            return;
        }
        __accept_cb(connio);
    }
    return;

accept_error:
    wloge("listenfd=%d accept error: %s:%d", wioGetFD(io), socketStrError(io->error), io->error);
    // NOTE: Don't close listen fd automatically anyway.
    // wioClose(io);
}

static void nio_connect(wio_t *io)
{
    // printd("nio_connect connfd=%d\n", wioGetFD(io));
    socklen_t addrlen = sizeof(sockaddr_u);
    int       ret     = getpeername(wioGetFD(io), io->peeraddr, &addrlen);
    if (ret < 0)
    {
        io->error = socketERRNO();
        goto connect_error;
    }
    else
    {
        addrlen = sizeof(sockaddr_u);
        getsockname(wioGetFD(io), io->localaddr, &addrlen);

        if (LIKELY(wloopNormalDispatchAllowed(io->loop)))
        {
            __connect_cb(io);
        }

        return;
    }

connect_error:
    wlogw("connfd=%d connect error: %s:%d", wioGetFD(io), socketStrError(io->error), io->error);
    wioClose(io);
}

static void nio_connect_event_cb(wevent_t *ev)
{
    wio_t   *io = (wio_t *) ev->userdata;
    uint32_t id = (uint32_t) (uintptr_t) ev->privdata;
    if (io->id != id)
        return;
    nio_connect(io);
}

static int nio_connect_async(wio_t *io)
{
    wevent_t ev;
    memoryZero(&ev, sizeof(ev));
    ev.cb       = nio_connect_event_cb;
    ev.userdata = io;
    ev.privdata = (void *) (uintptr_t) io->id;
    return wloopPostEvent(io->loop, &ev) ? 0 : -1;
}

static int __nio_read_udp(wio_t *io, void *buf, unsigned int len)
{
#if defined(OS_LINUX) && defined(MSG_TRUNC)
    struct iovec  iov = {.iov_base = buf, .iov_len = (size_t) len};
    struct msghdr msg = {.msg_name = io->peeraddr, .msg_namelen = sizeof(sockaddr_u), .msg_iov = &iov, .msg_iovlen = 1};

    ssize_t nread = recvmsg(wioGetFD(io), &msg, MSG_TRUNC);
    if (nread < 0)
    {
        return -1;
    }

    if ((msg.msg_flags & MSG_TRUNC) != 0 || nread > (ssize_t) len)
    {
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN]  = {0};
        LOGW("UDP datagram too large for read buffer, dropped: packet_size=%lld buffer_size=%u [%s] <= [%s]",
             LLD(nread),
             len,
             SOCKADDR_STR(io->localaddr, localaddrstr),
             SOCKADDR_STR(io->peeraddr, peeraddrstr));
        return kNioReadDropped;
    }

    return (int) nread;
#else
    socklen_t addrlen = sizeof(sockaddr_u);
    return recvfrom(wioGetFD(io), buf, (size_t) len, 0, io->peeraddr, &addrlen);
#endif
}

static int __nio_read(wio_t *io, void *buf, unsigned int len)
{
    int nread = 0;
    switch (io->io_type)
    {

    case WIO_TYPE_TCP:

        nread = recv(wioGetFD(io), buf, (size_t) len, 0);
        break;
    case WIO_TYPE_UDP: // udp can also be more than 1472 bytes
        nread = __nio_read_udp(io, buf, len);
        break;
    case WIO_TYPE_IP: {
        socklen_t addrlen = sizeof(sockaddr_u);
        nread             = recvfrom(wioGetFD(io), buf, (size_t) len, 0, io->peeraddr, &addrlen);
    }
    break;
    default:
        nread = read(wioGetFD(io), buf, len);
        break;
    }
    // wlogd("read retval=%d", nread);
    return nread;
}

static int __nio_write(wio_t *io, const void *buf, int len)
{
    int nwrite = 0;
    switch (io->io_type)
    {
    case WIO_TYPE_TCP: {
        int flag = 0;
#ifdef MSG_NOSIGNAL
        flag |= MSG_NOSIGNAL;
#endif
        nwrite = send(wioGetFD(io), buf, (size_t) len, flag);
    }
    break;
    case WIO_TYPE_UDP:
    case WIO_TYPE_IP:
        nwrite = sendto(wioGetFD(io), buf, (size_t) len, 0, io->peeraddr, SOCKADDR_LEN(io->peeraddr));
        break;
    default:
        nwrite = write(wioGetFD(io), buf, (size_t) len);
        break;
    }
    // wlogd("write retval=%d", nwrite);
    return nwrite;
}

// Return actual progress even when the body write fails after sending a prefix.
static int nioWriteBuffer(wio_t *io, sbuf_t *buf, int *error)
{
    *error = 0;
#if WW_HAVE_SPLICE
    if (buf->flags & kSbufFlagSplice)
    {
        assert(sbufGetLifetime(buf) == NULL);
        assert(buf->curpos <= sbufGetLeftPadding(buf));
        const uint32_t prefix = (uint32_t) sbufGetLeftPadding(buf) - buf->curpos;
        assert(prefix <= sbufGetLength(buf));
        const uint32_t body    = sbufGetLength(buf) - prefix;
        int            written = 0;
        if (prefix != 0)
        {
            written = __nio_write(io, sbufGetRawPtr(buf), (int) prefix);
            if (written < 0)
            {
                *error = socketERRNO();
                return written;
            }
            if ((uint32_t) written < prefix)
            {
                return written;
            }
        }
        if (body != 0)
        {
            splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
            if (UNLIKELY(metadata.pipefd[0] < 0))
            {
                LOGF("nioWriteBuffer: splice descriptor pipe must already be initialized");
                abortProgramNow(1);
            }
            const ssize_t moved = splice(metadata.pipefd[0], NULL, wioGetFD(io), NULL, body, SPLICE_F_NONBLOCK);
            if (moved <= 0)
            {
                *error = moved < 0 ? errno : EPIPE;
                return written != 0 ? written : -1;
            }
            written += (int) moved;
        }
        return written;
    }
#endif
    const int written = __nio_write(io, sbufGetRawPtr(buf), (int) sbufGetLength(buf));
    if (written < 0)
    {
        *error = socketERRNO();
    }
    return written;
}

static void nioConsumeWrittenBuffer(sbuf_t *buf, uint32_t bytes)
{
    if (buf->flags & kSbufFlagSplice)
    {
        assert(buf->curpos <= sbufGetLeftPadding(buf));
        const uint32_t prefix = min(bytes, (uint32_t) sbufGetLeftPadding(buf) - buf->curpos);
        sbufShiftRight(buf, prefix);
        sbufConsume(buf, bytes - prefix);
        buf->capacity -= bytes - prefix;
    }
    else
    {
        sbufShiftRight(buf, bytes);
    }
}

static void nio_read(wio_t *io)
{
    // printd("nio_read fd=%d\n", wioGetFD(io));
    int nread = 0;
    int err   = 0;
    //  read:;

    sbuf_t *buf;

#if WW_HAVE_SPLICE
    if (io->io_type == WIO_TYPE_TCP && wioIsSpliceEnabled(io))
    {
        int queued_bytes = 0;
        if (UNLIKELY(ioctl(wioGetFD(io), FIONREAD, &queued_bytes) != 0))
        {
            err = socketERRNO();
            if (err == EAGAIN || err == EINTR)
            {
                return;
            }
            LOGE("read fd=%d FIONREAD error: %s:%d", wioGetFD(io), socketStrError(err), err);
            io->error = err;
            goto read_error;
        }
        if (queued_bytes > 0)
        {
            buffer_pool_t *pool       = io->loop->bufpool;
            const uint32_t read_limit = min(bufferpoolGetLargeBufferSize(pool), (uint32_t) LARGE_BUFFER_SIZE_RAM_HIGH);
            const uint32_t requested  = min((uint32_t) queued_bytes, read_limit);
            assert(requested > 0);
            buf = bufferpoolGetSpliceBuffer(pool);
            assert(sbufGetLifetime(buf) == NULL);
            if (UNLIKELY(! wloopNormalDispatchAllowed(io->loop)))
            {
                bufferpoolReuseBuffer(pool, buf);
                return;
            }
            if (UNLIKELY(sbufSpliceInitPipe(buf, read_limit) != 0))
            {
                // No socket bytes were consumed; use ordinary storage for this delivery.
                bufferpoolReuseBuffer(pool, buf);
                goto read_ordinary;
            }
            const splice_buffer_metadata_t metadata = sbufSpliceMetadata(buf);
            ssize_t                        moved;
            do
            {
                moved = splice(wioGetFD(io), NULL, metadata.pipefd[1], NULL, requested, SPLICE_F_NONBLOCK);
            } while (moved < 0 && errno == EINTR);
            if (moved <= 0)
            {
                err = moved < 0 ? socketERRNO() : 0;
                bufferpoolReuseBuffer(pool, buf);
                if (moved == 0)
                    goto disconnect;
                if (err == EAGAIN)
                    return;
                LOGE("read fd=%d splice error: %s:%d", wioGetFD(io), socketStrError(err), err);
                io->error = err;
                goto read_error;
            }

            // Only bytes already held in this private pipe become visible to the callback.
            buf->capacity = (uint32_t) sbufGetLeftPadding(buf) + (uint32_t) moved;
            sbufSetLength(buf, (uint32_t) moved);
            if (UNLIKELY(! wloopNormalDispatchAllowed(io->loop)))
            {
                bufferpoolReuseBuffer(pool, buf);
                return;
            }
            __read_cb(io, buf);
            // Ownership transferred; the callback may free both buf and io.
            return;
        }
        // FIONREAD == 0 is not EOF proof. The ordinary nonblocking read handles EOF and transient readiness.
    }
read_ordinary:
#endif

    switch (io->io_type)
    {
    default:
    case WIO_TYPE_TCP:
    case WIO_TYPE_UDP:
        buf = bufferpoolGetLargeBuffer(io->loop->bufpool);
        break;
    case WIO_TYPE_IP:
        buf = bufferpoolGetSmallBuffer(io->loop->bufpool);
        break;
    }

    unsigned int available = sbufGetMaximumWriteableSize(buf);
    assert(available >= 1024);

    nread = __nio_read(io, sbufGetMutablePtr(buf), available);

    if (nread == kNioReadDropped)
    {
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return;
    }

    // printd("read retval=%d\n", nread);
    if (nread < 0)
    {
        err = socketERRNO();
        if (err == EAGAIN || err == EINTR)
        {
            // goto read_done;
            bufferpoolReuseBuffer(io->loop->bufpool, buf);
            return;
        }
        else if (err == EMSGSIZE)
        {
            // ignore
            bufferpoolReuseBuffer(io->loop->bufpool, buf);
            return;
        }
        else
        {
            // printError("read");
            LOGE("read fd=%d error: %s:%d", wioGetFD(io), socketStrError(err), err);
            bufferpoolReuseBuffer(io->loop->bufpool, buf);
            io->error = err;
            goto read_error;
        }
    }
    if (UNLIKELY(nread == 0 && (io->io_type & WIO_TYPE_SOCK_DGRAM) == 0))
    {
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        goto disconnect;
    }
    // printf("%d \n",nread);

    sbufSetLength(buf, min(available, (uint32_t) nread));
    if (UNLIKELY(! wloopNormalDispatchAllowed(io->loop)))
    {
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return;
    }
    __read_cb(io, buf);
    // user consumed buffer
    return;
read_error:
disconnect:
    if (io->io_type & WIO_TYPE_SOCK_STREAM)
    {
        wioClose(io);
    }
}

static void nio_write(wio_t *io)
{
    // printd("nio_write fd=%d\n", wioGetFD(io));
    int nwrite = 0, err = 0;
    //
write:
    if (write_queue_empty(&io->write_queue))
    {

        if (io->close)
        {
            io->close = 0;
            wioClose(io);
        }
        return;
    }
    sbuf_t *buf = *write_queue_front(&io->write_queue);
    int     len = (int) sbufGetLength(buf);
    // char* base = pbuf->base;
    nwrite = nioWriteBuffer(io, buf, &err);
    if (nwrite > 0)
    {
        nioConsumeWrittenBuffer(buf, (uint32_t) nwrite);
        io->write_bufsize -= (uint32_t) nwrite;
    }
    // printd("write retval=%d\n", nwrite);
    if (err != 0)
    {
        if (err == EAGAIN || err == EINTR)
        {
            if (nwrite <= 0)
            {
                return;
            }
        }
        else
        {
            // printError("write");
            io->error = err;
            goto write_error;
        }
    }
    if (nwrite == 0)
    {
        goto disconnect;
    }
    if (nwrite == len)
    {
        // NOTE: after write_cb, pbuf maybe invalid.
        // EVENTLOOP_FREE(pbuf->base);
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        write_queue_pop_front(&io->write_queue);
        if (UNLIKELY(! wloopNormalDispatchAllowed(io->loop)))
        {
            return;
        }
        __write_cb(io);

        if (! io->closed && LIKELY(wloopNormalDispatchAllowed(io->loop)))
        {
            // write continue
            goto write;
        }
    }
    else
    {
        if (LIKELY(wloopNormalDispatchAllowed(io->loop)))
        {
            __write_cb(io);
        }
    }

    return;
write_error:
disconnect:

    if (io->io_type & WIO_TYPE_SOCK_STREAM)
    {
        wioClose(io);
    }
}

static void wio_handle_events(wio_t *io)
{
    if (UNLIKELY(! wloopNormalDispatchAllowed(io->loop)))
    {
        io->revents = 0;
        return;
    }
    if ((io->events & WW_READ) && (io->revents & WW_READ))
    {
        if (io->accept)
        {
            nio_accept(io);
        }
        else
        {
            nio_read(io);
        }
    }

    if (UNLIKELY(! wloopNormalDispatchAllowed(io->loop)))
    {
        io->revents = 0;
        return;
    }
    if ((io->events & WW_WRITE) && (io->revents & WW_WRITE))
    {
        // NOTE: del WW_WRITE, if write_queue empty
        //
        if (write_queue_empty(&io->write_queue))
        {
            wioDel(io, WW_WRITE);
        }

        if (io->connect)
        {
            // NOTE: connect just do once
            // ONESHOT
            io->connect = 0;

            nio_connect(io);
        }
        else
        {
            nio_write(io);
        }
    }

    io->revents = 0;
}

int wioAccept(wio_t *io)
{
    io->accept    = 1;
    int add_error = wioAdd(io, wio_handle_events, WW_READ);
    if (UNLIKELY(add_error != 0))
    {
        io->accept = 0;
        wioClose(io);
    }
    return add_error;
}

int wioConnect(wio_t *io)
{
    if (! wloopNormalAdmissionBegin(io->loop))
    {
        return -1;
    }
    int ret = connect(wioGetFD(io), io->peeraddr, SOCKADDR_LEN(io->peeraddr));
    wloopNormalAdmissionEnd(io->loop);
#ifdef OS_WIN
    if (ret < 0 && socketERRNO() != WSAEWOULDBLOCK)
    {
#else
    if (ret < 0 && socketERRNO() != EINPROGRESS)
    {
#endif
        // printError("connect");
        io->error = socketERRNO();
        return wioCloseAsync(io) == 0 ? ret : -1;
    }
    if (ret == 0)
    {
        // connect ok
        if (UNLIKELY(nio_connect_async(io) != 0))
        {
            wioClose(io);
            return -1;
        }
        return 0;
    }
    int timeout       = io->connect_timeout ? io->connect_timeout : WIO_DEFAULT_CONNECT_TIMEOUT;
    io->connect_timer = wtimerAdd(io->loop, __connect_timeout_cb, (uint32_t) timeout, 1);
    if (UNLIKELY(io->connect_timer == NULL))
    {
        io->error = ECANCELED;
        wioClose(io);
        return -1;
    }
    io->connect_timer->privdata = io;
    io->connect                 = 1;
    int add_error               = wioAdd(io, wio_handle_events, WW_WRITE);
    if (UNLIKELY(add_error != 0))
    {
        io->connect = 0;
        wioDelConnectTimer(io);
        wioClose(io);
    }
    return add_error;
}

int wioRead(wio_t *io)
{
    if (io->closed)
    {
        wloge("wioRead called but fd[%d] already closed!", wioGetFD(io));
        return -1;
    }
    int add_error = wioAdd(io, wio_handle_events, WW_READ);
    if (UNLIKELY(add_error != 0))
    {
        wioClose(io);
    }
    return add_error;
}

// A transient sendto failure means the datagram is dropped, not retried.
static bool nio_sendto_error_is_transient(int err)
{
    if (err == EAGAIN || err == EINTR)
    {
        return true;
    }
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
    if (err == EWOULDBLOCK)
    {
        return true;
    }
#endif
#ifdef ENOBUFS
    if (err == ENOBUFS)
    {
        return true;
    }
#endif
#ifdef WSAENOBUFS
    if (err == WSAENOBUFS)
    {
        return true;
    }
#endif
    return false;
}

int wioWriteDatagram(wio_t *io, sbuf_t *buf, const sockaddr_u *peer_addr)
{
    if (io->closed)
    {
        wloge("wioWriteDatagram called but fd[%d] already closed!", wioGetFD(io));
        io->error = EBADF;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }
    if (((io->io_type & WIO_TYPE_SOCK_DGRAM) | (io->io_type & WIO_TYPE_SOCK_RAW)) == 0)
    {
        wloge("wioWriteDatagram called on non-datagram fd[%d]!", wioGetFD(io));
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        io->error = EINVAL;
        return -1;
    }
    // Datagram writes never enter the stream write_queue.
    assert(write_queue_empty(&io->write_queue));

    const bool nested_callback = wloopCurrentThreadInNormalCallback(io->loop);
    if (! nested_callback && ! wloopNormalAdmissionBegin(io->loop))
    {
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }

    int len = (int) sbufGetLength(buf);
    int nwrite = sendto(
        wioGetFD(io), (const char *) sbufGetRawPtr(buf), (size_t) len, 0, &peer_addr->sa, SOCKADDR_LEN(peer_addr));
    if (nwrite < 0)
    {
        int err = socketERRNO();
        if (nio_sendto_error_is_transient(err))
        {
            // Drop-on-pressure policy: no logging here, the pressure path must
            // not amplify overload.
            bufferpoolReuseBuffer(io->loop->bufpool, buf);
            if (! nested_callback)
            {
                wloopNormalAdmissionEnd(io->loop);
            }
            return 0;
        }
        io->error = err;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        if (! nested_callback)
        {
            wloopNormalAdmissionEnd(io->loop);
        }
        return -1;
    }
    // Datagram sends are atomic: the kernel accepts the whole payload or fails.
    assert(nwrite == len);
    bufferpoolReuseBuffer(io->loop->bufpool, buf);
    if (! nested_callback)
    {
        wloopNormalAdmissionEnd(io->loop);
    }
    if (nested_callback || LIKELY(wloopNormalDispatchAllowed(io->loop)))
    {
        __write_cb(io);
    }
    return nwrite;
}

int wioWrite(wio_t *io, sbuf_t *buf)
{
    const bool splice_buffer = (buf->flags & kSbufFlagSplice) != 0;
    if (splice_buffer)
    {
#if WW_HAVE_SPLICE
        if (UNLIKELY(io->io_type != WIO_TYPE_TCP))
        {
            LOGF("wioWrite: splice buffers require a TCP destination");
            abortProgramNow(1);
        }
        assert(sbufGetLifetime(buf) == NULL && "Splice buffers must not carry lifetime metadata");
#else
        LOGF("wioWrite: splice is unsupported on this build");
        abortProgramNow(1);
#endif
    }
    if (io->closed)
    {
        wloge("wioWrite called but fd[%d] already closed!", wioGetFD(io));
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }
    if ((io->io_type & WIO_TYPE_SOCK_DGRAM) || (io->io_type & WIO_TYPE_SOCK_RAW))
    {
        // Snapshot the default peer so a read arriving between this call and the
        // send cannot redirect the datagram; datagrams never use write_queue.
        sockaddr_u peer_addr = *io->peeraddr_u;
        return wioWriteDatagram(io, buf, &peer_addr);
    }
    int        nwrite = 0, err = 0, add_error = 0;
    int        len             = (int) sbufGetLength(buf);
    const bool nested_callback = wloopCurrentThreadInNormalCallback(io->loop);
    if (! nested_callback && ! wloopNormalAdmissionBegin(io->loop))
    {
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }

    if (splice_buffer && len == 0)
    {
        goto write_done;
    }
    if (write_queue_empty(&io->write_queue))
    {
        //    try_write:
        nwrite = nioWriteBuffer(io, buf, &err);
        if (nwrite > 0)
        {
            nioConsumeWrittenBuffer(buf, (uint32_t) nwrite);
        }
        // printd("write retval=%d\n", nwrite);
        if (err != 0)
        {
            if (err == EAGAIN || err == EINTR)
            {
                nwrite = max(nwrite, 0);
                wlogd("try_write failed, enqueue!");
                goto enqueue;
            }
            else
            {
                // printError("write");
                io->error = err;
                goto write_error;
            }
        }
        if (nwrite == 0)
        {
            goto disconnect;
        }
        if (nwrite == len)
        {
            goto write_done;
        }
    enqueue:
        add_error = wioAddAlreadyAdmitted(io, wio_handle_events, WW_WRITE);
        if (UNLIKELY(add_error != 0))
        {
            io->error = add_error < 0 ? -add_error : add_error;
            nwrite    = add_error;
            goto write_error;
        }
    }

    if (nwrite < len)
    {
        if (io->write_bufsize + (uint32_t) len - (uint32_t) nwrite > io->max_write_bufsize)
        {
            wloge("write bufsize > %u, close it!", io->max_write_bufsize);
            io->error = WERR_OVER_LIMIT;
            goto write_error;
        }
        if (io->write_queue.maxsize == 0)
        {
            write_queue_init(&io->write_queue, 4);
        }
        write_queue_push_back(&io->write_queue, &buf);
        io->write_bufsize += sbufGetLength(buf);
        if (io->write_bufsize > WRITE_BUFSIZE_HIGH_WATER)
        {
            wlogw("write len=%u enqueue %u, bufsize=%u over high water %u",
                  (unsigned int) len,
                  (unsigned int) (sbufGetLength(buf)),
                  (unsigned int) io->write_bufsize,
                  (unsigned int) WRITE_BUFSIZE_HIGH_WATER);
        }
    }

write_done:

    if (nwrite > 0 || (splice_buffer && len == 0))
    {
        if (nwrite == len)
        {
            bufferpoolReuseBuffer(io->loop->bufpool, buf);
        }
        if (! nested_callback)
        {
            wloopNormalAdmissionEnd(io->loop);
        }
        if (nested_callback || LIKELY(wloopNormalDispatchAllowed(io->loop)))
        {
            __write_cb(io);
        }
        return nwrite;
    }
    if (! nested_callback)
    {
        wloopNormalAdmissionEnd(io->loop);
    }
    return nwrite;
write_error:
disconnect:

    /* NOTE:
     * We usually free resources in wclose_cb,
     * if wio_close_sync, we have to be very careful to avoid using freed resources.
     * But if wioCloseAsync, we do not have to worry about this.
     */
    bufferpoolReuseBuffer(io->loop->bufpool, buf);
    if (! nested_callback)
    {
        wloopNormalAdmissionEnd(io->loop);
    }
    if (io->io_type & WIO_TYPE_SOCK_STREAM)
    {
        wioCloseAsync(io);
    }
    return nwrite < 0 ? nwrite : -1;
}

// This must only be called from the same thread that created the loop
int wioClose(wio_t *io)
{
    // if (io->destroy == 0 && getTID() != io->loop->tid) {
    //     return wioCloseAsync(io); /*  tid lost its meaning, its now ww tid */
    // }

    if (io->closed)
    {

        return 0;
    }
    if (! write_queue_empty(&io->write_queue) && io->error == 0 && io->close == 0 && io->destroy == 0)
    {
        io->close = 1;

        wlogd("write_queue not empty, close later.");
        int timeout_ms  = io->close_timeout ? io->close_timeout : WIO_DEFAULT_CLOSE_TIMEOUT;
        io->close_timer = wtimerAdd(io->loop, __close_timeout_cb, (uint32_t) timeout_ms, 1);
        if (UNLIKELY(io->close_timer == NULL))
        {
            io->close = 0;
            io->error = ECANCELED;
        }
        else
        {
            io->close_timer->privdata = io;
            return 0;
        }
    }
    // bool has_pending = io->pending;

    const bool freeing    = io->destroy;
    io->close_in_progress = 1;
    io->closed = 1;
    // wloop_t *loop = io->loop;

    wioDone(io);
    __close_cb(io);
    wioReleaseFD(io, false);
    io->close_in_progress = 0;
    if (io->destroy && ! freeing)
    {
        wioFinalizeNow(io);
    }

    return 0;
}
#endif
