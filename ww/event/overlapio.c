// WARN: overlapio maybe need MemoryPool to avoid alloc/free
#include "iowatcher.h"

#ifdef EVENT_IOCP
#include "overlapio.h"
#include "wevent.h"

#define ACCEPTEX_NUM    10

static void free_buffered_overlapped(wio_t *io, woverlapped_t *hovlp)
{
    if (hovlp == NULL)
    {
        return;
    }
    if (io != NULL && io->hovlp == hovlp)
    {
        io->hovlp = NULL;
    }
    EVENTLOOP_FREE(hovlp->addr);
    EVENTLOOP_FREE(hovlp->buf.buf);
    EVENTLOOP_FREE(hovlp);
}

int post_acceptex(wio_t *listenio, woverlapped_t *hovlp)
{
    LPFN_ACCEPTEX AcceptEx     = NULL;
    GUID          guidAcceptEx = WSAID_ACCEPTEX;
    DWORD         dwbytes      = 0;
    int           accept_error;
    int           connfd = -1;
    if (WSAIoctl(listenio->fd,
                 SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guidAcceptEx,
                 sizeof(guidAcceptEx),
                 &AcceptEx,
                 sizeof(AcceptEx),
                 &dwbytes,
                 NULL,
                 NULL) != 0)
    {
        accept_error = WSAGetLastError();
        goto error;
    }
    connfd = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (connfd < 0)
    {
        accept_error = WSAGetLastError();
        goto error;
    }
    if (hovlp == NULL)
    {
        EVENTLOOP_ALLOC_SIZEOF(hovlp);
        hovlp->buf.len = 20 + sizeof(struct sockaddr_in6) * 2;
        EVENTLOOP_ALLOC(hovlp->buf.buf, hovlp->buf.len);
    }
    memoryZero(&hovlp->ovlp, sizeof(hovlp->ovlp));
    hovlp->fd    = connfd;
    hovlp->event = WW_READ;
    hovlp->io    = listenio;
    if (AcceptEx(listenio->fd,
                 connfd,
                 hovlp->buf.buf,
                 0,
                 sizeof(struct sockaddr_in6),
                 sizeof(struct sockaddr_in6),
                 &dwbytes,
                 &hovlp->ovlp) != TRUE)
    {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING)
        {
            printError("AcceptEx error: %d\n", err);
            accept_error = err;
            goto error;
        }
    }
    return 0;
error:
    SAFE_CLOSESOCKET(connfd);
    free_buffered_overlapped(listenio, hovlp);
    return accept_error;
}

int post_recv(wio_t* io, woverlapped_t* hovlp) {
    const bool allocated_hovlp = hovlp == NULL;
    if (hovlp == NULL) {
        EVENTLOOP_ALLOC_SIZEOF(hovlp);
    }
    memoryZero(&hovlp->ovlp, sizeof(hovlp->ovlp));
    hovlp->fd = io->fd;
    hovlp->event = WW_READ;
    hovlp->io = io;
    if (hovlp->sbuf != NULL) {
        bufferpoolReuseBuffer(io->loop->bufpool, hovlp->sbuf);
        hovlp->sbuf = NULL;
    }
    if (io->io_type == WIO_TYPE_UDP) {
        hovlp->sbuf = bufferpoolGetLargeBuffer(io->loop->bufpool);
    } else if (io->io_type == WIO_TYPE_IP) {
        hovlp->sbuf = bufferpoolGetSmallBuffer(io->loop->bufpool);
    } else {
        hovlp->sbuf = bufferpoolGetLargeBuffer(io->loop->bufpool);
    }
    hovlp->buf.len = sbufGetMaximumWriteableSize(hovlp->sbuf);
    hovlp->buf.buf = (CHAR*)sbufGetMutablePtr(hovlp->sbuf);
    //memorySet(hovlp->buf.buf, 0, hovlp->buf.len);
    DWORD dwbytes = 0;
    DWORD flags = 0;
    int ret = 0;
    if (io->io_type == WIO_TYPE_TCP) {
        ret = WSARecv(io->fd, &hovlp->buf, 1, &dwbytes, &flags, &hovlp->ovlp, NULL);
    }
    else if (io->io_type == WIO_TYPE_UDP ||
            io->io_type == WIO_TYPE_IP) {
        if (hovlp->addr == NULL) {
            EVENTLOOP_ALLOC(hovlp->addr, sizeof(struct sockaddr_in6));
        }
        // WSARecvFrom updates addrlen with the completed peer address length.
        // Restore the full buffer capacity before every receive, especially when
        // a dual-stack socket receives IPv4 followed by IPv6.
        hovlp->addrlen = sizeof(struct sockaddr_in6);
        ret = WSARecvFrom(io->fd, &hovlp->buf, 1, &dwbytes, &flags, hovlp->addr, &hovlp->addrlen, &hovlp->ovlp, NULL);
    }
    else {
        ret = -1;
    }
    //printd("WSARecv ret=%d bytes=%u\n", ret, dwbytes);
    if (ret != 0) {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING) {
            printError("WSARecv error: %d\n", err);
            if (hovlp->sbuf) {
                bufferpoolReuseBuffer(io->loop->bufpool, hovlp->sbuf);
                hovlp->sbuf = NULL;
            }
            if (allocated_hovlp)
            {
                EVENTLOOP_FREE(hovlp->addr);
                EVENTLOOP_FREE(hovlp);
            }
            return err;
        }
    }
    return 0;
}

static void on_acceptex_complete(wio_t* io) {
    printd("on_acceptex_complete------\n");
    woverlapped_t* hovlp = (woverlapped_t*)io->hovlp;
    int listenfd = io->fd;
    int connfd = hovlp->fd;
    LPFN_GETACCEPTEXSOCKADDRS GetAcceptExSockaddrs = NULL;
    GUID guidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
    DWORD dwbytes = 0;
    if (WSAIoctl(connfd, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guidGetAcceptExSockaddrs, sizeof(guidGetAcceptExSockaddrs),
        &GetAcceptExSockaddrs, sizeof(GetAcceptExSockaddrs),
        &dwbytes, NULL, NULL) != 0) {
        return;
    }
    struct sockaddr* plocaladdr = NULL;
    struct sockaddr* ppeeraddr = NULL;
    socklen_t localaddrlen;
    socklen_t peeraddrlen;
    GetAcceptExSockaddrs(hovlp->buf.buf, 0, sizeof(struct sockaddr_in6), sizeof(struct sockaddr_in6),
        &plocaladdr, &localaddrlen, &ppeeraddr, &peeraddrlen);
    memoryCopy(io->localaddr, plocaladdr, localaddrlen);
    memoryCopy(io->peeraddr, ppeeraddr, peeraddrlen);
    if (io->accept_cb) {
        setsockopt(connfd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char*)&listenfd, sizeof(int));
        wio_t* connio = wioGet(io->loop, connfd);
        if (wioIsClosed(connio)) {
            // socket init rejected the accepted fd and already closed it
            post_acceptex(io, hovlp);
            return;
        }
        connio->userdata = io->userdata;
        memoryCopy(connio->localaddr, io->localaddr, localaddrlen);
        memoryCopy(connio->peeraddr, io->peeraddr, peeraddrlen);
        /*
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        printd("accept listenfd=%d connfd=%d [%s] <= [%s]\n", listenfd, connfd,
                SOCKADDR_STR(connio->localaddr, localaddrstr),
                SOCKADDR_STR(connio->peeraddr, peeraddrstr));
        */
        //printd("accept_cb------\n");
        io->accept_cb(connio);
        //printd("accept_cb======\n");
    }
    post_acceptex(io, hovlp);
}

static void on_connectex_complete(wio_t* io) {
    printd("on_connectex_complete------\n");
    woverlapped_t* hovlp = (woverlapped_t*)io->hovlp;
    io->error = hovlp->error;
    EVENTLOOP_FREE(io->hovlp);
    if (io->error != 0) {
        wioClose(io);
        return;
    }
    if (io->connect_cb) {
        setsockopt(io->fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
        socklen_t addrlen = sizeof(struct sockaddr_in6);
        getsockname(io->fd, io->localaddr, &addrlen);
        addrlen = sizeof(struct sockaddr_in6);
        getpeername(io->fd, io->peeraddr, &addrlen);
        /*
        char localaddrstr[SOCKADDR_STRLEN] = {0};
        char peeraddrstr[SOCKADDR_STRLEN] = {0};
        printd("connect connfd=%d [%s] => [%s]\n", io->fd,
                SOCKADDR_STR(io->localaddr, localaddrstr),
                SOCKADDR_STR(io->peeraddr, peeraddrstr));
        */
        //printd("connect_cb------\n");
        io->connect_cb(io);
        //printd("connect_cb======\n");
    }
}

static void on_wsarecv_complete(wio_t* io) {
    printd("on_recv_complete------\n");
    woverlapped_t* hovlp = (woverlapped_t*)io->hovlp;
    int recv_error;
    if (hovlp == NULL) {
        return;
    }
    if (hovlp->error != 0 ||
        (hovlp->bytes == 0 && (io->io_type & WIO_TYPE_SOCK_DGRAM) == 0)) {
        if (hovlp->sbuf) {
            bufferpoolReuseBuffer(io->loop->bufpool, hovlp->sbuf);
            hovlp->sbuf = NULL;
        }
        io->error = hovlp->error;
        wioClose(io);
        return;
    }

    if (io->read_cb) {
        if (io->io_type == WIO_TYPE_UDP || io->io_type == WIO_TYPE_IP) {
            if (hovlp->addr && hovlp->addrlen) {
                wioSetPeerAddr(io, hovlp->addr, hovlp->addrlen);
            }
        }
        sbufSetLength(hovlp->sbuf, (uint32_t)hovlp->bytes);
        //printd("read_cb------\n");
        io->read_cb(io, hovlp->sbuf);
        //printd("read_cb======\n");
    } else if (hovlp->sbuf) {
        bufferpoolReuseBuffer(io->loop->bufpool, hovlp->sbuf);
    }
    hovlp->sbuf = NULL;

    if (io->closed || io->hovlp == NULL) {
        return;
    }

    // Keep one receive pending for every socket type. UDP and raw-IP receives
    // complete one datagram at a time, so freeing hovlp here would permanently
    // stop delivery after the first packet.
    recv_error = post_recv(io, hovlp);
    if (UNLIKELY(recv_error != 0)) {
        io->error = recv_error;
        wioClose(io);
    }
}

static void on_wsasend_complete(wio_t* io) {
    printd("on_send_complete------\n");
    woverlapped_t* hovlp = (woverlapped_t*)io->hovlp;
    if (hovlp->bytes == 0) {
        io->error = WSAGetLastError();
        wioClose(io);
        goto end;
    }
    if (io->write_cb) {
        if (io->io_type == WIO_TYPE_UDP || io->io_type == WIO_TYPE_IP) {
            if (hovlp->addr) {
                wioSetPeerAddr(io, hovlp->addr, hovlp->addrlen);
            }
        }
        //printd("write_cb------\n");
        io->write_cb(io);
        //printd("write_cb======\n");
    }
end:
    if (io->hovlp) {
        EVENTLOOP_FREE(hovlp->addr);
        EVENTLOOP_FREE(hovlp->buf.buf);
        EVENTLOOP_FREE(io->hovlp);
    }
}

static void wio_handle_events(wio_t* io) {
    if ((io->events & WW_READ) && (io->revents & WW_READ)) {
        if (io->accept) {
            on_acceptex_complete(io);
        }
        else {
            on_wsarecv_complete(io);
        }
    }

    if ((io->events & WW_WRITE) && (io->revents & WW_WRITE)) {
        // NOTE: WW_WRITE just do once
        // ONESHOT
        iowatcherDelEvent(io->loop, io->fd, WW_WRITE);
        io->events &= ~WW_WRITE;
        if (io->connect) {
            io->connect = 0;

            on_connectex_complete(io);
        }
        else {
            on_wsasend_complete(io);
        }
    }

    io->revents = 0;
}

int wioAccept(wio_t *io)
{
    int add_error;
    int posted_count = 0;
    int accept_error = 0;

    io->accept = 1;
    add_error  = wioAdd(io, wio_handle_events, WW_READ);
    if (UNLIKELY(add_error != 0))
    {
        io->accept = 0;
        wioClose(io);
        return add_error;
    }

    for (int i = 0; i < ACCEPTEX_NUM; ++i)
    {
        int post_error = post_acceptex(io, NULL);
        if (post_error == 0)
        {
            posted_count++;
        }
        else
        {
            accept_error = post_error;
        }
    }
    // A partially populated accept queue is usable. Fail startup only when no
    // AcceptEx request could be posted.
    if (UNLIKELY(posted_count == 0))
    {
        io->accept = 0;
        io->error  = accept_error;
        wioClose(io);
        return accept_error;
    }
    return 0;
}

int wioConnect(wio_t *io)
{
    int connect_error;
    int add_error;
    // NOTE: ConnectEx must call bind
    struct sockaddr_in localaddr;
    socklen_t          addrlen       = sizeof(localaddr);
    LPFN_CONNECTEX     ConnectEx     = NULL;
    GUID               guidConnectEx = WSAID_CONNECTEX;
    DWORD              dwbytes;
    woverlapped_t     *hovlp = NULL;

    memoryZero(&localaddr, addrlen);
    localaddr.sin_family      = AF_INET;
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localaddr.sin_port        = htons(0);
    if (bind(io->fd, (struct sockaddr *) &localaddr, addrlen) < 0)
    {
        connect_error = socketERRNO();
        printError("syscall return error , call: bind , value: %d\n", connect_error);
        goto error;
    }
    // ConnectEx
    if (WSAIoctl(io->fd,
                 SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guidConnectEx,
                 sizeof(guidConnectEx),
                 &ConnectEx,
                 sizeof(ConnectEx),
                 &dwbytes,
                 NULL,
                 NULL) != 0)
    {
        connect_error = WSAGetLastError();
        goto error;
    }
    add_error = wioAdd(io, wio_handle_events, WW_WRITE);
    if (UNLIKELY(add_error != 0))
    {
        connect_error = add_error < 0 ? -add_error : add_error;
        goto error;
    }
    // NOTE: free on_connectex_complete
    EVENTLOOP_ALLOC_SIZEOF(hovlp);
    hovlp->fd    = io->fd;
    hovlp->event = WW_WRITE;
    hovlp->io    = io;
    if (ConnectEx(io->fd, io->peeraddr, sizeof(struct sockaddr_in6), NULL, 0, &dwbytes, &hovlp->ovlp) != TRUE)
    {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING)
        {
            printError("ConnectEx error: %d\n", err);
            connect_error = err;
            goto error;
        }
    }
    io->connectex = 1;
    io->connect   = 1;
    return 0;
error:
    free_buffered_overlapped(io, hovlp);
    io->error = connect_error;
    wioClose(io);
    return connect_error;
}

int wioRead (wio_t* io) {
    int add_error = wioAdd(io, wio_handle_events, WW_READ);
    if (UNLIKELY(add_error != 0))
    {
        return add_error;
    }

    int recv_error = post_recv(io, NULL);
    if (UNLIKELY(recv_error != 0))
    {
        io->error = recv_error;
        wioClose(io);
        return recv_error;
    }
    return 0;
}

int wioWriteDatagram(wio_t* io, sbuf_t* buf, const sockaddr_u* peer_addr) {
    if (io->closed) {
        io->error = EBADF;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }
    if ((io->io_type & WIO_TYPE_SOCK_DGRAM) == 0 && (io->io_type & WIO_TYPE_SOCK_RAW) == 0) {
        io->error = EINVAL;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }
    // One-shot nonblocking send with the explicit destination. A datagram that
    // cannot be sent immediately is dropped and recycled; no overlapped retry
    // is created and io->peeraddr is not read or written.
    int len = (int)sbufGetLength(buf);
    int nwrite = sendto(io->fd, (const char*)sbufGetRawPtr(buf), len, 0, &peer_addr->sa, SOCKADDR_LEN(peer_addr));
    if (nwrite < 0) {
        int err = socketERRNO();
        if (err == EAGAIN || err == EINTR || err == WSAENOBUFS) {
            // Transient pressure: drop without logging, the pressure path must
            // not amplify overload.
            bufferpoolReuseBuffer(io->loop->bufpool, buf);
            return 0;
        }
        io->error = err;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }
    bufferpoolReuseBuffer(io->loop->bufpool, buf);
    if (io->write_cb) {
        io->write_cb(io);
    }
    return nwrite;
}

int wioWrite(wio_t* io, sbuf_t* buf) {
    int nwrite = 0;
    if ((io->io_type & WIO_TYPE_SOCK_DGRAM) || (io->io_type & WIO_TYPE_SOCK_RAW)) {
        // Datagrams never enter the overlapped retry path; snapshot the default
        // peer so a later read cannot redirect this datagram.
        sockaddr_u peer_addr = *io->peeraddr_u;
        return wioWriteDatagram(io, buf, &peer_addr);
    }
try_send:
    if (io->io_type == WIO_TYPE_TCP) {
        nwrite = send(io->fd, sbufGetRawPtr(buf), sbufGetLength(buf), 0);
    }
    else if (io->io_type == WIO_TYPE_UDP) {
        nwrite = sendto(io->fd, sbufGetRawPtr(buf), sbufGetLength(buf), 0, io->peeraddr, sizeof(struct sockaddr_in6));
    }
    else if (io->io_type == WIO_TYPE_IP) {
        goto WSASend;
    }
    else {
        nwrite = -1;
    }
    //printd("write retval=%d\n", nwrite);
    if (nwrite < 0) {
        if (socketERRNO() == EAGAIN) {
            nwrite = 0;
            goto WSASend;
        }
        else {
            printError("write");
            io->error = socketERRNO();
            goto write_error;
        }
    }
    if (nwrite == 0) {
        goto disconnect;
    }
    if (io->write_cb) {
        //printd("try_write_cb------\n");
        io->write_cb(io);
        //printd("try_write_cb======\n");
    }
    if (nwrite == sbufGetLength(buf)) {
        //goto write_done;
        bufferpoolReuseBuffer(io->loop->bufpool,buf);
        return nwrite;
    }
WSASend: {
    int add_error = wioAdd(io, wio_handle_events, WW_WRITE);
    if (UNLIKELY(add_error != 0))
    {
        io->error = add_error < 0 ? -add_error : add_error;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        wioClose(io);
        return add_error;
    }

    woverlapped_t *hovlp;
    EVENTLOOP_ALLOC_SIZEOF(hovlp);
    hovlp->fd    = io->fd;
    hovlp->event = WW_WRITE;
    sbufShiftRight(buf, nwrite);
    hovlp->buf.len = sbufGetLength(buf);
    // NOTE: free on_send_complete
    EVENTLOOP_ALLOC(hovlp->buf.buf, hovlp->buf.len);
    memoryCopy(hovlp->buf.buf, sbufGetRawPtr(buf), hovlp->buf.len);
    bufferpoolReuseBuffer(io->loop->bufpool, buf);
    hovlp->io     = io;
    DWORD dwbytes = 0;
    DWORD flags   = 0;
    int   ret     = 0;
    if (io->io_type == WIO_TYPE_TCP)
    {
        ret = WSASend(io->fd, &hovlp->buf, 1, &dwbytes, flags, &hovlp->ovlp, NULL);
    }
    else if (io->io_type == WIO_TYPE_UDP || io->io_type == WIO_TYPE_IP)
    {
        ret = WSASendTo(
            io->fd, &hovlp->buf, 1, &dwbytes, flags, io->peeraddr, sizeof(struct sockaddr_in6), &hovlp->ovlp, NULL);
    }
    else
    {
        ret = -1;
    }
    // printd("WSASend ret=%d bytes=%u\n", ret, dwbytes);
    if (ret != 0)
    {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING)
        {
            printError("WSASend error: %d\n", err);
            io->error = err;
            free_buffered_overlapped(io, hovlp);
            wioClose(io);
            return ret;
        }
    }
    return 0;
}
write_error:
disconnect:
    bufferpoolReuseBuffer(io->loop->bufpool,buf);
    wioClose(io);
    return 0;
}

int wioClose (wio_t* io) {
    if (io->closed) return 0;
    io->closed = 1;
    wioDone(io);
    if (io->hovlp) {
        woverlapped_t* hovlp = (woverlapped_t*)io->hovlp;
        if (hovlp->sbuf) {
            bufferpoolReuseBuffer(io->loop->bufpool, hovlp->sbuf);
            hovlp->sbuf = NULL;
        }
        if (hovlp->event != WW_READ || io->accept) {
            EVENTLOOP_FREE(hovlp->buf.buf);
        }
        EVENTLOOP_FREE(hovlp->addr);
        EVENTLOOP_FREE(io->hovlp);
    }
    if (io->close_cb) {
        //printd("close_cb------\n");
        io->close_cb(io);
        //printd("close_cb======\n");
    }
    if (io->io_type & WIO_TYPE_SOCKET) {
#ifdef USE_DISCONNECTEX
        // DisconnectEx reuse socket
        if (io->connectex) {
            io->connectex = 0;
            LPFN_DISCONNECTEX DisconnectEx = NULL;
            GUID guidDisconnectEx = WSAID_DISCONNECTEX;
            DWORD dwbytes;
            if (WSAIoctl(io->fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
                &guidDisconnectEx, sizeof(guidDisconnectEx),
                &DisconnectEx, sizeof(DisconnectEx),
                &dwbytes, NULL, NULL) != 0) {
                return -1;
            }
            DisconnectEx(io->fd, NULL, 0, 0);
        }
#else
        closesocket(io->fd);
#endif
    }
    return 0;
}

#endif
