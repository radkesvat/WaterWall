// WARN: overlapio maybe need MemoryPool to avoid alloc/free
#include "iowatcher.h"

#ifdef EVENT_IOCP
#include "overlapio.h"
#include "wevent.h"

#define ACCEPTEX_NUM    10

int post_acceptex(wio_t* listenio, hoverlapped_t* hovlp) {
    LPFN_ACCEPTEX AcceptEx = NULL;
    GUID guidAcceptEx = WSAID_ACCEPTEX;
    DWORD dwbytes = 0;
    if (WSAIoctl(listenio->fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guidAcceptEx, sizeof(guidAcceptEx),
        &AcceptEx, sizeof(AcceptEx),
        &dwbytes, NULL, NULL) != 0) {
        return WSAGetLastError();
    }
    int connfd = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (connfd < 0) {
        return WSAGetLastError();
    }
    if (hovlp == NULL) {
        EVENTLOOP_ALLOC_SIZEOF(hovlp);
        hovlp->buf.len = 20 + sizeof(struct sockaddr_in6) * 2;
        EVENTLOOP_ALLOC(hovlp->buf.buf, hovlp->buf.len);
    }
    hovlp->fd = connfd;
    hovlp->event = WW_READ;
    hovlp->io = listenio;
    if (AcceptEx(listenio->fd, connfd, hovlp->buf.buf, 0, sizeof(struct sockaddr_in6), sizeof(struct sockaddr_in6),
        &dwbytes, &hovlp->ovlp) != TRUE) {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING) {
            printError("AcceptEx error: %d\n", err);
            return err;
        }
    }
    return 0;
}

int post_recv(wio_t* io, hoverlapped_t* hovlp) {
    if (hovlp == NULL) {
        EVENTLOOP_ALLOC_SIZEOF(hovlp);
    }
    hovlp->fd = io->fd;
    hovlp->event = WW_READ;
    hovlp->io = io;
    hovlp->buf.len = io->readbuf.len;
    if (io->io_type == WIO_TYPE_UDP || io->io_type == WIO_TYPE_IP) {
        EVENTLOOP_ALLOC(hovlp->buf.buf, hovlp->buf.len);
    }
    else {
        hovlp->buf.buf = io->readbuf.base;
    }
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
            hovlp->addrlen = sizeof(struct sockaddr_in6);
            EVENTLOOP_ALLOC(hovlp->addr, sizeof(struct sockaddr_in6));
        }
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
            return err;
        }
    }
    return 0;
}

static void on_acceptex_complete(wio_t* io) {
    printd("on_acceptex_complete------\n");
    hoverlapped_t* hovlp = (hoverlapped_t*)io->hovlp;
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
    hoverlapped_t* hovlp = (hoverlapped_t*)io->hovlp;
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
    hoverlapped_t* hovlp = (hoverlapped_t*)io->hovlp;
    if (hovlp->bytes == 0) {
        io->error = WSAGetLastError();
        wioClose(io);
        return;
    }

    if (io->read_cb) {
        if (io->io_type == WIO_TYPE_UDP || io->io_type == WIO_TYPE_IP) {
            if (hovlp->addr && hovlp->addrlen) {
                wioSetPeerAddr(io, hovlp->addr, hovlp->addrlen);
            }
        }
        //printd("read_cb------\n");
        io->read_cb(io, hovlp->buf.buf, hovlp->bytes);
        //printd("read_cb======\n");
    }

    if (io->io_type == WIO_TYPE_TCP) {
        // reuse hovlp
        if (!io->closed) {
            post_recv(io, hovlp);
        }
    }
    else if (io->io_type == WIO_TYPE_UDP ||
            io->io_type == WIO_TYPE_IP) {
        EVENTLOOP_FREE(hovlp->buf.buf);
        EVENTLOOP_FREE(hovlp->addr);
        EVENTLOOP_FREE(io->hovlp);
    }
}

static void on_wsasend_complete(wio_t* io) {
    printd("on_send_complete------\n");
    hoverlapped_t* hovlp = (hoverlapped_t*)io->hovlp;
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
        io->write_cb(io, hovlp->buf.buf, hovlp->bytes);
        //printd("write_cb======\n");
    }
end:
    if (io->hovlp) {
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

int wioAccept (wio_t* io) {
    for (int i = 0; i < ACCEPTEX_NUM; ++i) {
        post_acceptex(io, NULL);
    }
    io->accept = 1;
    return wioAdd(io, wio_handle_events, WW_READ);
}

int wioConnect (wio_t* io) {
    // NOTE: ConnectEx must call bind
    struct sockaddr_in localaddr;
    socklen_t addrlen = sizeof(localaddr);
    memorySet(&localaddr, 0, addrlen);
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localaddr.sin_port = htons(0);
    if (bind(io->fd, (struct sockaddr*)&localaddr, addrlen) < 0) {
        printError("bind");
        goto error;
    }
    // ConnectEx
    io->connectex = 1;
    LPFN_CONNECTEX ConnectEx = NULL;
    GUID guidConnectEx = WSAID_CONNECTEX;
    DWORD dwbytes;
    if (WSAIoctl(io->fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guidConnectEx, sizeof(guidConnectEx),
        &ConnectEx, sizeof(ConnectEx),
        &dwbytes, NULL, NULL) != 0) {
        goto error;
    }
    // NOTE: free on_connectex_complete
    hoverlapped_t* hovlp;
    EVENTLOOP_ALLOC_SIZEOF(hovlp);
    hovlp->fd = io->fd;
    hovlp->event = WW_WRITE;
    hovlp->io = io;
    if (ConnectEx(io->fd, io->peeraddr, sizeof(struct sockaddr_in6), NULL, 0, &dwbytes, &hovlp->ovlp) != TRUE) {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING) {
            printError("AcceptEx error: %d\n", err);
            goto error;
        }
    }
    io->connect = 1;
    return wioAdd(io, wio_handle_events, WW_WRITE);
error:
    wioClose(io);
    return 0;
}

int wioRead (wio_t* io) {
    post_recv(io, NULL);
    return wioAdd(io, wio_handle_events, WW_READ);
}

int wioWrite(wio_t* io, sbuf_t* buf) {
    int nwrite = 0;
try_send:
    if (io->io_type == WIO_TYPE_TCP) {
        nwrite = send(io->fd, sbufGetRawPtr(buf), sbufGetBufLength(buf), 0);
    }
    else if (io->io_type == WIO_TYPE_UDP) {
        nwrite = sendto(io->fd, sbufGetRawPtr(buf), sbufGetBufLength(buf), 0, io->peeraddr, sizeof(struct sockaddr_in6));
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
        io->write_cb(io, buf);
        //printd("try_write_cb======\n");
    }
    if (nwrite == sbufGetBufLength(buf)) {
        //goto write_done;
        bufferpoolResuesBuffer(io->loop->bufpool,buf);
        return nwrite;
    }
WSASend:
    {
        hoverlapped_t* hovlp;
        EVENTLOOP_ALLOC_SIZEOF(hovlp);
        hovlp->fd = io->fd;
        hovlp->event = WW_WRITE;
        sbufShiftRight(buf,nwrite);
        hovlp->buf.len = sbufGetBufLength(buf);
        // NOTE: free on_send_complete
        EVENTLOOP_ALLOC(hovlp->buf.buf, hovlp->buf.len);
        memoryCopy(hovlp->buf.buf, sbufGetRawPtr(buf), hovlp->buf.len);
        bufferpoolResuesBuffer(io->loop->bufpool,buf);
        hovlp->io = io;
        DWORD dwbytes = 0;
        DWORD flags = 0;
        int ret = 0;
        if (io->io_type == WIO_TYPE_TCP) {
            ret = WSASend(io->fd, &hovlp->buf, 1, &dwbytes, flags, &hovlp->ovlp, NULL);
        }
        else if (io->io_type == WIO_TYPE_UDP ||
                 io->io_type == WIO_TYPE_IP) {
            ret = WSASendTo(io->fd, &hovlp->buf, 1, &dwbytes, flags, io->peeraddr, sizeof(struct sockaddr_in6), &hovlp->ovlp, NULL);
        }
        else {
            ret = -1;
        }
        //printd("WSASend ret=%d bytes=%u\n", ret, dwbytes);
        if (ret != 0) {
            int err = WSAGetLastError();
            if (err != ERROR_IO_PENDING) {
                printError("WSASend error: %d\n", err);
                return ret;
            }
        }
        return wioAdd(io, wio_handle_events, WW_WRITE);
    }
write_error:
disconnect:
    bufferpoolResuesBuffer(io->loop->bufpool,buf);
    wioClose(io);
    return 0;
}

int wioClose (wio_t* io) {
    if (io->closed) return 0;
    io->closed = 1;
    wioDone(io);
    if (io->hovlp) {
        hoverlapped_t* hovlp = (hoverlapped_t*)io->hovlp;
        // NOTE: wRead buf provided by caller
        if (hovlp->buf.buf != io->readbuf.base) {
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
                return;
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
