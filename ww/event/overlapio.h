#ifndef WW_OVERLAPPED_H_
#define WW_OVERLAPPED_H_

#include "iowatcher.h"

#ifdef EVENT_IOCP

#include "hbuf.h"
#include "wsocket.h"
#include <mswsock.h>
#ifdef _MSC_VER
#pragma comment(lib, "mswsock.lib")
#endif

typedef struct hoverlapped_s {
    OVERLAPPED  ovlp;
    int         fd;
    int         event;
    WSABUF      buf;
    int         bytes;
    int         error;
    wio_t*      io;
    // for recvfrom
    struct sockaddr* addr;
    int         addrlen;
} hoverlapped_t;

int post_acceptex(wio_t* listenio, hoverlapped_t* hovlp);
int post_recv(wio_t* io, hoverlapped_t* hovlp);

#endif

#endif // WW_OVERLAPPED_H_
