#include "iowatcher.h"

#ifdef EVENT_IOCP
#include "wplatform.h"
#include "wdef.h"

#include "wevent.h"
#include "overlapio.h"

typedef struct iocp_ctx_s {
    HANDLE      iocp;
} iocp_ctx_t;

int iowatcherInit(wloop_t* loop) {
    if (loop->iowatcher)    return 0;
    iocp_ctx_t* iocp_ctx;
    EVENTLOOP_ALLOC_SIZEOF(iocp_ctx);
    iocp_ctx->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    loop->iowatcher = iocp_ctx;
    return 0;
}

int iowatcherCleanUp(wloop_t* loop) {
    if (loop->iowatcher == NULL) return 0;
    iocp_ctx_t* iocp_ctx = (iocp_ctx_t*)loop->iowatcher;
    CloseHandle(iocp_ctx->iocp);
    EVENTLOOP_FREE(loop->iowatcher);
    return 0;
}

int iowatcherAddEvent(wloop_t* loop, int fd, int events) {
    if (loop->iowatcher == NULL) {
        iowatcherInit(loop);
    }
    iocp_ctx_t* iocp_ctx = (iocp_ctx_t*)loop->iowatcher;
    wio_t* io = loop->ios.ptr[fd];
    if (io && io->events == 0 && events != 0) {
        CreateIoCompletionPort((HANDLE)fd, iocp_ctx->iocp, 0, 0);
    }
    return 0;
}

int iowatcherDelEvent(wloop_t* loop, int fd, int events) {
    wio_t* io = loop->ios.ptr[fd];
    if ((io->events & ~events) == 0) {
        CancelIo((HANDLE)fd);
    }
    return 0;
}

int iowatcherPollEvents(wloop_t* loop, int timeout) {
    if (loop->iowatcher == NULL) return 0;
    iocp_ctx_t* iocp_ctx = (iocp_ctx_t*)loop->iowatcher;
    DWORD bytes = 0;
    ULONG_PTR key = 0;
    LPOVERLAPPED povlp = NULL;
    BOOL bRet = GetQueuedCompletionStatus(iocp_ctx->iocp, &bytes, &key, &povlp, timeout);
    int err = 0;
    if (povlp == NULL) {
        err = WSAGetLastError();
        if (err == WAIT_TIMEOUT || ERROR_NETNAME_DELETED || ERROR_OPERATION_ABORTED) {
            return 0;
        }
        return -err;
    }
    hoverlapped_t* hovlp = (hoverlapped_t*)povlp;
    wio_t* io = hovlp->io;
    if (bRet == FALSE) {
        err = WSAGetLastError();
        printd("iocp ret=%d err=%d bytes=%u\n", bRet, err, bytes);
        // NOTE: when ConnectEx failed, err != 0
        hovlp->error = err;
    }
    // NOTE: when WSASend/WSARecv disconnect, bytes = 0
    hovlp->bytes = bytes;
    io->hovlp = hovlp;
    io->revents |= hovlp->event;
    EVENT_PENDING(hovlp->io);
    return 1;
}
#endif
