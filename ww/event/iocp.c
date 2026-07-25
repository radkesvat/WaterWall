#include "iowatcher.h"

#ifdef EVENT_IOCP
#include "wdef.h"
#include "wplatform.h"

#include "overlapio.h"
#include "wevent.h"

typedef struct iocp_ctx_s
{
    HANDLE iocp;
} iocp_ctx_t;

int iowatcherInit(wloop_t *loop)
{
    if (loop->iowatcher)
        return 0;
    iocp_ctx_t *iocp_ctx;
    EVENTLOOP_ALLOC_SIZEOF(iocp_ctx);
    iocp_ctx->iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (iocp_ctx->iocp == NULL)
    {
        int init_error = (int) GetLastError();
        EVENTLOOP_FREE(iocp_ctx);
        return -init_error;
    }
    loop->iowatcher = iocp_ctx;
    return 0;
}

int iowatcherCleanUp(wloop_t *loop)
{
    if (loop->iowatcher == NULL)
        return 0;
    iocp_ctx_t *iocp_ctx = (iocp_ctx_t *) loop->iowatcher;
    CloseHandle(iocp_ctx->iocp);
    EVENTLOOP_FREE(loop->iowatcher);
    return 0;
}

int iowatcherAddEvent(wloop_t *loop, int fd, int events)
{
    if (loop->iowatcher == NULL)
    {
        int init_error = iowatcherInit(loop);
        if (UNLIKELY(init_error != 0))
        {
            return init_error;
        }
    }
    iocp_ctx_t *iocp_ctx = (iocp_ctx_t *) loop->iowatcher;
    wio_t      *io       = loop->ios.ptr[fd];
    if (io && io->events == 0 && events != 0)
    {
        if (CreateIoCompletionPort((HANDLE) (uintptr_t) fd, iocp_ctx->iocp, 0, 0) == NULL)
        {
            return -(int) GetLastError();
        }
    }
    return 0;
}

int iowatcherDelEvent(wloop_t *loop, int fd, int events)
{
    wio_t *io = loop->ios.ptr[fd];
    if (io == NULL)
    {
        return 0;
    }
    // Record-aware cancellation replaces the old blanket CancelIo. The default
    // reason is STOP (read/write stop leaves the socket open). wioClose pre-marks
    // its records CLOSE before wioDone re-enters here, so that reason is kept.
    wioIocpCancel(io, events, WOVERLAPPED_CANCEL_STOP);
    return 0;
}

int iowatcherPollEvents(wloop_t *loop, int timeout)
{
    if (loop->iowatcher == NULL)
        return 0;
    iocp_ctx_t  *iocp_ctx = (iocp_ctx_t *) loop->iowatcher;
    DWORD        bytes    = 0;
    ULONG_PTR    key      = 0;
    LPOVERLAPPED povlp    = NULL;
    BOOL         bRet     = GetQueuedCompletionStatus(iocp_ctx->iocp, &bytes, &key, &povlp, timeout);
    if (povlp == NULL)
    {
        // No completion was dequeued (timeout, or a spurious wakeup).
        if (bRet)
        {
            return 0;
        }
        int err = (int) GetLastError();
        if (err == WAIT_TIMEOUT)
        {
            return 0;
        }
        return -err;
    }
    // A completion for a real record (possibly a canceled/aborted one, in which
    // case bRet == FALSE and GetLastError() carries the reason, e.g.
    // ERROR_OPERATION_ABORTED / ERROR_NETNAME_DELETED). Its error is stored on the
    // record and handled by dispatch/retire according to the record's cancel
    // reason, not by inspecting it here.
    int err = 0;
    if (bRet == FALSE)
    {
        err = (int) GetLastError();
        printd("iocp ret=%d err=%d bytes=%u\n", bRet, err, bytes);
    }
    woverlapped_t *record = (woverlapped_t *) povlp;
    wio_t         *io     = record->io;
    wioIocpOnDequeued(record, bytes, err);

    if (io->active)
    {
        // Normal path: dispatch with callbacks from the pending queue. The per-IO
        // completed queue retains every completion, so coalesced wakeups are fine.
        EVENT_PENDING(io);
    }
    else
    {
        // Closed/inactive io (also covers deferred-finalize objects and loop
        // shutdown): retire completions with lifecycle cleanup but no user
        // callbacks. This may finalize a deferred wio_t, so do not touch io after.
        wioIocpRetireCompletedWithoutCallbacks(io);
    }
    return 1;
}
#endif
