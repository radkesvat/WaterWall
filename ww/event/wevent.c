#include "wevent.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "watomic.h"
#include "werr.h"
#include "wsocket.h"
#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>
#endif
#ifdef EVENT_IOCP
#include "overlapio.h"
#endif

static pool_item_t *wiofdAllocateItem(generic_pool_t *pool)
{
    discard pool;
    return memoryAllocateZero(sizeof(wio_fd_t));
}

static void wiofdFreeItem(pool_item_t *item)
{
    memoryFree(item);
}

static master_pool_item_t *wiofdAllocateSharedItem(void *userdata)
{
    discard userdata;
    return wiofdAllocateItem(NULL);
}

generic_pool_t *wiofdCreatePool(master_pool_t *master, uint32_t capacity)
{
    generic_pool_t *pool = genericpoolCreateWithCapacity(master, capacity, wiofdAllocateItem, wiofdFreeItem);
    if (pool != NULL)
    {
        genericpoolSetItemSize(pool, sizeof(wio_fd_t));
        masterpoolInstallCallBacks(master, wiofdAllocateSharedItem, wiofdFreeItem);
    }
    return pool;
}

wio_fd_t *wiofdCreate(int fd)
{
    master_pool_t *master = GSTATE.masterpool_wio_fds;
    assert(master != NULL);
    worker_t       *worker = tryGetCurrentEventWorker();
    generic_pool_t *pool   = worker != NULL ? worker->wio_fd_pool : NULL;
    wio_fd_t       *handle;
    if (pool != NULL)
    {
        assert(pool->mp == master);
        handle = genericpoolGetItem(pool);
    }
    else
    {
        masterpoolRecordCheckout(master);
        masterpoolGetItems(master, (master_pool_item_t **) &handle, 1, NULL);
    }
    *handle = (wio_fd_t) {.fd = fd, .pipefd = {0, 0}, .refc = 1, .reserved = 0, .is_socket = true};
    return handle;
}

uint32_t wiofdGetRefCount(const wio_fd_t *handle)
{
    return atomicLoadU32Relaxed(&handle->refc);
}

void wiofdRef(wio_fd_t *handle)
{
    const uint32_t previous = atomicIncU32Relaxed(&handle->refc);
    if (UNLIKELY(previous == 0 || previous == UINT32_MAX))
    {
        LOGF("wiofdRef: invalid descriptor reference count");
        abortProgramNow(1);
    }
}

void wiofdUnref(wio_fd_t *handle)
{
    const uint32_t previous = atomicDecU32Explicit(&handle->refc, memory_order_acq_rel);
    if (UNLIKELY(previous == 0))
    {
        LOGF("wiofdUnref: descriptor reference count underflow");
        abortProgramNow(1);
    }
    if (previous != 1)
    {
        return;
    }

    if (handle->fd >= 0)
    {
#ifdef OS_WIN
        if (handle->is_socket)
        {
            closesocket(handle->fd);
        }
        else
        {
            _close(handle->fd);
        }
#else
        close(handle->fd);
#endif
        handle->fd = -1;
    }
#if WW_HAVE_SPLICE
    if (handle->pipefd[0] != 0 || handle->pipefd[1] != 0)
    {
        close(handle->pipefd[0]);
        close(handle->pipefd[1]);
        handle->pipefd[0] = handle->pipefd[1] = 0;
    }
#endif

    master_pool_t  *master = GSTATE.masterpool_wio_fds;
    worker_t       *worker = tryGetCurrentEventWorker();
    generic_pool_t *pool   = worker != NULL ? worker->wio_fd_pool : NULL;
    assert(master != NULL);
    if (pool != NULL)
    {
        assert(pool->mp == master);
        genericpoolReuseItem(pool, handle);
    }
    else
    {
        master_pool_item_t *item = handle;
        masterpoolReuseItems(master, &item, 1);
        masterpoolRecordReturn(master);
    }
}

int wiofdInitPipe(wio_fd_t *handle)
{
#if WW_HAVE_SPLICE
    if (handle->pipefd[0] != 0 || handle->pipefd[1] != 0)
    {
        return 0;
    }
    int pipefd[2];
    if (pipe2(pipefd, O_NONBLOCK | O_CLOEXEC) != 0)
    {
        return -1;
    }
    handle->pipefd[0] = pipefd[0];
    handle->pipefd[1] = pipefd[1];
    return 0;
#else
    discard handle;
    errno = ENOSYS;
    return -1;
#endif
}

ssize_t wioMoveSpliceBuferToPipe(sbuf_t *buf)
{
    // kSbufFlagSplice identifies the splice representation; capacity is logical.
    if (UNLIKELY(buf == NULL || (buf->flags & kSbufFlagSplice) == 0 || (buf->flags & kSbufFlagSplicePiped) != 0 ||
                 (buf->flags & kSbufFlagSpliceFD) == 0))
    {
        LOGF("wioMoveSpliceBuferToPipe: requires kSbufFlagSplice and kSbufFlagSpliceFD, "
             "with kSbufFlagSplicePiped clear");
        abortProgramNow(1);
    }
    assert(sbufGetLifetime(buf) == NULL && "Splice buffers must not carry lifetime metadata");
#if WW_HAVE_SPLICE
    assert(buf->curpos <= buf->l_pad);
    const uint32_t prefix_bytes = (uint32_t) buf->l_pad - buf->curpos;
    assert(buf->len >= prefix_bytes);
    const uint32_t socket_bytes = buf->len - prefix_bytes;

    wio_fd_t *handle;
    static_assert(sizeof(handle) <= SPLICE_BUFFER_STORAGE_SIZE, "WIO descriptor pointer must fit in a splice buffer");
    sbufByteCopy(&handle, buf->buf + buf->l_pad, sizeof(handle));
    assert(handle != NULL && handle->reserved >= socket_bytes);
    if (UNLIKELY(handle->pipefd[0] == 0 && handle->pipefd[1] == 0))
    {
        LOGF("wioMoveSpliceBuferToPipe: descriptor pipe must already be initialized");
        abortProgramNow(1);
    }

    ssize_t consumed = 0;
    if (socket_bytes != 0)
    {
        do
        {
            consumed = splice(handle->fd, NULL, handle->pipefd[1], NULL, socket_bytes, SPLICE_F_NONBLOCK);
        } while (consumed < 0 && errno == EINTR);
    }

    if (consumed > 0)
    {
        handle->reserved -= (uint32_t) consumed;
    }
    if (consumed >= 0 && (uint32_t) consumed == socket_bytes)
    {
        buf->flags &= (uint16_t) ~kSbufFlagSpliceFD;
        buf->flags |= kSbufFlagSplicePiped;
    }
    else
    {
        // TODO: Replace this temporary fatal policy with partial-transfer/error handling.
        // Short splices are valid; reservation accounting must keep using the actual result.
        const int splice_error = consumed < 0 ? errno : 0;
        LOGF("wioMoveSpliceBuferToPipe: incomplete splice (requested=%u, result=%lld, errno=%d)",
             (unsigned int) socket_bytes,
             (long long) consumed,
             splice_error);
        abortProgramNow(1);
    }
    return consumed;
#else
    discard buf;
    errno = ENOSYS;
    return -1;
#endif
}

sbuf_t *wioTransformSpliceBufferToRealBuffer(sbuf_t *buf, sbuf_t *dest, buffer_pool_t *pool)
{
    if (UNLIKELY(buf == NULL || (buf->flags & kSbufFlagSplice) == 0))
    {
        LOGF("wioTransformSpliceBufferToRealBuffer: requires kSbufFlagSplice");
        abortProgramNow(1);
    }
    assert(sbufGetLifetime(buf) == NULL && "Splice buffers must not carry lifetime metadata");
    const uint16_t location = buf->flags & (kSbufFlagSpliceFD | kSbufFlagSplicePiped);
    if (UNLIKELY(location != kSbufFlagSpliceFD && location != kSbufFlagSplicePiped))
    {
        LOGF("wioTransformSpliceBufferToRealBuffer: requires exactly one of SpliceFD and SplicePiped");
        abortProgramNow(1);
    }
    assert(dest != NULL && pool != NULL);
    if (UNLIKELY((dest->flags & (kSbufFlagSplice | kSbufFlagSpliceFD | kSbufFlagSplicePiped)) != 0))
    {
        LOGF("wioTransformSpliceBufferToRealBuffer: destination must be an ordinary buffer");
        abortProgramNow(1);
    }
#if WW_HAVE_SPLICE
    assert(buf->curpos <= buf->l_pad);
    const uint32_t prefix_bytes = (uint32_t) buf->l_pad - buf->curpos;
    assert(buf->len >= prefix_bytes);
    const uint32_t body_bytes = buf->len - prefix_bytes;

    // Preserve the source cursor/headroom without changing the destination's allocation geometry.
    if (UNLIKELY(buf->curpos > sbufGetTotalCapacity(dest)))
    {
        LOGF("wioTransformSpliceBufferToRealBuffer: destination too small for left headroom "
             "(capacity=%u, left headroom=%u)",
             (unsigned int) sbufGetTotalCapacity(dest),
             (unsigned int) buf->curpos);
        abortProgramNow(1);
    }
    dest->curpos = buf->curpos;
    if (UNLIKELY(sbufGetLength(buf) > sbufGetMaximumWriteableSize(dest)))
    {
        LOGF("wioTransformSpliceBufferToRealBuffer: destination too small "
             "(capacity=%u, left headroom=%u, payload=%u)",
             (unsigned int) sbufGetTotalCapacity(dest),
             (unsigned int) buf->curpos,
             (unsigned int) sbufGetLength(buf));
        abortProgramNow(1);
    }

    wio_fd_t *handle;
    static_assert(sizeof(handle) <= SPLICE_BUFFER_STORAGE_SIZE, "WIO descriptor pointer must fit in a splice buffer");
    sbufByteCopy(&handle, buf->buf + buf->l_pad, sizeof(handle));
    assert(handle != NULL);
    const bool from_pipe = location == kSbufFlagSplicePiped;
    if (UNLIKELY(from_pipe && handle->pipefd[0] == 0 && handle->pipefd[1] == 0))
    {
        LOGF("wioTransformSpliceBufferToRealBuffer: descriptor pipe must already be initialized");
        abortProgramNow(1);
    }
    assert(from_pipe || handle->reserved >= body_bytes);

    sbufByteCopy(dest->buf + buf->curpos, sbufGetRawPtr(buf), prefix_bytes);
    ssize_t consumed = 0;
    if (body_bytes != 0)
    {
        const int fd = from_pipe ? handle->pipefd[0] : handle->fd;
        consumed     = read(fd, dest->buf + buf->l_pad, body_bytes);
    }
    if (! from_pipe && consumed > 0)
    {
        handle->reserved -= (uint32_t) consumed;
    }
    if (UNLIKELY(consumed < 0 || (uint32_t) consumed != body_bytes))
    {
        const int read_error = consumed < 0 ? errno : 0;
        LOGF("wioTransformSpliceBufferToRealBuffer: incomplete read from %s "
             "(requested=%u, result=%lld, errno=%d)",
             from_pipe ? "pipe" : "source fd",
             (unsigned int) body_bytes,
             (long long) consumed,
             read_error);
        abortProgramNow(1);
    }

    sbufSetLength(dest, buf->len);
    dest->flags = buf->flags & (uint16_t) ~(kSbufFlagSplice | kSbufFlagSpliceFD | kSbufFlagSplicePiped);
    bufferpoolReuseBuffer(pool, buf);
    return dest;
#else
    discard dest;
    discard pool;
    LOGF("wioTransformSpliceBufferToRealBuffer: splice is unsupported on this build");
    abortProgramNow(1);
#endif
}

// todo (invesitage) how a dynamic node can have these?
uint64_t wloopGetNextEventID(void)
{
    static atomic_long s_id = (0);
    return (uint64_t) (++s_id);
}

uint32_t wioSetNextID(void)
{
    static atomic_long s_id = (0);
    return (uint32_t) (++s_id);
}

static void fillIoType(wio_t *io)
{
    int       type   = 0;
    socklen_t optlen = sizeof(int);
    int       ret    = getsockopt(wioGetFD(io), SOL_SOCKET, SO_TYPE, (char *) &type, &optlen);
    printd("getsockopt SO_TYPE fd=%d ret=%d type=%d errno=%d\n", wioGetFD(io), ret, type, socketERRNO());
    if (ret == 0)
    {
        switch (type)
        {
        case SOCK_STREAM:
            io->io_type = WIO_TYPE_TCP;
            break;
        case SOCK_DGRAM:
            io->io_type = WIO_TYPE_UDP;
            break;
        case SOCK_RAW:
            io->io_type = WIO_TYPE_IP;
            break;
        default:
            io->io_type = WIO_TYPE_SOCKET;
            break;
        }
    }
    else if (socketERRNO() == ENOTSOCK)
    {
        switch (wioGetFD(io))
        {
        case 0:
            io->io_type = WIO_TYPE_STDIN;
            break;
        case 1:
            io->io_type = WIO_TYPE_STDOUT;
            break;
        case 2:
            io->io_type = WIO_TYPE_STDERR;
            break;
        default:
            io->io_type = WIO_TYPE_FILE;
            break;
        }
    }
    else
    {
        io->io_type = WIO_TYPE_TCP;
    }
}

static void wioSocketInit(wio_t *io)
{
    // fill io->localaddr io->peeraddr
    if (io->localaddr == NULL)
    {
        EVENTLOOP_ALLOC(io->localaddr, sizeof(sockaddr_u));
    }
    if (io->peeraddr == NULL)
    {
        EVENTLOOP_ALLOC(io->peeraddr, sizeof(sockaddr_u));
    }
    // NOTE: datagram/raw writes go through wioWriteDatagram with an explicit
    // per-call destination and drop on transient pressure instead of queuing,
    // so every socket type runs nonblocking on the event loop.
    if (nonBlocking(wioGetFD(io)) != 0)
    {
        io->error = socketERRNO();
        wloge("failed to set fd[%d] nonblocking: %s:%d, rejecting socket",
              wioGetFD(io),
              socketStrError(io->error),
              io->error);
        // A blocking socket must never stay usable on the event loop; the io
        // comes back closed and every read/write path rejects it.
        wioClose(io);
        return;
    }
    socklen_t addrlen = sizeof(sockaddr_u);
    int       ret     = getsockname(wioGetFD(io), io->localaddr, &addrlen);
    discard   ret;
    printd("getsockname fd=%d ret=%d errno=%d\n", wioGetFD(io), ret, socketERRNO());
    // NOTE: udp peeraddr set by recvfrom/sendto
    if (io->io_type & WIO_TYPE_SOCK_STREAM)
    {
        addrlen = sizeof(sockaddr_u);
        ret     = getpeername(wioGetFD(io), io->peeraddr, &addrlen);
        printd("getpeername fd=%d ret=%d errno=%d\n", wioGetFD(io), ret, socketERRNO());
    }
}

void wioInit(wio_t *io)
{
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
    discard io;
}

void wioReady(wio_t *io)
{
    if (io->ready)
        return;
    // flags
    io->ready     = 1;
    io->connected = 0;
    io->closed    = 0;
    io->accept = io->connect = io->connectex = 0;
    io->recv = io->send = 0;
    io->recvfrom = io->sendto = 0;
    io->close                 = 0;
    io->release_no_close      = 0;
    io->splice_enabled        = 0;
    io->read_started          = 0;
#ifndef EVENT_IOCP
    io->close_in_progress = 0;
#endif
    // public:
    io->id      = wioSetNextID();
    io->io_type = WIO_TYPE_UNKNOWN;
    io->error   = 0;
    io->events = io->revents = 0;
    io->last_read_hrtime = io->last_write_hrtime = io->loop->cur_hrtime;

    io->read_flags = 0;
    // write_queue
    io->write_bufsize     = 0;
    io->max_write_bufsize = MAX_WRITE_BUFSIZE;
    // callbacks
    io->read_cb    = NULL;
    io->write_cb   = NULL;
    io->close_cb   = NULL;
    io->accept_cb  = NULL;
    io->connect_cb = NULL;
    // timers
    io->connect_timeout    = 0;
    io->connect_timer      = NULL;
    io->close_timeout      = 0;
    io->close_timer        = NULL;
    io->read_timeout       = 0;
    io->read_timer         = NULL;
    io->write_timeout      = 0;
    io->write_timer        = NULL;
    io->keepalive_timeout  = 0;
    io->keepalive_timer    = NULL;
    io->heartbeat_interval = 0;
    io->heartbeat_fn       = NULL;
    io->heartbeat_timer    = NULL;

    // private:
#if defined(EVENT_POLL) || defined(EVENT_KQUEUE)
    io->event_index[0] = io->event_index[1] = -1;
#endif
#ifdef EVENT_IOCP
    // Native IOCP record tracking. Deferred reuse (see wioGet/wioFree) guarantees
    // this object has no live records when it reaches wioReady, so a plain reset
    // is safe.
    assert(io->iocp_live_records == 0);
    assert(io->iocp_posted_count == 0);
    // A replenishment timer or a live accept slot must never survive into a
    // reused object; both are released by close/release before pool reuse.
    assert(io->iocp_accept_retry_timer == NULL);
    assert(io->iocp_accept_records == 0);
    io->iocp_posted_head = io->iocp_posted_tail = NULL;
    io->iocp_completed_head = io->iocp_completed_tail = NULL;
    io->iocp_send_active                              = NULL;
    io->iocp_live_records                             = 0;
    io->iocp_posted_count                             = 0;
    io->iocp_accept_records                           = 0;
    io->iocp_accept_retry_timer                       = NULL;
    io->iocp_accept_retry_attempts                    = 0;
    io->iocp_accept_last_error                        = 0;
    io->iocp_deferred_finalize                        = 0;
    io->iocp_pending_dispatch                         = 0;
    io->iocp_close_in_progress                        = 0;
    io->iocp_associated                               = 0;
#endif

    // io_type
    fillIoType(io);
    io->fd_handle->is_socket = (io->io_type & WIO_TYPE_SOCKET) != 0;
    if (io->io_type & WIO_TYPE_SOCKET)
    {
        wioSocketInit(io);
    }
}

void wioDone(wio_t *io)
{
    if (! io->ready)
        return;
    io->ready = 0;

    wioDel(io, WW_RDWR);

    // write_queue
    sbuf_t *buf = NULL;
    //
    while (! write_queue_empty(&io->write_queue))
    {
        buf = *write_queue_front(&io->write_queue);
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        write_queue_pop_front(&io->write_queue);
    }
    write_queue_cleanup(&io->write_queue);
    io->write_queue.ptr = NULL;
    io->write_bufsize   = 0;
}

void wioFree(wio_t *io)
{
    if (io == NULL || io->destroy)
        return;
#ifdef EVENT_IOCP
    if (io->loop != NULL && io->io_slot >= 0 && io->io_slot < (int) io->loop->ios.maxsize &&
        io->loop->ios.ptr[io->io_slot] == io)
    {
        io->loop->ios.ptr[io->io_slot] = NULL;
    }
    /*
     * A pending-list node, a dequeued completion, or wioClose itself may still
     * hold this address even when no operation record is live. Detach first so
     * descriptor reuse cannot discover the same object, then route every native
     * IOCP free through the common finalization predicate.
     */
    io->destroy                = 1;
    io->iocp_deferred_finalize = 1;
    wioClose(io);
    return;
#else
    io->destroy = 1;
    if (io->close_in_progress)
    {
        return;
    }
    wioClose(io);
    wioFinalizeNow(io);
#endif
}

#ifdef EVENT_IOCP
void wioFinalizeNow(wio_t *io)
{
    // Called from the native IOCP retire path once the last operation record for a
    // deferred-finalized wio_t has been released. At this point the socket is
    // closed, the object is detached from loop->ios, and no kernel reference
    // remains, so it is safe to return it to the worker pool.
    assert(io->iocp_deferred_finalize);
    assert(! io->pending);
    assert(! io->iocp_pending_dispatch);
    assert(! io->iocp_close_in_progress);
    assert(io->iocp_posted_count == 0);
    assert(io->iocp_live_records == 0);
    assert(io->iocp_completed_head == NULL);
    assert(io->iocp_send_active == NULL);
    // A surviving AcceptEx replenishment timer would fire on pooled memory, and a
    // stale live-slot count would corrupt the next listener's capacity math.
    assert(io->iocp_accept_retry_timer == NULL);
    assert(io->iocp_accept_records == 0);
    assert(io->loop == NULL || io->io_slot < 0 || io->io_slot >= (int) io->loop->ios.maxsize ||
           io->loop->ios.ptr[io->io_slot] != io);

    // Last line of defence: a timer surviving into the pool would fire on reused
    // memory. wioClose()/wioReleaseNoCloseNow() must already have removed them.
    assert(io->connect_timer == NULL);
    assert(io->close_timer == NULL);
    assert(io->read_timer == NULL);
    assert(io->write_timer == NULL);
    assert(io->keepalive_timer == NULL);
    assert(io->heartbeat_timer == NULL);
    wioDelConnectTimer(io);
    wioDelCloseTimer(io);
    wioDelReadTimer(io);
    wioDelWriteTimer(io);
    wioDelKeepaliveTimer(io);
    wioDelHeartBeatTimer(io);

    io->iocp_deferred_finalize = 0;
    io->destroy                = 1;
    EVENTLOOP_FREE(io->localaddr);
    EVENTLOOP_FREE(io->peeraddr);
    threadsafegenericpoolReuseItem(getWorkerWiosPool(io->loop->wid), io);
}
#else
void wioFinalizeNow(wio_t *io)
{
    assert(io->destroy && ! io->close_in_progress && io->fd_handle == NULL);
    if (io->loop != NULL && io->io_slot >= 0 && io->io_slot < (int) io->loop->ios.maxsize &&
        io->loop->ios.ptr[io->io_slot] == io)
    {
        io->loop->ios.ptr[io->io_slot] = NULL;
    }
    EVENTLOOP_FREE(io->localaddr);
    EVENTLOOP_FREE(io->peeraddr);
    threadsafegenericpoolReuseItem(getWorkerWiosPool(io->loop->wid), io);
}
#endif

bool wioIsOpened(wio_t *io)
{
    if (io == NULL)
        return false;
    return io->ready == 1 && io->closed == 0;
}

bool wioIsConnected(wio_t *io)
{
    if (io == NULL)
        return false;
    return io->ready == 1 && io->connected == 1 && io->closed == 0;
}

bool wioIsClosed(wio_t *io)
{
    if (io == NULL)
        return true;
    return io->ready == 0 && io->closed == 1;
}

uint32_t wioGetID(wio_t *io)
{
    return io->id;
}

int wioGetFD(const wio_t *io)
{
    return io->fd_handle != NULL ? io->fd_handle->fd : -1;
}

wio_fd_t *wioGetFDHandle(const wio_t *io)
{
    return io->fd_handle;
}

int wioInitPipe(wio_t *io)
{
    assert(io->fd_handle != NULL);
    return wiofdInitPipe(io->fd_handle);
}

int wioEnableSplice(wio_t *io)
{
    assert(io->ready && ! io->closed);
    assert(! io->read_started && "Splice must be enabled before starting WIO reads");
    if (wioInitPipe(io) != 0)
    {
        return -1;
    }
    io->splice_enabled = 1;
    return 0;
}

void wioDisableSplice(wio_t *io)
{
    io->splice_enabled = 0;
}

bool wioIsSpliceEnabled(const wio_t *io)
{
    return io->splice_enabled;
}

void wioReleaseFDHandle(wio_t *io, bool keep_fd)
{
    wio_fd_t *handle = io->fd_handle;
    io->fd_handle    = NULL;
    if (handle != NULL)
    {
        if (keep_fd)
        {
            handle->fd = -1;
        }
        wiofdUnref(handle);
    }
}

wio_type_e wioGetType(wio_t *io)
{
    return io->io_type;
}

int wioGetError(wio_t *io)
{
    return io->error;
}

int wioGetEvents(wio_t *io)
{
    return io->events;
}

int wioGetREvents(wio_t *io)
{
    return io->revents;
}

sockaddr_u *wioGetLocaladdrU(wio_t *io)
{
    return io->localaddr_u;
}

sockaddr_u *wioGetPeerAddrU(wio_t *io)
{
    return io->peeraddr_u;
}

struct sockaddr *wioGetLocaladdr(wio_t *io)
{
    return io->localaddr;
}

struct sockaddr *wioGetPeerAddr(wio_t *io)
{
    return io->peeraddr;
}

waccept_cb wioGetCallBackAccept(wio_t *io)
{
    return io->accept_cb;
}

wconnect_cb wioGetCallBackConnect(wio_t *io)
{
    return io->connect_cb;
}

wread_cb wioGetCallBackRead(wio_t *io)
{
    return io->read_cb;
}

wwrite_cb wioGetCallBackWrite(wio_t *io)
{
    return io->write_cb;
}

wclose_cb wioGetCallBackClose(wio_t *io)
{
    return io->close_cb;
}

void wioSetCallBackAccept(wio_t *io, waccept_cb accept_cb)
{
    io->accept_cb = accept_cb;
}

void wioSetCallBackConnect(wio_t *io, wconnect_cb connect_cb)
{
    io->connect_cb = connect_cb;
}

void wioSetCallBackRead(wio_t *io, wread_cb read_cb)
{
    io->read_cb = read_cb;
}

void wioSetCallBackWrite(wio_t *io, wwrite_cb write_cb)
{
    io->write_cb = write_cb;
}

void wioSetCallBackClose(wio_t *io, wclose_cb close_cb)
{
    io->close_cb = close_cb;
}

void wioAcceptCallBack(wio_t *io)
{
    /*
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};
    printd("accept connfd=%d [%s] <= [%s]\n", wioGetFD(io),
            SOCKADDR_STR(io->localaddr, localaddrstr),
            SOCKADDR_STR(io->peeraddr, peeraddrstr));
    */
    if (io->accept_cb)
    {
        // printd("accept_cb------\n");
        io->accept_cb(io);
        // printd("accept_cb======\n");
    }
}

void wioConnectCallBack(wio_t *io)
{
    /*
    char localaddrstr[SOCKADDR_STRLEN] = {0};
    char peeraddrstr[SOCKADDR_STRLEN] = {0};
    printd("connect connfd=%d [%s] => [%s]\n", wioGetFD(io),
            SOCKADDR_STR(io->localaddr, localaddrstr),
            SOCKADDR_STR(io->peeraddr, peeraddrstr));
    */
    io->connected = 1;
    if (io->connect_cb)
    {
        // printd("connect_cb------\n");
        io->connect_cb(io);
        // printd("connect_cb======\n");
    }
}

void wioHandleRead(wio_t *io, sbuf_t *buf)
{
    // wioRead
    wioReadCallBack(io, buf);
}

void wioReadCallBack(wio_t *io, sbuf_t *buf)
{
    if (io->read_flags & WIO_READ_ONCE)
    {
        io->read_flags &= ~(uint32_t) WIO_READ_ONCE;
        wioReadStop(io);
    }

    if (io->read_cb)
    {
        // printd("read_cb------\n");
        io->read_cb(io, buf);
        // printd("read_cb======\n");
    }
}

void wioWriteCallBack(wio_t *io)
{
    if (io->write_cb)
    {
        // printd("write_cb------\n");
        io->write_cb(io);
        // printd("write_cb======\n");
    }
}

void wioCloseCallBack(wio_t *io)
{
    io->connected = 0;
    io->closed    = 1;
    if (io->close_cb)
    {
        // printd("close_cb------\n");
        io->close_cb(io);
        // printd("close_cb======\n");
    }
}

void wioSetType(wio_t *io, wio_type_e type)
{
    io->io_type = type;
}

void wioSetLocaladdr(wio_t *io, struct sockaddr *addr, int addrlen)
{
    if (io->localaddr == NULL)
    {
        EVENTLOOP_ALLOC(io->localaddr, sizeof(sockaddr_u));
    }
    memoryCopy(io->localaddr, addr, (size_t) addrlen);
}

void wioSetPeerAddr(wio_t *io, struct sockaddr *addr, int addrlen)
{
    if (io->peeraddr == NULL)
    {
        EVENTLOOP_ALLOC(io->peeraddr, sizeof(sockaddr_u));
    }
    memoryCopy(io->peeraddr, addr, (size_t) addrlen);
}

void wioDelConnectTimer(wio_t *io)
{
    if (io->connect_timer)
    {
        wtimerDelete(io->connect_timer);
        io->connect_timer   = NULL;
        io->connect_timeout = 0;
    }
}

void wioDelCloseTimer(wio_t *io)
{
    if (io->close_timer)
    {
        wtimerDelete(io->close_timer);
        io->close_timer   = NULL;
        io->close_timeout = 0;
    }
}

void wioDelReadTimer(wio_t *io)
{
    if (io->read_timer)
    {
        wtimerDelete(io->read_timer);
        io->read_timer   = NULL;
        io->read_timeout = 0;
    }
}

void wioDelWriteTimer(wio_t *io)
{
    if (io->write_timer)
    {
        wtimerDelete(io->write_timer);
        io->write_timer   = NULL;
        io->write_timeout = 0;
    }
}

void wioDelKeepaliveTimer(wio_t *io)
{
    if (io->keepalive_timer)
    {
        wtimerDelete(io->keepalive_timer);
        io->keepalive_timer   = NULL;
        io->keepalive_timeout = 0;
    }
}

void wioDelHeartBeatTimer(wio_t *io)
{
    if (io->heartbeat_timer)
    {
        wtimerDelete(io->heartbeat_timer);
        io->heartbeat_timer    = NULL;
        io->heartbeat_interval = 0;
        io->heartbeat_fn       = NULL;
    }
}

void wioSetConnectTimeout(wio_t *io, int timeout_ms)
{
    io->connect_timeout = timeout_ms;
}

void wioSetCloseTimeout(wio_t *io, int timeout_ms)
{
    io->close_timeout = timeout_ms;
}

static void __read_timeout_cb(wtimer_t *timer)
{
    wio_t   *io          = (wio_t *) timer->privdata;
    uint64_t inactive_ms = (io->loop->cur_hrtime - io->last_read_hrtime) / 1000;
    if (inactive_ms + 100 < (uint64_t) io->read_timeout)
    {
        if (! wtimerReset(io->read_timer, (uint32_t) ((uint64_t) io->read_timeout - inactive_ms)))
        {
            io->read_timer = NULL;
        }
    }
    else
    {
        if (io->io_type & WIO_TYPE_SOCKET)
        {
            char localaddrstr[SOCKADDR_STRLEN] = {0};
            char peeraddrstr[SOCKADDR_STRLEN]  = {0};
            wlogw("read timeout [%s] <=> [%s]",
                  SOCKADDR_STR(io->localaddr, localaddrstr),
                  SOCKADDR_STR(io->peeraddr, peeraddrstr));
        }
        io->error = ETIMEDOUT;
        wioClose(io);
    }
}

void wioSetReadTimeout(wio_t *io, int timeout_ms)
{
    if (timeout_ms <= 0)
    {
        // del
        wioDelReadTimer(io);
        return;
    }

    if (io->read_timer)
    {
        // reset
        wtimerReset(io->read_timer, (uint32_t) timeout_ms);
    }
    else
    {
        // add
        io->read_timer           = wtimerAdd(io->loop, __read_timeout_cb, (uint32_t) timeout_ms, 1);
        if (io->read_timer != NULL)
        {
            io->read_timer->privdata = io;
        }
    }
    io->read_timeout = timeout_ms;
}

static void __write_timeout_cb(wtimer_t *timer)
{
    wio_t   *io          = (wio_t *) timer->privdata;
    uint64_t inactive_ms = (io->loop->cur_hrtime - io->last_write_hrtime) / 1000;
    if (inactive_ms + 100 < (uint64_t) io->write_timeout)
    {
        if (! wtimerReset(io->write_timer, (uint32_t) ((uint64_t) io->write_timeout - inactive_ms)))
        {
            io->write_timer = NULL;
        }
    }
    else
    {
        if (io->io_type & WIO_TYPE_SOCKET)
        {
            char localaddrstr[SOCKADDR_STRLEN] = {0};
            char peeraddrstr[SOCKADDR_STRLEN]  = {0};
            wlogw("write timeout [%s] <=> [%s]",
                  SOCKADDR_STR(io->localaddr, localaddrstr),
                  SOCKADDR_STR(io->peeraddr, peeraddrstr));
        }
        io->error = ETIMEDOUT;
        wioClose(io);
    }
}

void wiosSetWriteTimeout(wio_t *io, int timeout_ms)
{
    if (timeout_ms <= 0)
    {
        // del
        wioDelWriteTimer(io);
        return;
    }

    if (io->write_timer)
    {
        // reset
        wtimerReset(io->write_timer, (uint32_t) timeout_ms);
    }
    else
    {
        // add
        io->write_timer           = wtimerAdd(io->loop, __write_timeout_cb, (uint32_t) timeout_ms, 1);
        if (io->write_timer != NULL)
        {
            io->write_timer->privdata = io;
        }
    }
    io->write_timeout = timeout_ms;
}

static void __keepalive_timeout_cb(wtimer_t *timer)
{
    wio_t   *io             = (wio_t *) timer->privdata;
    uint64_t last_rw_hrtime = max(io->last_read_hrtime, io->last_write_hrtime);
    uint64_t inactive_ms    = (io->loop->cur_hrtime - last_rw_hrtime) / 1000;
    if (inactive_ms + 100 < (uint64_t) io->keepalive_timeout)
    {
        if (! wtimerReset(io->keepalive_timer, (uint32_t) ((uint64_t) io->keepalive_timeout - inactive_ms)))
        {
            io->keepalive_timer = NULL;
        }
    }
    else
    {
        if (io->io_type & WIO_TYPE_SOCKET)
        {
            char localaddrstr[SOCKADDR_STRLEN] = {0};
            char peeraddrstr[SOCKADDR_STRLEN]  = {0};
            wlogd("keepalive timeout [%s] <=> [%s]",
                  SOCKADDR_STR(io->localaddr, localaddrstr),
                  SOCKADDR_STR(io->peeraddr, peeraddrstr));
        }
        io->error = ETIMEDOUT;
        wioClose(io);
    }
}

void wioSetKeepaliveTimeout(wio_t *io, int timeout_ms)
{
    if (timeout_ms <= 0)
    {
        // del
        wioDelKeepaliveTimer(io);
        return;
    }

    if (io->keepalive_timer)
    {
        // reset
        wtimerReset(io->keepalive_timer, (uint32_t) timeout_ms);
    }
    else
    {
        // add
        io->keepalive_timer           = wtimerAdd(io->loop, __keepalive_timeout_cb, (uint32_t) timeout_ms, 1);
        if (io->keepalive_timer != NULL)
        {
            io->keepalive_timer->privdata = io;
        }
    }
    io->keepalive_timeout = timeout_ms;
}

static void __heartbeat_timer_cb(wtimer_t *timer)
{
    wio_t *io = (wio_t *) timer->privdata;
    if (io && io->heartbeat_fn)
    {
        io->heartbeat_fn(io);
    }
}

void wioSetHeartBeat(wio_t *io, int interval_ms, wio_send_heartbeat_fn fn)
{
    if (interval_ms <= 0)
    {
        // del
        wioDelHeartBeatTimer(io);
        return;
    }

    if (io->heartbeat_timer)
    {
        // reset
        wtimerReset(io->heartbeat_timer, (uint32_t) interval_ms);
    }
    else
    {
        // add
        io->heartbeat_timer           = wtimerAdd(io->loop, __heartbeat_timer_cb, (uint32_t) interval_ms, INFINITE);
        if (io->heartbeat_timer != NULL)
        {
            io->heartbeat_timer->privdata = io;
        }
    }
    io->heartbeat_interval = interval_ms;
    io->heartbeat_fn       = fn;
}

//-----------------iobuf---------------------------------------------

void wioSetMaxWriteBufSize(wio_t *io, uint32_t size)
{
    io->max_write_bufsize = size;
}

size_t wioGetWriteBufSize(wio_t *io)
{
    return io->write_bufsize;
}

int wioReadOnce(wio_t *io)
{
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
