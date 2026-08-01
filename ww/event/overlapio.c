// Native IOCP overlapped backend.
//
// Correctness model (see iocp-implementation-plan.md):
//   * Every submitted overlapped operation owns one woverlapped_t.
//   * A record, its buffers, its sbuf and its provisional accepted socket stay
//     valid until IOCP dequeues that operation's completion.
//   * Cancellation never returns ownership to the application; canceled records
//     are retired only after their completion is dequeued.
//   * A wio_t is kept alive (iocp_live_records) while any record references it,
//     so closing/freeing from a callback is safe.
#include "iowatcher.h"

#ifdef EVENT_IOCP
#include "loggers/internal_logger.h"
#include "overlapio.h"
#include "werr.h"
#include "wevent.h"

#define ACCEPTEX_NUM 10

// AcceptEx replenishment policy. A transient immediate submission failure (for
// example WSAENOBUFS under resource pressure) must not permanently cost the
// listener one of its accept slots, so a bounded exponential backoff restores
// the missing slots instead. A listener that cannot hold a single slot after the
// whole budget is spent closes with the last submission error rather than
// staying active and accepting nothing.
#define ACCEPTEX_RETRY_MIN_DELAY_MS  25
#define ACCEPTEX_RETRY_MAX_DELAY_MS  1000
#define ACCEPTEX_RETRY_ZERO_SLOT_MAX 8

// -----------------------------------------------------------------------------
// Record bookkeeping helpers
// -----------------------------------------------------------------------------

static void recordAttach(wio_t *io, woverlapped_t *record, woverlapped_kind_e kind)
{
    record->io             = io;
    record->io_id          = io->id;
    record->kind           = kind;
    record->cancel_reason  = WOVERLAPPED_NOT_CANCELED;
    record->posted         = false;
    record->completed      = false;
    record->posted_prev    = NULL;
    record->posted_next    = NULL;
    record->completed_next = NULL;
    record->fd             = -1;
    record->sbuf           = NULL;
    record->send_buffer    = NULL;
    record->addr           = NULL;
    record->addrlen        = 0;
    record->error          = 0;
    record->bytes          = 0;

    io->iocp_live_records++;
    io->loop->iocp_live_operations++;
    if (kind == WOVERLAPPED_ACCEPT)
    {
        // Listener capacity is counted per accept record in every state (posted,
        // completed, locally dispatching). Reposting an existing record does not
        // pass through here, so the count only moves on attach and retire.
        io->iocp_accept_records++;
        assert(io->iocp_accept_records <= ACCEPTEX_NUM);
    }
}

static void recordMarkPosted(woverlapped_t *record)
{
    wio_t *io = record->io;
    assert(! record->posted);
    assert(! record->completed);
    record->posted    = true;
    record->completed = false;

    record->posted_prev = io->iocp_posted_tail;
    record->posted_next = NULL;
    if (io->iocp_posted_tail != NULL)
    {
        io->iocp_posted_tail->posted_next = record;
    }
    else
    {
        io->iocp_posted_head = record;
    }
    io->iocp_posted_tail = record;

    io->iocp_posted_count++;
    io->loop->iocp_posted_operations++;
}

static void recordUnpost(woverlapped_t *record)
{
    wio_t *io = record->io;
    if (! record->posted)
    {
        return;
    }
    record->posted = false;

    if (record->posted_prev != NULL)
    {
        record->posted_prev->posted_next = record->posted_next;
    }
    else
    {
        io->iocp_posted_head = record->posted_next;
    }
    if (record->posted_next != NULL)
    {
        record->posted_next->posted_prev = record->posted_prev;
    }
    else
    {
        io->iocp_posted_tail = record->posted_prev;
    }
    record->posted_prev = NULL;
    record->posted_next = NULL;

    assert(io->iocp_posted_count > 0);
    io->iocp_posted_count--;
    assert(io->loop->iocp_posted_operations > 0);
    io->loop->iocp_posted_operations--;
}

static void recordPushCompleted(wio_t *io, woverlapped_t *record)
{
    assert(! record->posted);
    assert(! record->completed);
    record->completed      = true;
    record->completed_next = NULL;
    if (io->iocp_completed_tail != NULL)
    {
        io->iocp_completed_tail->completed_next = record;
    }
    else
    {
        io->iocp_completed_head = record;
    }
    io->iocp_completed_tail = record;
}

static woverlapped_t *recordPopCompleted(wio_t *io)
{
    woverlapped_t *record = io->iocp_completed_head;
    if (record == NULL)
    {
        return NULL;
    }
    io->iocp_completed_head = record->completed_next;
    if (io->iocp_completed_head == NULL)
    {
        io->iocp_completed_tail = NULL;
    }
    record->completed_next = NULL;
    record->completed      = false;
    return record;
}

// Release only the resources still owned by the record. Called from retire; a
// record being reposted keeps its accept buffer instead.
static void recordReleaseResources(woverlapped_t *record)
{
    wio_t *io = record->io;

    if (record->sbuf != NULL)
    {
        // Receive buffer that was never detached to read_cb.
        bufferpoolReuseBuffer(io->loop->bufpool, record->sbuf);
        record->sbuf = NULL;
    }
    if (record->addr != NULL)
    {
        EVENTLOOP_FREE(record->addr);
    }
    if (record->kind == WOVERLAPPED_ACCEPT)
    {
        // AcceptEx output buffer. RECV buf.buf points into sbuf (recycled above);
        // CONNECT has none.
        EVENTLOOP_FREE(record->buf.buf);
    }
    if (record->kind == WOVERLAPPED_SEND)
    {
        // buf.buf advances on partial completions, so release the allocation base.
        EVENTLOOP_FREE(record->send_buffer);
    }
    if (record->kind == WOVERLAPPED_ACCEPT && record->fd >= 0)
    {
        // Provisional accepted socket whose ownership never transferred.
        SAFE_CLOSESOCKET(record->fd);
        record->fd = -1;
    }
}

static void wioIocpMaybeFinalize(wio_t *io)
{
    if (io->iocp_deferred_finalize && wioIocpCanFinalize(io))
    {
        wioFinalizeNow(io);
    }
}

// Release a dequeued (unposted) record and drop the live reference it held. May
// finalize a deferred wio_t; callers iterating io must do so only after the loop.
static void recordRetire(woverlapped_t *record)
{
    wio_t *io = record->io;
    assert(! record->posted);
    if (record->kind == WOVERLAPPED_SEND)
    {
        assert(io->iocp_send_active == record);
        io->iocp_send_active = NULL;
        if (io->write_bufsize >= record->buf.len)
        {
            io->write_bufsize -= record->buf.len;
        }
        else
        {
            // wioDone resets the closed io's aggregate queue accounting before
            // canceled send completions retire.
            assert(io->closed);
            io->write_bufsize = 0;
        }
    }
    if (record->kind == WOVERLAPPED_ACCEPT)
    {
        assert(io->iocp_accept_records > 0);
        io->iocp_accept_records--;
    }
    recordReleaseResources(record);
    EVENTLOOP_FREE(record);

    assert(io->iocp_live_records > 0);
    io->iocp_live_records--;
    assert(io->loop->iocp_live_operations > 0);
    io->loop->iocp_live_operations--;
}

// Count the receives that still represent a live *logical* read for this io:
// records of the current generation, owned by the kernel or already dequeued but
// not yet dispatched, that were not canceled.
//
// Canceled records are deliberately excluded. A valid wioReadStop() immediately
// followed by wioReadStart() leaves the canceled kernel operation draining while
// its replacement is posted, and that replacement must not be suppressed.
static uint32_t countUncancelledReceives(const wio_t *io)
{
    uint32_t count = 0;
    for (const woverlapped_t *record = io->iocp_posted_head; record != NULL; record = record->posted_next)
    {
        if (record->kind == WOVERLAPPED_RECV && record->io_id == io->id &&
            record->cancel_reason == WOVERLAPPED_NOT_CANCELED)
        {
            count++;
        }
    }
    for (const woverlapped_t *record = io->iocp_completed_head; record != NULL; record = record->completed_next)
    {
        if (record->kind == WOVERLAPPED_RECV && record->io_id == io->id &&
            record->cancel_reason == WOVERLAPPED_NOT_CANCELED)
        {
            count++;
        }
    }
    return count;
}

// True when an uncancelled receive is already posted or waiting for dispatch.
// NOTE: a record popped off the completed queue and currently being dispatched is
// intentionally invisible here, so dispatch_recv must consult this *after* its
// user callback to learn whether the callback posted a replacement.
static bool hasUncancelledReceive(const wio_t *io)
{
    return countUncancelledReceives(io) > 0;
}

// -----------------------------------------------------------------------------
// Posting operations
// -----------------------------------------------------------------------------

// Post a receive. record == NULL allocates a fresh record; otherwise the record
// is reused (its live reference is retained). On immediate submission failure the
// record is retired locally because no completion packet will arrive.
static int post_recv(wio_t *io, woverlapped_t *record)
{
    const bool is_new = (record == NULL);
    if (is_new)
    {
        EVENTLOOP_ALLOC_SIZEOF(record);
        recordAttach(io, record, WOVERLAPPED_RECV);
    }

    memoryZero(&record->ovlp, sizeof(record->ovlp));
    record->error         = 0;
    record->bytes         = 0;
    record->cancel_reason = WOVERLAPPED_NOT_CANCELED;
    record->completed     = false;
    record->fd            = io->fd;

    if (record->sbuf != NULL)
    {
        bufferpoolReuseBuffer(io->loop->bufpool, record->sbuf);
        record->sbuf = NULL;
    }
    if (io->io_type == WIO_TYPE_UDP)
    {
        record->sbuf = bufferpoolGetLargeBuffer(io->loop->bufpool);
    }
    else if (io->io_type == WIO_TYPE_IP)
    {
        record->sbuf = bufferpoolGetSmallBuffer(io->loop->bufpool);
    }
    else
    {
        record->sbuf = bufferpoolGetLargeBuffer(io->loop->bufpool);
    }
    record->buf.len = sbufGetMaximumWriteableSize(record->sbuf);
    record->buf.buf = (CHAR *) sbufGetMutablePtr(record->sbuf);

    DWORD dwbytes = 0;
    DWORD flags   = 0;
    int   ret     = 0;

    recordMarkPosted(record);
    if (io->io_type == WIO_TYPE_TCP)
    {
        ret = WSARecv(io->fd, &record->buf, 1, &dwbytes, &flags, &record->ovlp, NULL);
    }
    else if (io->io_type == WIO_TYPE_UDP || io->io_type == WIO_TYPE_IP)
    {
        if (record->addr == NULL)
        {
            EVENTLOOP_ALLOC(record->addr, sizeof(struct sockaddr_in6));
        }
        // WSARecvFrom overwrites addrlen with the completed peer length. Restore
        // the full capacity before every receive (dual-stack IPv4-then-IPv6).
        record->addrlen = sizeof(struct sockaddr_in6);
        ret =
            WSARecvFrom(io->fd, &record->buf, 1, &dwbytes, &flags, record->addr, &record->addrlen, &record->ovlp, NULL);
    }
    else
    {
        WSASetLastError(WSAEINVAL);
        ret = -1;
    }

    if (ret != 0)
    {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING)
        {
            printError("WSARecv error: %d\n", err);
            recordUnpost(record);
            recordRetire(record);
            return err;
        }
    }
    // Exactly one uncancelled logical receive per wio_t: the one just posted.
    assert(countUncancelledReceives(io) == 1);
    return 0;
}

#if defined(WATERWALL_IOCP_TEST_HOOKS)
// Test-only AcceptEx fault injection. The unit test arms it after listener
// startup, so the initial slots are always real submissions, and each armed
// count makes exactly one later submission fail immediately with a
// representative transient error. Not compiled into production builds.
static uint32_t g_iocp_acceptex_forced_failures = 0;
static int      g_iocp_acceptex_forced_error    = WSAENOBUFS;

void wioIocpTestForceAcceptExFailures(uint32_t count, int error)
{
    g_iocp_acceptex_forced_failures = count;
    g_iocp_acceptex_forced_error    = (error != 0) ? error : WSAENOBUFS;
}

uint32_t wioIocpTestPendingAcceptExFailures(void)
{
    return g_iocp_acceptex_forced_failures;
}

static bool iocpTestConsumeAcceptExFailure(int *error)
{
    if (g_iocp_acceptex_forced_failures == 0)
    {
        return false;
    }
    g_iocp_acceptex_forced_failures--;
    *error = g_iocp_acceptex_forced_error;
    return true;
}
#endif

// Post an AcceptEx. record == NULL allocates a fresh record (with an output
// buffer sized for the listener family); otherwise the record is reused and its
// address buffer is retained. On immediate submission failure the record is
// retired locally.
static int post_acceptex(wio_t *listenio, woverlapped_t *record)
{
    const bool    is_new       = (record == NULL);
    int           accept_error = 0;
    int           connfd       = -1;
    LPFN_ACCEPTEX AcceptEx     = NULL;
    GUID          guidAcceptEx = WSAID_ACCEPTEX;
    DWORD         dwbytes      = 0;

    // Determine the listener family from its bound local address (Phase 5).
    int family = listenio->localaddr->sa_family;
    if (family != AF_INET && family != AF_INET6)
    {
        sockaddr_u local;
        socklen_t  local_len = sizeof(local);
        memoryZero(&local, sizeof(local));
        if (getsockname(listenio->fd, &local.sa, &local_len) == 0)
        {
            family = local.sa.sa_family;
        }
    }

    DWORD addr_region;
    if (family == AF_INET)
    {
        addr_region = (DWORD) (sizeof(struct sockaddr_in) + 16);
    }
    else if (family == AF_INET6)
    {
        addr_region = (DWORD) (sizeof(struct sockaddr_in6) + 16);
    }
    else
    {
        accept_error = WSAEAFNOSUPPORT;
        goto error;
    }
    DWORD out_buf_len = addr_region * 2;

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
    const SOCKET accepted = WSASocket(family, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (accepted == INVALID_SOCKET)
    {
        accept_error = WSAGetLastError();
        goto error;
    }
    connfd = socketToFd(accepted);
    if (connfd < 0)
    {
        accept_error = WSAGetLastError();
        goto error;
    }

    if (is_new)
    {
        EVENTLOOP_ALLOC_SIZEOF(record);
        recordAttach(listenio, record, WOVERLAPPED_ACCEPT);
        record->accept_family         = family;
        record->accept_address_length = addr_region;
        record->accept_buffer_length  = out_buf_len;
        EVENTLOOP_ALLOC(record->buf.buf, out_buf_len);
        record->buf.len = out_buf_len;
    }
    else
    {
        // Reuse must keep the same family so the retained buffer is valid.
        assert(record->accept_family == family);
        assert(record->accept_buffer_length == out_buf_len);
    }

    memoryZero(&record->ovlp, sizeof(record->ovlp));
    record->error         = 0;
    record->bytes         = 0;
    record->cancel_reason = WOVERLAPPED_NOT_CANCELED;
    record->completed     = false;
    record->fd            = connfd; // provisional accepted socket

    recordMarkPosted(record);
#if defined(WATERWALL_IOCP_TEST_HOOKS)
    int forced_error = 0;
    if (UNLIKELY(iocpTestConsumeAcceptExFailure(&forced_error)))
    {
        // Same unpost/retire path as a real immediate AcceptEx failure, without
        // having to exhaust real Windows socket resources in a unit test.
        printError("AcceptEx error (injected): %d\n", forced_error);
        recordUnpost(record);
        recordRetire(record); // closes connfd, frees buffer, drops live ref
        return forced_error;
    }
#endif
    if (AcceptEx(listenio->fd,
                 connfd,
                 record->buf.buf,
                 0,
                 record->accept_address_length,
                 record->accept_address_length,
                 &dwbytes,
                 &record->ovlp) != TRUE)
    {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING)
        {
            printError("AcceptEx error: %d\n", err);
            recordUnpost(record);
            recordRetire(record); // closes connfd, frees buffer, drops live ref
            return err;
        }
    }
    return 0;

error:
    if (connfd >= 0)
    {
        SAFE_CLOSESOCKET(connfd);
    }
    if (! is_new)
    {
        // Could not repost an existing record: no completion will arrive for it.
        recordRetire(record);
    }
    return accept_error;
}

// -----------------------------------------------------------------------------
// AcceptEx capacity replenishment
// -----------------------------------------------------------------------------

static void acceptRetryTimerCb(wtimer_t *timer);

// Drop any scheduled replenishment and reset its backoff. Idempotent, and safe
// to call from inside the retry callback (the callback clears its own pointer
// first, so this can never delete a timer the loop is about to free).
static void cancelAcceptExRetry(wio_t *io)
{
    if (io->iocp_accept_retry_timer != NULL)
    {
        wtimerDelete(io->iocp_accept_retry_timer);
        io->iocp_accept_retry_timer = NULL;
    }
    io->iocp_accept_retry_attempts = 0;
}

// Exponential backoff bounded by ACCEPTEX_RETRY_MAX_DELAY_MS.
static uint32_t acceptExRetryDelayMs(uint32_t attempts)
{
    uint32_t delay = ACCEPTEX_RETRY_MIN_DELAY_MS;
    for (uint32_t i = 0; i < attempts && delay < ACCEPTEX_RETRY_MAX_DELAY_MS; ++i)
    {
        delay *= 2;
    }
    return delay > (uint32_t) ACCEPTEX_RETRY_MAX_DELAY_MS ? (uint32_t) ACCEPTEX_RETRY_MAX_DELAY_MS : delay;
}

// Schedule one listener-level replenishment round. Idempotent: an already
// scheduled retry is kept so a burst of failures cannot stack timers.
static void scheduleAcceptExRetry(wio_t *io, int submission_error)
{
    if (submission_error != 0)
    {
        io->iocp_accept_last_error = submission_error;
    }
    if (io->iocp_accept_retry_timer != NULL)
    {
        return;
    }
    if (io->closed || io->destroy || ! io->accept || (io->events & WW_READ) == 0)
    {
        // Accept interest is gone: capacity no longer matters and a timer here
        // could outlive the listener.
        return;
    }

    wtimer_t *timer = wtimerAdd(io->loop, acceptRetryTimerCb, acceptExRetryDelayMs(io->iocp_accept_retry_attempts), 1);
    if (UNLIKELY(timer == NULL))
    {
        return;
    }
    // The generation stored alongside io lets the callback reject a pooled and
    // re-issued wio_t even in the (already guarded) case of a surviving timer.
    timer->privdata             = io;
    timer->userdata             = (void *) (uintptr_t) io->id;
    io->iocp_accept_retry_timer = timer;
}

static void acceptRetryTimerCb(wtimer_t *timer)
{
    wio_t *io = (wio_t *) timer->privdata;
    if (io == NULL)
    {
        return;
    }
    const uint32_t listener_id = (uint32_t) (uintptr_t) timer->userdata;

    // One-shot: the loop frees this timer once the callback returns, and
    // everything below may close io. Release the reference before either.
    io->iocp_accept_retry_timer = NULL;

    if (io->closed || io->destroy || io->id != listener_id || ! io->accept || (io->events & WW_READ) == 0)
    {
        io->iocp_accept_retry_attempts = 0;
        return;
    }

    int last_error = 0;
    while (io->iocp_accept_records < ACCEPTEX_NUM)
    {
        int post_error = post_acceptex(io, NULL);
        if (post_error != 0)
        {
            // Stop at the first failure: retrying in a tight loop would amplify
            // the very resource exhaustion that caused it.
            last_error = post_error;
            break;
        }
    }

    if (last_error == 0)
    {
        // Target capacity restored.
        io->iocp_accept_retry_attempts = 0;
        io->iocp_accept_last_error     = 0;
        return;
    }

    io->iocp_accept_last_error = last_error;
    io->iocp_accept_retry_attempts++;

    if (io->iocp_accept_records == 0 && io->iocp_accept_retry_attempts >= ACCEPTEX_RETRY_ZERO_SLOT_MAX)
    {
        // Persistent total failure: a listener with zero slots accepts nothing,
        // so surface it instead of leaving a zombie behind. All retry state is
        // cleared before the close, which may finalize io.
        const int fatal_error = io->iocp_accept_last_error;
        wloge("AcceptEx replenishment failed %d times with no accept slot left, closing listener (error %d)",
              ACCEPTEX_RETRY_ZERO_SLOT_MAX,
              fatal_error);
        io->iocp_accept_retry_attempts = 0;
        io->iocp_accept_last_error     = 0;
        io->error                      = fatal_error;
        wioClose(io);
        return;
    }

    scheduleAcceptExRetry(io, last_error);
}

// Single funnel for every dispatch_accept repost site. On immediate failure
// post_acceptex has already retired the dead record, so the listener is one slot
// short and a bounded replenishment round is scheduled instead of silently
// shrinking its capacity forever.
static void repostAcceptOrScheduleRetry(wio_t *io, woverlapped_t *record)
{
    if (io->closed || record->io_id != io->id || (io->events & WW_READ) == 0)
    {
        recordRetire(record);
        return;
    }

    int post_error = post_acceptex(io, record);
    if (post_error == 0)
    {
        io->iocp_accept_retry_attempts = 0;
        io->iocp_accept_last_error     = 0;
        return;
    }
    // record is dead here; post_acceptex retired it.
    scheduleAcceptExRetry(io, post_error);
}

static int post_send(wio_t *io, woverlapped_t *record)
{
    assert(record == io->iocp_send_active);
    assert(record->kind == WOVERLAPPED_SEND);
    assert(record->buf.len > 0);

    memoryZero(&record->ovlp, sizeof(record->ovlp));
    record->error         = 0;
    record->bytes         = 0;
    record->cancel_reason = WOVERLAPPED_NOT_CANCELED;
    record->completed     = false;

    DWORD dwbytes = 0;
    recordMarkPosted(record);
    int ret = WSASend(io->fd, &record->buf, 1, &dwbytes, 0, &record->ovlp, NULL);
    if (ret != 0)
    {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING)
        {
            printError("WSASend error: %d\n", err);
            recordUnpost(record);
            return err;
        }
    }
    return 0;
}

static int start_next_send(wio_t *io)
{
    if (io->iocp_send_active != NULL || write_queue_empty(&io->write_queue))
    {
        return 0;
    }

    sbuf_t *buf = *write_queue_front(&io->write_queue);
    write_queue_pop_front(&io->write_queue);

    woverlapped_t *record = NULL;
    EVENTLOOP_ALLOC_SIZEOF(record);
    recordAttach(io, record, WOVERLAPPED_SEND);
    record->fd      = io->fd;
    record->buf.len = sbufGetLength(buf);
    EVENTLOOP_ALLOC(record->send_buffer, record->buf.len);
    memoryCopy(record->send_buffer, sbufGetRawPtr(buf), record->buf.len);
    record->buf.buf = record->send_buffer;
    bufferpoolReuseBuffer(io->loop->bufpool, buf);

    io->iocp_send_active = record;
    int err              = post_send(io, record);
    if (UNLIKELY(err != 0))
    {
        // No completion will arrive after an immediate submission failure.
        recordRetire(record);
        return err;
    }
    return 0;
}

static int enqueue_send(wio_t *io, sbuf_t *buf)
{
    uint32_t len = sbufGetLength(buf);
    if (len > io->max_write_bufsize - min(io->write_bufsize, io->max_write_bufsize))
    {
        wloge("write bufsize > %u, close it!", io->max_write_bufsize);
        io->error = WERR_OVER_LIMIT;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return WERR_OVER_LIMIT;
    }
    if (io->write_queue.maxsize == 0)
    {
        write_queue_init(&io->write_queue, 4);
    }
    write_queue_push_back(&io->write_queue, &buf);
    io->write_bufsize += len;
    if (io->write_bufsize > WRITE_BUFSIZE_HIGH_WATER)
    {
        wlogw("write len=%u enqueue %u, bufsize=%u over high water %u",
              (unsigned int) len,
              (unsigned int) len,
              (unsigned int) io->write_bufsize,
              (unsigned int) WRITE_BUFSIZE_HIGH_WATER);
    }
    return 0;
}

// -----------------------------------------------------------------------------
// Completion dispatch (one record at a time, re-entrant-close safe)
// -----------------------------------------------------------------------------

static void dispatch_recv(wio_t *io, woverlapped_t *record)
{
    if (record->cancel_reason != WOVERLAPPED_NOT_CANCELED)
    {
        // Stop/close/shutdown: recycle the buffer, no callback, no repost, and do
        // not treat it as a socket failure.
        recordRetire(record);
        return;
    }

    const bool is_dgram = (io->io_type & WIO_TYPE_SOCK_DGRAM) != 0 || (io->io_type & WIO_TYPE_SOCK_RAW) != 0;
    if (record->error != 0 || (record->bytes == 0 && ! is_dgram))
    {
        // Real error or stream EOF.
        io->error = record->error;
        recordRetire(record); // recycles the still-attached sbuf
        wioClose(io);
        return;
    }

    // Detach the buffer: read_cb owns it, the record no longer points at it.
    sbuf_t *buf  = record->sbuf;
    record->sbuf = NULL;

    if (io->io_type == WIO_TYPE_UDP || io->io_type == WIO_TYPE_IP)
    {
        if (record->addr != NULL && record->addrlen > 0)
        {
            wioSetPeerAddr(io, record->addr, record->addrlen);
        }
    }

    if (io->read_cb != NULL)
    {
        sbufSetLength(buf, (uint32_t) record->bytes);
        io->last_read_hrtime = io->loop->cur_hrtime;
        // Common read path so WIO_READ_ONCE and related semantics still apply.
        wioHandleRead(io, buf);
        buf = NULL; // callback owns it now; never touch again
    }
    else
    {
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        buf = NULL;
    }

    // Repost only if still open, same generation, and read is still enabled.
    if (! io->closed && record->io_id == io->id && (io->events & WW_READ))
    {
        if (hasUncancelledReceive(io))
        {
            // The callback restarted reading (typically wioReadOnce from inside a
            // one-shot read callback) and already posted a replacement receive.
            // Reposting this completed record too would leave two uncancelled
            // WSARecv operations racing for the same stream. The successful
            // receive buffer was detached above, so retiring cannot recycle it.
            recordRetire(record);
            return;
        }
        int err = post_recv(io, record);
        if (UNLIKELY(err != 0))
        {
            // post_recv already retired the record on immediate failure.
            io->error = err;
            wioClose(io);
        }
    }
    else
    {
        recordRetire(record);
    }
}

static void dispatch_send(wio_t *io, woverlapped_t *record)
{
    if (record->cancel_reason != WOVERLAPPED_NOT_CANCELED)
    {
        recordRetire(record);
        return;
    }

    if (record->error != 0 || record->bytes == 0 || record->bytes > record->buf.len)
    {
        io->error = record->error != 0 ? record->error : WSAECONNRESET;
        recordRetire(record);
        wioClose(io);
        return;
    }

    record->buf.buf += record->bytes;
    record->buf.len -= record->bytes;
    assert(io->write_bufsize >= record->bytes);
    io->write_bufsize -= record->bytes;

    // Keep the sole active send record local through write_cb. A callback that
    // writes again appends behind it; a callback that frees io sees this record's
    // live reference and therefore defers pool reuse.
    if (io->write_cb != NULL)
    {
        io->last_write_hrtime = io->loop->cur_hrtime;
        io->write_cb(io); // may close io synchronously
    }

    if (io->closed || record->io_id != io->id || (io->events & WW_WRITE) == 0)
    {
        recordRetire(record);
        return;
    }

    if (record->buf.len > 0)
    {
        int err = post_send(io, record);
        if (UNLIKELY(err != 0))
        {
            io->error = err;
            recordRetire(record);
            wioClose(io);
        }
        return;
    }

    recordRetire(record);

    int err = start_next_send(io);
    if (UNLIKELY(err != 0))
    {
        io->error = err;
        wioClose(io);
        return;
    }
    // WW_WRITE is one-shot only after the serialized send stream is empty. A
    // callback may have enqueued the next write, so test both sources of work.
    if (io->iocp_send_active == NULL && write_queue_empty(&io->write_queue))
    {
        if (io->events & WW_WRITE)
        {
            wioDel(io, WW_WRITE);
        }
        if (io->close)
        {
            // A close deferred by wioClose() while payload was still queued.
            io->close = 0;
            wioClose(io);
            return;
        }
    }
}

static void dispatch_connect(wio_t *io, woverlapped_t *record)
{
    const bool canceled = (record->cancel_reason != WOVERLAPPED_NOT_CANCELED);
    const int  err      = record->error;

    // WW_WRITE is one-shot for connect too.
    io->connect = 0;
    if (! io->closed)
    {
        wioDel(io, WW_WRITE);
    }

    if (canceled)
    {
        recordRetire(record);
        return;
    }
    if (err != 0)
    {
        io->error = err;
        recordRetire(record);
        wioClose(io);
        return;
    }

    // Apply the connect context and resolve addresses before user code.
    setsockopt(io->fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
    socklen_t addrlen = sizeof(sockaddr_u);
    getsockname(io->fd, io->localaddr, &addrlen);
    addrlen = sizeof(sockaddr_u);
    getpeername(io->fd, io->peeraddr, &addrlen);

    wioDelConnectTimer(io);
    io->connected = 1;
    if (io->connect_cb != NULL)
    {
        io->connect_cb(io);
    }
    // Keep the operation reference through connect_cb. In particular, wioFree()
    // from the callback must defer returning io to its pool until the pending
    // dispatcher has also released its cursor.
    recordRetire(record);
}

static void dispatch_accept(wio_t *io, woverlapped_t *record)
{
    if (record->cancel_reason != WOVERLAPPED_NOT_CANCELED)
    {
        // Expected cleanup (listener stop/close/shutdown): close the provisional
        // accepted socket and retire without parsing addresses or reposting.
        recordRetire(record);
        return;
    }

    if (record->error != 0)
    {
        // Non-cancellation failure while the listener remains active: drop the
        // provisional socket and replenish the accept slot if still reading.
        SAFE_CLOSESOCKET(record->fd);
        record->fd = -1;
        repostAcceptOrScheduleRetry(io, record);
        return;
    }

    // SO_UPDATE_ACCEPT_CONTEXT takes a SOCKET, which is 8 bytes on Win64. Keeping
    // this as int would pass sizeof(int) == 4 as the option length. Widening here
    // (rather than at wio_t.fd) keeps the change local.
    const SOCKET              listenfd             = (SOCKET) io->fd;
    const int                 connfd               = record->fd;
    LPFN_GETACCEPTEXSOCKADDRS GetAcceptExSockaddrs = NULL;
    GUID                      guid                 = WSAID_GETACCEPTEXSOCKADDRS;
    DWORD                     dwbytes              = 0;
    struct sockaddr          *plocaladdr           = NULL;
    struct sockaddr          *ppeeraddr            = NULL;
    int                       localaddrlen         = 0;
    int                       peeraddrlen          = 0;

    bool parse_ok = (WSAIoctl(connfd,
                              SIO_GET_EXTENSION_FUNCTION_POINTER,
                              &guid,
                              sizeof(guid),
                              &GetAcceptExSockaddrs,
                              sizeof(GetAcceptExSockaddrs),
                              &dwbytes,
                              NULL,
                              NULL) == 0);
    if (parse_ok)
    {
        // Parse addresses with exactly the region length stored when posting.
        GetAcceptExSockaddrs(record->buf.buf,
                             0,
                             record->accept_address_length,
                             record->accept_address_length,
                             &plocaladdr,
                             &localaddrlen,
                             &ppeeraddr,
                             &peeraddrlen);
        if (setsockopt(connfd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, (const char *) &listenfd, sizeof(listenfd)) != 0)
        {
            parse_ok = false;
        }
    }

    if (! parse_ok)
    {
        SAFE_CLOSESOCKET(record->fd);
        record->fd = -1;
        repostAcceptOrScheduleRetry(io, record);
        return;
    }

    // Transfer the accepted socket to its own wio_t and immediately invalidate the
    // record's socket field so record cleanup cannot close a transferred socket.
    wio_t *connio = wioGet(io->loop, connfd);
    record->fd    = -1;

    if (connio == NULL || wioIsClosed(connio))
    {
        if (connio == NULL)
        {
            // No event io took ownership of the accepted socket.
            closesocket(connfd);
        }
        // A closed event io already released the socket; replenish the slot.
        repostAcceptOrScheduleRetry(io, record);
        return;
    }

    connio->userdata  = io->userdata;
    connio->accept_cb = io->accept_cb;
    if (localaddrlen > 0)
    {
        memoryCopy(connio->localaddr, plocaladdr, (size_t) localaddrlen);
    }
    if (peeraddrlen > 0)
    {
        memoryCopy(connio->peeraddr, ppeeraddr, (size_t) peeraddrlen);
    }

    if (io->accept_cb != NULL)
    {
        // A close of the listener inside accept_cb drains the other posted accept
        // records without callbacks; this record stays local and safe.
        io->accept_cb(connio);
    }

    // Repost only if the listener is still open, the generation matches, and
    // read/accept interest is still enabled.
    repostAcceptOrScheduleRetry(io, record);
}

// Drain and dispatch every completed record for an active io. The record is
// popped into a local variable (holding its live reference) before any user
// callback, so a re-entrant close/free cannot see or free it.
static void wioIocpDispatchCompleted(wio_t *io)
{
    for (;;)
    {
        woverlapped_t *record = recordPopCompleted(io);
        if (record == NULL)
        {
            break;
        }
        switch (record->kind)
        {
        case WOVERLAPPED_ACCEPT:
            dispatch_accept(io, record);
            break;
        case WOVERLAPPED_CONNECT:
            dispatch_connect(io, record);
            break;
        case WOVERLAPPED_RECV:
            dispatch_recv(io, record);
            break;
        case WOVERLAPPED_SEND:
            dispatch_send(io, record);
            break;
        default:
            recordRetire(record);
            break;
        }
    }
    wioIocpMaybeFinalize(io);
}

// io->cb installed by wioAdd; invoked from the pending queue for active io.
static void wio_handle_events(wio_t *io)
{
    assert(! io->iocp_pending_dispatch);
    io->iocp_pending_dispatch = 1;
    wioIocpDispatchCompleted(io);
}

// -----------------------------------------------------------------------------
// iocp.c <-> overlapio.c plumbing
// -----------------------------------------------------------------------------

void wioIocpOnDequeued(woverlapped_t *record, DWORD bytes, int error)
{
    wio_t *io = record->io;
    recordUnpost(record);
    record->bytes = bytes;
    record->error = error; // 0 on success; never leave a stale value
    recordPushCompleted(io, record);
}

void wioIocpRetireCompletedWithoutCallbacks(wio_t *io)
{
    for (;;)
    {
        woverlapped_t *record = recordPopCompleted(io);
        if (record == NULL)
        {
            break;
        }
        recordRetire(record);
    }
    wioIocpMaybeFinalize(io);
}

static bool recordMatchesEvents(const woverlapped_t *record, int event_mask)
{
    switch (record->kind)
    {
    case WOVERLAPPED_ACCEPT:
    case WOVERLAPPED_RECV:
        return (event_mask & WW_READ) != 0;
    case WOVERLAPPED_CONNECT:
    case WOVERLAPPED_SEND:
        return (event_mask & WW_WRITE) != 0;
    default:
        return false;
    }
}

void wioIocpCancel(wio_t *io, int event_mask, woverlapped_cancel_reason_e reason)
{
    const bool cancel_all = (event_mask & WW_READ) != 0 && (event_mask & WW_WRITE) != 0;

    if ((event_mask & WW_READ) != 0)
    {
        // Read/accept interest is being withdrawn (read stop, close,
        // release-no-close, loop shutdown). A scheduled AcceptEx replenishment
        // must not outlive it, or it would fire on a pooled wio_t.
        cancelAcceptExRetry(io);
    }

    for (woverlapped_t *record = io->iocp_posted_head; record != NULL; record = record->posted_next)
    {
        if (! recordMatchesEvents(record, event_mask))
        {
            continue;
        }
        // First reason wins: wioClose marks CLOSE before wioDel re-enters with STOP.
        if (record->cancel_reason == WOVERLAPPED_NOT_CANCELED)
        {
            record->cancel_reason = reason;
        }
        if (! cancel_all)
        {
            // Cancel exactly this operation so unrelated read/write/accept/connect
            // work on the same handle is not disturbed.
            CancelIoEx((HANDLE) (uintptr_t) io->fd, &record->ovlp);
        }
    }

    // A completion may already have left the kernel-owned list but still be
    // waiting behind timers in the generic pending queue. Stop/close must suppress
    // that callback just as reliably as cancellation of a posted operation.
    for (woverlapped_t *record = io->iocp_completed_head; record != NULL; record = record->completed_next)
    {
        if (recordMatchesEvents(record, event_mask) && record->cancel_reason == WOVERLAPPED_NOT_CANCELED)
        {
            record->cancel_reason = reason;
        }
    }

    if (cancel_all && io->iocp_posted_head != NULL)
    {
        // Close/shutdown: cancel everything outstanding on the handle at once.
        CancelIoEx((HANDLE) (uintptr_t) io->fd, NULL);
    }
}

bool wioIocpCanFinalize(wio_t *io)
{
    // A live AcceptEx retry timer still holds a pointer to io, so it counts as a
    // lifetime reference exactly like an outstanding record. Deferring is always
    // preferable to letting a timer reach pooled memory.
    return io->closed && io->iocp_completed_head == NULL && io->iocp_send_active == NULL &&
           io->iocp_posted_count == 0 && io->iocp_live_records == 0 && io->iocp_accept_retry_timer == NULL &&
           ! io->pending && ! io->iocp_pending_dispatch && ! io->iocp_close_in_progress;
}

void wioIocpFinalizeDeferred(wio_t *io)
{
    wioIocpMaybeFinalize(io);
}

// -----------------------------------------------------------------------------
// Public wio operations
// -----------------------------------------------------------------------------

int wioAccept(wio_t *io)
{
    io->accept    = 1;
    int add_error = wioAdd(io, wio_handle_events, WW_READ);
    if (UNLIKELY(add_error != 0))
    {
        io->accept = 0;
        wioClose(io);
        return add_error;
    }

    int posted_count = 0;
    int accept_error = 0;
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
    // A partially populated accept queue is usable; fail startup only when no
    // AcceptEx request could be posted at all.
    if (UNLIKELY(posted_count == 0))
    {
        io->accept = 0;
        io->error  = accept_error;
        wioClose(io);
        return accept_error;
    }
    if (UNLIKELY(posted_count < ACCEPTEX_NUM))
    {
        // Startup succeeded but under target. Restore the missing slots through
        // the same bounded backoff used for later repost failures.
        scheduleAcceptExRetry(io, accept_error);
    }
    return 0;
}

// Mirrors the normal backend's connect timeout (nio.c __connect_timeout_cb).
// Armed only after a successful ConnectEx submission, so an immediate submission
// failure never leaves a timer behind. wioClose() may finalize io, so this
// function must not touch io afterwards.
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

int wioConnect(wio_t *io)
{
    int connect_error = 0;

    // Family from the actual peer address (Phase 6).
    int family = io->peeraddr->sa_family;
    if (family != AF_INET && family != AF_INET6)
    {
        connect_error = WSAEAFNOSUPPORT;
        goto error;
    }

    // ConnectEx requires the socket to be bound. A caller may already have bound
    // it to a specific source address (TcpConnector source-ip, or the Windows
    // interface-name fallback), and Windows rejects a second bind() with
    // WSAEINVAL. That existing bind already satisfies the prerequisite.
    sockaddr_u bound;
    socklen_t  bound_len = sizeof(bound);
    if (getsockname(io->fd, &bound.sa, &bound_len) != 0)
    {
        // Not bound yet. A zeroed sockaddr already encodes the wildcard address
        // (INADDR_ANY / in6addr_any are all-zero) and port 0, so only the family
        // is set explicitly.
        sockaddr_u local;
        socklen_t  local_len;
        memoryZero(&local, sizeof(local));
        if (family == AF_INET)
        {
            local.sin.sin_family = AF_INET;
            local_len            = sizeof(struct sockaddr_in);
        }
        else
        {
            local.sin6.sin6_family = AF_INET6;
            local_len              = sizeof(struct sockaddr_in6);
        }
        if (bind(io->fd, &local.sa, local_len) < 0)
        {
            int bind_error = socketERRNO();
            // WSAEINVAL here means the socket was already bound after all;
            // anything else is a real failure.
            if (bind_error != WSAEINVAL)
            {
                connect_error = bind_error;
                printError("syscall return error , call: bind , value: %d\n", connect_error);
                goto error;
            }
        }
    }

    LPFN_CONNECTEX ConnectEx     = NULL;
    GUID           guidConnectEx = WSAID_CONNECTEX;
    DWORD          dwbytes       = 0;
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

    int add_error = wioAdd(io, wio_handle_events, WW_WRITE);
    if (UNLIKELY(add_error != 0))
    {
        connect_error = add_error < 0 ? -add_error : add_error;
        goto error;
    }

    woverlapped_t *record = NULL;
    EVENTLOOP_ALLOC_SIZEOF(record);
    recordAttach(io, record, WOVERLAPPED_CONNECT);
    record->fd = io->fd;

    recordMarkPosted(record);
    if (ConnectEx(io->fd, io->peeraddr, (int) SOCKADDR_LEN(io->peeraddr), NULL, 0, &dwbytes, &record->ovlp) != TRUE)
    {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING)
        {
            printError("ConnectEx error: %d\n", err);
            recordUnpost(record);
            recordRetire(record);
            connect_error = err;
            goto error;
        }
    }
    io->connectex = 1;
    io->connect   = 1;

    /*
     * Arm the public connect timeout only now: registration, record attachment
     * and the ConnectEx submission (including the normal ERROR_IO_PENDING) have
     * all succeeded, so exactly one completion is guaranteed to arrive and every
     * teardown path (dispatch_connect success, connect error, explicit close,
     * wioFree, loop shutdown) deletes the timer again.
     */
    int connect_timeout_ms = io->connect_timeout ? io->connect_timeout : WIO_DEFAULT_CONNECT_TIMEOUT;
    assert(io->connect_timer == NULL);
    if (UNLIKELY(io->connect_timer != NULL))
    {
        // Defensive: never stack two timers on one wio_t. wioDelConnectTimer also
        // clears io->connect_timeout, so the effective value is read above.
        wioDelConnectTimer(io);
    }
    io->connect_timer           = wtimerAdd(io->loop, __connect_timeout_cb, (uint32_t) connect_timeout_ms, 1);
    io->connect_timer->privdata = io;
    return 0;

error:
    io->error = connect_error;
    wioClose(io);
    return connect_error;
}

int wioRead(wio_t *io)
{
    // Restore read interest first so a restart re-enables the one-shot/stopped
    // read even when an uncancelled receive is still live.
    int add_error = wioAdd(io, wio_handle_events, WW_READ);
    if (UNLIKELY(add_error != 0))
    {
        wioClose(io);
        return add_error;
    }

    // Idempotent, like the readiness backend: repeated wioReadStart() calls (and
    // a restart issued from inside a read callback) must not create a second
    // uncancelled WSARecv.
    if (hasUncancelledReceive(io))
    {
        return 0;
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

int wioWriteDatagram(wio_t *io, sbuf_t *buf, const sockaddr_u *peer_addr)
{
    if (io->closed)
    {
        io->error = EBADF;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }
    if ((io->io_type & WIO_TYPE_SOCK_DGRAM) == 0 && (io->io_type & WIO_TYPE_SOCK_RAW) == 0)
    {
        io->error = EINVAL;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }
    // One-shot nonblocking send with an explicit destination. A datagram that
    // cannot be sent immediately is dropped and recycled; no overlapped retry is
    // created and io->peeraddr is not read or written.
    int len    = (int) sbufGetLength(buf);
    int nwrite = sendto(io->fd, (const char *) sbufGetRawPtr(buf), len, 0, &peer_addr->sa, SOCKADDR_LEN(peer_addr));
    if (nwrite < 0)
    {
        int err = socketERRNO();
        if (err == EAGAIN || err == EINTR || err == WSAENOBUFS)
        {
            // Transient pressure: drop without logging; the pressure path must not
            // amplify overload.
            bufferpoolReuseBuffer(io->loop->bufpool, buf);
            return 0;
        }
        io->error = err;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }
    bufferpoolReuseBuffer(io->loop->bufpool, buf);
    if (io->write_cb != NULL)
    {
        io->write_cb(io);
    }
    return nwrite;
}

int wioWrite(wio_t *io, sbuf_t *buf)
{
    if (io->closed)
    {
        io->error = EBADF;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }
    if ((io->io_type & WIO_TYPE_SOCK_DGRAM) || (io->io_type & WIO_TYPE_SOCK_RAW))
    {
        // Datagrams never enter the overlapped retry path; snapshot the default
        // peer so a later read cannot redirect this datagram.
        sockaddr_u peer_addr = *io->peeraddr_u;
        return wioWriteDatagram(io, buf, &peer_addr);
    }
    if (io->io_type != WIO_TYPE_TCP)
    {
        io->error = EINVAL;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        return -1;
    }

    int len = (int) sbufGetLength(buf);
    if (len == 0)
    {
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        wioClose(io);
        return 0;
    }

    // Once an overlapped send exists, every later TCP buffer joins the existing
    // stream queue. This prevents out-of-order concurrent WSASend records.
    if (io->iocp_send_active != NULL || ! write_queue_empty(&io->write_queue))
    {
        int add_error = wioAdd(io, wio_handle_events, WW_WRITE);
        if (UNLIKELY(add_error != 0))
        {
            io->error = add_error < 0 ? -add_error : add_error;
            bufferpoolReuseBuffer(io->loop->bufpool, buf);
            wioClose(io);
            return add_error;
        }
        if (UNLIKELY(enqueue_send(io, buf) != 0))
        {
            wioClose(io);
            return -1;
        }
        int send_error = start_next_send(io);
        if (UNLIKELY(send_error != 0))
        {
            io->error = send_error;
            wioClose(io);
            return -1;
        }
        return 0;
    }

    bool send_blocked = false;
    int  nwrite       = send(io->fd, sbufGetRawPtr(buf), len, 0);
    if (nwrite < 0)
    {
        int err = socketERRNO();
        if (err == EAGAIN || err == EINTR || err == WSAEWOULDBLOCK || err == WSAENOBUFS)
        {
            nwrite       = 0;
            send_blocked = true;
        }
        else
        {
            printError("write");
            io->error = err;
            bufferpoolReuseBuffer(io->loop->bufpool, buf);
            wioClose(io);
            return -1;
        }
    }
    if (nwrite == 0 && ! send_blocked)
    {
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        wioClose(io);
        return 0;
    }

    if (nwrite == len)
    {
        // Consume the buffer and update all io state before the callback. The
        // callback may wioFree(io), so the function returns without touching io.
        buffer_pool_t *pool   = io->loop->bufpool;
        wwrite_cb      cb     = io->write_cb;
        io->last_write_hrtime = io->loop->cur_hrtime;
        bufferpoolReuseBuffer(pool, buf);
        if (cb != NULL)
        {
            cb(io);
        }
        return nwrite;
    }

    if (nwrite > 0)
    {
        sbufShiftRight(buf, (uint32_t) nwrite);
    }

    int add_error = wioAdd(io, wio_handle_events, WW_WRITE);
    if (UNLIKELY(add_error != 0))
    {
        io->error = add_error < 0 ? -add_error : add_error;
        bufferpoolReuseBuffer(io->loop->bufpool, buf);
        wioClose(io);
        return add_error;
    }
    if (UNLIKELY(enqueue_send(io, buf) != 0))
    {
        wioClose(io);
        return -1;
    }
    int send_error = start_next_send(io);
    if (UNLIKELY(send_error != 0))
    {
        io->error = send_error;
        wioClose(io);
        return -1;
    }

    if (nwrite > 0)
    {
        // The active record holds io alive through a callback-driven wioFree().
        wwrite_cb cb          = io->write_cb;
        io->last_write_hrtime = io->loop->cur_hrtime;
        if (cb != NULL)
        {
            cb(io);
        }
    }
    return nwrite;
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

int wioClose(wio_t *io)
{
    if (io->closed)
    {
        // wioFree may begin deferred finalization after an earlier close.
        wioIocpFinalizeDeferred(io);
        return 0;
    }

    /*
     * Graceful close: an overlapped send in flight or buffers still queued behind
     * it are real payload. Cancelling now would truncate the stream (wioDone
     * recycles the queue), so mirror the nio backend and finish the close once the
     * serialized send stream drains. wioFree()/finalization must never defer.
     */
    if ((io->iocp_send_active != NULL || ! write_queue_empty(&io->write_queue)) && io->error == 0 && io->close == 0 &&
        io->destroy == 0 && ! io->iocp_deferred_finalize)
    {
        io->close = 1;
        wlogd("write_queue not empty, close later.");
        int timeout_ms            = io->close_timeout ? io->close_timeout : WIO_DEFAULT_CLOSE_TIMEOUT;
        io->close_timer           = wtimerAdd(io->loop, __close_timeout_cb, (uint32_t) timeout_ms, 1);
        io->close_timer->privdata = io;
        return 0;
    }

    io->iocp_close_in_progress = 1;
    io->closed                 = 1;

    // Mark closed before cancellation so completion handlers/callbacks cannot post
    // new work, then request cancellation of every outstanding operation. Posted
    // records and their buffers are NOT freed here; their completion packets still
    // arrive and retire them.
    wioIocpCancel(io, WW_RDWR, WOVERLAPPED_CANCEL_CLOSE);

    // Remove loop interest (also flips the io inactive). wioDel re-enters
    // wioIocpCancel with STOP, but the records are already CLOSE-marked so the
    // reason is preserved.
    wioDone(io);

    // Drop completions already sitting in the queue without user callbacks.
    wioIocpRetireCompletedWithoutCallbacks(io);

    /*
     * Same teardown as the nio backend (__close_cb): every timer holds
     * privdata == io and only wtimerDelete() removes it from the loop heap, so a
     * surviving timer would fire on a pooled/reused wio_t. Delete all six before
     * user code can free the object.
     *
     * The close-callback contract is preserved: user code runs before the socket
     * handle is closed, and iocp_close_in_progress keeps io out of the pool if
     * that callback calls wioFree().
     */
    wioDelConnectTimer(io);
    wioDelCloseTimer(io);
    wioDelReadTimer(io);
    wioDelWriteTimer(io);
    wioDelKeepaliveTimer(io);
    wioDelHeartBeatTimer(io);
    wioCloseCallBack(io);

    if (io->io_type & WIO_TYPE_SOCKET)
    {
        // Closing the handle also forces cancellation of anything still posted; the
        // aborted completions are dequeued and retired later.
        closesocket(io->fd);
    }

    /*
     * Release the close-stack lifetime reference last. Finalization may return io
     * to the pool, so this function must not access it after the call.
     */
    io->iocp_close_in_progress = 0;
    wioIocpFinalizeDeferred(io);
    return 0;
}

#else
typedef int ww_overlapio_dummy_t;
#endif
