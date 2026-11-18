#pragma once

#include "wevent.h"

/* Internal non-owning task transport for event and worker plumbing. */
bool wloopPostEvent(wloop_t *loop, wevent_t *ev);
/* Cleanup roots accepted here are drained before the worker publishes Quiesced. */
bool wloopPostControlEvent(wloop_t *loop, wevent_t *ev);

/* Deferred socket operations resolve their original descriptor slot and WIO ID on dispatch. */
wevent_t wioMakeDeferredEvent(const wio_t *io, wevent_cb cb);
wio_t   *wioResolveDeferredEvent(const wevent_t *ev);

bool wloopNormalAdmissionBegin(wloop_t *loop);
void wloopNormalAdmissionEnd(wloop_t *loop);
/* The wake transport is control infrastructure and remains admissible while normal work closes. */
bool wloopIOIsControl(const wio_t *io);
int  wioAddAlreadyAdmitted(wio_t *io, wio_cb cb, int events);

typedef void (*wloop_callback_root_cb)(void *context);

bool wloopInvokeNormalCallback(wloop_t *loop, wloop_callback_root_cb cb, void *context);
void wloopInvokeControlCallback(wloop_t *loop, wloop_callback_root_cb cb, void *context);
bool wloopInvokeWriteCallback(wio_t *io, wwrite_cb cb);

static inline sbuf_t *wioGetTcpReadBuffer(wio_t *io)
{
    assert(io->io_type == WIO_TYPE_TCP);
    buffer_pool_t *pool = io->loop->bufpool;
    if (io->splice_enabled)
        return bufferpoolGetLargeBuffer(pool);
    // A WIO may carry a threshold from a larger pool after a loop transfer.
    const uint32_t limit = bufferpoolGetLargeBufferSize(pool);
    return bufferpoolGetBestFit(pool, min(io->tcp_read_min_payload, limit), bufferpoolGetLargeBufferPadding(pool));
}

/* Call after a successful receive, before any callback can close/reuse the WIO
 * or start the next read. Capacity is the payload length offered to the OS. */
static inline void wioUpdateTcpReadCapacity(wio_t *io, uint32_t received, uint32_t capacity)
{
    assert(io->io_type == WIO_TYPE_TCP);
    assert(capacity > 0 && received <= capacity);
    if (! io->splice_enabled && received == capacity)
        io->tcp_read_min_payload = capacity < bufferpoolGetLargeBufferSize(io->loop->bufpool) ? capacity + 1 : capacity;
}

#ifdef WW_EVENT_MEMORY_TEST_SEAM
/* Reproduce the exact due one-shot state after heap removal and before pending
 * dispatch, so raw-loop destruction can verify its reclamation route. */
void wtimerTestMakePendingOneShot(wtimer_t *timer);
#endif
