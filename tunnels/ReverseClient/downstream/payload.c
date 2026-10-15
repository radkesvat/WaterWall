#include "structure.h"

#include "loggers/network_logger.h"

static void queueActivationPayload(reverseclient_pair_t *pair, sbuf_t *buf)
{
    buffer_pool_t *pool   = lineGetBufferPool(pair->u);
    const uint32_t length = sbufGetLength(buf);
    if (length == 0)
    {
        bufferpoolReuseBuffer(pool, buf);
        return;
    }
    if ((uint64_t) pair->activation_reentry_bytes + length > kReverseClientPendingBytes ||
        pair->activation_reentry_buffers >= kReverseClientPendingBuffers ||
        ! bufferqueueTryPushBack(&pair->activation_pending, &buf))
    {
        bufferpoolReuseBuffer(pool, buf);
        reverseclientClosePair(pair, kReverseClientCloseInternal);
        return;
    }
    pair->activation_reentry_bytes += length;
    ++pair->activation_reentry_buffers;
}

static bool consumeActivation(reverseclient_pair_t *pair, sbuf_t *buf)
{
    if (pair->activation_header_length < kReverseActivationHeaderSize)
    {
        const uint32_t count =
            min(sbufGetLength(buf), (uint32_t) kReverseActivationHeaderSize - pair->activation_header_length);
        sbufReadRangeToMemory(buf, pair->activation_header + pair->activation_header_length, count);
        pair->activation_header_length += (uint8_t) count;
        if (pair->activation_header_length < kReverseActivationHeaderSize)
            return false;
        const uint32_t length = reverseActivationReadSize(pair->activation_header);
        if (length < kReverseActivationHeaderSize || length > kReverseActivationMaxSize)
        {
            LOGD("ReverseClient: invalid activation size, closing reverse connection");
            lineReuseBuffer(pair->u, buf);
            reverseclientClosePair(pair, kReverseClientCloseInternal);
            return false;
        }
        pair->activation_remaining = length - kReverseActivationHeaderSize;
    }
    uint8_t scratch[256];
    while (pair->activation_remaining != 0 && sbufGetLength(buf) != 0)
    {
        const uint32_t count = min(pair->activation_remaining, min(sbufGetLength(buf), (uint32_t) sizeof(scratch)));
        sbufReadRangeToMemory(buf, scratch, count);
        pair->activation_remaining -= count;
    }
    return pair->activation_remaining == 0;
}

void reverseclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    reverseclient_tstate_t *ts   = tunnelGetState(t);
    reverseclient_pair_t   *pair = ((reverseclient_lstate_t *) lineGetState(l, t))->pair;

    if (pair->phase == kReverseClientPairActive)
    {
        if (pair->activation_dispatching)
        {
            queueActivationPayload(pair, buf);
            return;
        }
        tunnelPrevDownStreamPayload(t, pair->d, buf);
        return;
    }

    assert(pair->phase == kReverseClientPairConnecting || pair->phase == kReverseClientPairUnused);
    assert(pair->idle_handle != NULL);

    /* Invalid input closes both owned lines. Keep the allocation present to
     * distinguish that terminal path from a still-incomplete prefix. */
    lineRef(l);
    const bool complete = consumeActivation(pair, buf);
    if (! lineIsAlive(l))
    {
        lineUnref(l);
        return;
    }
    lineUnref(l);
    if (! complete)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    const wid_t wid   = lineGetWID(pair->u);
    pair->idle_handle = NULL;
    if (! idletableRemoveIdleItemByHash(wid, ts->starved_connections, (hash_t) (uintptr_t) pair))
    {
        LOGF("ReverseClient: failed to remove an idle pair while activating it");
        abortProgramNow(1);
    }
    reverseclient_thread_box_t *box = &ts->threadlocal_pool[wid];
    if (pair->phase == kReverseClientPairConnecting)
    {
        assert(box->connecting_cons_count > 0);
        box->connecting_cons_count--;
    }
    else
    {
        assert(box->unused_cons_count > 0);
        box->unused_cons_count--;
    }
    pair->phase = kReverseClientPairActive;
    atomicIncRelaxed(&ts->reverse_cons);
    reverseclientInitiateConnectOnWorker(t, wid);

    pair->activation_dispatching = true;
    if (sbufGetLength(buf) == 0)
        lineReuseBuffer(l, buf);
    else if (! bufferbudgetTryReserve(&pair->activation_budget, buf, &pair->activation_initial))
    {
        lineReuseBuffer(l, buf);
        reverseclientClosePair(pair, kReverseClientCloseInternal);
        return;
    }
    else
        pair->activation_payload = buf;

    pair->downstream_init_sent = true;
    if (! lineCallWithRef(pair->d, tunnelPrevDownStreamInit, t))
        return;
    /* The transport can request Pause before this destination exists. Init
     * may supersede it; replay only the request that is still pending. */
    if (pair->pending_downstream_pause)
    {
        pair->pending_downstream_pause = false;
        if (! lineCallWithRef(pair->d, tunnelPrevDownStreamPause, t))
            return;
    }
    if (pair->activation_payload != NULL)
    {
        buf                      = pair->activation_payload;
        pair->activation_payload = NULL;
        bufferbudgetReservationRelease(&pair->activation_initial);
        if (! lineCallWithRefWithBuf(pair->d, tunnelPrevDownStreamPayload, t, buf))
            return;
    }
    while (bufferqueueGetBufCount(&pair->activation_pending) != 0)
    {
        buf = bufferqueuePopFront(&pair->activation_pending);
        if (! lineCallWithRefWithBuf(pair->d, tunnelPrevDownStreamPayload, t, buf))
            return;
    }
    pair->activation_dispatching     = false;
    pair->activation_reentry_bytes   = 0;
    pair->activation_reentry_buffers = 0;
}
