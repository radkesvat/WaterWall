#include "HttpCommon/receive.h"

void httpReceiveInit(http_receive_t *receive)
{
    *receive = (http_receive_t) {0};
    bufferqueueInitEmpty(&receive->pending);
    bufferbudgetInit(&receive->budget,
                     (buffer_budget_cost_t) {.bytes = kHttpReceiveNestedBytes, .charge = kHttpReceiveNestedCharge});
    const bool attached = bufferqueueTryAttachBudget(&receive->pending, &receive->budget);
    assert(attached);
    discard attached;
}

void httpReceiveDestroy(http_receive_t *receive, buffer_pool_t *pool)
{
    if (receive->active != NULL)
        bufferpoolReuseBuffer(pool, receive->active);
    receive->active = NULL;
    bufferbudgetReservationRelease(&receive->reservation);
    bufferqueueDestroy(&receive->pending);
    bufferbudgetAssertEmpty(&receive->budget);
    receive->draining = false;
}

http_receive_result_t httpReceiveAdmit(http_receive_t *receive, buffer_pool_t *pool, sbuf_t *buf)
{
    assert(! sbufIsSplice(buf));
    if (sbufGetLength(buf) == 0)
    {
        bufferpoolReuseBuffer(pool, buf);
        return kHttpReceiveEmpty;
    }
    if (receive->draining)
        return bufferqueueTryPushBack(&receive->pending, &buf) ? kHttpReceiveQueued : kHttpReceiveRejected;

    assert(receive->active == NULL && bufferqueueGetEntryCount(&receive->pending) == 0);
    receive->active   = buf;
    receive->draining = true;
    return kHttpReceiveDrain;
}

sbuf_t *httpReceiveNext(http_receive_t *receive, buffer_pool_t *pool)
{
    assert(receive->draining);
    if (receive->active == NULL)
        receive->active = bufferqueuePopFrontReserved(&receive->pending, &receive->reservation);
    if (receive->active == NULL)
    {
        receive->draining = false;
        return NULL;
    }

    sbuf_t *buf = receive->active;
    if (sbufGetLength(buf) <= kHttpReceiveSliceBytes)
    {
        receive->active = NULL;
        bufferbudgetReservationRelease(&receive->reservation);
        return buf;
    }

    sbuf_t *slice = bufferpoolGetBestFit(pool, kHttpReceiveSliceBytes, bufferpoolGetLargeBufferPadding(pool));
    sbufWriteLarge(slice, sbufGetRawPtr(buf), kHttpReceiveSliceBytes);
    sbufSetLength(slice, kHttpReceiveSliceBytes);
    sbufShiftRight(buf, kHttpReceiveSliceBytes);
    return slice;
}

bool httpReceiveSettle(buffer_stream_t *stream, size_t max_bytes)
{
    if (bufferstreamGetLength(stream) > max_bytes)
        return false;
    return bufferstreamSettleRetained(stream, kHttpReceiveStreamCharge);
}
