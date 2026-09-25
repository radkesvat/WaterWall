#include "structure.h"

static bool bodyRange(const hpc_lstate_t *ls, size_t n)
{
    return ! ls->carry_length && ! ls->body.reject_data &&
           (ls->body.kind == kHpsBodyEof ||
            ((ls->body.kind == kHpsBodyFixed || (ls->body.kind == kHpsBodyChunked && ls->body.chunk_phase == 1)) &&
             n <= ls->body.remaining));
}
static void advanceBody(hpc_lstate_t *ls, size_t n)
{
    if (ls->body.kind == kHpsBodyEof)
        return;
    ls->body.remaining -= n;
    if (! ls->body.remaining)
    {
        if (ls->body.kind == kHpsBodyFixed)
            ls->body.kind = kHpsBodyDone;
        else
            ls->body.chunk_phase = 2;
    }
}
static bool deliver(tunnel_t *t, line_t *l, sbuf_t *b)
{
    if (! lineCallWithRefWithBuf(l, tunnelPrevDownStreamPayload, t, b))
        return false;
    hpc_tstate_t *ts = tunnelGetState(t);
    hpc_lstate_t *ls = lineGetState(l, t);
    if (! ts->connect && ls->body.kind == kHpsBodyDone)
    {
        hpcClose(t, l);
        return false;
    }
    return true;
}
static void consume(hpc_lstate_t *ls, size_t n)
{
    sbufShiftRight(ls->active, (uint32_t) n);
    bufferbudgetReservationSetBytes(&ls->active_cost, sbufGetLength(ls->active));
}
static sbuf_t *detach(hpc_lstate_t *ls)
{
    sbuf_t *b  = ls->active;
    ls->active = NULL;
    bufferbudgetReservationRelease(&ls->active_cost);
    return b;
}
bool hpcResponse(tunnel_t *t, line_t *l, sbuf_t *b)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    hpc_tstate_t *ts = tunnelGetState(t);
    size_t        n  = sbufGetLength(b);
    if (! ls->header_sent)
    {
        lineReuseBuffer(l, b);
        hpcClose(t, l);
        return false;
    }
    if (ls->accepted && (ts->connect || bodyRange(ls, n)))
    {
        if (! ts->connect)
            advanceBody(ls, n);
        return deliver(t, l, b);
    }
    /* Only parsing inputs materialize. One transient complete input is bounded
     * by the delivery cap, independent of ordinary pool tier geometry. */
    if (sbufIsSplice(b))
    {
        sbuf_t *ordinary = hpcBuffer(l, n);
        if (! ordinary)
        {
            lineReuseBuffer(l, b);
            hpcClose(t, l);
            return false;
        }
        sbufSpliceReadToBuffer(b, ordinary, (uint32_t) n);
        lineReuseBuffer(l, b);
        b = ordinary;
    }
    assert(! ls->active);
    if (! bufferbudgetTryReserve(&ls->budgets[1], b, &ls->active_cost))
    {
        lineReuseBuffer(l, b);
        hpcClose(t, l);
        return false;
    }
    ls->active = b;
    while (sbufGetLength(ls->active))
    {
        if (! ls->accepted)
        {
            if (! ls->header_started)
            {
                ls->header_started = true;
                ls->header_at      = hpcNow(l);
            }
            if (ls->carry_length == ts->max_header)
            {
                hpcClose(t, l);
                return false;
            }
            ls->carry[ls->carry_length++] = *(const char *) sbufGetRawPtr(ls->active);
            consume(ls, 1);
            size_t length = ls->carry_length;
            if (! ls->status_line_done)
            {
                if (length > kHpsRequestLineLimit + 2)
                {
                    hpcClose(t, l);
                    return false;
                }
                ls->status_line_done = ls->carry[length - 1] == '\n';
            }
            if (length < 4 || memoryCompare(ls->carry + length - 4, "\r\n\r\n", 4))
            {
                if (length == ts->max_header)
                {
                    hpcClose(t, l);
                    return false;
                }
                continue;
            }
            ls->carry[length] = 0;
            ls->saved_header  = memoryAllocate(length + 1);
            if (! ls->saved_header)
            {
                hpcClose(t, l);
                return false;
            }
            memoryCopy(ls->saved_header, ls->carry, length + 1);
            hp_response_context_t context = ts->connect                           ? kHpResponseToConnect
                                            : ! stringCompare(ts->method, "HEAD") ? kHpResponseToHead
                                                                                  : kHpResponseOrdinary;
            unsigned              error   = hpParseResponse(ls->saved_header, length, context, &ls->response);
            ls->carry_length              = 0;
            ls->header_started = ls->status_line_done = false;
            if (error)
            {
                hpcClose(t, l);
                return false;
            }
            if (ls->response.status < 200)
            {
                memoryFree(ls->saved_header);
                ls->saved_header = NULL;
                ls->response     = (hps_header_t) {0};
                if (++ls->informational > kHpsInformationalLimit)
                {
                    hpcClose(t, l);
                    return false;
                }
                continue;
            }
            if (ls->response.status >= 300)
            {
                hpcClose(t, l);
                return false;
            }
            ls->accepted = true;
            ls->body     = ls->response.body;
            if (! ts->connect && ls->body.kind == kHpsBodyDone)
            {
                hpcClose(t, l);
                return false;
            }
            if (! hpcDrainUpload(t, l))
                return false;
            continue;
        }
        size_t available = sbufGetLength(ls->active);
        if (ts->connect || bodyRange(ls, available))
        {
            if (! ts->connect)
                advanceBody(ls, available);
            return deliver(t, l, detach(ls));
        }
        if (ls->body.kind == kHpsBodyDone)
        {
            hpcClose(t, l);
            return false;
        }
        bool data = ls->body.kind == kHpsBodyEof || ls->body.kind == kHpsBodyFixed ||
                    (ls->body.kind == kHpsBodyChunked && ls->body.chunk_phase == 1);
        size_t used = 0;
        bool   emit = false;
        int    result;
        if (data)
        {
            result = hpsBodyStep(&ls->body, sbufGetRawPtr(ls->active), available, true, &ls->response, &used, &emit);
            if (result <= 0 || ! used)
            {
                hpcClose(t, l);
                return false;
            }
            sbuf_t *out = hpcBuffer(l, used);
            if (! out)
            {
                hpcClose(t, l);
                return false;
            }
            memoryCopy(sbufGetMutablePtr(out), sbufGetRawPtr(ls->active), used);
            sbufSetLength(out, (uint32_t) used);
            consume(ls, used);
            if (! deliver(t, l, out))
                return false;
        }
        else
        {
            size_t limit = ls->body.chunk_phase == 3   ? kHpsTrailerLimit
                           : ls->body.chunk_phase == 2 ? 2
                                                       : kHpsChunkLineLimit;
            if (ls->carry_length == limit)
            {
                hpcClose(t, l);
                return false;
            }
            ls->carry[ls->carry_length++] = *(const char *) sbufGetRawPtr(ls->active);
            consume(ls, 1);
            size_t length = ls->carry_length;
            if (ls->carry[length - 1] != '\n' && length < limit)
                continue;
            result =
                hpsBodyStep(&ls->body, (const unsigned char *) ls->carry, length, true, &ls->response, &used, &emit);
            if (result <= 0 || used != length)
            {
                hpcClose(t, l);
                return false;
            }
            ls->carry_length = 0;
            if (ls->body.kind == kHpsBodyDone)
            {
                hpcClose(t, l);
                return false;
            }
        }
    }
    lineReuseBuffer(l, detach(ls));
    return true;
}
void httpproxyclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    size_t        n  = sbufGetLength(b);
    if (ls->prev_finished || ! hpcAllowed(t, l) || ! n)
    {
        lineReuseBuffer(l, b);
        return;
    }
    if (n > kHpcDeliveryLimit)
    {
        lineReuseBuffer(l, b);
        hpcClose(t, l);
        return;
    }
    ls->progress_at = hpcNow(l);
    if (! ls->accepted && ! ls->header_started)
    {
        ls->header_started = true;
        ls->header_at      = ls->progress_at;
    }
    if (ls->down_busy || bufferqueueGetBufCount(&ls->pending[1]))
    {
        if (! hpcQueue(t, l, b, 1))
            return;
        hpcDrainResponse(t, l);
        return;
    }
    ls->down_busy = true;
    if (! hpcResponse(t, l, b))
        return;
    ls->down_busy = false;
    if (! hpcDrainResponse(t, l))
        return;
    hpcDrainUpload(t, l);
}
