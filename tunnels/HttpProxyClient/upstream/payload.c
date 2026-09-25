#include "structure.h"

bool hpcUpload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    hpc_tstate_t *ts = tunnelGetState(t);
    size_t        n  = sbufGetLength(b);
    if (! ts->connect)
    {
        if (ts->upload == kHpcBodyNone || (ts->upload == kHpcBodyFixed && n > ls->upload_remaining))
        {
            lineReuseBuffer(l, b);
            hpcClose(t, l);
            return false;
        }
        if (ts->upload == kHpcBodyFixed)
            ls->upload_remaining -= n;
        else
        {
            char prefix[kHpcRequiredPaddingLeft + 1];
            int  count = stringNPrintf(prefix, sizeof(prefix), "%x\r\n", (unsigned) n);
            assert(count > 0 && count <= kHpcRequiredPaddingLeft);
            if (sbufGetLeftCapacity(b) < (unsigned) count)
            {
                lineReuseBuffer(l, b);
                hpcClose(t, l);
                return false;
            }
            ls->suffix = hpcBuffer(l, 2);
            if (! ls->suffix)
            {
                lineReuseBuffer(l, b);
                hpcClose(t, l);
                return false;
            }
            memoryCopy(sbufGetMutablePtr(ls->suffix), "\r\n", 2);
            sbufSetLength(ls->suffix, 2);
            sbufShiftLeft(b, (uint32_t) count);
            memoryCopy(sbufGetMutablePtr(b), prefix, (size_t) count);
        }
    }
    ls->progress_at = hpcNow(l);
    if (! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, b))
        return false;
    if (ls->suffix)
    {
        sbuf_t *tail = ls->suffix;
        ls->suffix   = NULL;
        if (! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, tail))
            return false;
    }
    return true;
}
void httpproxyclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *b)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    hpc_tstate_t *ts = tunnelGetState(t);
    size_t        n  = sbufGetLength(b);
    if (ls->prev_finished || (! ts->connect && ls->accepted && ls->body.kind == kHpsBodyDone) || ! hpcAllowed(t, l) ||
        ! n)
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
    if (ls->init_busy || ls->up_busy || ! ls->header_sent || (ts->connect && ! ls->accepted) ||
        bufferqueueGetBufCount(&ls->pending[0]))
    {
        if (! hpcQueue(t, l, b, 0) || ! hpcPressure(t, l))
            return;
        hpcDrainUpload(t, l);
        return;
    }
    ls->up_busy = true;
    if (! hpcUpload(t, l, b))
        return;
    ls->up_busy = false;
    hpcDrainUpload(t, l);
}
