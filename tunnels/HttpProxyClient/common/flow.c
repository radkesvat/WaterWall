#include "structure.h"

bool hpcQueue(tunnel_t *t, line_t *l, sbuf_t *b, unsigned direction)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (bufferqueueTryPushBack(&ls->pending[direction], &b))
        return true;
    lineReuseBuffer(l, b);
    hpcClose(t, l);
    return false;
}
bool hpcPressure(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    hpc_tstate_t *ts = tunnelGetState(t);
    if (ls->prev_finished || (! ts->connect && ls->accepted && ls->body.kind == kHpsBodyDone) || ! hpcAllowed(t, l))
        return true;
    bool paused = ls->next_paused || ! ls->header_sent || (ts->connect && ! ls->accepted) ||
                  bufferqueueGetBufCount(&ls->pending[0]) != 0;
    if (paused == ls->source_paused)
        return true;
    ls->source_paused = paused;
    return lineCallWithRef(l, paused ? tunnelPrevDownStreamPause : tunnelPrevDownStreamResume, t);
}
bool hpcSendHeader(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->init_busy || ls->up_busy || ls->header_sent || ls->next_paused || ls->prev_finished || ! hpcAllowed(t, l))
        return true;
    sbuf_t *b = ls->request;
    assert(b != NULL);
    ls->request     = NULL;
    ls->header_sent = true;
    ls->connect_at = ls->progress_at = hpcNow(l);
    ls->up_busy                      = true;
    if (! lineCallWithRefWithBuf(l, tunnelNextUpStreamPayload, t, b))
        return false;
    ls->up_busy = false;
    return true;
}
bool hpcDrainUpload(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    hpc_tstate_t *ts = tunnelGetState(t);
    if ((! ts->connect && ls->accepted && ls->body.kind == kHpsBodyDone) || ls->up_busy || ls->init_busy ||
        ! ls->header_sent || (ts->connect && ! ls->accepted) || ls->prev_finished || ! hpcAllowed(t, l))
        return true;
    /* Bound this independent dispatch. Later reentry stays in the same FIFO and
     * resumes on permission or the existing owner-loop timer. */
    size_t count = bufferqueueGetBufCount(&ls->pending[0]);
    ls->up_busy  = true;
    while (count-- && ! ls->next_paused && hpcAllowed(t, l))
    {
        sbuf_t *b = bufferqueuePopFront(&ls->pending[0]);
        if (! b)
            break;
        if (! hpcUpload(t, l, b))
            return false;
    }
    ls->up_busy = false;
    return hpcPressure(t, l);
}
bool hpcDrainResponse(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->down_busy || ls->prev_paused || ls->prev_finished || ! hpcAllowed(t, l))
        return true;
    size_t count  = bufferqueueGetBufCount(&ls->pending[1]);
    ls->down_busy = true;
    while (count-- && ! ls->prev_paused && hpcAllowed(t, l))
    {
        sbuf_t *b = bufferqueuePopFront(&ls->pending[1]);
        if (! b)
            break;
        if (! hpcResponse(t, l, b))
            return false;
    }
    ls->down_busy = false;
    return true;
}
