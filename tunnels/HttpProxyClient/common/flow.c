#include "internal.h"

bool hpcQueue(tunnel_t *t, line_t *l, sbuf_t *b, unsigned direction)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (bufferqueueTryPushBack(&ls->pending[direction], &b))
        return true;
    lineReuseBuffer(l, b);
    hpcClose(t, l);
    return false;
}
static bool updatePressure(tunnel_t *t, line_t *l, bool repeat)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    hpc_tstate_t *ts = tunnelGetState(t);
    if (ls->prev_finished || (! ts->connect && ls->accepted && ls->body.kind == kHpsBodyDone) || ! hpcAllowed(t, l))
        return true;
    bool local = ! ls->header_sent || (ts->connect && ! ls->accepted) || ls->up_busy ||
                 bufferqueueGetEntryCount(&ls->pending[0]) != 0;
    bool paused = local || ls->next_paused;
    if (paused == ls->source_paused && (! repeat || local))
        return true;
    ls->source_paused = paused;
    return lineCallWithRef(l, paused ? tunnelPrevDownStreamPause : tunnelPrevDownStreamResume, t);
}
bool hpcPressure(tunnel_t *t, line_t *l)
{
    return updatePressure(t, l, false);
}
void hpcSetNextPaused(tunnel_t *t, line_t *l, bool paused)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->prev_finished)
        return;
    ls->next_paused = paused;
    discard updatePressure(t, l, true);
}
bool hpcSendHeader(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->init_busy || ls->up_busy || ls->header_sent || ls->prev_finished || ! hpcAllowed(t, l))
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
     * resumes on the existing owner-loop timer. */
    size_t count = bufferqueueGetEntryCount(&ls->pending[0]);
    ls->up_busy  = true;
    while (count-- && hpcAllowed(t, l))
    {
        sbuf_t *b = bufferqueuePopFront(&ls->pending[0]);
        assert(b != NULL);
        if (! hpcUpload(t, l, b))
            return false;
    }
    ls->up_busy = false;
    return hpcPressure(t, l);
}
bool hpcDrainResponse(tunnel_t *t, line_t *l)
{
    hpc_lstate_t *ls = lineGetState(l, t);
    if (ls->down_busy || ls->prev_finished || ! hpcAllowed(t, l))
        return true;
    size_t count  = bufferqueueGetEntryCount(&ls->pending[1]);
    ls->down_busy = true;
    while (count-- && hpcAllowed(t, l))
    {
        sbuf_t *b = bufferqueuePopFront(&ls->pending[1]);
        assert(b != NULL);
        if (! hpcResponse(t, l, b))
            return false;
    }
    ls->down_busy = false;
    return true;
}
