#include "structure.h"

#include "loggers/network_logger.h"

void ctpLinestateInitialize(ctp_lstate_t *ls, tunnel_t *t, line_t *l, ctp_line_kind_t kind)
{
    assert(kind == kCtpLineKindTcp || kind == kCtpLineKindUdp);

    lineRef(l);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
    ls->tunnel = t;
    ls->line   = l;
    ls->kind   = (uint8_t) kind;
    bufferqueueInitEmpty(&ls->pending_queue);

    if (kind == kCtpLineKindTcp)
    {
        ls->pending_queue = bufferqueueCreate(kCtpPendingQueueCapacity);
    }

    assert(currentThreadOwnsWorker(lineGetWID(l)));
    ctp_tstate_t *ts = tunnelGetState(t);
    assert(ts->active_lines != NULL && lineGetWID(l) < ts->netifs_count);
    ls->active_next = ts->active_lines[lineGetWID(l)];
    if (ls->active_next != NULL)
        ls->active_next->active_prev = ls;
    ts->active_lines[lineGetWID(l)] = ls;
}

void ctpLinestateDestroy(ctp_lstate_t *ls)
{
    line_t *l   = ls->line;
    wid_t   wid = lineGetWID(l);

    assert(currentThreadOwnsWorker(wid));
    ctp_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (ls->active_prev != NULL)
        ls->active_prev->active_next = ls->active_next;
    else
    {
        assert(ts->active_lines[wid] == ls);
        ts->active_lines[wid] = ls->active_next;
    }
    if (ls->active_next != NULL)
        ls->active_next->active_prev = ls->active_prev;
    ctpTerminalCancel(ls);

    /*
     * Every state release cancels the deadline before clearing the state, so
     * neither the timer nor its line reference can outlive the state it reads.
     */
    ctpCancelConnectDeadline(ls);

    bufferqueueDestroy(&ls->pending_queue);

#ifdef DEBUG
    /*
     * Every producer must already be detached: once tcp_arg()/udp_recv() were
     * cleared by the owner engine no lwIP callback can reach this state again,
     * which is what makes zeroing it here safe.
     */
    assert(ls->tcp_pcb == NULL);
    assert(ls->flow_registered == false);
#endif

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(ctp_lstate_t)));
    lineUnref(l);
}
