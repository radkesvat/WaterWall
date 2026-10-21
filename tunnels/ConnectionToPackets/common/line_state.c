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
    assert(ts->owned_lines != NULL && lineGetWID(l) < ts->netifs_count);
    ls->owned_next = ts->owned_lines[lineGetWID(l)];
    if (ls->owned_next != NULL)
        ls->owned_next->owned_prev = ls;
    ts->owned_lines[lineGetWID(l)] = ls;
}

void ctpLinestateDestroy(ctp_lstate_t *ls)
{
    line_t *l   = ls->line;
    wid_t   wid = lineGetWID(l);

    assert(currentThreadOwnsWorker(wid));
    ctp_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (ls->owned_prev != NULL)
        ls->owned_prev->owned_next = ls->owned_next;
    else
    {
        assert(ts->owned_lines[wid] == ls);
        ts->owned_lines[wid] = ls->owned_next;
    }
    if (ls->owned_next != NULL)
        ls->owned_next->owned_prev = ls->owned_prev;
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
