#include "structure.h"

#include "loggers/network_logger.h"

/*
 * Reports whether the line is usable rather than publishing a queue that only
 * looks allocated. On failure the caller must not use the state at all: the line
 * reference taken here is released again, exactly once.
 */
bool ctpLinestateInitialize(ctp_lstate_t *ls, tunnel_t *t, line_t *l, ctp_line_kind_t kind)
{
    assert(kind == kCtpLineKindTcp || kind == kCtpLineKindUdp);

    lineLock(l);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
    ls->tunnel = t;
    ls->line   = l;
    ls->kind   = (uint8_t) kind;
    bufferqueueInitEmpty(&ls->pending_queue);

    if (kind == kCtpLineKindTcp && ! bufferqueueInit(&ls->pending_queue, kCtpPendingQueueCapacity))
    {
        bufferqueueDestroy(&ls->pending_queue);
        memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
        lineUnlock(l);
        return false;
    }

    return true;
}

void ctpLinestateDestroy(ctp_lstate_t *ls)
{
    line_t *l   = ls->line;
    wid_t   wid = lineGetWID(l);

    ctpTerminalCancel(ls);

    /*
     * Unconditional, and deliberately the first thing here: every path that
     * releases this state goes through it, so this is the one place that
     * guarantees the deadline timer and the line reference it holds cannot
     * outlive the state the timer would read.
     */
    ctpCancelConnectDeadline(ls);

    while (bufferqueueGetBufCount(&ls->pending_queue) > 0)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), bufferqueuePopFront(&ls->pending_queue));
    }
    bufferqueueDestroy(&ls->pending_queue);

#ifdef DEBUG
    /*
     * Every producer must already be detached: once tcp_arg()/udp_recv() were
     * cleared under the core lock no lwIP callback can reach this state again,
     * which is what makes zeroing it here safe.
     */
    LOCK_TCPIP_CORE();
    assert(ls->tcp_pcb == NULL);
    assert(ls->flow_registered == false);
    UNLOCK_TCPIP_CORE();
#endif

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(ctp_lstate_t)));
    lineUnlock(l);
}
