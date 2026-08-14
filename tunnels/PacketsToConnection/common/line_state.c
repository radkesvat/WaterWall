#include "structure.h"

#include "loggers/network_logger.h"

/*
 * Reports whether the line is usable rather than publishing a queue that only
 * looks allocated. On failure the caller must not use the state at all: the line
 * reference this took is released here, and the partially created queue with it.
 *
 * Only TCP lines retain payloads, so a UDP flow allocates neither queue.
 */
bool ptcLinestateInitialize(ptc_lstate_t *ls, tunnel_t *t, line_t *l, ptc_line_kind_t kind, void *pcb)
{
    lineLock(l);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
    ls->tunnel = t;
    ls->line   = l;
    ls->kind   = (uint8_t) kind;

    if (kind == kPtcLineKindTcp)
    {
        ls->tcp_pcb   = pcb;
        ls->ack_queue = sbuf_ack_queue_t_init();

        if (! bufferqueueInit(&ls->pause_queue, kPtcRetainQueueCapacity) ||
            ! sbuf_ack_queue_t_reserve(&ls->ack_queue, kPtcRetainQueueCapacity))
        {
            bufferqueueDestroy(&ls->pause_queue);
            sbuf_ack_queue_t_drop(&ls->ack_queue);
            memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
            lineUnlock(l);
            return false;
        }
    }
    else if (kind == kPtcLineKindUdp)
    {
        ls->udp_pcb = pcb;
    }

    ptcOwnedLineRegister(ls);
    return true;
}

/*
 * Paused buffers are still referenced by their acknowledgement records, and they
 * occupy the matching suffix of that queue in the same order. Walking the two
 * together is single-pass; searching the record queue per buffer, as this used
 * to, made teardown quadratic in the number of retained payloads.
 */
static void ptcReleasePauseQueue(ptc_lstate_t *ls, buffer_pool_t *pool)
{
    size_t index = ptcFrontPauseAckIndexOf(ls);

    while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
    {
        sbuf_t     *buf = bufferqueuePopFront(&ls->pause_queue);
        sbuf_ack_t *ack = ptcPauseAckRecordAt(ls, index);

        assert(ack->buf == buf);
        ack->buf = NULL;
        bufferpoolReuseBuffer(pool, buf);
        ++index;
    }

    bufferqueueDestroy(&ls->pause_queue);
}

/*
 * Dropping the queue removes every remaining record at once, so the retained
 * byte counter is reconciled here rather than per record. It must reach exactly
 * zero: any residue means a record entered without being counted, or left
 * without being subtracted.
 */
static void ptcReleaseAckQueue(ptc_lstate_t *ls, buffer_pool_t *pool)
{
    c_foreach(i, sbuf_ack_queue_t, ls->ack_queue)
    {
        if ((*i.ref).buf != NULL)
        {
            bufferpoolReuseBuffer(pool, (*i.ref).buf);
        }
        assert(ls->pending_bytes >= (*i.ref).total);
        ls->pending_bytes = (ls->pending_bytes >= (*i.ref).total) ? (ls->pending_bytes - (*i.ref).total) : 0;
    }

    sbuf_ack_queue_t_drop(&ls->ack_queue);
    assert(ls->pending_bytes == 0);
    ls->pending_bytes = 0;
}

void ptcLinestateDestroy(ptc_lstate_t *ls)
{
    wid_t          wid  = lineGetWID(ls->line);
    line_t        *l    = ls->line;
    buffer_pool_t *pool = getWorkerBufferPool(wid);

    ptcCancelUdpIdleTimer(ls);
    ptcOwnedLineUnregister(ls);

    if (ls->kind == kPtcLineKindTcp)
    {
        ptcReleasePauseQueue(ls, pool);
        ptcReleaseAckQueue(ls, pool);
    }

#ifdef DEBUG
    LOCK_TCPIP_CORE();
    assert(ls->tcp_pcb == NULL);
    assert(ls->udp_pcb == NULL);
    assert(ls->route_ctx == NULL);
    UNLOCK_TCPIP_CORE();
#endif

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(ptc_lstate_t)));
    lineUnlock(l);
}
