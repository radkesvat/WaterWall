#include "structure.h"

#include "loggers/network_logger.h"

/* Only TCP lines retain payloads; UDP initializes no queues. */
void ptcLinestateInitialize(ptc_lstate_t *ls, tunnel_t *t, line_t *l, ptc_line_kind_t kind, void *pcb)
{
    lineRef(l);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
    ls->tunnel = t;
    ls->line   = l;
    ls->engine = wwLwipEngineCurrent();
    assert(ls->engine != NULL && currentThreadIsEventWorkerWID(lineGetWID(l)));
    ls->kind   = (uint8_t) kind;

    if (kind == kPtcLineKindTcp)
    {
        ls->tcp_pcb   = pcb;
        ls->ack_queue = sbuf_ack_queue_t_init();

        ls->pause_queue     = bufferqueueCreate(kPtcRetainQueueCapacity);
        const bool reserved = sbuf_ack_queue_t_reserve(&ls->ack_queue, kPtcRetainQueueCapacity);
        assert(reserved);
        discard reserved;
    }
    else if (kind == kPtcLineKindUdp)
    {
        ls->udp_pcb = pcb;
    }

    ptcOwnedLineRegister(ls);
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
        if (ls->rx_delivery != NULL)
        {
            bufferpoolReuseBuffer(pool, ls->rx_delivery);
            ls->rx_delivery = NULL;
        }
        ptcReleasePauseQueue(ls, pool);
        ptcReleaseAckQueue(ls, pool);
    }

#ifdef DEBUG
    assert(ls->tcp_pcb == NULL);
    assert(ls->udp_pcb == NULL);
    assert(ls->route_ctx == NULL);
#endif

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(ptc_lstate_t)));
    lineUnref(l);
}
