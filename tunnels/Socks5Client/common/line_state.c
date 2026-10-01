#include "internal.h"

#include "loggers/network_logger.h"

void socks5clientLinestateInitialize(socks5client_lstate_t *ls, tunnel_t *t, line_t *l, socks5client_line_kind_t kind)
{
    if (kind != kSocks5ClientLineKindDirect)
    {
        linePreferOrdinaryReadBoth(l);
    }
    *ls = (socks5client_lstate_t) {
        .tunnel    = t,
        .line      = l,
        .in_stream = (kind == kSocks5ClientLineKindDirect || kind == kSocks5ClientLineKindUdpControl)
                         ? bufferstreamCreate(lineGetBufferPool(l), 0)
                         : (buffer_stream_t) {.pool = lineGetBufferPool(l), .q = bs_doublequeue_t_init()},
        .protocol  = kSocks5ClientProtocolTcp,
        .phase     = kSocks5ClientPhaseIdle,
        .kind      = kind};
    bufferqueueInitEmpty(&ls->pending_up);
    bufferqueueInitEmpty(&ls->pending_down);
    bufferbudgetInit(&ls->pending_budget,
                     (buffer_budget_cost_t) {kSocks5ClientMaxPendingUpBytes, SIZE_MAX, kSocks5ClientMaxPendingBuffers});
    const bool attached = bufferqueueTryAttachBudget(&ls->pending_up, &ls->pending_budget);
    assert(attached);
    discard attached;
}

void socks5clientLinestateDestroy(socks5client_lstate_t *ls)
{
    addresscontextReset(&ls->target_addr);
    addresscontextReset(&ls->relay_addr);
    bufferstreamDestroy(&ls->in_stream);
    bufferqueueDestroy(&ls->pending_up);
    bufferqueueDestroy(&ls->pending_down);
    bufferbudgetAssertEmpty(&ls->pending_budget);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(socks5client_lstate_t)));
}
