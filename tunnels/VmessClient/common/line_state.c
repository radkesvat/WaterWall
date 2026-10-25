#include "internal.h"

void vmessclientLinestateInitialize(vmessclient_lstate_t *ls, line_t *l)
{
    *ls = (vmessclient_lstate_t) {.line = l, .phase = kVmessClientPhaseIdle};
    bufferqueueInitEmpty(&ls->pending_up);
    bufferqueueInitEmpty(&ls->pending_down);
    buffer_budget_cost_t limits = {kVmessClientMaxOrderBytes, kVmessClientMaxOrderCharge, kVmessClientMaxOrderEntries};
    bufferbudgetInit(&ls->upstream_budget, limits);
    bufferbudgetInit(&ls->downstream_budget, limits);
    bool attached = bufferqueueTryAttachBudget(&ls->pending_up, &ls->upstream_budget) &&
                    bufferqueueTryAttachBudget(&ls->pending_down, &ls->downstream_budget);
    assert(attached);
    discard attached;
}

void vmessclientLinestateDestroy(vmessclient_lstate_t *ls)
{
    if (ls->stats_counted)
    {
        vmessclient_tstate_t *ts = tunnelGetState(ls->tunnel);
        atomicDecU64Relaxed(ls->kind == kVmessClientLineKindUdpCarrier ? &ts->stats.active_carriers
                                                                       : &ts->stats.active_applications);
    }
    vmessclientCancelFirstPayloadTimer(ls);
    addresscontextReset(&ls->target_addr);
    vmessBodyDestroy(&ls->output_crypto);
    vmessBodyDestroy(&ls->input_crypto);
    if (ls->transmit_head != NULL)
        lineReuseBuffer(ls->line, ls->transmit_head);
    if (ls->receive_head != NULL)
        lineReuseBuffer(ls->line, ls->receive_head);
    if (ls->body_buffer != NULL)
        lineReuseBuffer(ls->line, ls->body_buffer);
    bufferbudgetReservationRelease(&ls->transmit_reservation);
    bufferbudgetReservationRelease(&ls->input_reservation);
    bufferbudgetReservationRelease(&ls->body_reservation);
    bufferbudgetRelease(&ls->downstream_budget, (buffer_budget_cost_t) {.bytes = ls->header_filled});
    bufferqueueDestroy(&ls->pending_up);
    bufferqueueDestroy(&ls->pending_down);
    bufferbudgetAssertEmpty(&ls->upstream_budget);
    bufferbudgetAssertEmpty(&ls->downstream_budget);
    memorySecureZero(ls->response_key, sizeof(ls->response_key));
    memorySecureZero(ls->response_iv, sizeof(ls->response_iv));
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}

/* Retain the smallest ordinary pool tier when a short fragment arrived in a
 * much larger allocation. This is storage compaction, never a flow-control gate. */
sbuf_t *vmessclientCompactInput(line_t *l, sbuf_t *buf)
{
    buffer_pool_t    *pool    = lineGetBufferPool(l);
    uint32_t          length  = sbufGetLength(buf);
    uint16_t          padding = bufferpoolGetLargeBufferPadding(pool);
    buffer_pool_fit_t fit;
    if (bufferpoolQueryBestFit(pool, length, padding, &fit) && fit.allocation_charge < sbufGetAllocationCharge(buf))
    {
        sbuf_t *compact = bufferpoolGetBestFit(pool, length, padding);
        memoryCopy(sbufGetMutablePtr(compact), sbufGetRawPtr(buf), length);
        sbufSetLength(compact, length);
        lineReuseBuffer(l, buf);
        return compact;
    }
    return buf;
}

void vmessclientCountLine(vmessclient_lstate_t *ls)
{
    assert(! ls->stats_counted && ls->tunnel != NULL);
    vmessclient_tstate_t *ts = tunnelGetState(ls->tunnel);
    atomicIncU64Relaxed(ls->kind == kVmessClientLineKindUdpCarrier ? &ts->stats.active_carriers
                                                                   : &ts->stats.active_applications);
    ls->stats_counted = true;
}
