#include "internal.h"

typedef struct vmessclient_close_context_s
{
    bool next_finished, prev_finished;
} vmessclient_close_context_t;

static void setLineProtocol(line_t *l, uint8_t protocol)
{
    addresscontextSetOnlyProtocol(lineGetDestinationAddressContext(l), protocol);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(l), protocol);
}

void vmessclientTunnelstateDestroy(vmessclient_tstate_t *ts)
{
    addresscontextReset(&ts->target_addr);
    memorySecureZero(&ts->key, sizeof(ts->key));
    memorySecureZero(ts->uuid, sizeof(ts->uuid));
    memoryZeroAligned32(ts, tunnelGetCorrectAlignedStateSize(sizeof(*ts)));
}

void vmessclientStartUdpCarrier(tunnel_t *t, line_t *l, vmessclient_lstate_t *ls)
{
    line_t               *carrier    = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(l));
    vmessclient_lstate_t *carrier_ls = lineGetState(carrier, t);
    vmessclientLinestateInitialize(carrier_ls, carrier);
    carrier_ls->tunnel           = t;
    carrier_ls->kind             = kVmessClientLineKindUdpCarrier;
    carrier_ls->application_line = l;
    carrier_ls->packet_target    = ls->packet_target;
    vmessclientCountLine(carrier_ls);
    addresscontextCopy(&carrier_ls->target_addr, &ls->target_addr);
    setLineProtocol(carrier, IP_PROTO_TCP);
    ls->carrier_line = carrier;
    tunnelNextUpStreamInit(t, carrier);
}

static sbuf_t *termination(line_t *l, vmessclient_lstate_t *ls)
{
    vmessclient_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (! ts->send_termination || ! ls->request_sent || ls->output_crypto.ended || ls->next_finished)
        return NULL;
    buffer_pool_t   *pool    = lineGetBufferPool(l);
    sbuf_t          *frame   = bufferpoolGetBestFit(pool, 18 + 16 + 63, bufferpoolGetLargeBufferPadding(pool));
    uint32_t         ordinal = ls->output_crypto.counter;
    size_t           length  = 0;
    wcrypto_status_t status  = vmessBodySeal(
        &ls->output_crypto, NULL, 0, true, sbufGetMutablePtr(frame), sbufGetMaximumWriteableSize(frame), &length);
    if (status != kWCryptoOk || length == 0)
    {
        lineReuseBuffer(l, frame);
        return NULL;
    }
    sbufSetLength(frame, (uint32_t) length);
    atomicAddU64Explicit(&ts->stats.tx_wire_bytes, length, memory_order_relaxed);
    if (! ls->output_crypto.raw)
        atomicIncU64Relaxed(&ts->stats.tx_records);
    if (ls->output_crypto.security != VMESS_SECURITY_NONE && ts->counter_policy == kVmessCounterWrap &&
        ordinal == UINT16_MAX)
        atomicIncU64Relaxed(&ts->stats.tx_wraps);
    return frame;
}

void vmessclientCloseLine(tunnel_t *t, line_t *l, vmessclient_close_origin_t origin)
{
    vmessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVmessClientPhaseClosed)
    {
        /* Record Finish during final output without reflecting it to its sender.
         * The outer frame has already released all protocol ownership. */
        if (ls->close_context != NULL)
        {
            vmessclient_close_context_t *context = ls->close_context;
            context->next_finished |= origin == kVmessClientCloseFromNext;
            context->prev_finished |= origin == kVmessClientCloseFromPrev;
            bool owned = ls->kind == kVmessClientLineKindUdpCarrier;
            memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
            if (owned)
                lineDestroy(l);
        }
        return;
    }
    bool    direct           = ls->kind == kVmessClientLineKindDirect;
    bool    from_application = ls->kind == kVmessClientLineKindUdpApplication;
    line_t *application      = direct || from_application ? l : ls->application_line;
    line_t *carrier          = direct ? l : (from_application ? ls->carrier_line : l);
    lineRef(application);
    if (carrier != application)
        lineRef(carrier);
    vmessclient_lstate_t *application_ls = lineGetState(application, t);
    vmessclient_lstate_t *carrier_ls     = lineGetState(carrier, t);
    application_ls->closing              = true;
    carrier_ls->closing                  = true;
    application_ls->prev_finished        = origin == kVmessClientCloseFromPrev && (direct || from_application);
    carrier_ls->next_finished            = origin == kVmessClientCloseFromNext && ! from_application;
    vmessclientSetReason(carrier_ls, kVmessClientReasonNormalClose);
    sbuf_t                     *final   = termination(carrier, carrier_ls);
    vmessclient_close_context_t context = {
        .next_finished = carrier_ls->next_finished,
        .prev_finished = application_ls->prev_finished,
    };
    application_ls->carrier_line = NULL;
    carrier_ls->application_line = NULL;
    vmessclientLinestateDestroy(application_ls);
    if (! direct)
        vmessclientLinestateDestroy(carrier_ls);
    /* The tombstone owns no protocol resource. A reentered owned-carrier
     * Finish clears it and marks the carrier logically dead before returning. */
    carrier_ls->closing       = true;
    carrier_ls->kind          = direct ? kVmessClientLineKindDirect : kVmessClientLineKindUdpCarrier;
    carrier_ls->close_context = &context;
    if (final != NULL)
        tunnelNextUpStreamPayload(t, carrier, final);
    if (lineIsAlive(carrier) && ! context.next_finished)
    {
        context.next_finished = true;
        tunnelNextUpStreamFinish(t, carrier);
    }
    if (lineIsAlive(carrier))
    {
        memoryZeroAligned32(carrier_ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*carrier_ls)));
        if (! direct)
            lineDestroy(carrier);
    }
    if (lineIsAlive(application) && ! context.prev_finished)
        tunnelPrevDownStreamFinish(t, application);
    if (carrier != application)
        lineUnref(carrier);
    lineUnref(application);
}
