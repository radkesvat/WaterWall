#include "internal.h"
#include "loggers/network_logger.h"

void vmessclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    vmessclient_tstate_t *ts     = tunnelGetState(t);
    vmessclient_lstate_t *ls     = lineGetState(l, t);
    size_t                length = sbufGetLength(buf);
    if (ls->phase == kVmessClientPhaseClosed || ls->closing || ls->kind == kVmessClientLineKindUdpCarrier ||
        (! length && (! ts->packetaddr || ls->kind != kVmessClientLineKindUdpApplication)))
    {
        lineReuseBuffer(l, buf);
        return;
    }
    line_t               *next    = ls->kind == kVmessClientLineKindUdpApplication ? ls->carrier_line : l;
    vmessclient_lstate_t *next_ls = lineGetState(next, t);
    if (ls->kind == kVmessClientLineKindUdpApplication)
    {
        /* Before bootstrap, use the same maximum-frame arithmetic as the codec. */
        vmess_body_ctx_t geometry = {.security = ts->security, .options = ts->options};
        size_t           envelope = ts->packetaddr ? vmessPacketAddrHeaderSize(&next_ls->packet_target) : 0;
        if (length > vmessBodyMaxPlaintext(next_ls->request_sent ? &next_ls->output_crypto : &geometry) - envelope)
        {
            vmessclientRecordReason(t, kVmessClientReasonUdpOversize, true);
            lineReuseBuffer(l, buf);
            return;
        }
    }
    assert(! sbufIsSplice(buf));
    if (ts->packetaddr && ls->kind == kVmessClientLineKindUdpApplication)
    {
        const size_t     envelope = vmessPacketAddrHeaderSize(&next_ls->packet_target);
        sbuf_t          *encoded  = bufferpoolGetBestFit(
            lineGetBufferPool(l), (length + envelope), bufferpoolGetLargeBufferPadding(lineGetBufferPool(l)));
        size_t           written  = 0;
        wcrypto_status_t status   = vmessPacketAddrEncode(
            &next_ls->packet_target, sbufGetMutablePtr(encoded), sbufGetWritableCapacity(encoded), &written);
        assert(status == kWCryptoOk && written == envelope);
        discard status;
        memoryCopy(sbufGetMutablePtr(encoded) + written, sbufGetRawPtr(buf), length);
        sbufSetLength(encoded, (written + length));
        lineReuseBuffer(l, buf);
        buf = encoded;
    }
    buf = vmessclientCompactInput(l, buf);
    if (! bufferqueueTryPushBack(&next_ls->pending_up, &buf))
    {
        const buffer_budget_cost_t usage           = bufferbudgetGetUsage(&next_ls->upstream_budget);
        const buffer_budget_cost_t limits          = bufferbudgetGetLimits(&next_ls->upstream_budget);
        const size_t               incoming_bytes  = sbufGetLength(buf);
        const size_t               incoming_charge = sbufGetQueueCharge(buf);
        LOGW("VmessClient: closing connection: upstream ordering queue refused: %s "
             "(retained_bytes=%zu, incoming_bytes=%zu, limit_bytes=%zu, retained_charge_bytes=%zu, "
             "incoming_charge_bytes=%zu, limit_charge_bytes=%zu)",
             incoming_bytes > limits.bytes - usage.bytes      ? "byte budget exceeded"
             : incoming_charge > limits.charge - usage.charge ? "storage charge budget exceeded"
                                                              : "queue admission failed",
             usage.bytes,
             incoming_bytes,
             limits.bytes,
             usage.charge,
             incoming_charge,
             limits.charge);
        lineReuseBuffer(l, buf);
        vmessclientSetReason(next_ls, kVmessClientReasonRetainedInput);
        vmessclientCloseLine(t, next, kVmessClientCloseInternal);
        return;
    }
    vmessclientTransmit(t, next);
}
