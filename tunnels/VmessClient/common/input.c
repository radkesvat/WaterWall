#include "internal.h"

static sbuf_t *receiveHead(vmessclient_lstate_t *ls)
{
    if (ls->receive_head == NULL)
        ls->receive_head = bufferqueuePopFrontReserved(&ls->pending_down, &ls->input_reservation);
    return ls->receive_head;
}

static void recycleEmptyHead(vmessclient_lstate_t *ls)
{
    if (ls->receive_head != NULL && sbufGetLength(ls->receive_head) == 0)
    {
        bufferbudgetReservationRelease(&ls->input_reservation);
        lineReuseBuffer(ls->line, ls->receive_head);
        ls->receive_head = NULL;
    }
}

/* Move logical-byte accounting from the active wire buffer into inline metadata
 * or the single incomplete record. Allocation and entry charges stay with owners. */
static void transferBytes(vmessclient_lstate_t *ls, uint32_t count, bool body)
{
    bufferbudgetReservationSetBytes(&ls->input_reservation, sbufGetLength(ls->receive_head));
    bool acquired = bufferbudgetTryAcquire(&ls->downstream_budget, (buffer_budget_cost_t) {.bytes = count});
    assert(acquired);
    discard acquired;
    if (body)
        ls->body_reservation.cost.bytes += count;
}

static bool gatherHeader(vmessclient_lstate_t *ls, uint16_t needed)
{
    assert(needed <= sizeof(ls->header));
    while (ls->header_filled < needed)
    {
        sbuf_t *head = receiveHead(ls);
        if (head == NULL)
            return false;
        uint32_t count = min(needed - ls->header_filled, sbufGetLength(head));
        sbufReadRangeToMemory(head, ls->header + ls->header_filled, count);
        transferBytes(ls, count, false);
        ls->header_filled += count;
        recycleEmptyHead(ls);
    }
    return true;
}

static void consumeHeader(vmessclient_lstate_t *ls)
{
    bufferbudgetRelease(&ls->downstream_budget, (buffer_budget_cost_t) {.bytes = ls->header_filled});
    ls->header_filled = 0;
}

/* Length is authenticated before storage for the bounded variable envelope is admitted. */
static int readResponse(vmessclient_lstate_t *ls)
{
    if (! gatherHeader(ls, 18))
        return 0;
    if (ls->response_length == 0 &&
        vmessResponseLengthOpen(ls->response_key, ls->response_iv, ls->header, &ls->response_length) != kWCryptoOk)
        return -1;
    if (! gatherHeader(ls, (uint16_t) (18 + ls->response_length + 16)))
        return 0;
    if (vmessResponseHeaderOpen(
            ls->response_key, ls->response_iv, ls->response_marker, ls->header + 18, ls->response_length + 16) !=
        kWCryptoOk)
        return -1;
    consumeHeader(ls);
    ls->response_complete = true;
    memorySecureZero(ls->response_key, sizeof(ls->response_key));
    memorySecureZero(ls->response_iv, sizeof(ls->response_iv));
    return 1;
}

static bool drainRecords(tunnel_t *t, line_t *l, line_t *application, vmessclient_lstate_t *ls)
{
    vmessclient_tstate_t *ts = tunnelGetState(t);
    while (vmessclientAssociationAlive(t, l, application))
    {
        if (ls->input_crypto.raw)
        {
            sbuf_t *out = receiveHead(ls);
            if (out == NULL)
                return true;
            ls->receive_head = NULL;
            bufferbudgetReservationRelease(&ls->input_reservation);
            atomicAddU64Explicit(&ts->stats.rx_application_bytes, sbufGetLength(out), memory_order_relaxed);
            tunnelPrevDownStreamPayload(t, application, out);
            continue;
        }
        if (! ls->input_crypto.pending)
        {
            uint16_t prefix = (uint16_t) vmessBodyLengthSize(&ls->input_crypto);
            if (! gatherHeader(ls, prefix))
                return true;
            if (vmessBodyLengthOpen(&ls->input_crypto, ls->header, prefix, &ls->body_length) != kWCryptoOk)
            {
                vmessclientSetReason(ls, kVmessClientReasonLengthFailure);
                goto malformed;
            }
            consumeHeader(ls);
            buffer_pool_t *pool = lineGetBufferPool(l);
            ls->body_buffer     = bufferpoolGetBestFit(pool, ls->body_length, bufferpoolGetLargeBufferPadding(pool));
            /* Reserve storage now; only bytes actually gathered count as retained input. */
            sbufSetLength(ls->body_buffer, 0);
            if (! bufferbudgetTryReserve(&ls->downstream_budget, ls->body_buffer, &ls->body_reservation))
            {
                vmessclientSetReason(ls, kVmessClientReasonRetainedInput);
                goto malformed;
            }
        }
        while (ls->body_filled < ls->body_length)
        {
            sbuf_t *head = receiveHead(ls);
            if (head == NULL)
                return true;
            uint32_t count = min(ls->body_length - ls->body_filled, sbufGetLength(head));
            sbufReadRangeToMemory(head, sbufGetMutablePtr(ls->body_buffer) + ls->body_filled, count);
            transferBytes(ls, count, true);
            ls->body_filled += count;
            recycleEmptyHead(ls);
        }
        sbuf_t *out              = ls->body_buffer;
        ls->body_buffer          = NULL;
        ls->body_filled          = 0;
        size_t           length  = 0;
        bool             eof     = false;
        const uint32_t   ordinal = ls->input_crypto.counter;
        wcrypto_status_t status  = vmessBodyOpen(&ls->input_crypto,
                                                sbufGetRawPtr(out),
                                                ls->body_length,
                                                sbufGetMutablePtr(out),
                                                ls->body_length,
                                                &length,
                                                &eof);
        bufferbudgetReservationRelease(&ls->body_reservation);
        if (status != kWCryptoOk)
        {
            lineReuseBuffer(l, out);
            vmessclientSetReason(ls, kVmessClientReasonBodyFailure);
            goto malformed;
        }
        atomicIncU64Relaxed(&ts->stats.rx_records);
        if (ls->input_crypto.security != VMESS_SECURITY_NONE && ordinal == UINT16_MAX &&
            ts->counter_policy == kVmessCounterWrap)
            atomicIncU64Relaxed(&ts->stats.rx_wraps);
        if (eof)
        {
            lineReuseBuffer(l, out);
            goto malformed;
        }
        sbufSetLength(out, (uint32_t) length);
        bool deliver = true;
        if (ts->packetaddr && ls->kind == kVmessClientLineKindUdpCarrier)
        {
            vmess_packet_addr_t source;
            size_t              envelope = 0;
            if (vmessPacketAddrDecode(sbufGetRawPtr(out), length, &source, &envelope) != kWCryptoOk)
            {
                lineReuseBuffer(l, out);
                vmessclientSetReason(ls, kVmessClientReasonMalformedPacketAddr);
                goto malformed;
            }
            if (source.address_type != ls->packet_target.address_type || source.port != ls->packet_target.port ||
                memoryCompare(source.address, ls->packet_target.address, source.address_type == 1 ? 4 : 16) != 0)
            {
                vmessclientRecordReason(t, kVmessClientReasonUnexpectedSource, true);
                lineReuseBuffer(l, out);
                deliver = false;
            }
            else
                sbufShiftRight(out, (uint32_t) envelope);
        }
        if (deliver)
        {
            atomicAddU64Explicit(&ts->stats.rx_application_bytes, sbufGetLength(out), memory_order_relaxed);
            tunnelPrevDownStreamPayload(t, application, out);
            if (! vmessclientAssociationAlive(t, l, application))
                return false;
        }
        if (ls->input_crypto.security != VMESS_SECURITY_NONE && ts->counter_policy == kVmessCounterStrict &&
            ls->input_crypto.counter > UINT16_MAX)
        {
            vmessclientSetReason(ls, kVmessClientReasonStrictExhaustion);
            goto malformed;
        }
    }
    return false;
malformed:
    vmessclientCloseLine(t, l, kVmessClientCloseInternal);
    return false;
}

void vmessclientReceive(tunnel_t *t, line_t *l)
{
    vmessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVmessClientPhaseClosed || ls->closing || ls->receiving)
        return;
    line_t *application = ls->kind == kVmessClientLineKindUdpCarrier ? ls->application_line : l;
    lineRef(l);
    if (application != l)
        lineRef(application);
    ls->receiving = true;
    bool ready    = true;
    if (! ls->response_complete)
    {
        int result = readResponse(ls);
        ready      = result == 1;
        if (result < 0)
        {
            vmessclientSetReason(ls, kVmessClientReasonMalformedHeader);
            vmessclientCloseLine(t, l, kVmessClientCloseInternal);
        }
    }
    if (ready && vmessclientAssociationAlive(t, l, application))
        discard drainRecords(t, l, application, ls);
    if (vmessclientAssociationAlive(t, l, application))
        ls->receiving = false;
    if (application != l)
        lineUnref(application);
    lineUnref(l);
}
