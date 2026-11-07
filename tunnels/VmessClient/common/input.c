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

/* Keep received response-header bytes charged while cached inline. */
static void transferBytes(vmessclient_lstate_t *ls, uint32_t count)
{
    bufferbudgetReservationSetBytes(&ls->input_reservation, sbufGetLength(ls->receive_head));
    bool acquired = bufferbudgetTryAcquire(&ls->downstream_budget, (buffer_budget_cost_t) {.bytes = count});
    assert(acquired);
    discard acquired;
}

static bool gatherHeader(vmessclient_lstate_t *ls, uint16_t needed)
{
    assert(needed <= sizeof(ls->header));
    while (ls->header_filled < needed)
    {
        sbuf_t *head = receiveHead(ls);
        if (head == NULL)
            return false;
        uint32_t count = (uint32_t) MIN_SIZE(needed - ls->header_filled, sbufGetLength(head));
        sbufReadRangeToMemory(head, ls->header + ls->header_filled, count);
        transferBytes(ls, count);
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
    vmessclient_tstate_t      *ts    = tunnelGetState(t);
    const vmess_record_input_t input = {
        .pending = &ls->pending_down, .head = &ls->receive_head, .reservation = &ls->input_reservation};
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
        const uint32_t        ordinal = ls->input_crypto.counter;
        vmess_record_result_t result  = vmessRecordReaderRead(&ls->record_reader, &ls->input_crypto, &input);
        switch (result.status)
        {
        case kVmessRecordNeedMore:
            return true;
        case kVmessRecordLengthError:
            vmessclientSetReason(ls, kVmessClientReasonLengthFailure);
            goto malformed;
        case kVmessRecordBodyError:
            vmessclientSetReason(ls, kVmessClientReasonBodyFailure);
            goto malformed;
        case kVmessRecordLimitError:
            vmessclientSetReason(ls, kVmessClientReasonRetainedInput);
            goto malformed;
        case kVmessRecordPayload:
        case kVmessRecordEof:
            break;
        }
        atomicIncU64Relaxed(&ts->stats.rx_records);
        if (ls->input_crypto.security != VMESS_SECURITY_NONE && ordinal == UINT16_MAX &&
            ts->counter_policy == kVmessCounterWrap)
            atomicIncU64Relaxed(&ts->stats.rx_wraps);
        if (result.status == kVmessRecordEof)
            goto malformed;
        sbuf_t *out     = result.payload;
        bool    deliver = true;
        if (ts->packetaddr && ls->kind == kVmessClientLineKindUdpCarrier)
        {
            vmess_packet_addr_t source;
            size_t              envelope = 0;
            if (vmessPacketAddrDecode(sbufGetRawPtr(out), sbufGetLength(out), &source, &envelope) != kWCryptoOk)
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
                sbufShiftRight(out, envelope);
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
