#include "internal.h"

#include "loggers/network_logger.h"

static sbuf_t *receiveHead(vmessserver_lstate_t *ls)
{
    if (ls->input_head == NULL)
        ls->input_head = bufferqueuePopFrontReserved(&ls->pending_up, &ls->input_reservation);
    return ls->input_head;
}

static void recycleEmptyHead(vmessserver_lstate_t *ls)
{
    if (ls->input_head != NULL && sbufGetLength(ls->input_head) == 0)
    {
        bufferbudgetReservationRelease(&ls->input_reservation);
        lineReuseBuffer(ls->line, ls->input_head);
        ls->input_head = NULL;
    }
}

bool vmessserverGatherHeader(vmessserver_lstate_t *ls, uint16_t needed)
{
    assert(needed <= sizeof(ls->header));
    while (ls->header_filled < needed)
    {
        sbuf_t *head = receiveHead(ls);
        if (head == NULL)
            return false;
        uint32_t count = (uint32_t) MIN_SIZE(needed - ls->header_filled, sbufGetLength(head));
        sbufReadRangeToMemory(head, ls->header + ls->header_filled, count);
        bufferbudgetReservationSetBytes(&ls->input_reservation, sbufGetLength(head));
        ls->header_filled += count;
        recycleEmptyHead(ls);
    }
    return true;
}

void vmessserverRetainActiveHead(vmessserver_lstate_t *ls)
{
    if (ls->input_head != NULL)
    {
        bool restored = bufferqueueTryPushFrontReserved(&ls->pending_up, &ls->input_head, &ls->input_reservation);
        if (! restored)
        {
            LOGF("VmessServer: failed to restore the reserved active input head");
            abortProgramNow(1);
        }
        ls->input_head = NULL;
    }
}

static bool drainRecords(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls)
{
    const vmess_record_input_t input = {
        .pending = &ls->pending_up, .head = &ls->input_head, .reservation = &ls->input_reservation};
    while (ls->input_bytes != 0)
    {
        if (ls->input_crypto.raw)
        {
            sbuf_t *out = receiveHead(ls);
            if (! out)
                return true;
            ls->input_head = NULL;
            ls->input_bytes -= sbufGetLength(out);
            bufferbudgetReservationRelease(&ls->input_reservation);
            if (! vmessserverDeliverDecoded(t, l, out))
                return false;
            continue;
        }
        vmess_record_result_t result = vmessRecordReaderRead(&ls->record_reader, &ls->input_crypto, &input);
        assert(result.consumed <= ls->input_bytes);
        ls->input_bytes -= result.consumed;
        switch (result.status)
        {
        case kVmessRecordNeedMore:
            return true;
        case kVmessRecordLengthError:
            vmessserverReason(ls, kVmessServerReasonLengthAuth);
            goto malformed;
        case kVmessRecordBodyError:
            vmessserverReason(ls, kVmessServerReasonBodyAuth);
            goto malformed;
        case kVmessRecordLimitError:
            vmessserverReason(ls, kVmessServerReasonAdmission);
            goto malformed;
        case kVmessRecordPayload:
        case kVmessRecordEof:
            break;
        }
        vmessserver_tstate_t *ts = tunnelGetState(t);
        atomicAddU64(&ts->stats.rx_records, 1);
        if (ls->input_crypto.security != VMESS_SECURITY_NONE && ls->input_crypto.counter == 0)
            atomicAddU64(&ts->stats.wrap_events, 1);
        if (result.status == kVmessRecordEof)
        {
            vmessserverReason(ls, kVmessServerReasonNormal);
            goto malformed;
        }
        sbuf_t *out = result.payload;
        if (! vmessserverDeliverDecoded(t, l, out))
            return false;
        if (ls->input_crypto.counter_policy == kVmessCounterStrict &&
            ls->input_crypto.security != VMESS_SECURITY_NONE && ls->input_crypto.counter > UINT16_MAX)
        {
            vmessserverReason(ls, kVmessServerReasonStrictExhaustion);
            atomicAddU64(&ts->stats.strict_exhaustion, 1);
            goto malformed;
        }
    }
    return true;
malformed:
    vmessserverCloseLineBidirectional(t, l);
    return false;
}

bool vmessserverDrainInput(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls)
{
    if (ls->phase == kVmessServerPhaseWaitInitial && ! vmessserverHandleInitialRequest(t, l, ls))
        return false;
    if (ls->crypto_ready && ! ls->branch_initializing)
        return drainRecords(t, l, ls);
    return true;
}

void vmessserverProcessInput(tunnel_t *t, line_t *l)
{
    vmessserver_lstate_t *ls = lineGetState(l, t);
    if (ls->input_dispatching || ls->phase == kVmessServerPhaseClosing)
        return;
    lineRef(l);
    ls->input_dispatching = true;
    bool ok               = vmessserverDrainInput(t, l, ls);
    if (ok && lineIsAlive(l))
    {
        ls = lineGetState(l, t);
        if (ls->tunnel == t)
        {
            ls->input_dispatching = false;
        }
    }
    lineUnref(l);
}
