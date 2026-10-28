#include "internal.h"

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
        uint32_t count = min(needed - ls->header_filled, sbufGetLength(head));
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
        assert(restored);
        if (! restored)
            abortProgramNow(1);
        ls->input_head = NULL;
    }
}

static bool drainRecords(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls)
{
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
        size_t prefix_length = vmessBodyLengthSize(&ls->input_crypto);
        if (! ls->input_crypto.pending)
        {
            if (! vmessserverGatherHeader(ls, (uint16_t) prefix_length))
                return true;
            if (vmessBodyLengthOpen(&ls->input_crypto, ls->header, prefix_length, &ls->body_length) != kWCryptoOk)
            {
                vmessserverReason(ls, kVmessServerReasonLengthAuth);
                goto malformed;
            }
            ls->input_bytes -= prefix_length;
            ls->header_filled   = 0;
            buffer_pool_t *pool = lineGetBufferPool(l);
            ls->body_buffer     = bufferpoolGetBestFit(pool, ls->body_length, bufferpoolGetLargeBufferPadding(pool));
            sbufSetLength(ls->body_buffer, ls->body_length);
            if (! bufferbudgetTryReserve(&ls->upstream_budget, ls->body_buffer, &ls->body_reservation))
            {
                vmessserverReason(ls, kVmessServerReasonAdmission);
                goto malformed;
            }
        }
        while (ls->body_filled < ls->body_length)
        {
            sbuf_t *head = receiveHead(ls);
            if (! head)
                return true;
            uint32_t count = min(ls->body_length - ls->body_filled, sbufGetLength(head));
            sbufReadRangeToMemory(head, sbufGetMutablePtr(ls->body_buffer) + ls->body_filled, count);
            bufferbudgetReservationSetBytes(&ls->input_reservation, sbufGetLength(head));
            ls->body_filled += count;
            ls->input_bytes -= count;
            recycleEmptyHead(ls);
        }
        sbuf_t *out                = ls->body_buffer;
        ls->body_buffer            = NULL;
        ls->body_filled            = 0;
        size_t           plaintext = 0;
        bool             eof       = false;
        wcrypto_status_t status    = vmessBodyOpen(&ls->input_crypto,
                                                sbufGetRawPtr(out),
                                                ls->body_length,
                                                sbufGetMutablePtr(out),
                                                ls->body_length,
                                                &plaintext,
                                                &eof);
        bufferbudgetReservationRelease(&ls->body_reservation);
        vmessserver_tstate_t *ts = tunnelGetState(t);
        if (status == kWCryptoOk)
        {
            atomicAddU64(&ts->stats.rx_records, 1);
            if (ls->input_crypto.security != VMESS_SECURITY_NONE && ls->input_crypto.counter == 0)
                atomicAddU64(&ts->stats.wrap_events, 1);
        }
        if (status != kWCryptoOk || eof)
        {
            vmessserverReason(ls, status == kWCryptoOk ? kVmessServerReasonNormal : kVmessServerReasonBodyAuth);
            lineReuseBuffer(l, out);
            goto malformed;
        }
        sbufSetLength(out, (uint32_t) plaintext);
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
