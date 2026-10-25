#include "internal.h"

bool vmessclientAssociationAlive(tunnel_t *t, line_t *next_line, line_t *prev_line)
{
    /* A nested TCP exchange can retire our state while the line stays alive. */
    if (! lineIsAlive(next_line) || ! lineIsAlive(prev_line) || ! tunnelIsActiveForLine(t, next_line))
        return false;
    vmessclient_lstate_t *ls      = lineGetState(next_line, t);
    vmessclient_lstate_t *prev_ls = lineGetState(prev_line, t);
    return ls->phase != kVmessClientPhaseClosed && prev_ls->phase != kVmessClientPhaseClosed &&
           (next_line == prev_line || (ls->application_line == prev_line && prev_ls->carrier_line == next_line));
}

void vmessclientCancelFirstPayloadTimer(vmessclient_lstate_t *ls)
{
    if (ls->first_payload_timer != NULL)
    {
        wtimerDelete(ls->first_payload_timer);
        ls->first_payload_timer = NULL;
    }
    ls->first_payload_due = false;
}

void vmessclientSendDueRequest(tunnel_t *t, line_t *l)
{
    vmessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVmessClientPhaseClosed || ls->closing || ls->request_sent || ! ls->first_payload_due ||
        (ls->kind == kVmessClientLineKindUdpCarrier && ls->carrier_paused) || ls->est_notifying ||
        ! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(l))))
        return;
    vmessclientTransmit(t, l);
}

static void firstPayloadExpired(wtimer_t *timer)
{
    vmessclient_lstate_t *ls = weventGetUserdata(timer);
    assert(ls->first_payload_timer == timer);
    tunnel_t *t   = ls->tunnel;
    line_t   *l   = ls->line;
    uint64_t  now = wloopNowLoopRunTime(weventGetLoop(timer));
    /* One-shot reclamation belongs to the dispatch loop, even if close reenters. */
    ls->first_payload_timer = NULL;
    if (now < ls->first_payload_deadline_us)
    {
        uint32_t remaining = (uint32_t) ((ls->first_payload_deadline_us - now + 999) / 1000);
        if (wtimerReset(timer, remaining))
            ls->first_payload_timer = timer;
        else
            vmessclientCloseLine(t, l, kVmessClientCloseInternal);
        return;
    }
    ls->first_payload_due = true;
    vmessclientSendDueRequest(t, l);
}

void vmessclientOnNextEstablished(tunnel_t *t, line_t *l, vmessclient_lstate_t *ls)
{
    assert(ls->phase != kVmessClientPhaseClosed);
    assert(ls->kind != kVmessClientLineKindUdpApplication);
    if (ls->phase == kVmessClientPhaseEstablished)
    {
        if (ls->kind == kVmessClientLineKindDirect)
            tunnelPrevDownStreamEst(t, l);
        return;
    }
    line_t *application = ls->kind == kVmessClientLineKindUdpCarrier ? ls->application_line : l;
    lineRef(l);
    if (application != l)
        lineRef(application);
    ls->phase         = kVmessClientPhaseEstablished;
    ls->est_notifying = true;
    if (! ls->request_sent)
    {
        vmessclient_tstate_t *ts = tunnelGetState(t);
        ls->first_payload_deadline_us =
            wloopNowLoopRunTime(getWorkerLoop(lineGetWID(l))) + (uint64_t) ts->first_payload_timeout_ms * 1000;
    }
    tunnelPrevDownStreamEst(t, application);
    if (vmessclientAssociationAlive(t, l, application))
    {
        ls->est_notifying = false;
        if (! ls->request_sent)
        {
            uint64_t now = wloopNowLoopRunTime(getWorkerLoop(lineGetWID(l)));
            if (now >= ls->first_payload_deadline_us)
            {
                ls->first_payload_due = true;
                vmessclientSendDueRequest(t, l);
            }
            else
            {
                uint32_t remaining      = (uint32_t) ((ls->first_payload_deadline_us - now + 999) / 1000);
                ls->first_payload_timer = wtimerAdd(getWorkerLoop(lineGetWID(l)), firstPayloadExpired, remaining, 1);
                if (ls->first_payload_timer != NULL)
                    weventSetUserData(ls->first_payload_timer, ls);
                else
                    vmessclientCloseLine(t, l, kVmessClientCloseInternal);
            }
        }
    }
    if (application != l)
        lineUnref(application);
    lineUnref(l);
}

void vmessclientSetNextPaused(tunnel_t *t, line_t *l, bool paused)
{
    vmessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVmessClientPhaseClosed || ls->kind == kVmessClientLineKindUdpApplication)
        return;
    if (ls->kind == kVmessClientLineKindDirect)
    {
        if (paused)
            tunnelPrevDownStreamPause(t, l);
        else
            tunnelPrevDownStreamResume(t, l);
        return;
    }
    if (ls->carrier_paused == paused)
        return;
    line_t *application = ls->application_line;
    ls->carrier_paused  = paused;
    if (paused)
    {
        tunnelPrevDownStreamPause(t, application);
        return;
    }
    lineRef(l);
    lineRef(application);
    tunnelPrevDownStreamResume(t, application);
    if (vmessclientAssociationAlive(t, l, application))
        vmessclientSendDueRequest(t, l);
    lineUnref(application);
    lineUnref(l);
}

/* Complete each accepted batch before later nested batches. Active input and its
 * reservation stay in line state so synchronous closure settles them exactly once. */
void vmessclientTransmit(tunnel_t *t, line_t *l)
{
    vmessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVmessClientPhaseClosed || ls->closing || ls->transmitting)
        return;
    line_t *application = ls->kind == kVmessClientLineKindUdpCarrier ? ls->application_line : l;
    lineRef(l);
    if (application != l)
        lineRef(application);
    ls->transmitting = true;
    while (vmessclientAssociationAlive(t, l, application))
    {
        if (ls->transmit_head == NULL)
            ls->transmit_head = bufferqueuePopFrontReserved(&ls->pending_up, &ls->transmit_reservation);
        bool header_only = ls->transmit_head == NULL;
        if (header_only && (ls->request_sent || ! ls->first_payload_due))
            break;
        size_t available = header_only ? 0 : sbufGetLength(ls->transmit_head);
        size_t take =
            ls->kind == kVmessClientLineKindUdpCarrier ? available : min(available, (size_t) kVmessClientTcpRecordSize);
        size_t         capacity = (ls->request_sent ? 0 : 374) + take + 18 + 16 + 63;
        buffer_pool_t *pool     = lineGetBufferPool(l);
        sbuf_t        *frame  = bufferpoolGetBestFit(pool, (uint32_t) capacity, bufferpoolGetLargeBufferPadding(pool));
        size_t         prefix = 0, written = 0;
        if (! ls->request_sent && ! vmessclientCommitRequest(ls, sbufGetMutablePtr(frame), capacity, &prefix))
        {
            lineReuseBuffer(l, frame);
            vmessclientSetReason(ls, kVmessClientReasonProviderFailure);
            vmessclientCloseLine(t, l, kVmessClientCloseInternal);
            break;
        }
        vmessclient_tstate_t *ts      = tunnelGetState(t);
        const uint32_t        ordinal = ls->output_crypto.counter;
        wcrypto_status_t      status  = kWCryptoOk;
        if (! header_only)
            status = vmessBodySeal(&ls->output_crypto,
                                   sbufGetRawPtr(ls->transmit_head),
                                   take,
                                   false,
                                   sbufGetMutablePtr(frame) + prefix,
                                   capacity - prefix,
                                   &written);
        if (status != kWCryptoOk)
        {
            lineReuseBuffer(l, frame);
            vmessclientSetReason(ls,
                                 ls->output_crypto.security != VMESS_SECURITY_NONE &&
                                         ts->counter_policy == kVmessCounterStrict && ordinal >= UINT16_MAX
                                     ? kVmessClientReasonStrictExhaustion
                                     : kVmessClientReasonProviderFailure);
            vmessclientCloseLine(t, l, kVmessClientCloseInternal);
            break;
        }
        if (! header_only)
        {
            size_t envelope = ts->packetaddr && ls->kind == kVmessClientLineKindUdpCarrier
                                  ? vmessPacketAddrHeaderSize(&ls->packet_target)
                                  : 0;
            atomicAddU64Explicit(&ts->stats.tx_application_bytes, take - envelope, memory_order_relaxed);
            if (! ls->output_crypto.raw)
                atomicIncU64Relaxed(&ts->stats.tx_records);
            if (ls->output_crypto.security != VMESS_SECURITY_NONE && ordinal == UINT16_MAX &&
                ts->counter_policy == kVmessCounterWrap)
                atomicIncU64Relaxed(&ts->stats.tx_wraps);
        }
        if (! header_only)
        {
            sbufShiftRight(ls->transmit_head, (uint32_t) take);
            bufferbudgetReservationSetBytes(&ls->transmit_reservation, sbufGetLength(ls->transmit_head));
            if (sbufGetLength(ls->transmit_head) == 0)
            {
                lineReuseBuffer(l, ls->transmit_head);
                ls->transmit_head = NULL;
                bufferbudgetReservationRelease(&ls->transmit_reservation);
            }
        }
        sbufSetLength(frame, (uint32_t) (prefix + written));
        atomicAddU64Explicit(&ts->stats.tx_wire_bytes, prefix + written, memory_order_relaxed);
        /* Request marker and both cipher contexts are published before this callback. */
        tunnelNextUpStreamPayload(t, l, frame);
    }
    if (vmessclientAssociationAlive(t, l, application))
        ls->transmitting = false;
    if (application != l)
        lineUnref(application);
    lineUnref(l);
}
