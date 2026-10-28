#include "internal.h"

bool vlessclientAssociationAlive(tunnel_t *t, line_t *next_line, line_t *prev_line)
{
    /* A nested TCP exchange can retire our state while the line stays alive. */
    if (! lineIsAlive(next_line) || ! lineIsAlive(prev_line) || ! tunnelIsActiveForLine(t, next_line))
        return false;
    vlessclient_lstate_t *ls      = lineGetState(next_line, t);
    vlessclient_lstate_t *prev_ls = lineGetState(prev_line, t);
    return ls->phase != kVlessClientPhaseClosed && prev_ls->phase != kVlessClientPhaseClosed &&
           (next_line == prev_line || (ls->application_line == prev_line && prev_ls->carrier_line == next_line));
}

void vlessclientTryBypass(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls)
{
    if (ls->kind != kVlessClientLineKindDirect || ! ls->request_sent || ! ls->response_complete || ls->receiving)
        return;
    assert(ls->receive_head == NULL && ls->receive_bytes == 0 && ls->header_filled == 0);
    assert(bufferqueueGetBufCount(&ls->pending_down) == 0);
    vlessclientLinestateDestroy(ls);
    tunnelBypassLine(t, l);
}

void vlessclientSendDueRequest(tunnel_t *t, line_t *l)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVlessClientPhaseClosed || ls->request_sent || ! firstPayloadWindowIsDue(&ls->first_payload) ||
        ls->carrier_paused || ls->est_notifying || ! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(l))))
        return;
    /* Encoding consumes no caller input and performs its sole callback last. */
    if (UNLIKELY(! vlessclientSendInitialRequest(t, l, ls, NULL)))
        vlessclientCloseLine(t, l, kVlessClientCloseInternal);
}

static void firstPayloadWindowNotified(void *owner, first_payload_window_event_t event)
{
    vlessclient_lstate_t *ls = owner;
    if (event == kFirstPayloadWindowDue)
        vlessclientSendDueRequest(ls->tunnel, ls->line);
    else
    {
        assert(event == kFirstPayloadWindowRearmFailed);
        vlessclientCloseLine(ls->tunnel, ls->line, kVlessClientCloseInternal);
    }
}

void vlessclientOnNextEstablished(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls)
{
    assert(ls->phase != kVlessClientPhaseClosed);
    assert(ls->kind != kVlessClientLineKindUdpApplication);
    if (ls->phase == kVlessClientPhaseEstablished)
    {
        if (ls->kind == kVlessClientLineKindDirect)
            tunnelPrevDownStreamEst(t, l);
        return;
    }
    line_t *application = ls->kind == kVlessClientLineKindUdpCarrier ? ls->application_line : l;
    lineRef(l);
    if (application != l)
        lineRef(application);
    ls->phase            = kVlessClientPhaseEstablished;
    ls->est_notifying    = true;
    if (! ls->request_sent)
    {
        vlessclient_tstate_t *ts = tunnelGetState(t);
        firstPayloadWindowStart(&ls->first_payload, getWorkerLoop(lineGetWID(l)), ts->first_payload_timeout_ms);
    }
    tunnelPrevDownStreamEst(t, application);
    if (vlessclientAssociationAlive(t, l, application))
    {
        ls->est_notifying = false;
        if (! ls->request_sent)
        {
            switch (
                firstPayloadWindowArm(&ls->first_payload, getWorkerLoop(lineGetWID(l)), firstPayloadWindowNotified, ls))
            {
            case kFirstPayloadWindowArmDue:
                vlessclientSendDueRequest(t, l);
                break;
            case kFirstPayloadWindowArmFailed:
                vlessclientCloseLine(t, l, kVlessClientCloseInternal);
                break;
            case kFirstPayloadWindowArmed:
                break;
            }
        }
    }
    if (application != l)
        lineUnref(application);
    lineUnref(l);
}

void vlessclientSetNextPaused(tunnel_t *t, line_t *l, bool paused)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVlessClientPhaseClosed || ls->kind == kVlessClientLineKindUdpApplication)
        return;
    if (ls->kind == kVlessClientLineKindDirect)
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
    if (vlessclientAssociationAlive(t, l, application))
        vlessclientSendDueRequest(t, l);
    lineUnref(application);
    lineUnref(l);
}
