#include "internal.h"

bool trojanclientAssociationAlive(tunnel_t *t, line_t *next_line, line_t *prev_line)
{
    /* A nested TCP request can retire our state while the line remains alive. */
    if (! lineIsAlive(next_line) || ! lineIsAlive(prev_line) || ! tunnelIsActiveForLine(t, next_line))
        return false;
    trojanclient_lstate_t *ls      = lineGetState(next_line, t);
    trojanclient_lstate_t *prev_ls = lineGetState(prev_line, t);
    return ls->phase != kTrojanClientPhaseClosed && prev_ls->phase != kTrojanClientPhaseClosed &&
           (next_line == prev_line || (ls->application_line == prev_line && prev_ls->carrier_line == next_line));
}

void trojanclientCancelFirstPayloadTimer(trojanclient_lstate_t *ls)
{
    if (ls->first_payload_timer != NULL)
    {
        wtimerDelete(ls->first_payload_timer);
        ls->first_payload_timer = NULL;
    }
    ls->first_payload_due = false;
}

void trojanclientSendDueRequest(tunnel_t *t, line_t *l)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kTrojanClientPhaseClosed || ls->request_sent || ! ls->first_payload_due || ls->carrier_paused ||
        ls->est_notifying || ! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(l))))
        return;
    /* Encoding consumes no caller input and performs its sole callback last. */
    if (UNLIKELY(! trojanclientSendInitialRequest(t, l, ls, NULL)))
        trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
}

static void firstPayloadExpired(wtimer_t *timer)
{
    trojanclient_lstate_t *ls = weventGetUserdata(timer);
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
            trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
        return;
    }
    ls->first_payload_due = true;
    trojanclientSendDueRequest(t, l);
}

void trojanclientOnNextEstablished(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls)
{
    assert(ls->phase != kTrojanClientPhaseClosed);
    assert(ls->kind != kTrojanClientLineKindUdpApplication);
    if (ls->phase == kTrojanClientPhaseEstablished)
    {
        if (ls->kind == kTrojanClientLineKindDirect)
            tunnelPrevDownStreamEst(t, l);
        return;
    }
    line_t *application = ls->kind == kTrojanClientLineKindUdpCarrier ? ls->application_line : l;
    lineRef(l);
    if (application != l)
        lineRef(application);
    ls->phase            = kTrojanClientPhaseEstablished;
    ls->est_notifying    = true;
    if (! ls->request_sent)
    {
        trojanclient_tstate_t *ts     = tunnelGetState(t);
        ls->first_payload_deadline_us =
            wloopNowLoopRunTime(getWorkerLoop(lineGetWID(l))) + (uint64_t) ts->first_payload_timeout_ms * 1000;
    }
    tunnelPrevDownStreamEst(t, application);
    if (trojanclientAssociationAlive(t, l, application))
    {
        ls->est_notifying = false;
        if (! ls->request_sent)
        {
            uint64_t now = wloopNowLoopRunTime(getWorkerLoop(lineGetWID(l)));
            if (now >= ls->first_payload_deadline_us)
            {
                ls->first_payload_due = true;
                trojanclientSendDueRequest(t, l);
            }
            else
            {
                uint32_t remaining      = (uint32_t) ((ls->first_payload_deadline_us - now + 999) / 1000);
                ls->first_payload_timer = wtimerAdd(getWorkerLoop(lineGetWID(l)), firstPayloadExpired, remaining, 1);
                if (ls->first_payload_timer != NULL)
                    weventSetUserData(ls->first_payload_timer, ls);
                else
                    trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
            }
        }
    }
    if (application != l)
        lineUnref(application);
    lineUnref(l);
}

void trojanclientSetNextPaused(tunnel_t *t, line_t *l, bool paused)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kTrojanClientPhaseClosed || ls->kind == kTrojanClientLineKindUdpApplication)
        return;
    if (ls->kind == kTrojanClientLineKindDirect)
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
    if (trojanclientAssociationAlive(t, l, application))
        trojanclientSendDueRequest(t, l);
    lineUnref(application);
    lineUnref(l);
}
