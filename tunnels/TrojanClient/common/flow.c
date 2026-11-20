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

void trojanclientSendDueRequest(tunnel_t *t, line_t *l)
{
    trojanclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kTrojanClientPhaseClosed || ls->request_sent || ! firstPayloadWindowIsDue(&ls->first_payload) ||
        ls->carrier_paused || ! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(l))))
        return;
    /* Encoding consumes no caller input and performs its sole callback last. */
    if (UNLIKELY(! trojanclientSendInitialRequest(t, l, ls, NULL)))
        trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
}

static void firstPayloadWindowNotified(void *owner, first_payload_window_event_t event)
{
    trojanclient_lstate_t *ls = owner;
    if (event == kFirstPayloadWindowDue)
        trojanclientSendDueRequest(ls->tunnel, ls->line);
    else
    {
        assert(event == kFirstPayloadWindowRearmFailed);
        trojanclientCloseLine(ls->tunnel, ls->line, kTrojanClientCloseInternal);
    }
}

void trojanclientStartNext(tunnel_t *t, line_t *l, line_t *application)
{
    lineRef(l);
    if (application != l)
        lineRef(application);
    tunnelNextUpStreamInit(t, l);
    if (trojanclientAssociationAlive(t, l, application))
    {
        trojanclient_lstate_t *ls   = lineGetState(l, t);
        wloop_t               *loop = getWorkerLoop(lineGetWID(l));
        if (! ls->request_sent && wloopNormalDispatchAllowed(loop))
        {
            trojanclient_tstate_t *ts = tunnelGetState(t);
            firstPayloadWindowStart(&ls->first_payload, loop, ts->first_payload_timeout_ms);
            switch (firstPayloadWindowArm(&ls->first_payload, loop, firstPayloadWindowNotified, ls))
            {
            case kFirstPayloadWindowArmDue:
                trojanclientSendDueRequest(t, l);
                break;
            case kFirstPayloadWindowArmFailed:
                trojanclientCloseLine(t, l, kTrojanClientCloseInternal);
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

void trojanclientOnNextEstablished(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls)
{
    assert(ls->phase != kTrojanClientPhaseClosed);
    assert(ls->kind != kTrojanClientLineKindUdpApplication);
    if (ls->kind == kTrojanClientLineKindDirect)
    {
        ls->phase = kTrojanClientPhaseEstablished;
        tunnelPrevDownStreamEst(t, l);
    }
    else if (ls->phase != kTrojanClientPhaseEstablished)
    {
        ls->phase = kTrojanClientPhaseEstablished;
        tunnelPrevDownStreamEst(t, ls->application_line);
    }
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
