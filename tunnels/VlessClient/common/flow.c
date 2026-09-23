#include "structure.h"

bool vlessclientAssociationAlive(tunnel_t *t, line_t *next_line, line_t *prev_line)
{
    if (! lineIsAlive(next_line) || ! lineIsAlive(prev_line))
        return false;
    vlessclient_lstate_t *ls      = lineGetState(next_line, t);
    vlessclient_lstate_t *prev_ls = lineGetState(prev_line, t);
    return ls->phase != kVlessClientPhaseClosed && prev_ls->phase != kVlessClientPhaseClosed &&
           (next_line == prev_line || (ls->app_line == prev_line && prev_ls->carrier_line == next_line));
}

void vlessclientCancelFirstPayloadTimer(vlessclient_lstate_t *ls)
{
    if (ls->first_payload_timer != NULL)
    {
        wtimerDelete(ls->first_payload_timer);
        ls->first_payload_timer = NULL;
    }
    ls->first_payload_due = false;
}

void vlessclientSendDueRequest(tunnel_t *t, line_t *l)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVlessClientPhaseClosed || ls->request_sent || ! ls->first_payload_due || ls->next_paused ||
        ls->est_notifying || ! wloopNormalDispatchAllowed(getWorkerLoop(lineGetWID(l))))
        return;
    /* Encoding consumes no caller input and performs its sole callback last. */
    if (UNLIKELY(! vlessclientSendInitialRequest(t, l, ls, NULL)))
        vlessclientCloseLine(t, l, kVlessClientCloseInternal);
}

static void firstPayloadExpired(wtimer_t *timer)
{
    vlessclient_lstate_t *ls = weventGetUserdata(timer);
    assert(ls->first_payload_timer == timer);
    tunnel_t *t   = ls->tunnel;
    line_t   *l   = ls->line;
    uint64_t  now = getHRTimeUs();
    /* One-shot reclamation belongs to the dispatch loop, even if close reenters. */
    ls->first_payload_timer = NULL;
    if (now < ls->first_payload_deadline_us)
    {
        uint32_t remaining = (uint32_t) ((ls->first_payload_deadline_us - now + 999) / 1000);
        if (wtimerReset(timer, remaining))
            ls->first_payload_timer = timer;
        else
            vlessclientCloseLine(t, l, kVlessClientCloseInternal);
        return;
    }
    ls->first_payload_due = true;
    vlessclientSendDueRequest(t, l);
}

void vlessclientOnNextEstablished(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls)
{
    if (ls->phase == kVlessClientPhaseClosed || ls->next_established)
        return;
    line_t *app = ls->kind == kVlessClientLineKindUdpCarrier ? ls->app_line : l;
    lineRef(l);
    if (app != l)
        lineRef(app);
    ls->next_established = true;
    ls->phase            = kVlessClientPhaseEstablished;
    ls->est_notifying    = true;
    if (! ls->request_sent)
    {
        vlessclient_tstate_t *ts      = tunnelGetState(t);
        ls->first_payload_deadline_us = getHRTimeUs() + (uint64_t) ts->first_payload_timeout_ms * 1000;
    }
    tunnelPrevDownStreamEst(t, app);
    if (vlessclientAssociationAlive(t, l, app))
    {
        ls->est_notifying = false;
        if (! ls->request_sent)
        {
            uint64_t now = getHRTimeUs();
            if (now >= ls->first_payload_deadline_us)
            {
                ls->first_payload_due = true;
                vlessclientSendDueRequest(t, l);
            }
            else
            {
                uint32_t remaining      = (uint32_t) ((ls->first_payload_deadline_us - now + 999) / 1000);
                ls->first_payload_timer = wtimerAdd(getWorkerLoop(lineGetWID(l)), firstPayloadExpired, remaining, 1);
                if (ls->first_payload_timer != NULL)
                    weventSetUserData(ls->first_payload_timer, ls);
                else
                    vlessclientCloseLine(t, l, kVlessClientCloseInternal);
            }
        }
    }
    if (app != l)
        lineUnref(app);
    lineUnref(l);
}

void vlessclientSetPrevPaused(tunnel_t *t, line_t *l, bool paused)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVlessClientPhaseClosed)
        return;
    line_t               *next    = ls->kind == kVlessClientLineKindUdpApp ? ls->carrier_line : l;
    vlessclient_lstate_t *next_ls = lineGetState(next, t);
    if (next_ls->prev_paused == paused)
        return;
    next_ls->prev_paused = paused;
    if (paused)
        tunnelNextUpStreamPause(t, next);
    else
        tunnelNextUpStreamResume(t, next);
}

void vlessclientSetNextPaused(tunnel_t *t, line_t *l, bool paused)
{
    vlessclient_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kVlessClientPhaseClosed || ls->kind == kVlessClientLineKindUdpApp || ls->next_paused == paused)
        return;
    line_t *app     = ls->kind == kVlessClientLineKindUdpCarrier ? ls->app_line : l;
    ls->next_paused = paused;
    if (paused)
    {
        tunnelPrevDownStreamPause(t, app);
        return;
    }
    lineRef(l);
    if (app != l)
        lineRef(app);
    tunnelPrevDownStreamResume(t, app);
    if (vlessclientAssociationAlive(t, l, app))
        vlessclientSendDueRequest(t, l);
    if (app != l)
        lineUnref(app);
    lineUnref(l);
}
