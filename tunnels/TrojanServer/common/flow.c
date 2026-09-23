#include "structure.h"

/* Step results select the pump's next action, independently of success or failure. */
typedef enum pump_step_result_e
{
    kPumpStepFallThrough, // No callback ran; the next step may inspect state.
    kPumpStepRecheck      // Restart liveness and permission checks before another step.
} pump_step_result_t;

bool trojanserverIsUdp(const trojanserver_lstate_t *ls)
{
    return ls->line_kind == kTrojanServerLineKindClient &&
           (ls->phase == kTrojanServerPhaseUdpWaitPacket || ls->phase == kTrojanServerPhaseUdpEstablished);
}

/* Steps share the pump's retained client line and reentrancy guard. Callbacks,
 * parser progress and close require Recheck; incomplete parsing and successful
 * fallback scheduling can FallThrough. */
static pump_step_result_t notifyPausedProducers(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, bool udp,
                                                bool next_paused)
{
    if (next_paused && ! ls->prev_pause_sent)
    {
        ls->prev_pause_sent = true;
        tunnelPrevDownStreamPause(t, l);
        return kPumpStepRecheck;
    }
    if (! ls->prev_paused)
        return kPumpStepFallThrough;
    if (udp)
        return trojanserverNotifyRemotePermission(t, l, ls) ? kPumpStepRecheck : kPumpStepFallThrough;
    if (ls->next_initialized && ! ls->next_pause_sent)
    {
        ls->next_pause_sent = true;
        if (ls->branch == kTrojanServerBranchFallback)
            tunnelUpStreamPause(trojanserverSelectedUpstream(t, ls), l);
        else
            tunnelNextUpStreamPause(t, l);
        return kPumpStepRecheck;
    }
    return kPumpStepFallThrough;
}

/* Parser/reentry input belongs to this dispatch, so Pause does not stop it.
 * Delayed fallback remains an independent producer with its own permission gate. */
static pump_step_result_t processPendingInput(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, bool udp)
{
    if (udp)
    {
        /* Decode may return false after closing; do not fall through to other steps. */
        if (trojanserverDecodeUdp(t, l, ls) || ! lineIsAlive(l))
            return kPumpStepRecheck;
        return kPumpStepFallThrough;
    }
    if (ls->branch == kTrojanServerBranchTrojan && bufferqueueGetBufCount(&ls->pending_up) != 0)
    {
        tunnelNextUpStreamPayload(t, l, bufferqueuePopFront(&ls->pending_up));
        return kPumpStepRecheck;
    }
    if (ls->branch == kTrojanServerBranchFallback)
    {
        trojanserver_tstate_t *ts = tunnelGetState(t);
        if (ts->fallback_intentional_delay_ms == 0 && ls->fallback_pending_up != NULL &&
            bufferqueueGetBufCount(ls->fallback_pending_up) != 0)
        {
            /* Only branch Init/reentry input can remain at zero delay. */
            sbuf_t *buf = bufferqueuePopFront(ls->fallback_pending_up);
            tunnelUpStreamPayload(trojanserverSelectedUpstream(t, ls), l, buf);
            return kPumpStepRecheck;
        }
        if (UNLIKELY(! trojanserverScheduleFallbackPayloadDrain(t, l, ls)))
        {
            trojanserverCloseLineBidirectional(t, l);
            return kPumpStepRecheck;
        }
    }
    /* A scheduled fallback task runs later; continue with Resume now. */
    return kPumpStepFallThrough;
}

static pump_step_result_t notifyResumedProducers(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, bool udp,
                                                 bool next_paused)
{
    if (! next_paused && ls->prev_pause_sent)
    {
        ls->prev_pause_sent = false;
        tunnelPrevDownStreamResume(t, l);
        return kPumpStepRecheck;
    }
    if (! ls->prev_paused)
    {
        if (udp)
            return trojanserverNotifyRemotePermission(t, l, ls) ? kPumpStepRecheck : kPumpStepFallThrough;
        if (ls->next_initialized && ls->next_pause_sent)
        {
            ls->next_pause_sent = false;
            if (ls->branch == kTrojanServerBranchFallback)
                tunnelUpStreamResume(trojanserverSelectedUpstream(t, ls), l);
            else
                tunnelNextUpStreamResume(t, l);
            return kPumpStepRecheck;
        }
    }
    return kPumpStepFallThrough;
}

void trojanserverPump(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kTrojanServerPhaseClosing || ls->pumping || ls->branch_initializing)
        return;
    lineRef(l);
    ls->pumping = true;
    /* Entry gates teardown reentrancy; completed callbacks report closure through logical death. */
    while (lineIsAlive(l))
    {
        bool udp         = trojanserverIsUdp(ls);
        bool next_paused = udp ? ls->paused_remotes != 0 : ls->next_paused;
        if (notifyPausedProducers(t, l, ls, udp, next_paused) == kPumpStepRecheck)
            continue;

        /* Initial parsing chooses TCP, UDP or fallback before any queued input is delivered. */
        if (ls->phase == kTrojanServerPhaseWaitInitial)
        {
            if (! ls->first_payload_seen)
                break;
            trojanserverParseInitial(t, l, ls);
            if (! lineIsAlive(l))
                break;
            if (ls->phase == kTrojanServerPhaseWaitInitial)
                break;
            continue;
        }
        if (processPendingInput(t, l, ls, udp) == kPumpStepRecheck)
            continue;
        /* Drain ready work before Resume, but let incomplete UDP frames receive more input. */
        if (notifyResumedProducers(t, l, ls, udp, next_paused) == kPumpStepRecheck)
            continue;
        break;
    }
    if (lineIsAlive(l))
        ls->pumping = false;
    lineUnref(l);
}

void trojanserverOnNextEstablished(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    if (ls->next_established)
        return;
    ls->next_established = true;
    if (ls->line_kind == kTrojanServerLineKindUdpRemote)
    {
        ls->phase                       = kTrojanServerPhaseUdpEstablished;
        line_t                *client_l = ls->client_line;
        trojanserver_lstate_t *client   = lineGetState(client_l, t);
        if (client->phase == kTrojanServerPhaseClosing || client->prev_est_sent)
            return;
        client->prev_est_sent = true;
        /* The backend's association reference can disappear in the callback. */
        lineRef(l);
        lineRef(client_l);
        tunnelPrevDownStreamEst(t, client_l);
        lineUnref(client_l);
        lineUnref(l);
        return;
    }
    if (ls->prev_est_sent)
        return;
    ls->prev_est_sent = true;
    if (ls->phase == kTrojanServerPhaseTcpConnecting)
        ls->phase = kTrojanServerPhaseTcpEstablished;
    /* Publish before forwarding, including synchronous Est from branch Init. */
    tunnelPrevDownStreamEst(t, l);
}

void trojanserverSetNextPaused(tunnel_t *t, line_t *l, bool paused)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kTrojanServerPhaseClosing)
        return;
    if (ls->line_kind == kTrojanServerLineKindUdpRemote)
    {
        trojanserver_lstate_t *client = lineGetState(ls->client_line, t);
        if (ls->next_paused != paused)
        {
            ls->next_paused = paused;
            if (paused)
                ++client->paused_remotes;
            else
            {
                assert(client->paused_remotes != 0);
                --client->paused_remotes;
            }
        }
        trojanserverPump(t, ls->client_line);
        return;
    }
    ls->next_paused = paused;
    trojanserverPump(t, l);
}
