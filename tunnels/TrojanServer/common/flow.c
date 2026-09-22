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

static pump_step_result_t notifyEstablished(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, bool udp)
{
    if (! ls->next_established || ls->prev_est_sent || udp)
        return kPumpStepFallThrough;
    ls->prev_est_sent = true;
    if (ls->phase == kTrojanServerPhaseTcpConnecting)
        ls->phase = kTrojanServerPhaseTcpEstablished;
    tunnelPrevDownStreamEst(t, l);
    return kPumpStepRecheck;
}

/* Called only after initial parsing and while the next side accepts payload. */
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
    if (ls->branch == kTrojanServerBranchFallback && ! trojanserverScheduleFallbackPayloadDrain(t, l, ls))
    {
        trojanserverCloseLineBidirectional(t, l);
        return kPumpStepRecheck;
    }
    /* A scheduled fallback task runs later; continue with replies and Resume now. */
    return kPumpStepFallThrough;
}

static pump_step_result_t forwardQueuedReplies(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, bool udp)
{
    if (ls->prev_paused)
        return kPumpStepFallThrough;
    if (udp && ls->reply_head != NULL && ls->reply_head->waiter == NULL)
    {
        trojanserver_reply_t *reply = ls->reply_head;
        ls->reply_head              = reply->next;
        if (ls->reply_head == NULL)
            ls->reply_tail = NULL;
        sbuf_t *buf = reply->buf;
        ls->reply_bytes -= sbufGetLength(buf);
        --ls->reply_count;
        memoryFree(reply);
        tunnelPrevDownStreamPayload(t, l, buf);
        return kPumpStepRecheck;
    }
    if (ls->branch == kTrojanServerBranchFallback && bufferqueueGetBufCount(&ls->pending_down) != 0)
    {
        /* Fallback replies have their own reentrancy gate and need no Est. */
        trojanserverPumpFallbackReplies(t, l, NULL);
        return kPumpStepRecheck;
    }
    if (! udp && ls->prev_est_sent && bufferqueueGetBufCount(&ls->pending_down) != 0)
    {
        tunnelPrevDownStreamPayload(t, l, bufferqueuePopFront(&ls->pending_down));
        return kPumpStepRecheck;
    }
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
        if (notifyEstablished(t, l, ls, udp) == kPumpStepRecheck)
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
        if (! next_paused && processPendingInput(t, l, ls, udp) == kPumpStepRecheck)
            continue;
        if (forwardQueuedReplies(t, l, ls, udp) == kPumpStepRecheck)
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
        ls->phase        = kTrojanServerPhaseUdpEstablished;
        line_t *client_l = ls->client_line;
        trojanserverSettleRemoteReplies(lineGetState(client_l, t), l, true);
        trojanserverPump(t, client_l);
        return;
    }
    trojanserverPump(t, l);
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
