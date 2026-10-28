#include "internal.h"

/* Step results select the pump's next action, independently of success or failure. */
typedef enum pump_step_result_e
{
    kPumpStepFallThrough, // No callback ran; the next step may inspect state.
    kPumpStepRecheck,     // Restart liveness and permission checks before another step.
    kPumpStepStop         // Replay retired state; release the pump reference and return.
} pump_step_result_t;

bool trojanserverIsUdp(const trojanserver_lstate_t *ls)
{
    return ls->line_kind == kTrojanServerLineKindClient &&
           (ls->phase == kTrojanServerPhaseUdpWaitPacket || ls->phase == kTrojanServerPhaseUdpEstablished);
}

/* Steps share the pump's retained client line and reentrancy guard. Callbacks,
 * parser progress and close require Recheck; incomplete parsing and successful
 * fallback scheduling can FallThrough. */
static pump_step_result_t notifyPausedProducers(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    if (ls->paused_remotes != 0 && ! ls->prev_pause_sent)
    {
        ls->prev_pause_sent = true;
        tunnelPrevDownStreamPause(t, l);
        return kPumpStepRecheck;
    }
    return ls->prev_paused && trojanserverNotifyRemotePermission(t, l, ls) ? kPumpStepRecheck : kPumpStepFallThrough;
}

/* Parser/reentry input and ready fallback output preserve FIFO without a Pause gate. */
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
        bool                           dispatched;
        const fallback_replay_result_e result = trojanserverDrainFallbackPayload(t, l, ls, &dispatched);
        if (result == kFallbackReplayRefused)
            trojanserverCloseLineBidirectional(t, l);
        if (result != kFallbackReplayOk)
            return kPumpStepStop;
        if (dispatched)
            return kPumpStepRecheck;
    }
    /* A scheduled fallback task runs later; this dispatch has no more ready input. */
    return kPumpStepFallThrough;
}

static pump_step_result_t notifyResumedProducers(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    if (ls->paused_remotes == 0 && ls->prev_pause_sent)
    {
        ls->prev_pause_sent = false;
        tunnelPrevDownStreamResume(t, l);
        return kPumpStepRecheck;
    }
    return ! ls->prev_paused && trojanserverNotifyRemotePermission(t, l, ls) ? kPumpStepRecheck : kPumpStepFallThrough;
}

void trojanserverPump(tunnel_t *t, line_t *l)
{
    trojanserver_lstate_t *ls = lineGetState(l, t);
    if (ls->phase == kTrojanServerPhaseClosing || ls->pumping || ls->branch_initializing)
        return;
    lineRef(l);
    ls->pumping = true;
    /* A source Finish can retire this borrowed state before its owner destroys
     * the line. Recheck both lifetimes after every pump callback. */
    while (lineIsAlive(l) && ls->line == l)
    {
        bool udp = trojanserverIsUdp(ls);
        if (udp && notifyPausedProducers(t, l, ls) == kPumpStepRecheck)
            continue;

        /* Initial parsing chooses TCP, UDP or fallback before any queued input is delivered. */
        if (ls->phase == kTrojanServerPhaseWaitInitial)
        {
            if (! ls->first_payload_seen)
                break;
            trojanserverParseInitial(t, l, ls);
            if (! lineIsAlive(l) || ls->line != l)
                break;
            if (ls->phase == kTrojanServerPhaseWaitInitial)
                break;
            continue;
        }
        const pump_step_result_t input_result = processPendingInput(t, l, ls, udp);
        if (input_result == kPumpStepStop)
        {
            lineUnref(l);
            return;
        }
        if (input_result == kPumpStepRecheck)
            continue;
        /* Drain ready work before Resume, but let incomplete UDP frames receive more input. */
        if (udp && notifyResumedProducers(t, l, ls) == kPumpStepRecheck)
            continue;
        break;
    }
    if (lineIsAlive(l) && ls->line == l)
    {
        ls->pumping = false;
        if (ls->line_kind == kTrojanServerLineKindClient && ls->branch == kTrojanServerBranchTrojan &&
            (ls->phase == kTrojanServerPhaseTcpConnecting || ls->phase == kTrojanServerPhaseTcpEstablished))
        {
            /* Setup input and deferred startup notifications are settled. */
            assert(ls->next_initialized && ! ls->branch_initializing);
            assert(ls->input_head == NULL && ls->input_bytes == 0 && ls->header_filled == 0);
            assert(bufferqueueGetBufCount(&ls->pending_up) == 0);
            assert(ls->prev_paused == ls->next_pause_sent);
            trojanserverLinestateDestroy(ls);
            tunnelBypassLine(t, l);
        }
    }
    lineUnref(l);
}

void trojanserverOnNextEstablished(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls)
{
    if (ls->line_kind == kTrojanServerLineKindUdpRemote)
    {
        if (ls->next_established)
            return;
        ls->next_established            = true;
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
    if (paused)
        tunnelPrevDownStreamPause(t, l);
    else
        tunnelPrevDownStreamResume(t, l);
}

bool trojanserverQueuePayload(buffer_queue_t *queue, sbuf_t **buf)
{
    assert(queue->budget != NULL);
    return bufferqueueTryPushBack(queue, buf);
}
