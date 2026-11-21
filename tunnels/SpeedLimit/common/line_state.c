#include "structure.h"

void speedlimitInitShaper(speedlimit_direction_t *direction)
{
    speedlimit_lstate_t *state = direction->state;
    trafficshaperInit(direction->upstream ? &state->up : &state->down,
                      state->line,
                      direction->upstream ? &state->up_budget : &state->down_budget,
                      &speedlimitShaperOps,
                      direction,
                      kTrafficShaperStream,
                      kSpeedLimitImmediateMs,
                      false);
}

void speedlimitLinestateInitialize(speedlimit_lstate_t *state, tunnel_t *tunnel, line_t *line)
{
    speedlimit_tstate_t *settings = tunnelGetState(tunnel);
    *state                        = (speedlimit_lstate_t) {
                               .tunnel = tunnel, .line = line, .line_bucket = {.tokens_units = settings->bucket_capacity_units}};
    state->close_phase                = kSpeedLimitOpen;
    state->up_context                 = (speedlimit_direction_t) {state, true};
    state->down_context               = (speedlimit_direction_t) {state, false};
    const buffer_budget_cost_t limits = {kSpeedLimitMaxQueueBytes, kSpeedLimitMaxQueueCharge};
    bufferbudgetInit(&state->up_budget, limits);
    bufferbudgetInit(&state->down_budget, limits);
    state->packet_line = tunnelchainIsWorkerPacketLine(tunnel->chain, line);
    speedlimitInitShaper(&state->up_context);
    speedlimitInitShaper(&state->down_context);
    speedlimit_lstate_t **head = &settings->worker_buckets[lineGetWID(line)].active_lines;
    state->active_next         = *head;
    if (*head != NULL)
        (*head)->active_prev = state;
    *head = state;
}

void speedlimitLinestateDestroy(speedlimit_lstate_t *state)
{
    speedlimit_tstate_t *settings = tunnelGetState(state->tunnel);
    if (state->active_prev != NULL)
        state->active_prev->active_next = state->active_next;
    else
        settings->worker_buckets[lineGetWID(state->line)].active_lines = state->active_next;
    if (state->active_next != NULL)
        state->active_next->active_prev = state->active_prev;

    trafficshaperDestroy(&state->up);
    trafficshaperDestroy(&state->down);
    bufferbudgetAssertEmpty(&state->up_budget);
    bufferbudgetAssertEmpty(&state->down_budget);
    memoryZeroAligned32(state, tunnelGetCorrectAlignedLineStateSize(sizeof(*state)));
}

void speedlimitFinish(tunnel_t *tunnel, line_t *line, bool upstream)
{
    speedlimit_lstate_t *state = lineGetState(line, tunnel);
    if (state->close_phase == kSpeedLimitClosingBoth)
    {
        state->close_phase = kSpeedLimitClosed;
        return;
    }
    if (state->close_phase == kSpeedLimitFlushing)
    {
        /* The receiver closed inside a final Payload callback. */
        speedlimitLinestateDestroy(state);
        return;
    }
    assert(state->close_phase == kSpeedLimitOpen);
    traffic_shaper_t *output = upstream ? &state->up : &state->down;
    if (! state->packet_line && ! output->stopped && trafficshaperPending(output) != 0)
    {
        state->close_phase = kSpeedLimitFlushing;
        trafficshaperQuiesce(&state->up);
        trafficshaperQuiesce(&state->down);
        sbuf_t *buffer;
        while ((buffer = trafficshaperPopForFinish(output, SIZE_MAX)) != NULL)
        {
            if (! lineCallWithRefWithBuf(
                    line, upstream ? tunnelNextUpStreamPayload : tunnelPrevDownStreamPayload, tunnel, buffer) ||
                state->close_phase != kSpeedLimitFlushing)
                return;
        }
    }
    speedlimitLinestateDestroy(state);
    if (upstream)
        tunnelNextUpStreamFinish(tunnel, line);
    else
        tunnelPrevDownStreamFinish(tunnel, line);
}

void speedlimitTunnelWorkerQuiesce(tunnel_t *tunnel, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard              context;
    speedlimit_tstate_t *settings = tunnelGetState(tunnel);
    for (speedlimit_lstate_t *state = settings->worker_buckets[wid].active_lines; state != NULL;
         state                      = state->active_next)
    {
        trafficshaperQuiesce(&state->up);
        trafficshaperQuiesce(&state->down);
    }
}

void speedlimitTunnelWorkerStop(tunnel_t *tunnel, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard              context;
    speedlimit_tstate_t *settings = tunnelGetState(tunnel);
    /* Normal lines are drained by their owners. A worker packet line lives
     * until chain destruction and only its local queues need to be released. */
    for (speedlimit_lstate_t *state = settings->worker_buckets[wid].active_lines; state != NULL;
         state                      = state->active_next)
    {
        if (tunnelchainIsWorkerPacketLine(tunnel->chain, state->line))
        {
            speedlimitLinestateDestroy(state);
            return;
        }
    }
}
