#include "structure.h"

void speedlimitLinestateInitialize(speedlimit_lstate_t *state, tunnel_t *tunnel, line_t *line)
{
    speedlimit_tstate_t *settings = tunnelGetState(tunnel);
    *state                        = (speedlimit_lstate_t) {
                               .tunnel = tunnel, .line = line, .line_bucket = {.tokens_units = settings->bucket_capacity_units}};
    state->up_context                 = (speedlimit_direction_t) {state, true};
    state->down_context               = (speedlimit_direction_t) {state, false};
    const buffer_budget_cost_t limits = {
        kSpeedLimitMaxQueueBytes, kSpeedLimitMaxQueueCharge, kSpeedLimitMaxQueueBuffers};
    bufferbudgetInit(&state->up_budget, limits);
    bufferbudgetInit(&state->down_budget, limits);
    trafficshaperInit(&state->up,
                      line,
                      &state->up_budget,
                      &speedlimitShaperOps,
                      &state->up_context,
                      kTrafficShaperStream,
                      kSpeedLimitImmediateMs,
                      false);
    trafficshaperInit(&state->down,
                      line,
                      &state->down_budget,
                      &speedlimitShaperOps,
                      &state->down_context,
                      kTrafficShaperStream,
                      kSpeedLimitImmediateMs,
                      false);
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
