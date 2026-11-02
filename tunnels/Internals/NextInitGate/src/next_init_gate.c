#include "NextInitGate/next_init_gate.h"

void nextinitgateInit(next_init_gate_t *gate, size_t max_bytes, size_t max_charge)
{
    assert(gate != NULL);
    *gate = (next_init_gate_t) {
        .pending = bufferqueueCreate(2),
        .limits  = {.bytes = max_bytes, .charge = max_charge},
        .phase   = kNextInitGateWaiting,
    };
}

void nextinitgateDestroy(next_init_gate_t *gate, buffer_pool_t *pool)
{
    assert(gate != NULL);
    sbuf_t *buf;
    while ((buf = bufferqueuePopFront(&gate->pending)) != NULL)
    {
        assert(pool != NULL);
        bufferpoolReuseBuffer(pool, buf);
    }
    bufferqueueDestroy(&gate->pending);
    memoryZero(gate, sizeof(*gate));
}

bool nextinitgateSignal(next_init_gate_t *gate, bool paused)
{
    assert(gate != NULL);
    assert(gate->phase == kNextInitGateWaiting || gate->phase == kNextInitGateStarting ||
           gate->phase == kNextInitGateOpen);
    if (gate->phase == kNextInitGateWaiting)
    {
        gate->pause_latched = paused;
        return false;
    }
    gate->pause_latched = false;
    return true;
}

next_init_gate_input_t nextinitgateSubmit(next_init_gate_t *gate, sbuf_t **buf)
{
    assert(gate != NULL && buf != NULL && *buf != NULL);
    assert(gate->phase == kNextInitGateStarting || gate->phase == kNextInitGateOpen);
    if (gate->phase == kNextInitGateOpen)
    {
        return kNextInitGateForward;
    }

    buffer_budget_t available = {
        .limits = gate->limits,
        .used   = {.bytes = bufferqueueGetBufLen(&gate->pending), .charge = bufferqueueGetCharge(&gate->pending)},
    };
    buffer_budget_cost_t cost;
    if (! bufferbudgetTryGetCost(*buf, &cost) || ! bufferbudgetTryAcquire(&available, cost) ||
        ! bufferqueueTryPushBack(&gate->pending, buf))
    {
        return kNextInitGateRejected;
    }
    *buf = NULL;
    return kNextInitGateQueued;
}

next_init_gate_result_t nextinitgateOpen(next_init_gate_t *gate, tunnel_t *t, line_t *line, sbuf_t *first,
                                         next_init_gate_valid_fn still_mine)
{
    assert(gate != NULL && t != NULL && line != NULL && still_mine != NULL);
    assert(lineIsAlive(line) && gate->phase == kNextInitGateWaiting);
    buffer_pool_t *pool = lineGetBufferPool(line);
    gate->phase         = kNextInitGateStarting;
    lineRef(line);
    tunnelNextUpStreamInit(t, line);
    if (! lineIsAlive(line) || ! still_mine(t, line))
    {
        goto gone;
    }
    if (gate->pause_latched)
    {
        gate->pause_latched = false;
        tunnelNextUpStreamPause(t, line);
        if (! lineIsAlive(line) || ! still_mine(t, line))
        {
            goto gone;
        }
    }
    for (;;)
    {
        sbuf_t *out = first != NULL ? first : bufferqueuePopFront(&gate->pending);
        first       = NULL;
        if (out == NULL)
        {
            gate->phase = kNextInitGateOpen;
            lineUnref(line);
            return kNextInitGateReady;
        }
        tunnelNextUpStreamPayload(t, line, out);
        if (! lineIsAlive(line) || ! still_mine(t, line))
        {
            goto gone;
        }
    }

gone:
    if (first != NULL)
    {
        bufferpoolReuseBuffer(pool, first);
    }
    lineUnref(line);
    return kNextInitGateGone;
}
