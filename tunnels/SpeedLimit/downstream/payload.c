#include "structure.h"

void speedlimitDownstreamDrainTimerCallback(wtimer_t *timer)
{
    trafficshaperTimerCallback(timer);
}

void speedlimitTunnelDownStreamPayload(tunnel_t *tunnel, line_t *line, sbuf_t *buffer)
{
    speedlimit_tstate_t *settings = tunnelGetState(tunnel);
    speedlimit_lstate_t *state    = lineGetState(line, tunnel);
    if (settings->work_mode == kSpeedLimitWorkModeDrop)
    {
        if (speedlimitGrantBytes(tunnel, line, sbufGetLength(buffer), false) == sbufGetLength(buffer))
            tunnelPrevDownStreamPayload(tunnel, line, buffer);
        else
            lineReuseBuffer(line, buffer);
        return;
    }
    if (trafficshaperSubmit(&state->down, buffer) == kTrafficShaperRefused)
        speedlimitCloseLineOnDrainFailure(state, buffer);
}
