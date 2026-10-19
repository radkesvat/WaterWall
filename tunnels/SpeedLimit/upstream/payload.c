#include "structure.h"

void speedlimitUpstreamDrainTimerCallback(wtimer_t *timer)
{
    trafficshaperTimerCallback(timer);
}

void speedlimitTunnelUpStreamPayload(tunnel_t *tunnel, line_t *line, sbuf_t *buffer)
{
    speedlimit_tstate_t *settings = tunnelGetState(tunnel);
    speedlimit_lstate_t *state    = lineGetState(line, tunnel);
    if (settings->work_mode == kSpeedLimitWorkModeDrop)
    {
        if (speedlimitGrantBytes(tunnel, line, sbufGetLength(buffer), false) == sbufGetLength(buffer))
            tunnelNextUpStreamPayload(tunnel, line, buffer);
        else
            lineReuseBuffer(line, buffer);
        return;
    }
    if (trafficshaperSubmit(&state->up, buffer) == kTrafficShaperRefused)
        speedlimitCloseLineOnDrainFailure(state, buffer);
}
