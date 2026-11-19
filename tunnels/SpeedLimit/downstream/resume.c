#include "structure.h"

void speedlimitTunnelDownStreamResume(tunnel_t *tunnel, line_t *line)
{
    speedlimit_lstate_t *state = lineGetState(line, tunnel);
    if (state->close_phase == kSpeedLimitOpen)
        trafficshaperSetExternalPause(&state->up, false);
}
