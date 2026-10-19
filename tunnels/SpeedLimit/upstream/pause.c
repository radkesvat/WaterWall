#include "structure.h"

void speedlimitTunnelUpStreamPause(tunnel_t *tunnel, line_t *line)
{
    speedlimit_lstate_t *state = lineGetState(line, tunnel);
    trafficshaperSetExternalPause(&state->down, true);
}
