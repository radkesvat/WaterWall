#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    // Backpressure is per stream line, never global: the remaining active lines
    // of this source keep carrying their flows.
    streamtopacketsSetLinePaused(t, l, true);
}
