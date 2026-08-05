#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    streamtopacketsSetLinePaused(t, l, false);
}
