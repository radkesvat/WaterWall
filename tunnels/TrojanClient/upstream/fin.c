#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    trojanclientCloseLine(t, l, kTrojanClientCloseFromPrev);
}
