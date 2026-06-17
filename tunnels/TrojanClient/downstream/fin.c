#include "structure.h"

#include "loggers/network_logger.h"

void trojanclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    trojanclientCloseLine(t, l, kTrojanClientCloseFromNext);
}
