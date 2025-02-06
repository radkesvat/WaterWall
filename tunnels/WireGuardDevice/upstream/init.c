#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamInit(t, l);
}
