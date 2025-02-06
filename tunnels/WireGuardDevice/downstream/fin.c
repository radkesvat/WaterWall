#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tunnelPrevdownStreamFinish(t, l);
}
