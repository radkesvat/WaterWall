#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("This Function is disabled, use the default PacketTunnel instead");
    exit(1);
}
