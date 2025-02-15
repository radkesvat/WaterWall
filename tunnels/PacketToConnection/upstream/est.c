#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    (void) t;
    (void) l;
    LOGF("This Function is disabled, using the default PacketTunnel instead");
    exit(1);
}
