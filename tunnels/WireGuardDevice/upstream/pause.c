#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    (void)l;
    LOGF("This Function is disabled, using the default PacketTunnel instead");
    terminateProgram(1);
}
