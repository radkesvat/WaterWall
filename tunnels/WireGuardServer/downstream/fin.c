#include "WireGuardServer/structure.h"
#include "loggers/network_logger.h"

void wireguardserverTunnelDownStreamFinish(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
    LOGF("WireGuardServer: unexpected Finish on inner packet line");
    abortProgramNow(1);
}
