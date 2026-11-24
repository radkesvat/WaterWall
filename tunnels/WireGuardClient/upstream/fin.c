#include "WireGuardClient/interface.h"
#include "loggers/network_logger.h"

void wireguardclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("WireGuardClient: unexpected Finish on packet input");
    abortProgramNow(1);
}
