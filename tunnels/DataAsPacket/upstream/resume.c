#include "structure.h"

#include "loggers/network_logger.h"

void dataaspacketTunnelUpStreamResume(tunnel_t *t, line_t *l)
{

    dataaspacket_lstate_t *ls = lineGetState(tunnelchainGetPacketLine(tunnelGetChain(t), lineGetWID(l)), t);

    ls->paused = false;
}
