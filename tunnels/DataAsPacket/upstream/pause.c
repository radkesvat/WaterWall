#include "structure.h"

#include "loggers/network_logger.h"

void dataaspacketTunnelUpStreamPause(tunnel_t *t, line_t *l)
{

    dataaspacket_lstate_t *ls = lineGetState(tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)), t);

    ls->paused = true; // packets will be dropped till we resume
}
