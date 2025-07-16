#include "structure.h"

#include "loggers/network_logger.h"

void packetasdataTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    packetasdata_lstate_t *ls = lineGetState(tunnelchainGetPacketLine(tunnelGetChain(t), lineGetWID(l)), t);

    ls->paused = true; // packets will be dropped till we resume
}
