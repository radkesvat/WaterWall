#include "structure.h"

#include "loggers/network_logger.h"

void packetasdataTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    packetasdata_lstate_t *ls = lineGetState(tunnelchainGetPacketLine(tunnelGetChain(t), lineGetWID(l)), t);

    ls->paused = false;
}
