#include "structure.h"

#include "loggers/network_logger.h"

void packetasdataTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    tunnelPrevDownStreamPayload(t, tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)), buf);
}
