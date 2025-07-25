#include "structure.h"

#include "loggers/network_logger.h"

void dataaspacketTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)), buf);
}
