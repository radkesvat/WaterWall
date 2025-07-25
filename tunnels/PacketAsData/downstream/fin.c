#include "structure.h"

#include "loggers/network_logger.h"

void packetasdataTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    packetasdata_lstate_t *ls = lineGetState(tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)), t);

    assert(ls->line);
    assert(ls->line == l);

    LOGD("PacketAsData: got fin, recreating line");

    line_t *nl = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(l));

    lineDestroy(ls->line);
    ls->line = NULL;

    ls->paused = false;
    ls->line   = nl;

    tunnelNextUpStreamInit(t, nl);
}
