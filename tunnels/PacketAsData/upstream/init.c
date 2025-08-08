#include "structure.h"

#include "loggers/network_logger.h"

void packetasdataTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    packetasdata_lstate_t *ls = (packetasdata_lstate_t *) lineGetState(l, t);

    if (ls->line == NULL)
    {
        line_t *nl = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), lineGetWID(l));

        ls->paused = false;
        ls->line = nl;
        ls->read_stream = bufferstreamCreate(lineGetBufferPool(l), 0);

        tunnelNextUpStreamInit(t, nl);
    }
    else
    {
        LOGW("PacketAsData: received 2 inits?");
    }
}
