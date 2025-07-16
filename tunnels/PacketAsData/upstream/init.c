#include "structure.h"

#include "loggers/network_logger.h"

void packetasdataTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    packetasdata_lstate_t *ls = (packetasdata_lstate_t *) lineGetState(l, t);

    if (ls->line == NULL)
    {
        line_t *nl = lineCreate(tunnelchainGetLinePool(tunnelGetChain(t), lineGetWID(l)), lineGetWID(l));

        ls->paused = false;
        ls->line = nl;

        tunnelNextUpStreamInit(t, nl);
    }
    else
    {
        LOGW("PacketAsData: received 2 inits?");
    }
}
