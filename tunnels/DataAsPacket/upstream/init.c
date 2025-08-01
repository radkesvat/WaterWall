#include "structure.h"

#include "loggers/network_logger.h"

void dataaspacketTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    dataaspacket_lstate_t *ls = lineGetState(tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)), t);
    
    if(ls->line != NULL)
    {
        // this can happen and is ok, it means that the line already has a state
        // LOGD("DataAsPacket: Upstream init called on a line that already has a state, the received packets will be sent to older line");
        return;
    }
    ls->paused = false;
    ls->line = l;
    ls->read_stream = bufferstreamCreate(lineGetBufferPool(l), 0);

}
