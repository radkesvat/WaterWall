#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    ptc_lstate_t *lstate = lineGetState(l, t);
    LOGD("PacketToConnection: recv closing connection");


    LOCK_TCPIP_CORE();


    if (lstate->tcp_pcb)
    {
        ptcFlushWriteQueue(lstate);
        tcp_close(lstate->tcp_pcb);
        lstate->tcp_pcb->callback_arg = NULL;
        lstate->tcp_pcb               = NULL;
    }

    lineDestroy(l);
    if (lstate->messages == 0)
    {
        ptcLinestateDestroy(lstate);
    }
    UNLOCK_TCPIP_CORE();
}
