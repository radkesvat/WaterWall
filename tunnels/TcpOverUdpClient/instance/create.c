#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *tcpoverudpclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tcpoverudpclient_tstate_t), sizeof(tcpoverudpclient_lstate_t));

    t->fnInitU    = &tcpoverudpclientTunnelUpStreamInit;
    t->fnEstU     = &tcpoverudpclientTunnelUpStreamEst;
    t->fnFinU     = &tcpoverudpclientTunnelUpStreamFinish;
    t->fnPayloadU = &tcpoverudpclientTunnelUpStreamPayload;
    t->fnPauseU   = &tcpoverudpclientTunnelUpStreamPause;
    t->fnResumeU  = &tcpoverudpclientTunnelUpStreamResume;

    t->fnInitD    = &tcpoverudpclientTunnelDownStreamInit;
    t->fnEstD     = &tcpoverudpclientTunnelDownStreamEst;
    t->fnFinD     = &tcpoverudpclientTunnelDownStreamFinish;
    t->fnPayloadD = &tcpoverudpclientTunnelDownStreamPayload;
    t->fnPauseD   = &tcpoverudpclientTunnelDownStreamPause;
    t->fnResumeD  = &tcpoverudpclientTunnelDownStreamResume;

    t->onPrepair = &tcpoverudpclientTunnelOnPrepair;
    t->onStart   = &tcpoverudpclientTunnelOnStart;
    t->onDestroy = &tcpoverudpclientTunnelDestroy;

    
    tcpoverudpclient_tstate_t *ts = tunnelGetState(t);

    *ts = (tcpoverudpclient_tstate_t){0};

    ikcp_allocator(&memoryAllocate,
                   &memoryFree);

    return t;
}
