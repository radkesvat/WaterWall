#include "structure.h"

#include "loggers/network_logger.h"

static void streamtopacketsQueueWorkerPacketInit(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

    tunnel_t *t = arg1;
    line_t   *l = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), getCurrentEventWorkerWID());

    tunnelNextUpStreamInit(t, l);
    assert(lineIsAlive(l));
}

void streamtopacketsTunnelOnStart(tunnel_t *t)
{
    // Queue the packet-line bootstrap onto each worker so packet-side tunnels see it after startup,
    // rather than re-entering their init paths inline during node-manager startup.

    for (wid_t wi = 0; wi < getWorkersCount(); wi++)
    {
        sendWorkerMessageForceQueue(wi, streamtopacketsQueueWorkerPacketInit, t, NULL, NULL);
    }
}
