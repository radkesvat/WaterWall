#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsQueueWorkerPacketInit(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

    if (UNLIKELY(isApplicationTerminating()))
    {
        return;
    }

    tunnel_t *t = arg1;
    line_t   *l = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), getCurrentEventWorkerWID());

    if (UNLIKELY(! withLineLocked(l, tunnelNextUpStreamInit, t)))
    {
        LOGF("StreamToPackets: worker packet line died during packet-side init");
        abortProgramNow(1);
        return;
    }
}

void streamtopacketsTunnelOnStart(tunnel_t *t)
{
    // Queue the packet-line bootstrap onto each worker so packet-side tunnels see it after startup,
    // rather than re-entering their init paths inline during node-manager startup.

    for (wid_t wi = 0; wi < getWorkersCount(); wi++)
    {
        if (UNLIKELY(! sendWorkerMessageForceQueueWithCleanup(
                wi, streamtopacketsQueueWorkerPacketInit, NULL, t, NULL, NULL)))
        {
            LOGF("StreamToPackets: failed to admit required packet-side Init on worker %u", (unsigned int) wi);
            terminateProgram(1);
            return;
        }
    }
}
