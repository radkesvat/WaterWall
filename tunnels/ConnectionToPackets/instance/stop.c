#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    /* Workers have detached PCBs/netifs and sources have sent Finish.
     * Main cleanup checks those barriers and releases shared routing records. */
    ctpDestroyLwipResources(t);
}

void ctpTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    ctpDrainTerminalLinesOnCurrentWorker(t, wid);
    ctpDetachWorkerLines(t, wid);
    ctpDestroyWorkerNetif(t, wid);
}
