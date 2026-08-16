#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    /*
     * Process-level lwIP shutdown follows node Stop, so this node's pcbs, flow
     * registry and netifs are detached while the core lock and tunnel state are
     * still valid. Borrowed normal lines are finished and destroyed later by
     * their real owners; nothing here calls into a neighboring tunnel.
     */
    ctpDestroyLwipResources(t);
}

void ctpTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    ctpDrainTerminalLinesOnCurrentWorker(t, wid);
}
