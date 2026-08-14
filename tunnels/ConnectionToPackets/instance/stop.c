#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelOnStop(tunnel_t *t)
{
    /*
     * Publish the gate before waiting for the core lock. A flow open, a packet
     * injection or a netif output that was already waiting on that lock rechecks
     * the gate after acquiring it, so none of them can republish state after the
     * cleanup below. The core lock, not this atomic, supplies the ordering.
     */
    ctpTunnelOnPreStop(t);

    /*
     * Process-level lwIP shutdown follows node Stop, so this node's pcbs, flow
     * registry and netifs are detached while the core lock and tunnel state are
     * still valid. Borrowed normal lines are finished and destroyed later by
     * their real owners; nothing here calls into a neighboring tunnel.
     */
    ctpDestroyLwipResources(t);
}

void ctpTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(currentThreadIsEventWorkerWID(wid));
    ctpDrainTerminalLinesOnCurrentWorker(t, wid);
}
