#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;

    ptcDestroyLwipResources(t);
}

void ptcTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    ptcDrainOwnedLinesOnCurrentWorker(t, wid);
}
