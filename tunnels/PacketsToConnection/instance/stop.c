#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelOnStop(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);

    /*
     * Set the value-only gate before waiting for the core lock. A packet
     * callback that was already waiting on that lock will recheck the gate
     * after acquiring it and cannot recreate a route after the cleanup below.
     * The core lock, not this atomic, supplies the cleanup ordering.
     */
    atomicStoreRelaxed(&state->stopping, true);

    // Process-level lwIP shutdown follows node Stop, so detach this tunnel's
    // netifs and PCBs while the core lock and tunnel state are still valid.
    ptcDestroyLwipResources(t);
}
