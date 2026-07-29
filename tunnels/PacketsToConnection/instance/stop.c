#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelOnStop(tunnel_t *t)
{
    /*
     * The process-level lwIP shutdown follows node Stop and precedes tunnel
     * destruction. Detach this tunnel's netifs and PCBs while the core thread
     * and tunnel state are both still valid.
     */
    ptcDestroyLwipResources(t);
}
