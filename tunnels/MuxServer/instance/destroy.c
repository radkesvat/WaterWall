#include "structure.h"

#include "loggers/network_logger.h"

void muxserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    muxserver_tstate_t *ts = tunnelGetState(t);
    for (uint32_t wid = 0; wid < ts->workers_count; ++wid)
    {
        muxserver_detached_registry_t *registry = &ts->detached_registries[wid];
        if (UNLIKELY(registry->head != NULL || registry->count != 0 || registry->queued_bytes != 0))
        {
            LOGF("MuxServer: destroy observed a nonempty detached registry on worker %u", wid);
            abortProgramNow(1);
        }
    }
    tunnelDestroy(t);
}
