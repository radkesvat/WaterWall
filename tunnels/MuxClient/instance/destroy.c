#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard             context;
    muxclient_tstate_t *ts = tunnelGetState(t);

    if (ts->fixed_parent_lines != NULL)
    {
        memoryFree(ts->fixed_parent_lines);
    }
    if (ts->fixed_next_parent_indexes != NULL)
    {
        memoryFree(ts->fixed_next_parent_indexes);
    }
    tunnelDestroy(t);
}
