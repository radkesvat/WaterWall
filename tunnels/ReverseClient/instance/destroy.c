#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                 context;
    reverseclient_tstate_t *ts = tunnelGetState(t);

    reverseclientHandshakeDestroy(ts->handshake_bytes);
    for (wid_t wid = 0; wid < getWorkersCount(); wid++)
    {
        assert(ts->threadlocal_pool[wid].owned_pairs == NULL);
    }
    if (ts->starved_connections != NULL)
    {
        idletableDestroy(ts->starved_connections);
    }
    tunnelDestroy(t);
}
