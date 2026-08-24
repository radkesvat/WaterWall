#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                 context;
    reverseclient_tstate_t *ts = tunnelGetState(t);

    for (wid_t wid = 0; wid < getWorkersCount(); wid++)
    {
        if (UNLIKELY(ts->threadlocal_pool[wid].owned_pairs != NULL))
        {
            LOGF("ReverseClient: destroy observed an undrained owned pair on worker %d", (int) wid);
            abortProgramNow(1);
        }
    }
    if (UNLIKELY(atomicLoadRelaxed(&ts->reverse_cons) != 0))
    {
        LOGF("ReverseClient: destroy observed %u active reverse pair reservation(s)",
             (unsigned int) atomicLoadRelaxed(&ts->reverse_cons));
        abortProgramNow(1);
    }

    reverseclientHandshakeDestroy(ts->handshake_bytes);
    if (ts->starved_connections != NULL)
    {
        idletableDestroy(ts->starved_connections);
    }
    tunnelDestroy(t);
}
