#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    tlsclient_tstate_t *ts       = tunnelGetState(t);
    tunnel_t           *fragment = ts->fragment_tunnel;
    assert(fragment != NULL);
    if (t->next != NULL || fragment->prev != NULL || fragment->next != NULL || fragment->chain != NULL)
    {
        LOGF("TlsClient: internal StreamFragmenter is already bound");
        startupFailureRecord(1);
        return;
    }
    tunnelBind(t, fragment);
    tunnelchainInsert(chain, t);
    if (startupFailurePending())
        return;
    /* The child carries the configured next link. Its normal chain traversal
     * also handles private helpers on that next node and existing chains. */
    fragment->onChain(fragment, chain);
}
