#include "structure.h"

void quicserverTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    quicCloseAdmission(t);
}

void quicserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    quicQuiesceWorker(t, wid);
}
