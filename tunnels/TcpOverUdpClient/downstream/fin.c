#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{

    tcpoverudpclient_lstate_t *ls = lineGetState(l, t);
    assert(ls->k_handle != NULL);

    // During our close-frame flush, retire state without reflecting Finish to prev.
    const bool forward = ls->can_downstream;
    tcpoverudpclientLinestateDestroy(ls);
    if (forward)
        tunnelPrevDownStreamFinish(t, l);
}
