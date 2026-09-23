#include "structure.h"

void tlsclientTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tlsclient_lstate_t *ls = lineGetState(l, t);
    if (ls->upstream_finished || ls->transport_est_sent)
    {
        return;
    }
    ls->transport_est_sent = true;
    tunnelPrevDownStreamEst(t, l);
}
