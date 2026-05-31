#include "structure.h"

void sniffrouterTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    if (ls->prev_finished || ls->next_finished)
    {
        return;
    }

    /*
     * The web branch is usually a TcpConnector, whose upstream Est is disabled.
     * Only the normal tunnel branch receives upstream Est.
     */
    if (ls->decided == kSniffRouteTunnel)
    {
        tunnelNextUpStreamEst(t, l);
    }
}
