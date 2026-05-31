#include "structure.h"

void sniffrouterTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    sniffrouterLinestateInitialize(ls);

    /*
     * Init is intentionally not propagated yet. The selected branch is
     * initialized lazily after the first cleartext bytes are classified.
     */
}
