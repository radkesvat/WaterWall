#include "structure.h"

void routerTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    router_lstate_t *ls = lineGetState(l, t);

    routerLinestateInitialize(ls);
    addresscontextClearOptionalFlags(lineGetDestinationAddressContext(l));

    /*
     * Init is intentionally not propagated yet. The selected branch is
     * initialized lazily after the first payload is classified, so that
     * content-based matchers have a payload window to inspect.
     */
}
