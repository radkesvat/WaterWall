#include "ConnectionStripeServer/structure.h"

void connectionstripeserverTunnelDownStreamEst(tunnel_t *t, line_t *line)
{
    /* Transport Init already notified its owner; backend Est is consumed. */
    discard t;
    discard line;
}
