#include "ConnectionStripeClient/structure.h"

void connectionstripeclientTunnelUpStreamEst(tunnel_t *t, line_t *line)
{
    /* Application Est is consumed; downstream transport Est establishes the application. */
    discard t;
    discard line;
}
