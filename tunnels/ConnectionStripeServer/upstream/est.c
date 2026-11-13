#include "ConnectionStripeServer/structure.h"

void connectionstripeserverTunnelUpStreamEst(tunnel_t *t, line_t *line)
{
    /* Carrier Est is consumed; a complete JOIN group starts the application. */
    discard t;
    discard line;
}
