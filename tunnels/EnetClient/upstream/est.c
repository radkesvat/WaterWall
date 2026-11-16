#include "EnetClient/structure.h"

void enetclientTunnelUpStreamEst(tunnel_t *t, line_t *line)
{
    /* Application Est is consumed. The carrier's Est establishes the application. */
    discard t;
    discard line;
}
