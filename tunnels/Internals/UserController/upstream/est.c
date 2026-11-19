#include "structure.h"

void usercontrollerTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    if (usercontrollerGetLineState(t, l)->phase == kUserControllerOpen)
        tunnelNextUpStreamEst(t, l);
}

void usercontrollerTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    if (usercontrollerGetLineState(t, l)->phase == kUserControllerOpen)
        tunnelPrevDownStreamEst(t, l);
}
