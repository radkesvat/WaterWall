#include "structure.h"

void usercontrollerTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    usercontrollerBandwidthSetExternalPause(t, l, false, false);
}
