#include "structure.h"

void usercontrollerTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    usercontrollerBandwidthSetExternalPause(t, l, true, false);
}
