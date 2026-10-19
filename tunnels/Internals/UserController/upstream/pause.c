#include "structure.h"

void usercontrollerTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    // The prev consumer controls downstream output and its next-side producer.
    usercontrollerBandwidthSetExternalPause(t, l, false, true);
}
