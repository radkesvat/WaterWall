#include "structure.h"

void usercontrollerTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    // The next consumer controls upstream output and its prev-side producer.
    usercontrollerBandwidthSetExternalPause(t, l, true, true);
}
