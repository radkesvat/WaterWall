#include "WireGuardServer/structure.h"

void wireguardserverTunnelUpStreamFinish(tunnel_t *t, line_t *line)
{
    wireguardserverDetachIngress(t, line);
}
