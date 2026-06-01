#include "structure.h"

void realityclientTunnelOnStart(tunnel_t *t)
{
    realityclient_tstate_t *ts = tunnelGetState(t);
    if (ts->tls_tunnel != NULL)
    {
        ts->tls_tunnel->onStart(ts->tls_tunnel);
    }
}
