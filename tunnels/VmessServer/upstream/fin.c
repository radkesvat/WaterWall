#include "internal.h"

void vmessserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    vmessserverCloseLineFromUpstream(t, l);
}
