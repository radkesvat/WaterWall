#include "structure.h"

void halfduplexclientTunnelDownStreamPayload(tunnel_t *t, line_t *child, sbuf_t *buf)
{
    halfduplexclient_pair_t *pair = halfduplexclientGetPair(t, child);
    if (pair != NULL && pair->main != NULL && ! pair->ending)
        tunnelPrevDownStreamPayload(t, pair->main, buf);
    else
        lineReuseBuffer(child, buf);
}
