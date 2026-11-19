#include "structure.h"

void halfduplexclientTunnelDownStreamEst(tunnel_t *t, line_t *child)
{
    halfduplexclient_pair_t *pair = halfduplexclientGetPair(t, child);
    if (pair != NULL && pair->main != NULL && ! pair->ending)
    {
        pair->est_seen = true;
        halfduplexclientNotifyEstablished(pair);
    }
}
