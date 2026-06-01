#include "structure.h"

#include "loggers/network_logger.h"

void encryptionserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    encryptionserver_lstate_t *ls = lineGetState(l, t);
    encryptionserverLinestateDestroy(ls);

    tunnelPrevDownStreamFinish(t, l);
}
