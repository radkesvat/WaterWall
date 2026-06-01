#include "structure.h"

#include "loggers/network_logger.h"

void encryptionserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    encryptionserver_lstate_t *ls = lineGetState(l, t);
    encryptionserverLinestateDestroy(ls);

    tunnelNextUpStreamFinish(t, l);
}
