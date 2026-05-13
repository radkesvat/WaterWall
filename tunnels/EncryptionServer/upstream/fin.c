#include "structure.h"

#include "loggers/network_logger.h"

void encryptionserverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    lineLock(l);

    encryptionserver_lstate_t *ls = lineGetState(l, t);
    bool send_next = ! ls->next_finished;

    ls->next_finished = true;
    encryptionserverLinestateDestroy(ls);

    if (send_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineUnlock(l);
}
