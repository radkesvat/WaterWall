#include "structure.h"

#include "loggers/network_logger.h"

void encryptionserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    lineLock(l);

    encryptionserver_lstate_t *ls = lineGetState(l, t);
    bool send_prev = ! ls->prev_finished;

    ls->prev_finished = true;
    encryptionserverLinestateDestroy(ls);

    if (send_prev)
    {
        tunnelPrevDownStreamFinish(t, l);
    }

    lineUnlock(l);
}
