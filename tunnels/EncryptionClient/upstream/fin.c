#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    lineLock(l);

    encryptionclient_lstate_t *ls = lineGetState(l, t);
    bool send_next = ! ls->next_finished;

    ls->next_finished = true;
    encryptionclientLinestateDestroy(ls);

    if (send_next)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineUnlock(l);
}
