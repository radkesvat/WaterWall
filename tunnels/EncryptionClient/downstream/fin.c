#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    encryptionclient_lstate_t *ls = lineGetState(l, t);
    encryptionclientLinestateDestroy(ls);

    tunnelPrevDownStreamFinish(t, l);
}
