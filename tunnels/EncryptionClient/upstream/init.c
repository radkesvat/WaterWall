#include "structure.h"

#include "loggers/network_logger.h"

void encryptionclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    encryptionclient_lstate_t *ls = lineGetState(l, t);
    encryptionclientLinestateInitialize(ls, lineGetBufferPool(l));

    tunnelNextUpStreamInit(t, l);
}
