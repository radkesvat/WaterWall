#include "structure.h"

#include "loggers/network_logger.h"

void httpclientV2TunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    httpclientV2LinestateDestroy(lineGetState(l, t));

    tunnelPrevDownStreamFinish(t, l);
}
