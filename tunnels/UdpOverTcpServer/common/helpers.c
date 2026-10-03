#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverCloseLine(tunnel_t *t, line_t *l)
{
    udpovertcpserverLinestateDestroy(lineGetState(l, t));
    if (lineCallWithRef(l, tunnelNextUpStreamFinish, t))
        tunnelPrevDownStreamFinish(t, l);
}
