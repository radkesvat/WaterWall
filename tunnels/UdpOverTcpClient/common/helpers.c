#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientCloseLine(tunnel_t *t, line_t *l)
{
    udpovertcpclientLinestateDestroy(lineGetState(l, t));
    if (lineCallWithRef(l, tunnelNextUpStreamFinish, t))
        tunnelPrevDownStreamFinish(t, l);
}
