#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->upload_line);
    tunnelPrevDownStreamPause(t, ls->upload_line);
}
