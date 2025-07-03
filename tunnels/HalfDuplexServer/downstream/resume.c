#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    halfduplexserver_lstate_t *ls = lineGetState(l, t);
    assert(ls->upload_line);
    tunnelPrevDownStreamResume(t, ls->upload_line);
}
