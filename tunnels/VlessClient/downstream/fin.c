#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    vlessclientCloseLine(t, l, kVlessClientCloseFromNext);
}
