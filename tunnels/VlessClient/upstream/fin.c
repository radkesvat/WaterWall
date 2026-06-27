#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    vlessclientCloseLine(t, l, kVlessClientCloseFromPrev);
}
