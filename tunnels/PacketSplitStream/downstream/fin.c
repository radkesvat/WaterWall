#include "structure.h"

#include "loggers/network_logger.h"

void packetsplitstreamTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("packetsplitstreamTunnelDownStreamFinish is not supposed to be called");
    abortProgramNow(1);
}
