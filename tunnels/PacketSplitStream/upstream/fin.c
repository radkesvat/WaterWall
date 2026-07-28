#include "structure.h"

#include "loggers/network_logger.h"

void packetsplitstreamTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("packetsplitstreamTunnelUpStreamFinish is not supposed to be called");
    abortProgramNow(1);
}
