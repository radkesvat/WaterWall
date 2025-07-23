#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("MuxClient: UpStreamEst is disabled");
    terminateProgram(1);
}
