#include "structure.h"

#include "loggers/network_logger.h"

void muxclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("MuxClient: DownStreamInit is disabled");
    terminateProgram(1);
}
