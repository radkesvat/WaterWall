#include "structure.h"

#include "loggers/network_logger.h"

void packetstostreamTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{

    discard t;
    discard l;

    LOGF("PacketsToStream: not supposed to receive upstream fin");
    abortProgramNow(1);
}
