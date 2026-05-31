#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;
    discard buf;
    LOGF("SpeedTestServer: downstream Payload is disabled");
    terminateProgram(1);
}

