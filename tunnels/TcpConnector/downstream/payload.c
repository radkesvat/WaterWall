#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;
    discard buf;
    LOGF("TcpConnector: downStreamPayload disabled");
    assert(false);
}
