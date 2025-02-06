#include "structure.h"

#include "loggers/network_logger.h"

void wireguarddeviceTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, l, buf);
}
