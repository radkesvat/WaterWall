#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    halfduplexclient_lstate_t *ls = lineGetState(l, t);
    assert(l == ls->download_line);

    tunnelPrevDownStreamPayload(t, ls->main_line, buf);
}
