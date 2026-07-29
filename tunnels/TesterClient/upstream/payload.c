#include "structure.h"

#include "loggers/network_logger.h"

void testerclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;
    discard buf;
    LOGF("TesterClient: upStreamPayload disabled");
    abortProgramNow(1);
}
