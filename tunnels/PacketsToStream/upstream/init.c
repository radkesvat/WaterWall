#include "structure.h"

#include "loggers/network_logger.h"

void packetstostreamTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    packetstostream_lstate_t *ls = lineGetState(l, t);
    bool                      created;
    line_t                   *stream_line = packetstostreamEnsureOutputLine(t, l, ls, &created);
    if (created)
    {
        packetstostreamResumePacketSource(t, l, ls, stream_line);
    }
}
