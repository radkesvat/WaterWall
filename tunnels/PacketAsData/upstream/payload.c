#include "structure.h"

#include "loggers/network_logger.h"

void packetasdataTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    packetasdata_lstate_t *ls = (packetasdata_lstate_t *) lineGetState(l, t);

    if (ls->line == NULL)
    {
        LOGF("PacketAsData: in upstream we are supposed to have line");
        terminateProgram(1);
    }
    if (ls->paused)
    {
        bufferpoolReuseBuffer(lineGetBufferPool(l), buf);
        return;
    }
    tunnelNextUpStreamPayload(t, ls->line, buf);
}
