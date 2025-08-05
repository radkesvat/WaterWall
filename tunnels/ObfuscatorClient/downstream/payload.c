#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorclient_tstate_t *ts = tunnelGetState(t);

    if (ts->method == kObfuscatorMethodXor)
    {
        obfuscatorclientXorByte(sbufGetMutablePtr(buf),sbufGetLength(buf), ts->xor_key);
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
