#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{

    obfuscatorserver_tstate_t *ts = tunnelGetState(t);

    if (ts->method == kObfuscatorMethodXor)
    {
        obfuscatorserverXorByte(sbufGetMutablePtr(buf), sbufGetLength(buf), ts->xor_key);
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
