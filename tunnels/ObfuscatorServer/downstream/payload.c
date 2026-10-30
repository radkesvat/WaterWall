#include "loggers/network_logger.h"
#include "structure.h"

void obfuscatorserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorserver_tstate_t *ts     = tunnelGetState(t);
    const bool                 packet = tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l);
    if (ts->tls_record_header && ! packet)
    {
        obfuscatorserverEncodeStream(t, l, buf);
        return;
    }

    obfuscatorApplyXor(buf, ts->skip, ts->xor_key);
    if (ts->tls_record_header)
    {
        buf = obfuscatorWrapRecord(lineGetBufferPool(l), buf);
        if (! buf)
        {
            LOGW("ObfuscatorServer: oversized TLS-like packet dropped");
            return;
        }
    }

    if (packet)
        sbufSetRecalculateChecksum(buf, true);
    tunnelPrevDownStreamPayload(t, l, buf);
}
