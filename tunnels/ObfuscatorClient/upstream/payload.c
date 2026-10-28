#include "loggers/network_logger.h"
#include "structure.h"

void obfuscatorclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorclient_tstate_t *ts     = tunnelGetState(t);
    const bool                 packet = tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l);
    if (ts->tls_record_header && ! packet)
    {
        obfuscatorclientEncodeStream(t, l, buf);
        return;
    }

    obfuscatorApplyXor(buf, ts->skip, ts->xor_key);
    if (ts->tls_record_header)
    {
        buf = obfuscatorWrapRecord(lineGetBufferPool(l), buf);
        if (! buf)
        {
            LOGW("ObfuscatorClient: oversized TLS-like packet dropped");
            return;
        }
    }

    if (packet)
        sbufSetRecalculateChecksum(buf, true);
    tunnelNextUpStreamPayload(t, l, buf);
}
