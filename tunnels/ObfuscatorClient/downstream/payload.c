#include "loggers/network_logger.h"
#include "structure.h"

void obfuscatorclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorclient_tstate_t *ts     = tunnelGetState(t);
    const bool                 packet = tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l);
    if (ts->tls_record_header && ! packet)
    {
        obfuscatorclientDecodeStream(t, l, buf);
        return;
    }

    if (ts->tls_record_header && ! obfuscatorStripRecord(buf))
    {
        LOGW("ObfuscatorClient: malformed TLS-like packet dropped");
        lineReuseBuffer(l, buf);
        return;
    }
    obfuscatorApplyXor(buf, ts->skip, ts->xor_key);

    if (packet)
        sbufSetRecalculateChecksum(buf, true);
    tunnelPrevDownStreamPayload(t, l, buf);
}
