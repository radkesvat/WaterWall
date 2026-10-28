#include "loggers/network_logger.h"
#include "structure.h"

void obfuscatorserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorserver_tstate_t *ts     = tunnelGetState(t);
    const bool                 packet = tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l);
    if (ts->tls_record_header && ! packet)
    {
        obfuscatorserverDecodeStream(t, l, buf);
        return;
    }

    if (ts->tls_record_header && ! obfuscatorStripRecord(buf))
    {
        LOGW("ObfuscatorServer: malformed TLS-like packet dropped");
        lineReuseBuffer(l, buf);
        return;
    }
    obfuscatorApplyXor(buf, ts->skip, ts->xor_key);

    if (packet)
        sbufSetRecalculateChecksum(buf, true);
    tunnelNextUpStreamPayload(t, l, buf);
}
