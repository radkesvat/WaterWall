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
        const uint32_t packet_bytes = sbufGetLength(buf);
        buf = obfuscatorWrapRecord(lineGetBufferPool(l), buf);
        if (! buf)
        {
            LOGW("ObfuscatorServer: dropping TLS-like packet: record body exceeds protocol limit "
                 "(packet_bytes=%u, protocol_body_limit_bytes=%u)",
                 packet_bytes,
                 (unsigned) UINT16_MAX);
            return;
        }
    }

    if (packet)
        sbufSetRecalculateChecksum(buf, true);
    tunnelPrevDownStreamPayload(t, l, buf);
}
