#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorserver_tstate_t *ts = tunnelGetState(t);
    if (ts->tls_record_header && ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
    {
        obfuscatorserverDecodeStream(t, l, buf);
        return;
    }

    if (ts->tls_record_header && ! obfuscatorserverStripTlsRecordHeader(l, buf))
    {
        return;
    }

    obfuscatorserverApplyXor(t, l, buf);

    if (l == tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)))
    {
        sbufSetRecalculateChecksum(buf, true);
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
