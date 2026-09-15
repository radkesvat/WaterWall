#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorclient_tstate_t *ts = tunnelGetState(t);
    if (ts->tls_record_header && ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
    {
        obfuscatorclientDecodeStream(t, l, buf);
        return;
    }

    if (ts->tls_record_header && ! obfuscatorclientStripTlsRecordHeader(l, buf))
    {
        return;
    }

    if (ts->method == kObfuscatorMethodXor)
    {
        obfuscatorclientApplyXor(t, l, buf);
    }

    if (l == tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)))
    {
        l->recalculate_checksum = true;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
