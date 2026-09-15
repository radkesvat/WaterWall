#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorserver_tstate_t *ts = tunnelGetState(t);
    if (ts->tls_record_header && ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l))
    {
        obfuscatorserverEncodeStream(t, l, buf);
        return;
    }

    if (ts->method == kObfuscatorMethodXor)
    {
        obfuscatorserverApplyXor(t, l, buf);
    }

    if (ts->tls_record_header && ! obfuscatorserverWrapTlsRecordHeader(l, &buf))
    {
        return;
    }

    if (l == tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)))
    {
        l->recalculate_checksum = true;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
