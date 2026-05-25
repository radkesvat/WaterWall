#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    obfuscatorserver_tstate_t *ts = tunnelGetState(t);

    if (ts->tls_record_header && ! obfuscatorserverStripTlsRecordHeader(l, buf))
    {
        return;
    }

    if (ts->method == kObfuscatorMethodXor)
    {
        obfuscatorserverApplyXor(t, l, buf);
    }

    if (l == tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l)))
    {
        l->recalculate_checksum = true;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
