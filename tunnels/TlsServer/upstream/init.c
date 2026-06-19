#include "structure.h"

#include "loggers/network_logger.h"

void tlsserverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tlsserver_tstate_t *ts = tunnelGetState(t);
    tlsserver_lstate_t *ls = lineGetState(l, t);

    if (ts->verbose)
    {
        LOGD("TlsServer: worker %u initializing TLS server line", (unsigned int) lineGetWID(l));
    }

    if (! tlsserverLinestateInitialize(ls, ts->threadlocal_ssl_contexts[lineGetWID(l)], lineGetBufferPool(l),
                                       ts->verbose))
    {
        LOGE("TlsServer: failed to initialize per-line OpenSSL state");
        tunnelPrevDownStreamFinish(t, l);
        return;
    }

    tlsserverArmHandshakeDeadline(t, l, ls);

    if (ts->verbose)
    {
        LOGD("TlsServer: worker %u TLS server line initialized%s",
             (unsigned int) lineGetWID(l),
             ts->fallback_tunnel == NULL ? "; forwarding upstream Init" : "; waiting for TLS classification");
    }
    if (ts->fallback_tunnel == NULL)
    {
        discard tlsserverStartProtectedBranch(t, l, ls);
    }
}
