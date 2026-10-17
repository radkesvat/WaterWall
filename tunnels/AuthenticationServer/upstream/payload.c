#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    const size_t byte_limit = kAuthenticationServerMaxMessagePayload + kAuthenticationServerRequestEnvelopeHeaderSize;
    size_t       charge     = sbufGetAllocationCharge(buf);
    const ptrdiff_t count   = bs_doublequeue_t_size(&ls->read_stream.q);
    for (ptrdiff_t i = 0; i < count && charge <= 32U * 1024U * 1024U; ++i)
    {
        const size_t entry = sbufGetAllocationCharge(*bs_doublequeue_t_at(&ls->read_stream.q, i));
        if (entry > 32U * 1024U * 1024U - charge)
            charge = 32U * 1024U * 1024U + 1U;
        else
            charge += entry;
    }
    if (sbufGetLength(buf) > byte_limit || bufferstreamGetBufLen(&ls->read_stream) > byte_limit - sbufGetLength(buf) ||
        count >= 1024 || charge > 32U * 1024U * 1024U)
    {
        lineReuseBuffer(l, buf);
        authenticationserverCloseLine(t, l, ls, "request storage limit");
        return;
    }

    if (ts->verbose)
    {
        LOGD("AuthenticationServer: upstream payload bytes=%u", (unsigned int) sbufGetLength(buf));
    }

    bufferstreamPush(&ls->read_stream, buf);
    discard authenticationserverProcessRequests(t, l, ls);
}
