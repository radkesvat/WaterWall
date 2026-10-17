#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    authenticationclient_lstate_t *ls = lineGetState(l, t);
    const size_t    limit  = kAuthenticationClientMaxResponsePayload + kAuthenticationClientResponseEnvelopeHeaderSize;
    size_t          charge = sbufGetAllocationCharge(buf);
    const ptrdiff_t count  = bs_doublequeue_t_size(&ls->read_stream.q);
    for (ptrdiff_t i = 0; i < count && charge <= 32U * 1024U * 1024U; ++i)
    {
        const size_t entry = sbufGetAllocationCharge(*bs_doublequeue_t_at(&ls->read_stream.q, i));
        if (entry > 32U * 1024U * 1024U - charge)
            charge = 32U * 1024U * 1024U + 1U;
        else
            charge += entry;
    }
    if (sbufGetLength(buf) > limit || bufferstreamGetBufLen(&ls->read_stream) > limit - sbufGetLength(buf) ||
        count >= 1024 || charge > 32U * 1024U * 1024U)
    {
        lineReuseBuffer(l, buf);
        authenticationclientRecoverControlLine(t, l, true);
        return;
    }

    lineRef(l);
    bufferstreamPush(&ls->read_stream, buf);
    discard authenticationclientProcessResponses(t, l, ls);
    lineUnref(l);
}
