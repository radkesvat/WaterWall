#include "structure.h"

#include "../../Internals/AuthenticationCommon/stream.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    authenticationclient_lstate_t *ls = lineGetState(l, t);
    const uint32_t                 max_message =
        kAuthenticationClientMaxResponsePayload + kAuthenticationClientResponseEnvelopeHeaderSize;
    if (sbufGetLength(buf) == 0)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->processing_responses)
    {
        if (! authenticationStreamPushNested(&ls->read_stream, buf, max_message))
        {
            lineReuseBuffer(l, buf);
            authenticationclientRecoverControlLine(t, l, true);
        }
        return;
    }

    /* Publish the complete delivery before callbacks: its unread suffix must
     * precede nested input. Only incomplete input remains after the drain. */
    lineRef(l);
    bufferstreamPush(&ls->read_stream, buf);
    if (authenticationclientProcessResponses(t, l, ls))
        authenticationStreamCompactIncomplete(&ls->read_stream, max_message);
    lineUnref(l);
}
