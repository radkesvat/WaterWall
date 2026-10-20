#include "structure.h"

#include "../../Internals/AuthenticationCommon/credentials.h"
#include "../../Internals/AuthenticationCommon/stream.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    authenticationserver_lstate_t *ls = lineGetState(l, t);

    if (ls->reject_further_input)
    {
        lineReuseBuffer(l, buf);
        authenticationserverCloseLine(t, l, ls, "input after rejected authentication");
        return;
    }

    const uint32_t max_message =
        kAuthenticationServerMaxMessagePayload + kAuthenticationServerRequestEnvelopeHeaderSize;
    if (sbufGetLength(buf) == 0)
    {
        lineReuseBuffer(l, buf);
        return;
    }
    if (ls->processing_requests)
    {
        bool valid_token;
        if (! authenticationserverInputAllowance(t, &ls->read_stream, buf, &valid_token))
        {
            lineReuseBuffer(l, buf);
            authenticationserverCloseLine(t, l, ls, "nested request storage limit");
            return;
        }
        const uint32_t preauth_max =
            kAuthenticationPreAuthPayloadLimit + kAuthenticationServerRequestEnvelopeHeaderSize;
        buffer_pool_fit_t fit;
        const bool        fits =
            bufferpoolQueryBestFit(ls->pool, preauth_max, bufferpoolGetSmallBufferPadding(ls->pool), &fit);
        assert(fits);
        discard fits;
        if (! authenticationStreamPushNestedBounded(
                &ls->read_stream,
                buf,
                valid_token ? max_message + kAuthenticationStreamReentryHeadroom : preauth_max,
                valid_token ? kAuthenticationStreamChargeLimit : max((size_t) (128U * 1024U), fit.allocation_charge),
                valid_token ? kAuthenticationStreamEntryLimit : 64U))
        {
            lineReuseBuffer(l, buf);
            authenticationserverCloseLine(t, l, ls, "request storage limit");
        }
        return;
    }

    if (ts->verbose)
    {
        LOGD("AuthenticationServer: upstream payload bytes=%u", (unsigned int) sbufGetLength(buf));
    }

    lineRef(l);
    bufferstreamPush(&ls->read_stream, buf);
    if (authenticationserverProcessRequests(t, l, ls))
    {
        bool valid_token;
        if (! authenticationserverInputAllowance(t, &ls->read_stream, NULL, &valid_token))
        {
            authenticationserverCloseLine(t, l, ls, "incomplete request storage limit");
            lineUnref(l);
            return;
        }
        const uint32_t preauth_max =
            kAuthenticationPreAuthPayloadLimit + kAuthenticationServerRequestEnvelopeHeaderSize;
        buffer_pool_fit_t fit;
        const bool        fits =
            bufferpoolQueryBestFit(ls->pool, preauth_max, bufferpoolGetSmallBufferPadding(ls->pool), &fit);
        assert(fits);
        discard fits;
        authenticationStreamCompactIncompleteBounded(&ls->read_stream,
                                                     valid_token ? max_message : preauth_max,
                                                     valid_token ? kAuthenticationStreamChargeLimit
                                                                 : max((size_t) (128U * 1024U), fit.allocation_charge),
                                                     valid_token ? kAuthenticationStreamEntryLimit : 64U);
    }
    lineUnref(l);
}
