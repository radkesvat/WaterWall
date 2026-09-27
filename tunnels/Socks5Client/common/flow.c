#include "internal.h"

#include "loggers/network_logger.h"

bool socks5clientMaybeSendGreeting(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);
    if (! ls->greeting_due || ls->next_paused)
        return true;
    ls->greeting_due = false;
    return socks5clientSendGreeting(t, l, ls);
}

static bool updateSourcePressure(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls     = lineGetState(l, t);
    const bool             paused = ls->next_paused || ls->draining_up || bufferqueueGetBufCount(&ls->pending_up) != 0;
    if (ls->source_pause_sent == paused)
        return true;
    ls->source_pause_sent = paused;
    return paused ? lineCallWithRef(l, tunnelPrevDownStreamPause, t)
                  : lineCallWithRef(l, tunnelPrevDownStreamResume, t);
}

bool socks5clientQueuePayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    socks5client_lstate_t *ls = lineGetState(l, t);
    if (UNLIKELY(! bufferqueueTryPushBack(&ls->pending_up, &buf)))
    {
        lineReuseBuffer(l, buf);
        socks5clientCloseLineBidirectional(t, l);
        return false;
    }
    return updateSourcePressure(t, l);
}

bool socks5clientDrainPending(tunnel_t *t, line_t *l)
{
    socks5client_lstate_t *ls = lineGetState(l, t);
    if (ls->draining_up || ls->phase != kSocks5ClientPhaseEstablished)
        return true;
    lineRef(l);
    ls->draining_up = true;
    while (lineIsAlive(l) && ! ls->next_paused && bufferqueueGetBufCount(&ls->pending_up) != 0)
    {
        sbuf_t *buf = bufferqueuePopFront(&ls->pending_up);
        if (ls->kind == kSocks5ClientLineKindUdpApplication)
        {
            if (UNLIKELY(! socks5clientForwardUdpPayloadToRelay(t, l, ls, buf)))
                break;
        }
        else
            tunnelNextUpStreamPayload(t, l, buf);
    }
    bool alive = lineIsAlive(l);
    if (alive)
    {
        ls->draining_up = false;
        alive           = updateSourcePressure(t, l);
    }
    lineUnref(l);
    return alive;
}

void socks5clientSetNextPaused(tunnel_t *t, line_t *l, bool paused)
{
    socks5client_lstate_t *ls = lineGetState(l, t);
    ls->next_paused           = paused;
    if (! paused && ! socks5clientMaybeSendGreeting(t, l))
        return;
    line_t *application = (ls->kind == kSocks5ClientLineKindUdpControl || ls->kind == kSocks5ClientLineKindUdpRelay)
                              ? ls->application_line
                              : l;
    if (application == NULL)
        return;
    socks5client_lstate_t *application_ls = lineGetState(application, t);
    if (application != l)
    {
        socks5client_lstate_t *control =
            application_ls->control_line ? lineGetState(application_ls->control_line, t) : NULL;
        socks5client_lstate_t *relay = application_ls->udp_line ? lineGetState(application_ls->udp_line, t) : NULL;
        application_ls->next_paused  = (control && control->next_paused) || (relay && relay->next_paused);
    }
    if (application_ls->next_paused)
    {
        discard updateSourcePressure(t, application);
        return;
    }
    if (UNLIKELY(! socks5clientDrainPending(t, application)))
        return;
    discard updateSourcePressure(t, application);
}
