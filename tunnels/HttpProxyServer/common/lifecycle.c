#include "structure.h"

void hpsRetain(hps_session_t *s)
{
    ++s->references;
}

void hpsRelease(hps_session_t *s)
{
    if (--s->references == 0)
    {
        assert(s->phase == kHpsClosed);
        lineUnref(s->client);
        memoryZero(s->credentials, sizeof(s->credentials));
        memoryFree(s);
    }
}

void hpsClearLineState(line_t *l, tunnel_t *t)
{
    memoryZeroAligned32(lineGetState(l, t), tunnelGetCorrectAlignedLineStateSize(sizeof(hps_lstate_t)));
}

void hpsDetachTimer(hps_session_t *s)
{
    if (! s->timer)
        return;
    hps_worker_t *w = &hpsSettings(s)->workers[lineGetWID(s->client)];
    if (s->timer_prev)
        s->timer_prev->timer_next = s->timer_next;
    else
        w->timers = s->timer_next;
    if (s->timer_next)
        s->timer_next->timer_prev = s->timer_prev;
    wtimer_t *timer = s->timer;
    s->timer        = NULL;
    s->timer_prev = s->timer_next = NULL;
    weventSetUserData(timer, NULL);
    wtimerDelete(timer);
}

void hpsCloseChild(hps_session_t *s, bool from_child)
{
    line_t *child = s->child;
    if (! child)
        return;
    hps_lstate_t *ls               = lineGetState(child, s->t);
    hps_worker_t *w                = &hpsSettings(s)->workers[lineGetWID(child)];
    tunnel_t     *entry            = s->child_entry;
    s->child_entry                 = NULL;
    s->child                       = NULL;
    s->child_established           = false;
    s->connect_at                  = 0;
    s->paused[kHpsUpstream]        = false;
    s->read_paused[kHpsDownstream] = false;
    if (ls->prev)
        ls->prev->next = ls->next;
    else
        w->children = ls->next;
    if (ls->next)
        ls->next->prev = ls->prev;
    lineRef(child);
    hpsClearLineState(child, s->t);
    if (! from_child)
        entry->fnFinU(entry, child);
    lineDestroy(child);
    lineUnref(child);
}

void hpsClose(hps_session_t *s, bool from_client)
{
    if (s->phase == kHpsClosed)
        return;
    s->phase = kHpsClosed;
    hpsDetachTimer(s);
    hpsClearLineState(s->client, s->t);
    hpsCloseChild(s, false);
    for (unsigned i = 0; i < 2; ++i)
    {
        hpsDiscardBuffer(s, &s->input[i]);
        hpsDiscardBuffer(s, &s->output[i]);
        hpsDiscardBuffer(s, &s->deferred[i]);
        hpsDiscardBuffer(s, &s->incoming[i]);
        hpsClearHeader(s, i);
    }
    if (! from_client)
        tunnelPrevDownStreamFinish(s->t, s->client);
    hpsRelease(s); /* borrowed client slot's session reference */
}

void hpsCreateChild(hps_session_t *s, const char *username, const char *password)
{
    line_t       *l  = lineCreate(tunnelchainGetLinePools(tunnelGetChain(s->t)), lineGetWID(s->client));
    hps_lstate_t *ls = lineGetState(l, s->t);
    *ls              = (hps_lstate_t) {.session = s, .line = l, .child = true};
    hps_worker_t *w  = &hpsSettings(s)->workers[lineGetWID(l)];
    ls->next         = w->children;
    if (ls->next)
        ls->next->prev = ls;
    w->children    = ls;
    s->child       = l;
    s->child_entry = s->phase == kHpsFallback ? hpsSettings(s)->fallback : s->t->next;
    s->child_eof   = false;
    s->connect_at  = hpsNowMs(s);
    addresscontextCopy(lineGetSourceAddressContext(l), lineGetSourceAddressContext(s->client));
    lineGetRoutingContext(l)->local_listener_port = lineGetRoutingContext(s->client)->local_listener_port;
    lineGetRoutingContext(l)->peer_source_port    = lineGetRoutingContext(s->client)->peer_source_port;
    lineCopyUsers(l, s->client);
    if (s->phase != kHpsFallback)
    {
        if (s->auth_mode == kHpsAuthLocal)
            lineAddAuthenticatedCredentials(l, username, password);
        else if (s->auth_mode == kHpsAuthTracked)
        {
            lineAddUser(l, &s->identity, username, password);
        }
        address_context_t *dest = lineGetDestinationAddressContext(l);
        if (s->authority.literal)
            addresscontextSetIp(dest, &s->authority.ip);
        else
            addresscontextDomainSetByString(dest, s->authority.host);
        addresscontextSetPort(dest, s->authority.port);
        addresscontextSetOnlyProtocol(dest, IP_PROTO_TCP);
    }
    lineRef(l);
    s->child_initializing = true;
    s->child_entry->fnInitU(s->child_entry, l);
    s->child_initializing = false;
    lineUnref(l);
}
