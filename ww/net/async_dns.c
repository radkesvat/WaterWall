#include "async_dns.h"

#include "wevent.h"
#include "wsocket.h"

typedef struct asyncdns_request_s
{
    dns_resolver_t *resolver;
    dns_resolve_cb  cb;
    void           *userdata;
    char           *host;
    char           *service;
} asyncdns_request_t;

static void asyncdnsTimerCallback(wtimer_t *timer);

static dns_watch_t *asyncdnsFindWatch(dns_resolver_t *r, ares_socket_t fd)
{
    for (dns_watch_t *watch = r->watches; watch != NULL; watch = watch->next)
    {
        if (watch->fd == fd)
        {
            return watch;
        }
    }

    return NULL;
}

static void asyncdnsRefreshTimer(dns_resolver_t *r);

static void asyncdnsReleaseWatch(dns_resolver_t *r, dns_watch_t *watch)
{
    dns_watch_t **link = &r->watches;
    while (*link != NULL && *link != watch)
    {
        link = &(*link)->next;
    }

    if (*link == watch)
    {
        *link = watch->next;
    }

    if (watch->io != NULL)
    {
        weventSetUserData(watch->io, NULL);
        wioReleaseNoClose(watch->io);
    }

    memoryFree(watch);
}

static void asyncdnsProcessFd(dns_resolver_t *r, ares_socket_t fd, unsigned int events)
{
    if (r->shutting_down || r->channel == NULL)
    {
        return;
    }

    ares_fd_events_t ev = {.fd = fd, .events = events};
    (void) ares_process_fds(r->channel, &ev, 1, ARES_PROCESS_FLAG_NONE);
    asyncdnsRefreshTimer(r);
}

static void asyncdnsIoCallback(wio_t *io)
{
    dns_watch_t *watch = weventGetUserdata(io);
    if (watch == NULL)
    {
        return;
    }

    unsigned int events = ARES_FD_EVENT_NONE;
    if (wioGetREvents(io) & WW_READ)
    {
        events |= ARES_FD_EVENT_READ;
    }
    if (wioGetREvents(io) & WW_WRITE)
    {
        events |= ARES_FD_EVENT_WRITE;
    }

    io->revents = 0;

    if (events != ARES_FD_EVENT_NONE)
    {
        asyncdnsProcessFd(watch->resolver, watch->fd, events);
    }
}

static void asyncdnsSockStateCallback(void *data, ares_socket_t fd, int readable, int writable)
{
    dns_resolver_t *r      = data;
    int             events = 0;

    if (readable)
    {
        events |= WW_READ;
    }
    if (writable)
    {
        events |= WW_WRITE;
    }

    dns_watch_t *watch = asyncdnsFindWatch(r, fd);
    if (events == 0)
    {
        if (watch != NULL)
        {
            asyncdnsReleaseWatch(r, watch);
        }
        asyncdnsRefreshTimer(r);
        return;
    }

    if (r->shutting_down)
    {
        return;
    }

    if (watch == NULL)
    {
        watch = memoryAllocate(sizeof(*watch));
        *watch = (dns_watch_t) {
            .fd       = fd,
            .io       = wioGet(r->loop, fd),
            .events   = 0,
            .resolver = r,
            .next     = r->watches,
        };
        r->watches = watch;

        // wioReady() detects UDP sockets and makes them blocking for normal
        // datagram users. c-ares expects its sockets to remain non-blocking.
        nonBlocking(fd);
        watch->io->priority = WEVENT_HIGH_PRIORITY;
        weventSetUserData(watch->io, watch);
    }

    int add_events = events & ~watch->events;
    int del_events = watch->events & ~events;

    if (del_events != 0)
    {
        wioDel(watch->io, del_events);
    }
    if (add_events != 0)
    {
        wioAdd(watch->io, asyncdnsIoCallback, add_events);
    }

    watch->events = events;
    asyncdnsRefreshTimer(r);
}

static uint32_t asyncdnsTimeoutMs(dns_resolver_t *r)
{
    struct timeval  tv;
    struct timeval  max_tv = {.tv_sec = 1, .tv_usec = 0};
    struct timeval *next   = ares_timeout(r->channel, &max_tv, &tv);

    if (next == NULL)
    {
        return 0;
    }

    uint64_t timeout_ms = ((uint64_t) next->tv_sec * 1000ULL) + ((uint64_t) (next->tv_usec + 999) / 1000ULL);
    if (timeout_ms == 0)
    {
        timeout_ms = 1;
    }
    if (timeout_ms > UINT32_MAX)
    {
        timeout_ms = UINT32_MAX;
    }

    return (uint32_t) timeout_ms;
}

static void asyncdnsRefreshTimer(dns_resolver_t *r)
{
    if (r->shutting_down || r->channel == NULL)
    {
        return;
    }

    if (ares_queue_active_queries(r->channel) == 0)
    {
        if (r->timer != NULL)
        {
            wtimerDelete(r->timer);
            r->timer = NULL;
        }
        return;
    }

    uint32_t timeout_ms = asyncdnsTimeoutMs(r);
    if (timeout_ms == 0)
    {
        return;
    }

    if (r->timer == NULL)
    {
        r->timer = wtimerAdd(r->loop, asyncdnsTimerCallback, timeout_ms, 1);
        if (r->timer != NULL)
        {
            weventSetUserData(r->timer, r);
        }
    }
    else
    {
        wtimerReset(r->timer, timeout_ms);
    }
}

static void asyncdnsTimerCallback(wtimer_t *timer)
{
    dns_resolver_t *r = weventGetUserdata(timer);
    if (r == NULL || r->shutting_down || r->channel == NULL)
    {
        return;
    }

    (void) ares_process_fds(r->channel, NULL, 0, ARES_PROCESS_FLAG_NONE);
    asyncdnsRefreshTimer(r);
}

static size_t asyncdnsCountAddrs(const struct ares_addrinfo *res)
{
    size_t count = 0;
    if (res == NULL)
    {
        return 0;
    }

    for (const struct ares_addrinfo_node *node = res->nodes; node != NULL; node = node->ai_next)
    {
        if ((node->ai_family == AF_INET || node->ai_family == AF_INET6) &&
            node->ai_addr != NULL && node->ai_addrlen <= sizeof(struct sockaddr_storage))
        {
            ++count;
        }
    }

    return count;
}

static void asyncdnsCopyAddrs(dns_resolved_addr_t *out, const struct ares_addrinfo *res)
{
    size_t index = 0;

    for (const struct ares_addrinfo_node *node = res->nodes; node != NULL; node = node->ai_next)
    {
        if ((node->ai_family != AF_INET && node->ai_family != AF_INET6) ||
            node->ai_addr == NULL || node->ai_addrlen > sizeof(out[index].addr))
        {
            continue;
        }

        memoryZero(&out[index], sizeof(out[index]));
        memoryCopy(&out[index].addr, node->ai_addr, node->ai_addrlen);
        out[index].addrlen = node->ai_addrlen;
        out[index].family  = node->ai_family;
        out[index].ttl     = node->ai_ttl;
        ++index;
    }
}

static void asyncdnsRequestDestroy(asyncdns_request_t *req)
{
    if (req == NULL)
    {
        return;
    }

    memoryFree(req->host);
    memoryFree(req->service);
    memoryFree(req);
}

static void asyncdnsAddrInfoCallback(void *arg, int status, int timeouts, struct ares_addrinfo *res)
{
    discard timeouts;

    asyncdns_request_t *req   = arg;
    dns_resolved_addr_t *addrs = NULL;
    size_t               count = 0;
    int                  cb_status = status;

    if (status == ARES_SUCCESS)
    {
        count = asyncdnsCountAddrs(res);
        if (count == 0)
        {
            cb_status = ARES_ENODATA;
        }
        else
        {
            addrs = memoryAllocate(sizeof(*addrs) * count);
            asyncdnsCopyAddrs(addrs, res);
        }
    }

    req->cb(req->userdata, cb_status, ares_strerror(cb_status), addrs, count);

    memoryFree(addrs);
    ares_freeaddrinfo(res);
    asyncdnsRequestDestroy(req);
}

int asyncdnsInit(dns_resolver_t *r, wloop_t *loop)
{
    if (r == NULL || loop == NULL)
    {
        return ARES_EFORMERR;
    }

    memoryZero(r, sizeof(*r));
    r->loop = loop;

    struct ares_options options;
    memoryZero(&options, sizeof(options));
    options.sock_state_cb      = asyncdnsSockStateCallback;
    options.sock_state_cb_data = r;

    int rc = ares_init_options(&r->channel, &options, ARES_OPT_SOCK_STATE_CB);
    if (rc != ARES_SUCCESS)
    {
        memoryZero(r, sizeof(*r));
        return rc;
    }

    return ARES_SUCCESS;
}

void asyncdnsCleanup(dns_resolver_t *r)
{
    if (r == NULL)
    {
        return;
    }

    r->shutting_down = 1;

    if (r->timer != NULL)
    {
        wtimerDelete(r->timer);
        r->timer = NULL;
    }

    if (r->channel != NULL)
    {
        ares_cancel(r->channel);
        ares_destroy(r->channel);
        r->channel = NULL;
    }

    while (r->watches != NULL)
    {
        asyncdnsReleaseWatch(r, r->watches);
    }

    memoryZero(r, sizeof(*r));
}

int asyncdnsResolve(dns_resolver_t *r, const char *host, const char *service, int socktype, dns_resolve_cb cb,
                    void *userdata)
{
    if (r == NULL || r->channel == NULL || host == NULL || host[0] == '\0' || cb == NULL)
    {
        return ARES_EFORMERR;
    }

    if (r->shutting_down)
    {
        return ARES_ECANCELLED;
    }

    asyncdns_request_t *req = memoryAllocate(sizeof(*req));
    *req = (asyncdns_request_t) {
        .resolver  = r,
        .cb        = cb,
        .userdata  = userdata,
        .host      = stringDuplicate(host),
        .service   = service != NULL ? stringDuplicate(service) : NULL,
    };

    struct ares_addrinfo_hints hints;
    memoryZero(&hints, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = socktype;

    ares_getaddrinfo(r->channel, req->host, req->service, &hints, asyncdnsAddrInfoCallback, req);
    asyncdnsRefreshTimer(r);

    return ARES_SUCCESS;
}
