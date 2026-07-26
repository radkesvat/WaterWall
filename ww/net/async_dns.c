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

enum
{
    kAsyncDnsQueryCacheMaxTtlSeconds    = 30 * 60,
    kAsyncDnsInitialTimeoutMs           = 1000,
    kAsyncDnsMaxTimeoutMs               = 5000,
    kAsyncDnsTries                      = 2,
    kAsyncDnsServerFailoverRetryChance  = 10,
    kAsyncDnsServerFailoverRetryDelayMs = 5000,
    kAsyncDnsIocpPollIntervalMs         = 20
};

static void asyncdnsTimerCallback(wtimer_t *timer);

void asyncdnsOptionsSetDefaults(asyncdns_options_t *options)
{
    assert(options != NULL);

    memoryZero(options, sizeof(*options));
    options->defaults_initialized            = true;
    options->query_cache_max_ttl             = kAsyncDnsQueryCacheMaxTtlSeconds;
    options->timeout_ms                      = kAsyncDnsInitialTimeoutMs;
    options->max_timeout_ms                  = kAsyncDnsMaxTimeoutMs;
    options->tries                           = kAsyncDnsTries;
    options->server_failover_retry_chance    = kAsyncDnsServerFailoverRetryChance;
    options->server_failover_retry_delay_ms  = kAsyncDnsServerFailoverRetryDelayMs;
}

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

#ifndef EVENT_IOCP
static void asyncdnsProcessFd(dns_resolver_t *r, ares_socket_t fd, unsigned int fd_events)
{
    if (r->shutting_down || r->channel == NULL)
    {
        return;
    }

    ares_fd_events_t ev = {.fd = fd, .events = fd_events};
    discard          ares_process_fds(r->channel, &ev, 1, ARES_PROCESS_FLAG_NONE);
    asyncdnsRefreshTimer(r);
}

static void asyncdnsIoCallback(wio_t *io)
{
    dns_watch_t *watch = weventGetUserdata(io);
    if (watch == NULL)
    {
        return;
    }

    unsigned int fd_events = ARES_FD_EVENT_NONE;
    if (wioGetREvents(io) & WW_READ)
    {
        fd_events |= ARES_FD_EVENT_READ;
    }
    if (wioGetREvents(io) & WW_WRITE)
    {
        fd_events |= ARES_FD_EVENT_WRITE;
    }

    io->revents = 0;

    if (fd_events != ARES_FD_EVENT_NONE)
    {
        asyncdnsProcessFd(watch->resolver, watch->fd, fd_events);
    }
}
#endif

static void asyncdnsSockStateCallback(void *data, ares_socket_t fd, int readable, int writable)
{
    dns_resolver_t *r         = data;
    int             io_events = 0;

    if (readable)
    {
        io_events |= WW_READ;
    }
    if (writable)
    {
        io_events |= WW_WRITE;
    }

    dns_watch_t *watch = asyncdnsFindWatch(r, fd);
    if (io_events == 0)
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
#ifndef EVENT_IOCP
        // wioReady() keeps every socket nonblocking, exactly what c-ares
        // expects; a socket it cannot switch comes back closed and rejected.
        wio_t *io = wioGet(r->loop, fd);
        if (UNLIKELY(wioIsClosed(io)))
        {
            // nothing to watch; c-ares observes the failure on its own
            // socket operations and times the query out
            return;
        }
#endif
        watch  = memoryAllocate(sizeof(*watch));
        *watch = (dns_watch_t) {
            .fd = fd,
#ifndef EVENT_IOCP
            .io = io,
#else
            // The native IOCP backend has no readiness model: a bare wioAdd()
            // posts no overlapped operation and therefore never calls back.
            // asyncdnsTimerCallback() polls these descriptors instead, so no wio
            // wrapper is created. c-ares opens its own sockets nonblocking.
            .io = NULL,
#endif
            .events   = 0,
            .resolver = r,
            .next     = r->watches,
        };
        r->watches = watch;

#ifndef EVENT_IOCP
        watch->io->priority = WEVENT_HIGH_PRIORITY;
        weventSetUserData(watch->io, watch);
#endif
    }

#ifndef EVENT_IOCP
    int add_events = io_events & ~watch->events;
    int del_events = watch->events & ~io_events;

    if (del_events != 0)
    {
        wioDel(watch->io, del_events);
    }
    if (add_events != 0)
    {
        if (UNLIKELY(wioAdd(watch->io, asyncdnsIoCallback, add_events) != 0))
        {
            // c-ares owns this descriptor. Drop only our event wrapper so the
            // resolver can observe the socket failure or finish by timeout.
            asyncdnsReleaseWatch(r, watch);
            asyncdnsRefreshTimer(r);
            return;
        }
    }
#endif

    watch->events = io_events;
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
#ifdef EVENT_IOCP
    // Progress is driven by polling, so the tick must be short enough to bound
    // response latency, and a zero c-ares timeout must not leave the resolver
    // with no timer at all.
    if (timeout_ms == 0 || timeout_ms > (uint32_t) kAsyncDnsIocpPollIntervalMs)
    {
        timeout_ms = (uint32_t) kAsyncDnsIocpPollIntervalMs;
    }
#else
    if (timeout_ms == 0)
    {
        return;
    }
#endif

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

#ifdef EVENT_IOCP
// Grow the reusable readiness scratch buffer to at least `needed` entries.
static bool asyncdnsReservePollEvents(dns_resolver_t *r, size_t needed)
{
    if (r->poll_capacity >= needed)
    {
        return true;
    }

    if (needed > SIZE_MAX / sizeof(*r->poll_events))
    {
        return false;
    }

    size_t capacity = r->poll_capacity == 0 ? 16 : r->poll_capacity;
    while (capacity < needed)
    {
        if (capacity > SIZE_MAX / 2U)
        {
            capacity = needed;
            break;
        }
        capacity *= 2U;
    }

    ares_fd_events_t *grown = memoryReAllocate(r->poll_events, capacity * sizeof(*grown));
    if (grown == NULL)
    {
        return false;
    }

    r->poll_events   = grown;
    r->poll_capacity = capacity;
    return true;
}

// The native IOCP backend delivers completions, not readiness, so c-ares
// descriptors are probed on the resolver timer.
//
// The probe must report what is actually ready, never what was merely requested.
// c-ares treats a write event as proof that a pending TCP connect completed: it
// sets ARES_CONN_STATE_CONNECTED and thereby clears its own "don't write before
// connected" guard before flushing. Reporting bare interest therefore makes it
// send() on a still-connecting socket, which Winsock fails with WSAENOTCONN;
// c-ares maps that to a hard connection error and tears the connection down.
//
// select() rather than WSAPoll(): WSAPoll() does not report a failed nonblocking
// connect (no POLLERR/POLLHUP), so a refused DNS server would hang until the
// query timed out. select()'s exceptfds does report it.
static size_t asyncdnsPollWatchedFds(dns_resolver_t *r)
{
    // Pass 1 - snapshot. ares_process_fds() re-enters the socket-state callback
    // and can free watches, so the list must not be walked across that call.
    // The snapshot holds requested interest here; pass 3 overwrites it with
    // the readiness actually observed.
    size_t nwatched = 0;
    for (dns_watch_t *watch = r->watches; watch != NULL; watch = watch->next)
    {
        unsigned int interest = ARES_FD_EVENT_NONE;
        if (watch->events & WW_READ)
        {
            interest |= ARES_FD_EVENT_READ;
        }
        if (watch->events & WW_WRITE)
        {
            interest |= ARES_FD_EVENT_WRITE;
        }
        if (interest == ARES_FD_EVENT_NONE)
        {
            continue;
        }
        if (! asyncdnsReservePollEvents(r, nwatched + 1U))
        {
            break; // Out of memory: probe what fits; the rest retries next tick.
        }
        r->poll_events[nwatched++] = (ares_fd_events_t) {.fd = watch->fd, .events = interest};
    }

    // Pass 2/3 - probe in FD_SETSIZE batches and compact the observed readiness
    // in place. nready <= i always holds, so the rewrite never outruns the read.
    size_t nready = 0;
    for (size_t base = 0; base < nwatched; base += FD_SETSIZE)
    {
        size_t end = base + FD_SETSIZE;
        if (end > nwatched)
        {
            end = nwatched;
        }

        fd_set readfds;
        fd_set writefds;
        fd_set exceptfds;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);

        for (size_t i = base; i < end; ++i)
        {
            if (r->poll_events[i].events & ARES_FD_EVENT_READ)
            {
                FD_SET(r->poll_events[i].fd, &readfds);
            }
            if (r->poll_events[i].events & ARES_FD_EVENT_WRITE)
            {
                FD_SET(r->poll_events[i].fd, &writefds);
            }
            // Always: a failed connect surfaces only here, and it is the case
            // that matters most for TCP DNS.
            FD_SET(r->poll_events[i].fd, &exceptfds);
        }

        // The first argument is ignored by Winsock.
        struct timeval immediate = {.tv_sec = 0, .tv_usec = 0};
        const int      ready     = select(0, &readfds, &writefds, &exceptfds, &immediate);
        if (ready <= 0)
        {
            // 0: nothing ready in this batch. SOCKET_ERROR: leave the batch
            // alone and let the c-ares timeout path handle it below.
            continue;
        }

        for (size_t i = base; i < end; ++i)
        {
            const ares_socket_t fd        = r->poll_events[i].fd;
            unsigned int        fd_events = ARES_FD_EVENT_NONE;

            if (FD_ISSET(fd, &readfds))
            {
                fd_events |= ARES_FD_EVENT_READ;
            }
            if (FD_ISSET(fd, &writefds))
            {
                fd_events |= ARES_FD_EVENT_WRITE;
            }
            // ARES_FD_EVENT_READ is documented as covering disconnect/error, so
            // an exceptional socket routes into process_read(), which surfaces
            // the error. Reporting WRITE would be read as connect success and
            // reintroduce the defect this function exists to avoid.
            if (FD_ISSET(fd, &exceptfds))
            {
                fd_events |= ARES_FD_EVENT_READ;
            }

            if (fd_events != ARES_FD_EVENT_NONE)
            {
                r->poll_events[nready++] = (ares_fd_events_t) {.fd = fd, .events = fd_events};
            }
        }
    }

    // Unconditional: with nready == 0 this is what runs process_timeouts() and
    // ares_check_cleanup_conns(). Returning early when nothing is ready would
    // stop queries from ever timing out.
    discard ares_process_fds(r->channel, r->poll_events, nready, ARES_PROCESS_FLAG_NONE);
    return nready;
}

#if defined(WATERWALL_IOCP_TEST_HOOKS)
size_t asyncdnsTestPollWatchedFds(dns_resolver_t *r)
{
    return asyncdnsPollWatchedFds(r);
}
#endif
#endif

static void asyncdnsTimerCallback(wtimer_t *timer)
{
    dns_resolver_t *r = weventGetUserdata(timer);
    if (r == NULL || r->shutting_down || r->channel == NULL)
    {
        return;
    }

#ifdef EVENT_IOCP
    discard asyncdnsPollWatchedFds(r);
#else
    discard ares_process_fds(r->channel, NULL, 0, ARES_PROCESS_FLAG_NONE);
#endif
    asyncdnsRefreshTimer(r);
}

static bool asyncdnsAddrNodeUsable(const struct ares_addrinfo_node *node, size_t max_addrlen)
{
    if (node == NULL || node->ai_addr == NULL)
    {
        return false;
    }

    size_t min_addrlen;
    switch (node->ai_family)
    {
    case AF_INET:
        min_addrlen = sizeof(struct sockaddr_in);
        break;
    case AF_INET6:
        min_addrlen = sizeof(struct sockaddr_in6);
        break;
    default:
        return false;
    }

    if (node->ai_addr->sa_family != node->ai_family)
    {
        return false;
    }

    uintmax_t addrlen = (uintmax_t) node->ai_addrlen;
    return addrlen >= (uintmax_t) min_addrlen && addrlen <= (uintmax_t) max_addrlen;
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
        if (asyncdnsAddrNodeUsable(node, sizeof(struct sockaddr_storage)))
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
        if (!asyncdnsAddrNodeUsable(node, sizeof(out[index].addr)))
        {
            continue;
        }

        size_t addrlen = (size_t) node->ai_addrlen;

        memoryZero(&out[index], sizeof(out[index]));
        memoryCopy(&out[index].addr, node->ai_addr, addrlen);
        out[index].addrlen = (socklen_t) addrlen;
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
            if (addrs == NULL)
            {
                cb_status = ARES_ENOMEM;
                count     = 0;
            }
            else
            {
                asyncdnsCopyAddrs(addrs, res);
            }
        }
    }

    req->cb(req->userdata, cb_status, ares_strerror(cb_status), addrs, count);

    memoryFree(addrs);
    if (res != NULL)
    {
        ares_freeaddrinfo(res);
    }
    asyncdnsRequestDestroy(req);
}

int asyncdnsInit(dns_resolver_t *r, wloop_t *loop, const asyncdns_options_t *dns_options)
{
    if (r == NULL || loop == NULL)
    {
        return ARES_EFORMERR;
    }

    asyncdns_options_t default_options;
    if (dns_options == NULL || ! dns_options->defaults_initialized)
    {
        asyncdnsOptionsSetDefaults(&default_options);
        dns_options = &default_options;
    }

    memoryZero(r, sizeof(*r));
    r->loop = loop;

    struct ares_options options;
    memoryZero(&options, sizeof(options));
    options.sock_state_cb      = asyncdnsSockStateCallback;
    options.sock_state_cb_data = r;
    options.qcache_max_ttl     = dns_options->query_cache_max_ttl;
    options.timeout            = dns_options->timeout_ms;
    options.maxtimeout         = dns_options->max_timeout_ms;
    options.tries              = dns_options->tries;

    int optmask = ARES_OPT_SOCK_STATE_CB | ARES_OPT_QUERY_CACHE | ARES_OPT_TIMEOUTMS | ARES_OPT_MAXTIMEOUTMS |
                  ARES_OPT_TRIES;

    if (dns_options->flags_set)
    {
        options.flags = dns_options->flags;
        optmask |= ARES_OPT_FLAGS;
    }
    if (dns_options->ndots_set)
    {
        options.ndots = dns_options->ndots;
        optmask |= ARES_OPT_NDOTS;
    }
    if (dns_options->udp_port_set)
    {
        options.udp_port = dns_options->udp_port;
        optmask |= ARES_OPT_UDP_PORT;
    }
    if (dns_options->tcp_port_set)
    {
        options.tcp_port = dns_options->tcp_port;
        optmask |= ARES_OPT_TCP_PORT;
    }
    if (dns_options->socket_send_buffer_size_set)
    {
        options.socket_send_buffer_size = dns_options->socket_send_buffer_size;
        optmask |= ARES_OPT_SOCK_SNDBUF;
    }
    if (dns_options->socket_receive_buffer_size_set)
    {
        options.socket_receive_buffer_size = dns_options->socket_receive_buffer_size;
        optmask |= ARES_OPT_SOCK_RCVBUF;
    }
    if (dns_options->ednspsz_set)
    {
        options.ednspsz = dns_options->ednspsz;
        optmask |= ARES_OPT_EDNSPSZ;
    }
    if (dns_options->udp_max_queries_set)
    {
        options.udp_max_queries = dns_options->udp_max_queries;
        optmask |= ARES_OPT_UDP_MAX_QUERIES;
    }
    if (dns_options->domains != NULL && dns_options->ndomains > 0)
    {
        options.domains  = dns_options->domains;
        options.ndomains = dns_options->ndomains;
        optmask |= ARES_OPT_DOMAINS;
    }
    if (dns_options->lookups != NULL)
    {
        options.lookups = dns_options->lookups;
        optmask |= ARES_OPT_LOOKUPS;
    }
    if (dns_options->resolvconf_path != NULL)
    {
        options.resolvconf_path = dns_options->resolvconf_path;
        optmask |= ARES_OPT_RESOLVCONF;
    }
    if (dns_options->hosts_path != NULL)
    {
        options.hosts_path = dns_options->hosts_path;
        optmask |= ARES_OPT_HOSTS_FILE;
    }
    if (dns_options->rotate_set)
    {
        optmask |= dns_options->rotate ? ARES_OPT_ROTATE : ARES_OPT_NOROTATE;
    }
    if (dns_options->server_failover_set)
    {
        options.server_failover_opts.retry_chance = dns_options->server_failover_retry_chance;
        options.server_failover_opts.retry_delay  = dns_options->server_failover_retry_delay_ms;
        optmask |= ARES_OPT_SERVER_FAILOVER;
    }

    int rc = ares_init_options(&r->channel, &options, optmask);
    if (rc != ARES_SUCCESS)
    {
        memoryZero(r, sizeof(*r));
        return rc;
    }

    if (dns_options->servers_csv != NULL)
    {
        rc = ares_set_servers_ports_csv(r->channel, dns_options->servers_csv);
        if (rc != ARES_SUCCESS)
        {
            ares_destroy(r->channel);
            memoryZero(r, sizeof(*r));
            return rc;
        }
    }

    if (dns_options->sortlist != NULL)
    {
        rc = ares_set_sortlist(r->channel, dns_options->sortlist);
        if (rc != ARES_SUCCESS)
        {
            ares_destroy(r->channel);
            memoryZero(r, sizeof(*r));
            return rc;
        }
    }

    return ARES_SUCCESS;
}

void asyncdnsCleanup(dns_resolver_t *r)
{
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

#ifdef EVENT_IOCP
    memoryFree(r->poll_events);
    r->poll_events   = NULL;
    r->poll_capacity = 0;
#endif

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
    if (req == NULL)
    {
        return ARES_ENOMEM;
    }

    char *host_copy = stringDuplicate(host);
    if (host_copy == NULL)
    {
        memoryFree(req);
        return ARES_ENOMEM;
    }

    char *service_copy = NULL;
    if (service != NULL)
    {
        service_copy = stringDuplicate(service);
        if (service_copy == NULL)
        {
            memoryFree(host_copy);
            memoryFree(req);
            return ARES_ENOMEM;
        }
    }

    *req = (asyncdns_request_t) {
        .resolver  = r,
        .cb        = cb,
        .userdata  = userdata,
        .host      = host_copy,
        .service   = service_copy,
    };

    struct ares_addrinfo_hints hints;
    memoryZero(&hints, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = socktype;

    ares_getaddrinfo(r->channel, req->host, req->service, &hints, asyncdnsAddrInfoCallback, req);
    asyncdnsRefreshTimer(r);

    return ARES_SUCCESS;
}
