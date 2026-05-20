#pragma once

#include "wlibc.h"
#include "wloop.h"

#include <ares.h>

typedef struct dns_resolved_addr_s
{
    struct sockaddr_storage addr;
    socklen_t               addrlen;
    int                     family;
    int                     ttl;
} dns_resolved_addr_t;

typedef void (*dns_resolve_cb)(void *userdata, int status, const char *error, const dns_resolved_addr_t *addrs,
                               size_t naddrs);

typedef struct dns_resolver_s dns_resolver_t;

typedef struct dns_watch_s
{
    ares_socket_t       fd;
    wio_t              *io;
    int                 events;
    dns_resolver_t     *resolver;
    struct dns_watch_s *next;
} dns_watch_t;

struct dns_resolver_s
{
    wloop_t        *loop;
    ares_channel_t *channel;
    wtimer_t       *timer;
    dns_watch_t    *watches;
    int             shutting_down;
};

int  asyncdnsInit(dns_resolver_t *r, wloop_t *loop);
void asyncdnsCleanup(dns_resolver_t *r);

static inline bool asyncdnsStatusIsShutdown(int status)
{
    return status == ARES_ECANCELLED || status == ARES_EDESTRUCTION;
}

/*
 * The callback always runs on the resolver's worker thread. `addrs` is owned by
 * async_dns and is valid only until the callback returns.
 *
 * During resolver cleanup c-ares invokes callbacks with ARES_ECANCELLED or
 * ARES_EDESTRUCTION. Callers must release their userdata for those statuses, but
 * should not start new tunnel lifecycle or socket work from them.
 */
int asyncdnsResolve(dns_resolver_t *r, const char *host, const char *service, int socktype, dns_resolve_cb cb,
                    void *userdata);
