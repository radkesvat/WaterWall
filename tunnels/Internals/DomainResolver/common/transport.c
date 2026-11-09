#include "DomainResolver/transport.h"
#include "DomainResolver/structure.h"

#include "splice_buffer.h"

enum
{
    kDnsTransportMaxSockets      = 128,
    kDnsTransportMaxInputEntries = 128,
    kDnsTransportMaxInputBytes   = 1024 * 1024,
    kDnsTransportMaxInputCharge  = 2 * 1024 * 1024,
    kDnsTransportWorkerBytes     = 8 * 1024 * 1024,
    kDnsTransportWorkerCharge    = 16 * 1024 * 1024,
    kDnsTransportReadHigh        = 64 * 1024,
    kDnsTransportReadLow         = 32 * 1024,
    kDnsTransportTcpWriteChunk   = 16 * 1024,
    kDnsTransportMaxDatagram     = 65535
};

typedef struct domainresolver_socket_s domainresolver_socket_t;
struct domainresolver_socket_s
{
    domainresolver_transport_t *transport;
    domainresolver_socket_t    *next;
    line_t                     *line; /* Owned normal line, independent of application requests. */
    ares_socket_t               handle;
    sockaddr_u                  peer;
    buffer_queue_t              input;
    int                         family;
    bool                        tcp;
    bool                        established;
    bool                        send_paused;
    bool                        read_paused;
    bool                        failed;
    bool                        eof;
    bool                        read_interest;
    bool                        write_interest;
    bool                        write_blocked;
};

struct domainresolver_transport_s
{
    tunnel_t                *owner;
    tunnel_t                *egress;
    wid_t                    wid;
    dns_resolver_t           resolver;
    domainresolver_socket_t *sockets;
    buffer_budget_t          input_budget;
    size_t                   socket_count;
    /* Never reuse a virtual descriptor. A readiness snapshot from before close
     * cannot address a later connection, even in a reentrant c-ares callback. */
    uint32_t next_handle;
    bool     quiesced;
};

static void dnsTransportSetError(int error)
{
#ifdef OS_WIN
    int socket_error = WSAEINVAL;
    switch (error)
    {
    case EWOULDBLOCK:
        socket_error = WSAEWOULDBLOCK;
        break;
    case EINPROGRESS:
        socket_error = WSAEINPROGRESS;
        break;
    case ECONNREFUSED:
        socket_error = WSAECONNREFUSED;
        break;
    case ENOSYS:
        socket_error = WSAEOPNOTSUPP;
        break;
    case EBADF:
        socket_error = WSAEBADF;
        break;
    case EAFNOSUPPORT:
        socket_error = WSAEAFNOSUPPORT;
        break;
    case ENOBUFS:
        socket_error = WSAENOBUFS;
        break;
    default:
        break;
    }
    WSASetLastError(socket_error);
#else
    errno = error;
#endif
}

static domainresolver_socket_t *dnsTransportSocket(domainresolver_transport_t *transport, ares_socket_t handle)
{
    for (domainresolver_socket_t *socket = transport->sockets; socket != NULL; socket = socket->next)
        if (socket->handle == handle)
            return socket;
    return NULL;
}

static bool dnsTransportCanWrite(const domainresolver_socket_t *socket)
{
    return (socket->write_interest || socket->write_blocked) && socket->established && ! socket->send_paused &&
           ! socket->failed;
}

static domainresolver_socket_t *dnsTransportLine(tunnel_t *owner, line_t *line)
{
    assert(lineIsOnCurrentWorker(line));
    domainresolver_lstate_t *ls = lineGetState(line, owner);
    return ls->dns_transport;
}

static bool dnsTransportPeerEquals(const sockaddr_u *peer, const struct sockaddr *address, ares_socklen_t length)
{
    if (address == NULL || address->sa_family != peer->sa.sa_family)
        return false;
    if (address->sa_family == AF_INET && length >= (ares_socklen_t) sizeof(struct sockaddr_in))
    {
        const struct sockaddr_in *other = (const struct sockaddr_in *) address;
        return peer->sin.sin_port == other->sin_port && peer->sin.sin_addr.s_addr == other->sin_addr.s_addr;
    }
    if (address->sa_family == AF_INET6 && length >= (ares_socklen_t) sizeof(struct sockaddr_in6))
    {
        const struct sockaddr_in6 *other = (const struct sockaddr_in6 *) address;
        return peer->sin6.sin6_port == other->sin6_port && peer->sin6.sin6_scope_id == other->sin6_scope_id &&
               memcmp(&peer->sin6.sin6_addr, &other->sin6_addr, sizeof(other->sin6_addr)) == 0;
    }
    return false;
}

static void dnsTransportDetachLine(domainresolver_socket_t *socket, bool notify)
{
    line_t *line = socket->line;
    if (line == NULL)
        return;
    socket->line = NULL;
    lineRef(line);
    /* Publish detachment before notifying next. Synchronous callbacks recognize
     * this socket but cannot revive it or deliver into an application owner. */
    if (notify)
        tunnelUpStreamFin(socket->transport->egress, line);
    domainresolver_lstate_t *ls = lineGetState(line, socket->transport->owner);
    ls->dns_transport           = NULL;
    if (lineIsAlive(line))
        lineDestroy(line);
    lineUnref(line);
}

static void dnsTransportFail(domainresolver_socket_t *socket, bool notify)
{
    socket->failed = true;
    dnsTransportDetachLine(socket, notify);
    asyncdnsWakeTransport(&socket->transport->resolver);
}

static ares_socket_t dnsTransportOpen(int family, int type, int protocol, void *userdata)
{
    discard                     protocol;
    domainresolver_transport_t *transport = userdata;
    assert(currentThreadOwnsWorker(transport->wid));
    if (transport->quiesced || transport->socket_count >= kDnsTransportMaxSockets || transport->next_handle == INT_MAX)
    {
        dnsTransportSetError(ENOBUFS);
        return ARES_SOCKET_BAD;
    }
    if ((family != AF_INET && family != AF_INET6) || (type != SOCK_STREAM && type != SOCK_DGRAM))
    {
        dnsTransportSetError(EAFNOSUPPORT);
        return ARES_SOCKET_BAD;
    }
    domainresolver_socket_t *socket = memoryAllocate(sizeof(*socket));
    *socket                         = (domainresolver_socket_t) {
                                .transport = transport,
                                .next      = transport->sockets,
                                .handle    = (ares_socket_t) ++transport->next_handle,
                                .family    = family,
                                .tcp       = type == SOCK_STREAM,
    };
    bufferqueueInitEmpty(&socket->input);
    bufferqueueAttachBudget(&socket->input, &transport->input_budget);
    transport->sockets = socket;
    ++transport->socket_count;
    return socket->handle;
}

static int dnsTransportClose(ares_socket_t handle, void *userdata)
{
    domainresolver_transport_t *transport = userdata;
    domainresolver_socket_t   **link      = &transport->sockets;
    while (*link != NULL && (*link)->handle != handle)
        link = &(*link)->next;
    domainresolver_socket_t *socket = *link;
    if (socket == NULL)
    {
        dnsTransportSetError(EBADF);
        return -1;
    }
    *link = socket->next;
    --transport->socket_count;
    socket->failed = true;
    dnsTransportDetachLine(socket, true);
    bufferqueueDestroy(&socket->input);
    memoryFree(socket);
    return 0;
}

static int dnsTransportSetOption(ares_socket_t handle, ares_socket_opt_t option, const void *value,
                                 ares_socklen_t length, void *userdata)
{
    discard handle;
    discard option;
    discard value;
    discard length;
    discard userdata;
    /* No kernel socket belongs to this adapter. In particular TCP Fast Open
     * must remain disabled: establishment is reported by the selected egress. */
    dnsTransportSetError(ENOSYS);
    return -1;
}

static int dnsTransportConnect(ares_socket_t handle, const struct sockaddr *address, ares_socklen_t length,
                               unsigned int flags, void *userdata)
{
    domainresolver_transport_t *transport = userdata;
    domainresolver_socket_t    *socket    = dnsTransportSocket(transport, handle);
    if (socket == NULL || socket->failed || socket->line != NULL || flags != 0 || address == NULL ||
        address->sa_family != socket->family ||
        (socket->family == AF_INET && length != (ares_socklen_t) sizeof(struct sockaddr_in)) ||
        (socket->family == AF_INET6 && length != (ares_socklen_t) sizeof(struct sockaddr_in6)))
    {
        dnsTransportSetError(ECONNREFUSED);
        return -1;
    }
    memoryCopy(&socket->peer, address, (size_t) length);
    /* c-ares chooses this address solely from the resolver's explicit numeric
     * server list. This line is a connected logical flow: terminal UDP adapters
     * demultiplex by the full peer (including port), while proxy protocols bind
     * their reply stream to this target. A local source context is not recvfrom
     * metadata and must never be used to authenticate the DNS peer. */
    line_t *line                = lineCreate(tunnelchainGetLinePools(tunnelGetChain(transport->owner)), transport->wid);
    socket->line                = line;
    socket->established         = ! socket->tcp;
    domainresolver_lstate_t *ls = lineGetState(line, transport->owner);
    ls->dns_transport           = socket;
    addresscontextFromSockAddrWithProtocol(
        lineGetDestinationAddressContext(line), &socket->peer, socket->tcp ? IP_PROTO_TCP : IP_PROTO_UDP);
    addresscontextSetResolverDns(lineGetDestinationAddressContext(line), true);
    /* The first logical endpoint consumer must use this exact DNS target. A
     * proxy consumes the one-shot pin before its outer connector selects the
     * independently configured VPN peer. */
    addresscontextSetDestinationPinned(lineGetDestinationAddressContext(line), true);
    addresscontextSetOnlyProtocol(lineGetSourceAddressContext(line), socket->tcp ? IP_PROTO_TCP : IP_PROTO_UDP);
    linePreferOrdinaryReadBoth(line);
    lineRef(line);
    tunnelUpStreamInit(transport->egress, line);
    bool alive = lineIsAlive(line);
    lineUnref(line);
    if (! alive || socket->failed)
    {
        dnsTransportSetError(ECONNREFUSED);
        return -1;
    }
    if (! socket->established)
    {
        dnsTransportSetError(EINPROGRESS);
        return -1;
    }
    return 0;
}

static ares_ssize_t dnsTransportSend(ares_socket_t handle, const void *data, size_t length, int flags,
                                     const struct sockaddr *address, ares_socklen_t address_length, void *userdata)
{
    discard                     flags;
    domainresolver_transport_t *transport = userdata;
    domainresolver_socket_t    *socket    = dnsTransportSocket(transport, handle);
    if (socket == NULL || socket->failed || socket->line == NULL ||
        (address != NULL && ! dnsTransportPeerEquals(&socket->peer, address, address_length)))
    {
        dnsTransportSetError(ECONNREFUSED);
        return -1;
    }
    if (! socket->established || socket->send_paused)
    {
        /* c-ares 1.34.8 clears UDP WRITE interest after a would-block flush.
         * Retain that pending send independently until capacity can retry it. */
        socket->write_blocked = true;
        dnsTransportSetError(EWOULDBLOCK);
        return -1;
    }
    socket->write_blocked = false;
    if (! socket->tcp && length > kDnsTransportMaxDatagram)
    {
        dnsTransportSetError(ENOBUFS);
        return -1;
    }
    const size_t accepted = socket->tcp ? min(length, (size_t) kDnsTransportTcpWriteChunk) : length;
    line_t      *line     = socket->line;
    sbuf_t      *buf =
        bufferpoolGetBestFit(lineGetBufferPool(line), accepted, tunnelGetChain(transport->owner)->sum_padding_left);
    sbufSetLength(buf, accepted);
    sbufWrite(buf, data, accepted);
    /* c-ares owns its write memory. Only this copied, pool-owned buffer crosses
     * the tunnel boundary; a TCP short write leaves its suffix with c-ares. */
    lineRef(line);
    tunnelUpStreamPayload(transport->egress, line, buf);
    lineUnref(line);
    return (ares_ssize_t) accepted;
}

static ares_ssize_t dnsTransportReceive(ares_socket_t handle, void *data, size_t length, int flags,
                                        struct sockaddr *address, ares_socklen_t *address_length, void *userdata)
{
    discard                     flags;
    domainresolver_transport_t *transport = userdata;
    domainresolver_socket_t    *socket    = dnsTransportSocket(transport, handle);
    if (socket == NULL)
    {
        dnsTransportSetError(EBADF);
        return -1;
    }
    sbuf_t *buf = bufferqueuePopFront(&socket->input);
    if (buf == NULL)
    {
        if (socket->failed)
        {
            if (socket->eof)
                return 0;
            dnsTransportSetError(ECONNREFUSED);
            return -1;
        }
        dnsTransportSetError(EWOULDBLOCK);
        return -1;
    }
    size_t copied = min(length, sbufGetLength(buf));
    memoryCopy(data, sbufGetRawPtr(buf), copied);
    if (address != NULL && address_length != NULL)
    {
        const ares_socklen_t peer_length = (ares_socklen_t) sockaddrLen(&socket->peer);
        memoryCopy(address, &socket->peer, min((size_t) *address_length, (size_t) peer_length));
        *address_length = peer_length;
    }
    if (socket->tcp && copied < sbufGetLength(buf))
    {
        sbufShiftRight(buf, copied);
        /* The exact entry was just removed; its smaller replacement cannot
         * exceed the unchanged worker budget or require a new queue slot. */
        bufferqueuePushFront(&socket->input, buf);
    }
    else
        bufferpoolReuseBuffer(getWorkerBufferPool(transport->wid), buf);

    if (socket->read_paused && socket->line != NULL && bufferqueueGetLength(&socket->input) <= kDnsTransportReadLow)
    {
        socket->read_paused = false;
        line_t *line        = socket->line;
        lineRef(line);
        tunnelUpStreamResume(transport->egress, line);
        lineUnref(line);
    }
    return (ares_ssize_t) copied;
}

static void dnsTransportState(void *userdata, ares_socket_t handle, int readable, int writable)
{
    domainresolver_transport_t *transport = userdata;
    domainresolver_socket_t    *socket    = dnsTransportSocket(transport, handle);
    if (socket == NULL)
        return;
    socket->read_interest  = readable != 0;
    socket->write_interest = writable != 0;
    if ((readable && (socket->failed || bufferqueueGetEntryCount(&socket->input) != 0)) || dnsTransportCanWrite(socket))
        asyncdnsWakeTransport(&transport->resolver);
}

static void dnsTransportProcess(void *userdata)
{
    domainresolver_transport_t *transport = userdata;
    ares_fd_events_t            events[kDnsTransportMaxSockets];
    size_t                      count = 0;
    /* Snapshot before processing: c-ares may close sockets and tunnel callbacks
     * may queue new input. Closed handles are never reused, so stale entries
     * remain harmless. Synchronous callbacks only arrange another timer tick. */
    for (domainresolver_socket_t *socket = transport->sockets; socket != NULL; socket = socket->next)
    {
        unsigned int ready = ARES_FD_EVENT_NONE;
        if (socket->read_interest && (socket->failed || bufferqueueGetEntryCount(&socket->input) != 0))
            ready |= ARES_FD_EVENT_READ;
        if (dnsTransportCanWrite(socket))
        {
            ready |= ARES_FD_EVENT_WRITE;
            /* Consume the independent retry once. A send that blocks again
             * republishes it; an empty c-ares output queue cannot spin it. */
            socket->write_blocked = false;
        }
        if (ready != ARES_FD_EVENT_NONE)
            events[count++] = (ares_fd_events_t) {.fd = socket->handle, .events = ready};
    }
    discard ares_process_fds(transport->resolver.channel, events, count, ARES_PROCESS_FLAG_NONE);
    /* Interest callbacks are edge notifications in the pinned c-ares release.
     * A short TCP write can leave WRITE unchanged; rearm the level while actual
     * capacity remains rather than waiting for the query deadline. */
    for (domainresolver_socket_t *socket = transport->sockets; socket != NULL; socket = socket->next)
    {
        if ((socket->read_interest && (socket->failed || bufferqueueGetEntryCount(&socket->input) != 0)) ||
            dnsTransportCanWrite(socket))
        {
            asyncdnsWakeTransport(&transport->resolver);
            break;
        }
    }
}

domainresolver_transport_t *domainresolverTransportCreate(tunnel_t *owner, tunnel_t *egress, wid_t wid,
                                                          const asyncdns_options_t *options)
{
    assert(owner != NULL && egress != NULL && currentThreadOwnsWorker(wid));
    assert(options != NULL && options->servers_csv != NULL);
    domainresolver_transport_t *transport = memoryAllocate(sizeof(*transport));
    *transport                            = (domainresolver_transport_t) {.owner = owner, .egress = egress, .wid = wid};
    bufferbudgetInit(&transport->input_budget,
                     (buffer_budget_cost_t) {kDnsTransportWorkerBytes, kDnsTransportWorkerCharge});
    const struct ares_socket_functions_ex functions = {
        .version     = 1,
        .flags       = ARES_SOCKFUNC_FLAG_NONBLOCKING,
        .asocket     = dnsTransportOpen,
        .aclose      = dnsTransportClose,
        .asetsockopt = dnsTransportSetOption,
        .aconnect    = dnsTransportConnect,
        .arecvfrom   = dnsTransportReceive,
        .asendto     = dnsTransportSend,
        /* No invented VPN-exit source address, native bind or interface APIs. */
    };
    int status = asyncdnsInitCustom(&transport->resolver,
                                    getWorkerLoop(wid),
                                    options,
                                    &functions,
                                    dnsTransportState,
                                    dnsTransportProcess,
                                    transport);
    if (status != ARES_SUCCESS)
    {
        memoryFree(transport);
        return NULL;
    }
    return transport;
}

dns_resolver_t *domainresolverTransportResolver(domainresolver_transport_t *transport)
{
    assert(currentThreadOwnsWorker(transport->wid));
    return &transport->resolver;
}

void domainresolverTransportQuiesce(domainresolver_transport_t *transport)
{
    assert(currentThreadOwnsWorker(transport->wid));
    if (transport->quiesced)
        return;
    transport->quiesced = true;
    /* Suppress application completion while c-ares settles every retained query
     * reference. Socket close drains owned lines while neighbours/pools live. */
    asyncdnsCleanup(&transport->resolver);
    assert(transport->sockets == NULL && transport->socket_count == 0);
    bufferbudgetAssertEmpty(&transport->input_budget);
}

void domainresolverTransportDestroy(domainresolver_transport_t *transport)
{
    if (transport == NULL)
        return;
    domainresolverTransportQuiesce(transport);
    memoryFree(transport);
}

void domainresolverTransportEst(tunnel_t *owner, line_t *line)
{
    domainresolver_socket_t *socket = dnsTransportLine(owner, line);
    if (socket == NULL || socket->line != line)
        return;
    socket->established = true;
    asyncdnsWakeTransport(&socket->transport->resolver);
}

void domainresolverTransportFinish(tunnel_t *owner, line_t *line)
{
    domainresolver_socket_t *socket = dnsTransportLine(owner, line);
    if (socket != NULL && socket->line == line)
    {
        socket->eof = socket->tcp && socket->established;
        dnsTransportFail(socket, false);
    }
}

void domainresolverTransportPayload(tunnel_t *owner, line_t *line, sbuf_t *buf)
{
    domainresolver_socket_t *socket = dnsTransportLine(owner, line);
    if (socket == NULL || socket->line != line || socket->failed)
    {
        lineReuseBuffer(line, buf);
        return;
    }
    size_t length = sbufGetLength(buf);
    if ((! socket->tcp && length > kDnsTransportMaxDatagram) ||
        length > kDnsTransportMaxInputBytes - bufferqueueGetLength(&socket->input) ||
        bufferqueueGetEntryCount(&socket->input) >= kDnsTransportMaxInputEntries)
    {
        lineReuseBuffer(line, buf);
        dnsTransportFail(socket, true);
        return;
    }
    buf           = sbufEnsureOrdinary(lineGetBufferPool(line), buf);
    size_t charge = sbufGetQueueCharge(buf);
    if (charge > kDnsTransportMaxInputCharge - bufferqueueGetCharge(&socket->input) ||
        ! bufferqueueTryPushBack(&socket->input, &buf))
    {
        lineReuseBuffer(line, buf);
        dnsTransportFail(socket, true);
        return;
    }
    asyncdnsWakeTransport(&socket->transport->resolver);
    if (! socket->read_paused && bufferqueueGetLength(&socket->input) >= kDnsTransportReadHigh)
    {
        socket->read_paused = true;
        lineRef(line);
        tunnelUpStreamPause(socket->transport->egress, line);
        lineUnref(line);
    }
}

void domainresolverTransportPause(tunnel_t *owner, line_t *line)
{
    domainresolver_socket_t *socket = dnsTransportLine(owner, line);
    if (socket != NULL && socket->line == line)
        socket->send_paused = true;
}

void domainresolverTransportResume(tunnel_t *owner, line_t *line)
{
    domainresolver_socket_t *socket = dnsTransportLine(owner, line);
    if (socket != NULL && socket->line == line)
    {
        socket->send_paused = false;
        asyncdnsWakeTransport(&socket->transport->resolver);
    }
}
