#include "structure.h"

#include "loggers/network_logger.h"

static void onUdpConnectonExpire(local_idle_item_t *idle_udp)
{
    udplistener_lstate_t *ls = idle_udp->userdata;
    assert(ls != NULL && ls->tunnel != NULL);
    idle_udp->userdata = NULL;

    LOGD("UdpListener: expired 1 udp connection FD:%x ", ls->listener_fd);
    tunnel_t *self = ls->tunnel;
    line_t   *line = ls->line;
    udplistenerLinestateDestroy(ls);
    tunnelNextUpStreamFinish(self, line);
    lineDestroy(line);
}

static bool udpEndpointEquals(const sockaddr_u *left, const sockaddr_u *right)
{
    if (! sockaddrCmpIP(left, right))
    {
        return false;
    }

    sockaddr_u left_copy  = *left;
    sockaddr_u right_copy = *right;
    return sockaddrPort(&left_copy) == sockaddrPort(&right_copy);
}

static bool idleLineMatchesPacket(const udplistener_lstate_t *ls, tunnel_t *t, const sockaddr_u *peer_addr,
                                  const sockaddr_u *local_addr)
{
    return ls != NULL && ls->tunnel == t && udpEndpointEquals(&ls->peer_addr, peer_addr) &&
           udpEndpointEquals(&ls->local_addr, local_addr);
}

// payload that comes here has passed filtering (whitelist, etc that we gave socketmanager) and is ready to be processed
void onUdpListenerFilteredPayloadReceived(wevent_t *ev)
{
    udp_payload_t *data = (udp_payload_t *) weventGetUserdata(ev);

    udpsock_t          *sock           = data->sock;
    tunnel_t           *t              = data->tunnel;
    wid_t               wid            = data->wid;
    sbuf_t             *buf            = data->buf;
    uint16_t            real_localport = data->real_localport;
    local_idle_table_t *table          = udpsockGetWorkerIdleTable(sock);

    assert(wid == getWID());

    // Key idle lines by (peer addr+port, local addr+port, selected tunnel). A single physical UDP socket can
    // serve more than one logical local endpoint (iptables multiport) AND more than one tunnel: exact endpoint
    // sharing and UDP balance groups let dispatch pick a different filter/tunnel for the same peer over time
    // (e.g. a 60s balance entry expiring while this 300s line is still alive). Peer+local alone could then hand
    // a line created for tunnel A to a packet routed to tunnel B, forwarding B's callbacks over A's line.
    // Including the selected tunnel identity keeps each tunnel's line distinct. For an ordinary single-endpoint,
    // single-tunnel socket the local/tunnel components are constant, so this reduces to peer keying.
    hash_t peeraddr_hash  = sockaddrCalcHashWithPort(&data->peer_addr);
    hash_t localaddr_hash = sockaddrCalcHashWithPort(&data->real_localaddr);
    hash_t tunnel_hash    = (hash_t) (uintptr_t) t;
    hash_t idle_key       = peeraddr_hash;
    idle_key ^= localaddr_hash + 0x9E3779B97F4A7C15ULL + (idle_key << 6) + (idle_key >> 2);
    idle_key ^= tunnel_hash + 0x9E3779B97F4A7C15ULL + (idle_key << 6) + (idle_key >> 2);

    local_idle_item_t *idle = localidletableGetIdleItemByHash(table, idle_key);
    // A hash hit must match the full identity; otherwise this is a collision and must fail closed.
    if (idle != NULL)
    {
        udplistener_lstate_t *existing = idle->userdata;
        if (! idleLineMatchesPacket(existing, t, &data->peer_addr, &data->real_localaddr))
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
            udppayloadDestroy(data);
            return;
        }
    }
    // if idle is NULL, it means this is the first packet from this peer, so we need to create a new connection
    // and add it to the idle table
    if (idle == NULL)
    {
        idle = localidletableCreateItem(table, idle_key, NULL, onUdpConnectonExpire, kUdpInitExpireTime);
        // if idle is NULL, it means we failed to create a new idle item (duplicate hash, etc)
        if (! idle)
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
            udppayloadDestroy(data);
            return;
        }
        line_t *l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);

        udplistener_lstate_t *ls = lineGetState(l, t);

        udplistenerLinestateInitialize(ls, l, t, sock, real_localport, &data->peer_addr, &data->real_localaddr);

        idle->userdata  = ls;
        ls->idle_handle = idle;

        if (! withLineLocked(l, tunnelNextUpStreamInit, t))
        {
            LOGW("UdpListener: socket just got closed by upstream before anything happend");

            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
            udppayloadDestroy(data);
            return;
        }
    }
    else
    {
        localidletableKeepIdleItemForAtleast(table, idle, kUdpKeepExpireTime);
    }

    udplistener_lstate_t *ls = idle->userdata;

    if (ls->read_paused)
    {
        // drop the payload if the read is paused
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
    }
    else
    {
        // LOGD("reading %d bytes", sbufGetLength(buf));

        tunnelNextUpStreamPayload(t, ls->line, buf);
    }
    udppayloadDestroy(data);
}
