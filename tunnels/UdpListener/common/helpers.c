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

    // Hash the packet snapshot, not the shared socket's mutable peer address.
    hash_t peeraddr_hash = sockaddrCalcHashWithPort(&data->peer_addr);

    local_idle_item_t *idle = localidletableGetIdleItemByHash(table, peeraddr_hash);
    // if idle is NULL, it means this is the first packet from this peer, so we need to create a new connection
    // and add it to the idle table
    if (idle == NULL)
    {
        idle = localidletableCreateItem(table, peeraddr_hash, NULL, onUdpConnectonExpire, kUdpInitExpireTime);
        // if idle is NULL, it means we failed to create a new idle item (duplicate hash, etc)
        if (! idle)
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
            udppayloadDestroy(data);
            return;
        }
        line_t *l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);

        udplistener_lstate_t *ls = lineGetState(l, t);

        udplistenerLinestateInitialize(ls, l, t, sock, real_localport, &data->peer_addr);

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
