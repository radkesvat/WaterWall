#include "structure.h"

#include "loggers/network_logger.h"

static void onUdpConnectonExpire(widle_item_t *idle_udp)
{
    udplistener_lstate_t *ls = idle_udp->userdata;
    assert(ls != NULL && ls->tunnel != NULL);
    idle_udp->userdata = NULL;

    LOGD("UdpListener: expired 1 udp connection on FD:%x ", wioGetFD(ls->uio->io));
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

    widle_table_t *table          = data->sock->table;
    udpsock_t     *sock           = data->sock;
    tunnel_t      *t              = data->tunnel;
    wid_t          wid            = data->wid;
    sbuf_t        *buf            = data->buf;
    uint16_t       real_localport = data->real_localport;

    hash_t peeraddr_hash = sockaddrCalcHashWithPort((sockaddr_u *) wioGetPeerAddr(sock->io));

    widle_item_t *idle = idleTableGetIdleItemByHash(wid, table, peeraddr_hash);
    // if idle is NULL, it means this is the first packet from this peer, so we need to create a new connection
    // and add it to the idle table
    if (idle == NULL)
    {
        idle = idleItemNew(table, peeraddr_hash, NULL, onUdpConnectonExpire, wid, (uint64_t) kUdpInitExpireTime);
        // if idle is NULL, it means we failed to create a new idle item (duplicate hash, etc)
        if (! idle)
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
            udppayloadDestroy(data);
            return;
        }
        line_t *l = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), wid);

        udplistener_lstate_t *ls = lineGetState(l, t);

        udplistenerLinestateInitialize(ls, l, t, sock, real_localport);

        lineLock(l);
        {
            tunnelNextUpStreamInit(t, l);
            if (! lineIsAlive(l))
            {
                LOGW("UdpListener: socket just got closed by upstream before anything happend");
                bool removed = idleTableRemoveIdleItemByHash(wid, table, peeraddr_hash);
                if (! removed)
                {
                    LOGF("UdpListener: failed to remove idle item for hash %x, how?", peeraddr_hash);
                    terminateProgram(1);
                }
                udplistenerLinestateDestroy(ls);
                bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
                udppayloadDestroy(data);
                lineUnlock(l);
                return;
            }
        }
        lineUnlock(l);

        idle->userdata  = ls;
        ls->idle_handle = idle;
    }
    else
    {
        idleTableKeepIdleItemForAtleast(table, idle, (uint64_t) kUdpKeepExpireTime);
    }

    udplistener_lstate_t *ls = idle->userdata;

    if (ls->read_paused)
    {
        // drop the payload if the read is paused
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
    }
    else
    {
        tunnelNextUpStreamPayload(t, ls->line, buf);
    }
    udppayloadDestroy(data);
}
