#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    discard t;
}

void udpconnectorTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    udpconnector_tstate_t *ts = tunnelGetState(t);
    assert(ts->worker_pools != NULL);

    udpconnector_worker_pool_t *pool = &ts->worker_pools[wid];
    assert(pool->wid == wid);
    pool->quiescing = true;

    if (pool->idle_table != NULL)
    {
        localidletableQuiesce(pool->idle_table);
    }

    for (udpconnector_pool_socket_t *s = pool->v4_sockets; s != NULL; s = s->next)
    {
        if (s->io != NULL)
        {
            wioSetCallBackRead(s->io, NULL);
            wioReadStop(s->io);
        }
    }

    for (udpconnector_pool_socket_t *s = pool->v6_sockets; s != NULL; s = s->next)
    {
        if (s->io != NULL)
        {
            wioSetCallBackRead(s->io, NULL);
            wioReadStop(s->io);
        }
    }
}

void udpconnectorTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    udpconnector_tstate_t *ts = tunnelGetState(t);
    assert(ts->worker_pools != NULL);

    udpconnector_worker_pool_t *pool = &ts->worker_pools[wid];
    assert(pool->wid == wid);
    pool->quiescing = true;

    if (pool->idle_table != NULL)
    {
        localidletableDrainItems(pool->idle_table);
    }

    if (UNLIKELY(pool->active_bindings_count != 0))
    {
        LOGF("UdpConnector: worker drain left active socket bindings on worker %u", (unsigned int) wid);
        abortProgramNow(1);
    }

    while (pool->v4_sockets != NULL)
    {
        udpconnector_pool_socket_t *sock = pool->v4_sockets;
        assert(sock->active_bindings_count == 0);
        udpconnectorPoolSocketRetire(sock);
    }

    while (pool->v6_sockets != NULL)
    {
        udpconnector_pool_socket_t *sock = pool->v6_sockets;
        assert(sock->active_bindings_count == 0);
        udpconnectorPoolSocketRetire(sock);
    }

    assert(pool->v4_sockets_count == 0 && pool->v6_sockets_count == 0);

    if (pool->idle_table != NULL)
    {
        localidletableDestroy(pool->idle_table);
        pool->idle_table = NULL;
    }

    pool->next_line_idle_id = 0;
}
