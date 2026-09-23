#include "structure.h"

#include "loggers/network_logger.h"

local_idle_table_t *udpconnectorGetWorkerIdleTable(udpconnector_tstate_t *ts)
{
    assert(ts != NULL);
    assert(ts->worker_pools != NULL);

    const wid_t wid = getCurrentEventWorkerWID();
    assert(wid < getWorkersCount());

    udpconnector_worker_pool_t *pool = &ts->worker_pools[wid];
    if (pool->idle_table == NULL)
    {
        pool->idle_table = localIdleTableCreate(getWorkerLoop(wid));
    }

    return pool->idle_table;
}

local_idle_table_t *udpconnectorGetLineIdleTable(udpconnector_tstate_t *ts, line_t *l)
{
    assert(l != NULL);
    assert(lineIsOnCurrentEventWorker(l));
    discard l;
    return udpconnectorGetWorkerIdleTable(ts);
}

void udpconnectorOnIdleConnectionExpire(local_idle_item_t *idle_udp)
{
    udpconnector_lstate_t *ls = (udpconnector_lstate_t *) (idle_udp->userdata);
    assert(ls != NULL && ls->tunnel != NULL && ls->line != NULL);

    idle_udp->userdata = NULL;
    ls->idle_handle    = NULL; // mark as removed

    tunnel_t *t = ls->tunnel;
    line_t   *l = ls->line;

    const bool worker_drain = idle_udp->table == NULL;
    if (! worker_drain)
    {
        LOGW("UdpConnector: expired 1 udp connection");
    }
    udpconnectorLineDetach(t, l, ls, worker_drain ? kUdpConnectorDetachWorkerDrain : kUdpConnectorDetachIdleExpire);
}

bool udpconnectorQueueWrite(udpconnector_lstate_t *ls, buffer_queue_t *queue, sbuf_t **buf)
{
    assert(queue->budget == &ls->write_budget);
    discard ls;
    return bufferqueueTryPushBack(queue, buf);
}

sbuf_t *udpconnectorPopWrite(udpconnector_lstate_t *ls, buffer_queue_t *queue)
{
    assert(queue->budget == &ls->write_budget);
    discard ls;
    return bufferqueuePopFront(queue);
}

size_t udpconnectorQueuedWriteBytes(udpconnector_lstate_t *ls)
{
    return bufferbudgetGetUsage(&ls->write_budget).bytes;
}

bool udpconnectorFlushWriteQueue(udpconnector_lstate_t *ls)
{
    line_t                 *line    = ls->line;
    udpconnector_binding_t *binding = ls->fixed_binding != NULL ? ls->fixed_binding : ls->last_send_binding;
    assert(binding != NULL && binding->active);

    while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
    {
        sbuf_t *buf = udpconnectorPopWrite(ls, &ls->pause_queue);
        if (! udpconnectorBindingCanSend(binding))
        {
            lineReuseBuffer(line, buf);
            continue;
        }
        wioWriteDatagram(binding->socket->io, buf, &binding->peer_addr);
        if (! lineIsAlive(line))
            return false;
    }
    return true;
}

bool udpconnectorReplayWriteQueue(udpconnector_lstate_t *ls)
{
    tunnel_t *t = ls->tunnel;
    line_t   *l = ls->line;

    while (bufferqueueGetBufCount(&ls->pause_queue) > 0)
    {
        sbuf_t *buf = udpconnectorPopWrite(ls, &ls->pause_queue);
        udpconnectorTunnelUpStreamPayload(t, l, buf);

        if (! lineIsAlive(l))
        {
            return false;
        }
    }

    return true;
}
