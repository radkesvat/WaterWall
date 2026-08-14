#include "structure.h"

#include "loggers/network_logger.h"

static void udpstatelesssocketStopIo(udpstatelesssocket_tstate_t *state)
{
    if (state->async_session != NULL)
    {
        tunnelasyncsessionCloseAndQuiesce(state->async_session);
    }

    wio_t *io = state->socket.io;
    if (io == NULL)
    {
        return;
    }

    /* Normal construction is pinned to worker 0; never lose a foreign WIO. */
    assert(state->io_wid == 0);
    assert(currentThreadIsEventWorkerWID(state->io_wid));
    assert(getWorker(state->io_wid)->loop != NULL);
    wioClose(io);
    state->socket.io = NULL;
}

void udpstatelesssocketTunnelOnPreStop(tunnel_t *t)
{
    udpstatelesssocketStopIo(tunnelGetState(t));
}

void udpstatelesssocketTunnelOnStop(tunnel_t *t)
{
    udpstatelesssocketStopIo(tunnelGetState(t));
}

void udpstatelesssocketTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    // onWorkerStop runs on the worker being stopped, for its own slot only.
    assert(currentThreadIsEventWorkerWID(wid));

    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    if (state->socket.idle_tables == NULL)
    {
        return;
    }

    local_idle_table_t *table = state->socket.idle_tables[wid];
    if (table == NULL)
    {
        return;
    }

    localidletableDrainItems(table);
    localidletableDestroy(table);
    state->socket.idle_tables[wid] = NULL;
}
