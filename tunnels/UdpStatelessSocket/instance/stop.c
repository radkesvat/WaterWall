#include "structure.h"

#include "loggers/network_logger.h"

static void udpstatelesssocketStopIo(udpstatelesssocket_tstate_t *state)
{
    wio_t *io = state->socket.io;
    if (io == NULL)
    {
        return;
    }

    state->socket.io = NULL;
    if (getTID() == getWorker(state->io_wid)->tid && getWorker(state->io_wid)->loop != NULL)
    {
        wioClose(io);
    }
}

void udpstatelesssocketTunnelOnStop(tunnel_t *t)
{
    udpstatelesssocketStopIo(tunnelGetState(t));
}

void udpstatelesssocketTunnelOnWorkerStop(tunnel_t *t, wid_t wid)
{
    assert(wid == getWID());

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
