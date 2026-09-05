#include "structure.h"

#include "loggers/network_logger.h"

void udpstatelesssocketTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    if (wid == state->io_wid && state->socket.io != NULL)
    {
        wioClose(state->socket.io);
        state->socket.io = NULL;
    }
    assert(state->socket.idle_tables != NULL);
    if (state->socket.idle_tables[wid] != NULL)
    {
        localidletableQuiesce(state->socket.idle_tables[wid]);
    }
}

void udpstatelesssocketTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
    assert(currentThreadIsEventWorkerWID(wid));

    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    assert(state->socket.idle_tables != NULL);

    local_idle_table_t *table = state->socket.idle_tables[wid];
    if (table == NULL)
    {
        return;
    }

    localidletableDrainItems(table);
    localidletableDestroy(table);
    state->socket.idle_tables[wid] = NULL;
}
