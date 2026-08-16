#include "structure.h"

#include "loggers/network_logger.h"

static void udpstatelesssocketCloseExternalAdmission(udpstatelesssocket_tstate_t *state)
{
    if (state->async_session != NULL)
    {
        tunnelasyncsessionClose(state->async_session);
    }
}

void udpstatelesssocketTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard context;
    udpstatelesssocketCloseExternalAdmission(tunnelGetState(t));
}

void udpstatelesssocketTunnelOnQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                      context;
    udpstatelesssocket_tstate_t *state = tunnelGetState(t);
    if (state->async_session != NULL)
    {
        tunnelasyncsessionWaitQuiesced(state->async_session);
    }
}

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
    if (state->socket.idle_tables != NULL && state->socket.idle_tables[wid] != NULL)
    {
        localidletableQuiesce(state->socket.idle_tables[wid]);
    }
}

void udpstatelesssocketTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard context;
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
