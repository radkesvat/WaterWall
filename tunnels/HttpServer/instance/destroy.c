#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelDestroy(tunnel_t *t)
{
    if (t == NULL)
    {
        return;
    }

    httpserver_tstate_t *ts = tunnelGetState(t);

    if (ts->cbs != NULL)
    {
        nghttp2_session_callbacks_del(ts->cbs);
        ts->cbs = NULL;
    }

    if (ts->ngoptions != NULL)
    {
        nghttp2_option_del(ts->ngoptions);
        ts->ngoptions = NULL;
    }

    memoryFree(ts->expected_host);
    memoryFree(ts->expected_path);
    memoryFree(ts->expected_method);
    memoryFree(ts->websocket_origin);
    memoryFree(ts->websocket_subprotocol);
    memoryFree(ts->upgrade_protocol);

    tunnelDestroy(t);
}
