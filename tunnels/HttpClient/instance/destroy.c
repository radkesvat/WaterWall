#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelDestroy(tunnel_t *t)
{
    if (t == NULL)
    {
        return;
    }

    httpclient_tstate_t *ts = tunnelGetState(t);

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

    memoryFree(ts->scheme);
    memoryFree(ts->path);
    memoryFree(ts->host);
    memoryFree(ts->method);
    memoryFree(ts->user_agent);
    memoryFree(ts->websocket_origin);
    memoryFree(ts->websocket_subprotocol);
    memoryFree(ts->websocket_extensions);
    memoryFree(ts->upgrade_protocol);
    memoryFree(ts->upgrade_settings_payload);
    memoryFree(ts->upgrade_settings_b64);

    tunnelDestroy(t);
}
