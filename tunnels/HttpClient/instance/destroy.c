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
    memoryFree(ts->split_upload_method);
    memoryFree(ts->split_download_method);
    memoryFree(ts->split_upload_path);
    memoryFree(ts->split_download_path);
    memoryFree(ts->split_id_name);
    memoryFree(ts->split_direction_name);
    memoryFree(ts->split_upload_value);
    memoryFree(ts->split_download_value);
    memoryFree(ts->split_cache_bypass_name);
    memoryFree(ts->split_token);
    memoryFree(ts->split_token_name);
    memoryFree(ts->upgrade_settings_payload);
    memoryFree(ts->upgrade_settings_b64);

    tunnelDestroy(t);
}
