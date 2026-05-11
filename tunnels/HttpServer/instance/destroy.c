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

    if (ts->split_maps_initialized)
    {
        mutexDestroy(&ts->split_upload_map_mutex);
        mutexDestroy(&ts->split_download_map_mutex);
        hmap_httpserver_split_t_drop(&ts->split_upload_map);
        hmap_httpserver_split_t_drop(&ts->split_download_map);
        ts->split_maps_initialized = false;
    }

    tunnelDestroy(t);
}
