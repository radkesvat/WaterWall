#include "structure.h"

#include "loggers/network_logger.h"



tunnel_t *httpclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(httpclient_tstate_t), sizeof(httpclient_lstate_t));

    t->fnInitU    = &httpclientTunnelUpStreamInit;
    t->fnEstU     = &httpclientTunnelUpStreamEst;
    t->fnFinU     = &httpclientTunnelUpStreamFinish;
    t->fnPayloadU = &httpclientTunnelUpStreamPayload;
    t->fnPauseU   = &httpclientTunnelUpStreamPause;
    t->fnResumeU  = &httpclientTunnelUpStreamResume;

    t->fnInitD    = &httpclientTunnelDownStreamInit;
    t->fnEstD     = &httpclientTunnelDownStreamEst;
    t->fnFinD     = &httpclientTunnelDownStreamFinish;
    t->fnPayloadD = &httpclientTunnelDownStreamPayload;
    t->fnPauseD   = &httpclientTunnelDownStreamPause;
    t->fnResumeD  = &httpclientTunnelDownStreamResume;

    t->onPrepare = &httpclientTunnelOnPrepair;
    t->onStart   = &httpclientTunnelOnStart;
    t->onDestroy = &httpclientTunnelDestroy;

    const cJSON *settings = node->node_settings_json;

    const cJSON *hv = cJSON_GetObjectItemCaseSensitive(settings, "http-version");

    if (! cJSON_IsNumber(hv))
    {
        LOGF("JSON Error: Http2Client->settings->http-version (number field) : The data was empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    double hv_d = hv->valuedouble;

    if (hv_d != 2.0)
    {
        LOGF("JSON Error: Http2Client->settings->http-version (number field) : Only HTTP/2 (2) is supported");
        tunnelDestroy(t);
        return NULL;
    }

    httpclient_tstate_t *ts = tunnelGetState(t);

    // nghttp2_session_callbacks_new(&(ts->cbs));
    // nghttp2_session_callbacks_set_on_header_callback(ts->cbs, httpclientV2OnHeaderCallBack);
    // nghttp2_session_callbacks_set_on_data_chunk_recv_callback(ts->cbs, httpclientV2OnDataChunkRecvCallBack);
    // nghttp2_session_callbacks_set_on_frame_recv_callback(ts->cbs, httpclientV2OnFrameRecvCallBack);
    // nghttp2_session_callbacks_set_on_stream_close_callback(ts->cbs, httpclientV2OnStreamClosedCallBack);

    for (size_t i = 0; i < getWorkersCount(); i++)
    {
        ts->thread_cpool[i] = (thread_connection_pool_t) {.round_index = 0, .cons = vec_cons_with_capacity(8)};
    }

    if (! getStringFromJsonObject(&(ts->host), settings, "host"))
    {
        LOGF("JSON Error: Http2Client->settings->host (string field) : The data was empty or invalid");
        return NULL;
    }
    getStringFromJsonObjectOrDefault(&(ts->path), settings, "path", "/");

    if (! getIntFromJsonObject(&(ts->host_port), settings, "port"))
    {
        LOGF("JSON Error: Http2Client->settings->port (number field) : The data was empty or invalid");
        return NULL;
    }

    getStringFromJsonObjectOrDefault(&(ts->scheme), settings, "scheme", "https");

    char *content_type_buf = NULL;
    if (getStringFromJsonObject(&content_type_buf, settings, "content-type"))
    {
        ts->content_type = httpContentTypeEnum(content_type_buf);
        memoryFree(content_type_buf);
    }

    int int_concurrency;
    getIntFromJsonObjectOrDefault(&(int_concurrency), settings, "concurrency", kDefaultHttp2MuxConcurrency);
    ts->concurrency = int_concurrency;

    nghttp2_option_new(&(ts->ngoptions));
    nghttp2_option_set_peer_max_concurrent_streams(ts->ngoptions, 0xffffffffU);
    nghttp2_option_set_no_http_messaging(ts->ngoptions, 1);
    nghttp2_option_set_no_auto_window_update(ts->ngoptions, 1);
    // nghttp2_option_set_no_http_messaging use this with grpc?
    
    // nghttp2_mem mem = {.mem_user_data = NULL, // Optional: pass your context here
    //                    .malloc        = &httpclientNgh2CustomMemoryAllocate,
    //                    .free          = &httpclientNgh2CustomMemoryFree,
    //                    .calloc        = &httpclientNgh2CustomMemoryCalloc,
    //                    .realloc       = &httpclientNgh2CustomMemoryReAllocate};

    return t;
}
