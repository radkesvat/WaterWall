#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *httpclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(httpclient_tstate_t), sizeof(httpclient_lstate_t));

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

    if (hv_d == 2.0)
    {
        t->fnInitU    = &httpclientV2TunnelUpStreamInit;
        t->fnEstU     = &httpclientV2TunnelUpStreamEst;
        t->fnFinU     = &httpclientV2TunnelUpStreamFinish;
        t->fnPayloadU = &httpclientV2TunnelUpStreamPayload;
        t->fnPauseU   = &httpclientV2TunnelUpStreamPause;
        t->fnResumeU  = &httpclientV2TunnelUpStreamResume;

        t->fnInitD    = &httpclientV2TunnelDownStreamInit;
        t->fnEstD     = &httpclientV2TunnelDownStreamEst;
        t->fnFinD     = &httpclientV2TunnelDownStreamFinish;
        t->fnPayloadD = &httpclientV2TunnelDownStreamPayload;
        t->fnPauseD   = &httpclientV2TunnelDownStreamPause;
        t->fnResumeD  = &httpclientV2TunnelDownStreamResume;

        nghttp2_session_callbacks_new(&(ts->cbs));
        nghttp2_session_callbacks_set_on_header_callback(ts->cbs, httpclientV2OnHeaderCallBack);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(ts->cbs, httpclientV2OnDataChunkRecvCallBack);
        nghttp2_session_callbacks_set_on_frame_recv_callback(ts->cbs, httpclientV2OnFrameRecvCallBack);
        nghttp2_session_callbacks_set_on_stream_close_callback(ts->cbs, httpclientV2OnStreamClosedCallBack);

        nghttp2_option_new(&(ts->ngoptions));
        nghttp2_option_set_peer_max_concurrent_streams(ts->ngoptions, 0xffffffffU);
        nghttp2_option_set_no_http_messaging(ts->ngoptions, 1);
        nghttp2_option_set_no_auto_window_update(ts->ngoptions, 1);
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

    // nghttp2_option_set_no_http_messaging use this with grpc?

    return t;
}
