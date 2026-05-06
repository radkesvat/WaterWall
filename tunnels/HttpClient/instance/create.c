#include "structure.h"

#include "loggers/network_logger.h"

static size_t base64UrlEncode(const uint8_t *src, size_t len, char *dst, size_t cap)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    if (src == NULL || dst == NULL)
    {
        return 0;
    }

    size_t out_len = 0;
    size_t i       = 0;

    while (i + 3 <= len)
    {
        uint32_t v = ((uint32_t) src[i] << 16) | ((uint32_t) src[i + 1] << 8) | ((uint32_t) src[i + 2]);
        if (out_len + 4 >= cap)
        {
            return 0;
        }
        dst[out_len++] = table[(v >> 18) & 0x3F];
        dst[out_len++] = table[(v >> 12) & 0x3F];
        dst[out_len++] = table[(v >> 6) & 0x3F];
        dst[out_len++] = table[v & 0x3F];
        i += 3;
    }

    size_t rem = len - i;
    if (rem == 1)
    {
        uint32_t v = ((uint32_t) src[i] << 16);
        if (out_len + 2 >= cap)
        {
            return 0;
        }
        dst[out_len++] = table[(v >> 18) & 0x3F];
        dst[out_len++] = table[(v >> 12) & 0x3F];
    }
    else if (rem == 2)
    {
        uint32_t v = ((uint32_t) src[i] << 16) | ((uint32_t) src[i + 1] << 8);
        if (out_len + 3 >= cap)
        {
            return 0;
        }
        dst[out_len++] = table[(v >> 18) & 0x3F];
        dst[out_len++] = table[(v >> 12) & 0x3F];
        dst[out_len++] = table[(v >> 6) & 0x3F];
    }

    dst[out_len] = '\0';
    return out_len;
}

static bool strEqualsAnyIgnoreCase(const char *value, const char *a, const char *b, const char *c, const char *d)
{
    if (value == NULL)
    {
        return false;
    }

    char *tmp = stringDuplicate(value);
    stringLowerCase(tmp);

    bool ret = false;
    if ((a != NULL && stringCompare(tmp, a) == 0) || (b != NULL && stringCompare(tmp, b) == 0) ||
        (c != NULL && stringCompare(tmp, c) == 0) || (d != NULL && stringCompare(tmp, d) == 0))
    {
        ret = true;
    }

    memoryFree(tmp);
    return ret;
}

static bool parseHttpVersionMode(httpclient_tstate_t *ts, const cJSON *settings)
{
    const cJSON *hv = cJSON_GetObjectItemCaseSensitive(settings, "http-version");

    if (cJSON_IsNumber(hv))
    {
        if (hv->valueint == 1)
        {
            ts->version_mode = kHttpClientVersionModeHttp1;
            return true;
        }
        if (hv->valueint == 2)
        {
            ts->version_mode = kHttpClientVersionModeHttp2;
            return true;
        }

        LOGF("JSON Error: HttpClient->settings->http-version only supports 1 or 2 as number");
        return false;
    }

    if (cJSON_IsString(hv) && hv->valuestring != NULL)
    {
        if (strEqualsAnyIgnoreCase(hv->valuestring, "1.1", "http1", "http1.1", "1"))
        {
            ts->version_mode = kHttpClientVersionModeHttp1;
            return true;
        }
        if (strEqualsAnyIgnoreCase(hv->valuestring, "2", "2.0", "http2", "h2"))
        {
            ts->version_mode = kHttpClientVersionModeHttp2;
            return true;
        }
        if (strEqualsAnyIgnoreCase(hv->valuestring, "both", "any", "auto", "1.1+2"))
        {
            ts->version_mode = kHttpClientVersionModeBoth;
            return true;
        }

        LOGF("JSON Error: HttpClient->settings->http-version string supports: 1.1, 2, both");
        return false;
    }

    ts->version_mode = kHttpClientVersionModeHttp2;
    return true;
}

static bool parseHttpMethod(httpclient_tstate_t *ts, const cJSON *settings)
{
    if (! getStringFromJsonObjectOrDefault(&ts->method, settings, "method", "POST"))
    {
        // default applied
    }

    ts->method_enum = httpMethodEnum(ts->method);
    if (ts->method_enum == kHttpCustomMethod)
    {
        LOGF("JSON Error: HttpClient->settings->method is invalid: %s", ts->method);
        return false;
    }

    return true;
}

static bool parseRequiredFields(httpclient_tstate_t *ts, const cJSON *settings)
{
    if (! getStringFromJsonObject(&ts->host, settings, "host"))
    {
        LOGF("JSON Error: HttpClient->settings->host (string field) is required");
        return false;
    }

    getStringFromJsonObjectOrDefault(&ts->path, settings, "path", "/");
    getStringFromJsonObjectOrDefault(&ts->scheme, settings, "scheme", "https");

    if (! parseHttpMethod(ts, settings))
    {
        return false;
    }

    char *content_type_buf = NULL;
    if (getStringFromJsonObject(&content_type_buf, settings, "content-type"))
    {
        ts->content_type = httpContentTypeEnum(content_type_buf);
        memoryFree(content_type_buf);
    }
    else
    {
        ts->content_type = kContentTypeNone;
    }

    return true;
}

static void parsePortAndUpgrade(httpclient_tstate_t *ts, const cJSON *settings)
{
    if (! getIntFromJsonObject(&ts->host_port, settings, "port"))
    {
        ts->host_port = strEqualsAnyIgnoreCase(ts->scheme, "https", NULL, NULL, NULL) ? kHttpClientDefaultHttpsPort
                                                                                        : kHttpClientDefaultHttp1Port;
    }

    bool default_upgrade = (ts->version_mode == kHttpClientVersionModeBoth);
    getBoolFromJsonObjectOrDefault(&ts->enable_upgrade, settings, "upgrade", default_upgrade);

    ts->headers                  = cJSON_GetObjectItemCaseSensitive(settings, "headers");
    ts->upgrade_request_headers  = cJSON_GetObjectItemCaseSensitive(settings, "upgrade-request-headers");
    ts->upgrade_response_headers = cJSON_GetObjectItemCaseSensitive(settings, "upgrade-response-headers");
    getStringFromJsonObject(&ts->upgrade_protocol, settings, "upgrade-protocol");
}

static void parseUserAgentAndWebSocket(httpclient_tstate_t *ts, const cJSON *settings)
{
    getStringFromJsonObjectOrDefault(&ts->user_agent, settings, "user-agent", "WaterWall/1.x");
    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);
    getBoolFromJsonObjectOrDefault(&ts->full_duplex, settings, "full-duplex", false);

    getBoolFromJsonObjectOrDefault(&ts->websocket_enabled, settings, "websocket", false);

    if (ts->websocket_enabled)
    {
        getStringFromJsonObject(&ts->websocket_origin, settings, "websocket-origin");
        getStringFromJsonObject(&ts->websocket_subprotocol, settings, "websocket-subprotocol");
        getStringFromJsonObject(&ts->websocket_extensions, settings, "websocket-extensions");
    }
}

static bool initializeNghttp2State(httpclient_tstate_t *ts)
{
    if (ts->version_mode == kHttpClientVersionModeHttp1)
    {
        return true;
    }

    if (nghttp2_session_callbacks_new(&ts->cbs) != 0)
    {
        LOGF("HttpClient: nghttp2_session_callbacks_new failed");
        return false;
    }

    if (nghttp2_option_new(&ts->ngoptions) != 0)
    {
        LOGF("HttpClient: nghttp2_option_new failed");
        return false;
    }

    nghttp2_option_set_peer_max_concurrent_streams(ts->ngoptions, 1);
    nghttp2_option_set_no_http_messaging(ts->ngoptions, 0);
    nghttp2_option_set_no_auto_window_update(ts->ngoptions, 0);

    return true;
}

static bool buildUpgradeSettings(httpclient_tstate_t *ts)
{
    if (ts->version_mode == kHttpClientVersionModeHttp1)
    {
        return true;
    }

    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, (1U << 20)},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (uint32_t) kHttpClientHttp2FrameBytes}
    };

    uint8_t payload[128];
    nghttp2_ssize raw_len = nghttp2_pack_settings_payload2(payload, sizeof(payload), settings, ARRAY_SIZE(settings));
    if (raw_len <= 0)
    {
        LOGF("HttpClient: nghttp2_pack_settings_payload2 failed");
        return false;
    }

    ts->upgrade_settings_payload_len = (size_t) raw_len;
    ts->upgrade_settings_payload     = memoryAllocate(ts->upgrade_settings_payload_len);
    memoryCopy(ts->upgrade_settings_payload, payload, ts->upgrade_settings_payload_len);

    size_t b64_cap            = ((ts->upgrade_settings_payload_len + 2U) / 3U) * 4U + 2U;
    ts->upgrade_settings_b64  = memoryAllocate(b64_cap);
    size_t b64_len            = base64UrlEncode(ts->upgrade_settings_payload, ts->upgrade_settings_payload_len,
                                                ts->upgrade_settings_b64, b64_cap);
    if (b64_len == 0)
    {
        LOGF("HttpClient: HTTP2-Settings encoding failed");
        return false;
    }

    return true;
}

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

    httpclient_tstate_t *ts       = tunnelGetState(t);
    const cJSON         *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: HttpClient->settings (object field) is empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    if (! parseHttpVersionMode(ts, settings) || ! parseRequiredFields(ts, settings))
    {
        httpclientTunnelDestroy(t);
        return NULL;
    }

    parsePortAndUpgrade(ts, settings);
    parseUserAgentAndWebSocket(ts, settings);

    if (! initializeNghttp2State(ts))
    {
        httpclientTunnelDestroy(t);
        return NULL;
    }

    if (! buildUpgradeSettings(ts))
    {
        httpclientTunnelDestroy(t);
        return NULL;
    }

    return t;
}
