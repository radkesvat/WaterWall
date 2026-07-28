#include "structure.h"

#include "loggers/network_logger.h"
#include "utils/base64.h"

static bool parseSplitPlacement(const char *value, httpclient_split_placement_t *out, const char *field_name)
{
    if (value == NULL || out == NULL)
    {
        return false;
    }

    static const char *const query_aliases[]  = {"query", "query-parameter", "query-param", "param"};
    static const char *const header_aliases[] = {"header", "http-header"};
    static const char *const cookie_aliases[] = {"cookie", "cookies"};
    static const char *const path_aliases[]   = {"path", "path-segment", "path-template"};

    if (stringAsciiCaseEqualsAny(value, query_aliases, ARRAY_SIZE(query_aliases)))
    {
        *out = kHttpClientSplitPlacementQuery;
        return true;
    }
    if (stringAsciiCaseEqualsAny(value, header_aliases, ARRAY_SIZE(header_aliases)))
    {
        *out = kHttpClientSplitPlacementHeader;
        return true;
    }
    if (stringAsciiCaseEqualsAny(value, cookie_aliases, ARRAY_SIZE(cookie_aliases)))
    {
        *out = kHttpClientSplitPlacementCookie;
        return true;
    }
    if (stringAsciiCaseEqualsAny(value, path_aliases, ARRAY_SIZE(path_aliases)))
    {
        *out = kHttpClientSplitPlacementPath;
        return true;
    }

    LOGF("JSON Error: HttpClient->settings->%s supports: query, header, cookie, path", field_name);
    return false;
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
        static const char *const h1_aliases[]   = {"1.1", "http1", "http1.1", "1"};
        static const char *const h2_aliases[]   = {"2", "2.0", "http2", "h2"};
        static const char *const both_aliases[] = {"both", "any", "auto", "1.1+2"};

        if (stringAsciiCaseEqualsAny(hv->valuestring, h1_aliases, ARRAY_SIZE(h1_aliases)))
        {
            ts->version_mode = kHttpClientVersionModeHttp1;
            return true;
        }
        if (stringAsciiCaseEqualsAny(hv->valuestring, h2_aliases, ARRAY_SIZE(h2_aliases)))
        {
            ts->version_mode = kHttpClientVersionModeHttp2;
            return true;
        }
        if (stringAsciiCaseEqualsAny(hv->valuestring, both_aliases, ARRAY_SIZE(both_aliases)))
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

static bool parseHttp1TransportMode(httpclient_tstate_t *ts, const cJSON *settings)
{
    ts->h1_transport_mode = kHttpClientH1TransportSingle;

    const cJSON *mode = cJSON_GetObjectItemCaseSensitive(settings, "http1-mode");
    if (! cJSON_IsString(mode) || mode->valuestring == NULL)
    {
        bool split_enabled = false;
        if (getBoolFromJsonObject(&split_enabled, settings, "http1-split") && split_enabled)
        {
            ts->h1_transport_mode = kHttpClientH1TransportSplit;
        }
        return true;
    }

    static const char *const single_aliases[] = {"single", "classic", "full-duplex", "legacy"};
    static const char *const split_aliases[]  = {"split", "half-duplex", "dual", "dual-connection"};

    if (stringAsciiCaseEqualsAny(mode->valuestring, single_aliases, ARRAY_SIZE(single_aliases)))
    {
        ts->h1_transport_mode = kHttpClientH1TransportSingle;
        return true;
    }

    if (stringAsciiCaseEqualsAny(mode->valuestring, split_aliases, ARRAY_SIZE(split_aliases)))
    {
        ts->h1_transport_mode = kHttpClientH1TransportSplit;
        return true;
    }

    LOGF("JSON Error: HttpClient->settings->http1-mode supports: single, split");
    return false;
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

static bool parseSplitMethod(char **dest, enum http_method *method_enum, const cJSON *root, const cJSON *side,
                             const char *root_key, const char *side_key, const char *def, const char *log_name)
{
    if (side != NULL && getStringFromJsonObject(dest, side, side_key))
    {
        ;
    }
    else if (! getStringFromJsonObject(dest, root, root_key))
    {
        *dest = stringDuplicate(def);
    }

    *method_enum = httpMethodEnum(*dest);
    if (*method_enum == kHttpCustomMethod)
    {
        LOGF("JSON Error: HttpClient->settings->%s is invalid: %s", log_name, *dest);
        return false;
    }

    return true;
}

static void parseSplitString(char **dest, const cJSON *root, const cJSON *side, const char *root_key,
                             const char *side_key, const char *def)
{
    if (side != NULL && getStringFromJsonObject(dest, side, side_key))
    {
        return;
    }

    if (getStringFromJsonObject(dest, root, root_key))
    {
        return;
    }

    *dest = stringDuplicate(def);
}

static bool parseHttp1SplitSettings(httpclient_tstate_t *ts, const cJSON *settings)
{
    if (ts->h1_transport_mode != kHttpClientH1TransportSplit)
    {
        return true;
    }

    if (ts->version_mode != kHttpClientVersionModeHttp1)
    {
        LOGF("JSON Error: HttpClient split HTTP/1 transport requires http-version = 1/http1");
        return false;
    }

    if (ts->websocket_enabled)
    {
        LOGF("JSON Error: HttpClient split HTTP/1 transport cannot be combined with websocket mode");
        return false;
    }

    const cJSON *split = cJSON_GetObjectItemCaseSensitive(settings, "split");
    if (! cJSON_IsObject(split))
    {
        split = settings;
    }

    const cJSON *upload   = cJSON_GetObjectItemCaseSensitive(split, "upload");
    const cJSON *download = cJSON_GetObjectItemCaseSensitive(split, "download");
    if (! cJSON_IsObject(upload))
    {
        upload = NULL;
    }
    if (! cJSON_IsObject(download))
    {
        download = NULL;
    }

    if (! parseSplitMethod(&ts->split_upload_method,
                           &ts->split_upload_method_enum,
                           split,
                           upload,
                           "upload-method",
                           "method",
                           ts->method,
                           "split.upload-method") ||
        ! parseSplitMethod(&ts->split_download_method,
                           &ts->split_download_method_enum,
                           split,
                           download,
                           "download-method",
                           "method",
                           "GET",
                           "split.download-method"))
    {
        return false;
    }

    parseSplitString(&ts->split_upload_path, split, upload, "upload-path", "path", ts->path);
    parseSplitString(&ts->split_download_path, split, download, "download-path", "path", ts->path);
    parseSplitString(&ts->split_id_name, split, NULL, "id-name", "name", "wwid");
    parseSplitString(&ts->split_direction_name, split, NULL, "direction-name", "name", "wwdir");
    parseSplitString(&ts->split_upload_value, split, NULL, "upload-value", "value", "upload");
    parseSplitString(&ts->split_download_value, split, NULL, "download-value", "value", "download");
    parseSplitString(&ts->split_cache_bypass_name, split, NULL, "cache-bypass-name", "name", "wwcb");
    parseSplitString(&ts->split_token_name, split, NULL, "token-name", "name", "X-Waterwall-Token");
    getStringFromJsonObject(&ts->split_token, split, "token");

    char *placement = NULL;
    getStringFromJsonObjectOrDefault(&placement, split, "id-placement", "query");
    bool ok = parseSplitPlacement(placement, &ts->split_id_placement, "split.id-placement");
    memoryFree(placement);
    if (! ok)
    {
        return false;
    }

    placement = NULL;
    getStringFromJsonObjectOrDefault(&placement, split, "direction-placement", "query");
    ok = parseSplitPlacement(placement, &ts->split_direction_placement, "split.direction-placement");
    memoryFree(placement);
    if (! ok)
    {
        return false;
    }

    placement = NULL;
    getStringFromJsonObjectOrDefault(&placement, split, "token-placement", "header");
    ok = parseSplitPlacement(placement, &ts->split_token_placement, "split.token-placement");
    memoryFree(placement);
    if (! ok)
    {
        return false;
    }

    getBoolFromJsonObjectOrDefault(&ts->split_cache_bypass, split, "cache-bypass", true);

    ts->split_upload_headers = cJSON_GetObjectItemCaseSensitive(split, "upload-headers");
    if (! cJSON_IsObject(ts->split_upload_headers) && upload != NULL)
    {
        ts->split_upload_headers = cJSON_GetObjectItemCaseSensitive(upload, "headers");
    }

    ts->split_download_headers = cJSON_GetObjectItemCaseSensitive(split, "download-headers");
    if (! cJSON_IsObject(ts->split_download_headers) && download != NULL)
    {
        ts->split_download_headers = cJSON_GetObjectItemCaseSensitive(download, "headers");
    }

    ts->split_identifier = fastRand64() % 10000000;
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
        static const char *const https_aliases[] = {"https"};
        ts->host_port = stringAsciiCaseEqualsAny(ts->scheme, https_aliases, ARRAY_SIZE(https_aliases))
                            ? kHttpClientDefaultHttpsPort
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

    nghttp2_settings_entry settings[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1},
                                         {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, (1U << 20)},
                                         {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, (uint32_t) kHttpClientHttp2FrameBytes}};

    uint8_t       payload[128];
    nghttp2_ssize raw_len = nghttp2_pack_settings_payload2(payload, sizeof(payload), settings, ARRAY_SIZE(settings));
    if (raw_len <= 0)
    {
        LOGF("HttpClient: nghttp2_pack_settings_payload2 failed");
        return false;
    }

    ts->upgrade_settings_payload_len = (size_t) raw_len;
    ts->upgrade_settings_payload     = memoryAllocate(ts->upgrade_settings_payload_len);
    memoryCopy(ts->upgrade_settings_payload, payload, ts->upgrade_settings_payload_len);

    size_t b64_cap           = ((ts->upgrade_settings_payload_len + 2U) / 3U) * 4U + 2U;
    ts->upgrade_settings_b64 = memoryAllocate(b64_cap);
    size_t b64_len           = 0;
    if (! wwBase64UrlEncodeNoPadding(ts->upgrade_settings_payload,
                                     ts->upgrade_settings_payload_len,
                                     ts->upgrade_settings_b64,
                                     b64_cap,
                                     &b64_len) ||
        b64_len == 0)
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
    t->onStop    = &httpclientTunnelOnStop;
    t->onDestroy = &httpclientTunnelDestroy;

    httpclient_tstate_t *ts       = tunnelGetState(t);
    const cJSON         *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: HttpClient->settings (object field) is empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    if (! parseHttpVersionMode(ts, settings) || ! parseHttp1TransportMode(ts, settings) ||
        ! parseRequiredFields(ts, settings))
    {
        httpclientTunnelDestroy(t);
        return NULL;
    }

    parsePortAndUpgrade(ts, settings);
    parseUserAgentAndWebSocket(ts, settings);

    if (! parseHttp1SplitSettings(ts, settings))
    {
        httpclientTunnelDestroy(t);
        return NULL;
    }

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
