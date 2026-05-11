#include "structure.h"

#include "loggers/network_logger.h"
#include "pipe_tunnel.h"

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

static bool parseSplitPlacement(const char *value, httpserver_split_placement_t *out, const char *field_name)
{
    if (value == NULL || out == NULL)
    {
        return false;
    }

    if (strEqualsAnyIgnoreCase(value, "query", "query-parameter", "query-param", "param"))
    {
        *out = kHttpServerSplitPlacementQuery;
        return true;
    }
    if (strEqualsAnyIgnoreCase(value, "header", "http-header", NULL, NULL))
    {
        *out = kHttpServerSplitPlacementHeader;
        return true;
    }
    if (strEqualsAnyIgnoreCase(value, "cookie", "cookies", NULL, NULL))
    {
        *out = kHttpServerSplitPlacementCookie;
        return true;
    }
    if (strEqualsAnyIgnoreCase(value, "path", "path-segment", "path-template", NULL))
    {
        *out = kHttpServerSplitPlacementPath;
        return true;
    }

    LOGF("JSON Error: HttpServer->settings->%s supports: query, header, cookie, path", field_name);
    return false;
}

static bool parseHttpVersionMode(httpserver_tstate_t *ts, const cJSON *settings)
{
    const cJSON *hv = cJSON_GetObjectItemCaseSensitive(settings, "http-version");

    if (cJSON_IsNumber(hv))
    {
        if (hv->valueint == 1)
        {
            ts->version_mode = kHttpServerVersionModeHttp1;
            return true;
        }
        if (hv->valueint == 2)
        {
            ts->version_mode = kHttpServerVersionModeHttp2;
            return true;
        }

        LOGF("JSON Error: HttpServer->settings->http-version only supports 1 or 2 as number");
        return false;
    }

    if (cJSON_IsString(hv) && hv->valuestring != NULL)
    {
        if (strEqualsAnyIgnoreCase(hv->valuestring, "1.1", "http1", "http1.1", "1"))
        {
            ts->version_mode = kHttpServerVersionModeHttp1;
            return true;
        }
        if (strEqualsAnyIgnoreCase(hv->valuestring, "2", "2.0", "http2", "h2"))
        {
            ts->version_mode = kHttpServerVersionModeHttp2;
            return true;
        }
        if (strEqualsAnyIgnoreCase(hv->valuestring, "both", "any", "auto", "1.1+2"))
        {
            ts->version_mode = kHttpServerVersionModeBoth;
            return true;
        }

        LOGF("JSON Error: HttpServer->settings->http-version string supports: 1.1, 2, both");
        return false;
    }

    ts->version_mode = kHttpServerVersionModeBoth;
    return true;
}

static bool parseHttp1TransportMode(httpserver_tstate_t *ts, const cJSON *settings)
{
    ts->h1_transport_mode = kHttpServerH1TransportSingle;

    const cJSON *mode = cJSON_GetObjectItemCaseSensitive(settings, "http1-mode");
    if (! cJSON_IsString(mode) || mode->valuestring == NULL)
    {
        bool split_enabled = false;
        if (getBoolFromJsonObject(&split_enabled, settings, "http1-split") && split_enabled)
        {
            ts->h1_transport_mode = kHttpServerH1TransportSplit;
        }
        return true;
    }

    if (strEqualsAnyIgnoreCase(mode->valuestring, "single", "classic", "full-duplex", "legacy"))
    {
        ts->h1_transport_mode = kHttpServerH1TransportSingle;
        return true;
    }

    if (strEqualsAnyIgnoreCase(mode->valuestring, "split", "half-duplex", "dual", "dual-connection"))
    {
        ts->h1_transport_mode = kHttpServerH1TransportSplit;
        return true;
    }

    LOGF("JSON Error: HttpServer->settings->http1-mode supports: single, split");
    return false;
}

static bool parseExpectedMethod(httpserver_tstate_t *ts, const cJSON *settings)
{
    getStringFromJsonObjectOrDefault(&ts->expected_method, settings, "method", "POST");

    ts->expected_method_enum = httpMethodEnum(ts->expected_method);
    if (ts->expected_method_enum == kHttpCustomMethod)
    {
        LOGF("JSON Error: HttpServer->settings->method is invalid: %s", ts->expected_method);
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
        LOGF("JSON Error: HttpServer->settings->%s is invalid: %s", log_name, *dest);
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

static bool parseHttp1SplitSettings(httpserver_tstate_t *ts, const cJSON *settings)
{
    if (ts->h1_transport_mode != kHttpServerH1TransportSplit)
    {
        return true;
    }

    if (ts->version_mode != kHttpServerVersionModeHttp1)
    {
        LOGF("JSON Error: HttpServer split HTTP/1 transport requires http-version = 1/http1");
        return false;
    }

    if (ts->websocket_enabled)
    {
        LOGF("JSON Error: HttpServer split HTTP/1 transport cannot be combined with websocket mode");
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

    if (! parseSplitMethod(&ts->split_upload_method, &ts->split_upload_method_enum, split, upload, "upload-method",
                           "method", ts->expected_method, "split.upload-method") ||
        ! parseSplitMethod(&ts->split_download_method, &ts->split_download_method_enum, split, download,
                           "download-method", "method", "GET", "split.download-method"))
    {
        return false;
    }

    parseSplitString(&ts->split_upload_path, split, upload, "upload-path", "path", ts->expected_path);
    parseSplitString(&ts->split_download_path, split, download, "download-path", "path", ts->expected_path);
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

    mutexInit(&ts->split_upload_map_mutex);
    mutexInit(&ts->split_download_map_mutex);
    ts->split_upload_map   = hmap_httpserver_split_t_with_capacity(64);
    ts->split_download_map = hmap_httpserver_split_t_with_capacity(64);
    ts->split_maps_initialized = true;
    return true;
}

static bool parseBasicFields(httpserver_tstate_t *ts, const cJSON *settings)
{
    getStringFromJsonObject(&ts->expected_host, settings, "host");
    getStringFromJsonObjectOrDefault(&ts->expected_path, settings, "path", "/");

    if (! parseExpectedMethod(ts, settings))
    {
        return false;
    }

    if (! getIntFromJsonObjectOrDefault(&ts->status_code, settings, "status", 200))
    {
        ts->status_code = 200;
    }

    if (ts->status_code < 100 || ts->status_code > 599)
    {
        LOGF("JSON Error: HttpServer->settings->status should be in range 100..599");
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

    ts->headers = cJSON_GetObjectItemCaseSensitive(settings, "headers");

    return true;
}

static void parseUpgradeMode(httpserver_tstate_t *ts, const cJSON *settings)
{
    bool default_upgrade = (ts->version_mode == kHttpServerVersionModeBoth);
    getBoolFromJsonObjectOrDefault(&ts->enable_upgrade, settings, "upgrade", default_upgrade);
    getStringFromJsonObject(&ts->upgrade_protocol, settings, "upgrade-protocol");
    ts->upgrade_request_headers  = cJSON_GetObjectItemCaseSensitive(settings, "upgrade-request-headers");
    ts->upgrade_response_headers = cJSON_GetObjectItemCaseSensitive(settings, "upgrade-response-headers");
}

static void parseWebSocketMode(httpserver_tstate_t *ts, const cJSON *settings)
{
    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);
    getBoolFromJsonObjectOrDefault(&ts->full_duplex, settings, "full-duplex", false);
    getBoolFromJsonObjectOrDefault(&ts->websocket_enabled, settings, "websocket", false);

    if (ts->websocket_enabled)
    {
        getStringFromJsonObject(&ts->websocket_origin, settings, "websocket-origin");
        getStringFromJsonObject(&ts->websocket_subprotocol, settings, "websocket-subprotocol");
    }
}

static bool initializeNghttp2State(httpserver_tstate_t *ts)
{
    if (ts->version_mode == kHttpServerVersionModeHttp1)
    {
        return true;
    }

    if (nghttp2_session_callbacks_new(&ts->cbs) != 0)
    {
        LOGF("HttpServer: nghttp2_session_callbacks_new failed");
        return false;
    }

    if (nghttp2_option_new(&ts->ngoptions) != 0)
    {
        LOGF("HttpServer: nghttp2_option_new failed");
        return false;
    }

    nghttp2_option_set_peer_max_concurrent_streams(ts->ngoptions, 1);
    nghttp2_option_set_no_http_messaging(ts->ngoptions, 0);
    nghttp2_option_set_no_auto_window_update(ts->ngoptions, 0);

    return true;
}

tunnel_t *httpserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(httpserver_tstate_t), sizeof(httpserver_lstate_t));

    t->fnInitU    = &httpserverTunnelUpStreamInit;
    t->fnEstU     = &httpserverTunnelUpStreamEst;
    t->fnFinU     = &httpserverTunnelUpStreamFinish;
    t->fnPayloadU = &httpserverTunnelUpStreamPayload;
    t->fnPauseU   = &httpserverTunnelUpStreamPause;
    t->fnResumeU  = &httpserverTunnelUpStreamResume;

    t->fnInitD    = &httpserverTunnelDownStreamInit;
    t->fnEstD     = &httpserverTunnelDownStreamEst;
    t->fnFinD     = &httpserverTunnelDownStreamFinish;
    t->fnPayloadD = &httpserverTunnelDownStreamPayload;
    t->fnPauseD   = &httpserverTunnelDownStreamPause;
    t->fnResumeD  = &httpserverTunnelDownStreamResume;

    t->onPrepare = &httpserverTunnelOnPrepair;
    t->onStart   = &httpserverTunnelOnStart;
    t->onDestroy = &httpserverTunnelDestroy;

    httpserver_tstate_t *ts       = tunnelGetState(t);
    const cJSON         *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: HttpServer->settings (object field) is empty or invalid");
        tunnelDestroy(t);
        return NULL;
    }

    if (! parseHttpVersionMode(ts, settings) || ! parseHttp1TransportMode(ts, settings) ||
        ! parseBasicFields(ts, settings))
    {
        httpserverTunnelDestroy(t);
        return NULL;
    }

    parseUpgradeMode(ts, settings);
    parseWebSocketMode(ts, settings);

    if (! parseHttp1SplitSettings(ts, settings))
    {
        httpserverTunnelDestroy(t);
        return NULL;
    }

    if (! initializeNghttp2State(ts))
    {
        httpserverTunnelDestroy(t);
        return NULL;
    }

    if (ts->h1_transport_mode == kHttpServerH1TransportSplit)
    {
        return pipetunnelCreate(t);
    }

    return t;
}
