#include "structure.h"

#include "loggers/network_logger.h"

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

    if (! parseHttpVersionMode(ts, settings) || ! parseBasicFields(ts, settings))
    {
        httpserverTunnelDestroy(t);
        return NULL;
    }

    parseUpgradeMode(ts, settings);
    parseWebSocketMode(ts, settings);

    if (! initializeNghttp2State(ts))
    {
        httpserverTunnelDestroy(t);
        return NULL;
    }

    return t;
}
