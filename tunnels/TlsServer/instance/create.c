#include "structure.h"

#include "loggers/network_logger.h"
#include "managers/node_manager.h"

#include <stdlib.h>

enum
{
    kTlsServerDefaultSessionTimeout            = 300,
    kTlsServerDefaultFallbackIntentionalDelayMs = 7,
    kTlsServerDefaultFallbackIntentionalDelayJitterMs = 1
};

static const char *tlsserverSessionCacheName(int mode)
{
    switch (mode)
    {
    case kTlsServerSessionCacheOff:
        return "off";
    case kTlsServerSessionCacheBuiltin:
        return "builtin";
    case kTlsServerSessionCacheNone:
    default:
        return "none";
    }
}

static void tlsserverInfoCallback(const SSL *ssl, int where, int ret)
{
    tlsserver_tstate_t *ts      = SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
    bool                verbose = ts != NULL && ts->verbose;

    if ((where & SSL_CB_ALERT) != 0)
    {
        const char *alert_type = SSL_alert_type_string_long(ret);
        if (verbose)
        {
            LOGD("TlsServer: TLS alert %s: %s:%s",
                 (where & SSL_CB_READ) != 0 ? "read" : "write",
                 alert_type,
                 SSL_alert_desc_string_long(ret));
        }
        else if (stricmp(alert_type, "fatal") == 0)
        {
            LOGW("TlsServer: TLS fatal alert %s: %s",
                 (where & SSL_CB_READ) != 0 ? "read" : "write",
                 SSL_alert_desc_string_long(ret));
        }
        return;
    }

    if (verbose && (where & SSL_CB_HANDSHAKE_START) != 0)
    {
        LOGD("TlsServer: OpenSSL handshake started (state=\"%s\")", SSL_state_string_long(ssl));
        return;
    }

    if (verbose && (where & SSL_CB_HANDSHAKE_DONE) != 0)
    {
        LOGD("TlsServer: OpenSSL handshake done (state=\"%s\")", SSL_state_string_long(ssl));
    }
}

static void configureTunnelCallbacks(tunnel_t *t)
{
    t->fnInitU    = &tlsserverTunnelUpStreamInit;
    t->fnEstU     = &tlsserverTunnelUpStreamEst;
    t->fnFinU     = &tlsserverTunnelUpStreamFinish;
    t->fnPayloadU = &tlsserverTunnelUpStreamPayload;
    t->fnPauseU   = &tlsserverTunnelUpStreamPause;
    t->fnResumeU  = &tlsserverTunnelUpStreamResume;

    t->fnInitD    = &tlsserverTunnelDownStreamInit;
    t->fnEstD     = &tlsserverTunnelDownStreamEst;
    t->fnFinD     = &tlsserverTunnelDownStreamFinish;
    t->fnPayloadD = &tlsserverTunnelDownStreamPayload;
    t->fnPauseD   = &tlsserverTunnelDownStreamPause;
    t->fnResumeD  = &tlsserverTunnelDownStreamResume;

    t->onPrepare = &tlsserverTunnelOnPrepair;
    t->onStart   = &tlsserverTunnelOnStart;
    t->onStop    = &tlsserverTunnelOnStop;
    t->onDestroy = &tlsserverTunnelDestroy;
}

static const cJSON *tlsserverGetSettingsItemByKeys(const cJSON *settings, const char *key1, const char *key2,
                                                   const char *key3)
{
    const char *keys[3] = {key1, key2, key3};

    for (size_t i = 0; i < ARRAY_SIZE(keys); ++i)
    {
        if (keys[i] == NULL)
        {
            continue;
        }

        const cJSON *item = cJSON_GetObjectItemCaseSensitive(settings, keys[i]);
        if (item != NULL)
        {
            return item;
        }
    }

    return NULL;
}

static bool parseFallbackNode(tlsserver_tstate_t *ts, tunnel_t *t, node_t *node, const cJSON *settings)
{
    const cJSON *fallback_json =
        tlsserverGetSettingsItemByKeys(settings, "fallback-node-name", "fallback-node", "fallback");

    if (fallback_json == NULL)
    {
        ts->fallback_node = NULL;
        return true;
    }

    if (! cJSON_IsString(fallback_json) || fallback_json->valuestring == NULL || fallback_json->valuestring[0] == '\0')
    {
        LOGF("JSON Error: TlsServer->settings->fallback-node-name (string field) must be a non-empty string");
        tlsserverTunnelDestroy(t);
        return false;
    }

    node_t *fallback_node = nodemanagerGetConfigNodeByName(node->node_manager_config, fallback_json->valuestring);
    if (fallback_node == NULL)
    {
        LOGF("TlsServer: fallback node \"%s\" was not found", fallback_json->valuestring);
        tlsserverTunnelDestroy(t);
        return false;
    }

    if (fallback_node == node)
    {
        LOGF("TlsServer: fallback node must not point back to TlsServer itself");
        tlsserverTunnelDestroy(t);
        return false;
    }

    ts->fallback_node = fallback_node;
    return true;
}

static bool parseRequiredString(char **dest, const cJSON *settings, const char *key, tunnel_t *t)
{
    if (! getStringFromJsonObject(dest, settings, key) || stringLength(*dest) == 0)
    {
        LOGF("JSON Error: TlsServer->settings->%s (string field) : The data was empty or invalid", key);
        tlsserverTunnelDestroy(t);
        return false;
    }

    return true;
}

static bool parseOptionalString(char **dest, const cJSON *settings, const char *key, tunnel_t *t)
{
    if (! getStringFromJsonObject(dest, settings, key))
    {
        return true;
    }

    if (stringLength(*dest) == 0)
    {
        LOGF("JSON Error: TlsServer->settings->%s (string field) : The data was empty or invalid", key);
        tlsserverTunnelDestroy(t);
        return false;
    }

    return true;
}

static bool parseTlsVersionString(const char *version, int *out)
{
    if (stricmp(version, "TLSv1") == 0 || stricmp(version, "1.0") == 0 || stricmp(version, "TLS1.0") == 0)
    {
        *out = TLS1_VERSION;
        return true;
    }

#ifdef TLS1_1_VERSION
    if (stricmp(version, "TLSv1.1") == 0 || stricmp(version, "1.1") == 0 || stricmp(version, "TLS1.1") == 0)
    {
        *out = TLS1_1_VERSION;
        return true;
    }
#endif

    if (stricmp(version, "TLSv1.2") == 0 || stricmp(version, "1.2") == 0 || stricmp(version, "TLS1.2") == 0)
    {
        *out = TLS1_2_VERSION;
        return true;
    }

#ifdef TLS1_3_VERSION
    if (stricmp(version, "TLSv1.3") == 0 || stricmp(version, "1.3") == 0 || stricmp(version, "TLS1.3") == 0)
    {
        *out = TLS1_3_VERSION;
        return true;
    }
#endif

    return false;
}

static bool parseTlsVersionSetting(const cJSON *settings, const char *key, int *out, int default_version, tunnel_t *t)
{
    char *value = NULL;

    *out = default_version;

    if (! getStringFromJsonObject(&value, settings, key))
    {
        return true;
    }

    if (! parseTlsVersionString(value, out))
    {
        LOGF("JSON Error: TlsServer->settings->%s (string field) : Unsupported TLS version \"%s\"", key, value);
        memoryFree(value);
        tlsserverTunnelDestroy(t);
        return false;
    }

    memoryFree(value);
    return true;
}

static bool parseSessionCacheSetting(tlsserver_tstate_t *ts, const cJSON *settings, tunnel_t *t)
{
    char *value = NULL;

    ts->session_cache_mode = kTlsServerSessionCacheNone;
    ts->session_cache_size = 20480;

    if (! getStringFromJsonObject(&value, settings, "session-cache"))
    {
        getIntFromJsonObjectOrDefault(&ts->session_cache_size, settings, "session-cache-size", ts->session_cache_size);
        if (ts->session_cache_size < 0)
        {
            LOGF("JSON Error: TlsServer->settings->session-cache-size (number field) : The value was invalid");
            tlsserverTunnelDestroy(t);
            return false;
        }
        return true;
    }

    if (stricmp(value, "none") == 0)
    {
        ts->session_cache_mode = kTlsServerSessionCacheNone;
    }
    else if (stricmp(value, "off") == 0)
    {
        ts->session_cache_mode = kTlsServerSessionCacheOff;
    }
    else if (strnicmp(value, "builtin", 7) == 0)
    {
        ts->session_cache_mode = kTlsServerSessionCacheBuiltin;

        if (value[7] == ':')
        {
            char *end = NULL;
            long  sz  = strtol(&value[8], &end, 10);
            if (end == &value[8] || *end != '\0' || sz < 0 || sz > INT32_MAX)
            {
                LOGF("JSON Error: TlsServer->settings->session-cache (string field) : Invalid builtin cache size");
                memoryFree(value);
                tlsserverTunnelDestroy(t);
                return false;
            }
            ts->session_cache_size = (int) sz;
        }
        else if (value[7] != '\0')
        {
            LOGF("JSON Error: TlsServer->settings->session-cache (string field) : Unsupported value \"%s\"", value);
            memoryFree(value);
            tlsserverTunnelDestroy(t);
            return false;
        }
    }
    else if (strnicmp(value, "shared", 6) == 0)
    {
        LOGF("JSON Error: TlsServer->settings->session-cache (string field) : shared cache is not supported yet");
        memoryFree(value);
        tlsserverTunnelDestroy(t);
        return false;
    }
    else
    {
        LOGF("JSON Error: TlsServer->settings->session-cache (string field) : Unsupported value \"%s\"", value);
        memoryFree(value);
        tlsserverTunnelDestroy(t);
        return false;
    }

    memoryFree(value);

    getIntFromJsonObjectOrDefault(&ts->session_cache_size, settings, "session-cache-size", ts->session_cache_size);
    if (ts->session_cache_size < 0)
    {
        LOGF("JSON Error: TlsServer->settings->session-cache-size (number field) : The value was invalid");
        tlsserverTunnelDestroy(t);
        return false;
    }

    return true;
}

static void tlsserverInitializeSessionIdContext(tlsserver_tstate_t *ts, node_t *node)
{
    struct
    {
        hash_t node_name;
        hash_t node_type;
        hash_t cert_file;
        hash_t key_file;
    } sid_ctx = {.node_name = calcHashBytes(node->name, stringLength(node->name)),
                 .node_type = calcHashBytes(node->type, stringLength(node->type)),
                 .cert_file = calcHashBytes(ts->cert_file, stringLength(ts->cert_file)),
                 .key_file  = calcHashBytes(ts->key_file, stringLength(ts->key_file))};

    memoryCopy(ts->session_id_context, &sid_ctx, sizeof(sid_ctx));
    ts->session_id_context_len = (unsigned int) sizeof(sid_ctx);
}

static bool parseAlpns(tlsserver_tstate_t *ts, const cJSON *settings, tunnel_t *t)
{
    const cJSON *alpns = cJSON_GetObjectItemCaseSensitive(settings, "alpns");
    if (! cJSON_IsArray(alpns))
    {
        return true;
    }

    int count = cJSON_GetArraySize(alpns);
    if (count <= 0)
    {
        return true;
    }

    ts->alpns = memoryAllocate((size_t) count * sizeof(*ts->alpns));
    memoryZero(ts->alpns, (size_t) count * sizeof(*ts->alpns));

    int          i    = 0;
    const cJSON *item = NULL;
    cJSON_ArrayForEach(item, alpns)
    {
        char *name = NULL;

        if (cJSON_IsString(item) && item->valuestring != NULL)
        {
            name = memoryAllocate(stringLength(item->valuestring) + 1);
            stringCopy(name, item->valuestring);
        }
        else if (cJSON_IsObject(item))
        {
            if (! getStringFromJsonObject(&name, item, "value"))
            {
                name = NULL;
            }
        }

        if (name == NULL || stringLength(name) == 0)
        {
            memoryFree(name);
            LOGF("JSON Error: TlsServer->settings->alpns[%d] : The value was empty or invalid", i);
            tlsserverTunnelDestroy(t);
            return false;
        }

        ts->alpns[i].name        = name;
        ts->alpns[i].name_length = (unsigned int) stringLength(name);
        ++i;
    }

    ts->alpns_length = (unsigned int) i;
    return true;
}

static bool parseTlsDefaults(tlsserver_tstate_t *ts, const cJSON *settings, tunnel_t *t)
{
    int fallback_intentional_delay_ms        = kTlsServerDefaultFallbackIntentionalDelayMs;
    int fallback_intentional_delay_jitter_ms = kTlsServerDefaultFallbackIntentionalDelayJitterMs;

    getBoolFromJsonObjectOrDefault(&ts->prefer_server_ciphers, settings, "prefer-server-ciphers", false);
    getBoolFromJsonObjectOrDefault(&ts->session_tickets, settings, "session-tickets", true);
    getIntFromJsonObjectOrDefault(&ts->session_timeout, settings, "session-timeout", kTlsServerDefaultSessionTimeout);
    getIntFromJsonObjectOrDefault(&fallback_intentional_delay_ms,
                                  settings,
                                  "fallback-intentional-delay-ms",
                                  kTlsServerDefaultFallbackIntentionalDelayMs);
    getIntFromJsonObjectOrDefault(&fallback_intentional_delay_jitter_ms,
                                  settings,
                                  "fallback-intentional-delay-jitter-ms",
                                  kTlsServerDefaultFallbackIntentionalDelayJitterMs);
    getStringFromJsonObjectOrDefault(&ts->ciphers, settings, "ciphers", "HIGH:!aNULL:!MD5");

    if (ts->session_timeout < 0)
    {
        LOGF("JSON Error: TlsServer->settings->session-timeout (number field) : The value was invalid");
        tlsserverTunnelDestroy(t);
        return false;
    }

    if (fallback_intentional_delay_ms < 0)
    {
        LOGF("JSON Error: TlsServer->settings->fallback-intentional-delay-ms (number field) : The value was invalid");
        tlsserverTunnelDestroy(t);
        return false;
    }
    ts->fallback_intentional_delay_ms = (uint32_t) fallback_intentional_delay_ms;

    if (fallback_intentional_delay_jitter_ms < 0)
    {
        LOGF(
            "JSON Error: TlsServer->settings->fallback-intentional-delay-jitter-ms (number field) : The value was invalid");
        tlsserverTunnelDestroy(t);
        return false;
    }
    ts->fallback_intentional_delay_jitter_ms = (uint32_t) fallback_intentional_delay_jitter_ms;

    if (ts->fallback_intentional_delay_ms == 0 && ts->fallback_intentional_delay_jitter_ms > 0)
    {
        LOGD("TlsServer: fallback-intentional-delay-jitter-ms is ignored because fallback-intentional-delay-ms is 0");
    }

    if (! parseTlsVersionSetting(settings, "min-version", &ts->min_proto_version, TLS1_2_VERSION, t) ||
        ! parseTlsVersionSetting(settings, "max-version", &ts->max_proto_version, TLS1_3_VERSION, t))
    {
        return false;
    }

    if (ts->min_proto_version > ts->max_proto_version)
    {
        LOGF("TlsServer: min-version cannot be greater than max-version");
        tlsserverTunnelDestroy(t);
        return false;
    }

    if (! parseSessionCacheSetting(ts, settings, t))
    {
        return false;
    }

    return true;
}

static SSL_CTX *createServerSslContext(tlsserver_tstate_t *ts)
{
    ssl_ctx_opt_t params = {.crt_file    = ts->cert_file,
                            .key_file    = ts->key_file,
                            .ca_file     = NULL,
                            .ca_path     = NULL,
                            .verify_peer = 0,
                            .endpoint    = kSslServer};

    SSL_CTX *ctx = (SSL_CTX *) sslCtxNew(&params);
    if (ctx == NULL)
    {
        LOGE("TlsServer: failed to create SSL_CTX with cert-file=\"%s\" key-file=\"%s\"", ts->cert_file, ts->key_file);
        tlsserverPrintSSLError();
        return NULL;
    }

    if (! SSL_CTX_set_min_proto_version(ctx, ts->min_proto_version) ||
        ! SSL_CTX_set_max_proto_version(ctx, ts->max_proto_version))
    {
        LOGE("TlsServer: failed to set TLS protocol version range");
        tlsserverPrintSSLError();
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_set_cipher_list(ctx, ts->ciphers) != 1)
    {
        LOGE("TlsServer: failed to set TLS cipher list \"%s\"", ts->ciphers);
        tlsserverPrintSSLError();
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_app_data(ctx, ts);
    SSL_CTX_set_info_callback(ctx, tlsserverInfoCallback);

    if (ts->prefer_server_ciphers)
    {
        SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

#ifdef SSL_OP_NO_RENEGOTIATION
    // a mid-stream renegotiation would make SSL_write return WANT_READ, which
    // the synchronous mem-BIO encrypt loop cannot satisfy
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION);
#endif

    switch (ts->session_cache_mode)
    {
    case kTlsServerSessionCacheOff:
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        break;
    case kTlsServerSessionCacheBuiltin:
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_sess_set_cache_size(ctx, (long) ts->session_cache_size);
        if (! SSL_CTX_set_session_id_context(ctx, ts->session_id_context, ts->session_id_context_len))
        {
            LOGE("TlsServer: failed to set TLS session id context");
            tlsserverPrintSSLError();
            SSL_CTX_free(ctx);
            return NULL;
        }
        break;
    case kTlsServerSessionCacheNone:
    default:
        SSL_CTX_set_session_cache_mode(
            ctx, SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_INTERNAL_LOOKUP | SSL_SESS_CACHE_NO_INTERNAL_STORE);
        break;
    }

    SSL_CTX_set_timeout(ctx, (long) ts->session_timeout);

    if (! ts->session_tickets)
    {
#ifdef SSL_OP_NO_TICKET
        SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
#endif
    }

    if (ts->expected_sni != NULL)
    {
        if (ts->verbose)
        {
            LOGD("TlsServer: enabling exact SNI check for \"%s\"", ts->expected_sni);
        }
        SSL_CTX_set_tlsext_servername_callback(ctx, tlsserverOnServername);
        SSL_CTX_set_tlsext_servername_arg(ctx, ts);
    }

    if (ts->alpns_length > 0)
    {
        if (ts->verbose)
        {
            LOGD("TlsServer: enabling ALPN selection with %u configured protocol(s)", ts->alpns_length);
        }
        SSL_CTX_set_alpn_select_cb(ctx, tlsserverOnAlpnSelect, ts);
    }

    return ctx;
}

tunnel_t *tlsserverTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tlsserver_tstate_t), sizeof(tlsserver_lstate_t));
    configureTunnelCallbacks(t);

    tlsserver_tstate_t *ts       = tunnelGetState(t);
    const cJSON        *settings = node->node_settings_json;

    if (! checkJsonIsObjectAndHasChild(settings))
    {
        LOGF("JSON Error: TlsServer->settings (object field) : The object was empty or invalid");
        tlsserverTunnelDestroy(t);
        return NULL;
    }

    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);

    if (! parseRequiredString(&ts->cert_file, settings, "cert-file", t) ||
        ! parseRequiredString(&ts->key_file, settings, "key-file", t) ||
        ! parseOptionalString(&ts->expected_sni, settings, "sni", t) || ! parseTlsDefaults(ts, settings, t) ||
        ! parseAlpns(ts, settings, t) || ! parseFallbackNode(ts, t, node, settings))
    {
        return NULL;
    }

    if (ts->fallback_node != NULL)
    {
        t->onChain = &tlsserverTunnelOnChain;
    }

    tlsserverInitializeSessionIdContext(ts, node);

    int worker_count = getWorkersCount();
    if (ts->verbose)
    {
        LOGD(
            "TlsServer: creating node \"%s\" cert-file=\"%s\" key-file=\"%s\" sni=\"%s\" min-version=%d max-version=%d "
            "ciphers=\"%s\" session-cache=%s session-cache-size=%d session-tickets=%d "
            "fallback-intentional-delay-ms=%u fallback-intentional-delay-jitter-ms=%u alpns=%u workers=%d",
            node->name,
            ts->cert_file,
            ts->key_file,
            ts->expected_sni != NULL ? ts->expected_sni : "<none>",
            ts->min_proto_version,
            ts->max_proto_version,
            ts->ciphers,
            tlsserverSessionCacheName(ts->session_cache_mode),
            ts->session_cache_size,
            (int) ts->session_tickets,
            (unsigned int) ts->fallback_intentional_delay_ms,
            (unsigned int) ts->fallback_intentional_delay_jitter_ms,
            ts->alpns_length,
            worker_count);
    }

    ts->threadlocal_ssl_contexts = memoryAllocate((size_t) worker_count * sizeof(SSL_CTX *));
    memoryZero(ts->threadlocal_ssl_contexts, (size_t) worker_count * sizeof(SSL_CTX *));

    for (int i = 0; i < worker_count; ++i)
    {
        ts->threadlocal_ssl_contexts[i] = createServerSslContext(ts);
        if (ts->threadlocal_ssl_contexts[i] == NULL)
        {
            LOGF("TlsServer: failed to create OpenSSL server context for worker %d", i);
            tlsserverTunnelDestroy(t);
            return NULL;
        }
        if (ts->verbose)
        {
            LOGD("TlsServer: created OpenSSL server context for worker %d", i);
        }
    }

    return t;
}
