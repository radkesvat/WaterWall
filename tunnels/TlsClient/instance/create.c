#include "structure.h"

#include "utils/cacert.h"

#include "loggers/network_logger.h"

static void configureTunnelCallbacks(tunnel_t *t)
{
    t->fnInitU    = &tlsclientTunnelUpStreamInit;
    t->fnEstU     = &tlsclientTunnelUpStreamEst;
    t->fnFinU     = &tlsclientTunnelUpStreamFinish;
    t->fnPayloadU = &tlsclientTunnelUpStreamPayload;
    t->fnPauseU   = &tlsclientTunnelUpStreamPause;
    t->fnResumeU  = &tlsclientTunnelUpStreamResume;

    t->fnInitD    = &tlsclientTunnelDownStreamInit;
    t->fnEstD     = &tlsclientTunnelDownStreamEst;
    t->fnFinD     = &tlsclientTunnelDownStreamFinish;
    t->fnPayloadD = &tlsclientTunnelDownStreamPayload;
    t->fnPauseD   = &tlsclientTunnelDownStreamPause;
    t->fnResumeD  = &tlsclientTunnelDownStreamResume;

    t->onPrepair = &tlsclientTunnelOnPrepair;
    t->onStart   = &tlsclientTunnelOnStart;
    t->onDestroy = &tlsclientTunnelDestroy;
}

static bool validateSniSetting(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t)
{
    if (! getStringFromJsonObject(&(ts->sni), settings, "sni") || stringLength(ts->sni) == 0)
    {
        LOGF("JSON Error: OpenSSLClient->settings->sni (string field) : The data was empty or invalid");
        tunnelDestroy(t);
        return false;
    }
    return true;
}

static bool validateAlpnSetting(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t)
{
    getStringFromJsonObjectOrDefault(&(ts->alpn), settings, "alpn", "http/1.1");

    if (stringLength(ts->alpn) == 0)
    {
        LOGF("JSON Error: OpenSSLClient->settings->alpn (string field) : The data was empty or invalid");
        memoryFree(ts->sni);
        memoryFree(ts->alpn);
        tunnelDestroy(t);
        return false;
    }
    return true;
}

static void *createAlpnFormat(const char *alpn_string, size_t alpn_len)
{
    struct
    {
        uint8_t len;
        char    alpn_data[];
    } *alpn_format = memoryAllocate(1 + alpn_len);

    alpn_format->len = alpn_len;
    memoryCopy(&(alpn_format->alpn_data[0]), alpn_string, alpn_len);

    return alpn_format;
}

static bool loadCaCertificates(SSL_CTX *ssl_ctx)
{
    BIO *bio = BIO_new(BIO_s_mem());
    int  n   = BIO_write(bio, cacert_bytes, (int) cacert_len);
    assert(n == (int) cacert_len);
    discard n;

    X509 *x = NULL;
    while (true)
    {
        x = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
        if (x == NULL)
        {
            break;
        }
        X509_STORE_add_cert(SSL_CTX_get_cert_store(ssl_ctx), x);
        X509_free(x);
        x = NULL;
    }

    BIO_free(bio);
    return true;
}

static SSL_CTX *setupSslContext(void *alpn_format, size_t alpn_len)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());

    if (ssl_ctx == NULL)
    {
        return NULL;
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    SSL_CTX_set_alpn_protos(ssl_ctx,
                            (const unsigned char *) ((struct {
                                uint8_t len;
                                char    alpn_data[];
                            } *) alpn_format)
                                ->alpn_data,
                            1 + alpn_len);

    if (! SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION))
    {
        LOGF("TlsClient: (part of making SSL_CTX match chrome) Failed to set min proto version for SSL_CTX");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (! SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION))
    {
        LOGF("TlsClient: (part of making SSL_CTX match chrome) Failed to set max proto version for SSL_CTX");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    SSL_CTX_set_grease_enabled(ssl_ctx, true);

    SSL_CTX_set_permute_extensions(ssl_ctx, true);

    if (! SSL_CTX_set1_groups_list(ssl_ctx, "X25519:P-256:P-384"))
    {
        LOGF("TlsClient: (part of making SSL_CTX match chrome) Failed to set groups list for SSL_CTX");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (! loadCaCertificates(ssl_ctx))
    {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    return ssl_ctx;
}

static bool createSslContexts(tlsclient_tstate_t *ts, void *alpn_format, size_t alpn_len, int worker_count, tunnel_t *t)
{
    ts->threadlocal_ssl_contexts = (SSL_CTX **) memoryAllocate(worker_count * sizeof(SSL_CTX *));

    for (int i = 0; i < worker_count; i++)
    {
        ts->threadlocal_ssl_contexts[i] = setupSslContext(alpn_format, alpn_len);

        if (ts->threadlocal_ssl_contexts[i] == NULL)
        {
            LOGF("TlsClient: Could not create ssl context");
            memoryFree(ts->sni);
            memoryFree(ts->alpn);
            memoryFree(alpn_format);
            memoryFree((void *) ts->threadlocal_ssl_contexts);
            tunnelDestroy(t);
            return false;
        }
    }

    return true;
}

tunnel_t *tlsclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tlsclient_tstate_t), sizeof(tlsclient_lstate_t));

    configureTunnelCallbacks(t);

    int                 worker_count = getWorkersCount() - WORKER_ADDITIONS;
    tlsclient_tstate_t *ts           = tunnelGetState(t);
    const cJSON        *settings     = node->node_settings_json;

    // We want to build up exact chrome handshake, so we dont ask for sni and alpn settings
    discard settings;

    // if (!validateSniSetting(ts, settings, t))
    // {
    //     return NULL;
    // }

    // getBoolFromJsonObjectOrDefault(&(ts->verify), settings, "verify", true);

    // if (!validateAlpnSetting(ts, settings, t))
    // {
    //     return NULL;
    // }

    // size_t alpn_len = stringLength(ts->alpn);
    // void *alpn_format = createAlpnFormat(ts->alpn, alpn_len);

    const uint8_t chrome_alpn[] = {2, 'h', '2', // HTTP/2
                                   8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

    if (! createSslContexts(ts, (void *) chrome_alpn, sizeof(chrome_alpn), worker_count, t))
    {
        return NULL;
    }

    // memoryFree(alpn_format);
    return t;
}
