#include "structure.h"

#include "utils/cacert.h"

#include "loggers/network_logger.h"

extern int tlsclientDecompressBrotliCert(SSL *ssl, CRYPTO_BUFFER **out, size_t uncompressed_len, const uint8_t *in,
                                         size_t in_len);

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

    t->onPrepare = &tlsclientTunnelOnPrepair;
    t->onStart   = &tlsclientTunnelOnStart;
    t->onStop    = &tlsclientTunnelOnStop;
    t->onDestroy = &tlsclientTunnelDestroy;
}

static bool getandvalidateSniSetting(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t)
{
    if (! getStringFromJsonObject(&(ts->sni), settings, "sni") || stringLength(ts->sni) == 0)
    {
        LOGF("JSON Error: OpenSSLClient->settings->sni (string field) : The data was empty or invalid");
        tunnelDestroy(t);
        return false;
    }
    return true;
}

static bool getandvalidateAlpnSetting(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t)
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

static void getX25519MLKEM768Setting(tlsclient_tstate_t *ts, const cJSON *settings)
{
    getBoolFromJsonObjectOrDefault(&ts->x25519mlkem768_enabled, settings, "x25519mlkem768", true);
}

static void getVerifySetting(tlsclient_tstate_t *ts, const cJSON *settings)
{
    getBoolFromJsonObjectOrDefault(&ts->verify, settings, "verify", true);
}

static void getVerboseSetting(tlsclient_tstate_t *ts, const cJSON *settings)
{
    getBoolFromJsonObjectOrDefault(&ts->verbose, settings, "verbose", false);
}

static bool getAndValidateEchGreaseSniOverrideSetting(tlsclient_tstate_t *ts, const cJSON *settings, tunnel_t *t)
{
    if (! getStringFromJsonObject(&(ts->ech_grease_sni_override), settings, "ech-sni-trick"))
    {
        return true;
    }

    const size_t override_len = stringLength(ts->ech_grease_sni_override);

    if (override_len == 0)
    {
        LOGF("JSON Error: TlsClient->settings->ech-sni-trick (string field) : The data was empty or invalid");
        tlsclientTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return false;
    }

    return true;
}

static const char *getSupportedGroupsList(bool x25519mlkem768_enabled)
{
    if (x25519mlkem768_enabled)
    {
        return "X25519MLKEM768:X25519:P-256:P-384:P-521";
    }

    return "X25519:P-256:P-384:P-521";
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

static SSL_CTX *setupSslContext(void *alpn_format, size_t alpn_len, bool verify, bool x25519mlkem768_enabled)
{
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());

    if (ssl_ctx == NULL)
    {
        return NULL;
    }

    SSL_CTX_set_verify(ssl_ctx, verify ? SSL_VERIFY_PEER : SSL_VERIFY_NONE, NULL);

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

    // session tickets are by default enabled, this code disables it (WE DONT WANT TO DISABLE IT)
    // SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_set_timeout(ssl_ctx, 7200); // 2 hours, typical for browsers

    if (! SSL_CTX_set1_groups_list(ssl_ctx, getSupportedGroupsList(x25519mlkem768_enabled)))
    {
        LOGF("TlsClient: (part of making SSL_CTX match chrome) Failed to set groups list for SSL_CTX");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    // Enable certificate compression with brotli (Chrome supports this)
    SSL_CTX_add_cert_compression_alg(ssl_ctx,
                                     TLSEXT_cert_compression_brotli,
                                     NULL /* compression not supported (same as chrome)*/,
                                     tlsclientDecompressBrotliCert);

    // Enable SCT (Signed Certificate Timestamp) extension at context level
    SSL_CTX_enable_signed_cert_timestamps(ssl_ctx);

    // Configure signature algorithms to match Chrome
    // Chrome uses these signature algorithms in this order
    if (! SSL_CTX_set1_sigalgs_list(ssl_ctx,
                                    "ecdsa_secp256r1_sha256:"
                                    "rsa_pss_rsae_sha256:"
                                    "rsa_pkcs1_sha256:"
                                    "ecdsa_secp384r1_sha384:"
                                    "rsa_pss_rsae_sha384:"
                                    "rsa_pkcs1_sha384:"
                                    "rsa_pss_rsae_sha512:"
                                    "rsa_pkcs1_sha512"))
    {
        LOGF("TlsClient: (part of making SSL_CTX match chrome) Failed to set signature algorithms for SSL_CTX");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (verify && ! loadCaCertificates(ssl_ctx))
    {
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    // boringssl: Note this function's return value is backwards.
    if (SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *) alpn_format, alpn_len))
    {
        LOGF("TlsClient: (part of making SSL_CTX match chrome) Failed to set ALPN for SSL_CTX (len=%zu)", alpn_len);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }
    return ssl_ctx;
}

static bool createSslContextPool(SSL_CTX ***out_contexts, void *alpn_format, size_t alpn_len, int worker_count,
                                 bool verify, bool x25519mlkem768_enabled)
{
    *out_contexts = memoryAllocateZero((size_t) worker_count * sizeof(SSL_CTX *));

    for (int i = 0; i < worker_count; i++)
    {
        (*out_contexts)[i] = setupSslContext(alpn_format, alpn_len, verify, x25519mlkem768_enabled);

        if ((*out_contexts)[i] == NULL)
        {
            LOGF("TlsClient: Could not create ssl context");
            return false;
        }
    }

    return true;
}

tunnel_t *tlsclientTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(tlsclient_tstate_t), sizeof(tlsclient_lstate_t));

    configureTunnelCallbacks(t);

    int                 worker_count = getWorkersCount();
    tlsclient_tstate_t *ts           = tunnelGetState(t);
    const cJSON        *settings     = node->node_settings_json;

    if (! getandvalidateSniSetting(ts, settings, t))
    {
        return NULL;
    }

    getX25519MLKEM768Setting(ts, settings);
    getVerifySetting(ts, settings);
    getVerboseSetting(ts, settings);
    if (! getAndValidateEchGreaseSniOverrideSetting(ts, settings, t))
    {
        return NULL;
    }
    // We want to build up exact chrome handshake, so we dont ask for alpn settings

    // if (!validateAlpnSetting(ts, settings, t))
    // {
    //     return NULL;
    // }

    // size_t alpn_len = stringLength(ts->alpn);
    // void *alpn_format = createAlpnFormat(ts->alpn, alpn_len);

    const uint8_t chrome_alpn[] = {2,
                                   'h',
                                   '2', // HTTP/2
                                   8,
                                   'h',
                                   't',
                                   't',
                                   'p',
                                   '/',
                                   '1',
                                   '.',
                                   '1'};

    if (! createSslContextPool(&(ts->threadlocal_ssl_contexts),
                               (void *) &chrome_alpn[0],
                               sizeof(chrome_alpn),
                               worker_count,
                               ts->verify,
                               ts->x25519mlkem768_enabled))
    {
        tlsclientTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return NULL;
    }

    if (ts->ech_grease_sni_override != NULL && ! createSslContextPool(&(ts->threadlocal_ech_grease_inner_ssl_contexts),
                                                                      (void *) &chrome_alpn[0],
                                                                      sizeof(chrome_alpn),
                                                                      worker_count,
                                                                      false,
                                                                      false))
    {
        tlsclientTunnelstateDestroy(ts);
        tunnelDestroy(t);
        return NULL;
    }

    // memoryFree(alpn_format);
    return t;
}
