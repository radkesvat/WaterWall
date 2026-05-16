#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientPrintSSLState(const SSL *ssl)
{
    const char *current_state = SSL_state_string_long(ssl);
    LOGD("TlsClient: BoringSSL State: %s", current_state);
}

void tlsclientPrintSSLError(void)
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf = NULL;
    size_t len = BIO_get_mem_data(bio, &buf);
    if (len > 0)
    {
        LOGE("TlsClient: BoringSSL Error: %.*s", len, buf);
    }
    BIO_free(bio);
}
void tlsclientPrintSSLErrorAndAbort(void)
{
    tlsclientPrintSSLError();
    abort();
}

bool tlsclientConfigureSslForConnect(SSL *ssl, BIO *rbio, BIO *wbio, const char *sni,
                                     const uint8_t *ech_grease_override_payload,
                                     size_t ech_grease_override_payload_len)
{
    SSL_set_connect_state(ssl);
    SSL_set_bio(ssl, rbio, wbio);

    if (SSL_set_tlsext_host_name(ssl, sni) != 1)
    {
        return false;
    }

    if (ech_grease_override_payload != NULL && ech_grease_override_payload_len > 0)
    {
        if (SSL_set1_ech_grease_override_payload(
                ssl, ech_grease_override_payload, ech_grease_override_payload_len) != 1)
        {
            return false;
        }
    }

    return true;
}

bool tlsclientCreateClientHelloFromContext(SSL_CTX *ssl_ctx, const char *sni,
                                           const uint8_t *ech_grease_override_payload,
                                           size_t ech_grease_override_payload_len, sbuf_t **out)
{
    if (ssl_ctx == NULL || sni == NULL || out == NULL)
    {
        return false;
    }

    *out = NULL;

    wid_t wid = getWID();

    if (wid >= getWorkersCount())
    {
        wid = 0;
    }

    STACK_ALLOCATE_ALIGNED(tlsclient_lstate_t, ls, 32);
    memoryZero(ls, sizeof(*ls));
    tlsclientLinestateInitialize(ls, ssl_ctx);

    if (! tlsclientConfigureSslForConnect(
            ls->ssl, ls->rbio, ls->wbio, sni, ech_grease_override_payload, ech_grease_override_payload_len))
    {
        tlsclientLinestateDestroy(ls);
        return false;
    }

    int            n      = SSL_connect(ls->ssl);
    enum sslstatus status = getSslStatus(ls->ssl, n);

    if (status == kSslstatusFail)
    {
        tlsclientLinestateDestroy(ls);
        return false;
    }

    sbuf_t *buf   = bufferpoolGetLargeBuffer(getWorkerBufferPool(wid));
    int     avail = (int) sbufGetMaximumWriteableSize(buf);

    while (true)
    {
        n = BIO_read(ls->wbio, sbufGetMutablePtr(buf), avail);
        if (n > 0)
        {
            sbufSetLength(buf, n);
            tlsclientLinestateDestroy(ls);
            *out = buf;
            return true;
        }

        if (! BIO_should_retry(ls->wbio))
        {
            bufferpoolReuseBuffer(getWorkerBufferPool(wid), buf);
            tlsclientLinestateDestroy(ls);
            return false;
        }
    }
}

bool tlsclientCreateEchGreaseInnerClientHello(tlsclient_tstate_t *ts, wid_t wid, sbuf_t **out)
{
    if (ts == NULL || out == NULL)
    {
        return false;
    }

    *out = NULL;

    if (ts->ech_grease_sni_override == NULL)
    {
        return true;
    }

    if (wid >= getWorkersCount())
    {
        wid = 0;
    }

    if (ts->threadlocal_ech_grease_inner_ssl_contexts == NULL ||
        ts->threadlocal_ech_grease_inner_ssl_contexts[wid] == NULL)
    {
        return false;
    }

    return tlsclientCreateClientHelloFromContext(
        ts->threadlocal_ech_grease_inner_ssl_contexts[wid], ts->ech_grease_sni_override, NULL, 0, out);
}

static void tlsclientFreeSslContextPool(SSL_CTX ***contexts)
{
    if (contexts == NULL || *contexts == NULL)
    {
        return;
    }

    int worker_count = getWorkersCount();
    for (int i = 0; i < worker_count; ++i)
    {
        if ((*contexts)[i] != NULL)
        {
            SSL_CTX_free((*contexts)[i]);
        }
    }

    memoryFree(*contexts);
    *contexts = NULL;
}

void tlsclientTunnelstateDestroy(tlsclient_tstate_t *ts)
{
    if (ts == NULL)
    {
        return;
    }

    tlsclientFreeSslContextPool(&ts->threadlocal_ssl_contexts);
    tlsclientFreeSslContextPool(&ts->threadlocal_ech_grease_inner_ssl_contexts);

    memoryFree(ts->alpn);
    memoryFree(ts->sni);
    memoryFree(ts->ech_grease_sni_override);

    ts->alpn                            = NULL;
    ts->sni                             = NULL;
    ts->ech_grease_sni_override         = NULL;
    ts->verify                          = false;
    ts->x25519mlkem768_enabled          = false;
    ts->threadlocal_ech_grease_inner_ssl_contexts = NULL;
}
