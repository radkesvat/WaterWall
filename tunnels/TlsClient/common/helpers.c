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

    memoryFree(ts->alpn);
    memoryFree(ts->sni);

    ts->alpn                            = NULL;
    ts->sni                             = NULL;
    ts->verify                          = false;
    ts->x25519mlkem768_enabled          = false;
}
