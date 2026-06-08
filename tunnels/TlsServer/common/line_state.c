#include "structure.h"

#include "loggers/network_logger.h"

bool tlsserverLinestateInitialize(tlsserver_lstate_t *ls, SSL_CTX *ssl_ctx, bool verbose)
{
    *ls = (tlsserver_lstate_t) {.pending_down = bufferqueueCreate(2), .verbose = verbose};

    ls->rbio = BIO_new(BIO_s_mem());
    ls->wbio = BIO_new(BIO_s_mem());
    ls->ssl  = SSL_new(ssl_ctx);

    if (ls->rbio == NULL || ls->wbio == NULL || ls->ssl == NULL)
    {
        LOGE("TlsServer: failed to allocate per-line TLS objects (rbio=%p, wbio=%p, ssl=%p)",
             (void *) ls->rbio,
             (void *) ls->wbio,
             (void *) ls->ssl);
        tlsserverPrintSSLError();
        tlsserverLinestateDestroy(ls);
        return false;
    }

    SSL_set_accept_state(ls->ssl);
    SSL_set_bio(ls->ssl, ls->rbio, ls->wbio);
    ls->rbio = NULL;
    ls->wbio = NULL;

    return true;
}

void tlsserverLinestateRelease(tlsserver_lstate_t *ls)
{
    if (ls->resources_released)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: per-line TLS resources already released");
        }
        return;
    }
    ls->resources_released = true;

    if (ls->ssl != NULL)
    {
        if (ls->verbose)
        {
            LOGD("TlsServer: releasing per-line SSL object");
        }
        SSL_free(ls->ssl);
        ls->ssl = NULL;
    }
    else
    {
        if (ls->rbio != NULL)
        {
            if (ls->verbose)
            {
                LOGD("TlsServer: releasing detached read BIO");
            }
            BIO_free(ls->rbio);
            ls->rbio = NULL;
        }
        if (ls->wbio != NULL)
        {
            if (ls->verbose)
            {
                LOGD("TlsServer: releasing detached write BIO");
            }
            BIO_free(ls->wbio);
            ls->wbio = NULL;
        }
    }

    bufferqueueDestroy(&ls->pending_down);

    ls->handshake_completed = false;
}

void tlsserverLinestateDestroy(tlsserver_lstate_t *ls)
{
    tlsserverLinestateRelease(ls);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tlsserver_lstate_t)));
}
