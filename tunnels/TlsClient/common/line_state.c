#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientLinestateInitialize(tlsclient_lstate_t *ls, SSL_CTX *sctx)
{

    ls->rbio = BIO_new(BIO_s_mem());
    ls->wbio = BIO_new(BIO_s_mem());
    ls->ssl  = SSL_new(sctx);
    ls->bq   = bufferqueueCreate(2);

    // ALPS settings for HTTP/2 (matches Chrome's 0x026832)
    static const uint8_t h2_alps_settings[] = {0x02, 0x68, 0x32};

    // ALPS settings for HTTP/1.1 (typically empty for HTTP/1.1)
    // C shows warning for zero sized arrays (zero or negative size array 'h1_alps_settings' GCC), so hardcode...
    // static const uint8_t h1_alps_settings[] = {};
    static const void   *h1_alps_settings_ptr = NULL;
    static const uint8_t kH1AlpsSettingsLen   = 0;

    // Add ALPS for h2
    if (SSL_add_application_settings(ls->ssl, (const uint8_t *) "h2", 2, h2_alps_settings, sizeof(h2_alps_settings)) !=
        1)
    {
        LOGF("Failed to add ALPS for HTTP/2   (part of matching Chrome)");
        SSL_free(ls->ssl);
        BIO_free(ls->rbio);
        BIO_free(ls->wbio);
        bufferqueueDestroy(&(ls->bq));
        memorySet(ls, 0, sizeof(tlsclient_lstate_t));
        terminateProgram(1);
        return;
    }

    // Add ALPS for http/1.1
    if (SSL_add_application_settings(ls->ssl, (const uint8_t *) "http/1.1", 8, h1_alps_settings_ptr,
                                     kH1AlpsSettingsLen) != 1)
    {
        LOGF("Failed to add ALPS for HTTP/1   (part of matching Chrome)");
        SSL_free(ls->ssl);
        BIO_free(ls->rbio);
        BIO_free(ls->wbio);
        bufferqueueDestroy(&(ls->bq));
        memorySet(ls, 0, sizeof(tlsclient_lstate_t));
        terminateProgram(1);
        return;
    }

    // Enable ECH GREASE to match Chrome's behavior
    // This sends a fake ECH extension to prevent fingerprinting
    SSL_set_enable_ech_grease(ls->ssl, 1);

    // Configure additional Chrome-like extensions

    // Enable OCSP stapling (status_request extension)
    SSL_enable_ocsp_stapling(ls->ssl);

    // Enable Signed Certificate Timestamp extension
    SSL_enable_signed_cert_timestamps(ls->ssl);
}

void tlsclientLinestateDestroy(tlsclient_lstate_t *ls)
{

    SSL_free(ls->ssl); /* free the SSL object and its BIO's */
    // BIO_free(ls->rbio);
    // BIO_free(ls->wbio);
    bufferqueueDestroy(&(ls->bq));
    memorySet(ls, 0, sizeof(tlsclient_lstate_t));
}
