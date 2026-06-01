#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientLinestateInitialize(tlsclient_lstate_t *ls, SSL_CTX *sctx)
{
    // Chrome's h2 ALPS payload is a fixed three-byte value captured on the wire.
    // Do not replace this with a serialized HTTP/2 SETTINGS frame.
    static const uint8_t kChromeH2AlpsPayload[] = {0x02, 0x68, 0x32};
    static const void   *kChromeH1AlpsPayload   = NULL;
    static const uint8_t kChromeH1AlpsPayloadLen = 0;

    static_assert(sizeof(kChromeH2AlpsPayload) == 3, "Chrome h2 ALPS payload must stay 0x026832");

    *ls = (tlsclient_lstate_t) {0};

    ls->rbio = BIO_new(BIO_s_mem());
    ls->wbio = BIO_new(BIO_s_mem());
    ls->ssl  = SSL_new(sctx);
    ls->bq   = bufferqueueCreate(2);

    // Add ALPS for h2
    if (SSL_add_application_settings(ls->ssl, (const uint8_t *) "h2", 2, kChromeH2AlpsPayload,
                                     sizeof(kChromeH2AlpsPayload)) != 1)
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
    if (SSL_add_application_settings(ls->ssl, (const uint8_t *) "http/1.1", 8, kChromeH1AlpsPayload,
                                     kChromeH1AlpsPayloadLen) != 1)
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

void tlsclientLinestateRelease(tlsclient_lstate_t *ls)
{
    if (ls->resources_released)
    {
        return;
    }

    ls->resources_released = true;

    SSL_free(ls->ssl); /* free the SSL object and its BIO's */
    ls->ssl  = NULL;
    ls->rbio = NULL;
    ls->wbio = NULL;
    bufferqueueDestroy(&(ls->bq));
}

void tlsclientLinestateDestroy(tlsclient_lstate_t *ls)
{
    tlsclientLinestateRelease(ls);
    memoryZeroAligned32(ls, sizeof(tlsclient_lstate_t));
}
