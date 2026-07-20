#include "structure.h"

#include "loggers/network_logger.h"

static bool tlsclientAddConfiguredApplicationSettings(SSL *ssl, const uint8_t *alpn_wire, size_t alpn_wire_len)
{
    // Chrome's h2 ALPS payload is a fixed three-byte value captured on the wire.
    // Do not replace this with a serialized HTTP/2 SETTINGS frame.
    static const uint8_t kChromeH2AlpsPayload[]  = {0x02, 0x68, 0x32};
    static const void   *kChromeH1AlpsPayload    = NULL;
    static const uint8_t kChromeH1AlpsPayloadLen = 0;

    static_assert(sizeof(kChromeH2AlpsPayload) == 3, "Chrome h2 ALPS payload must stay 0x026832");

    size_t offset = 0;
    while (offset < alpn_wire_len)
    {
        const size_t name_len = alpn_wire[offset++];
        assert(name_len > 0 && name_len <= alpn_wire_len - offset);

        const uint8_t *name = alpn_wire + offset;
        if (name_len == 2 && memoryCompare(name, "h2", 2) == 0)
        {
            if (SSL_add_application_settings(
                    ssl, name, name_len, kChromeH2AlpsPayload, sizeof(kChromeH2AlpsPayload)) != 1)
            {
                return false;
            }
        }
        else if (name_len == 8 && memoryCompare(name, "http/1.1", 8) == 0)
        {
            if (SSL_add_application_settings(
                    ssl, name, name_len, kChromeH1AlpsPayload, kChromeH1AlpsPayloadLen) != 1)
            {
                return false;
            }
        }

        offset += name_len;
    }

    return true;
}

void tlsclientLinestateInitialize(tlsclient_lstate_t *ls, SSL_CTX *sctx, buffer_pool_t *pool,
                                  const uint8_t *alpn_wire, size_t alpn_wire_len)
{
    assert(alpn_wire != NULL || alpn_wire_len == 0);

    assert(ls != NULL && sctx != NULL && pool != NULL);

    *ls = (tlsclient_lstate_t) {
        .bq              = bufferqueueCreate(2),
        .takeover_stream = bufferstreamCreate(pool, 0),
        .takeover_phase  = kTlsClientTakeoverHandshake,
    };

    ls->rbio = BIO_new(BIO_s_mem());
    ls->wbio = BIO_new(BIO_s_mem());
    ls->ssl  = SSL_new(sctx);

    if (ls->rbio == NULL || ls->wbio == NULL || ls->ssl == NULL)
    {
        LOGF("Failed to allocate TlsClient BoringSSL line state");
        SSL_free(ls->ssl);
        BIO_free(ls->rbio);
        BIO_free(ls->wbio);
        bufferqueueDestroy(&(ls->bq));
        bufferstreamDestroy(&(ls->takeover_stream));
        memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tlsclient_lstate_t)));
        terminateProgram(1);
        return;
    }

    // Register Chrome-like ALPS values only for matching protocols in the configured ALPN offer.
    if (! tlsclientAddConfiguredApplicationSettings(ls->ssl, alpn_wire, alpn_wire_len))
    {
        LOGF("Failed to add configured ALPS values (part of matching Chrome)");
        SSL_free(ls->ssl);
        BIO_free(ls->rbio);
        BIO_free(ls->wbio);
        bufferqueueDestroy(&(ls->bq));
        bufferstreamDestroy(&(ls->takeover_stream));
        memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tlsclient_lstate_t)));
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
    bufferstreamDestroy(&(ls->takeover_stream));
}

void tlsclientLinestateDestroy(tlsclient_lstate_t *ls)
{
    tlsclientLinestateRelease(ls);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(tlsclient_lstate_t)));
}
