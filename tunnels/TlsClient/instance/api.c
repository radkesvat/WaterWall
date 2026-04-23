#include "structure.h"

#include "loggers/network_logger.h"

static bool tlsclientApiCreateClientHello(SSL_CTX **ssl_contexts, const char *sni, sbuf_t **out)
{
    wid_t wid = getWID();

    if (wid >= getWorkersCount())
    {
        wid = 0;
    }

    SSL_CTX *ssl_ctx = ssl_contexts[wid];
    if (ssl_ctx == NULL)
    {
        return false;
    }

    STACK_ALLOCATE_ALIGNED(tlsclient_lstate_t, ls, 32);
    memoryZero(ls, sizeof(*ls));
    tlsclientLinestateInitialize(ls, ssl_ctx);

    SSL_set_connect_state(ls->ssl);
    SSL_set_bio(ls->ssl, ls->rbio, ls->wbio);

    if (SSL_set_tlsext_host_name(ls->ssl, sni) != 1)
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

api_result_t tlsclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    static const char kGenerateTlsHelloPrefix[] = "generateTlsHello:";
    const uint8_t    *msg_ptr                   = (const uint8_t *) sbufGetRawPtr(message);
    uint32_t          msg_len                   = sbufGetLength(message);
    const uint32_t    prefix_len                = (uint32_t) (sizeof(kGenerateTlsHelloPrefix) - 1);

    if (msg_len <= prefix_len || memoryCompare(msg_ptr, kGenerateTlsHelloPrefix, prefix_len) != 0)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message);
        return (api_result_t) {.result_code = kApiResultError};
    }

    const uint32_t sni_len = msg_len - prefix_len;

    if (sni_len == 0)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message);
        return (api_result_t) {.result_code = kApiResultError};
    }

    char *sni = memoryAllocate(sni_len + 1);

    memoryCopy(sni, msg_ptr + prefix_len, sni_len);
    sni[sni_len] = '\0';
    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message);

    tlsclient_tstate_t *ts         = tunnelGetState(instance);
    sbuf_t             *hello_buf  = NULL;
    bool                created_ok = tlsclientApiCreateClientHello(ts->threadlocal_ssl_contexts, sni, &hello_buf);

    memoryFree(sni);

    if (! created_ok)
    {
        return (api_result_t) {.result_code = kApiResultError};
    }

    return (api_result_t) {.result_code = kApiResultOk, .buffer = hello_buf};
}
