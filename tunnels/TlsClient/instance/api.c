#include "structure.h"

#include "loggers/network_logger.h"

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

    tlsclient_tstate_t *ts = tunnelGetState(instance);
    wid_t               wid = getWID();

    if (wid >= getWorkersCount())
    {
        wid = 0;
    }

    sbuf_t *ech_payload = NULL;
    bool    created_ok  = tlsclientCreateEchGreaseInnerClientHello(ts, wid, &ech_payload);

    sbuf_t *hello_buf = NULL;
    if (created_ok)
    {
        created_ok = tlsclientCreateClientHelloFromContext(
            ts->threadlocal_ssl_contexts[wid],
            sni,
            ech_payload != NULL ? (const uint8_t *) sbufGetRawPtr(ech_payload) : NULL,
            ech_payload != NULL ? sbufGetLength(ech_payload) : 0,
            &hello_buf);
    }

    if (ech_payload != NULL)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(wid), ech_payload);
    }

    memoryFree(sni);

    if (! created_ok)
    {
        return (api_result_t) {.result_code = kApiResultError};
    }

    return (api_result_t) {.result_code = kApiResultOk, .buffer = hello_buf};
}
