#include "structure.h"

#include "loggers/network_logger.h"

static bool tlsclientHostnameBytesAreValid(const uint8_t *hostname, uint32_t hostname_length)
{
    if (hostname == NULL || hostname_length == 0 || hostname_length > kTlsClientMaxSniLength)
    {
        return false;
    }

    for (uint32_t i = 0; i < hostname_length; ++i)
    {
        if (hostname[i] == '\0')
        {
            return false;
        }
    }

    return true;
}

/*
 * Shared generation body. Every caller has already resolved which worker owns
 * `pool`; this validates that ownership exactly once - `wid` must index the
 * getWorkersCount()-sized per-event-worker context arrays, and the caller must
 * be that very event worker.
 */
static sbuf_t *tlsclientGenerateClientHelloForWorker(tunnel_t *instance, wid_t wid, buffer_pool_t *pool,
                                                     const uint8_t *hostname, uint32_t hostname_length)
{
    if (instance == NULL || pool == NULL || wid >= getWorkersCount() || ! currentThreadIsEventWorkerWID(wid) ||
        ! tlsclientHostnameBytesAreValid(hostname, hostname_length))
    {
        return NULL;
    }

    char *sni = memoryAllocate((size_t) hostname_length + 1U);
    memoryCopy(sni, hostname, hostname_length);
    sni[hostname_length] = '\0';

    tlsclient_tstate_t *ts = tunnelGetState(instance);

    sbuf_t *ech_payload = NULL;
    bool    created_ok  = tlsclientCreateEchGreaseInnerClientHello(ts, wid, &ech_payload);

    sbuf_t *hello = NULL;
    if (created_ok)
    {
        created_ok = tlsclientCreateClientHelloFromContext(
            ts->threadlocal_ssl_contexts[wid],
            sni,
            ech_payload != NULL ? (const uint8_t *) sbufGetRawPtr(ech_payload) : NULL,
            ech_payload != NULL ? sbufGetLength(ech_payload) : 0,
            ts->alpn_wire,
            ts->alpn_wire_len,
            &hello);
    }

    if (ech_payload != NULL)
    {
        bufferpoolReuseBuffer(pool, ech_payload);
    }
    memoryFree(sni);

    if (! created_ok && hello != NULL)
    {
        bufferpoolReuseBuffer(pool, hello);
        hello = NULL;
    }

    return created_ok ? hello : NULL;
}

sbuf_t *tlsclientTunnelGenerateClientHello(tunnel_t *instance, line_t *caller_line, const uint8_t *hostname,
                                           uint32_t hostname_length)
{
    if (caller_line == NULL)
    {
        return NULL;
    }

    // Generation runs on the caller's line: its worker owns both the SSL context
    // slot and the pool the generated ClientHello is allocated from.
    if (! lineIsOnCurrentEventWorker(caller_line))
    {
        return NULL;
    }

    return tlsclientGenerateClientHelloForWorker(
        instance, lineGetWID(caller_line), lineGetBufferPool(caller_line), hostname, hostname_length);
}

/*
 * Unlike the shared tunnel-API helpers in node.h, this API returns a generated
 * buffer, so it keeps the exact originating pool for both the request and the
 * response through every error path.
 */
api_result_t tlsclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    static const char kGenerateTlsHelloPrefix[] = "generateTlsHello:";
    const uint32_t    prefix_len                = (uint32_t) (sizeof(kGenerateTlsHelloPrefix) - 1);

    if (message == NULL)
    {
        return (api_result_t) {.result_code = kApiResultError};
    }

    /*
     * There is no per-event-worker SSL context for the lwIP pseudo-worker and no
     * worker-local pool at all for an unregistered thread. Neither may borrow
     * worker 0's, so the request is destroyed rather than recycled and the call
     * fails.
     */
    worker_t *worker = tryGetCurrentEventWorker();
    if (worker == NULL)
    {
        sbufDestroy(message);
        return (api_result_t) {.result_code = kApiResultError};
    }

    const wid_t    wid     = worker->wid;
    buffer_pool_t *pool    = getWorkerBufferPool(wid);
    const uint8_t *msg_ptr = (const uint8_t *) sbufGetRawPtr(message);
    uint32_t       msg_len = sbufGetLength(message);

    if (msg_len <= prefix_len || memoryCompare(msg_ptr, kGenerateTlsHelloPrefix, prefix_len) != 0)
    {
        bufferpoolReuseBuffer(pool, message);
        return (api_result_t) {.result_code = kApiResultError};
    }

    sbuf_t *hello =
        tlsclientGenerateClientHelloForWorker(instance, wid, pool, msg_ptr + prefix_len, msg_len - prefix_len);
    bufferpoolReuseBuffer(pool, message);
    if (hello == NULL)
    {
        return (api_result_t) {.result_code = kApiResultError};
    }

    return (api_result_t) {.result_code = kApiResultOk, .buffer = hello};
}
