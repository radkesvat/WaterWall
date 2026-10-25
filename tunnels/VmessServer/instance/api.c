#include "auth.h"
#include "internal.h"

static api_result_t vmessserverStatsResult(const node_api_call_context_t *context, enum api_result_e code,
                                           const char *text, size_t length)
{
    buffer_pool_t    *pool = getCurrentWorkerBufferPool();
    buffer_pool_fit_t fit;
    /* Account for the handler's fixed stack/render storage as well as the real
     * pooled output allocation. No live-line traversal or tree allocation. */
    if (nodeApiNowMs() >= context->deadline_ms || length > context->max_response_body_size ||
        context->working_memory_allowance < 4608 || ! bufferpoolQueryBestFit(pool, length, 0, &fit) ||
        fit.allocation_charge > context->working_memory_allowance - 4608)
        return (api_result_t) {.result_code = kApiResultError};
    sbuf_t *out = bufferpoolGetBestFit(pool, (uint32_t) length, 0);
    sbufSetLength(out, (uint32_t) length);
    memoryCopy(sbufGetMutablePtr(out), text, length);
    return (api_result_t) {.result_code = code, .buffer = out};
}

static api_result_t vmessserverStats(tunnel_t *t, sbuf_t *message, const node_api_call_context_t *context)
{
    const size_t   length = sbufGetLength(message);
    const uint8_t *body   = sbufGetRawPtr(message);
    bool           valid  = length <= 64;
    unsigned       phase  = 0;
    for (size_t i = 0; valid && i < length; ++i)
    {
        if (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n')
            continue;
        if (phase == 0 && body[i] == '{')
            phase = 1;
        else if (phase == 1 && body[i] == '}')
            phase = 2;
        else
            valid = false;
    }
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), message);
    if (! valid || phase != 2)
        return vmessserverStatsResult(context, kApiResultError, "{\"error\":\"expected_empty_object\"}", 33);
    if (nodeApiNowMs() >= context->deadline_ms || context->working_memory_allowance < 4608)
        return (api_result_t) {.result_code = kApiResultError};
    vmessserver_tstate_t *ts = tunnelGetState(t);
    uint64_t              pending, pending_bytes, cache, auth_marks, session_marks;
    if (! vmessserverAuthSnapshot(ts->auth, &pending, &pending_bytes, &cache) ||
        ! vmessReplaySnapshot(ts->replay, &auth_marks, &session_marks))
        return vmessserverStatsResult(context, kApiResultError, "{\"error\":\"busy\"}", 16);
    char   text[4096];
    size_t used = 0;
#define VMESS_STATS_APPEND(...)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        int count = snprintf(text + used, sizeof(text) - used, __VA_ARGS__);                                           \
        if (count < 0 || (size_t) count >= sizeof(text) - used)                                                        \
            return (api_result_t) {.result_code = kApiResultError};                                                    \
        used += (size_t) count;                                                                                        \
    } while (0)
#define VMESS_STATS_COUNTER(name)                                                                                      \
    VMESS_STATS_APPEND(",\"" #name "\":\"%" PRIu64 "\"", (uint64_t) atomicLoadU64Relaxed(&ts->stats.name))
    VMESS_STATS_APPEND("{\"approximate\":true,\"encrypted_counter_policy\":\"%s\",\"send_termination\":%s,"
                       "\"packetaddr\":%s,\"packetaddr_max_destinations\":%u,\"connect\":%s,\"udp\":%s,"
                       "\"verbose\":%s,\"managed\":%s,\"allowed_security\":[",
                       ts->counter_policy == kVmessCounterWrap ? "wrap" : "strict",
                       ts->send_termination ? "true" : "false",
                       ts->packetaddr ? "true" : "false",
                       ts->packetaddr_max_destinations,
                       ts->allow_connect ? "true" : "false",
                       ts->allow_udp ? "true" : "false",
                       ts->verbose ? "true" : "false",
                       ts->auth_client_node != NULL ? "true" : "false");
    const char *const modes[] = {"aes-128-gcm", "chacha20-poly1305", "none", "zero"};
    bool              comma   = false;
    for (unsigned i = 0; i < 4; ++i)
        if ((ts->allowed_security & (1U << i)) != 0)
        {
            VMESS_STATS_APPEND("%s\"%s\"", comma ? "," : "", modes[i]);
            comma = true;
        }
    VMESS_STATS_APPEND("]");
    VMESS_STATS_COUNTER(applications);
    VMESS_STATS_COUNTER(carriers);
    VMESS_STATS_COUNTER(backends);
    VMESS_STATS_COUNTER(tx_records);
    VMESS_STATS_COUNTER(rx_records);
    VMESS_STATS_COUNTER(tx_application_bytes);
    VMESS_STATS_COUNTER(rx_application_bytes);
    VMESS_STATS_COUNTER(tx_wire_bytes);
    VMESS_STATS_COUNTER(rx_wire_bytes);
    VMESS_STATS_COUNTER(wrap_events);
    VMESS_STATS_COUNTER(strict_exhaustion);
    VMESS_STATS_APPEND(",\"pending_auth\":\"%" PRIu64 "\",\"pending_auth_bytes\":\"%" PRIu64
                       "\",\"auth_cache_bytes\":\"%" PRIu64 "\",\"authid_marks\":\"%" PRIu64
                       "\",\"session_marks\":\"%" PRIu64 "\",\"reasons\":{",
                       pending,
                       pending_bytes,
                       cache,
                       auth_marks,
                       session_marks);
    for (unsigned i = 1; i < kVmessServerReasonCount; ++i)
        VMESS_STATS_APPEND("%s\"%s\":\"%" PRIu64 "\"",
                           i == 1 ? "" : ",",
                           vmessserverReasonName(i),
                           (uint64_t) atomicLoadU64Relaxed(&ts->stats.reasons[i]));
    VMESS_STATS_APPEND("}}");
#undef VMESS_STATS_COUNTER
#undef VMESS_STATS_APPEND
    return vmessserverStatsResult(context, kApiResultOk, text, used);
}

bool vmessserverRegisterApi(tunnel_t *t)
{
    static const node_api_operation_t operations[] = {{.name                  = "stats",
                                                       .handler               = vmessserverStats,
                                                       .read_only             = true,
                                                       .request_content_type  = "application/json",
                                                       .response_content_type = "application/json",
                                                       .response_encoding     = kNodeApiEncodingUtf8,
                                                       .execution             = kNodeApiCallingWorker}};
    return nodeApiRegister(t, operations, sizeof(operations) / sizeof(operations[0]));
}

api_result_t vmessserverTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiUnsupportedMessage(message);
}
