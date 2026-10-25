#include "internal.h"
#include "loggers/network_logger.h"

static const char *vmessclientBodyName(const vmessclient_tstate_t *ts)
{
    return ts->security == VMESS_SECURITY_AES128_GCM          ? "aes-128-gcm"
           : ts->security == VMESS_SECURITY_CHACHA20_POLY1305 ? "chacha20-poly1305"
           : (ts->options & VMESS_OPTION_CHUNK) != 0          ? "none"
                                                              : "zero";
}

const char *vmessclientReasonName(vmessclient_reason_t reason)
{
    static const char *const names[kVmessClientReasonCount] = {"normal_close",
                                                               "invalid_target",
                                                               "malformed_header",
                                                               "length_failure",
                                                               "body_failure",
                                                               "retained_input",
                                                               "admission_refused",
                                                               "udp_oversize",
                                                               "unexpected_source",
                                                               "malformed_packetaddr",
                                                               "packetaddr_needs_ip",
                                                               "strict_exhaustion",
                                                               "provider_failure"};
    assert(reason < kVmessClientReasonCount);
    return names[reason];
}

void vmessclientRecordReason(tunnel_t *t, vmessclient_reason_t reason, bool udp)
{
    vmessclient_tstate_t *ts = tunnelGetState(t);
    atomicIncU64Relaxed(&ts->stats.reasons[reason]);
    if (! ts->verbose)
        return;
    uint64_t now   = nodeApiNowMs();
    uint64_t after = atomicLoadU64Relaxed(&ts->stats.verbose_after_ms);
    if (now < after || ! atomicCompareExchangeU64Explicit(
                           &ts->stats.verbose_after_ms, &after, now + 1000, memory_order_relaxed, memory_order_relaxed))
    {
        atomicIncU64Relaxed(&ts->stats.verbose_suppressed);
        return;
    }
    LOGD("VmessClient: protocol=%s security=%s reason=%s",
         udp ? "udp" : "tcp",
         vmessclientBodyName(ts),
         vmessclientReasonName(reason));
}

void vmessclientSetReason(vmessclient_lstate_t *ls, vmessclient_reason_t reason)
{
    if (ls->reason_recorded)
        return;
    ls->reason_recorded = true;
    vmessclientRecordReason(ls->tunnel, reason, ls->kind != kVmessClientLineKindDirect);
}

static bool vmessclientEmptyRequest(const sbuf_t *message)
{
    const uint8_t *bytes  = sbufGetRawPtr(message);
    size_t         length = sbufGetLength(message), cursor = 0;
    if (length > 64)
        return false;
#define SKIP_SPACE()                                                                                                   \
    do                                                                                                                 \
    {                                                                                                                  \
        while (cursor < length &&                                                                                      \
               (bytes[cursor] == ' ' || bytes[cursor] == '\t' || bytes[cursor] == '\r' || bytes[cursor] == '\n'))      \
            ++cursor;                                                                                                  \
    } while (0)
    SKIP_SPACE();
    if (cursor == length || bytes[cursor++] != '{')
        return false;
    SKIP_SPACE();
    if (cursor == length || bytes[cursor++] != '}')
        return false;
    SKIP_SPACE();
#undef SKIP_SPACE
    return cursor == length;
}

static api_result_t vmessclientStatsApi(tunnel_t *t, sbuf_t *message, const node_api_call_context_t *context)
{
    assert(message != NULL && context != NULL);
    bool           valid = vmessclientEmptyRequest(message);
    buffer_pool_t *pool  = getCurrentWorkerBufferPool();
    bufferpoolReuseBuffer(pool, message);
    enum
    {
        kStatsTextCapacity  = 4096,
        kStatsWorkingMemory = kStatsTextCapacity + 512
    };
    if (! valid || nodeApiNowMs() >= context->deadline_ms || context->working_memory_allowance < kStatsWorkingMemory)
        return (api_result_t) {.result_code = kApiResultError};
    vmessclient_tstate_t *ts = tunnelGetState(t);
    char                  text[kStatsTextCapacity];
    size_t                used = 0;
#define APPEND(...)                                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        int count = snprintf(text + used, sizeof(text) - used, __VA_ARGS__);                                           \
        if (count < 0 || (size_t) count >= sizeof(text) - used)                                                        \
            return (api_result_t) {.result_code = kApiResultError};                                                    \
        used += (size_t) count;                                                                                        \
    } while (0)
#define COUNTER(field) APPEND(",\"" #field "\":\"%" PRIu64 "\"", atomicLoadU64Relaxed(&ts->stats.field))
    APPEND("{\"snapshot\":\"approximate\",\"configuration\":{\"security\":\"%s\",\"security_auto\":%s,"
           "\"encrypted_counter_policy\":\"%s\",\"send_termination\":%s,\"packet_encoding\":\"%s\","
           "\"verbose\":%s,\"options\":%u,\"protocol\":\"%s\",\"first_payload_timeout_ms\":%u}",
           vmessclientBodyName(ts),
           ts->security_auto ? "true" : "false",
           ts->counter_policy == kVmessCounterWrap ? "wrap" : "strict",
           ts->send_termination ? "true" : "false",
           ts->packetaddr ? "packetaddr" : "none",
           ts->verbose ? "true" : "false",
           (unsigned) ts->options,
           ts->protocol == kVmessClientProtocolTcp   ? "tcp"
           : ts->protocol == kVmessClientProtocolUdp ? "udp"
                                                     : "dest_context->protocol",
           (unsigned) ts->first_payload_timeout_ms);
    COUNTER(active_applications);
    COUNTER(active_carriers);
    APPEND(",\"active_backends\":\"0\"");
    COUNTER(tx_records);
    COUNTER(rx_records);
    COUNTER(tx_application_bytes);
    COUNTER(rx_application_bytes);
    COUNTER(tx_wire_bytes);
    COUNTER(rx_wire_bytes);
    COUNTER(tx_wraps);
    COUNTER(rx_wraps);
    COUNTER(verbose_suppressed);
    APPEND(",\"reasons\":{");
    for (unsigned i = 0; i < kVmessClientReasonCount; ++i)
        APPEND("%s\"%s\":\"%" PRIu64 "\"",
               i == 0 ? "" : ",",
               vmessclientReasonName((vmessclient_reason_t) i),
               atomicLoadU64Relaxed(&ts->stats.reasons[i]));
    APPEND("}}");
#undef COUNTER
#undef APPEND
    buffer_pool_fit_t fit;
    if (nodeApiNowMs() >= context->deadline_ms || used > context->max_response_body_size ||
        ! bufferpoolQueryBestFit(pool, used, 0, &fit) ||
        fit.allocation_charge > context->working_memory_allowance - kStatsWorkingMemory)
        return (api_result_t) {.result_code = kApiResultError};
    sbuf_t *result = bufferpoolGetBestFit(pool, (uint32_t) used, 0);
    memoryCopy(sbufGetMutablePtr(result), text, used);
    sbufSetLength(result, (uint32_t) used);
    return (api_result_t) {.result_code = kApiResultOk, .buffer = result};
}

bool vmessclientRegisterApi(tunnel_t *t)
{
    static const node_api_operation_t operations[] = {{.name                  = "stats",
                                                       .handler               = vmessclientStatsApi,
                                                       .read_only             = true,
                                                       .request_content_type  = "application/json",
                                                       .response_content_type = "application/json",
                                                       .response_encoding     = kNodeApiEncodingUtf8,
                                                       .execution             = kNodeApiCallingWorker}};
    return nodeApiRegister(t, operations, ARRAY_SIZE(operations));
}

api_result_t vmessclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiRecycleMessage(message);
}
