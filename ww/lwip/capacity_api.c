#include "capacity_api.h"

#include "buffer_pool.h"
#include "capacity.h"
#include "port_registry.h"
#include "worker.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

enum
{
    kCapacityApiPools   = 64,
    kCapacityApiText    = 32768,
    kCapacityApiScratch = kCapacityApiText + kCapacityApiPools * sizeof(ww_lwip_pool_snapshot_t) +
                          sizeof(ww_lwip_capacity_snapshot_t) + 1024
};

static bool capacityApiAppend(char *text, size_t *used, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    const int count = vsnprintf(text + *used, kCapacityApiText - *used, format, args);
    va_end(args);
    if (count < 0 || (size_t) count >= kCapacityApiText - *used)
        return false;
    *used += (size_t) count;
    return true;
}

static bool capacityApiName(char *text, size_t *used, const char *name)
{
    for (unsigned i = 0; i < 128; ++i)
    {
        const unsigned char ch = (unsigned char) name[i];
        if (ch == 0)
            return true;
        if (ch < 32 || ch >= 127 || ch == '"' || ch == '\\')
        {
            if (! capacityApiAppend(text, used, "\\u%04x", (unsigned) ch))
                return false;
        }
        else if (! capacityApiAppend(text, used, "%c", ch))
            return false;
    }
    return false;
}

static api_result_t capacityApiResult(const node_api_call_context_t *context, enum api_result_e code, const char *text,
                                      size_t length)
{
    buffer_pool_t    *pool = getCurrentWorkerBufferPool();
    buffer_pool_fit_t fit;
    if (nodeApiNowMs() >= context->deadline_ms || length > context->max_response_body_size ||
        context->working_memory_allowance < kCapacityApiScratch || ! bufferpoolQueryBestFit(pool, length, 0, &fit) ||
        fit.allocation_charge > context->working_memory_allowance - kCapacityApiScratch)
        return (api_result_t) {.result_code = kApiResultError};
    sbuf_t *out = bufferpoolGetBestFit(pool, length, 0);
    sbufSetLength(out, length);
    memoryCopy(sbufGetMutablePtr(out), text, length);
    return (api_result_t) {.result_code = code, .buffer = out};
}

static api_result_t capacityApiStats(tunnel_t *tunnel, sbuf_t *message, const node_api_call_context_t *context)
{
    (void) tunnel;
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
        return capacityApiResult(context, kApiResultError, "{\"error\":\"expected_empty_object\"}", 33);
    if (nodeApiNowMs() >= context->deadline_ms || context->working_memory_allowance < kCapacityApiScratch)
        return (api_result_t) {.result_code = kApiResultError};

    ww_lwip_capacity_snapshot_t snapshot;
    ww_lwip_pool_snapshot_t     pools[kCapacityApiPools];
    ww_lwip_port_stats_t        ports[2];
    const size_t                count = wwLwipCapacitySnapshot(&snapshot, pools, kCapacityApiPools);
    wwLwipPortGetStats(kWwLwipTcp, &ports[0]);
    wwLwipPortGetStats(kWwLwipUdp, &ports[1]);
    if (count > kCapacityApiPools)
        return capacityApiResult(context, kApiResultError, "{\"error\":\"too_many_pools\"}", 26);
    char   text[kCapacityApiText];
    size_t used = 0;
#define APPEND(...)                                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! capacityApiAppend(text, &used, __VA_ARGS__))                                                             \
            return (api_result_t) {.result_code = kApiResultError};                                                    \
    } while (0)
    APPEND("{\"scope\":\"process\",\"dynamic\":%s,\"held_includes_worker_caches\":true,"
           "\"memory_budget\":\"%" PRIu64 "\",\"reserved_bytes\":\"%" PRIu64 "\","
           "\"peak_reserved_bytes\":\"%" PRIu64 "\",\"external_bytes\":\"%" PRIu64 "\","
           "\"byte_refusals\":\"%" PRIu64 "\",\"external_refusals\":\"%" PRIu64 "\","
           "\"reclaimed_bytes\":\"%" PRIu64 "\",\"limits\":{\"tcp_flows\":%" PRIu32 ","
           "\"udp_flows\":%" PRIu32 ",\"tcp_listeners\":%" PRIu32 ",\"tcp_segments\":%" PRIu32 ","
           "\"rx_wrappers\":%" PRIu32 "},\"pools\":[",
           snapshot.dynamic ? "true" : "false",
           snapshot.config.memory_budget,
           snapshot.reserved_bytes,
           snapshot.peak_reserved_bytes,
           snapshot.external_bytes,
           snapshot.byte_refusals,
           snapshot.external_refusals,
           snapshot.reclaimed_bytes,
           snapshot.config.tcp_flows,
           snapshot.config.udp_flows,
           snapshot.config.tcp_listeners,
           snapshot.config.tcp_segments,
           snapshot.config.rx_wrappers);
    for (size_t i = 0; i < count; ++i)
    {
        const ww_lwip_pool_snapshot_t *p = &pools[i];
        APPEND("%s{\"name\":\"", i == 0 ? "" : ",");
        if (! capacityApiName(text, &used, p->name))
            return (api_result_t) {.result_code = kApiResultError};
        APPEND("\",\"object_size\":%" PRIu32 ",\"limit\":%" PRIu32 ",\"allocated\":%" PRIu32 ","
               "\"held\":%" PRIu32 ",\"peak_held\":%" PRIu32 ",\"reserved_bytes\":\"%" PRIu64 "\","
               "\"entry_refusals\":\"%" PRIu64 "\",\"byte_refusals\":\"%" PRIu64 "\"}",
               p->object_size,
               p->limit,
               p->allocated,
               p->held,
               p->peak_held,
               p->reserved_bytes,
               p->entry_refusals,
               p->byte_refusals);
    }
    APPEND("],\"recovery_headroom\":\"%" PRIu64 "\",\"recovery_bytes\":\"%" PRIu64 "\","
           "\"external_recovery_bytes\":\"%" PRIu64 "\",\"recovery_refusals\":\"%" PRIu64 "\",\"ports\":{",
           snapshot.recovery_headroom,
           snapshot.recovery_bytes,
           snapshot.external_recovery_bytes,
           snapshot.recovery_refusals);
    for (unsigned i = 0; i < 2; ++i)
        APPEND("%s\"%s\":{\"active\":\"%" PRIu64 "\",\"peak\":\"%" PRIu64 "\","
               "\"refused\":\"%" PRIu64 "\",\"scoped\":\"%" PRIu64 "\",\"unscoped\":\"%" PRIu64 "\"}",
               i == 0 ? "" : ",",
               i == 0 ? "tcp" : "udp",
               ports[i].active,
               ports[i].peak,
               ports[i].refused,
               ports[i].scoped,
               ports[i].unscoped);
    APPEND("}}");
#undef APPEND
    return capacityApiResult(context, kApiResultOk, text, used);
}

bool wwLwipCapacityRegisterApi(tunnel_t *tunnel)
{
    static const node_api_operation_t operations[] = {{.name                  = "stack-stats",
                                                       .handler               = capacityApiStats,
                                                       .read_only             = true,
                                                       .request_content_type  = "application/json",
                                                       .response_content_type = "application/json",
                                                       .response_encoding     = kNodeApiEncodingUtf8,
                                                       .execution             = kNodeApiCallingWorker}};
    return nodeApiRegister(tunnel, operations, sizeof(operations) / sizeof(operations[0]));
}
