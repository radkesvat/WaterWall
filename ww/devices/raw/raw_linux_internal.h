#pragma once

#include "raw_private.h"

#if defined(OS_LINUX)

#include "loggers/log_rate_limiter.h"

/* Each event worker owns its diagnostics until output admission quiesces. */
struct raw_native_writer_s
{
    bool               waiting_writable;
    log_rate_limiter_t discard_log_limiter;
    uint64_t           oversized_packet_total;
    uint64_t           message_too_large_packet_total;
    uint64_t           packet_local_send_error_total;
    uint64_t           transient_send_error_total;
    uint32_t           last_discard_error;
};
typedef raw_native_writer_t raw_linux_writer_state_t;

/* Production batch body exposed for deterministic syscall-failure tests. */
raw_writer_batch_result_t rawLinuxWriteBatch(void *context, worker_t *worker, raw_writer_lane_t *lane, sbuf_t **buffers,
                                             size_t count);

/* Lifecycle-owner operations. Quiesce native sends before removing the exemption. */
bool rawLinuxNotrackInstall(raw_device_t *rdev);
bool rawLinuxNotrackRemove(raw_device_t *rdev);

/* Selection inspects IPv4 iptables-save and ip -4 rule show snapshots. */
bool rawLinuxSelectNotrackMark(const char *iptables_rules, const char *routing_rules, uint32_t *selected);

#endif
