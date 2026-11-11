#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientLinestateInitialize(udpovertcpclient_lstate_t *ls, buffer_pool_t *pool, bool splice_output)
{
    spliceframereaderInit(&ls->reader, pool, kHeaderSize, kMaxReentryBytes, kReadChargeLimit, splice_output);
    ls->size_drop_log       = (log_rate_limiter_t) {0};
    ls->last_rejected_bytes = 0;
}

void udpovertcpclientLinestateDestroy(udpovertcpclient_lstate_t *ls)
{
    const log_rate_limiter_report_t report = logRateLimiterFlush(&ls->size_drop_log);
    if (report.should_log)
        LOGW("UdpOverTcpClient: dropped datagrams with unsupported payload size at line close "
             "(drops=%" PRIu64 ", total_drops=%" PRIu64 ", last_payload_bytes=%zu, max_payload_bytes=%u)",
             report.events,
             report.total,
             ls->last_rejected_bytes,
             (unsigned) kMaxAllowedUDPPacketLength);
    spliceframereaderDestroy(&ls->reader);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(udpovertcpclient_lstate_t)));
}

void udpovertcpclientLogSizeDrop(udpovertcpclient_lstate_t *ls, size_t length)
{
    ls->last_rejected_bytes = length;
    /* One datagram callback per packet can otherwise flood logs on an oversized producer. */
    const log_rate_limiter_report_t report = logRateLimiterRecordImmediate(&ls->size_drop_log, 5000);
    if (report.should_log)
        LOGW("UdpOverTcpClient: dropping datagrams: unsupported payload size "
             "(drops=%" PRIu64 ", total_drops=%" PRIu64 ", last_payload_bytes=%zu, min_payload_bytes=1, "
             "max_payload_bytes=%u)",
             report.events,
             report.total,
             length,
             (unsigned) kMaxAllowedUDPPacketLength);
}
