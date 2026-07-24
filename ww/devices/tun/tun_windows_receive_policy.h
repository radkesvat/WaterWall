#pragma once

#include <stdbool.h>
#include <stdint.h>

// Reader-owned accounting for oversized Wintun receive packets. When the Windows
// TUN reader sees a packet larger than the configured MTU it drops that single
// packet instead of terminating the process. The drops are counted and reported
// with a rate-limited aggregate warning, mirroring the local patterns in
// raw_windows.c and capture_linux.c.
//
// Only the Windows TUN reader thread mutates this state (shutdown joins that
// thread before destroying the device), so it needs no atomics. The decision and
// rate-limit state machine are factored out here as pure functions so they can be
// unit-tested with an injected clock, following the tun_windows_lifetime.h seam
// style.

enum
{
    kTunOversizedReadDiscardReportIntervalMs = 1000
};

typedef struct tun_oversized_read_discard_stats_s
{
    uint64_t           total;          // lifetime count of dropped oversized packets
    uint64_t           suppressed;     // dropped packets not yet covered by a warning
    unsigned long long last_report_ms; // timestamp of the last aggregate report (0 = unarmed)
} tun_oversized_read_discard_stats_t;

typedef struct tun_oversized_read_discard_report_s
{
    bool               should_log; // true when the caller should emit one aggregate warning
    uint64_t           discarded;  // packets covered by this aggregate warning
    unsigned long long elapsed_ms; // interval covered (0 for the reader-exit flush)
    uint64_t           total;      // lifetime dropped packets at report time
} tun_oversized_read_discard_report_t;

// Classifies a received packet against the configured MTU.
static inline bool tunWindowsReceivePacketExceedsMtu(uint16_t mtu, uint64_t packet_size)
{
    return packet_size > (uint64_t) mtu;
}

// Records one oversized-read discard observed at now_ms and returns whether the
// caller should emit an aggregate warning now. The first discard only arms the
// report clock; later discards accumulate until the interval elapses.
static inline tun_oversized_read_discard_report_t tunWindowsAccountOversizedReadDiscard(
    tun_oversized_read_discard_stats_t *stats, unsigned long long now_ms)
{
    tun_oversized_read_discard_report_t report = {0};

    stats->total++;
    stats->suppressed++;

    if (stats->last_report_ms == 0)
    {
        stats->last_report_ms = now_ms;
        return report;
    }

    unsigned long long elapsed_ms = now_ms - stats->last_report_ms;
    if (elapsed_ms < (unsigned long long) kTunOversizedReadDiscardReportIntervalMs)
    {
        return report;
    }

    report.should_log = true;
    report.discarded  = stats->suppressed;
    report.elapsed_ms = elapsed_ms;
    report.total      = stats->total;

    stats->suppressed     = 0;
    stats->last_report_ms = now_ms;
    return report;
}

// Reports any still-suppressed discards once, e.g. during reader cleanup.
static inline tun_oversized_read_discard_report_t tunWindowsAccountPendingOversizedReadDiscards(
    tun_oversized_read_discard_stats_t *stats)
{
    tun_oversized_read_discard_report_t report = {0};

    if (stats->suppressed == 0)
    {
        return report;
    }

    report.should_log = true;
    report.discarded  = stats->suppressed;
    report.total      = stats->total;

    stats->suppressed = 0;
    return report;
}
