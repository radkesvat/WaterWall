#include "structure.h"

#include "loggers/network_logger.h"

#include <stdarg.h>
#include <stdio.h>

enum
{
    kPacketReceiverFileBufferSize = 4096
};

static void packetreceiverFormatIpv4(char *dest, size_t size, uint32_t host_addr)
{
    stringNPrintf(dest, size, "%u.%u.%u.%u", (host_addr >> 24U) & 0xFFU, (host_addr >> 16U) & 0xFFU,
                  (host_addr >> 8U) & 0xFFU, host_addr & 0xFFU);
}

static bool packetreceiverWriteFormat(FILE *file, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    const int written = vfprintf(file, fmt, args);
    va_end(args);

    return written >= 0;
}

static bool packetreceiverResolveSourceIndex(const packetreceiver_tstate_t *state, uint32_t src_addr_network,
                                             uint64_t *source_index_out)
{
    const uint32_t src_addr_host = lwip_ntohl(src_addr_network);
    uint64_t       offset        = 0;

    for (uint32_t ri = 0; ri < state->source_range_count; ++ri)
    {
        const packetreceiver_source_range_t *range = &state->source_ranges[ri];
        const uint64_t range_end = (uint64_t) range->base_host + range->count;

        if ((uint64_t) src_addr_host >= (uint64_t) range->base_host && (uint64_t) src_addr_host < range_end)
        {
            *source_index_out = offset + ((uint64_t) src_addr_host - (uint64_t) range->base_host);
            return true;
        }

        offset += range->count;
    }

    return false;
}

static void packetreceiverBuildHistogramBar(char *bar, size_t bar_size, uint64_t expected, uint64_t received)
{
    if (bar_size == 0)
    {
        return;
    }

    const size_t width = (kPacketReceiverHistogramWidth < (bar_size - 1U)) ? kPacketReceiverHistogramWidth
                                                                           : (bar_size - 1U);
    size_t filled = 0;

    if (width == 0)
    {
        bar[0] = '\0';
        return;
    }

    if (expected > 0)
    {
        filled = (received >= expected) ? width : (size_t) ((received * width) / expected);
    }
    else
    {
        filled = (received > 0) ? width : 0;
    }

    if (filled > width)
    {
        filled = width;
    }

    for (size_t i = 0; i < width; ++i)
    {
        bar[i] = (i < filled) ? '#' : '-';
    }
    bar[width] = '\0';
}

static bool packetreceiverWriteReport(tunnel_t *t)
{
    packetreceiver_tstate_t *state = tunnelGetState(t);
    char                     file_buffer[kPacketReceiverFileBufferSize];
    FILE                    *file = fopen(state->output_file, "wb");

    if (file == NULL)
    {
        return false;
    }

    setvbuf(file, file_buffer, _IOFBF, sizeof(file_buffer));

    uint64_t total_received = 0;
    uint64_t total_lost     = 0;

    uint64_t index = 0;
    for (uint32_t ri = 0; ri < state->source_range_count; ++ri)
    {
        const packetreceiver_source_range_t *range = &state->source_ranges[ri];

        for (uint64_t i = 0; i < range->count; ++i)
        {
            const uint64_t source_index = index++;
            const uint64_t received     = state->received_counts[source_index];
            const uint64_t expected     = (uint64_t) state->expected_packets_per_ip;
            const uint64_t lost         = (expected > received) ? (expected - received) : 0ULL;

            total_received += received;
            total_lost += lost;
        }
    }

    state->total_received_packets = total_received;
    state->total_lost_packets     = total_lost;

    bool ok = true;
    ok = ok && packetreceiverWriteFormat(file, "PacketReceiver report\n");
    ok = ok && packetreceiverWriteFormat(file, "output-file: %s\n", state->output_file);
    ok = ok && packetreceiverWriteFormat(file, "source-ip-count: %llu\n", (unsigned long long) state->source_count);
    ok = ok && packetreceiverWriteFormat(file, "expected-packets-per-ip: %u\n",
                                         (unsigned int) state->expected_packets_per_ip);
    ok = ok && packetreceiverWriteFormat(file, "expected-total-packets: %llu\n",
                                         (unsigned long long) state->total_expected_packets);
    ok = ok && packetreceiverWriteFormat(file, "received-total-packets: %llu\n",
                                         (unsigned long long) state->total_received_packets);
    ok = ok && packetreceiverWriteFormat(file, "lost-total-packets: %llu\n",
                                         (unsigned long long) state->total_lost_packets);
    ok = ok && packetreceiverWriteFormat(file, "unexpected-packets: %llu\n",
                                         (unsigned long long) state->unexpected_packets);
    ok = ok && packetreceiverWriteFormat(file, "\nsource-ip | expected | received | lost | loss-percent | histogram\n");

    index = 0;
    for (uint32_t ri = 0; ok && ri < state->source_range_count; ++ri)
    {
        const packetreceiver_source_range_t *range = &state->source_ranges[ri];

        for (uint64_t i = 0; ok && i < range->count; ++i)
        {
            const uint64_t source_index = index++;
            const uint64_t received     = state->received_counts[source_index];
            const uint64_t expected     = (uint64_t) state->expected_packets_per_ip;
            const uint64_t lost         = (expected > received) ? (expected - received) : 0ULL;
            const double   loss_percent = (expected > 0) ? ((double) lost * 100.0 / (double) expected) : 0.0;
            char           ipbuf[32];
            char           bar[kPacketReceiverHistogramWidth + 1U];

            packetreceiverFormatIpv4(ipbuf, sizeof(ipbuf), range->base_host + (uint32_t) i);
            packetreceiverBuildHistogramBar(bar, sizeof(bar), expected, received);

            ok = packetreceiverWriteFormat(file, "%s | %llu | %llu | %llu | %.2f%% | [%s]\n", ipbuf,
                                           (unsigned long long) expected, (unsigned long long) received,
                                           (unsigned long long) lost, loss_percent, bar);
        }
    }

    ok = ok && packetreceiverWriteFormat(file, "\nsummary\n");
    ok = ok && packetreceiverWriteFormat(file, "received-total-packets: %llu\n", (unsigned long long) total_received);
    ok = ok && packetreceiverWriteFormat(file, "lost-total-packets: %llu\n", (unsigned long long) total_lost);
    ok = ok && packetreceiverWriteFormat(file, "expected-total-packets: %llu\n",
                                         (unsigned long long) state->total_expected_packets);

    if (fclose(file) != 0)
    {
        ok = false;
    }
    return ok;
}

void packetreceiverPrepareRuntime(tunnel_t *t)
{
    packetreceiver_tstate_t *state = tunnelGetState(t);
    tunnel_chain_t          *chain = tunnelGetChain(t);

    if (t->prev == NULL && t->next == NULL)
    {
        LOGF("PacketReceiver: must have a previous or next tunnel to receive packets from");
        terminateProgram(1);
    }

    if (chain == NULL || chain->workers_count == 0)
    {
        LOGF("PacketReceiver: the chain has zero workers");
        terminateProgram(1);
    }

    state->workers_count = chain->workers_count;

    if (state->source_count > (SIZE_MAX / (uint64_t) sizeof(uint64_t)))
    {
        LOGF("PacketReceiver: expected source count exceeds addressable memory");
        terminateProgram(1);
    }

    state->received_counts = memoryAllocateZero((size_t) state->source_count * sizeof(uint64_t));

    if (state->source_count > (UINT64_MAX / (uint64_t) state->expected_packets_per_ip))
    {
        LOGF("PacketReceiver: total expected packet count would overflow");
        terminateProgram(1);
    }

    state->total_expected_packets = state->source_count * (uint64_t) state->expected_packets_per_ip;
    state->report_written         = false;
    state->report_in_progress     = false;
}

void packetreceiverHandlePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    packetreceiver_tstate_t *state = tunnelGetState(t);
    bool                     match  = false;
    uint64_t                 source_index = 0;

    if (sbufGetLength(buf) >= sizeof(struct ip_hdr))
    {
        const uint8_t *raw = (const uint8_t *) sbufGetRawPtr(buf);
        if ((raw[0] >> 4U) == 4U)
        {
            const struct ip_hdr *ipheader = (const struct ip_hdr *) raw;
            match = packetreceiverResolveSourceIndex(state, ipheader->src.addr, &source_index);
        }
    }

    mutexLock(&state->state_mutex);
    if (! state->report_written)
    {
        if (match)
        {
            state->received_counts[source_index] += 1ULL;
            state->total_received_packets += 1ULL;
        }
        else
        {
            state->unexpected_packets += 1ULL;
        }
    }
    mutexUnlock(&state->state_mutex);

    lineReuseBuffer(l, buf);
}

void packetreceiverFinalizeReport(tunnel_t *t, bool terminate_after_write)
{
    packetreceiver_tstate_t *state = tunnelGetState(t);
    bool                     should_write = false;

    if (state->received_counts == NULL)
    {
        return;
    }

    mutexLock(&state->state_mutex);
    if (! state->report_written)
    {
        state->report_written      = true;
        state->report_in_progress = true;
        should_write               = true;
    }
    mutexUnlock(&state->state_mutex);

    if (! should_write)
    {
        return;
    }

    const bool write_ok = packetreceiverWriteReport(t);

    mutexLock(&state->state_mutex);
    state->report_in_progress = false;
    mutexUnlock(&state->state_mutex);

    if (! write_ok)
    {
        LOGF("PacketReceiver: failed to write report to \"%s\"", state->output_file);
        terminateProgram(1);
        return;
    }

    LOGI("PacketReceiver: wrote packet analysis report to \"%s\"", state->output_file);

    if (terminate_after_write)
    {
        terminateProgram(0);
    }
}

void packetreceiverReportTimerTask(void *worker, void *arg1, void *arg2, void *arg3)
{
    discard worker;
    discard arg2;
    discard arg3;

    packetreceiverFinalizeReport((tunnel_t *) arg1, true);
}
