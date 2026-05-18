#include "structure.h"

#include "loggers/network_logger.h"

#include <stdarg.h>
#include <stdio.h>

static void packetreceiverFormatIpv4(char *dest, size_t size, uint32_t host_addr)
{
    stringNPrintf(dest, size, "%u.%u.%u.%u", (host_addr >> 24U) & 0xFFU, (host_addr >> 16U) & 0xFFU,
                  (host_addr >> 8U) & 0xFFU, host_addr & 0xFFU);
}

static void packetreceiverAppendBytes(sbuf_t **report, const char *data, size_t len)
{
    if (len == 0)
    {
        return;
    }

    if (*report == NULL)
    {
        *report = sbufCreateWithPadding((uint32_t) len, 0);
    }

    const size_t old_len = (size_t) sbufGetLength(*report);
    *report = sbufReserveSpace(*report, (uint32_t) (old_len + len));
    sbufSetLength(*report, (uint32_t) (old_len + len));
    memoryCopy(sbufGetMutablePtr(*report) + old_len, data, len);
}

static void packetreceiverAppendText(sbuf_t **report, const char *text)
{
    packetreceiverAppendBytes(report, text, stringLength(text));
}

static void packetreceiverAppendFormat(sbuf_t **report, const char *fmt, ...)
{
    char    stack_buf[1024];
    va_list args;

    va_start(args, fmt);
    int written = vsnprintf(stack_buf, sizeof(stack_buf), fmt, args);
    va_end(args);

    if (written < 0)
    {
        return;
    }

    if ((size_t) written >= sizeof(stack_buf))
    {
        char *heap_buf = memoryAllocate((size_t) written + 1U);
        va_start(args, fmt);
        vsnprintf(heap_buf, (size_t) written + 1U, fmt, args);
        va_end(args);
        packetreceiverAppendBytes(report, heap_buf, (size_t) written);
        memoryFree(heap_buf);
        return;
    }

    packetreceiverAppendBytes(report, stack_buf, (size_t) written);
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
    sbuf_t                  *report = sbufCreateWithPadding(4096, 0);

    if (report == NULL)
    {
        return false;
    }

    uint64_t total_received = 0;
    uint64_t total_lost     = 0;

    packetreceiverAppendText(&report, "PacketReceiver report\n");
    packetreceiverAppendFormat(&report, "output-file: %s\n", state->output_file);
    packetreceiverAppendFormat(&report, "source-ip-count: %llu\n", (unsigned long long) state->source_count);
    packetreceiverAppendFormat(&report, "expected-packets-per-ip: %u\n",
                               (unsigned int) state->expected_packets_per_ip);
    packetreceiverAppendFormat(&report, "expected-total-packets: %llu\n",
                               (unsigned long long) state->total_expected_packets);
    packetreceiverAppendFormat(&report, "received-total-packets: %llu\n",
                               (unsigned long long) state->total_received_packets);
    packetreceiverAppendFormat(&report, "lost-total-packets: %llu\n", (unsigned long long) state->total_lost_packets);
    packetreceiverAppendFormat(&report, "unexpected-packets: %llu\n", (unsigned long long) state->unexpected_packets);
    packetreceiverAppendText(&report, "\nsource-ip | sent | received | lost | loss-percent | histogram\n");

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
            const double   loss_percent = (expected > 0) ? ((double) lost * 100.0 / (double) expected) : 0.0;
            char           ipbuf[32];
            char           bar[kPacketReceiverHistogramWidth + 1U];

            packetreceiverFormatIpv4(ipbuf, sizeof(ipbuf), range->base_host + (uint32_t) i);
            packetreceiverBuildHistogramBar(bar, sizeof(bar), expected, received);

            packetreceiverAppendFormat(&report, "%s | %llu | %llu | %llu | %.2f%% | [%s]\n", ipbuf,
                                       (unsigned long long) expected, (unsigned long long) received,
                                       (unsigned long long) lost, loss_percent, bar);

            total_received += received;
            total_lost += lost;
        }
    }

    state->total_received_packets = total_received;
    state->total_lost_packets     = total_lost;

    packetreceiverAppendText(&report, "\nsummary\n");
    packetreceiverAppendFormat(&report, "sent-total-packets: %llu\n", (unsigned long long) state->total_expected_packets);
    packetreceiverAppendFormat(&report, "received-total-packets: %llu\n", (unsigned long long) total_received);
    packetreceiverAppendFormat(&report, "lost-total-packets: %llu\n", (unsigned long long) total_lost);
    packetreceiverAppendFormat(&report, "expected-total-packets: %llu\n", (unsigned long long) state->total_expected_packets);

    const bool ok = writeFile(state->output_file, (const char *) sbufGetRawPtr(report), sbufGetLength(report));
    sbufDestroy(report);
    return ok;
}

static void packetreceiverMarkWorkerFinished(packetreceiver_tstate_t *state, wid_t wid, bool *should_write_out)
{
    if (wid >= state->workers_count)
    {
        LOGF("PacketReceiver: worker id %u is out of range", (unsigned int) wid);
        terminateProgram(1);
        return;
    }

    mutexLock(&state->state_mutex);

    if (! state->worker_finished[wid])
    {
        state->worker_finished[wid] = true;
        state->completed_workers += 1U;
    }

    if (state->completed_workers >= state->workers_count && ! state->report_written)
    {
        state->report_written = true;
        *should_write_out     = true;
    }

    mutexUnlock(&state->state_mutex);
}

void packetreceiverPrepareRuntime(tunnel_t *t)
{
    packetreceiver_tstate_t *state = tunnelGetState(t);
    tunnel_chain_t          *chain = tunnelGetChain(t);

    if (t->prev == NULL)
    {
        LOGF("PacketReceiver: must have a previous tunnel to receive packets from");
        terminateProgram(1);
    }

    if (t->next != NULL)
    {
        LOGF("PacketReceiver: must be the chain end");
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
    state->worker_finished = memoryAllocateZero(sizeof(*state->worker_finished) * state->workers_count);

    if (state->source_count > (UINT64_MAX / (uint64_t) state->expected_packets_per_ip))
    {
        LOGF("PacketReceiver: total expected packet count would overflow");
        terminateProgram(1);
    }

    state->total_expected_packets = state->source_count * (uint64_t) state->expected_packets_per_ip;
    state->completed_workers = 0;
    state->report_written     = false;
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

    if (match)
    {
        mutexLock(&state->state_mutex);
        state->received_counts[source_index] += 1ULL;
        state->total_received_packets += 1ULL;
        mutexUnlock(&state->state_mutex);
    }
    else
    {
        mutexLock(&state->state_mutex);
        state->unexpected_packets += 1ULL;
        mutexUnlock(&state->state_mutex);
    }

    lineReuseBuffer(l, buf);
}

void packetreceiverHandleWorkerFinish(tunnel_t *t, line_t *l)
{
    packetreceiver_tstate_t *state = tunnelGetState(t);
    bool                     should_write = false;

    packetreceiverMarkWorkerFinished(state, lineGetWID(l), &should_write);

    if (should_write)
    {
        if (! packetreceiverWriteReport(t))
        {
            LOGF("PacketReceiver: failed to write report to \"%s\"", state->output_file);
            terminateProgram(1);
            return;
        }

        LOGI("PacketReceiver: wrote packet analysis report to \"%s\"", state->output_file);
        terminateProgram(0);
    }
}

void packetreceiverFinalizeReport(tunnel_t *t, bool terminate_after_write)
{
    packetreceiver_tstate_t *state = tunnelGetState(t);
    bool                     should_write = false;

    if (state->received_counts == NULL || state->worker_finished == NULL)
    {
        return;
    }

    mutexLock(&state->state_mutex);
    if (! state->report_written)
    {
        state->report_written = true;
        should_write          = true;
    }
    mutexUnlock(&state->state_mutex);

    if (! should_write)
    {
        return;
    }

    if (! packetreceiverWriteReport(t))
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
