#include "structure.h"

#include "loggers/network_logger.h"

void speedtestserverLinestateInitialize(speedtestserver_lstate_t *ls, tunnel_t *t, line_t *l)
{
    speedtestserver_tstate_t *state = tunnelGetState(t);

    *ls = (speedtestserver_lstate_t) {
        .recv_stream              = bufferstreamCreate(lineGetBufferPool(l), 0),
        .tunnel                   = t,
        .line                     = l,
        .stream_id                = 0,
        .duration_ms              = 0,
        .warmup_ms                = 0,
        .report_interval_ms       = state->report_interval_ms,
        .payload_size             = 0,
        .total_streams            = 0,
        .target_bandwidth_bps     = 0,
        .mode                     = kSpeedTestServerModeTcp,
        .upload                   = false,
        .download                 = false,
        .json_summary             = state->json_summary,
        .start_ms                 = 0,
        .measure_start_ms         = 0,
        .measure_end_ms           = 0,
        .last_report_ms           = 0,
        .sender_last_report_bytes = 0,
        .receiver_last_report_bytes = 0,
        .next_send_sequence       = 0,
        .next_warmup_sequence     = 0,
        .expected_recv_sequence   = 0,
        .last_transit_us          = 0,
        .paced_bytes              = 0,
        .sender                   = {0},
        .receiver                 = {0},
        .hello_received           = false,
        .send_paused              = false,
        .send_scheduled           = false,
        .report_scheduled         = false,
        .sender_finished          = true,
        .receiver_finished        = true,
        .upload_report_sent       = false,
        .download_report_sent     = false,
        .closing                  = false,
    };
}

void speedtestserverLinestateDestroy(speedtestserver_lstate_t *ls)
{
    if (ls->recv_stream.pool != NULL)
    {
        bufferstreamDestroy(&ls->recv_stream);
    }

    memoryZeroAligned32(ls, sizeof(*ls));
}

