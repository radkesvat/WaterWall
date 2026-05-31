#include "structure.h"

#include "loggers/network_logger.h"

void speedtestclientLinestateInitialize(speedtestclient_lstate_t *ls, tunnel_t *t, line_t *l, uint32_t stream_id)
{
    speedtestclient_tstate_t *state = tunnelGetState(t);
    const uint64_t now_ms = speedtestclientNowMs();

    *ls = (speedtestclient_lstate_t) {
        .recv_stream              = bufferstreamCreate(lineGetBufferPool(l), 0),
        .tunnel                   = t,
        .line                     = l,
        .stream_id                = stream_id,
        .expected_reports         = (state->upload ? 1U : 0U) + (state->download ? 1U : 0U),
        .received_reports         = 0,
        .start_ms                 = now_ms,
        .measure_start_ms         = now_ms + state->warmup_ms,
        .measure_end_ms           = now_ms + state->warmup_ms + state->duration_ms,
        .last_report_ms           = now_ms + state->warmup_ms,
        .sender_last_report_bytes = 0,
        .receiver_last_report_bytes = 0,
        .next_send_sequence       = 0,
        .next_warmup_sequence     = 0,
        .expected_recv_sequence   = 0,
        .last_transit_us          = 0,
        .paced_bytes              = 0,
        .sender                   = {0},
        .receiver                 = {0},
        .remote_sender            = {0},
        .remote_receiver          = {0},
        .est_received             = false,
        .hello_sent               = false,
        .ack_received             = false,
        .send_paused              = false,
        .send_scheduled           = false,
        .report_scheduled         = false,
        .sender_finished          = ! state->upload,
        .receiver_finished        = ! state->download,
        .remote_sender_report_received = false,
        .remote_receiver_report_received = false,
        .line_complete            = false,
        .failed                   = false,
    };
}

void speedtestclientLinestateDestroy(speedtestclient_lstate_t *ls)
{
    if (ls->recv_stream.pool != NULL)
    {
        bufferstreamDestroy(&ls->recv_stream);
    }

    memoryZeroAligned32(ls, sizeof(*ls));
}
