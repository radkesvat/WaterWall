#pragma once

#include "wwapi.h"

enum
{
    kSpeedTestClientProtocolVersion = 1,
    kSpeedTestClientFrameHeaderSize = 48,
    kSpeedTestClientHelloSize       = 32,
    kSpeedTestClientReportSize      = 72,
    kSpeedTestClientMagic           = 0x53505431U, /* SPT1 */
    kSpeedTestClientDefaultDurationMs = 10000,
    kSpeedTestClientDefaultIntervalMs = 1000,
    kSpeedTestClientDefaultStartDelayMs = 50,
    kSpeedTestClientDefaultTcpPayloadSize = 128U * 1024U,
    kSpeedTestClientDefaultUdpPayloadSize = 1200U,
    kSpeedTestClientDefaultUdpBandwidthBps = 10U * 1000U * 1000U,
    kSpeedTestClientMaxPayloadSize = 16U * 1024U * 1024U,
    kSpeedTestClientMaxUdpPayloadSize = 65000U - kSpeedTestClientFrameHeaderSize,
    kSpeedTestClientMaxBurstFrames = 32,
    kSpeedTestClientUdpFinalRepeats = 3
};

typedef enum speedtestclient_frame_type_e
{
    kSpeedTestClientFrameHello = 1,
    kSpeedTestClientFrameAck,
    kSpeedTestClientFrameData,
    kSpeedTestClientFrameEnd,
    kSpeedTestClientFrameReport,
    kSpeedTestClientFrameError
} speedtestclient_frame_type_e;

typedef enum speedtestclient_mode_e
{
    kSpeedTestClientModeTcp = 1,
    kSpeedTestClientModeUdp
} speedtestclient_mode_e;

enum speedtestclient_frame_flags_e
{
    kSpeedTestClientFlagUpload   = 1U << 0U,
    kSpeedTestClientFlagDownload = 1U << 1U,
    kSpeedTestClientFlagTcp      = 1U << 2U,
    kSpeedTestClientFlagUdp      = 1U << 3U,
    kSpeedTestClientFlagWarmup   = 1U << 4U,
    kSpeedTestClientFlagSender   = 1U << 5U,
    kSpeedTestClientFlagReceiver = 1U << 6U,
    kSpeedTestClientFlagJson     = 1U << 7U
};

typedef struct speedtestclient_stats_s
{
    uint64_t bytes;
    uint64_t packets;
    uint64_t valid_packets;
    uint64_t lost_packets;
    uint64_t duplicate_packets;
    uint64_t out_of_order_packets;
    uint64_t validation_errors;
    double   jitter_us;
} speedtestclient_stats_t;

typedef struct speedtestclient_frame_s
{
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint32_t stream_id;
    uint32_t payload_len;
    uint64_t sequence;
    uint64_t timestamp_us;
    uint64_t aux1;
    uint64_t aux2;
    const uint8_t *payload;
} speedtestclient_frame_t;

typedef struct speedtestclient_tstate_s
{
    uint32_t duration_ms;
    uint32_t warmup_ms;
    uint32_t report_interval_ms;
    uint32_t start_delay_ms;
    uint32_t timeout_ms;
    uint32_t payload_size;
    uint32_t connection_count;
    uint64_t target_bandwidth_bps;
    uint8_t  mode;
    bool     upload;
    bool     download;
    bool     json_summary;
    bool     terminate_on_complete;

    atomic_uint completed_streams;
    atomic_uint failed_streams;
    wmutex_t    aggregate_mutex;
    speedtestclient_stats_t aggregate_sender;
    speedtestclient_stats_t aggregate_receiver;
    speedtestclient_stats_t aggregate_remote_sender;
    speedtestclient_stats_t aggregate_remote_receiver;
} speedtestclient_tstate_t;

typedef struct speedtestclient_lstate_s
{
    buffer_stream_t recv_stream;
    tunnel_t       *tunnel;
    line_t         *line;
    uint32_t        stream_id;
    uint32_t        expected_reports;
    uint32_t        received_reports;
    uint64_t        start_ms;
    uint64_t        measure_start_ms;
    uint64_t        measure_end_ms;
    uint64_t        last_report_ms;
    uint64_t        sender_last_report_bytes;
    uint64_t        receiver_last_report_bytes;
    uint64_t        next_send_sequence;
    uint64_t        next_warmup_sequence;
    uint64_t        expected_recv_sequence;
    uint64_t        last_transit_us;
    uint64_t        paced_bytes;
    speedtestclient_stats_t sender;
    speedtestclient_stats_t receiver;
    speedtestclient_stats_t remote_sender;
    speedtestclient_stats_t remote_receiver;
    bool            est_received;
    bool            hello_sent;
    bool            ack_received;
    bool            send_paused;
    bool            send_scheduled;
    bool            report_scheduled;
    bool            sender_finished;
    bool            receiver_finished;
    bool            remote_sender_report_received;
    bool            remote_receiver_report_received;
    bool            line_complete;
    bool            failed;
} speedtestclient_lstate_t;

WW_EXPORT void         speedtestclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *speedtestclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t speedtestclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void speedtestclientTunnelOnPrepair(tunnel_t *t);
void speedtestclientTunnelOnStart(tunnel_t *t);

void speedtestclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void speedtestclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void speedtestclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void speedtestclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void speedtestclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void speedtestclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void speedtestclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void speedtestclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void speedtestclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void speedtestclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void speedtestclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void speedtestclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void speedtestclientLinestateInitialize(speedtestclient_lstate_t *ls, tunnel_t *t, line_t *l, uint32_t stream_id);
void speedtestclientLinestateDestroy(speedtestclient_lstate_t *ls);

uint64_t speedtestclientNowMs(void);
uint64_t speedtestclientNowUs(void);
uint16_t speedtestclientBaseFlags(const speedtestclient_tstate_t *state);
void speedtestclientFormatBytes(uint64_t bytes, char *out, size_t out_len);
void speedtestclientFormatBitrate(double bits_per_sec, char *out, size_t out_len);
void speedtestclientWriteHeader(uint8_t *ptr, uint8_t type, uint16_t flags, uint32_t stream_id, uint32_t payload_len,
                                uint64_t sequence, uint64_t timestamp_us, uint64_t aux1, uint64_t aux2);
bool speedtestclientReadHeader(const uint8_t *ptr, size_t len, speedtestclient_frame_t *frame);
sbuf_t *speedtestclientCreateFrame(tunnel_t *t, line_t *l, uint8_t type, uint16_t flags, uint32_t stream_id,
                                   uint64_t sequence, uint32_t payload_len, uint64_t timestamp_us, uint64_t aux1,
                                   uint64_t aux2);
void speedtestclientFillPattern(uint8_t *ptr, uint32_t len, uint32_t stream_id, uint64_t sequence, uint16_t flags);
bool speedtestclientVerifyPattern(const uint8_t *ptr, uint32_t len, uint32_t stream_id, uint64_t sequence,
                                  uint16_t flags);
void speedtestclientSendTask(tunnel_t *t, line_t *l);
void speedtestclientReportTask(tunnel_t *t, line_t *l);
void speedtestclientWatchdogTask(tunnel_t *t, line_t *l);
void speedtestclientScheduleSend(tunnel_t *t, line_t *l, speedtestclient_lstate_t *ls);
void speedtestclientScheduleReport(tunnel_t *t, line_t *l, speedtestclient_lstate_t *ls);
void speedtestclientProcessIncoming(tunnel_t *t, line_t *l, sbuf_t *buf);
void speedtestclientMaybeComplete(tunnel_t *t, line_t *l);
void speedtestclientFailLine(tunnel_t *t, line_t *l, const char *reason);
void speedtestclientFinishFromDownstreamFinish(tunnel_t *t, line_t *l, bool success, const char *reason);
