#pragma once

#include "wwapi.h"

enum
{
    kSpeedTestServerProtocolVersion = 1,
    kSpeedTestServerFrameHeaderSize = 48,
    kSpeedTestServerHelloSize       = 32,
    kSpeedTestServerReportSize      = 72,
    kSpeedTestServerMagic           = 0x53505431U,
    kSpeedTestServerDefaultIntervalMs = 1000,
    kSpeedTestServerMaxPayloadSize = 16U * 1024U * 1024U,
    kSpeedTestServerMaxUdpPayloadSize = 65000U - kSpeedTestServerFrameHeaderSize,
    kSpeedTestServerMaxBurstFrames = 32,
    kSpeedTestServerUdpFinalRepeats = 3
};

typedef enum speedtestserver_frame_type_e
{
    kSpeedTestServerFrameHello = 1,
    kSpeedTestServerFrameAck,
    kSpeedTestServerFrameData,
    kSpeedTestServerFrameEnd,
    kSpeedTestServerFrameReport,
    kSpeedTestServerFrameError
} speedtestserver_frame_type_e;

typedef enum speedtestserver_mode_e
{
    kSpeedTestServerModeTcp = 1,
    kSpeedTestServerModeUdp
} speedtestserver_mode_e;

enum speedtestserver_frame_flags_e
{
    kSpeedTestServerFlagUpload   = 1U << 0U,
    kSpeedTestServerFlagDownload = 1U << 1U,
    kSpeedTestServerFlagTcp      = 1U << 2U,
    kSpeedTestServerFlagUdp      = 1U << 3U,
    kSpeedTestServerFlagWarmup   = 1U << 4U,
    kSpeedTestServerFlagSender   = 1U << 5U,
    kSpeedTestServerFlagReceiver = 1U << 6U,
    kSpeedTestServerFlagJson     = 1U << 7U
};

typedef struct speedtestserver_stats_s
{
    uint64_t bytes;
    uint64_t packets;
    uint64_t valid_packets;
    uint64_t lost_packets;
    uint64_t duplicate_packets;
    uint64_t out_of_order_packets;
    uint64_t validation_errors;
    double   jitter_us;
} speedtestserver_stats_t;

typedef struct speedtestserver_frame_s
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
} speedtestserver_frame_t;

typedef struct speedtestserver_tstate_s
{
    uint32_t report_interval_ms;
    bool     json_summary;
    wmutex_t aggregate_mutex;
    speedtestserver_stats_t aggregate_sender;
    speedtestserver_stats_t aggregate_receiver;
    atomic_uint completed_streams;
} speedtestserver_tstate_t;

typedef struct speedtestserver_lstate_s
{
    buffer_stream_t recv_stream;
    tunnel_t       *tunnel;
    line_t         *line;
    uint32_t        stream_id;
    uint32_t        duration_ms;
    uint32_t        warmup_ms;
    uint32_t        report_interval_ms;
    uint32_t        payload_size;
    uint32_t        total_streams;
    uint64_t        target_bandwidth_bps;
    uint8_t         mode;
    bool            upload;
    bool            download;
    bool            json_summary;
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
    speedtestserver_stats_t sender;
    speedtestserver_stats_t receiver;
    bool            hello_received;
    bool            send_paused;
    bool            send_scheduled;
    bool            report_scheduled;
    bool            sender_finished;
    bool            receiver_finished;
    bool            upload_report_sent;
    bool            download_report_sent;
    bool            closing;
} speedtestserver_lstate_t;

WW_EXPORT void         speedtestserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *speedtestserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t speedtestserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void speedtestserverTunnelOnPrepair(tunnel_t *t);
void speedtestserverTunnelOnStart(tunnel_t *t);

void speedtestserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void speedtestserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void speedtestserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void speedtestserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void speedtestserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void speedtestserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void speedtestserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void speedtestserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void speedtestserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void speedtestserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void speedtestserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void speedtestserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void speedtestserverLinestateInitialize(speedtestserver_lstate_t *ls, tunnel_t *t, line_t *l);
void speedtestserverLinestateDestroy(speedtestserver_lstate_t *ls);

uint64_t speedtestserverNowMs(void);
uint64_t speedtestserverNowUs(void);
uint16_t speedtestserverBaseFlags(const speedtestserver_lstate_t *ls);
void speedtestserverFormatBytes(uint64_t bytes, char *out, size_t out_len);
void speedtestserverFormatBitrate(double bits_per_sec, char *out, size_t out_len);
void speedtestserverWriteHeader(uint8_t *ptr, uint8_t type, uint16_t flags, uint32_t stream_id, uint32_t payload_len,
                                uint64_t sequence, uint64_t timestamp_us, uint64_t aux1, uint64_t aux2);
bool speedtestserverReadHeader(const uint8_t *ptr, size_t len, speedtestserver_frame_t *frame);
sbuf_t *speedtestserverCreateFrame(tunnel_t *t, line_t *l, uint8_t type, uint16_t flags, uint32_t stream_id,
                                   uint64_t sequence, uint32_t payload_len, uint64_t timestamp_us, uint64_t aux1,
                                   uint64_t aux2);
void speedtestserverFillPattern(uint8_t *ptr, uint32_t len, uint32_t stream_id, uint64_t sequence, uint16_t flags);
bool speedtestserverVerifyPattern(const uint8_t *ptr, uint32_t len, uint32_t stream_id, uint64_t sequence,
                                  uint16_t flags);
void speedtestserverSendTask(tunnel_t *t, line_t *l);
void speedtestserverReportTask(tunnel_t *t, line_t *l);
void speedtestserverScheduleSend(tunnel_t *t, line_t *l, speedtestserver_lstate_t *ls);
void speedtestserverScheduleReport(tunnel_t *t, line_t *l, speedtestserver_lstate_t *ls);
void speedtestserverProcessIncoming(tunnel_t *t, line_t *l, sbuf_t *buf);
void speedtestserverMaybeComplete(tunnel_t *t, line_t *l);
void speedtestserverFailLine(tunnel_t *t, line_t *l, const char *reason);

