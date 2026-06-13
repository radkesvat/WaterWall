#pragma once

#include "wwapi.h"

typedef enum packetstostream_packet_validation_level_e
{
    kPacketsToStreamPacketValidationNone = 0,
    kPacketsToStreamPacketValidationLoose,
    kPacketsToStreamPacketValidationHard
} packetstostream_packet_validation_level_t;

typedef struct packetstostream_tstate_s
{
    wtimer_t                                **worker_timers;
    wtimer_t                                **worker_timeout_timers;
    uint32_t                                  interval_ms;
    uint32_t                                  tolerance_ms;
    packetstostream_packet_validation_level_t packet_validation_level;
    bool                                      sensitive_mode;
} packetstostream_tstate_t;

typedef struct packetstostream_lstate_s
{
    line_t         *line;             // Pointer to the line associated with this state
    buffer_stream_t read_stream;      // Stream for reading data packets
    uint64_t        ping_sent_at_ms;  // On packet lines: timestamp of the last ping in flight
    uint64_t        pong_deadline_ms; // On packet lines: current pong deadline
    bool            paused;           // Indicates if the line is paused, dropping packets
    bool            awaiting_pong;    // On packet lines: whether a ping is in flight
    bool            recreate_scheduled;

} packetstostream_lstate_t;

enum
{
    kTunnelStateSize             = sizeof(packetstostream_tstate_t),
    kLineStateSize               = sizeof(packetstostream_lstate_t),
    kMaxBufferSize               = 65536 * 2, // Maximum buffer size for reading data packets
    kHeaderSize                  = 2,         // add 2 bytes to packet to store real size
    kSensitivePayloadSize        = 5,
    kSensitivePingByte           = 0xFF,
    kSensitivePongByte           = 0xDD,
    kSensitiveDefaultIntervalMs  = 50,
    kSensitiveDefaultToleranceMs = 150
};

WW_EXPORT void         packetstostreamTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *packetstostreamTunnelCreate(node_t *node);
WW_EXPORT api_result_t packetstostreamTunnelApi(tunnel_t *instance, sbuf_t *message);

void packetstostreamTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void packetstostreamTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void packetstostreamTunnelOnPrepair(tunnel_t *t);
void packetstostreamTunnelOnStart(tunnel_t *t);
void packetstostreamTunnelOnStop(tunnel_t *t);
void packetstostreamTunnelOnWorkerStop(tunnel_t *t, wid_t wid);

void packetstostreamTunnelUpStreamInit(tunnel_t *t, line_t *l);
void packetstostreamTunnelUpStreamEst(tunnel_t *t, line_t *l);
void packetstostreamTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void packetstostreamTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetstostreamTunnelUpStreamPause(tunnel_t *t, line_t *l);
void packetstostreamTunnelUpStreamResume(tunnel_t *t, line_t *l);

void packetstostreamTunnelDownStreamInit(tunnel_t *t, line_t *l);
void packetstostreamTunnelDownStreamEst(tunnel_t *t, line_t *l);
void packetstostreamTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void packetstostreamTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetstostreamTunnelDownStreamPause(tunnel_t *t, line_t *l);
void packetstostreamTunnelDownStreamResume(tunnel_t *t, line_t *l);

void packetstostreamLinestateInitialize(packetstostream_lstate_t *ls, buffer_pool_t *pool);
void packetstostreamLinestateDestroy(packetstostream_lstate_t *ls);

bool packetstostreamReadStreamIsOverflowed(buffer_stream_t *read_stream);
bool packetstostreamTryReadIPv4Packet(buffer_stream_t *stream, sbuf_t **packet_out);
bool packetstostreamFrameMatchesFillByte(const sbuf_t *packet, uint8_t fill_byte);
bool packetstostreamValidatePacket(packetstostream_packet_validation_level_t level, sbuf_t *packet,
                                   const char *direction);
void packetstostreamRecalculateChecksumIfRequested(line_t *l, sbuf_t *buf);
void packetstostreamRecreateOutputLineTask(tunnel_t *t, line_t *packet_line);
void packetstostreamHeartbeatTimerCallback(wtimer_t *timer);
void packetstostreamTimeoutTimerCallback(wtimer_t *timer);
void packetstostreamScheduleRecreateOutputLine(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls);
void packetstostreamResetOutputLineState(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls);
void packetstostreamCloseOutputLineAndScheduleRecreate(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls);
line_t *packetstostreamEnsureOutputLine(tunnel_t *t, line_t *packet_line, packetstostream_lstate_t *ls);
