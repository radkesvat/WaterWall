#pragma once

#include "wwapi.h"

typedef enum streamtopackets_packet_validation_level_e
{
    kStreamToPacketsPacketValidationNone = 0,
    kStreamToPacketsPacketValidationLoose,
    kStreamToPacketsPacketValidationHard
} streamtopackets_packet_validation_level_t;

typedef struct streamtopackets_tstate_s
{
    streamtopackets_packet_validation_level_t packet_validation_level;
    bool                                      sensitive_mode;
} streamtopackets_tstate_t;

typedef struct streamtopackets_lstate_s
{
    line_t         *line;        // On packet lines: last stream line used for downstream writes
    buffer_stream_t read_stream; // On stream lines: per-line framed-packet parser state
    bool            paused;      // On packet lines: whether writes to the last stream line are paused

} streamtopackets_lstate_t;

enum
{
    kTunnelStateSize      = sizeof(streamtopackets_tstate_t),
    kLineStateSize        = sizeof(streamtopackets_lstate_t),
    kMaxBufferSize        = 65536 * 2, // Maximum buffer size for reading data packets
    kSensitivePayloadSize = 5,
    kHeartbeatPacketSize  = IP_HLEN + kSensitivePayloadSize, // synthetic IPv4 heartbeat packet length
    kHeartbeatProtocol    = 0xFD, // RFC 3692 experimentation protocol used to tag heartbeat packets
    kResyncScanWindow     = 256,  // bytes inspected while re-synchronizing after garbage
    kSensitivePingByte    = 0xFF,
    kSensitivePongByte    = 0xDD
};

WW_EXPORT void         streamtopacketsTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *streamtopacketsTunnelCreate(node_t *node);
WW_EXPORT api_result_t streamtopacketsTunnelApi(tunnel_t *instance, sbuf_t *message);

void streamtopacketsTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void streamtopacketsTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void streamtopacketsTunnelOnPrepair(tunnel_t *t);
void streamtopacketsTunnelOnStart(tunnel_t *t);
void streamtopacketsTunnelOnStop(tunnel_t *t);

void streamtopacketsTunnelUpStreamInit(tunnel_t *t, line_t *l);
void streamtopacketsTunnelUpStreamEst(tunnel_t *t, line_t *l);
void streamtopacketsTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void streamtopacketsTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void streamtopacketsTunnelUpStreamPause(tunnel_t *t, line_t *l);
void streamtopacketsTunnelUpStreamResume(tunnel_t *t, line_t *l);

void streamtopacketsTunnelDownStreamInit(tunnel_t *t, line_t *l);
void streamtopacketsTunnelDownStreamEst(tunnel_t *t, line_t *l);
void streamtopacketsTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void streamtopacketsTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void streamtopacketsTunnelDownStreamPause(tunnel_t *t, line_t *l);
void streamtopacketsTunnelDownStreamResume(tunnel_t *t, line_t *l);

void streamtopacketsLinestateInitialize(streamtopackets_lstate_t *ls, buffer_pool_t *pool);
void streamtopacketsLinestateDestroy(streamtopackets_lstate_t *ls);
void streamtopacketsLinestateReset(streamtopackets_lstate_t *ls);

bool streamtopacketsReadStreamIsOverflowed(buffer_stream_t *read_stream);
bool streamtopacketsTryReadIPv4Packet(buffer_stream_t *stream, sbuf_t **packet_out);
bool streamtopacketsIsForwardableIpv4Packet(const sbuf_t *packet);
bool streamtopacketsFrameMatchesFillByte(const sbuf_t *packet, uint8_t fill_byte);
bool streamtopacketsValidatePacket(streamtopackets_packet_validation_level_t level, sbuf_t *packet,
                                   const char *direction);
void streamtopacketsRecalculateChecksumIfRequested(line_t *l, sbuf_t *buf);
bool streamtopacketsSendSensitivePong(tunnel_t *t, line_t *stream_line);
