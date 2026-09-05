#pragma once

#include "wwapi.h"

typedef enum streamtopackets_packet_validation_level_e
{
    kStreamToPacketsPacketValidationNone = 0,
    kStreamToPacketsPacketValidationLoose,
    kStreamToPacketsPacketValidationHard
} streamtopackets_packet_validation_level_t;

/*
 * The identity of the one remote peer allowed to contribute active stream lines.
 *
 * Only the concrete source IP is compared. The source port is not part of the
 * identity: TcpListener stores the local listener port there, and reconnects
 * from the same peer use fresh ephemeral ports. Lines without a concrete source
 * IP - a directly composed in-process PacketsToStream -> StreamToPackets pair,
 * for example - share one explicit anonymous identity.
 */
typedef struct streamtopackets_source_key_s
{
    bool      identified;
    ip_addr_t ip;
} streamtopackets_source_key_t;

typedef enum streamtopackets_line_status_e
{
    // Tracked but not selectable: it has not produced a valid IPv4 packet or a
    // valid sensitive-mode heartbeat yet.
    kStreamToPacketsLineCandidate = 0,
    // Validated and owned by the current source generation.
    kStreamToPacketsLineActive
} streamtopackets_line_status_t;

/*
 * One registry node per tracked stream line, owned by tunnel state rather than by
 * the line, so a takeover running on another worker never mutates a foreign
 * line's state. Nodes are only ever read or written under the registry lock.
 */
typedef struct streamtopackets_line_entry_s
{
    struct streamtopackets_line_entry_s *prev;
    struct streamtopackets_line_entry_s *next;
    line_t                              *line;
    streamtopackets_source_key_t         source;
    uint64_t                             line_id;
    uint64_t                             source_generation;
    wid_t                                wid;
    streamtopackets_line_status_t        status;
    bool                                 paused;
} streamtopackets_line_entry_t;

typedef struct streamtopackets_tstate_s
{
    streamtopackets_packet_validation_level_t packet_validation_level;
    bool                                      sensitive_mode;

    // Registry of tracked stream lines and the single active source owner.
    wrwlock_t                     lines_lock;
    streamtopackets_line_entry_t *lines_head;        /* protected by lines_lock */
    streamtopackets_source_key_t  active_source;     /* protected by lines_lock */
    bool                          active_source_set; /* protected by lines_lock */
    bool                          stopping;          /* protected by lines_lock */
    uint64_t                      active_generation; /* protected by lines_lock; zero means none */
    uint64_t                      next_line_id;      /* protected by lines_lock */
    uint64_t                      next_generation;   /* protected by lines_lock */

    /*
     * Release-published mirror of active_generation, acquire-loaded by queued
     * cross-worker work. Publishing it is the linearization point of a takeover:
     * an operation that already entered its final callback may finish, but no
     * queued old-epoch work can enter afterwards.
     */
    atomic_ullong published_generation;
} streamtopackets_tstate_t;

typedef struct streamtopackets_lstate_s
{
    buffer_stream_t read_stream;       // On stream lines: per-line framed-packet parser state
    uint64_t        line_id;           // Registry identity of this line, unique per tunnel instance
    uint64_t        source_generation; // Source epoch this line was activated in; zero while a candidate
    bool            tracked;           // Whether a registry entry was published for this line
    bool            active;            // Whether this line may carry return packets
    bool            write_paused;      // Owner-worker view of backpressure toward the previous side

} streamtopackets_lstate_t;

/*
 * One rendezvous-selected return line, captured under the registry read lock.
 * The line carries a temporary reference the caller must release exactly once.
 */
typedef struct streamtopackets_selected_line_s
{
    line_t  *line;
    uint64_t line_id;
    uint64_t generation;
    wid_t    wid;
} streamtopackets_selected_line_t;

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

WW_EXPORT void         streamtopacketsTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *streamtopacketsTunnelCreate(node_t *node);
WW_EXPORT api_result_t streamtopacketsTunnelApi(tunnel_t *instance, sbuf_t *message);

void streamtopacketsTunnelOnStart(tunnel_t *t);
void streamtopacketsQueueWorkerPacketInit(void *worker, void *arg1, void *arg2, void *arg3);
void streamtopacketsTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);

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
void streamtopacketsForwardDecodedPacket(tunnel_t *t, line_t *stream_line, sbuf_t *packet, uint64_t generation);

// ---------------------------------------------------------------------------
// Active-source ownership (common/ownership.c)
// ---------------------------------------------------------------------------

bool     streamtopacketsOwnershipInitialize(streamtopackets_tstate_t *ts);
void     streamtopacketsOwnershipDestroy(tunnel_t *t);
void     streamtopacketsOwnershipStop(tunnel_t *t);
uint64_t streamtopacketsPublishedGeneration(streamtopackets_tstate_t *ts);

bool     streamtopacketsRegisterCandidateLine(tunnel_t *t, line_t *l);
uint64_t streamtopacketsAuthorizeLine(tunnel_t *t, line_t *l);
void     streamtopacketsUnregisterLine(tunnel_t *t, line_t *l);
void     streamtopacketsSetLinePaused(tunnel_t *t, line_t *l, bool paused);
bool     streamtopacketsSelectReturnLine(tunnel_t *t, uint64_t flow_hash, streamtopackets_selected_line_t *out);
uint64_t streamtopacketsRendezvousScore(uint64_t flow_hash, uint64_t line_id);
void streamtopacketsDeliverSelectedWrite(tunnel_t *t, line_t *l, uint64_t line_id, uint64_t generation, sbuf_t *buf);
void streamtopacketsQueueSelectedWrite(tunnel_t *t, streamtopackets_selected_line_t *selected, sbuf_t *buf);
