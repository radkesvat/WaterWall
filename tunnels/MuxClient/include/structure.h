#pragma once

#include "wwapi.h"

/*
    This part is shared with the MuxServer
*/
// if you change this structure, you must also change the kMuxFrameLength value
// in the enum below, this is used for left padding in node.c
typedef uint16_t mux_length_t;
typedef uint32_t cid_t;
#define CID_MAX 0xFFFFFFFFU

typedef struct muxclient_tstate_s
{
    uint8_t  concurrency_mode; // timer, counter, fixed-connections-count
    uint32_t concurrency_duration;
    uint32_t concurrency_capacity;
    uint32_t fixed_connections_count;
    uint32_t child_buffer_limit;
    uint32_t child_buffer_pause_tolerance;

    line_t  **fixed_parent_lines;
    uint32_t *fixed_next_parent_indexes;

    line_t *unsatisfied_lines[]; // lines (per worker) that still want child connections
} muxclient_tstate_t;

typedef struct muxclient_lstate_s
{
    line_t *l; // the line this state is associated with
    line_t *last_writer; // used when parent, to track the last writer line

    struct muxclient_lstate_s *parent;         // the parent  f is_child is true
    struct muxclient_lstate_s *child_prev;     // previous child in the parent connection
    struct muxclient_lstate_s *child_next;     // next child in the parent connection
    buffer_stream_t            read_stream;    // stream for reading data from the parent connection
    buffer_queue_t             pending_child_data; // child-destined data queued while the child write side is paused
    uint64_t                   creation_epoch; // epoch of the connection creation, used for concurrency mode timer
    cid_t                      connection_id;  // unique connection id, used for multiplexing
    uint32_t children_count; // number of children in the parent connection, used for concurrency mode counter
    bool     is_child : 1;              // if this connection is muxed into a parent connection
    bool     paused : 1;                // child: local child write side is paused
    bool     flow_paused_sent : 1;      // child: FlowPause was sent to the peer for this cid
    bool     parent_input_paused : 1;   // parent: main input was paused because a child queue hit the limit
    bool     parent_finishing : 1;      // parent: main FIN is being handled, suppress parent writes
} muxclient_lstate_t;

enum
{
    kTunnelStateSize        = sizeof(muxclient_tstate_t),
    kLineStateSize          = sizeof(muxclient_lstate_t),
    kConcurrencyModeTimer   = kDvsFirstOption,
    kConcurrencyModeCounter = kDvsSecondOption,
    kConcurrencyModeFixedConnectionsCount = kDvsThirdOption,
    kMaxMainChannelBufferSize = 1024 * 1024, // 1MB
    kMuxDefaultChildBufferLimit = 8 * 1024 * 1024,
    kMuxDefaultChildBufferPauseTolerance = 512 * 1024,
    kMuxChildBufferResumeThreshold = 512 * 1024,
    kMuxChildBufferQueueCap = 8,
};

/*
    This part is shared with the MuxServer
*/
#ifdef COMPILER_MSVC
#pragma pack(push, 1)
#define ATTR_PACKED
#else
#define ATTR_PACKED __attribute__((__packed__))

#endif

// if you change this structure, you must also change the kMuxFrameLength value
// in the enum below, this is used for left padding in node.c
// and MuxServer
typedef struct
{
    mux_length_t length;
    uint8_t      flags;
    uint8_t      _pad1; // padding for alignment
    cid_t        cid;

    char data[];

} ATTR_PACKED mux_frame_t;

#ifdef COMPILER_MSVC
#pragma pack(pop)
#endif

enum
{
    kMuxFlagOpen       = 0,
    kMuxFlagClose      = 1,
    kMuxFlagFlowPause  = 2,
    kMuxFlagFlowResume = 3,
    kMuxFlagData       = 4,
    kMuxFrameLength =
        sizeof(mux_frame_t), // This value must be 8 and this value is hard coded in node.c for left padding
};

WW_EXPORT void         muxclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *muxclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t muxclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void muxclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void muxclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void muxclientTunnelOnPrepair(tunnel_t *t);
void muxclientTunnelOnStart(tunnel_t *t);

void muxclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void muxclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void muxclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void muxclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void muxclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void muxclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void muxclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void muxclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void muxclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void muxclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void muxclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void muxclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void muxclientLinestateInitialize(muxclient_lstate_t *ls, line_t *l, bool is_child,cid_t connection_id);
void muxclientLinestateDestroy(muxclient_lstate_t *ls);

bool muxclientCheckConnectionIsExhausted(muxclient_tstate_t *ts, muxclient_lstate_t *ls);
void muxclientForgetParentLine(muxclient_tstate_t *ts, wid_t wid, line_t *parent_l);
line_t *muxclientGetParentLineForNewChild(tunnel_t *t, line_t *child_l);

void muxclientJoinConnection(muxclient_lstate_t *parent, muxclient_lstate_t *child);
void muxclientLeaveConnection(muxclient_lstate_t *child);

void muxclientMakeMuxFrame(sbuf_t *buf, cid_t cid, uint8_t flag);
bool muxclientSendControlFrame(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls, line_t *child_l,
                               cid_t cid, uint8_t flag);
bool muxclientMaybeSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                      muxclient_lstate_t *parent_ls, line_t *child_l,
                                      muxclient_lstate_t *child_ls);
bool muxclientQueueChildPayload(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls, sbuf_t *buf);
bool muxclientFlushChildPending(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls, line_t *child_l,
                                muxclient_lstate_t *child_ls, bool fin_mode);
bool muxclientMaybeResumeParentForChildBuffers(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                               muxclient_lstate_t *parent_ls);
