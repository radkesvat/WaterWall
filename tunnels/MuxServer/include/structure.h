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

typedef struct muxserver_tstate_s
{
    uint32_t child_buffer_limit;
    uint32_t child_buffer_pause_tolerance;
    bool     log_main_line_stats;
} muxserver_tstate_t;

typedef struct muxserver_lstate_s
{
    line_t *l;           // the line this state is associated with
    line_t *last_writer; // used when parent, to track the last writer line

    struct muxserver_lstate_s *parent;             // the parent  f is_child is true
    struct muxserver_lstate_s *child_prev;         // previous child in the parent connection
    struct muxserver_lstate_s *child_next;         // next child in the parent connection
    buffer_stream_t            read_stream;        // stream for reading data from the parent connection
    buffer_queue_t             pending_child_data; // child-destined data queued while the child write side is paused
    size_t                     pending_child_data_len; // parent: total queued child-destined bytes
    cid_t                      connection_id;          // unique connection id, used for multiplexing
    uint32_t children_count;          // number of children in the parent connection, used for concurrency mode counter
    uint32_t parent_read_pause_count; // parent: child queues currently pausing parent reads
    bool     is_child : 1;            // if this connection is muxed into a parent connection
    bool     paused : 1;              // child: local child write side is paused
    bool     flow_paused_sent : 1;    // child: FlowPause was sent to the peer for this cid
    bool     peer_flow_paused : 1;    // child: peer sent FlowPause for this cid
    bool     parent_write_paused : 1; // child: parent transport write pause was reflected to this child
    bool     parent_read_paused : 1;  // child: queued child data paused parent transport reads
    bool     aggregate_read_paused : 1; // parent: aggregate child queues paused parent transport reads
    bool     parent_finishing : 1;      // parent: main FIN is being handled, suppress parent writes
} muxserver_lstate_t;

enum
{
    kTunnelStateSize                     = sizeof(muxserver_tstate_t),
    kLineStateSize                       = sizeof(muxserver_lstate_t),
    kConcurrencyModeTimer                = kDvsFirstOption,
    kConcurrencyModeCounter              = kDvsSecondOption,
    kMaxMainChannelBufferSize            = 1024 * 1024, // 1MB
    kMuxDefaultChildBufferLimit          = 8 * 1024 * 1024,
    kMuxDefaultChildBufferPauseTolerance = 512 * 1024,
    kMuxChildBufferResumeThreshold       = 512 * 1024,
    kMuxChildBufferQueueCap              = 8,
    kMuxMainLineStatsLogIntervalMs       = 5000,
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

WW_EXPORT void         muxserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *muxserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t muxserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void muxserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void muxserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void muxserverTunnelOnPrepair(tunnel_t *t);
void muxserverTunnelOnStart(tunnel_t *t);
void muxserverTunnelOnStop(tunnel_t *t);

void muxserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void muxserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void muxserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void muxserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void muxserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void muxserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void muxserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void muxserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void muxserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void muxserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void muxserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void muxserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void muxserverLinestateInitialize(muxserver_lstate_t *ls, line_t *l, bool is_child, cid_t connection_id);
void muxserverLinestateDestroy(muxserver_lstate_t *ls);
void muxserverScheduleParentStatsLog(tunnel_t *t, line_t *parent_l);

bool muxserverCheckConnectionIsExhausted(muxserver_tstate_t *ts, muxserver_lstate_t *ls);

void muxserverJoinConnection(muxserver_lstate_t *parent, muxserver_lstate_t *child);
void muxserverLeaveConnection(muxserver_lstate_t *child);

void muxserverMakeMuxFrame(sbuf_t *buf, cid_t cid, uint8_t flag);
bool muxserverSendControlFrame(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, line_t *child_l, cid_t cid,
                               uint8_t flag);
bool muxserverSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, line_t *child_l,
                                 muxserver_lstate_t *child_ls);
bool muxserverMaybeSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                      muxserver_lstate_t *parent_ls, line_t *child_l, muxserver_lstate_t *child_ls);
bool muxserverMaybePauseParentInputForChild(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                            muxserver_lstate_t *parent_ls, muxserver_lstate_t *child_ls);
bool muxserverResumeParentInputForChild(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                        muxserver_lstate_t *child_ls);
bool muxserverReleaseParentInputForChildClose(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                              muxserver_lstate_t *child_ls);
bool muxserverPauseChildSource(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *child_ls, bool peer_flow,
                               bool parent_write);
bool muxserverResumeChildSource(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *child_ls, bool peer_flow,
                                bool parent_write);
bool muxserverQueueChildPayload(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts, muxserver_lstate_t *parent_ls,
                                muxserver_lstate_t *child_ls, sbuf_t *buf);
bool muxserverFlushChildPending(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, line_t *child_l,
                                muxserver_lstate_t *child_ls, bool fin_mode);
