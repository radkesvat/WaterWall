#pragma once

#include "MuxCommon/mux_wire.h"
#include "wwapi.h"

typedef struct muxserver_tstate_s
{
    uint32_t child_buffer_limit;
    uint32_t child_buffer_pause_tolerance;
    uint32_t parent_buffer_limit;
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
    mux_cid_t                  connection_id;          // unique connection id, used for multiplexing
    uint32_t children_count;          // number of children in the parent connection, used for concurrency mode counter
    bool     is_child : 1;            // if this connection is muxed into a parent connection
    bool     paused : 1;              // child: local child write side is paused
    bool     flow_paused_sent : 1;    // child: FlowPause was sent to the peer for this cid
    bool     peer_flow_paused : 1;    // child: peer sent FlowPause for this cid
    bool     parent_write_paused : 1; // child: parent transport write pause was reflected to this child
    bool     parent_finishing : 1;    // parent: main FIN is being handled, suppress parent writes
} muxserver_lstate_t;

enum
{
    kTunnelStateSize                     = sizeof(muxserver_tstate_t),
    kLineStateSize                       = sizeof(muxserver_lstate_t),
    kConcurrencyModeTimer                = kDvsFirstOption,
    kConcurrencyModeCounter              = kDvsSecondOption,
    kMaxMainChannelBufferSize            = 1024 * 1024, // 1MB
    kMuxDefaultChildBufferLimit          = 24 * 1024 * 1024,
    kMuxDefaultChildBufferPauseTolerance = 512 * 1024,
    kMuxDefaultParentBufferLimit         = 32 * 1024 * 1024,
    kMuxParentBufferLimitUnlimited       = 0,
    kMuxChildBufferResumeThreshold       = 256 * 1024,
    kMuxChildBufferQueueCap              = 8,
    kMuxMainLineStatsLogIntervalMs       = 5000,
};

WW_EXPORT void         muxserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *muxserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t muxserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void muxserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);
void muxserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void muxserverTunnelOnPrepair(tunnel_t *t);
void muxserverTunnelOnStart(tunnel_t *t);
void muxserverTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context);

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

void muxserverLinestateInitialize(muxserver_lstate_t *ls, line_t *l, bool is_child, mux_cid_t connection_id);
void muxserverLinestateDestroy(muxserver_lstate_t *ls);
void muxserverScheduleParentStatsLog(tunnel_t *t, line_t *parent_l);

bool muxserverCheckConnectionIsExhausted(muxserver_tstate_t *ts, muxserver_lstate_t *ls);

void muxserverJoinConnection(muxserver_lstate_t *parent, muxserver_lstate_t *child);
void muxserverLeaveConnection(muxserver_lstate_t *child);

/**
 * Close one child of a still-live parent connection: unlink it, release its flow control, emit the Close frame,
 * destroy the child line state and destroy the child line.
 *
 * MuxServer creates its child lines, so it is also the node that destroys them.
 *
 * @param notify_child_next send Finish to the child's next side. Must be false when this close is the reaction to
 *                          a Finish received from that same side.
 *
 * The caller must return immediately: the parent line may be dead afterwards.
 */
void muxserverCloseChildKeepParent(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls,
                                   muxserver_lstate_t *child_ls, bool notify_child_next);
bool muxserverSendControlFrame(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, line_t *child_l,
                               mux_cid_t cid, uint8_t flag);
bool muxserverSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxserver_lstate_t *parent_ls, line_t *child_l,
                                 muxserver_lstate_t *child_ls);
bool muxserverMaybeSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxserver_tstate_t *ts,
                                      muxserver_lstate_t *parent_ls, line_t *child_l, muxserver_lstate_t *child_ls);
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
