#pragma once

#include "MuxCommon/mux_limits.h"
#include "MuxCommon/mux_wire.h"
#include "wwapi.h"

typedef struct muxclient_tstate_s
{
    uint8_t  concurrency_mode; // timer, counter, fixed-connections-count
    uint32_t concurrency_duration;
    uint32_t concurrency_capacity;
    uint32_t fixed_connections_count;
    uint32_t child_buffer_limit;
    uint32_t child_buffer_pause_tolerance;
    uint32_t parent_buffer_limit;
    uint32_t detached_buffer_limit;
    uint32_t detached_child_limit;
    uint32_t workers_count;
    bool     log_main_line_stats;

    line_t  **fixed_parent_lines;
    uint32_t *fixed_next_parent_indexes;
    uint32_t *detached_child_counts;
    size_t   *detached_queued_bytes;

    line_t *unsatisfied_lines[]; // lines (per worker) that still want child connections
} muxclient_tstate_t;

typedef enum muxclient_child_close_state_e
{
    kMuxClientChildCloseOpen = 0,
    kMuxClientChildClosePeerDraining,
    kMuxClientChildCloseParentGoneDraining,
} muxclient_child_close_state_t;

typedef enum muxclient_child_drain_result_e
{
    kMuxClientChildDrainBlocked = 0,
    kMuxClientChildDrainReadyToFinish,
    kMuxClientChildDrainChildGone,
    kMuxClientChildDrainParentGone,
} muxclient_child_drain_result_t;

typedef struct muxclient_lstate_s
{
    line_t *l;           // the line this state is associated with
    line_t *last_writer; // used when parent, to track the last writer line

    struct muxclient_lstate_s    *parent;             // the parent  f is_child is true
    struct muxclient_lstate_s    *child_prev;         // previous child in the parent connection
    struct muxclient_lstate_s    *child_next;         // next child in the parent connection
    buffer_stream_t               read_stream;        // stream for reading data from the parent connection
    buffer_queue_t                pending_child_data; // child-destined data queued while the child write side is paused
    size_t                        pending_child_data_len; // parent: total queued child-destined bytes
    uint64_t                      creation_epoch; // epoch of the connection creation, used for concurrency mode timer
    mux_cid_t                     connection_id;  // unique connection id, used for multiplexing
    muxclient_child_close_state_t close_state;    // child: monotonic ordered-close/drain state
    uint32_t children_count;          // number of children in the parent connection, used for concurrency mode counter
    bool     is_child : 1;            // immutable line role: this line is a Mux child
    bool     paused : 1;              // child: local child write side is paused
    bool     flow_paused_sent : 1;    // child: FlowPause was sent to the peer for this cid
    bool     peer_flow_paused : 1;    // child: peer sent FlowPause for this cid
    bool     parent_write_paused : 1; // child: parent transport write pause was reflected to this child
    bool     parent_finishing : 1;    // parent: main FIN is being handled, suppress parent writes
    bool     open_frame_sent : 1;     // child: peer has received the Open frame for this cid
} muxclient_lstate_t;

enum
{
    kTunnelStateSize                      = sizeof(muxclient_tstate_t),
    kLineStateSize                        = sizeof(muxclient_lstate_t),
    kConcurrencyModeTimer                 = kDvsFirstOption,
    kConcurrencyModeCounter               = kDvsSecondOption,
    kConcurrencyModeFixedConnectionsCount = kDvsThirdOption,
    kMaxMainChannelBufferSize             = 1024 * 1024, // 1MB
    kMuxDefaultChildBufferLimit           = 24 * 1024 * 1024,
    kMuxDefaultChildBufferPauseTolerance  = 512 * 1024,
    kMuxDefaultParentBufferLimit          = 32 * 1024 * 1024,
    kMuxParentBufferLimitUnlimited        = 0,
    kMuxChildBufferResumeThreshold        = 256 * 1024,
    kMuxChildBufferQueueCap               = 8,
    kMuxMainLineStatsLogIntervalMs        = 5000,
};

WW_EXPORT void         muxclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *muxclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t muxclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void muxclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);
void muxclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void muxclientTunnelOnPrepair(tunnel_t *t);
void muxclientTunnelOnStart(tunnel_t *t);
void muxclientTunnelOnStop(tunnel_t *t, const ww_lifecycle_context_t *context);
void muxclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

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

void muxclientLinestateInitialize(muxclient_lstate_t *ls, line_t *l, bool is_child, mux_cid_t connection_id);
void muxclientLinestateDestroy(muxclient_lstate_t *ls);

bool    muxclientCheckConnectionIsExhausted(muxclient_tstate_t *ts, muxclient_lstate_t *ls);
void    muxclientForgetParentSelection(muxclient_tstate_t *ts, wid_t wid, line_t *parent_l);
line_t *muxclientGetParentLineForNewChild(tunnel_t *t, line_t *child_l);
void    muxclientScheduleParentStatsLog(tunnel_t *t, line_t *parent_l);

void muxclientJoinConnection(muxclient_lstate_t *parent, muxclient_lstate_t *child);
void muxclientLeaveConnection(muxclient_lstate_t *child);

/**
 * Finish and release a parent line that this node owns and that has no children left.
 */
void muxclientCloseIdleExhaustedParentLine(tunnel_t *t, muxclient_tstate_t *ts, wid_t wid, line_t *parent_l,
                                           muxclient_lstate_t *parent_ls);

/**
 * Close one child of a still-live parent connection: unlink it, release its flow control, emit the Close frame
 * (preceded by an Open frame when the peer never saw this cid) and destroy the child line state.
 *
 * MuxClient does not own the child line, so it never calls lineDestroy() on it.
 *
 * @param notify_child_prev send Finish to the child's previous side. Must be false when this close is the reaction
 *                          to a Finish received from that same side.
 *
 * The caller must return immediately: both the parent line and the child line may be dead afterwards.
 */
void muxclientCloseChildKeepParent(tunnel_t *t, muxclient_tstate_t *ts, line_t *parent_l, muxclient_lstate_t *parent_ls,
                                   muxclient_lstate_t *child_ls, bool notify_child_prev);
bool muxclientSendControlFrame(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls, line_t *child_l,
                               mux_cid_t cid, uint8_t flag);
bool muxclientSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls, line_t *child_l,
                                 muxclient_lstate_t *child_ls);
bool muxclientMaybeSendChildFlowPause(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                      muxclient_lstate_t *parent_ls, line_t *child_l, muxclient_lstate_t *child_ls);
bool muxclientReleaseParentInputForChildClose(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls,
                                              muxclient_lstate_t *child_ls);
bool muxclientPauseChildSource(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *child_ls, bool peer_flow,
                               bool parent_write);
bool muxclientResumeChildSource(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *child_ls, bool peer_flow,
                                bool parent_write);
bool muxclientQueueChildPayload(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls,
                                muxclient_lstate_t *child_ls, sbuf_t *buf);
muxclient_child_drain_result_t muxclientDrainAttachedChild(tunnel_t *t, line_t *parent_l, muxclient_lstate_t *parent_ls,
                                                           line_t *child_l, muxclient_lstate_t *child_ls);
muxclient_child_drain_result_t muxclientDrainDetachedChild(tunnel_t *t, line_t *child_l, muxclient_lstate_t *child_ls);
bool muxclientBeginPeerCloseDrain(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts, muxclient_lstate_t *parent_ls,
                                  muxclient_lstate_t *child_ls);
bool muxclientFinalizeAttachedPeerClose(tunnel_t *t, line_t *parent_l, muxclient_tstate_t *ts,
                                        muxclient_lstate_t *parent_ls, muxclient_lstate_t *child_ls);
void muxclientFinalizeDetachedChild(tunnel_t *t, line_t *child_l, muxclient_lstate_t *child_ls);
void muxclientAbortDetachedChild(tunnel_t *t, line_t *child_l, muxclient_lstate_t *child_ls, bool notify_child_prev);
void muxclientHandleParentLoss(tunnel_t *t, line_t *parent_l, bool notify_parent_next);
