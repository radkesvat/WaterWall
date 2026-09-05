#include "MuxClient/structure.h"

#include "mux_tls_close_backpressure_fixture.h"

enum
{
    kMxbClientCid = 41,
};

static mxb_fixture_t *mxbClientFixtureFromEndpoint(tunnel_t *endpoint)
{
    return *(mxb_fixture_t **) tunnelGetState(endpoint);
}

static void mxbClientParentPayload(tunnel_t *endpoint, line_t *parent, sbuf_t *buf)
{
    mxb_fixture_t *fixture = mxbClientFixtureFromEndpoint(endpoint);
    ++fixture->parent_control_payloads;
    lineReuseBuffer(parent, buf);
}

static void mxbClientParentFinish(tunnel_t *endpoint, line_t *parent)
{
    discard parent;
    ++mxbClientFixtureFromEndpoint(endpoint)->wire_finish_calls;
}

void mxbMuxClientCreate(mxb_fixture_t *fixture)
{
    fixture->mux = tunnelCreate(NULL, sizeof(muxclient_tstate_t) + sizeof(line_t *), sizeof(muxclient_lstate_t));
    fixture->parent_peer = tunnelCreate(NULL, sizeof(mxb_fixture_t *), 0);
    mxbRequire(fixture->mux != NULL && fixture->parent_peer != NULL, "failed to create MuxClient composition tunnels");

    fixture->mux->fnPayloadD = muxclientTunnelDownStreamPayload;
    fixture->mux->fnFinD     = muxclientTunnelDownStreamFinish;
    fixture->mux->fnPauseU   = muxclientTunnelUpStreamPause;
    fixture->mux->fnResumeU  = muxclientTunnelUpStreamResume;

    *(mxb_fixture_t **) tunnelGetState(fixture->parent_peer) = fixture;
    fixture->parent_peer->fnPayloadU                         = mxbClientParentPayload;
    fixture->parent_peer->fnFinU                             = mxbClientParentFinish;
    tunnelBind(fixture->mux, fixture->parent_peer);

    muxclient_tstate_t *ts            = tunnelGetState(fixture->mux);
    ts->concurrency_mode              = kConcurrencyModeCounter;
    ts->concurrency_capacity          = UINT32_MAX;
    ts->child_buffer_limit            = kMxbRetainedChargeLimit;
    ts->child_buffer_pause_tolerance  = kMuxDefaultChildBufferPauseTolerance;
    ts->child_buffer_resume_threshold = kMuxDefaultChildBufferResumeThreshold;
    ts->parent_buffer_limit           = kMxbRetainedChargeLimit;
    ts->detached_buffer_limit         = kMxbRetainedChargeLimit;
    ts->detached_child_limit          = kMuxMinimumDetachedChildLimit;
    ts->workers_count                 = 1;
    ts->detached_child_counts         = memoryAllocateZero(sizeof(*ts->detached_child_counts));
    ts->detached_queued_charge        = memoryAllocateZero(sizeof(*ts->detached_queued_charge));
    mxbRequire(ts->detached_child_counts != NULL && ts->detached_queued_charge != NULL,
               "failed to allocate MuxClient detached accounting");
}

void mxbMuxClientInitializeLines(mxb_fixture_t *fixture)
{
    muxclient_lstate_t *parent_ls = lineGetState(fixture->parent, fixture->mux);
    muxclient_lstate_t *child_ls  = lineGetState(fixture->child, fixture->mux);
    muxclientLinestateInitialize(parent_ls, fixture->parent, false, 0);
    muxclientLinestateInitialize(child_ls, fixture->child, true, kMxbClientCid);
    child_ls->open_frame_sent = true;
    muxclientJoinConnection(parent_ls, child_ls);
    ((muxclient_tstate_t *) tunnelGetState(fixture->mux))->unsatisfied_lines[0] = fixture->parent;
}

void mxbMuxClientFeedParent(mxb_fixture_t *fixture, bool include_close)
{
    muxclientTunnelDownStreamPayload(
        fixture->mux, fixture->parent, mxbMakeParentBatch(fixture, kMxbClientCid, include_close));
}

void mxbMuxClientFinishParent(mxb_fixture_t *fixture)
{
    muxclientTunnelDownStreamFinish(fixture->mux, fixture->parent);
}

bool mxbMuxClientChildIsPaused(const mxb_fixture_t *fixture)
{
    return ((muxclient_lstate_t *) lineGetState(fixture->child, fixture->mux))->paused;
}

bool mxbMuxClientChildIsPeerDraining(const mxb_fixture_t *fixture)
{
    return ((muxclient_lstate_t *) lineGetState(fixture->child, fixture->mux))->close_state ==
           kMuxClientChildClosePeerDraining;
}

bool mxbMuxClientChildIsParentGoneDraining(const mxb_fixture_t *fixture)
{
    return ((muxclient_lstate_t *) lineGetState(fixture->child, fixture->mux))->close_state ==
           kMuxClientChildCloseParentGoneDraining;
}

bool mxbMuxClientChildHasNoParent(const mxb_fixture_t *fixture)
{
    return ((muxclient_lstate_t *) lineGetState(fixture->child, fixture->mux))->parent == NULL;
}

size_t mxbMuxClientChildQueuedBytes(const mxb_fixture_t *fixture)
{
    muxclient_lstate_t *child_ls = lineGetState(fixture->child, fixture->mux);
    return bufferqueueGetBufLen(&child_ls->pending_child_data);
}

size_t mxbMuxClientChildQueueCharge(const mxb_fixture_t *fixture)
{
    return ((muxclient_lstate_t *) lineGetState(fixture->child, fixture->mux))->pending_child_queue_charge;
}

size_t mxbMuxClientParentQueueCharge(const mxb_fixture_t *fixture)
{
    muxclient_lstate_t *parent_ls = lineGetState(fixture->parent, fixture->mux);
    return parent_ls->pending_child_queue_charge;
}

uint32_t mxbMuxClientDetachedChildren(const mxb_fixture_t *fixture)
{
    return ((muxclient_tstate_t *) tunnelGetState(fixture->mux))->detached_child_counts[0];
}

size_t mxbMuxClientDetachedCharge(const mxb_fixture_t *fixture)
{
    return ((muxclient_tstate_t *) tunnelGetState(fixture->mux))->detached_queued_charge[0];
}

void mxbMuxClientDestroy(mxb_fixture_t *fixture)
{
    muxclient_tstate_t *ts = tunnelGetState(fixture->mux);
    mxbRequire(ts->detached_child_counts[0] == 0 && ts->detached_queued_charge[0] == 0,
               "MuxClient composition teardown retained detached accounting");

    if (fixture->parent != NULL)
    {
        mxbRequire(lineIsAlive(fixture->parent), "MuxClient composition retained a dead parent pointer");
        muxclient_lstate_t *parent_ls = lineGetState(fixture->parent, fixture->mux);
        if (parent_ls->l != NULL)
        {
            mxbRequire(parent_ls->children_count == 0, "MuxClient composition parent retained a child at teardown");
            muxclientLinestateDestroy(parent_ls);
        }
        lineDestroy(fixture->parent);
        fixture->parent = NULL;
    }

    memoryFree(ts->detached_child_counts);
    memoryFree(ts->detached_queued_charge);
    tunnelDestroy(fixture->parent_peer);
    tunnelDestroy(fixture->mux);
    fixture->parent_peer = NULL;
    fixture->mux         = NULL;
}
