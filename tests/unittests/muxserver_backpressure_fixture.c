#include "MuxServer/structure.h"

#include "mux_tls_close_backpressure_fixture.h"

enum
{
    kMxbServerCid = 53,
};

static mxb_fixture_t *mxbServerFixtureFromEndpoint(tunnel_t *endpoint)
{
    return *(mxb_fixture_t **) tunnelGetState(endpoint);
}

static void mxbServerParentPayload(tunnel_t *endpoint, line_t *parent, sbuf_t *buf)
{
    mxb_fixture_t *fixture = mxbServerFixtureFromEndpoint(endpoint);
    ++fixture->parent_control_payloads;
    lineReuseBuffer(parent, buf);
}

static void mxbServerParentFinish(tunnel_t *endpoint, line_t *parent)
{
    discard parent;
    ++mxbServerFixtureFromEndpoint(endpoint)->wire_finish_calls;
}

void mxbMuxServerCreate(mxb_fixture_t *fixture)
{
    fixture->mux =
        tunnelCreate(NULL, sizeof(muxserver_tstate_t) + sizeof(muxserver_worker_state_t), sizeof(muxserver_lstate_t));
    fixture->parent_peer = tunnelCreate(NULL, sizeof(mxb_fixture_t *), 0);
    mxbRequire(fixture->mux != NULL && fixture->parent_peer != NULL, "failed to create MuxServer composition tunnels");

    fixture->mux->fnPayloadU = muxserverTunnelUpStreamPayload;
    fixture->mux->fnFinU     = muxserverTunnelUpStreamFinish;
    fixture->mux->fnPauseD   = muxserverTunnelDownStreamPause;
    fixture->mux->fnResumeD  = muxserverTunnelDownStreamResume;

    *(mxb_fixture_t **) tunnelGetState(fixture->parent_peer) = fixture;
    fixture->parent_peer->fnPayloadD                         = mxbServerParentPayload;
    fixture->parent_peer->fnFinD                             = mxbServerParentFinish;
    tunnelBind(fixture->parent_peer, fixture->mux);

    muxserver_tstate_t *ts            = tunnelGetState(fixture->mux);
    ts->child_buffer_limit            = kMxbRetainedChargeLimit;
    ts->child_buffer_pause_tolerance  = kMuxDefaultChildBufferPauseTolerance;
    ts->child_buffer_resume_threshold = kMuxDefaultChildBufferResumeThreshold;
    ts->parent_buffer_limit           = kMxbRetainedChargeLimit;
    ts->detached_buffer_limit         = kMxbRetainedChargeLimit;
    ts->detached_child_limit          = kMuxMinimumDetachedChildLimit;
    ts->workers_count                 = 1;
}

void mxbMuxServerInitializeLines(mxb_fixture_t *fixture)
{
    muxserver_lstate_t *parent_ls = lineGetState(fixture->parent, fixture->mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture->child, fixture->mux);
    muxserverLinestateInitialize(fixture->mux, parent_ls, fixture->parent, false, 0);
    muxserverLinestateInitialize(fixture->mux, child_ls, fixture->child, true, kMxbServerCid);
    muxserverJoinConnection(parent_ls, child_ls);
}

void mxbMuxServerFeedParent(mxb_fixture_t *fixture, bool include_close)
{
    muxserverTunnelUpStreamPayload(
        fixture->mux, fixture->parent, mxbMakeParentBatch(fixture, kMxbServerCid, include_close));
}

void mxbMuxServerFinishParent(mxb_fixture_t *fixture)
{
    muxserverTunnelUpStreamFinish(fixture->mux, fixture->parent);
}

bool mxbMuxServerChildIsPaused(const mxb_fixture_t *fixture)
{
    return ((muxserver_lstate_t *) lineGetState(fixture->child, fixture->mux))->paused;
}

bool mxbMuxServerChildIsPeerDraining(const mxb_fixture_t *fixture)
{
    return ((muxserver_lstate_t *) lineGetState(fixture->child, fixture->mux))->close_state ==
           kMuxServerChildClosePeerDraining;
}

bool mxbMuxServerChildIsParentGoneDraining(const mxb_fixture_t *fixture)
{
    return ((muxserver_lstate_t *) lineGetState(fixture->child, fixture->mux))->close_state ==
           kMuxServerChildCloseParentGoneDraining;
}

bool mxbMuxServerChildHasNoParent(const mxb_fixture_t *fixture)
{
    return ((muxserver_lstate_t *) lineGetState(fixture->child, fixture->mux))->parent == NULL;
}

size_t mxbMuxServerChildQueuedBytes(const mxb_fixture_t *fixture)
{
    muxserver_lstate_t *child_ls = lineGetState(fixture->child, fixture->mux);
    return bufferqueueGetBufLen(&child_ls->pending_child_data);
}

size_t mxbMuxServerChildQueueCharge(const mxb_fixture_t *fixture)
{
    return ((muxserver_lstate_t *) lineGetState(fixture->child, fixture->mux))->pending_child_queue_charge;
}

size_t mxbMuxServerParentQueueCharge(const mxb_fixture_t *fixture)
{
    muxserver_lstate_t *parent_ls = lineGetState(fixture->parent, fixture->mux);
    return parent_ls->pending_child_queue_charge;
}

uint32_t mxbMuxServerDetachedChildren(const mxb_fixture_t *fixture)
{
    return ((muxserver_tstate_t *) tunnelGetState(fixture->mux))->worker_states[0].detached_registry.count;
}

size_t mxbMuxServerDetachedCharge(const mxb_fixture_t *fixture)
{
    return ((muxserver_tstate_t *) tunnelGetState(fixture->mux))->worker_states[0].detached_registry.queued_charge;
}

bool mxbMuxServerDetachedHeadIsChild(const mxb_fixture_t *fixture)
{
    muxserver_detached_registry_t *registry =
        &((muxserver_tstate_t *) tunnelGetState(fixture->mux))->worker_states[0].detached_registry;
    return registry->head == lineGetState(fixture->child, fixture->mux);
}

void mxbMuxServerDestroy(mxb_fixture_t *fixture)
{
    muxserver_tstate_t *ts = tunnelGetState(fixture->mux);
    mxbRequire(ts->worker_states[0].detached_registry.head == NULL &&
                   ts->worker_states[0].detached_registry.count == 0 &&
                   ts->worker_states[0].detached_registry.queued_charge == 0,
               "MuxServer composition teardown retained detached registry state");

    if (fixture->parent != NULL)
    {
        mxbRequire(lineIsAlive(fixture->parent), "MuxServer composition retained a dead borrowed parent pointer");
        muxserver_lstate_t *parent_ls = lineGetState(fixture->parent, fixture->mux);
        if (parent_ls->l != NULL)
        {
            mxbRequire(parent_ls->children_count == 0, "MuxServer composition parent retained a child at teardown");
            muxserverLinestateDestroy(fixture->mux, parent_ls);
        }
        lineDestroy(fixture->parent);
        fixture->parent = NULL;
    }

    tunnelDestroy(fixture->parent_peer);
    tunnelDestroy(fixture->mux);
    fixture->parent_peer = NULL;
    fixture->mux         = NULL;
}
