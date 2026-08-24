#define kTunnelStateSize kMuxServerTestTunnelStateSize
#define kLineStateSize   kMuxServerTestLineStateSize
#include "MuxServer/structure.h"
#undef kTunnelStateSize
#undef kLineStateSize

#include "VlessServer/structure.h"

#include "fallback_finish_lifetime_fixture.h"

enum
{
    kTestLargeBufferSize = 64 * 1024,
    kTestChildCid        = 19,
    kTestLinePoolItems   = 8
};

typedef struct muxserver_vless_fixture_s
{
    twf_worker_env_t          env;
    twf_line_pool_t           lines;
    twf_trace_t               trace;
    fallback_finish_fixture_t fallback;
    tunnel_t                 *prev;
    tunnel_t                 *mux;
    tunnel_t                 *vless;
    line_t                   *parent;
    line_t                   *child;
} muxserver_vless_fixture_t;

static void requireVlessStateZero(fallback_finish_fixture_t *fallback, line_t *line)
{
    twfRequireLineStateZeroed(line, fallback->node, "VlessServer state survived MuxServer child close");
}

static void configureMux(muxserver_vless_fixture_t *fixture)
{
    muxserver_tstate_t *ts                = tunnelGetState(fixture->mux);
    ts->child_buffer_limit                = kMuxDefaultChildBufferLimit;
    ts->child_buffer_pause_tolerance      = kMuxDefaultChildBufferPauseTolerance;
    ts->child_buffer_resume_threshold     = kMuxDefaultChildBufferResumeThreshold;
    ts->parent_buffer_limit               = kMuxDefaultParentBufferLimit;
    ts->detached_buffer_limit             = kMuxMinimumDetachedBufferLimit;
    ts->detached_child_limit              = kMuxMinimumDetachedChildLimit;
    ts->max_live_children                 = 1024;
    ts->memory_fallback_max_live_children = 1024;
    ts->initial_child_idle_timeout_ms     = 60000;
    ts->active_child_idle_timeout_ms      = 60000;
    ts->workers_count                     = 1;
}

static void fixtureSetup(muxserver_vless_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, kMuxFrameLength * 2);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->mux =
        tunnelCreate(NULL, sizeof(muxserver_tstate_t) + sizeof(muxserver_worker_state_t), sizeof(muxserver_lstate_t));
    fixture->vless = tunnelCreate(NULL, sizeof(vlessserver_tstate_t), sizeof(vlessserver_lstate_t));
    twfRequire(fixture->mux != NULL && fixture->vless != NULL, "failed to create the MuxServer/VlessServer fixture");

    tunnelBind(fixture->prev, fixture->mux);
    tunnelBind(fixture->mux, fixture->vless);
    fixture->mux->lstate_offset   = 0;
    fixture->vless->lstate_offset = fixture->mux->lstate_size;
    fixture->vless->fnFinU        = vlessserverTunnelUpStreamFinish;
    configureMux(fixture);

    fixture->fallback.node                    = fixture->vless;
    fixture->fallback.require_node_state_zero = requireVlessStateZero;
    fallbackFinishCreateBranch(&fixture->fallback);

    vlessserver_tstate_t *vless_ts                 = tunnelGetState(fixture->vless);
    vless_ts->fallback_tunnel                      = fixture->fallback.fallback;
    vless_ts->fallback_intentional_delay_ms        = 7;
    vless_ts->fallback_intentional_delay_jitter_ms = 0;

    twfLinePoolSetup(&fixture->lines, fixture->mux->lstate_size + fixture->vless->lstate_size, kTestLinePoolItems);
    fixture->parent = twfLinePoolCreateLine(&fixture->lines);
    fixture->child  = twfLinePoolCreateLine(&fixture->lines);

    muxserver_lstate_t *parent_ls = lineGetState(fixture->parent, fixture->mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture->child, fixture->mux);
    muxserverLinestateInitialize(fixture->mux, parent_ls, fixture->parent, false, 0);
    muxserver_tstate_t *mux_ts = tunnelGetState(fixture->mux);
    twfRequire(muxserverTryReserveLiveChildSlot(mux_ts, mux_ts->max_live_children),
               "failed to reserve the MuxServer child slot");
    muxserverLinestateInitialize(fixture->mux, child_ls, fixture->child, true, kTestChildCid);
    child_ls->child_slot_reserved = true;
    muxserverArmChildIdle(fixture->mux, child_ls);
    muxserverJoinConnection(parent_ls, child_ls);

    vlessserver_lstate_t *vless_ls = lineGetState(fixture->child, fixture->vless);
    vlessserverLinestateInitialize(vless_ls, fixture->vless, fixture->child, kVlessServerLineKindClient);
    vless_ls->phase = kVlessServerPhaseFallback;
    tunnelUpStreamInit(fixture->fallback.fallback, fixture->child);
    fallbackFinishResetScheduledTask();
}

static void queueFallbackFifo(muxserver_vless_fixture_t *fixture)
{
    vlessserver_lstate_t *ls = lineGetState(fixture->child, fixture->vless);

    twfRequire(vlessserverSendFallbackPayload(
                   fixture->vless, fixture->child, ls, fallbackFinishMakePayload(fixture->env.pool, "first")),
               "first fallback payload was rejected");
    twfRequire(vlessserverSendFallbackPayload(
                   fixture->vless, fixture->child, ls, fallbackFinishMakePayload(fixture->env.pool, "-second")),
               "second fallback payload was rejected");
    twfRequire(g_fallback_finish_task.pending, "VlessServer did not retain its delayed fallback task");
}

static void requireChildResourcesReleased(muxserver_vless_fixture_t *fixture)
{
    muxserver_tstate_t *ts = tunnelGetState(fixture->mux);
    twfRequireEqualU32(
        (uint32_t) atomicLoadRelaxed(&ts->live_children_count), 0, "MuxServer did not release the child reservation");
    local_idle_table_t *table = ts->worker_states[0].child_idle_table;
    twfRequireEqualU32(table == NULL ? 0 : (uint32_t) localidletableGetItemCount(table),
                       0,
                       "MuxServer did not release the child idle item");
}

static void fixtureTeardown(muxserver_vless_fixture_t *fixture)
{
    if (fixture->parent != NULL && lineIsAlive(fixture->parent))
    {
        muxserver_lstate_t *parent_ls = lineGetState(fixture->parent, fixture->mux);
        if (parent_ls->l != NULL)
        {
            muxserverLinestateDestroy(fixture->mux, parent_ls);
        }
        lineDestroy(fixture->parent);
    }

    muxserver_tstate_t *ts = tunnelGetState(fixture->mux);
    if (ts->worker_states[0].child_idle_table != NULL)
    {
        localidletableDestroy(ts->worker_states[0].child_idle_table);
        ts->worker_states[0].child_idle_table = NULL;
    }

    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&fixture->lines);
    tunnelDestroy(fixture->fallback.fallback);
    tunnelDestroy(fixture->vless);
    tunnelDestroy(fixture->mux);
    tunnelDestroy(fixture->prev);
    twfWorkerEnvTeardown(&fixture->env);
}

static void caseCloseChildKeepsParent(void)
{
    twfSetCase("MuxServer child close settles VlessServer fallback before destruction");

    muxserver_vless_fixture_t fixture;
    fixtureSetup(&fixture);
    queueFallbackFifo(&fixture);

    muxserver_lstate_t *parent_ls = lineGetState(fixture.parent, fixture.mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture.child, fixture.mux);
    muxserverCloseChildKeepParent(fixture.mux, fixture.parent, parent_ls, child_ls, true);

    twfRequire(! lineIsAlive(fixture.child), "MuxServer returned with its owned child line alive");
    twfRequireLineStateZeroed(fixture.child, fixture.mux, "MuxServer child state survived close");
    twfRequireLineStateZeroed(fixture.child, fixture.vless, "VlessServer child state survived close");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "fallback did not receive one coalesced payload");
    twfRequireEqualText((const char *) fixture.fallback.received, "first-second", "fallback FIFO order changed");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "fallback did not receive one Finish");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "MuxServer did not emit its child Close frame exactly once");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "VlessServer reflected Finish toward the MuxServer parent");
    twfRequire(parent_ls->child_next == NULL && parent_ls->children_count == 0,
               "MuxServer retained the closed child in its parent state");
    requireChildResourcesReleased(&fixture);

    fallbackFinishDriveDelayedTask();
    fixture.child = NULL;
    fixtureTeardown(&fixture);
}

static void caseParentLossSweepsChild(void)
{
    twfSetCase("MuxServer parent loss settles VlessServer fallback before child destruction");

    muxserver_vless_fixture_t fixture;
    fixtureSetup(&fixture);
    queueFallbackFifo(&fixture);

    muxserverTunnelUpStreamFinish(fixture.mux, fixture.parent);

    twfRequire(! lineIsAlive(fixture.child), "parent-loss sweep returned with its owned child line alive");
    twfRequireLineStateZeroed(fixture.child, fixture.mux, "parent-loss sweep retained MuxServer child state");
    twfRequireLineStateZeroed(fixture.child, fixture.vless, "parent-loss sweep retained VlessServer child state");
    twfRequireLineStateZeroed(fixture.parent, fixture.mux, "parent-loss sweep retained MuxServer parent state");
    twfRequireEqualU32(fixture.fallback.payload_calls, 1, "parent-loss sweep did not flush pending fallback bytes");
    twfRequireEqualText(
        (const char *) fixture.fallback.received, "first-second", "parent-loss fallback FIFO order changed");
    twfRequireEqualU32(fixture.fallback.finish_calls, 1, "parent-loss sweep did not finish fallback exactly once");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "parent-loss sweep reflected Finish toward the sender");
    requireChildResourcesReleased(&fixture);

    fallbackFinishDriveDelayedTask();
    fixture.child = NULL;
    lineDestroy(fixture.parent);
    fixture.parent = NULL;
    fixtureTeardown(&fixture);
}

int main(void)
{
    caseCloseChildKeepsParent();
    caseParentLossSweepsChild();

    printf("muxserver_vless_fallback_finish_test: all cases passed\n");
    return 0;
}
