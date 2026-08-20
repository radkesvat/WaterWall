#include "MuxClient/structure.h"

#include "tunnel_line_failure_harness.h"
#include "udplistener_shutdown_fixture.h"

enum
{
    kShutdownLineCapacity = 8,
    kShutdownIdleHash     = 0x44
};

static const char *modeName(uint8_t mode)
{
    switch (mode)
    {
    case kConcurrencyModeCounter:
        return "counter";
    case kConcurrencyModeTimer:
        return "timer";
    case kConcurrencyModeFixedConnectionsCount:
        return "fixed";
    default:
        return "unknown";
    }
}

static void caseUdpSourceDrainsBeforeMuxWorkerStop(uint8_t mode)
{
    char case_name[96];
    snprintf(case_name, sizeof(case_name), "UdpListener source drains before %s Mux worker stop", modeName(mode));
    twfSetCase(case_name);

    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      trace = {0};
    twfWorkerEnvSetup(&env, 8192, kMuxFrameLength * 2U);

    tunnel_t *udp  = udplistenerShutdownFixtureCreateTunnel();
    tunnel_t *mux  = tunnelCreate(NULL, sizeof(muxclient_tstate_t) + sizeof(line_t *), sizeof(muxclient_lstate_t));
    tunnel_t *next = twfCreateNextTunnel(&trace);
    twfRequire(udp != NULL && mux != NULL, "failed to create the UdpListener/MuxClient shutdown fixture");

    udp->lstate_offset = 0;
    mux->lstate_offset = udp->lstate_size;
    mux->fnInitU       = muxclientTunnelUpStreamInit;
    mux->fnFinU        = muxclientTunnelUpStreamFinish;
    tunnelBind(udp, mux);
    tunnelBind(mux, next);

    const uint32_t aggregate_lstate_size = udp->lstate_size + mux->lstate_size;
    twfLinePoolSetup(&lines, aggregate_lstate_size, kShutdownLineCapacity);

    muxclient_tstate_t *ts            = tunnelGetState(mux);
    ts->concurrency_mode              = mode;
    ts->concurrency_capacity          = 16;
    ts->concurrency_duration          = UINT32_MAX;
    ts->child_buffer_limit            = kMuxDefaultChildBufferLimit;
    ts->child_buffer_pause_tolerance  = kMuxDefaultChildBufferPauseTolerance;
    ts->child_buffer_resume_threshold = kMuxDefaultChildBufferResumeThreshold;
    ts->parent_buffer_limit           = kMuxDefaultParentBufferLimit;
    ts->detached_buffer_limit         = kMuxMinimumDetachedBufferLimit;
    ts->detached_child_limit          = kMuxMinimumDetachedChildLimit;
    ts->workers_count                 = 1;
    ts->detached_child_counts         = memoryAllocateZero(sizeof(*ts->detached_child_counts));
    ts->detached_queued_bytes         = memoryAllocateZero(sizeof(*ts->detached_queued_bytes));
    twfRequire(ts->detached_child_counts != NULL && ts->detached_queued_bytes != NULL,
               "failed to allocate detached MuxClient accounting");

    line_t *parent = twfLinePoolCreateLine(&lines);
    lineLock(parent);
    muxclient_lstate_t *parent_ls = lineGetState(parent, mux);
    muxclientLinestateInitialize(parent_ls, parent, false, 0);

    if (mode == kConcurrencyModeFixedConnectionsCount)
    {
        ts->fixed_connections_count   = 1;
        ts->fixed_parent_lines        = memoryAllocateZero(sizeof(*ts->fixed_parent_lines));
        ts->fixed_next_parent_indexes = memoryAllocateZero(sizeof(*ts->fixed_next_parent_indexes));
        twfRequire(ts->fixed_parent_lines != NULL && ts->fixed_next_parent_indexes != NULL,
                   "failed to allocate fixed Mux selection storage");
        ts->fixed_parent_lines[0] = parent;
    }
    else
    {
        ts->unsatisfied_lines[0] = parent;
    }

    line_t *child = twfLinePoolCreateLine(&lines);
    lineLock(child);

    local_idle_table_t *idle_table = localIdleTableCreate(env.loop);
    twfRequire(idle_table != NULL, "failed to create the UdpListener owner inventory");
    local_idle_table_t *idle_tables[1] = {idle_table};
    udpsock_t           socket         = {.io = NULL, .idle_tables = idle_tables};
    twfRequire(udplistenerShutdownFixtureAttach(udp, child, idle_table, &socket, kShutdownIdleHash) != NULL,
               "failed to publish the UdpListener line before Init");

    tunnelNextUpStreamInit(udp, child);
    twfRequire(parent_ls->children_count == 1, "the real Mux Init did not attach the UdpListener-owned child");

    socketmanagerDrainUdpSocketForWorker(&socket, 0);
    twfRequire(socket.idle_tables[0] == NULL, "SocketManager retained the drained UdpListener inventory");
    twfRequire(! lineIsAlive(child), "UdpListener source drain left its owned child alive");
    twfRequire(parent_ls->children_count == 0, "UdpListener Finish did not detach the borrowed Mux child");
    twfRequireEqualU32(trace.prev_finish, 0, "Mux reflected Finish toward the source owner");

    socketmanagerDrainUdpSocketForWorker(&socket, 0);
    twfRequireEqualU32(trace.prev_finish, 0, "repeated SocketManager drain emitted another source Finish");

    muxclientTunnelOnWorkerStop(mux, 0, wwLifecycleProcessShutdown());
    twfRequire(! lineIsAlive(parent), "Mux worker stop left its zero-child internal parent alive");
    twfRequireEqualU32(trace.next_finish, 1, "Mux did not close its internal parent exactly once");
    muxclientTunnelOnWorkerStop(mux, 0, wwLifecycleProcessShutdown());
    twfRequireEqualU32(trace.next_finish, 1, "repeated Mux worker stop reclosed its internal parent");

    twfRequireLineStateZeroed(child, udp, "UdpListener state survived source-owner drain");
    twfRequireLineStateZeroed(child, mux, "Mux borrowed-child state survived source-owner drain");
    twfRequireLineStateZeroed(parent, mux, "Mux parent state survived worker stop");
    lineUnlock(child);
    lineUnlock(parent);
    twfRequireEqualU32(masterpoolGetCheckedOut(lines.master), 0, "shutdown retained a pooled line");
    twfRequireNoLeakedBuffers();

    memoryFree(ts->fixed_parent_lines);
    memoryFree(ts->fixed_next_parent_indexes);
    memoryFree(ts->detached_child_counts);
    memoryFree(ts->detached_queued_bytes);
    tunnelDestroy(next);
    tunnelDestroy(mux);
    tunnelDestroy(udp);
    twfLinePoolTeardown(&lines);
    twfWorkerEnvTeardown(&env);
}

static void caseUdpSourceDrainWithoutMux(void)
{
    twfSetCase("UdpListener source drain does not depend on a Mux neighbour");

    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      trace = {0};
    twfWorkerEnvSetup(&env, 4096, 0);

    tunnel_t *udp  = udplistenerShutdownFixtureCreateTunnel();
    tunnel_t *next = twfCreateNextTunnel(&trace);
    twfRequire(udp != NULL, "failed to create the UdpListener control fixture");
    tunnelBind(udp, next);
    twfLinePoolSetup(&lines, udp->lstate_size, kShutdownLineCapacity);

    line_t *line = twfLinePoolCreateLine(&lines);
    lineLock(line);
    local_idle_table_t *idle_table = localIdleTableCreate(env.loop);
    twfRequire(idle_table != NULL, "failed to create the UdpListener control inventory");
    local_idle_table_t *idle_tables[1] = {idle_table};
    udpsock_t           socket         = {.io = NULL, .idle_tables = idle_tables};
    twfRequire(udplistenerShutdownFixtureAttach(udp, line, idle_table, &socket, kShutdownIdleHash) != NULL,
               "failed to publish the UdpListener control line");

    socketmanagerDrainUdpSocketForWorker(&socket, 0);
    twfRequire(! lineIsAlive(line), "non-Mux UdpListener source drain left its line alive");
    twfRequireEqualU32(trace.next_finish, 1, "non-Mux source drain did not propagate exactly one Finish");
    socketmanagerDrainUdpSocketForWorker(&socket, 0);
    twfRequireEqualU32(trace.next_finish, 1, "repeated non-Mux source drain emitted another Finish");

    lineUnlock(line);
    twfRequireEqualU32(masterpoolGetCheckedOut(lines.master), 0, "non-Mux source drain retained its line");
    tunnelDestroy(next);
    tunnelDestroy(udp);
    twfLinePoolTeardown(&lines);
    twfWorkerEnvTeardown(&env);
}

int main(void)
{
    caseUdpSourceDrainsBeforeMuxWorkerStop(kConcurrencyModeCounter);
    caseUdpSourceDrainsBeforeMuxWorkerStop(kConcurrencyModeTimer);
    caseUdpSourceDrainsBeforeMuxWorkerStop(kConcurrencyModeFixedConnectionsCount);
    caseUdpSourceDrainWithoutMux();
    puts("UdpListener/MuxClient shutdown ordering tests passed");
    return 0;
}
