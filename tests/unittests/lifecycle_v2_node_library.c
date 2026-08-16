#include "lifecycle_node_abi_fixture.h"

#include "node_builder/node_library.h"
#include "objects/node.h"

#include <stdlib.h>
#include <string.h>

#ifdef OS_WIN
#include <malloc.h>
#include <windows.h>
#define FIXTURE_EXPORT __declspec(dllexport)
#else
#include <pthread.h>
#define FIXTURE_EXPORT __attribute__((visibility("default")))
#endif

enum lifecycle_fixture_stage_e
{
    kLifecycleFixtureQuiesceRequest = 1,
    kLifecycleFixtureWorkerQuiesce,
    kLifecycleFixtureQuiesceWait,
    kLifecycleFixtureWorkerStop,
    kLifecycleFixtureStop,
    kLifecycleFixtureDestroy,
};

static lifecycle_node_fixture_snapshot_t snapshot;
static void *(*fixture_allocate)(size_t) = malloc;
static char fixture_node_name[]          = "LifecycleV2Fixture";

FIXTURE_EXPORT uint32_t waterwallNodeLifecycleAbiVersion(void);
FIXTURE_EXPORT node_t   nodeGet(void);
FIXTURE_EXPORT void     lifecycleNodeFixtureReset(void);
FIXTURE_EXPORT void     lifecycleNodeFixtureSetAllocator(void *(*allocate)(size_t) );
FIXTURE_EXPORT void     lifecycleNodeFixtureGetSnapshot(lifecycle_node_fixture_snapshot_t *result);

static uintptr_t currentThreadToken(void)
{
#ifdef OS_WIN
    return (uintptr_t) GetCurrentThreadId();
#else
    pthread_t    id        = pthread_self();
    uintptr_t    token     = 0;
    const size_t copy_size = sizeof(id) < sizeof(token) ? sizeof(id) : sizeof(token);
    memcpy(&token, &id, copy_size);
    return token;
#endif
}

static void recordStage(unsigned int stage, const ww_lifecycle_context_t *context)
{
    const unsigned int index = snapshot.count++;
    if (index >= kLifecycleNodeFixtureStageCount)
    {
        return;
    }
    snapshot.stages[index]         = stage;
    snapshot.scopes[index]         = context->scope;
    snapshot.close_policies[index] = context->close_policy;
    snapshot.thread_tokens[index]  = currentThreadToken();
}

static void fixtureFlow(tunnel_t *t, line_t *line)
{
    discard t;
    discard line;
}

static void fixturePayload(tunnel_t *t, line_t *line, sbuf_t *payload)
{
    discard t;
    discard line;
    discard payload;
}

static void fixtureChain(tunnel_t *t, tunnel_chain_t *chain)
{
    discard t;
    discard chain;
}

static void fixtureIndex(tunnel_t *t, uint16_t index, uint32_t *offset)
{
    discard t;
    discard index;
    discard offset;
}

static void fixtureStatus(tunnel_t *t)
{
    discard t;
}

static void fixtureQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard t;
    recordStage(kLifecycleFixtureQuiesceRequest, context);
}

static void fixtureWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard t;
    snapshot.worker_wids[0] = wid;
    recordStage(kLifecycleFixtureWorkerQuiesce, context);
}

static void fixtureQuiesceWait(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard t;
    recordStage(kLifecycleFixtureQuiesceWait, context);
}

static void fixtureWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context)
{
    discard t;
    snapshot.worker_wids[1] = wid;
    recordStage(kLifecycleFixtureWorkerStop, context);
}

static void fixtureStop(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard t;
    recordStage(kLifecycleFixtureStop, context);
}

static void fixtureDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    recordStage(kLifecycleFixtureDestroy, context);
#ifdef OS_WIN
    _aligned_free(t);
#else
    free(t);
#endif
}

static tunnel_t *fixtureCreate(node_t *node)
{
    const size_t allocation_size = offsetof(tunnel_t, state) + kCpuLineCacheSize;
#ifdef OS_WIN
    tunnel_t *t = _aligned_malloc(allocation_size, kCpuLineCacheSize);
#else
    tunnel_t *t = aligned_alloc(kCpuLineCacheSize, allocation_size);
#endif
    if (t == NULL)
    {
        return NULL;
    }
    memset(t, 0, allocation_size);

    t->fnInitU          = fixtureFlow;
    t->fnInitD          = fixtureFlow;
    t->fnPayloadU       = fixturePayload;
    t->fnPayloadD       = fixturePayload;
    t->fnEstU           = fixtureFlow;
    t->fnEstD           = fixtureFlow;
    t->fnFinU           = fixtureFlow;
    t->fnFinD           = fixtureFlow;
    t->fnPauseU         = fixtureFlow;
    t->fnPauseD         = fixtureFlow;
    t->fnResumeU        = fixtureFlow;
    t->fnResumeD        = fixtureFlow;
    t->onChain          = fixtureChain;
    t->onIndex          = fixtureIndex;
    t->onPrepare        = fixtureStatus;
    t->onStart          = fixtureStatus;
    t->onQuiesceRequest = fixtureQuiesceRequest;
    t->onWorkerQuiesce  = fixtureWorkerQuiesce;
    t->onQuiesceWait    = fixtureQuiesceWait;
    t->onWorkerStop     = fixtureWorkerStop;
    t->onStop           = fixtureStop;
    t->onDestroy        = fixtureDestroy;
    t->node             = node;
    return t;
}

FIXTURE_EXPORT uint32_t waterwallNodeLifecycleAbiVersion(void)
{
    return WW_EXTERNAL_NODE_LIFECYCLE_ABI_VERSION;
}

FIXTURE_EXPORT node_t nodeGet(void)
{
    char *type = fixture_allocate(sizeof("LifecycleV2Fixture"));
    if (type != NULL)
    {
        memcpy(type, "LifecycleV2Fixture", sizeof("LifecycleV2Fixture"));
    }
    return (node_t) {
        .name         = fixture_node_name,
        .type         = type,
        .flags        = kNodeFlagNoChain,
        .createHandle = fixtureCreate,
        .layer_group  = kNodeLayerAnything,
    };
}

FIXTURE_EXPORT void lifecycleNodeFixtureReset(void)
{
    memset(&snapshot, 0, sizeof(snapshot));
}

FIXTURE_EXPORT void lifecycleNodeFixtureSetAllocator(void *(*allocate)(size_t) )
{
    fixture_allocate = allocate;
}

FIXTURE_EXPORT void lifecycleNodeFixtureGetSnapshot(lifecycle_node_fixture_snapshot_t *result)
{
    *result = snapshot;
}
