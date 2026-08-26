#include "objects/node.h"

#ifdef OS_WIN
#define FIXTURE_EXPORT __declspec(dllexport)
#else
#define FIXTURE_EXPORT __attribute__((visibility("default")))
#endif

#ifndef FIXTURE_NODE_TYPE
#define FIXTURE_NODE_TYPE "MissingAbiFixture"
#endif

static unsigned int getter_calls;

FIXTURE_EXPORT node_t       nodeGet(void);
FIXTURE_EXPORT void         rejectedNodeResetCounters(void);
FIXTURE_EXPORT unsigned int rejectedNodeGetGetterCalls(void);

#ifdef FIXTURE_ABI_VERSION
FIXTURE_EXPORT uint32_t waterwallNodeLifecycleAbiVersion(void);

FIXTURE_EXPORT uint32_t waterwallNodeLifecycleAbiVersion(void)
{
    return FIXTURE_ABI_VERSION;
}
#endif

FIXTURE_EXPORT node_t nodeGet(void)
{
    ++getter_calls;
    return (node_t) {.type = FIXTURE_NODE_TYPE};
}

FIXTURE_EXPORT void rejectedNodeResetCounters(void)
{
    getter_calls = 0;
}

FIXTURE_EXPORT unsigned int rejectedNodeGetGetterCalls(void)
{
    return getter_calls;
}
