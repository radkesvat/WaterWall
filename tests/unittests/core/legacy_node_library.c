/*
 * Covers: legacy node library; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Auxiliary translation unit; linked into its owning suite with the same feature/seam
 * definitions. The suite driver owns initialization and teardown.
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: owning suite registration in tests/cmake/native/; this is a helper/conditional source, not a
 * separate selectable test
 */
#include "node_builder/node_library.h"

#ifdef OS_WIN
#define FIXTURE_EXPORT __declspec(dllexport)
#else
#define FIXTURE_EXPORT __attribute__((visibility("default")))
#endif

#ifndef FIXTURE_NODE_TYPE
#define FIXTURE_NODE_TYPE "MissingAbiFixture"
#endif

static unsigned int getter_calls;
static char         fixture_node_name[] = FIXTURE_NODE_TYPE;

FIXTURE_EXPORT node_t       nodeGet(void);
FIXTURE_EXPORT void         rejectedNodeResetCounters(void);
FIXTURE_EXPORT unsigned int rejectedNodeGetGetterCalls(void);

#ifdef FIXTURE_C11_DESCRIPTOR_ONLY
#define FIXTURE_ABI_VERSION WW_EXTERNAL_NODE_ABI_FOR_ATOMICS(1)
#endif

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
    return (node_t) {.type = fixture_node_name};
}

FIXTURE_EXPORT void rejectedNodeResetCounters(void)
{
    getter_calls = 0;
}

FIXTURE_EXPORT unsigned int rejectedNodeGetGetterCalls(void)
{
    return getter_calls;
}
