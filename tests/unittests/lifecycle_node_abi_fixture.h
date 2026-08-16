#pragma once

#include "instance/lifecycle.h"
#include "instance/worker.h"

#include <stdint.h>

enum
{
    kLifecycleNodeFixtureStageCount = 6,
};

typedef struct lifecycle_node_fixture_snapshot_s
{
    unsigned int                count;
    unsigned int                stages[kLifecycleNodeFixtureStageCount];
    ww_lifecycle_scope_e        scopes[kLifecycleNodeFixtureStageCount];
    ww_lifecycle_close_policy_e close_policies[kLifecycleNodeFixtureStageCount];
    wid_t                       worker_wids[2];
    uintptr_t                   thread_tokens[kLifecycleNodeFixtureStageCount];
} lifecycle_node_fixture_snapshot_t;
