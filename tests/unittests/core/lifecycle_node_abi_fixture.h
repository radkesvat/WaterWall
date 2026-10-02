/*
 * Covers: lifecycle node abi fixture; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Opt-in fixture/header composition. The including suite owns setup, case publication, and
 * cleanup; this header has no independent CTest entry.
 * CTest: Shared header; see the including suite for execution.
 */
#pragma once

#include "instance/lifecycle.h"
#include "instance/worker.h"

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
