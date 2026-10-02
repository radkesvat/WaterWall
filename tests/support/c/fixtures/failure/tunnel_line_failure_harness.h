/*
 * Covers: tunnel line failure harness; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: Opt-in fixture/header composition. The including suite owns setup, case publication, and cleanup;
 * this header has no independent CTest entry.
 * Cases: the explicit main/fixture operations and boundary vectors below
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network or
 * application-throughput behavior.
 * CTest: owning suite registration in tests/cmake/native/; this is a helper/conditional source, not a
 * separate selectable test
 */
#pragma once

#include "wevent.h"

/*
 * Shared scaffolding for the Category-C per-line failure-injection tests.
 *
 * A Category-C failure belongs to one connection. The tunnel must release everything that line owned, close only
 * that line through the correct callbacks, and leave the process and every other line running. This header gives
 * each of those properties a machine-checkable form:
 *
 *   - the two process APIs are linker-wrapped and fail the test the moment one of them is reached;
 *   - every pooled buffer handed out is tracked, so a leak and a double recycle are both hard errors;
 *   - fake previous/next tunnels record an ordered event trace, so "no Init reached the next branch" and
 *     "upstream Finish came before downstream Finish" are single string comparisons.
 *
 * It deliberately includes no tunnel structure.h: several tunnels ship a header with that name and one
 * translation unit must only ever see the tunnel it is testing. Anything tunnel-specific belongs in the test.
 *
 * Link ww_test_support privately. Every test that includes this header must link with:
 *   -Wl,--wrap=abortProgramNow -Wl,--wrap=requestProgramShutdown
 *   -Wl,--wrap=bufferpoolGetLargeBuffer -Wl,--wrap=bufferpoolGetSmallBuffer -Wl,--wrap=bufferpoolReuseBuffer
 */

#include "wwapi.h"

#include "fixtures/assertions.h"
#include "fixtures/buffer_ledger.h"
#include "fixtures/callback_trace.h"
#include "fixtures/process_guard.h"
#include "fixtures/worker_lines.h"
