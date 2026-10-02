/*
 * Covers: reality close lifecycle; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Opt-in fixture/header composition. The including suite owns setup, case publication, and
 * cleanup; this header has no independent CTest entry.
 * CTest: Shared header; see the including suite for execution.
 */
#pragma once

void realityTestClientCloseLifecycle(void);
void realityTestServerCloseLifecycle(void);
void realityTestClientRecordSizing(void);
void realityTestServerRecordSizing(void);
