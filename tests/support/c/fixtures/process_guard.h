#pragma once

/* Opt-in Category-C process guards. Define TWF_CUSTOM_PROCESS_API_WRAPS before including to supply Category-B guards.
 */
#include "fixtures/assertions.h"
#include "wevent.h"
#include "wwapi.h"

// ---------------------------------------------------------------------------
// process API guard
// ---------------------------------------------------------------------------
//
// A Category-C failure belongs to one line, so reaching any process API is a
// test failure. A Category-B test proves the opposite policy - that a runtime
// failure does request an orderly shutdown - so it defines
// TWF_CUSTOM_PROCESS_API_WRAPS and supplies recording wrappers of its own
// (tunnel_orderly_shutdown_harness.h). Everything else here is shared.

#ifndef TWF_CUSTOM_PROCESS_API_WRAPS

_Noreturn void __wrap_abortProgramNow(int exit_code);
bool           __wrap_requestProgramShutdown(int exit_code);

_Noreturn void __wrap_abortProgramNow(int exit_code)
{
    fprintf(stderr, "FAIL [%s]: a line-local failure called abortProgramNow(%d)\n", testCaseName(), exit_code);
    fflush(stderr);
    _Exit(1);
}

bool __wrap_requestProgramShutdown(int exit_code)
{
    fprintf(stderr, "FAIL [%s]: a line-local failure called requestProgramShutdown(%d)\n", testCaseName(), exit_code);
    fflush(stderr);
    _Exit(1);
}

#endif // TWF_CUSTOM_PROCESS_API_WRAPS
