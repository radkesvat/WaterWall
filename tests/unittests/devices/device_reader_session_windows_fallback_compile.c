/*
 * Covers: device reader session windows fallback compile; the explicit inputs, callbacks and expected
 * results below define this suite.
 * Setup: Auxiliary translation unit; linked into its owning suite with the same feature/seam
 * definitions. The suite driver owns initialization and teardown.
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Standalone compile/link/API probe: retain its original library boundary; runtime assertion
 * support is intentionally omitted where it would invalidate the probe.
 * CTest: compile-only: waterwall_platform_unit_tests
 */
/* Compile-only coverage of the real shared implementation, including all CAS
 * expected-value temporaries, with Win64's pointer-width fallback atomics. */
#include "wconfig.h"

#if ! defined(_WIN64) || WW_HAVE_C11_ATOMICS != 0
#error "This compile check requires Win64 with C11 atomics disabled"
#endif

/* CMake compiles session, budget and dispatch as separate real-source objects
 * with the same fallback definition. None is linked into the runtime. */
#include "devices/device_reader_session.h"
