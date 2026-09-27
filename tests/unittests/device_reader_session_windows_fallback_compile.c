/* Compile-only coverage of the real shared implementation, including all CAS
 * expected-value temporaries, with Win64's pointer-width fallback atomics. */
#include "wconfig.h"

#if ! defined(_WIN64) || WW_HAVE_C11_ATOMICS != 0
#error "This compile check requires Win64 with C11 atomics disabled"
#endif

/* CMake compiles session, budget and dispatch as separate real-source objects
 * with the same fallback definition. None is linked into the runtime. */
#include "devices/device_reader_session.h"
