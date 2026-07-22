#include "global_state.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

int main(void)
{
    system_load_state_t state = {0};
    system_load_state_t *previous_state = GSTATE.system_load;

    mutexInit(&state.mutex);
    state.initialized = true;
    state.supported   = true;
    GSTATE.system_load = &state;

    state.sample_warming_up = true;
    state.prev_read_ms      = getHRTimeUs() / 1000ULL;
    require(! isSystemUnderLoad(0.9), "the initial load-sampler warm-up did not fail open");

    state.prev_read_ms = 1;
    require(isSystemUnderLoad(0.9), "a stale load-sampler warm-up did not fail closed");

    state.sample_warming_up = false;
    state.sample_error      = true;
    require(isSystemUnderLoad(0.9), "a load-sampler read error did not fail closed");

    state.sample_error = false;
    require(isSystemUnderLoad(0.9), "an invalid non-warm-up sample did not fail closed");

    state.sample_valid    = true;
    state.last_valid_ms   = getHRTimeUs() / 1000ULL;
    state.cached_cpu_load = 0.95;
    require(isSystemUnderLoad(0.9), "valid CPU load above the threshold was not detected");

    state.cached_cpu_load = 0.5;
    require(! isSystemUnderLoad(0.9), "valid CPU load below the threshold was treated as overload");

    state.last_valid_ms = 1;
    require(isSystemUnderLoad(0.9), "a stale load sample did not fail closed");

    state.supported = false;
    require(! isSystemUnderLoad(0.9), "an unsupported sampler did not fail open");

    systemLoadSamplerSetForceUnderLoad(&state, true);
    require(isSystemUnderLoad(0.9), "the explicit overload test hook did not force a closed result");

    GSTATE.system_load = previous_state;
    mutexDestroy(&state.mutex);
    return 0;
}
