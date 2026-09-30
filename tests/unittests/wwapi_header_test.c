#include "wwapi.h"

/* Check before choosing a logger: shared API headers must not choose for us. */
#if defined(WW_LOG_H_) || defined(LOGGER_CHOSEN) || defined(wlog) || defined(LOGD) || defined(LOGI) ||                 \
    defined(LOGW) || defined(LOGE) || defined(LOGF)
#error "wwapi.h must not include logging headers or select a logger"
#endif

_Static_assert(_Generic(&wwLwipRuntimeGet, ww_lwip_engine_t *(*) (uint8_t): 1, default: 0),
               "wwapi.h must expose the lwIP runtime API");

#include "loggers/network_logger.h"

#define WWAPI_TEST_STRINGIFY_IMPL(value) #value
#define WWAPI_TEST_STRINGIFY(value)      WWAPI_TEST_STRINGIFY_IMPL(value)

int main(void)
{
    if (strcmp(WWAPI_TEST_STRINGIFY(LOGGER_CHOSEN), "NetworkLogger") != 0)
    {
        fputs("wwapi.h prevented explicit network logger selection\n", stderr);
        return EXIT_FAILURE;
    }

    quiescence_gate_t gate;
    quiescenceGateInit(&gate);
    if (! quiescenceGateOpen(&gate) || ! quiescenceGateEnter(&gate))
    {
        fputs("quiescence gate is not usable through wwapi.h\n", stderr);
        return EXIT_FAILURE;
    }
    quiescenceGateLeave(&gate);
    quiescenceGateCloseAndQuiesce(&gate, quiescenceGateYieldThread, NULL);
    if (! quiescenceGateIsClosedAndQuiesced(&gate))
    {
        fputs("quiescence gate did not close\n", stderr);
        return EXIT_FAILURE;
    }

    puts("wwapi header isolation tests passed");
    return EXIT_SUCCESS;
}
