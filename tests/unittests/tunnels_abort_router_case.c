/*
 * Router GeoIP lifecycle invariant fixture.
 *
 * Router startup refuses to load a rule table containing geoip conditions without opening the MaxMind database, so
 * evaluating a geoip rule against a closed database is an internal lifecycle violation, not something a peer
 * address can provoke. The MaxMind *lookup* errors that a peer can reach are Category-C and are covered by the
 * failure-injection test instead.
 */
#include "Router/structure.h"

#include "tunnels_abort_runtime_cases.h"

int tunnelsAbortRouterGeoipUnopenedDatabaseCase(void)
{
    router_tstate_t ts;
    memoryZero(&ts, sizeof(ts));
    ts.geoip_db_opened = false;

    address_context_t ctx;
    memoryZero(&ctx, sizeof(ctx));

    router_geoip_code_t code           = {.code = {'I', 'R', '\0'}};
    bool                evaluation_bad = false;

    discard routerGeoipCodesMatch(&ts, &ctx, &code, 1, &evaluation_bad);

    return 0;
}
