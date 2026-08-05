#include "structure.h"

#include "loggers/network_logger.h"

void ipmanipulatorUpStreamInit(tunnel_t *t, line_t *l)
{
    ipmanipulator_tstate_t *ts = tunnelGetState(t);
    if (! withLineLocked(l, tunnelNextUpStreamInit, t))
    {
        LOGF("IpManipulator: next packet line died during upstream init");
        abortProgramNow(1);
    }

    tunnel_t *helpers[] = {
        ts->trick_real_sni_upstream_tunnel,
        ts->trick_real_fin_upstream_tunnel,
    };

    for (uint32_t i = 0; i < ARRAY_SIZE(helpers); ++i)
    {
        if (helpers[i] == NULL)
        {
            continue;
        }

        bool already_initialized = false;
        for (uint32_t j = 0; j < i; ++j)
        {
            already_initialized |= helpers[j] == helpers[i];
        }

        if (! already_initialized)
        {
            tunnelUpStreamInit(helpers[i], l);
        }
    }
}
