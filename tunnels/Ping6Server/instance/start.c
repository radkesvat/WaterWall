#include "structure.h"

#include "loggers/network_logger.h"

static bool ping6serverChooseRandomIdentifier(uint16_t *identifier)
{
    for (uint32_t attempt = 0; attempt < 8; ++attempt)
    {
        const uint16_t candidate = (uint16_t) fastRand32();
        if (pingwireSelectIdentifier(true, 0, candidate, identifier))
        {
            return true;
        }
    }
    return false;
}

void ping6serverOnStart(tunnel_t *t)
{
    ping6server_tstate_t *state = tunnelGetState(t);

    if (state->tracker == NULL)
    {
        LOGF("Ping6Server: correlation tracker is unavailable; refusing to start Ping6");
        startupFailureRecord(1);
        return;
    }

    getRandomBytes(state->digest_key, sizeof(state->digest_key));
    uint32_t reply_seed = fastRand32();
    if (state->identifier_is_random && ! ping6serverChooseRandomIdentifier(&state->wire.identifier))
    {
        memorySecureZero(state->digest_key, sizeof(state->digest_key));
        memorySecureZero(&reply_seed, sizeof(reply_seed));
        LOGF("Ping6Server: could not choose a nonzero random identifier");
        startupFailureRecord(1);
        return;
    }

    pingwireReplyIdGeneratorInitialize(&state->reply_ids, reply_seed, getHRTimeUs() / 1000U);
    memorySecureZero(&reply_seed, sizeof(reply_seed));
    state->started = true;
}
