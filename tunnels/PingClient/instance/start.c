#include "structure.h"

#include "loggers/network_logger.h"

static bool pingclientChooseRandomIdentifier(uint16_t *identifier)
{
    for (uint32_t attempt = 0; attempt < 8; ++attempt)
    {
        if (! secureRandomBytes(identifier, sizeof(*identifier)))
        {
            return false;
        }
        const uint16_t candidate = *identifier;
        if (pingwireSelectIdentifier(true, 0, candidate, identifier))
        {
            return true;
        }
    }
    return false;
}

void pingclientOnStart(tunnel_t *t)
{
    pingclient_tstate_t *state = tunnelGetState(t);
    uint32_t             reply_seed;

    if (state->tracker == NULL || ! secureRandomBytes(state->digest_key, sizeof(state->digest_key)) ||
        ! secureRandomBytes(&reply_seed, sizeof(reply_seed)) ||
        (state->identifier_is_random && ! pingclientChooseRandomIdentifier(&state->wire.identifier)))
    {
        memorySecureZero(state->digest_key, sizeof(state->digest_key));
        LOGF("PingClient: secure randomness is unavailable; refusing to start Ping wire v2");
        startupFailureRecord(1);
        return;
    }

    pingwireReplyIdGeneratorInitialize(&state->reply_ids, reply_seed, getHRTimeUs() / 1000U);
    memorySecureZero(&reply_seed, sizeof(reply_seed));
    state->started = true;
}
