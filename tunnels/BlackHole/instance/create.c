#include "structure.h"

#include "loggers/network_logger.h"

static bool parseBlackHoleMode(blackhole_tstate_t *state, const cJSON *settings)
{
    const cJSON *mode = cJSON_GetObjectItemCaseSensitive(settings, "mode");

    if (! (cJSON_IsString(mode) && mode->valuestring != NULL))
    {
        LOGF("BlackHole: settings.mode is required");
        return false;
    }

    const char *value = mode->valuestring;

    if (strcasecmp(value, "passive") == 0 || strcasecmp(value, "drop") == 0 || strcasecmp(value, "packet-drop") == 0 ||
        strcasecmp(value, "silent") == 0 || strcasecmp(value, "calm") == 0)
    {
        state->mode = kBlackHoleModePassive;
        return true;
    }

    if (strcasecmp(value, "active") == 0 || strcasecmp(value, "close") == 0 || strcasecmp(value, "aggressive") == 0 ||
        strcasecmp(value, "kill") == 0 || strcasecmp(value, "kill-connection") == 0)
    {
        state->mode = kBlackHoleModeActive;
        return true;
    }

    LOGF("BlackHole: settings.mode must be passive/drop/packet-drop/silent/calm or "
         "active/close/aggressive/kill/kill-connection");
    return false;
}

tunnel_t *blackholeTunnelCreate(node_t *node)
{
    tunnel_t *t = tunnelCreate(node, sizeof(blackhole_tstate_t), sizeof(blackhole_lstate_t));
    if (t == NULL)
    {
        return NULL;
    }

    t->fnInitU    = &blackholeTunnelUpStreamInit;
    t->fnEstU     = &blackholeTunnelUpStreamEst;
    t->fnFinU     = &blackholeTunnelUpStreamFinish;
    t->fnPayloadU = &blackholeTunnelUpStreamPayload;
    t->fnPauseU   = &blackholeTunnelUpStreamPause;
    t->fnResumeU  = &blackholeTunnelUpStreamResume;

    t->fnInitD    = &blackholeTunnelDownStreamInit;
    t->fnEstD     = &blackholeTunnelDownStreamEst;
    t->fnFinD     = &blackholeTunnelDownStreamFinish;
    t->fnPayloadD = &blackholeTunnelDownStreamPayload;
    t->fnPauseD   = &blackholeTunnelDownStreamPause;
    t->fnResumeD  = &blackholeTunnelDownStreamResume;

    t->onStop    = &blackholeTunnelOnStop;
    t->onDestroy = &blackholeTunnelDestroy;

    blackhole_tstate_t *state = tunnelGetState(t);

    if (! parseBlackHoleMode(state, node->node_settings_json))
    {
        tunnelDestroy(t);
        return NULL;
    }

    return t;
}
