#include "structure.h"

#include "loggers/network_logger.h"

tunnel_t *ipoverriderCreate(node_t *node)
{
    tunnel_t *t = packettunnelCreate(node, sizeof(ipoverrider_tstate_t), sizeof(ipoverrider_lstate_t));

    t->fnPayloadU = &ipoverriderUpStreamPayload;
    t->fnPayloadD = &ipoverriderDownStreamPayload;
    t->onPrepair  = &ipoverriderOnPrepair;
    t->onStart    = &ipoverriderOnStart;
    t->onDestroy  = &ipoverriderDestroy;

    ipoverrider_tstate_t *state = tunnelGetState(t);

    const cJSON *settings = node->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Layer3IpOverrider->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    dynamic_value_t directon_dv = parseDynamicNumericValueFromJsonObject(settings, "direction", 2, "up", "down");
    if (directon_dv.status != kDvsUp && directon_dv.status != kDvsDown)
    {
        LOGF("Layer3IpOverrider: Layer3IpOverrider->settings->direction (string field)  must be either up or down ");
        exit(1);
    }

    dynamic_value_t mode_dv = parseDynamicNumericValueFromJsonObject(settings, "mode", 2, "source-ip", "dest-ip");

    if (mode_dv.status != kDvsDestMode && mode_dv.status != kDvsSourceMode)
    {
        LOGF("Layer3IpOverrider: Layer3IpOverrider->settings->mode (string field)  mode is not set or invalid, do you "
             "want to override source ip or dest ip?");
        exit(1);
    }

    if (directon_dv.status == kDvsUp)
    {
        t->fnPayloadU = (mode_dv.status == kDvsDestMode) ? &ipoverriderReplacerDestModeUpStreamPayload
                                                         : &ipoverriderReplacerSrcModeUpStreamPayload;
    }
    else
    {
        t->fnPayloadD = (mode_dv.status == kDvsDestMode) ? &ipoverriderReplacerDestModeDownStreamPayload
                                                         : &ipoverriderReplacerSrcModeDownStreamPayload;
    }

    dynamicvalueDestroy(mode_dv);

    char *ipbuf = NULL;

    if (getStringFromJsonObject(&ipbuf, settings, "ipv4"))
    {
        state->support4 = true;
        sockaddr_u sa;
        sockaddrSetIp(&(sa), ipbuf);

        memoryCopy(&(state->ov_4), &(sa.sin.sin_addr.s_addr), sizeof(sa.sin.sin_addr.s_addr));
        memoryFree(ipbuf);
        ipbuf = NULL;
    }
    else if (getStringFromJsonObject(&ipbuf, settings, "ipv6"))
    {
        state->support6 = true;
        sockaddr_u sa;
        sockaddrSetIp(&(sa), ipbuf);

        memoryCopy(&(state->ov_6), &(sa.sin6.sin6_addr.s6_addr), sizeof(sa.sin6.sin6_addr.s6_addr));
        memoryFree(ipbuf);
        ipbuf = NULL;
    }
    else
    {
        LOGF("RawSocket: please give the  ip, use ipv4 or ipv6 json keys");
        return NULL;
    }

    return t;
}
