#include "ip_overrider.h"
#include "wsocket.h"
#include "loggers/network_logger.h"
#include "packet_types.h"
#include "utils/jsonutils.h"

enum mode_dynamic_value_status
{
    kDvsSourceMode = kDvsFirstOption,
    kDvsDestMode
};

typedef struct layer3_ip_overrider_state_s
{

    struct in6_addr ov_6;
    uint32_t        ov_4;
    bool            support4;
    bool            support6;

} layer3_ip_overrider_state_t;

typedef struct layer3_ip_overrider_con_state_s
{
    void *_;

} layer3_ip_overrider_con_state_t;

static void upStreamSrcMode(tunnel_t *self, context_t *c)
{
    layer3_ip_overrider_state_t *state = TSTATE(self);

    packet_mask *packet = (packet_mask *) (sbufGetMutablePtr(c->payload));

    if (state->support4 && packet->ip4_header.version == 4)
    {
        // alignment assumed to be correct
        packet->ip4_header.saddr = state->ov_4;
    }
    else if (state->support6 && packet->ip6_header.version == 6)
    {

        // alignment assumed to be correct
        packet->ip6_header.saddr = state->ov_6;
    }

    self->up->upStream(self->up, c);
}

static void upStreamDestMode(tunnel_t *self, context_t *c)
{
    layer3_ip_overrider_state_t *state = TSTATE(self);

    packet_mask *packet = (packet_mask *) (sbufGetMutablePtr(c->payload));

    if (packet->ip4_header.version == 4)
    {
        // alignment assumed to be correct
        packet->ip4_header.daddr = state->ov_4;
    }
    else if (packet->ip6_header.version == 6)
    {

        // alignment assumed to be correct
        packet->ip6_header.daddr = state->ov_6;
    }

    self->up->upStream(self->up, c);
}

static void downStream(tunnel_t *self, context_t *c)
{
    (void) (self);
    (void) (c);
    assert(false);

    if (c->payload)
    {
        reuseContextPayload(c);
    }
    destroyContext(c);
}

tunnel_t *newLayer3IpOverrider(node_instance_context_t *instance_info)
{
    layer3_ip_overrider_state_t *state = memoryAllocate(sizeof(layer3_ip_overrider_state_t));
    memorySet(state, 0, sizeof(layer3_ip_overrider_state_t));
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Layer3IpOverrider->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    dynamic_value_t mode_dv = parseDynamicNumericValueFromJsonObject(settings, "mode", 2, "source-ip", "dest-ip");

    if ((int) mode_dv.status != kDvsDestMode && (int) mode_dv.status != kDvsSourceMode)
    {
        LOGF("Layer3IpOverrider: Layer3IpOverrider->settings->mode (string field)  mode is not set or invalid, do you "
             "want to override source ip or dest ip?");
        exit(1);
    }
    destroyDynamicValue(mode_dv);


    char *ipbuf = NULL;

    if (getStringFromJsonObject(&ipbuf, settings, "ipv4"))
    {
        state->support4 = true;
        sockaddr_u sa;
        sockaddrSetIp(&(sa), ipbuf);

        memcpy(&(state->ov_4), &(sa.sin.sin_addr.s_addr), sizeof(sa.sin.sin_addr.s_addr));
        memoryFree(ipbuf);
        ipbuf = NULL;
    }

    if (getStringFromJsonObject(&ipbuf, settings, "ipv6"))
    {
        state->support6 = true;
        sockaddr_u sa;
        sockaddrSetIp(&(sa), ipbuf);

        memcpy(&(state->ov_6), &(sa.sin6.sin6_addr.s6_addr), sizeof(sa.sin6.sin6_addr.s6_addr));
        memoryFree(ipbuf);
        ipbuf = NULL;
    }

    tunnel_t *t = newTunnel();

    t->state      = state;
    t->upStream   = ((int) mode_dv.status == kDvsDestMode) ? &upStreamDestMode : &upStreamSrcMode;
    t->downStream = &downStream;

    return t;
}

api_result_t apiLayer3IpOverrider(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyLayer3IpOverrider(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataLayer3IpOverrider(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
