#include "ip_overrider.h"
#include "hsocket.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "utils/jsonutils.h"
#include "utils/stringutils.h"
#include <endian.h>

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

struct ipv4hdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ihl : 4;
    unsigned int version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version : 4;
    unsigned int ihl : 4;
#else
#error "byte order macro is not defined"
#endif
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
    /*The options start here. */
};

struct ipv6hdr
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t priority : 4, version : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version : 4, priority : 4;
#else
#error "byte order macro is not defined"
#endif
    uint8_t flow_lbl[3];

    uint16_t payload_len;
    uint8_t  nexthdr;
    uint8_t  hop_limit;

    struct in6_addr saddr;
    struct in6_addr daddr;
};

typedef union {
    struct ipv4hdr ip4_header;
    struct ipv6hdr ip6_header;

} packet_mask;

static void upStreamSrcMode(tunnel_t *self, context_t *c)
{
    layer3_ip_overrider_state_t *state = TSTATE(self);

    if (WW_UNLIKELY(bufLen(c->payload) < sizeof(struct ipv4hdr)))
    {
        LOGW("Layer3IpOverrider: dropped a packet that was too small");
        dropContexPayload(c);
        destroyContext(c);
        return;
    }
    packet_mask *packet = (packet_mask *) (rawBufMut(c->payload));

    if (packet->ip4_header.version == 4)
    {
        // alignment must be correct
        packet->ip4_header.saddr = state->ov_4;
    }
    else if (packet->ip4_header.version == 6)
    {
        if (WW_UNLIKELY(bufLen(c->payload) < sizeof(struct ipv6hdr)))
        {
            LOGW("Layer3IpOverrider: dropped a ipv6 packet that was too small");
            dropContexPayload(c);
            destroyContext(c);
            return;
        }
        // alignment must be correct
        packet->ip6_header.saddr = state->ov_6;
    }
    else
    {
        LOGW("Layer3IpOverrider: dropped a non ip protocol packet");
        dropContexPayload(c);
        destroyContext(c);
        return;
    }

    self->up->upStream(self->up, c);
}

enum mode_dynamic_value_status
{
    kDvsSourceMode = kDvsFirstOption,
    kDvsDestMode
};

static void upStreamDestMode(tunnel_t *self, context_t *c)
{
    layer3_ip_overrider_state_t *state = TSTATE(self);

    if (WW_UNLIKELY(bufLen(c->payload) < sizeof(struct ipv4hdr)))
    {
        LOGW("Layer3IpOverrider: dropped a packet that was too small");
        dropContexPayload(c);
        destroyContext(c);
        return;
    }
    packet_mask *packet = (packet_mask *) (rawBufMut(c->payload));

    if (packet->ip4_header.version == 4)
    {
        // alignment must be correct
        packet->ip4_header.daddr = state->ov_4;
    }
    else if (packet->ip4_header.version == 6)
    {
        if (WW_UNLIKELY(bufLen(c->payload) < sizeof(struct ipv6hdr)))
        {
            LOGW("Layer3IpOverrider: dropped a ipv6 packet that was too small");
            dropContexPayload(c);
            destroyContext(c);
            return;
        }

        // alignment must be correct
        packet->ip6_header.daddr = state->ov_6;
    }
    else
    {
        LOGW("Layer3IpOverrider: dropped a non ip protocol packet");
        dropContexPayload(c);
        destroyContext(c);
        return;
    }

    self->up->upStream(self->up, c);
}

static void downStream(tunnel_t *self, context_t *c)
{
    self->dw->downStream(self->dw, c);
}

tunnel_t *newLayer3IpOverrider(node_instance_context_t *instance_info)
{
    layer3_ip_overrider_state_t *state = globalMalloc(sizeof(layer3_ip_overrider_state_t));
    memset(state, 0, sizeof(layer3_ip_overrider_state_t));
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Layer3IpOverrider->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    dynamic_value_t mode_dv =
        parseDynamicNumericValueFromJsonObject(settings, "mode", 2, "dest-override", "src-override");

    if ((int) mode_dv.status != kDvsDestMode && (int) mode_dv.status != kDvsSourceMode)
    {
        LOGF("Layer3IpOverrider: Layer3IpOverrider->settings->mode (string field)  mode is not set or invalid, do you "
             "want to override source ip or dest ip?");
        exit(1);
    }

    char ipbuf[128];

    if (getStringFromJsonObject((char **) &ipbuf, settings, "ipv4"))
    {
        state->support4 = true;
        sockaddr_u sa;
        sockaddr_set_ip(&(sa), ipbuf);

        memcpy(&(state->ov_4), &(sa.sin.sin_addr.s_addr), sizeof(sa.sin.sin_addr.s_addr));
    }

    if (getStringFromJsonObject((char **) &ipbuf, settings, "ipv6"))
    {
        state->support6 = true;
        sockaddr_u sa;
        sockaddr_set_ip(&(sa), ipbuf);

        memcpy(&(state->ov_6), &(sa.sin6.sin6_addr.s6_addr), sizeof(sa.sin6.sin6_addr.s6_addr));
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
