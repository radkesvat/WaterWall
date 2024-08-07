#include "ip_overrider.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "utils/stringutils.h"
#include <endian.h>

typedef struct layer3_ip_overrider_state_s
{

    bool            dest_mode;
    bool            support4;
    bool            support6;
    struct in6_addr ov_6;
    uint32_t        ov_4;

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

static void upStream(tunnel_t *self, context_t *c)
{
    layer3_ip_overrider_state_t *state = TSTATE(self);

    struct ipv4hdr *ip4_header = (struct ipv4hdr *) (rawBufMut(c->payload));
    struct ipv6hdr *ip6_header = (struct ipv6hdr *) (rawBufMut(c->payload));

    if (WW_UNLIKELY(bufLen(c->payload) < 1))
    {
        LOGW("Layer3IpOverrider: dropped a packet that was too small");
        dropContexPayload(c);
        destroyContext(c);
        return;
    }

    bool isv4 = ip4_header->version == 4;

    if (isv4)
    {
        if (! state->support4)
        {
            goto bypass;
        }
        if (WW_UNLIKELY(bufLen(c->payload) < sizeof(struct ipv4hdr)))
        {
            LOGW("Layer3IpOverrider: dropped a packet that was too small");
            dropContexPayload(c);
            destroyContext(c);
            return;
        }
    }
    else
    {
        if (! state->support6)
        {
            goto bypass;
        }
        if (WW_UNLIKELY(ip4_header->version != 6))
        {
            LOGW("Layer3IpOverrider: dropped a non ip protocol packet");
            dropContexPayload(c);
            destroyContext(c);
            return;
        }
        if (WW_UNLIKELY(bufLen(c->payload) < sizeof(struct ipv6hdr)))
        {
            LOGW("Layer3IpOverrider: dropped a packet that was too small");
            dropContexPayload(c);
            destroyContext(c);
            return;
        }
    }

bypass:

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

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
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
