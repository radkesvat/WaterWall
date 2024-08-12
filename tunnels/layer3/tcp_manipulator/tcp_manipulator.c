#include "tcp_manipulator.h"
#include "hsocket.h"
#include "loggers/network_logger.h"
#include "packet_types.h"
#include "utils/jsonutils.h"

enum bitaction_dynamic_value_status
{
    kDvsNothing = kDvsFirstOption,
    kDvsToggle,
    kDvsOn,
    kDvsOff
};

typedef struct layer3_tcp_manipulator_state_s
{

    dynamic_value_t reset_bit_action;

} layer3_tcp_manipulator_state_t;

typedef struct layer3_tcp_manipulator_con_state_s
{
    void *_;

} layer3_tcp_manipulator_con_state_t;


static inline void handleResetBitAction(struct tcpheader *tcp_header, dynamic_value_t *reset_bit)
{
    switch ((enum bitaction_dynamic_value_status) reset_bit->status)
    {
    case kDvsOff:
        tcp_header->rst = 0;

        break;
    case kDvsOn:
        tcp_header->rst = 1;

        break;
    case kDvsToggle:
        tcp_header->rst = ! tcp_header->rst;

        break;
    default:
    case kDvsNothing:
        return;
        break;
    }
}

static void upStream(tunnel_t *self, context_t *c)
{
    layer3_tcp_manipulator_state_t *state = TSTATE(self);

    packet_mask *packet = (packet_mask *) (rawBufMut(c->payload));

    unsigned int ip_header_len;

    if (packet->ip4_header.version == 4)
    {
        ip_header_len = packet->ip4_header.ihl * 4;

        if (WW_UNLIKELY(bufLen(c->payload) < ip_header_len + sizeof(struct tcpheader)))
        {
            LOGE("TcpManipulator: ipv4 packet too short for TCP header");
            reuseContextPayload(c);
            destroyContext(c);
            return;
        }

        if (packet->ip4_header.protocol != 6)
        {
            // LOGD("TcpManipulator: ipv4 packet is not TCP");
            self->up->upStream(self->up, c);
            return;
        }
    }
    else if (packet->ip6_header.version == 6)
    {
        ip_header_len = sizeof(struct ipv6header);

        if (WW_UNLIKELY(bufLen(c->payload) < ip_header_len + sizeof(struct tcpheader)))
        {
            LOGE("TcpManipulator: ipv6 packet too short for TCP header");
            reuseContextPayload(c);
            destroyContext(c);
            return;
        }

        if (packet->ip6_header.nexthdr != 6)
        {
            // LOGD("TcpManipulator: ipv6 packet is not TCP");
            self->up->upStream(self->up, c);
            return;
        }
    }
    else
    {
        LOGF("TcpManipulator: non ip packets is assumed to be per filtered by receiver node");
        exit(1);
    }

    struct tcpheader *tcp_header            = (struct tcpheader *) (rawBufMut(c->payload) + ip_header_len);

    handleResetBitAction(tcp_header, &(state->reset_bit_action));

    // reCalculateCheckSum(tcp_header, transport_palyoad_len);

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

tunnel_t *newLayer3TcpManipulator(node_instance_context_t *instance_info)
{
    layer3_tcp_manipulator_state_t *state = globalMalloc(sizeof(layer3_tcp_manipulator_state_t));
    memset(state, 0, sizeof(layer3_tcp_manipulator_state_t));
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Layer3TcpManipulator->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    state->reset_bit_action =
        parseDynamicNumericValueFromJsonObject(settings, "bit-reset", 4, "nothing", "toggle", "on", "off");

    tunnel_t *t = newTunnel();

    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiLayer3TcpManipulator(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyLayer3TcpManipulator(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataLayer3TcpManipulator(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
