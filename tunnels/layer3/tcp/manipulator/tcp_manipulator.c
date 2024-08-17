#include "tcp_manipulator.h"
#include "frand.h"
#include "hsocket.h"
#include "loggers/network_logger.h"
#include "packet_types.h"
#include "utils/jsonutils.h"

enum bitaction_dynamic_value_status
{
    kDvsbaNothing = kDvsFirstOption,
    kDvsbaToggle,
    kDvsbaOn,
    kDvsbaOff
};

enum portaction_dynamic_value_status
{
    kDvspaCorrupt = kDvsFirstOption
};

typedef struct layer3_tcp_manipulator_state_s
{
    dynamic_value_t reset_bit_action;
    dynamic_value_t source_port_action;
    dynamic_value_t dest_port_action;
    int             corrupt_password;

} layer3_tcp_manipulator_state_t;

typedef struct layer3_tcp_manipulator_con_state_s
{
    void *_;

} layer3_tcp_manipulator_con_state_t;

static inline void handleResetBitAction(struct tcpheader *tcp_header, dynamic_value_t *reset_bit)
{
    switch ((enum bitaction_dynamic_value_status) reset_bit->status)
    {
    case kDvsbaOff:
        tcp_header->rst = 0;

        break;
    case kDvsbaOn:
        tcp_header->rst = 1;

        break;
    case kDvsbaToggle:
        tcp_header->rst = ! tcp_header->rst;

        break;
    default:
    case kDvsbaNothing:
        return;
        break;
    }
}

static inline void handleSourcePortAction(struct tcpheader *tcp_header, dynamic_value_t *source_port_action, int offset,
                                          const char *packet_end)
{
    switch ((int) source_port_action->status)
    {
    case kDvsConstant:
        tcp_header->source = source_port_action->value;

        break;
    case kDvspaCorrupt:
        tcp_header->source = tcp_header->source ^ *(int *) (packet_end - (offset));

        break;
    default:
        return;
        break;
    }
}
static inline void handleDestPortAction(struct tcpheader *tcp_header, dynamic_value_t *dest_port_action, int offset,
                                        const char *packet_end)
{
    switch ((int) dest_port_action->status)
    {
    case kDvsConstant:
        tcp_header->dest = dest_port_action->value;

        break;
    case kDvspaCorrupt:
        tcp_header->dest = tcp_header->dest ^ *(int *) (packet_end - (offset));

        break;
    default:
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
            LOGW("TcpManipulator: dropped an ipv4 packet, length is too short for TCP header");
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
            LOGW("TcpManipulator: dropped an ipv6 packet, length is too short for TCP header");
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
        LOGF("TcpManipulator: non ip packets is assumed to be pre-filtered by receiver node");
        exit(1);
    }

    struct tcpheader *tcp_header = (struct tcpheader *) (rawBufMut(c->payload) + ip_header_len);

    handleResetBitAction(tcp_header, &(state->reset_bit_action));

    handleSourcePortAction(tcp_header, &(state->source_port_action), state->corrupt_password,
                           ((const char *) rawBufMut(c->payload) + bufLen(c->payload)));

    handleDestPortAction(tcp_header, &(state->dest_port_action), state->corrupt_password,
                         ((const char *) rawBufMut(c->payload) + bufLen(c->payload)));

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

    state->source_port_action = parseDynamicNumericValueFromJsonObject(settings, "source-port", 1, "corrupt");
    state->dest_port_action   = parseDynamicNumericValueFromJsonObject(settings, "dest-port", 1, "corrupt");

    if (getIntFromJsonObjectOrDefault(&(state->corrupt_password), settings, "corruption-password", 0))
    {
        state->corrupt_password = max(0,state->corrupt_password);
        state->corrupt_password = state->corrupt_password % 29;
    }

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
