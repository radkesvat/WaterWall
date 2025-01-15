#include "ip_manipulator.h"
#include "loggers/network_logger.h"
#include "packet_types.h"
#include "utils/jsonutils.h"

/*****************************************************************************
| Protocol Number | Protocol Name                                            |
|-----------------|----------------------------------------------------------|
| 1               | ICMP (Internet Control Message Protocol)                 |
| 2               | IGMP (Internet Group Management Protocol)                |
| 6               | TCP (Transmission Control Protocol)                      |
| 8               | EGP (Exterior Gateway Protocol)                          |
| 17              | UDP (User Datagram Protocol)                             |
| 27              | RDP (Reliable Datagram Protocol)                         |
| 33              | DCCP (Datagram Congestion Control Protocol)              |
| 41              | IPv6 encapsulation                                       |
| 43              | Fragment Header for IPv6                                 |
| 44              | RSVP (Resource Reservation Protocol)                     |
| 47              | GRE (Generic Routing Encapsulation)                      |
| 50              | ESP (Encapsulating Security Payload)                     |
| 51              | AH (Authentication Header)                               |
| 58              | ICMPv6 (ICMP for IPv6)                                   |
| 59              | No Next Header for IPv6                                  |
| 60              | Destination Options for IPv6                             |
| 88              | EIGRP (Enhanced Interior Gateway Routing Protocol)       |
| 89              | OSPF (Open Shortest Path First)                          |
| 94              | IPIP (IP-in-IP encapsulation)                            |
| 103             | PIM (Protocol Independent Multicast)                     |
| 108             | PCAP (Packet Capture)                                    |
| 112             | VRRP (Virtual Router Redundancy Protocol)                |
| 115             | L2TP (Layer 2 Tunneling Protocol)                        |
| 124             | ISIS (Intermediate System to Intermediate System)        |
| 132             | SCTP (Stream Control Transmission Protocol)              |
| 133             | FC (Fibre Channel)                                       |
| 136             | UDPLite (Lightweight User Datagram Protocol)             |
| 137             | MPLS-in-IP (Multiprotocol Label Switching encapsulation) |
| 138             | MANET (Mobile Ad Hoc Networks)                           |
| 139             | HIP (Host Identity Protocol)                             |
| 140             | Shim6 (Site Multihoming by IPv6 Intermediation)          |
| 141             | WESP (Wrapped Encapsulating Security Payload)            |
| 142             | ROHC (Robust Header Compression)                         |
| 253             | Use for experimentation and testing (RFC 3692)           |
| 254             | Use for experimentation and testing (RFC 3692)           |
| 255             | Reserved                                                 |
*****************************************************************************/

enum protocol_dynamic_value_status
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

typedef struct layer3_ip_manipulator_state_s
{
    dynamic_value_t protocol_action;

} layer3_ip_manipulator_state_t;

typedef struct layer3_ip_manipulator_con_state_s
{
    void *_;

} layer3_ip_manipulator_con_state_t;

static inline void handleProtocolAction4(struct ipv4header *ip_header, dynamic_value_t *protocol_action)
{
    if (protocol_action->status != kDvsEmpty)
    {
        ip_header->protocol = protocol_action->value;
    }
}

static inline void handleProtocolAction6(struct ipv6header *ip_header, dynamic_value_t *protocol_action)
{
    if (protocol_action->status != kDvsEmpty)
    {
        ip_header->nexthdr = protocol_action->value;
    }
}

static void upStream(tunnel_t *self, context_t *c)
{
    layer3_ip_manipulator_state_t *state = TSTATE(self);

    packet_mask *packet = (packet_mask *) (sbufGetMutablePtr(c->payload));

    if (packet->ip4_header.version == 4)
    {
        handleProtocolAction4(&packet->ip4_header, &state->protocol_action);
    }
    else if (packet->ip6_header.version == 6)
    {
        handleProtocolAction6(&packet->ip6_header, &state->protocol_action);
    }
    else
    {
        LOGF("IPManipulator: non ip packets is assumed to be pre-filtered by receiver node");
        exit(1);
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

tunnel_t *newLayer3IpManipulator(node_instance_context_t *instance_info)
{
    layer3_ip_manipulator_state_t *state = memoryAllocate(sizeof(layer3_ip_manipulator_state_t));
    memorySet(state, 0, sizeof(layer3_ip_manipulator_state_t));
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Layer3IpManipulator->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    state->protocol_action = parseDynamicNumericValueFromJsonObject(
        settings, "protocol", 36, "icmp", "igmp", "tcp", "egp", "udp", "rdp", "dccp", "ipv6", "ipv6-frag", "rsvp",
        "gre", "esp", "ah", "icmpv6", "nonext", "destopts", "eigrp", "ospf", "ipip", "pim", "pcap", "vrrp", "l2tp",
        "isis", "sctp", "fc", "udplite", "mpls", "manet", "hip", "shim6", "wesp", "rohc", "test1", "test2", "reserved");

    int map_array[36] = {1,  2,   6,   8,   17,  27,  33,  41,  43,  44,  47,  50,  51,  58,  59,  60,  88,  89,
                         94, 103, 108, 112, 115, 124, 132, 133, 136, 137, 138, 139, 140, 141, 142, 253, 254, 255};

    if (state->protocol_action.status > kDvsConstant)
    {
        state->protocol_action.value = map_array[state->protocol_action.status - kDvsFirstOption];
    }

    tunnel_t *t = newTunnel();

    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiLayer3IpManipulator(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyLayer3IpManipulator(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataLayer3IpManipulator(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
