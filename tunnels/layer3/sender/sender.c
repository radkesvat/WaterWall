#include "sender.h"
#include "wsocket.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "packet_types.h"
#include "utils/jsonutils.h"


typedef struct layer3_senderstate_s
{
    char     *device_name;
    tunnel_t *device_tunnel;

} layer3_senderstate_t;

typedef struct layer3_sendercon_state_s
{
    void *_;
} layer3_sendercon_state_t;

static void printSendingIPPacketInfo(const unsigned char *buffer, unsigned int len)
{
    char  src_ip[INET6_ADDRSTRLEN];
    char  dst_ip[INET6_ADDRSTRLEN];
    char  logbuf[2048];
    int   rem = sizeof(logbuf);
    char *ptr = logbuf;
    int   ret;

    uint8_t version = buffer[0] >> 4;

    if (version == 4)
    {
        struct ipv4header *ip_header = (struct ipv4header *) buffer;

        inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_header->daddr, dst_ip, INET_ADDRSTRLEN);

        ret = snprintf(ptr, rem, "Sending: => From %s to %s, Data: ", src_ip, dst_ip);
    }
    else if (version == 6)
    {
        struct ipv6header *ip6_header = (struct ipv6header *) buffer;

        inet_ntop(AF_INET6, &ip6_header->saddr, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->daddr, dst_ip, INET6_ADDRSTRLEN);

        ret = snprintf(ptr, rem, "Sending:  From %s to %s, Data: ", src_ip, dst_ip);
    }
    else
    {
        ret = snprintf(ptr, rem, "Sending: => Unknown IP version, Data: ");
    }

    ptr += ret;
    rem -= ret;

    for (int i = 0; i < (int) min(len, 240); i++)
    {
        ret = snprintf(ptr, rem, "%02x ", buffer[i]);
        ptr += ret;
        rem -= ret;
    }
    *ptr = '\0';

    LOGD(logbuf);
}

static void upStream(tunnel_t *self, context_t *c)
{
    layer3_senderstate_t *state = TSTATE(self);

    // printSendingIPPacketInfo(sbufGetRawPtr(c->payload), sbufGetBufLength(c->payload));

    packet_mask *packet = (packet_mask *) (sbufGetMutablePtr(c->payload));
    unsigned int ip_header_len;

    /* Tcp checksum must be recalculated even if ip header is the only changed part of packet */

    if (packet->ip4_header.version == 4)
    {
        ip_header_len = packet->ip4_header.ihl * 4;

        packet->ip4_header.check = 0x0;
        packet->ip4_header.check = standardCheckSum((void *) packet, packet->ip4_header.ihl * 4);

        if (packet->ip4_header.protocol == 6)
        {
            struct tcpheader *tcp_header = (struct tcpheader *) (sbufGetMutablePtr(c->payload) + ip_header_len);
            tcpCheckSum4(&(packet->ip4_header), tcp_header);
        }
    }
    else if (packet->ip6_header.version == 6)
    {
        ip_header_len = sizeof(struct ipv6header);

        if (packet->ip6_header.nexthdr == 6)
        {
            struct tcpheader *tcp_header = (struct tcpheader *) (sbufGetMutablePtr(c->payload) + ip_header_len);
            tcpCheckSum6(&(packet->ip6_header), tcp_header);
        }
    }
    else
    {
        LOGF("Layer3Sender: non ip packets is assumed to be pre-filtered by receiver node");
        exit(1);
    }

    state->device_tunnel->upStream(state->device_tunnel, c);
}

static void downStream(tunnel_t *self, context_t *c)
{
    (void) (self);
    (void) (c);
    assert(false);

    if (c->payload)
    {
        contextReusePayload(c);
    }
    contextDestroy(c);
}

// only for debug and tests
static void onTimer(wtimer_t *timer)
{
    LOGD("sending...");
    tunnel_t             *self  = weventGetUserdata(timer);
    layer3_senderstate_t *state = TSTATE(self);
    line_t               *l     = newLine(0);
    context_t            *c     = contextCreate(l);
    c->payload                  = bufferpoolGetLargeBuffer(contextGetBufferPool(c));

    // unsigned char bpacket[] = {0x45, 0x00, 0x00, 0x2C, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0xC4, 0xC0, 0x00,
    // 0x02,
    //                            0x02, 0x22, 0xC2, 0x95, 0x43, 0x78, 0x0C, 0x00, 0x50, 0xF4, 0x70, 0x98, 0x8B, 0x00,
    //                            0x00, 0x00, 0x00, 0x60, 0x02, 0xFF, 0xFF, 0x18, 0xC6, 0x00, 0x00, 0x02, 0x04, 0x05,
    //                            0xB4};

    unsigned char bpacket[] = {0x45, 0x00, 0x00, 0x2C, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0xC4, 0x0A, 0x00, 0x00,
                               0x02, 0x22, 0xC2, 0x95, 0x43, 0x78, 0x0C, 0x00, 0x50, 0xF4, 0x70, 0x98, 0x8B, 0x00, 0x00,
                               0x00, 0x00, 0x60, 0x02, 0xFF, 0xFF, 0x18, 0xC6, 0x00, 0x00, 0x02, 0x04, 0x05, 0xB4};

    sbufSetLength(c->payload, sizeof(bpacket));
    sbufWrite(c->payload, bpacket, sizeof(bpacket));

    printSendingIPPacketInfo(sbufGetRawPtr(c->payload), sbufGetBufLength(c->payload));

    packet_mask *packet = (packet_mask *) (sbufGetMutablePtr(c->payload));

    packet->ip4_header.check = 0x0;

    int ip_header_len        = packet->ip4_header.ihl * 4;
    packet->ip4_header.check = standardCheckSum((void *) packet, ip_header_len);

    state->device_tunnel->upStream(state->device_tunnel, c);
}

tunnel_t *newLayer3Sender(node_instance_context_t *instance_info)
{
    layer3_senderstate_t *state = memoryAllocate(sizeof(layer3_senderstate_t));
    memorySet(state, 0, sizeof(layer3_senderstate_t));
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Layer3Sender->settings (object field) : The object was empty or invalid");
        memoryFree(state);
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->device_name), settings, "device"))
    {
        LOGF("JSON Error: Layer3Sender->settings->device (string field) : The string was empty or invalid");
        memoryFree(state);
        return NULL;
    }

    hash_t  hash_tdev_name = calcHashBytes(state->device_name, strlen(state->device_name));
    node_t *tundevice_node = nodemanagerGetNodeInstance(instance_info->node_manager_config, hash_tdev_name);

    if (tundevice_node == NULL)
    {
        LOGF("Layer3Sender: could not find tun device node \"%s\"", state->device_name);
        memoryFree(state);
        return NULL;
    }

    if (tundevice_node->instance == NULL)
    {
        nodemanagerRunNode(instance_info->node_manager_config, tundevice_node, 0);
    }

    if (tundevice_node->instance == NULL)
    {
        memoryFree(state);
        return NULL;
    }

    state->device_tunnel = tundevice_node->instance;

    tunnel_t *t = tunnelCreate();

    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    // for testing
    // wtimer_t *tm = wtimerAdd(getWorkerLoop(0), onTimer, 500, INFINITE);
    // weventSetUserData(tm, t);

    return t;
}

api_result_t apiLayer3Sender(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyLayer3Sender(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataLayer3Sender(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
