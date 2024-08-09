#include "sender.h"
#include "hsocket.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "packet_types.h"
#include "utils/jsonutils.h"
#include "utils/mathutils.h"

typedef struct layer3_senderstate_s
{
    char     *tundevice_name;
    tunnel_t *tun_device_tunnel;

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

    for (int i = 0; i < (int) min(len,640); i++)
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
    printSendingIPPacketInfo(rawBuf(c->payload),bufLen(c->payload));
    // reuseContextPayload(c);
    // shift_buffer_t* buf = popBuffer(getContextBufferPool(c));
    // writeRaw(buf, const void *const restrict buffer, const unsigned int len)
    packet_mask *packet = (packet_mask *) (rawBufMut(c->payload));

    if (packet->ip4_header.version == 4)
    {
        int ip_header_len = packet->ip4_header.ihl * 4;
        packet->ip4_header.check = standardCheckSum((void *) packet, ip_header_len);
    }

    state->tun_device_tunnel->upStream(state->tun_device_tunnel, c);
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

tunnel_t *newLayer3Sender(node_instance_context_t *instance_info)
{
    layer3_senderstate_t *state = globalMalloc(sizeof(layer3_senderstate_t));
    memset(state, 0, sizeof(layer3_senderstate_t));
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Layer3Sender->settings (object field) : The object was empty or invalid");
        globalFree(state);
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->tundevice_name), settings, "device"))
    {
        LOGF("JSON Error: Layer3Sender->settings->device (string field) : The string was empty or invalid");
        globalFree(state);
        return NULL;
    }

    hash_t  hash_tdev_name = CALC_HASH_BYTES(state->tundevice_name, strlen(state->tundevice_name));
    node_t *tundevice_node = getNode(instance_info->node_manager_config, hash_tdev_name);
    if (tundevice_node == NULL)
    {
        LOGF("Layer3Sender: could not find tun device node \"%s\"", state->tundevice_name);
        globalFree(state);
        return NULL;
    }

    if (tundevice_node->instance == NULL)
    {
        runNode(instance_info->node_manager_config, tundevice_node, 0);
    }

    if (tundevice_node->instance == NULL)
    {
        globalFree(state);
        return NULL;
    }

    state->tun_device_tunnel = tundevice_node->instance;

    tunnel_t *t = newTunnel();

    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

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
