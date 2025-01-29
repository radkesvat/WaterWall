#include "receiver.h"
#include "wsocket.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "packet_types.h"
#include "utils/jsonutils.h"
#include "utils/stringutils.h"

typedef struct layer3_receiver_state_s
{
    char     *device_name;
    tunnel_t *device_tunnel;

} layer3_receiver_state_t;

typedef struct layer3_receiver_con_state_s
{
    void *_;
} layer3_receiver_con_state_t;

enum
{
    kCheckPackets = true
};

enum mode_dynamic_value_status
{
    kDvsSourceMode = kDvsFirstOption,
    kDvsDestMode
};


static void upStream(tunnel_t *self, context_t *c)
{
    // layer3_receiver_state_t *state = TSTATE(self);
    (void) (self);

    packet_mask *packet = (packet_mask *) (sbufGetMutablePtr(c->payload));

    /*      im not sure these checks are necessary    */
    if (kCheckPackets)
    {
        if (packet->ip4_header.version == 4)
        {
            if (UNLIKELY(sbufGetBufLength(c->payload) < sizeof(struct ipv4header)))
            {
                LOGW("Layer3Receiver: dropped a ipv4 packet that was too small");
                reuseContextPayload(c);
                destroyContext(c);
                return;
            }
        }
        else if (packet->ip6_header.version == 6)
        {

            if (UNLIKELY(sbufGetBufLength(c->payload) < sizeof(struct ipv6header)))
            {
                LOGW("Layer3Receiver: dropped a ipv6 packet that was too small");
                reuseContextPayload(c);
                destroyContext(c);
                return;
            }
        }
        else
        {
            LOGW("Layer3Receiver: dropped a non ip protocol packet");
            reuseContextPayload(c);
            destroyContext(c);
            return;
        }
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

tunnel_t *newLayer3Receiver(node_instance_context_t *instance_info)
{
    layer3_receiver_state_t *state = memoryAllocate(sizeof(layer3_receiver_state_t));
    memorySet(state, 0, sizeof(layer3_receiver_state_t));
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Layer3Receiver->settings (object field) : The object was empty or invalid");
        memoryFree(state);
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->device_name), settings, "device"))
    {
        LOGF("JSON Error: Layer3Receiver->settings->device (string field) : The string was empty or invalid");
        memoryFree(state);
        return NULL;
    }

    hash_t  hash_tdev_name = calcHashBytes(state->device_name, strlen(state->device_name));
    node_t *tundevice_node = nodemanagerGetNode(instance_info->node_manager_config, hash_tdev_name);
    
    if (tundevice_node == NULL)
    {
        LOGF("Layer3Receiver: could not find tun device node \"%s\"", state->device_name);
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

    if (tundevice_node->instance->up != NULL)
    {
        LOGF("Layer3Receiver: tun device \"%s\" cannot be used by 2 receivers", state->device_name);
        memoryFree(state);
        return NULL;
    }

    state->device_tunnel = tundevice_node->instance;

    tunnel_t *t = tunnelCreate();

    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    tunnelBind(tundevice_node->instance, t);

    return t;
}

api_result_t apiLayer3Receiver(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyLayer3Receiver(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataLayer3Receiver(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = kNodeFlagChainHead};
}
