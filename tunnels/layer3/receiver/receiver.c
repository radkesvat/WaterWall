#include "receiver.h"
#include "hsocket.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "utils/jsonutils.h"
#include "utils/stringutils.h"

typedef struct layer3_receiver_state_s
{
    char     *tundevice_name;
    tunnel_t *tun_device_tunnel;

} layer3_receiver_state_t;

typedef struct layer3_receiver_con_state_s
{
    void *_;
} layer3_receiver_con_state_t;

enum mode_dynamic_value_status
{
    kDvsSourceMode = kDvsFirstOption,
    kDvsDestMode
};

static void upStream(tunnel_t *self, context_t *c)
{
    // layer3_receiver_state_t *state = TSTATE(self);
    (void) (self);

    LOGD("got a packet");
    if (c->payload)
    {
        dropContexPayload(c);
    }
    destroyContext(c);

    // self->up->upStream(self->up, c);
}

static void downStream(tunnel_t *self, context_t *c)
{
    (void) (self);
    (void) (c);
    assert(false);

    if (c->payload)
    {
        dropContexPayload(c);
    }
    destroyContext(c);
}

tunnel_t *newLayer3Receiver(node_instance_context_t *instance_info)
{
    layer3_receiver_state_t *state = globalMalloc(sizeof(layer3_receiver_state_t));
    memset(state, 0, sizeof(layer3_receiver_state_t));
    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Layer3Receiver->settings (object field) : The object was empty or invalid");
        globalFree(state);
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->tundevice_name), settings, "device"))
    {
        LOGF("JSON Error: Layer3Receiver->settings->device (string field) : The string was empty or invalid");
        globalFree(state);
        return NULL;
    }

    hash_t  hash_tdev_name = CALC_HASH_BYTES(state->tundevice_name, strlen(state->tundevice_name));
    node_t *tundevice_node = getNode(instance_info->node_manager_config, hash_tdev_name);
    if (tundevice_node == NULL)
    {
        LOGF("Layer3Receiver: could not find tun device node \"%s\"", state->tundevice_name);
        globalFree(state);
        return NULL;
    }

    if (tundevice_node->instance != NULL)
    {
        LOGF("Layer3Receiver: tun device \"%s\" cannot be used by 2 receivers", state->tundevice_name);
        globalFree(state);
        return NULL;
    }
    runNode(instance_info->node_manager_config, tundevice_node, 0);

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

    chain(tundevice_node->instance, t);

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
