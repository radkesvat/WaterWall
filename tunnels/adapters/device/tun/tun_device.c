#include "tun_device.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "utils/stringutils.h"
#include "ww/devices/tun/tun.h"

typedef struct tun_device_state_s
{
    tun_device_t *tdev;

    const char  *name;
    const char  *ip_present;
    unsigned int subnet_mask;

} tun_device_state_t;

static void upStream(tunnel_t *self, context_t *c)
{
}

static void downStream(tunnel_t *self, context_t *c)
{
}

tunnel_t *newTunDevice(node_instance_context_t *instance_info)
{
    tun_device_state_t *state = globalMalloc(sizeof(tun_device_state_t));
    memset(state, 0, sizeof(tun_device_state_t));

    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: Listener->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    tunnel_t *t   = newTunnel();
    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiTunDevice(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyTunDevice(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataTunDevice(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = kNodeFlagChainHead};
}
