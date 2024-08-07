#include "tun_device.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "utils/jsonutils.h"
#include "utils/sockutils.h"
#include "ww/devices/tun/tun.h"

#define LOG_PACKET_INFO 1

typedef struct tun_device_state_s
{
    tun_device_t *tdev;
    line_t      **thread_lines;

    char        *name;
    char        *ip_subnet;
    char        *ip_present;
    unsigned int subnet_mask;

} tun_device_state_t;

static void upStream(tunnel_t *self, context_t *c)
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

static void onIPPacketReceived(struct tun_device_s *tdev, void *userdata, shift_buffer_t *buf, tid_t tid)
{
    (void) tdev;
    tunnel_t* self = userdata;
    tun_device_state_t *state = TSTATE((tunnel_t*)self);


#if LOG_PACKET_INFO
    printIPPacketInfo(tdev->name, rawBuf(buf));
#endif

    // reuseBuffer(getWorkerBufferPool(tid), buf);

    context_t* ctx = newContext(state->thread_lines[tid]);
    ctx->payload = buf;
    self->up->upStream(self->up, ctx);
}

tunnel_t *newTunDevice(node_instance_context_t *instance_info)
{
    tun_device_state_t *state = globalMalloc(sizeof(tun_device_state_t));
    memset(state, 0, sizeof(tun_device_state_t));

    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: TunDevice->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->name), settings, "device-name"))
    {
        LOGF("JSON Error: TunDevice->settings->device-name (string field) : The data was empty or invalid");
        return NULL;
    }

    if (! getStringFromJsonObject(&(state->ip_subnet), settings, "device-ip"))
    {
        LOGF("JSON Error: TunDevice->settings->device-name (string field) : The data was empty or invalid");
        return NULL;
    }
    verifyIpCdir(state->ip_subnet, getNetworkLogger());

    char *slash        = strchr(state->ip_subnet, '/');
    slash[0]           = 0x0;
    state->ip_present  = strdup(state->ip_subnet);
    slash[0]           = '/';
    char *subnet_part  = slash + 1;
    state->subnet_mask = atoi(subnet_part);

    state->thread_lines = globalMalloc(sizeof(line_t *) * WORKERS_COUNT);
    for (unsigned int i = 0; i < WORKERS_COUNT; i++)
    {
        state->thread_lines[i] = newLine(i);
    }

    state->tdev = createTunDevice(state->name, false, state, onIPPacketReceived);
    assignIpToTunDevice(state->tdev, state->ip_present, state->subnet_mask);
    bringTunDeviceUP(state->tdev);

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
