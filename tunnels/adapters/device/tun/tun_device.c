#include "tun_device.h"
#include "loggers/network_logger.h"
#include "packet_types.h"
#include "utils/jsonutils.h"

#include "ww/devices/tun/tun.h"

#define LOG_PACKET_INFO 0

typedef struct tun_device_state_s
{
    tun_device_t *tdev;
    line_t      **thread_lines;
    char         *name;
    char         *ip_subnet;
    char         *ip_present;
    unsigned int  subnet_mask;

} tun_device_state_t;

static void printIPPacketInfo(const unsigned char *buffer, unsigned int len)
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

        ret = snprintf(ptr, rem, "TunDevice Received: => From %s to %s, Data: ", src_ip, dst_ip);
    }
    else if (version == 6)
    {
        struct ipv6header *ip6_header = (struct ipv6header *) buffer;

        inet_ntop(AF_INET6, &ip6_header->saddr, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->daddr, dst_ip, INET6_ADDRSTRLEN);

        ret = snprintf(ptr, rem, "TunDevice Received:  From %s to %s, Data: ", src_ip, dst_ip);
    }
    else
    {
        ret = snprintf(ptr, rem, "TunDevice Received: => Unknown IP version, Data: ");
    }

    ptr += ret;
    rem -= ret;

    for (int i = 0; i < (int) min(len, 16); i++)
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
    tun_device_state_t *state = TSTATE((tunnel_t *) self);

    tun_device_t *tdev = state->tdev;
    if (! writeToTunDevce(tdev, c->payload))
    {
        reuseContextPayload(c);
    }
    else
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

static void onIPPacketReceived(struct tun_device_s *tdev, void *userdata, sbuf_t *buf, tid_t tid)
{
    (void) tdev;
    tunnel_t           *self  = userdata;
    tun_device_state_t *state = TSTATE((tunnel_t *) self);

#if LOG_PACKET_INFO
    printIPPacketInfo(sbufGetRawPtr(buf), sbufGetBufLength(buf));
#endif

    // bufferpoolResuesBuffer(getWorkerBufferPool(tid), buf);

    context_t *ctx = newContext(state->thread_lines[tid]);
    ctx->payload   = buf;
    self->up->upStream(self->up, ctx);
}

tunnel_t *newTunDevice(node_instance_context_t *instance_info)
{
    tun_device_state_t *state = memoryAllocate(sizeof(tun_device_state_t));
    memorySet(state, 0, sizeof(tun_device_state_t));

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
    verifyIPCdir(state->ip_subnet, getNetworkLogger());

    char *slash        = strchr(state->ip_subnet, '/');
    slash[0]           = 0x0;
    state->ip_present  = stringDuplicate(state->ip_subnet);
    slash[0]           = '/';
    char *subnet_part  = slash + 1;
    state->subnet_mask = atoi(subnet_part);

    state->thread_lines = memoryAllocate(sizeof(line_t *) * WORKERS_COUNT);
    for (unsigned int i = 0; i < WORKERS_COUNT; i++)
    {
        state->thread_lines[i] = newLine(i);
    }

    tunnel_t *t = tunnelCreate();

    state->tdev = createTunDevice(state->name, false, t, onIPPacketReceived);

    if (state->tdev == NULL)
    {
        LOGF("TunDevice: could not create device");
        return NULL;
    }
    assignIpToTunDevice(state->tdev, state->ip_present, state->subnet_mask);
    bringTunDeviceUP(state->tdev);

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
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
