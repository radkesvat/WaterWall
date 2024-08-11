#include "raw_device.h"
#include "loggers/network_logger.h"
#include "packet_types.h"
#include "utils/jsonutils.h"
#include "ww/devices/raw/raw.h"

#define LOG_PACKET_INFO 1

enum rawdevice_mode_dynamic_value_status
{
    kDvsRead = kDvsFirstOption,
    kDvsWrite,
    kDvsReadWrite
};

typedef struct raw_device_state_s
{
    raw_device_t *rdev;
    line_t      **thread_lines;
    char         *name;
    unsigned int  subnet_mask;

} raw_device_state_t;

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

        ret = snprintf(ptr, rem, "Received: => From %s to %s, Data: ", src_ip, dst_ip);
    }
    else if (version == 6)
    {
        struct ipv6header *ip6_header = (struct ipv6header *) buffer;

        inet_ntop(AF_INET6, &ip6_header->saddr, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->daddr, dst_ip, INET6_ADDRSTRLEN);

        ret = snprintf(ptr, rem, "Received:  From %s to %s, Data: ", src_ip, dst_ip);
    }
    else
    {
        ret = snprintf(ptr, rem, "Received: => Unknown IP version, Data: ");
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
    raw_device_state_t *state = TSTATE((tunnel_t *) self);

    raw_device_t *rdev = state->rdev;
    writeToRawDevce(rdev, c->payload);

    dropContexPayload(c);
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

static void onIPPacketReceived(struct raw_device_s *rdev, void *userdata, shift_buffer_t *buf, tid_t tid)
{
    (void) rdev;
    tunnel_t           *self  = userdata;
    raw_device_state_t *state = TSTATE((tunnel_t *) self);

#if LOG_PACKET_INFO
    printIPPacketInfo(rawBuf(buf), bufLen(buf));
#endif

    // reuseBuffer(getWorkerBufferPool(tid), buf);

    context_t *ctx = newContext(state->thread_lines[tid]);
    ctx->payload   = buf;
    self->up->upStream(self->up, ctx);
}

tunnel_t *newRawDevice(node_instance_context_t *instance_info)
{
    raw_device_state_t *state = globalMalloc(sizeof(raw_device_state_t));
    memset(state, 0, sizeof(raw_device_state_t));

    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: RawDevice->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    // not forced
    getStringFromJsonObject(&(state->name), settings, "device-name");
    uint32_t fwmark = 0;
    getIntFromJsonObjectOrDefault((int *) &fwmark, settings, "mark", 0);

    dynamic_value_t mode = parseDynamicNumericValueFromJsonObject(settings, "mode", 3, "R", "W", "RW");
    if ((int) mode.status < kDvsRead)
    {
        LOGF("JSON Error: RawDevice->settings->mode (string field) : mode is not specified or invalid");
        return NULL;
    }

    state->thread_lines = globalMalloc(sizeof(line_t *) * WORKERS_COUNT);
    for (unsigned int i = 0; i < WORKERS_COUNT; i++)
    {
        state->thread_lines[i] = newLine(i);
    }

    tunnel_t *t = newTunnel();

    if ((int) mode.status == kDvsRead || (int) mode.status == kDvsReadWrite)
    {
        state->rdev = createRawDevice(state->name, fwmark, t, onIPPacketReceived);
    }
    else
    {
        state->rdev = createRawDevice(state->name, fwmark, t, NULL);
    }

    if (state->rdev == NULL)
    {
        LOGF("RawDevice: could not create device");
        return NULL;
    }
    bringRawDeviceUP(state->rdev);

    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiRawDevice(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyRawDevice(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataRawDevice(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
