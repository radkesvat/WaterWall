#include "caputre_device.h"
#include "frand.h"
#include "loggers/network_logger.h"
#include "managers/signal_manager.h"
#include "packet_types.h"
#include "utils/jsonutils.h"

#include "ww/devices/capture/capture.h"

#define LOG_PACKET_INFO 0

enum capturedevice_direction_dynamic_value_status
{
    kDvsIncoming = kDvsFirstOption,
    kDvsOutgoing,
    kDvsBoth
};

enum capturedevice_filter_type_dynamic_value_status
{
    kDvsSourceIp = kDvsFirstOption,
    kDvsDestIp
};

static const char *ip_tables_enable_queue_mi  = "iptables -I INPUT -s %s -j NFQUEUE --queue-num %d";
static const char *ip_tables_disable_queue_mi = "iptables -D INPUT -s %s -j NFQUEUE --queue-num %d";

typedef struct capture_device_state_s
{
    capture_device_t *cdev;
    line_t          **thread_lines;
    char             *ip;
    char             *name;
    char             *exitcmd;
    uint32_t          queue_number;
    uint32_t          except_fwmark;

} capture_device_state_t;

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

        ret = snprintf(ptr, rem, "CaptureDevice Received: => From %s to %s, Data: ", src_ip, dst_ip);
    }
    else if (version == 6)
    {
        struct ipv6header *ip6_header = (struct ipv6header *) buffer;

        inet_ntop(AF_INET6, &ip6_header->saddr, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->daddr, dst_ip, INET6_ADDRSTRLEN);

        ret = snprintf(ptr, rem, "CaptureDevice Received:  From %s to %s, Data: ", src_ip, dst_ip);
    }
    else
    {
        ret = snprintf(ptr, rem, "CaptureDevice Received: => Unknown IP version, Data: ");
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
    capture_device_state_t *state = TSTATE((tunnel_t *) self);

    capture_device_t *cdev = state->cdev;
    if (! writeToCaptureDevce(cdev, c->payload))
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

static void onIPPacketReceived(struct capture_device_s *cdev, void *userdata, sbuf_t *buf, tid_t tid)
{
    (void) cdev;
    tunnel_t               *self  = userdata;
    capture_device_state_t *state = TSTATE((tunnel_t *) self);

#if LOG_PACKET_INFO
    printIPPacketInfo(sbufGetRawPtr(buf), sbufGetBufLength(buf));
#endif

    // bufferpoolResuesbuf(getWorkerBufferPool(tid), buf);

    context_t *ctx = newContext(state->thread_lines[tid]);
    ctx->payload   = buf;
    self->up->upStream(self->up, ctx);
}

static void exitHook(void *userdata, int sig)
{
    (void) sig;
    capture_device_state_t *state = TSTATE((tunnel_t *) userdata);
    execCmd(state->exitcmd);
}

tunnel_t *newCaptureDevice(node_instance_context_t *instance_info)
{
    capture_device_state_t *state = memoryAllocate(sizeof(capture_device_state_t));
    memorySet(state, 0, sizeof(capture_device_state_t));

    cJSON *settings = instance_info->node_settings_json;

    if (! (cJSON_IsObject(settings) && settings->child != NULL))
    {
        LOGF("JSON Error: CaptureDevice->settings (object field) : The object was empty or invalid");
        return NULL;
    }

    // not forced
    getStringFromJsonObjectOrDefault(&(state->name), settings, "device-name", "unnamed-device");

    dynamic_value_t directoin =
        parseDynamicNumericValueFromJsonObject(settings, "direction", 3, "incoming", "outgoing", "bothdirections");

    if ((int) directoin.status < kDvsIncoming)
    {
        LOGF("JSON Error: CaptureDevice->settings->direction (string field) : direction is not specified or invalid");
        return NULL;
    }
    dynamic_value_t fmode = parseDynamicNumericValueFromJsonObject(settings, "filter-mode", 2, "source-ip", "dest-ip");
    if ((int) fmode.status < kDvsSourceIp)
    {
        LOGF("JSON Error: CaptureDevice->settings->filter-mode (string field) : mode is not specified or invalid");
        return NULL;
    }
    state->queue_number = 200 + (fastRand() % 200);
    state->ip           = NULL;
    if (! getStringFromJsonObject(&state->ip, settings, "ip"))
    {
        LOGF("JSON Error: CaptureDevice->settings->ip (string field) : mode is not specified or invalid");
    }

    char     *cmdbuf = memoryAllocate(200);
    tunnel_t *t      = newTunnel();

    if ((int) directoin.status == kDvsIncoming)
    {
        if ((int) fmode.status == kDvsSourceIp)
        {
            snprintf(cmdbuf, 100, ip_tables_enable_queue_mi, state->ip, (int) state->queue_number);
            if (execCmd(cmdbuf).exit_code != 0)
            {
                LOGF("CaptureDevicer: command failed: %s", cmdbuf);
                return NULL;
            }

            state->exitcmd = cmdbuf;
            snprintf(cmdbuf, 100, ip_tables_disable_queue_mi, state->ip, (int) state->queue_number);
            registerAtExitCallBack(exitHook, t);
        }
        else
        {
            // todo
        }
    }

    state->thread_lines = memoryAllocate(sizeof(line_t *) * WORKERS_COUNT);
    for (unsigned int i = 0; i < WORKERS_COUNT; i++)
    {
        state->thread_lines[i] = newLine(i);
    }

    state->cdev = createCaptureDevice(state->name, state->queue_number, t, onIPPacketReceived);

    if (state->cdev == NULL)
    {
        LOGF("CaptureDevice: could not create device");
        return NULL;
    }
    bringCaptureDeviceUP(state->cdev);

    t->state      = state;
    t->upStream   = &upStream;
    t->downStream = &downStream;

    return t;
}

api_result_t apiCaptureDevice(tunnel_t *self, const char *msg)
{
    (void) (self);
    (void) (msg);
    return (api_result_t) {0};
}

tunnel_t *destroyCaptureDevice(tunnel_t *self)
{
    (void) (self);
    return NULL;
}

tunnel_metadata_t getMetadataCaptureDevice(void)
{
    return (tunnel_metadata_t) {.version = 0001, .flags = 0x0};
}
