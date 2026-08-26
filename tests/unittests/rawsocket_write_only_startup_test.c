#include "RawSocket/structure.h"

static capture_device_t fake_capture_device;
static raw_device_t     fake_raw_device;
static bool             fake_raw_device_up;
static unsigned int     capture_call_count;
static unsigned int     raw_create_count;
static unsigned int     raw_bring_up_count;
static unsigned int     raw_stop_request_count;
static unsigned int     raw_bring_down_count;
static unsigned int     raw_destroy_count;

capture_device_t *__wrap_caputredeviceCreate(const char *name, const ipmask_t *capture_ranges,
                                             uint32_t capture_range_count, bool skip_sysctl, void *userdata,
                                             CaptureReadEventHandle cb);
bool              __wrap_caputredeviceBringUp(capture_device_t *cdev);
bool              __wrap_capturedeviceRequestStop(capture_device_t *cdev);
bool              __wrap_caputredeviceBringDown(capture_device_t *cdev);
void              __wrap_capturedeviceDestroy(capture_device_t *cdev);
raw_device_t     *__wrap_rawdeviceCreate(const char *name, uint32_t mark, void *userdata);
bool              __wrap_rawdeviceBringUp(raw_device_t *rdev);
void              __wrap_rawdeviceRequestStop(raw_device_t *rdev);
bool              __wrap_rawdeviceBringDown(raw_device_t *rdev);
void              __wrap_rawdeviceDestroy(raw_device_t *rdev);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void noopPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;
    discard buf;
}

void rawsocketOnIPPacketReceived(struct capture_device_s *cdev, void *userdata, sbuf_t *buf, wid_t wid)
{
    discard cdev;
    discard userdata;
    discard buf;
    discard wid;
}

capture_device_t *__wrap_caputredeviceCreate(const char *name, const ipmask_t *capture_ranges,
                                             uint32_t capture_range_count, bool skip_sysctl, void *userdata,
                                             CaptureReadEventHandle cb)
{
    discard name;
    discard capture_ranges;
    discard capture_range_count;
    discard skip_sysctl;
    discard userdata;
    discard cb;
    ++capture_call_count;
    return &fake_capture_device;
}

bool __wrap_caputredeviceBringUp(capture_device_t *cdev)
{
    discard cdev;
    ++capture_call_count;
    return true;
}

bool __wrap_capturedeviceRequestStop(capture_device_t *cdev)
{
    discard cdev;
    ++capture_call_count;
    return true;
}

bool __wrap_caputredeviceBringDown(capture_device_t *cdev)
{
    discard cdev;
    ++capture_call_count;
    return true;
}

void __wrap_capturedeviceDestroy(capture_device_t *cdev)
{
    discard cdev;
    ++capture_call_count;
}

raw_device_t *__wrap_rawdeviceCreate(const char *name, uint32_t mark, void *userdata)
{
    require(name != NULL, "RawSocket did not pass a raw device name in write-only mode");
    require(mark == 11, "RawSocket passed the wrong firewall mark in write-only mode");
    require(userdata != NULL, "RawSocket did not pass tunnel userdata to the raw device");
    ++raw_create_count;
    fake_raw_device    = (raw_device_t) {0};
    fake_raw_device_up = false;
    return &fake_raw_device;
}

bool __wrap_rawdeviceBringUp(raw_device_t *rdev)
{
    require(rdev == &fake_raw_device, "RawSocket brought up an unexpected raw device");
    require(! fake_raw_device_up, "RawSocket brought up the raw device twice");
    ++raw_bring_up_count;
    fake_raw_device_up = true;
    return true;
}

void __wrap_rawdeviceRequestStop(raw_device_t *rdev)
{
    require(rdev == &fake_raw_device, "RawSocket stopped an unexpected raw device");
    require(fake_raw_device_up, "RawSocket requested stop after the raw device was already down");
    ++raw_stop_request_count;
}

bool __wrap_rawdeviceBringDown(raw_device_t *rdev)
{
    require(rdev == &fake_raw_device, "RawSocket brought down an unexpected raw device");
    require(fake_raw_device_up, "RawSocket brought down a raw device that was not up");
    ++raw_bring_down_count;
    fake_raw_device_up = false;
    return true;
}

void __wrap_rawdeviceDestroy(raw_device_t *rdev)
{
    require(rdev == &fake_raw_device, "RawSocket destroyed an unexpected raw device");
    require(! fake_raw_device_up, "RawSocket destroyed the raw device while it was still up");
    ++raw_destroy_count;
}

int main(void)
{
    node_t node = {.next = NULL};

    tunnel_t *t = packettunnelCreate(&node, sizeof(rawsocket_tstate_t), 0);
    require(t != NULL, "failed to create the write-only RawSocket test tunnel");
    require(packettunnelConfigureLifecycleAnchor(t, "RawSocket", noopPayload, kPacketLifecycleAnchorPublishDownstream),
            "failed to configure the write-only RawSocket packet anchor");

    char                raw_name[] = "write-only-raw";
    rawsocket_tstate_t *state      = tunnelGetState(t);
    state->raw_device_name         = raw_name;
    state->firewall_mark           = 11;

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    rawsocketOnStart(t);
    const ww_startup_result_t result = wwStartupContextEnd(&startup);

    require(wwStartupSucceeded(result), "write-only RawSocket startup failed");
    require(capture_call_count == 0, "write-only RawSocket executed capture-device code");
    require(raw_create_count == 1 && raw_bring_up_count == 1,
            "write-only RawSocket did not start exactly one raw writer");

    rawsocketOnQuiesceRequest(t, wwLifecycleProcessShutdown());
    rawsocketOnQuiesceWait(t, wwLifecycleProcessShutdown());
    require(capture_call_count == 0, "write-only RawSocket executed capture-device shutdown code");
    require(raw_stop_request_count == 1 && raw_bring_down_count == 1,
            "write-only RawSocket did not stop its raw writer cleanly");

    state->raw_device_name = NULL;
    rawsocketDestroy(t, wwLifecycleProcessShutdown());

    require(capture_call_count == 0, "write-only RawSocket executed capture-device destruction code");
    require(raw_destroy_count == 1, "write-only RawSocket did not destroy exactly one raw writer");
    return 0;
}
