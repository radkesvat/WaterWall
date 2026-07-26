#include "RawSocket/structure.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int notify_fd = -1;

static capture_device_t fake_capture_device;
static raw_device_t     fake_raw_device;

capture_device_t *__wrap_caputredeviceCreate(const char *name, const ipmask_t *capture_ranges,
                                             uint32_t capture_range_count, void *userdata, CaptureReadEventHandle cb);
raw_device_t     *__wrap_rawdeviceCreate(const char *name, uint32_t mark, void *userdata);
bool              __wrap_caputredeviceBringUp(capture_device_t *cdev);
bool              __wrap_rawdeviceBringUp(raw_device_t *rdev);
bool              __wrap_caputredeviceBringDown(capture_device_t *cdev);
bool              __wrap_rawdeviceBringDown(raw_device_t *rdev);
void              __wrap_capturedeviceDestroy(capture_device_t *cdev);
void              __wrap_rawdeviceDestroy(raw_device_t *rdev);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void notifyCleanup(char marker)
{
    if (notify_fd >= 0)
    {
        ssize_t write_res = write(notify_fd, &marker, 1);
        discard write_res;
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
                                             uint32_t capture_range_count, void *userdata, CaptureReadEventHandle cb)
{
    require(name != NULL, "RawSocket did not pass a capture device name");
    require(capture_ranges != NULL, "RawSocket did not pass capture ranges");
    require(capture_range_count == 1, "RawSocket passed the wrong capture range count");
    require(userdata != NULL, "RawSocket did not pass tunnel userdata to capture device");
    require(cb == rawsocketOnIPPacketReceived, "RawSocket passed the wrong capture callback");

    fake_capture_device = (capture_device_t) {0};
    atomic_store(&fake_capture_device.up, false);
    return &fake_capture_device;
}

raw_device_t *__wrap_rawdeviceCreate(const char *name, uint32_t mark, void *userdata)
{
    require(name != NULL, "RawSocket did not pass a raw device name");
    require(mark == 7, "RawSocket passed the wrong firewall mark");
    require(userdata != NULL, "RawSocket did not pass tunnel userdata to raw device");

    fake_raw_device = (raw_device_t) {0};
    atomic_store(&fake_raw_device.up, false);
    return &fake_raw_device;
}

bool __wrap_caputredeviceBringUp(capture_device_t *cdev)
{
    require(cdev == &fake_capture_device, "RawSocket brought up an unexpected capture device");
    require(atomic_load(&fake_raw_device.up), "RawSocket activated capture before the raw writer was ready");
    notifyCleanup('c');
    return false;
}

bool __wrap_rawdeviceBringUp(raw_device_t *rdev)
{
    require(rdev == &fake_raw_device, "RawSocket brought up an unexpected raw device");
    atomic_store(&rdev->up, true);
    notifyCleanup('u');
    return true;
}

bool __wrap_caputredeviceBringDown(capture_device_t *cdev)
{
    require(cdev == &fake_capture_device, "RawSocket brought down an unexpected capture device");
    atomic_store(&cdev->up, false);
    notifyCleanup('b');
    return true;
}

bool __wrap_rawdeviceBringDown(raw_device_t *rdev)
{
    require(rdev == &fake_raw_device, "RawSocket brought down an unexpected raw device");
    require(atomic_load(&rdev->up), "RawSocket brought down a raw device that was not up");
    atomic_store(&rdev->up, false);
    notifyCleanup('d');
    return true;
}

void __wrap_capturedeviceDestroy(capture_device_t *cdev)
{
    require(cdev == &fake_capture_device, "RawSocket destroyed an unexpected capture device");
    require(! atomic_load(&cdev->up), "RawSocket destroyed the capture device while it was still up");
    notifyCleanup('x');
}

void __wrap_rawdeviceDestroy(raw_device_t *rdev)
{
    require(rdev == &fake_raw_device, "RawSocket destroyed an unexpected raw device");
    require(! atomic_load(&fake_capture_device.up), "RawSocket destroyed raw device before capture was down");
    require(! atomic_load(&rdev->up), "RawSocket destroyed raw device while its writer was still up");
    notifyCleanup('r');
}

static void runRawSocketStartWithCaptureBringupFailure(int write_fd)
{
    notify_fd = write_fd;

    node_t node = {.next = NULL};

    tunnel_t *t = tunnelCreate(&node, sizeof(rawsocket_tstate_t), sizeof(rawsocket_lstate_t));
    require(t != NULL, "failed to create RawSocket test tunnel");

    tunnel_t prev = {.fnPayloadD = noopPayload};
    t->prev       = &prev;

    ipmask_t capture_range;
    memoryZero(&capture_range, sizeof(capture_range));

    char capture_name[] = "capture-test";
    char raw_name[]     = "raw-test";

    rawsocket_tstate_t *state       = tunnelGetState(t);
    state->capture_device_name      = capture_name;
    state->raw_device_name          = raw_name;
    state->capture_ranges           = &capture_range;
    state->capture_range_count      = 1;
    state->firewall_mark            = 7;
    state->write_direction_upstream = false;

    rawsocketOnStart(t);
    _Exit(99);
}

int main(void)
{
    int pipe_fds[2];
    require(pipe(pipe_fds) == 0, "failed to create cleanup notification pipe");

    pid_t child = fork();
    require(child >= 0, "failed to fork RawSocket startup failure child");

    if (child == 0)
    {
        close(pipe_fds[0]);
        runRawSocketStartWithCaptureBringupFailure(pipe_fds[1]);
    }

    close(pipe_fds[1]);

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for RawSocket startup failure child");
    require(WIFEXITED(status), "RawSocket startup failure child did not exit normally");
    require(WEXITSTATUS(status) == EXIT_FAILURE, "RawSocket startup failure used the wrong exit status");

    char   events[8];
    size_t event_count = 0;
    for (;;)
    {
        ssize_t read_res = read(pipe_fds[0], events + event_count, sizeof(events) - event_count);
        if (read_res < 0)
        {
            perror("read");
            return 1;
        }
        if (read_res == 0)
        {
            break;
        }
        event_count += (size_t) read_res;
        require(event_count < sizeof(events), "RawSocket cleanup emitted too many events");
    }

    close(pipe_fds[0]);

    require(event_count == 6, "RawSocket startup failure used an incomplete or unexpected cleanup sequence");
    require(memcmp(events, "ucbdxr", 6) == 0,
            "RawSocket did not ready raw output before capture or clean up in fail-open order");

    return 0;
}
