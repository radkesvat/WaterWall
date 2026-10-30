#include "capture_linux_nfqueue.h"
#include "capture_linux_private.h"
#include "capture_linux_rules.h"
#include "devices/device_kernel_queue_tuning.h"
#include "devices/device_pool.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

static void captureDeliverPacket(void *device, sbuf_t *buffer, wid_t wid)
{
    capture_device_t *cdev = device;
    cdev->read_event_callback(cdev, cdev->userdata, buffer, wid);
}

static void captureCloseQueues(capture_device_t *cdev)
{
    for (uint16_t i = 0; i < cdev->queue_count; ++i)
    {
        if (cdev->queues[i].fd >= 0)
            close(cdev->queues[i].fd);
        cdev->queues[i].fd = -1;
    }
}

static void captureReleaseQueues(capture_device_t *cdev)
{
    assert(capturedevicePendingRangeCount(cdev) == 0 && cdev->reader == NULL);
    captureCloseQueues(cdev);
    memoryFree(cdev->queues);
    memoryFree(cdev->rule_states);
    cdev->queues      = NULL;
    cdev->rule_states = NULL;
    cdev->queue_count = 0;
}

static bool captureProbeReceiveBuffer(int requested, int *actual)
{
    /* An unbound Netlink socket observes the same namespace's socket limits
     * without altering a live queue. SOCK_DGRAM and SOCK_RAW use the same
     * Netlink socket-buffer implementation. */
    const int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0)
        return false;
    socklen_t  length = sizeof(*actual);
    const bool result = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested)) == 0 &&
                        getsockopt(fd, SOL_SOCKET, SO_RCVBUF, actual, &length) == 0;
    const int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return result;
}

static bool captureConfigureQueueLimits(capture_device_t *cdev, capture_linux_queue_t *queue, uint16_t count)
{
    const uint32_t packet_limit = deviceKernelQueueCapturePackets(
        cdev->kernel_queue_profile, count, cdev->kernel_queue_packets, cdev->kernel_queue_tune);
    /* A fallback may reconfigure this descriptor. Never reduce an earlier
     * request, including one whose ACK was lost and whose result is unknown. */
    if (! queue->queue_limit_known || packet_limit > queue->requested_queue_limit)
    {
        queue->requested_queue_limit = max(packet_limit, queue->requested_queue_limit);
        queue->queue_limit_known     = netfilterSetQueueLength(queue->fd, queue->number, queue->requested_queue_limit);
        if (! queue->queue_limit_known)
            LOGW("CaptureDevice: queue %u maximum-length request %u was not confirmed: %s; effective limit unknown",
                 queue->number,
                 queue->requested_queue_limit,
                 strerror(errno));
    }

    /* Required copy setup also synchronizes the configuration channel after a
     * refused or timed-out optional request. Its matching ACK consumes earlier
     * responses before the packet reader can encounter them. No capture rules
     * are live here, including during single-queue fallback. */
    if (! netfilterSetParams(queue->fd, queue->number, NFQNL_COPY_PACKET, kMaxAllowedPacketLength))
    {
        LOGE("CaptureDevice: queue %u copy setup/configuration synchronization failed: %s",
             queue->number,
             strerror(errno));
        return false;
    }

    const int receive_bytes = (int) deviceKernelQueueCaptureReceiveBytes(
        cdev->kernel_queue_profile, count, cdev->kernel_receive_buffer, cdev->kernel_queue_tune);
    int       actual;
    socklen_t length = sizeof(actual);
    if (getsockopt(queue->fd, SOL_SOCKET, SO_RCVBUF, &actual, &length) != 0)
        LOGW("CaptureDevice: queue %u cannot read SO_RCVBUF; preserving its existing setting: %s",
             queue->number,
             strerror(errno));
    else if ((uint64_t) actual < (uint64_t) receive_bytes * 2U)
    {
        int granted;
        if (! captureProbeReceiveBuffer(receive_bytes, &granted))
            LOGW("CaptureDevice: queue %u cannot probe SO_RCVBUF allowance; preserving existing setting: %s",
                 queue->number,
                 strerror(errno));
        else if (granted > actual)
        {
            /* A socket can already exceed today's rmem_max. Reapplying even a
             * larger request would reduce it to that cap. This startup snapshot
             * cannot serialize a concurrent host-policy change with setsockopt. */
            queue->requested_receive_bytes = (uint32_t) receive_bytes;
            if (setsockopt(queue->fd, SOL_SOCKET, SO_RCVBUF, &receive_bytes, sizeof(receive_bytes)) != 0)
                LOGW("CaptureDevice: queue %u SO_RCVBUF request %d failed; retaining existing setting: %s",
                     queue->number,
                     receive_bytes,
                     strerror(errno));
        }
    }
    return true;
}

static void captureLogQueueLimits(capture_device_t *cdev)
{
    for (uint16_t i = 0; i < cdev->queue_count; ++i)
    {
        capture_linux_queue_t *queue           = &cdev->queues[i];
        int                    actual          = 0;
        socklen_t              length          = sizeof(actual);
        const bool             known           = getsockopt(queue->fd, SOL_SOCKET, SO_RCVBUF, &actual, &length) == 0;
        char                   actual_text[24] = "unavailable";
        if (known)
            stringNPrintf(actual_text, sizeof(actual_text), "%d", actual);
        const uint32_t desired = deviceKernelQueueCaptureReceiveBytes(
            cdev->kernel_queue_profile, cdev->queue_count, cdev->kernel_receive_buffer, cdev->kernel_queue_tune);
        if (! known)
            LOGW("CaptureDevice: queue %u cannot read effective SO_RCVBUF: %s", queue->number, strerror(errno));
        else if ((uint64_t) actual < (uint64_t) desired * 2U)
            LOGW("CaptureDevice: queue %u receive buffer is below requested target %u bytes (SO_RCVBUF=%d, Linux "
                 "doubled accounting); check net.core.rmem_max",
                 queue->number,
                 desired,
                 actual);
        LOGI("CaptureDevice: %s queue %u of %u, profile=%u, packet source=%s, NFQUEUE request=%u, "
             "effective=%s; receive source=%s, target=%u, SO_RCVBUF request=%u, actual=%s (Linux doubled accounting)",
             cdev->name,
             queue->number,
             cdev->queue_count,
             cdev->kernel_queue_profile,
             ! cdev->kernel_queue_tune         ? "disabled"
             : cdev->kernel_queue_packets != 0 ? "override"
                                               : "auto",
             queue->requested_queue_limit,
             queue->queue_limit_known ? "ACK-confirmed" : "unknown",
             ! cdev->kernel_queue_tune          ? "disabled"
             : cdev->kernel_receive_buffer != 0 ? "override"
                                                : "auto",
             desired,
             queue->requested_receive_bytes,
             actual_text);
    }
}

static bool captureOpenQueue(capture_device_t *cdev, capture_linux_queue_t *queue, uint16_t count)
{
    const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0)
        return false;
    struct sockaddr_nl address = {.nl_family = AF_NETLINK};
    if (bind(fd, (struct sockaddr *) &address, sizeof(address)) != 0)
        goto failed;
    const int one = 1;
    if (setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one)) != 0)
        LOGW("CaptureDevice: unable to suppress Netlink overflow notifications: %s", strerror(errno));
    queue->fd = fd;
    if (! netfilterSetConfig(fd, NFQNL_CFG_CMD_BIND, queue->number, 0) ||
        ! captureConfigureQueueLimits(cdev, queue, count))
        goto failed;
    return true;
failed:
    close(fd);
    queue->fd = -1;
    return false;
}

static bool captureUseSingleQueue(capture_device_t *cdev)
{
    assert(capturedevicePendingRangeCount(cdev) == 0 && cdev->reader == NULL);
    for (uint16_t i = 1; i < cdev->queue_count; ++i)
    {
        if (cdev->queues[i].fd >= 0)
            close(cdev->queues[i].fd);
        cdev->queues[i].fd = -1;
    }
    cdev->queue_count                  = 1;
    cdev->queues[0].steering_filter[0] = '\0';
    return captureConfigureQueueLimits(cdev, &cdev->queues[0], 1);
}

static bool captureOpenQueues(capture_device_t *cdev)
{
    uint16_t count = cdev->multi_queue ? getWorkersCount() : 1;
    uint16_t first;
    if (! capturedeviceChooseQueueRange(count, &first))
    {
        if (count == 1 || ! capturedeviceChooseQueueRange(1, &first))
            return false;
        count = 1;
        LOGW("CaptureDevice: no multiqueue range available; using worker 0");
    }
    size_t state_count;
    size_t state_bytes;
    if (! memoryTryComputeArraySize(cdev->capture_range_count, count, &state_count) ||
        ! memoryTryComputeArraySize(state_count, sizeof(*cdev->rule_states), &state_bytes))
        return false;
    cdev->queues      = memoryAllocateZero((size_t) count * sizeof(*cdev->queues));
    cdev->rule_states = memoryAllocateZero(state_bytes);
    cdev->queue_count = count;
    for (uint16_t i = 0; i < count; ++i)
    {
        cdev->queues[i].fd     = -1;
        cdev->queues[i].number = first + i;
    }
    for (uint16_t i = 0; i < count; ++i)
    {
        if (! captureOpenQueue(cdev, &cdev->queues[i], count))
        {
            LOGW("CaptureDevice: queue %u setup failed: %s", cdev->queues[i].number, strerror(errno));
            if (i == 0 || ! captureUseSingleQueue(cdev))
            {
                captureReleaseQueues(cdev);
                return false;
            }
            LOGW("CaptureDevice: extra receive queues unavailable; using worker 0");
            break;
        }
        if (count > 1)
            captureLinuxBuildSteeringFilter(count, i, cdev->opaque_flow_mode, cdev->queues[i].steering_filter);
    }
    GSTATE.capturedevice_queue_start_number = (uint16_t) (first + cdev->queue_count);
    return true;
}

bool capturedeviceReaderOperational(capture_device_t *cdev)
{
    if (! captureLifecycleIsActive(captureLifecycleLoad(&cdev->lifecycle)) || ! cdev->queue_restartable ||
        cdev->reader == NULL)
        return false;
    for (uint16_t i = 0; i < cdev->queue_count; ++i)
        if (cdev->queues[i].fd < 0)
            return false;
    return true;
}

bool capturedeviceIsUp(const capture_device_t *cdev)
{
    assert(cdev != NULL);
    return atomicLoadRelaxed(&cdev->up);
}

void capturedeviceSetMultiQueue(capture_device_t *cdev, bool enabled)
{
    assert(captureLifecycleLoad(&cdev->lifecycle) == kCaptureLifecycleDown && cdev->reader == NULL);
    cdev->multi_queue = enabled;
}

void capturedeviceSetOpaqueFlowMode(capture_device_t *cdev, device_opaque_flow_mode_t mode)
{
    assert(cdev != NULL);
    assert(captureLifecycleLoad(&cdev->lifecycle) == kCaptureLifecycleDown && cdev->reader == NULL);
    assert(mode >= kDeviceOpaqueFlowPrefix && mode <= kDeviceOpaqueFlowSpread);
    cdev->opaque_flow_mode = mode;
    deviceReaderSessionSetOpaqueFlowMode(cdev->reader_session, mode);
}

void capturedeviceConfigureKernelQueue(capture_device_t *cdev, bool enabled, uint32_t packet_total,
                                       uint32_t receive_bytes_total)
{
    assert(captureLifecycleLoad(&cdev->lifecycle) == kCaptureLifecycleDown && cdev->reader == NULL);
    assert(packet_total <= INT_MAX && receive_bytes_total <= INT_MAX);
    cdev->kernel_queue_tune     = enabled;
    cdev->kernel_queue_packets  = packet_total;
    cdev->kernel_receive_buffer = receive_bytes_total;
}

bool caputredeviceBringUp(capture_device_t *cdev)
{
    if (! cdev->queue_restartable || ! captureLifecycleTransitionDownToStarting(&cdev->lifecycle))
        return false;
    /* Inactive coordinator scratch can become the first active worker packet.
     * Capture finalized chain padding before either source allocates buffers. */
    devicePoolUpdatePadding(cdev->reader_buffer_pool, getCurrentWorkerBufferPool());
    deviceFragAffinityEnableShared(cdev->reader_session->frag_affinity,
                                   bufferpoolGetSmallBufferPadding(cdev->reader_buffer_pool));
    capturedeviceApplySysctls(cdev->skip_sysctl);
    if (! captureOpenQueues(cdev) || deviceReaderSessionBegin(cdev->reader_session) == 0)
        goto failed;

    captureReaderOpen(cdev);

    /* Before capture activation, the command supervisor services these queues
     * with NF_ACCEPT. No packet can enter the chain before its queued Init. */
    if (! capturedeviceInstallRuleKind(cdev, false))
    {
        if (cdev->queue_count == 1 || ! capturedeviceRemoveInstalledRules(cdev) ||
            capturedevicePendingRangeCount(cdev) != 0 || ! captureReaderDrain(cdev))
            goto failed;
        captureReaderDestroy(cdev);
        if (! captureUseSingleQueue(cdev))
            goto failed;
        captureReaderOpen(cdev);
        LOGW("CaptureDevice: multiqueue routing unavailable; using worker 0");
        if (! capturedeviceInstallRuleKind(cdev, false))
            goto failed;
    }
    if ((cdev->bypass_conntrack && ! capturedeviceInstallRuleKind(cdev, true)) ||
        ! capturedeviceReaderOperational(cdev) || ! captureLifecycleTransitionStartingToUp(&cdev->lifecycle))
        goto failed;
    captureLogQueueLimits(cdev);
    atomicStoreRelaxed(&cdev->capture_active, true);
    atomicStoreRelaxed(&cdev->up, true);
    if (! captureReaderStart(cdev))
        goto failed;
    LOGI("CaptureDevice: %s up with %u worker-owned receive queue(s), opaque-flow-mode=%s; %s",
         cdev->name,
         cdev->queue_count,
         deviceOpaqueFlowModeName(cdev->opaque_flow_mode),
         cdev->queue_count > 1 ? "kernel receive steering" : "worker 0 reads; all workers process");
    return true;
failed:
    discard caputredeviceBringDown(cdev);
    return false;
}

bool capturedeviceRequestStop(capture_device_t *cdev)
{
    captureLifecycleTransitionToStopping(&cdev->lifecycle);
    atomicStoreRelaxed(&cdev->capture_active, false);
    atomicStoreRelaxed(&cdev->up, false);
    deviceReaderSessionEndRequest(cdev->reader_session);
    captureReaderCloseRequest(cdev);
    return true;
}

bool caputredeviceBringDown(capture_device_t *cdev)
{
    discard capturedeviceRequestStop(cdev);
    deviceReaderSessionEndWait(cdev->reader_session);
    captureReaderCloseWait(cdev);
    /* All owner watchers are detached. The coordinator now services inactive
     * NF_ACCEPT verdicts throughout supervised rule removal, including timeout
     * cleanup, without an auxiliary application reader thread. */
    bool result = capturedeviceRemoveInstalledRules(cdev);
    result      = captureReaderDrain(cdev) && result;
    captureCloseQueues(cdev);
    captureReaderDestroy(cdev);
    deviceReaderSessionRetireGenerationBuffers(cdev->reader_session);
    if (capturedevicePendingRangeCount(cdev) == 0)
        captureReleaseQueues(cdev);
    else
    {
        cdev->queue_restartable = false;
        LOGE("CaptureDevice: rule cleanup incomplete; closed queues bypass capture. Remaining WWCAP_NOTRACK rules "
             "must be removed to restore host connection tracking");
    }
    captureLifecycleTransitionStoppingToDown(&cdev->lifecycle);
    return result;
}

capture_device_t *caputredeviceCreate(const char *name, const ipmask_t *capture_ranges, uint32_t capture_range_count,
                                      bool skip_sysctl, bool bypass_conntrack,
                                      const capture_protocol_filter_t *protocol_filter, void *userdata,
                                      CaptureReadEventHandle cb, device_fragment_policy_t fragment_policy)
{
    if (capture_ranges == NULL || capture_range_count == 0)
    {
        LOGE("CaptureDevice: no capture ranges configured");
        return NULL;
    }
    size_t range_bytes;
    if (! memoryTryComputeArraySize(capture_range_count, sizeof(char *), &range_bytes))
        return NULL;
    buffer_pool_t *pool = devicePoolCreate(getCurrentWorkerBufferPool(), 0);
    if (pool == NULL)
        return NULL;
    buffer_pool_fit_t fit;
    if (! bufferpoolQueryBestFit(pool, kNetfilterReadBufferSize, 0, &fit) ||
        fit.allocation_charge > kCaptureReaderChargeLimit)
    {
        LOGE("CaptureDevice: receive allocation exceeds the device dispatch budget");
        bufferpoolDestroy(pool);
        return NULL;
    }
    capture_device_t *cdev    = memoryAllocateZero(sizeof(*cdev));
    cdev->name                = stringDuplicate(name);
    cdev->capture_cidrs       = memoryAllocateZero(range_bytes);
    cdev->capture_range_count = capture_range_count;
    for (uint32_t i = 0; i < capture_range_count; ++i)
        cdev->capture_cidrs[i] = capturedeviceFormatCidrString(&capture_ranges[i]);
    cdev->multi_queue         = true;
    cdev->kernel_queue_tune    = true;
    cdev->kernel_queue_profile = RAM_PROFILE;
    cdev->bypass_conntrack    = bypass_conntrack;
    cdev->skip_sysctl         = skip_sysctl;
    cdev->rule_token          = fastRand64();
    cdev->queue_restartable   = true;
    cdev->reader_buffer_pool  = pool;
    cdev->read_event_callback = cb;
    cdev->userdata            = userdata;
    atomic_init(&cdev->lifecycle, kCaptureLifecycleDown);
    captureLinuxBuildProtocolFilter(protocol_filter, cdev->protocol_filter);
    cdev->reader_session =
        deviceReaderSessionCreate(RAM_PROFILE * 2, 1, cdev, captureDeliverPacket, pool, fragment_policy);
    if (cdev->reader_session == NULL)
    {
        capturedeviceFreeCidrs(cdev->capture_cidrs, capture_range_count);
        memoryFree(cdev->name);
        bufferpoolDestroy(pool);
        memoryFree(cdev);
        return NULL;
    }
    if (! deviceReaderSessionConfigureOutputBudget(
            cdev->reader_session, kCaptureReaderChargeLimit, kCaptureReaderPacketLimit) ||
        ! deviceReaderSessionEnableWorkerQueue(cdev->reader_session))
    {
        capturedeviceDestroy(cdev);
        return NULL;
    }
    deviceReaderSessionConfigureCapacityNotify(cdev->reader_session, captureReaderCapacityReady, cdev);
    return cdev;
}

void capturedeviceDestroy(capture_device_t *cdev)
{
    discard caputredeviceBringDown(cdev);
    if (capturedevicePendingRangeCount(cdev) != 0)
    {
        discard capturedeviceRemoveInstalledRules(cdev);
        if (capturedevicePendingRangeCount(cdev) != 0)
            LOGE("CaptureDevice: %s destroyed with unresolved owned firewall rules", cdev->name);
    }
    deviceReaderSessionRetireProducerBuffers(cdev->reader_session);
    bufferpoolDestroy(cdev->reader_buffer_pool);
    deviceReaderSessionUnref(cdev->reader_session);
    memoryFree(cdev->rule_states);
    memoryFree(cdev->queues);
    capturedeviceFreeCidrs(cdev->capture_cidrs, cdev->capture_range_count);
    memoryFree(cdev->name);
    memoryFree(cdev);
}
