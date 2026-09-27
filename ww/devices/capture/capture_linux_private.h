#pragma once
#include "capture_linux_internal.h"
#include "capture_private.h"

/* The coordinator owns descriptors, rule records and joinable threads. The
 * reader borrows its stable socket until join; rule cleanup runs while inactive
 * capture can still return packets to the host. Queued sessions outlive devices. */
enum
{
    kNetfilterReadBufferSize    = kCaptureLinuxNetfilterReadBufferSize,
    kMaxReadDistributeQueueSize = 512,
    kNetfilterQueueLen          = 64 * 1024,
    kNetfilterSocketRecvBuffer  = 64 * 1024 * 1024,

    // Two independent timeout layers guard every Capture iptables command. The
    // numeric xtables lock wait only bounds lock acquisition inside iptables; the
    // parent-side command deadline is authoritative and also covers a hung
    // executable or wrapper. Mutations and sysctls should produce little output,
    // so 64 KiB bounds a broken tool. Rule inspection legitimately scales with
    // firewall size and therefore gets the same 1 MiB cap used by socket-manager
    // iptables inspection.
    kCaptureIptablesLockWaitSeconds  = 5,
    kCaptureCommandTimeoutMs         = 7000,
    kCaptureCommandTerminateGraceMs  = 250,
    kCaptureMutationMaxOutputBytes   = 64 * 1024,
    kCaptureInspectionMaxOutputBytes = 1024 * 1024,

    // The stop pipe is the fast way out of poll(), but it is not a guaranteed
    // one: BringDown's wake write can fail hard, and then no token ever arrives.
    // A bounded poll makes `running == false` an independent exit condition, so
    // BringDown's join always completes and its failure becomes observable
    // instead of hanging. An idle capture device therefore wakes twice a second,
    // and a lost wake token costs at most one timeout of shutdown latency.
    kCaptureReaderPollTimeoutMs     = 500,
    kCaptureReaderReadyTimeoutMs    = 5000,
    kCaptureDiscardReportIntervalMs = 1000,

    // Configuration and verdict traffic shares the queue socket with the
    // reader. Keep every individual netlink transaction short so a full kernel
    // send buffer cannot hold device teardown indefinitely. Residual teardown
    // uses one such absolute deadline for the whole drain, plus a modest packet
    // budget, instead of renewing this allowance for every queued packet.
    kNetfilterIoDeadlineMs         = 250,
    kNetfilterResidualPacketBudget = 4096,
    kNetfilterAckBufferSize        = 4096,

    // A deterministic syscall seam or a signal storm may return EINTR without
    // advancing the monotonic clock. Bound consecutive interrupted attempts in
    // addition to every absolute deadline/Stop predicate.
    kCaptureInterruptedRetryBudget = 64
};

bool capturedeviceReaderOperational(capture_device_t *cdev);
bool capturedeviceDrainResidualQueue(capture_device_t *cdev, int socket_fd, uint64_t deadline_us);
