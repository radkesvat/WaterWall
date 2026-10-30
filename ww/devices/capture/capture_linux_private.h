#pragma once
#include "capture_linux_internal.h"
#include "capture_linux_reader.h"
#include "capture_linux_steering.h"
#include "capture_private.h"

/* Native queue descriptors move from exclusive startup to their worker and
 * back to the coordinator after reader quiescence. */
typedef struct capture_linux_queue_s
{
    int      fd;
    uint16_t number;
    uint32_t requested_queue_limit;
    bool     queue_limit_known;
    bool     batch_verdicts;
    uint32_t requested_receive_bytes;
    char     steering_filter[kCaptureLinuxSteeringFilterSize];
} capture_linux_queue_t;

enum
{
    kNetfilterReadBufferSize   = kCaptureLinuxNetfilterReadBufferSize,
    kNetfilterBatchCapacity    = 256,
    kNetfilterQueueLen         = 64 * 1024,
    kNetfilterSocketRecvBuffer = 64 * 1024 * 1024,

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

    kCaptureDiscardReportIntervalMs = 1000,
    kCaptureReaderPacketLimit       = 512,
    kCaptureReaderChargeLimit       = 8 * 1024 * 1024,

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
