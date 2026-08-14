#pragma once

#include "shiftbuffer.h"
#include "wlibc.h"
#include "wthread.h"

enum
{
    kCaptureLinuxNetfilterReadBufferSize = 4096
};

typedef enum netfilter_packet_parse_result_e
{
    kNetfilterPacketParseMalformed = 0,
    kNetfilterPacketParseDiscarded,
    kNetfilterPacketParseReady
} netfilter_packet_parse_result_t;

typedef struct netfilter_packet_view_s
{
    const uint8_t *payload;
    uint32_t       payload_length;
    uint32_t       capture_length;
    uint32_t       packet_id;
    uint32_t       skb_info;
    bool           has_capture_length;
    bool           has_packet_id;
    bool           has_skb_info;
} netfilter_packet_view_t;

netfilter_packet_parse_result_t captureLinuxNetfilterParsePacket(uint8_t *message, size_t copied_len,
                                                                 netfilter_packet_view_t *view);
bool captureLinuxNetfilterTryReadPacketIdFromPrefix(const uint8_t *message, size_t copied_len, uint32_t *packet_id);
void captureLinuxNetfilterExposePacket(sbuf_t *buff, const uint8_t *message, const netfilter_packet_view_t *view);

#if defined(OS_LINUX)

// Outcome of one supervised Capture command. Timeout, parent-side execution
// failure, and output-limit termination are distinct from an ordinary nonzero
// exit because an iptables mutation may already have committed before the
// supervisor terminated or lost control of the child.
typedef enum capturedevice_command_status_e
{
    kCapturedeviceCommandOk = 0,
    kCapturedeviceCommandFailed,
    kCapturedeviceCommandSpawnFailed,
    kCapturedeviceCommandTimedOut,
    kCapturedeviceCommandOutputTooLarge
} capturedevice_command_status_t;

// Command-layer seams. These are internal to the Linux capture device and are
// exposed only so the command-wiring unit test can drive them without opening a
// real NFQUEUE socket or requiring root.
capturedevice_command_status_t capturedeviceRunIptablesQueueRule(const char *operation, const char *cidr,
                                                                 uint32_t queue_number, const char *rule_comment);
capturedevice_command_status_t capturedeviceReadIptablesInputRules(char **input_rules);
void                           capturedeviceApplySysctls(void);

// Select the first queue at or after `start` (with uint16_t wraparound) that is
// not referenced by an existing `--queue-num` or `--queue-balance` rule in an
// `iptables -S INPUT` snapshot. This prevents an old fail-open rule from
// becoming active again merely because a later process reused its queue number.
bool capturedeviceSelectUnusedQueueNumber(const char *input_rules, uint16_t start, uint16_t *selected);

// Stop-pipe lifecycle seams. The pipe lives for the whole lifetime of a
// capture_device_t, so both BringUp and BringDown must be able to assert that it
// contains no unread wake token. These are exposed only so the focused lifecycle
// unit test can drive them without a real NFQUEUE socket or root.
struct capture_device_s;

// Make one stop-pipe descriptor nonblocking, preserving its other flags.
bool capturedeviceMakeStopPipeNonblocking(int pipe_fd);

// Read the stop pipe until empty. Retries on EINTR, treats EAGAIN/EWOULDBLOCK as
// successful completion, and reports EOF or any other error as a failure. Never
// blocks.
bool capturedeviceDrainStopPipe(struct capture_device_s *cdev);

// The production NFQUEUE reader. Exposed so the lifecycle test can prove that its
// poll() is bounded and that `running == false` alone terminates it, which is
// what keeps BringDown's join from deadlocking when the wake write fails.
WTHREAD_ROUTINE(captureLinuxReadRoutine);

// Publish the readiness handshake after a reader has taken a stable queue-socket
// reference and is about to enter its poll loop. Test readers use the same seam.
bool captureLinuxReaderPublishReady(struct capture_device_s *cdev, int *reader_socket);

// Bounded verdict seam for the Linux constructor/lifecycle fault harness.
bool captureLinuxNetfilterSendVerdictForTest(int netfilter_socket, uint16_t queue_number, uint32_t packet_id,
                                             uint32_t verdict);

#endif
