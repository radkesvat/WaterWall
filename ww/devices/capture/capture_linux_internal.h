#pragma once

#include "shiftbuffer.h"
#include "wlibc.h"

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
    bool           has_capture_length;
    bool           has_packet_id;
} netfilter_packet_view_t;

netfilter_packet_parse_result_t captureLinuxNetfilterParsePacket(uint8_t *message, size_t copied_len,
                                                                 netfilter_packet_view_t *view);
bool captureLinuxNetfilterTryReadPacketIdFromPrefix(const uint8_t *message, size_t copied_len, uint32_t *packet_id);
void captureLinuxNetfilterExposePacket(sbuf_t *buff, const uint8_t *message, const netfilter_packet_view_t *view);

#if defined(OS_LINUX)

// Outcome of one supervised Capture command. A timeout is deliberately distinct
// from an ordinary nonzero exit: it is the only status that means the command
// path itself has hung, and both Capture batches use it to stop early instead of
// spending another full deadline per remaining item.
typedef enum capturedevice_command_status_e
{
    kCapturedeviceCommandOk = 0,
    kCapturedeviceCommandFailed,
    kCapturedeviceCommandSpawnFailed,
    kCapturedeviceCommandTimedOut
} capturedevice_command_status_t;

// Command-layer seams. These are internal to the Linux capture device and are
// exposed only so the command-wiring unit test can drive them without opening a
// real NFQUEUE socket or requiring root.
capturedevice_command_status_t capturedeviceRunIptablesQueueRule(const char *operation, const char *cidr,
                                                                 uint32_t queue_number);
void                           capturedeviceApplySysctls(void);

#endif
