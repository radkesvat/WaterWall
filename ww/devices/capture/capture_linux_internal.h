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
