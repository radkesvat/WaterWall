#pragma once
#include "capture_linux_private.h"

typedef enum netfilter_packet_result_e
{
    kNetfilterPacketError = -1,
    kNetfilterPacketWouldBlock,
    kNetfilterPacketEof,
    kNetfilterPacketAccepted,
    kNetfilterPacketDiscarded,
    kNetfilterPacketMalformedDiscarded,
    kNetfilterPacketReady
} netfilter_packet_result_t;

bool                      netfilterSetConfig(int netfilter_socket, uint8_t cmd, uint16_t qnum, uint16_t pf);
bool                      netfilterSetParams(int netfilter_socket, uint16_t qnumber, uint8_t mode, uint32_t range);
bool                      netfilterSetQueueLength(int netfilter_socket, uint16_t qnumber, uint32_t qlen);
netfilter_packet_result_t netfilterGetPacketUntil(capture_device_t *cdev, int netfilter_socket, uint16_t qnumber,
                                                  sbuf_t *buff, uint64_t verdict_deadline_us);
netfilter_packet_result_t netfilterGetPacket(capture_device_t *cdev, int netfilter_socket, uint16_t qnumber,
                                             sbuf_t *buff);
