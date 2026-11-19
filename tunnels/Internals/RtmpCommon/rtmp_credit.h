#ifndef WW_RTMP_CREDIT_H
#define WW_RTMP_CREDIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint64_t committed;
    uint64_t acknowledged;
    uint32_t window;
    uint8_t  limit_type;
} rtmp_credit_t;

/* Initialize to zero. Wire limit types are hard (0), soft (1), and dynamic (2). */
bool rtmpCreditSetBandwidth(rtmp_credit_t *credit, uint32_t value, uint8_t type);
bool rtmpCreditReceiveAck(rtmp_credit_t *credit, uint32_t sequence);
bool rtmpCreditCanSend(const rtmp_credit_t *credit, size_t length, bool application);
void rtmpCreditCommit(rtmp_credit_t *credit, size_t length);

#endif
