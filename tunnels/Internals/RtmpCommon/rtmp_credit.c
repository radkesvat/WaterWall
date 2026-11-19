#include "rtmp_credit.h"

#include "ww-rtmp-engine.h"

#include <assert.h>

enum
{
    kHard          = 0,
    kSoft          = 1,
    kDynamic       = 2,
    kMinWindow     = 65536,
    kControlCredit = 8192,
};

static const uint32_t kHalfSequence = UINT32_C(0x80000000);

bool rtmpCreditSetBandwidth(rtmp_credit_t *credit, uint32_t value, uint8_t type)
{
    if (type > kDynamic)
        return false;
    if (type == kDynamic)
    {
        if (credit->limit_type != kHard + 1)
            return true;
        type = kHard;
    }
    if (type == kSoft && credit->window != 0 && credit->window < value)
        value = credit->window;
    if (value < kMinWindow || value >= kHalfSequence || credit->committed - credit->acknowledged > value)
        return false;
    credit->window     = value;
    credit->limit_type = (uint8_t) (type + 1);
    return true;
}

bool rtmpCreditReceiveAck(rtmp_credit_t *credit, uint32_t sequence)
{
    const uint32_t delta = sequence - (uint32_t) credit->acknowledged;
    if (delta > kHalfSequence)
        return UINT64_C(0x100000000) - delta <= credit->acknowledged;
    if (delta == kHalfSequence || delta > credit->committed - credit->acknowledged)
        return false;
    credit->acknowledged += delta;
    return true;
}

bool rtmpCreditCanSend(const rtmp_credit_t *credit, size_t length, bool application)
{
    uint32_t limit = credit->window == 0 ? kRtmpInitialPeerBandwidth : credit->window;
    if (application)
        limit -= kControlCredit;
    return length <= limit && credit->committed - credit->acknowledged <= limit - length &&
           length <= UINT64_MAX - credit->committed;
}

void rtmpCreditCommit(rtmp_credit_t *credit, size_t length)
{
    assert(rtmpCreditCanSend(credit, length, false));
    credit->committed += length;
}
