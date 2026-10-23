#include "fake_dns_internal.h"

#include "loggers/dns_logger.h"

typedef struct ptc_dns_answer_s
{
    uint32_t fake_addr_network;
    uint16_t name_offset;
} ptc_dns_answer_t;

static uint16_t ptcDnsRead16(const uint8_t *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8U) | (uint16_t) p[1]);
}

static void ptcDnsWrite16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t) (value >> 8U);
    p[1] = (uint8_t) value;
}

static void ptcDnsWrite32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t) (value >> 24U);
    p[1] = (uint8_t) (value >> 16U);
    p[2] = (uint8_t) (value >> 8U);
    p[3] = (uint8_t) value;
}

static bool ptcDnsReadQuestionName(const uint8_t *packet, uint32_t packet_len, uint32_t *offset, char *domain,
                                   uint8_t *domain_len)
{
    uint32_t pos = *offset;
    uint32_t out = 0;

    while (true)
    {
        if (pos >= packet_len)
        {
            return false;
        }

        uint8_t label_len = packet[pos++];
        if (label_len == 0)
        {
            break;
        }

        if ((label_len & 0xC0U) != 0 || label_len > 63U || pos + label_len > packet_len)
        {
            return false;
        }

        if (out != 0)
        {
            if (out >= 253U)
            {
                return false;
            }
            domain[out++] = '.';
        }

        if (out + label_len > 253U)
        {
            return false;
        }

        for (uint8_t i = 0; i < label_len; ++i)
        {
            const uint8_t ch = packet[pos + i];
            /* The destination is shared by length-aware policy matching and a
             * C-string resolver. Keep one unambiguous ASCII hostname identity;
             * a literal dot inside a label cannot become a label separator. */
            if (! ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' ||
                   ch == '_'))
                return false;
            domain[out++] = asciiLower((char) ch);
        }
        pos += label_len;
    }

    if (out == 0 || out > UINT8_MAX)
    {
        return false;
    }

    domain[out] = '\0';
    *domain_len = (uint8_t) out;
    *offset     = pos;
    return true;
}

/*
 * Parses and validates the whole question section without touching the cache.
 *
 * The parse used to allocate a mapping per question as it went, so a query whose
 * second question was truncated still inserted the first - and against a full
 * cache that insertion evicts a live mapping by LRU. A query that receives no
 * answer at all must not be able to change what any other name resolves to.
 *
 * Returns the number of parsed questions, or -1. `end_offset` is where the
 * question section ends, which is also where answers start.
 */
static int ptcFakeDnsParseQuestions(const uint8_t *query, uint32_t query_len, ptc_dns_question_t *questions,
                                    uint32_t *end_offset)
{
    uint32_t offset = kPtcDnsHeaderLen;

    if (query_len < kPtcDnsHeaderLen)
    {
        return -1;
    }

    const uint16_t query_flags = ptcDnsRead16(query + 2);
    if ((query_flags & 0x8000U) != 0)
    {
        return -1;
    }

    const uint16_t question_count = ptcDnsRead16(query + 4);
    if (question_count == 0 || question_count > kPtcDnsMaxQuestions)
    {
        return -1;
    }

    for (uint16_t i = 0; i < question_count; ++i)
    {
        ptc_dns_question_t *question    = &questions[i];
        const uint32_t      name_offset = offset;

        question->domain_len = 0;
        if (name_offset > 0x3FFFU ||
            ! ptcDnsReadQuestionName(query, query_len, &offset, question->domain, &question->domain_len))
        {
            return -1;
        }

        if (offset + 4U > query_len)
        {
            return -1;
        }

        question->qtype       = ptcDnsRead16(query + offset);
        question->qclass      = ptcDnsRead16(query + offset + 2U);
        question->name_offset = (uint16_t) name_offset;
        offset += 4U;
    }

    *end_offset = offset;
    return (int) question_count;
}

int ptcFakeDnsBuildResponse(ptc_tstate_t *ts, const uint8_t *query, uint32_t query_len, uint8_t *response,
                            uint32_t response_capacity)
{
    ptc_dns_answer_t   answers[kPtcDnsMaxQuestions];
    ptc_dns_mapping_t  mappings[kPtcDnsMaxQuestions] = {0};
    ptc_dns_question_t questions[kPtcDnsMaxQuestions];
    uint16_t           answer_count = 0;
    uint32_t           offset       = 0;

    const int question_count = ptcFakeDnsParseQuestions(query, query_len, questions, &offset);
    if (question_count < 0)
    {
        return -1;
    }

    /*
     * Whether the answers fit is decided before the first mapping is created,
     * for the same reason: an over-capacity response used to be refused after
     * every question had already touched the cache.
     */
    const uint32_t dns_len = offset + ((uint32_t) question_count * kPtcDnsAnswerALen);
    if (dns_len > response_capacity)
    {
        return -1;
    }

    uint8_t mapping_count = 0;
    mutexLock(&ts->dns_lock);
    const bool committed = ptcFakeDnsCommitQuestions(
        &ts->fake_dns, questions, question_count, mappings, &mapping_count, getHRTimeUs() / 1000ULL);
    if (committed)
    {
        for (int i = 0; i < question_count; ++i)
        {
            const ptc_dns_question_t *question = &questions[i];

            if (question->mapping_index != UINT8_MAX)
            {
                assert(question->mapping_index < mapping_count);
                const uint32_t fake_addr = mappings[question->mapping_index].entry->fake_addr_network;
                assert(fake_addr != 0);
                answers[answer_count++] =
                    (ptc_dns_answer_t) {.fake_addr_network = fake_addr, .name_offset = question->name_offset};
            }
        }
    }

    mutexUnlock(&ts->dns_lock);

    /* Only answered questions carry an answer record, so this cannot exceed dns_len. */
    const uint32_t answered_len = offset + ((uint32_t) answer_count * kPtcDnsAnswerALen);
    assert(answered_len <= dns_len);
    const uint16_t query_flags = ptcDnsRead16(query + 2);

    memoryCopy(response, query, offset);

    uint16_t response_flags = (uint16_t) (0x8000U | 0x0080U | (query_flags & 0x7900U));
    if (! committed)
        response_flags |= 2U; /* SERVFAIL: retry after a protected slot becomes reusable. */
    ptcDnsWrite16(response + 2, response_flags);
    ptcDnsWrite16(response + 6, answer_count);
    ptcDnsWrite16(response + 8, 0);
    ptcDnsWrite16(response + 10, 0);

    uint8_t *answer = response + offset;
    for (uint16_t i = 0; i < answer_count; ++i)
    {
        answer[0] = (uint8_t) (0xC0U | (answers[i].name_offset >> 8U));
        answer[1] = (uint8_t) answers[i].name_offset;
        ptcDnsWrite16(answer + 2, kPtcDnsTypeA);
        ptcDnsWrite16(answer + 4, kPtcDnsClassIn);
        ptcDnsWrite32(answer + 6, ts->fake_dns.ttl);
        ptcDnsWrite16(answer + 10, 4);
        memoryCopy(answer + 12, &answers[i].fake_addr_network, sizeof(answers[i].fake_addr_network));
        answer += kPtcDnsAnswerALen;
    }

    return (int) answered_len;
}
