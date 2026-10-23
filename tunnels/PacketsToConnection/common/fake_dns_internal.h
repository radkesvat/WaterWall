#pragma once

#include "structure.h"

/* Private parsing/cache transaction boundary; no caller may retain staged questions. */
enum
{
    kPtcDnsHeaderLen    = 12,
    kPtcDnsMaxQuestions = 32,
    kPtcDnsAnswerALen   = 16,
    kPtcDnsTypeA        = 1,
    kPtcDnsClassIn      = 1
};

/* One fully parsed question, staged before any cache state is touched. */
typedef struct ptc_dns_question_s
{
    char     domain[256];
    uint16_t name_offset;
    uint16_t qtype;
    uint16_t qclass;
    uint8_t  domain_len;
    uint8_t  mapping_index;
} ptc_dns_question_t;

typedef struct ptc_dns_mapping_s
{
    ptc_fake_dns_entry_t *entry;
    ptc_fake_dns_entry_t *victim;
    const char           *domain;
    uint8_t               domain_len;
    bool                  staged;
} ptc_dns_mapping_t;

bool ptcFakeDnsCommitQuestions(ptc_fake_dns_t *dns, ptc_dns_question_t *questions, int question_count,
                               ptc_dns_mapping_t *mappings, uint8_t *mapping_count_out, uint64_t now_ms);
int  ptcFakeDnsBuildResponse(ptc_tstate_t *ts, const uint8_t *query, uint32_t query_len, uint8_t *response,
                             uint32_t response_capacity);
