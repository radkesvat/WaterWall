/*
 * Full matrix for the shared flow-opening SYN predicate used by every stateful
 * IpManipulator SNI tracker. A flow may only be opened by a payload-free SYN
 * without ACK/FIN/RST and without unexpected control flags; ECN negotiation
 * (ECE/CWR) is accepted and TCP Fast Open SYN data is not.
 */

#include "IpManipulator/structure.h"

typedef struct syn_case_s
{
    const char *name;
    uint8_t     flags;
    uint32_t    payload_len;
    bool        expected;
} syn_case_t;

static const syn_case_t kSynCases[] = {
    {"plain SYN", TCP_SYN, 0, true},
    {"SYN|ECE", TCP_SYN | TCP_ECE, 0, true},
    {"SYN|CWR", TCP_SYN | TCP_CWR, 0, true},
    {"SYN|ECE|CWR", TCP_SYN | TCP_ECE | TCP_CWR, 0, true},

    {"SYN|ACK", TCP_SYN | TCP_ACK, 0, false},
    {"SYN|FIN", TCP_SYN | TCP_FIN, 0, false},
    {"SYN|RST", TCP_SYN | TCP_RST, 0, false},
    {"SYN|PSH", TCP_SYN | TCP_PSH, 0, false},
    {"SYN|URG", TCP_SYN | TCP_URG, 0, false},
    {"SYN|ECE|ACK", TCP_SYN | TCP_ECE | TCP_ACK, 0, false},
    {"SYN|ECE|CWR|FIN", TCP_SYN | TCP_ECE | TCP_CWR | TCP_FIN, 0, false},

    {"payload-bearing SYN", TCP_SYN, 1, false},
    {"payload-bearing SYN|ECE|CWR", TCP_SYN | TCP_ECE | TCP_CWR, 512, false},

    {"no flags", 0, 0, false},
    {"ACK only", TCP_ACK, 0, false},
    {"FIN|ACK", TCP_FIN | TCP_ACK, 0, false},
    {"RST", TCP_RST, 0, false},
    {"ECE|CWR without SYN", TCP_ECE | TCP_CWR, 0, false},
    {"PSH|ACK with payload", TCP_PSH | TCP_ACK, 100, false},
};

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void testPredicateMatrix(void)
{
    for (uint32_t i = 0; i < ARRAY_SIZE(kSynCases); ++i)
    {
        const syn_case_t *test_case = &kSynCases[i];
        char              message[192];

        snprintf(message,
                 sizeof(message),
                 "%s (flags=0x%02X payload=%u) should %sopen a flow",
                 test_case->name,
                 (unsigned int) test_case->flags,
                 test_case->payload_len,
                 test_case->expected ? "" : "not ");
        require(ipmanipulatorIsFlowOpeningSyn(test_case->flags, test_case->payload_len) == test_case->expected,
                message);
    }
}

static void testExhaustiveFlagCoverage(void)
{
    /*
     * Exhaustive over every 8-bit flag combination: the accepted set must be
     * exactly SYN plus any subset of {ECE, CWR}, and only with zero payload.
     */
    for (uint32_t flags = 0; flags <= UINT8_MAX; ++flags)
    {
        bool expected = (flags & TCP_SYN) != 0 && (flags & ~(uint32_t) (TCP_SYN | TCP_ECE | TCP_CWR)) == 0;

        char message[128];
        snprintf(message, sizeof(message), "flag combination 0x%02X was classified incorrectly", flags);
        require(ipmanipulatorIsFlowOpeningSyn((uint8_t) flags, 0) == expected, message);

        snprintf(message, sizeof(message), "flag combination 0x%02X opened a flow with payload", flags);
        require(! ipmanipulatorIsFlowOpeningSyn((uint8_t) flags, 1), message);
    }
}

int main(void)
{
    testPredicateMatrix();
    testExhaustiveFlagCoverage();

    printf("ALL unit tests passed!\n");
    return 0;
}
