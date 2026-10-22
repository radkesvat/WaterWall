/* CTest: waterwall.packetstoconnection_fake_dns_unit.
 * In-memory parser/cache tests: canonical destination identity, atomic refusal,
 * lease refresh/expiry and zero/maximum TTL. No network or resolver is used. */
#include "PacketsToConnection/structure.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static uint64_t fake_now_ms;
static uint64_t fakeNowUs(void)
{
    return fake_now_ms * 1000U;
}
#define getHRTimeUs fakeNowUs
#include "common/fake_dns.c"
#undef getHRTimeUs

static uint32_t appendQuestion(uint8_t *query, uint32_t offset, const uint8_t *label, uint8_t length)
{
    query[offset++] = length;
    memoryCopy(query + offset, label, length);
    offset += length;
    query[offset++] = 4;
    memoryCopy(query + offset, "test", 4);
    offset += 4;
    query[offset++] = 0;
    PUT_BE16(query + offset, 1);
    PUT_BE16(query + offset + 2, 1);
    return offset + 4;
}

static int answer(ptc_tstate_t *state, const char *name, uint8_t *response)
{
    uint8_t query[512] = {0};
    PUT_BE16(query + 4, 1);
    uint32_t length = appendQuestion(query, 12, (const uint8_t *) name, (uint8_t) strlen(name));
    return ptcFakeDnsBuildResponse(state, query, length, response, 512);
}

static tunnel_t *setup(uint32_t ttl)
{
    tunnel_t *t = tunnelCreate(NULL, sizeof(ptc_tstate_t), 0);
    require(t != NULL, "DNS fixture tunnel allocation");
    ptc_tstate_t *state = tunnelGetState(t);
    mutexInit(&state->dns_lock);
    char settings_text[96];
    snprintf(settings_text, sizeof(settings_text), "{\"fake-dns\":{\"cache-size\":2,\"ttl\":%u}}", ttl);
    cJSON *settings = cJSON_Parse(settings_text);
    require(settings != NULL && ptcFakeDnsLoadSettings(state, settings), "DNS fixture settings");
    cJSON_Delete(settings);
    fake_now_ms = 1000;
    return t;
}

static void teardown(tunnel_t *t)
{
    ptc_tstate_t *state = tunnelGetState(t);
    ptcFakeDnsDestroy(state);
    mutexDestroy(&state->dns_lock);
    tunnelDestroy(t);
}

static void caseCanonicalNames(void)
{
    testCaseSet("fake DNS has one canonical length-aware and C-string destination identity");
    tunnel_t          *t       = setup(0);
    ptc_tstate_t      *state   = tunnelGetState(t);
    static const char *names[] = {"MiXeD-123", "_service", "xn--label"};
    uint8_t            response[512];
    for (size_t i = 0; i < ARRAY_SIZE(names); ++i)
    {
        int length = answer(state, names[i], response);
        require(length > 0 && GET_BE16(response + 6) == 1, "supported hostname refused");
        ip_addr_t ip = {0};
        IP_SET_TYPE_VAL(ip, IPADDR_TYPE_V4);
        memoryCopy(&ip.u_addr.ip4.addr, response + length - 4, 4);
        address_context_t destination = {0};
        require(ptcFakeDnsApplyMappedDestination(t, &destination, &ip, 80, IP_PROTO_TCP), "reverse name missing");
        char expected[256];
        snprintf(expected, sizeof(expected), "%s.test", names[i]);
        for (char *ch = expected; *ch != 0; ++ch)
            *ch = asciiLower(*ch);
        require(destination.domain_len == strlen(destination.domain) && strcmp(destination.domain, expected) == 0,
                "policy byte length and resolver C-string identity differ");
        addresscontextReset(&destination);
    }
    static const uint8_t invalid[] = {0, '.', ' ', '/', '\\', 0x1f, 0x7f, 0x80};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        uint8_t query[512] = {0};
        PUT_BE16(query + 4, 2);
        uint32_t length             = appendQuestion(query, 12, (const uint8_t *) "fresh", 5);
        uint8_t  label[]            = {'a', invalid[i], 'b'};
        length                      = appendQuestion(query, length, label, sizeof(label));
        ptc_fake_dns_entry_t *head  = state->fake_dns.lru_head;
        ptc_fake_dns_entry_t *tail  = state->fake_dns.lru_tail;
        const uint64_t        lease = tail->lease_until_ms;
        require(ptcFakeDnsBuildResponse(state, query, length, response, sizeof(response)) == -1,
                "unrepresentable hostname accepted");
        require(state->fake_dns.used == 2 && state->fake_dns.lru_head == head && state->fake_dns.lru_tail == tail &&
                    tail->lease_until_ms == lease && ptcFakeDnsFindByName(&state->fake_dns, "fresh.test", 10) == NULL,
                "invalid trailing question mutated the cache");
    }
    teardown(t);
}

static void caseLeases(void)
{
    testCaseSet("fake DNS preserves advertised leases and refreshes only committed answers");
    tunnel_t     *t     = setup(10);
    ptc_tstate_t *state = tunnelGetState(t);
    uint8_t       response[512];
    require(answer(state, "alpha", response) > 0 && GET_BE16(response + 6) == 1, "first lease");
    ptc_fake_dns_entry_t *alpha         = ptcFakeDnsFindByName(&state->fake_dns, "alpha.test", 10);
    const uint32_t        alpha_address = alpha->fake_addr_network;
    require(answer(state, "beta", response) > 0 && GET_BE16(response + 6) == 1, "second lease");
    ptc_fake_dns_entry_t *beta         = ptcFakeDnsFindByName(&state->fake_dns, "beta.test", 9);
    const uint32_t        beta_address = beta->fake_addr_network;
    require(answer(state, "gamma", response) > 0 && GET_BE16(response + 6) == 0 && (response[3] & 15U) == 2,
            "protected capacity did not return SERVFAIL");
    require(state->fake_dns.lru_head == alpha && state->fake_dns.lru_tail == beta &&
                alpha->fake_addr_network == alpha_address && beta->fake_addr_network == beta_address,
            "refusal replaced a protected mapping or changed LRU");
    fake_now_ms = 6000;
    require(answer(state, "ALPHA", response) > 0 && GET_BE16(response + 6) == 1 && alpha->lease_until_ms == 16000,
            "reissued answer did not refresh lease");
    fake_now_ms = 11000;
    require(answer(state, "gamma", response) > 0 && GET_BE16(response + 6) == 1,
            "expired lease did not permit admission");
    ptc_fake_dns_entry_t *gamma = ptcFakeDnsFindByName(&state->fake_dns, "gamma.test", 10);
    require(gamma->fake_addr_network == beta_address && alpha->fake_addr_network == alpha_address &&
                ptcFakeDnsFindByName(&state->fake_dns, "beta.test", 9) == NULL,
            "expiry did not reuse exactly the expired mapping");
    uint8_t query[512] = {0};
    PUT_BE16(query + 4, 2);
    uint32_t length = appendQuestion(query, 12, (const uint8_t *) "alpha", 5);
    length          = appendQuestion(query, length, (const uint8_t *) "delta", 5);
    require(ptcFakeDnsBuildResponse(state, query, length, response, sizeof(response)) > 0 &&
                GET_BE16(response + 6) == 0 && alpha->lease_until_ms == 16000 && state->fake_dns.lru_head == alpha &&
                state->fake_dns.lru_tail == gamma,
            "failed multi-question transaction renewed or evicted an existing entry");
    fake_now_ms = 16000;
    require(answer(state, "delta", response) > 0 && GET_BE16(response + 6) == 1,
            "refreshed lease did not expire at its boundary");
    teardown(t);

    t     = setup(INT32_MAX);
    state = tunnelGetState(t);
    require(answer(state, "maximum", response) > 0 && GET_BE16(response + 6) == 1, "maximum TTL refused");
    require(state->fake_dns.lru_head->lease_until_ms == 1000U + (uint64_t) INT32_MAX * 1000U,
            "maximum TTL arithmetic truncated");
    teardown(t);
}

int main(void)
{
    caseCanonicalNames();
    caseLeases();
    puts("packetstoconnection_fake_dns_test: all cases passed");
    return 0;
}
