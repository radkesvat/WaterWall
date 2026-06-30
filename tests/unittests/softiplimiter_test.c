#include "SoftIpLimiter/structure.h"

#include <stdio.h>
#include <stdlib.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static softiplimiter_ip_key_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    softiplimiter_ip_key_t ip = {.type = 4};
    ip.bytes[0] = a;
    ip.bytes[1] = b;
    ip.bytes[2] = c;
    ip.bytes[3] = d;
    return ip;
}

static const softiplimiter_identity_entry_t *findEntry(const softiplimiter_identity_map_t *table, hash_t identifier)
{
    softiplimiter_identity_map_t_iter it = softiplimiter_identity_map_t_find(table, identifier);
    if (it.ref == softiplimiter_identity_map_t_end(table).ref)
    {
        return NULL;
    }
    return &it.ref->second;
}

static void testVlessExtraction(void)
{
    uint8_t bytes[1 + kSoftIpLimiterVlessUuidLen] = {0};
    for (uint8_t i = 0; i < kSoftIpLimiterVlessUuidLen; ++i)
    {
        bytes[1 + i] = (uint8_t) (0xA0U + i);
    }

    hash_t out = 0;
    require(softiplimiterTryExtractIdentifierFromBytes(
                kSoftIpLimiterIdentifierVless, bytes, sizeof(bytes), &out) == kSoftIpLimiterExtractOk,
            "vless: expected full UUID extraction");
    require(out == calcHashBytes(bytes + 1, kSoftIpLimiterVlessUuidLen), "vless: wrong UUID hash");

    require(softiplimiterTryExtractIdentifierFromBytes(
                kSoftIpLimiterIdentifierVless, bytes, 8, &out) == kSoftIpLimiterExtractWait,
            "vless: short UUID should wait");

    bytes[0] = 1;
    require(softiplimiterTryExtractIdentifierFromBytes(
                kSoftIpLimiterIdentifierVless, bytes, sizeof(bytes), &out) == kSoftIpLimiterExtractInvalid,
            "vless: invalid version should reject");
}

static void testTrojanExtraction(void)
{
    const uint8_t hex[kSoftIpLimiterTrojanPasswordLen + 2] =
        "f1d1bbbcd40453cb585a2b136031c94f8b65ce015e62fc798ec6ea53\r\n";
    uint8_t sha224[SHA224_DIGEST_SIZE] = {0};
    hash_t  out = 0;

    require(asciiHexDecodeBytes(hex, kSoftIpLimiterTrojanPasswordLen, sha224, sizeof(sha224)),
            "trojan: test vector should decode");
    require(softiplimiterTryExtractIdentifierFromBytes(
                kSoftIpLimiterIdentifierTrojan, hex, kSoftIpLimiterTrojanPasswordLen, &out) ==
                kSoftIpLimiterExtractOk,
            "trojan: expected SHA224 extraction");
    require(out == calcHashBytes(sha224, sizeof(sha224)), "trojan: wrong SHA224 hash");

    require(softiplimiterTryExtractIdentifierFromBytes(kSoftIpLimiterIdentifierTrojan, hex, 12, &out) ==
                kSoftIpLimiterExtractWait,
            "trojan: short SHA224 hex should wait");

    uint8_t invalid_hex[kSoftIpLimiterTrojanPasswordLen] = {0};
    memorySet(invalid_hex, '0', sizeof(invalid_hex));
    invalid_hex[4] = 'g';
    require(softiplimiterTryExtractIdentifierFromBytes(
                kSoftIpLimiterIdentifierTrojan, invalid_hex, sizeof(invalid_hex), &out) ==
                kSoftIpLimiterExtractInvalid,
            "trojan: invalid hex should reject");

    uint8_t invalid_crlf[kSoftIpLimiterTrojanPasswordLen + 1] = {0};
    memorySet(invalid_crlf, '0', kSoftIpLimiterTrojanPasswordLen);
    invalid_crlf[kSoftIpLimiterTrojanPasswordLen] = 'x';
    require(softiplimiterTryExtractIdentifierFromBytes(
                kSoftIpLimiterIdentifierTrojan, invalid_crlf, sizeof(invalid_crlf), &out) ==
                kSoftIpLimiterExtractInvalid,
            "trojan: invalid CRLF prefix should reject");
}

static void testAdmissionSameIpRefs(void)
{
    softiplimiter_identity_map_t table = softiplimiter_identity_map_t_with_capacity(4);
    softiplimiter_table_result_t result = {0};
    softiplimiter_ip_key_t       ip = ip4(10, 0, 0, 1);
    hash_t                       id = 1001;

    require(softiplimiterTableAdmit(&table, id, &ip, 1, 1000, 100, &result), "same-ip: first admit failed");
    require(softiplimiterTableAdmit(&table, id, &ip, 1, 1000, 101, &result), "same-ip: second admit failed");
    require(result.count == 1, "same-ip: duplicate IP should count once");

    const softiplimiter_identity_entry_t *entry = findEntry(&table, id);
    require(entry != NULL && entry->ip_count == 1, "same-ip: expected one row");
    require(entry->ips[0].refs == 2, "same-ip: expected refs=2");

    softiplimiterTableRelease(&table, id, &ip, 1000, 102);
    entry = findEntry(&table, id);
    require(entry != NULL && entry->ips[0].refs == 1, "same-ip: first release should keep row with refs=1");
    softiplimiterTableRelease(&table, id, &ip, 1000, 103);
    require(findEntry(&table, id) == NULL, "same-ip: second release should erase empty identifier");

    softiplimiter_identity_map_t_drop(&table);
}

static void testAdmissionRejectsNewIpAtLimit(void)
{
    softiplimiter_identity_map_t table = softiplimiter_identity_map_t_with_capacity(4);
    softiplimiter_table_result_t result = {0};
    softiplimiter_ip_key_t       ip1 = ip4(10, 0, 0, 1);
    softiplimiter_ip_key_t       ip2 = ip4(10, 0, 0, 2);
    hash_t                       id = 1002;

    require(softiplimiterTableAdmit(&table, id, &ip1, 1, 1000, 100, &result), "limit: first admit failed");
    require(! softiplimiterTableAdmit(&table, id, &ip2, 1, 1000, 101, &result),
            "limit: second IP should reject");
    require(result.reason == kSoftIpLimiterTableLimitReached, "limit: expected limit reason");
    require(result.count == 1 && result.limit == 1, "limit: expected count=1 limit=1");

    softiplimiter_identity_map_t_drop(&table);
}

static void testStaleRowsArePrunedBeforeReject(void)
{
    softiplimiter_identity_map_t table = softiplimiter_identity_map_t_with_capacity(4);
    softiplimiter_table_result_t result = {0};
    softiplimiter_ip_key_t       ip1 = ip4(10, 0, 0, 1);
    softiplimiter_ip_key_t       ip2 = ip4(10, 0, 0, 2);
    hash_t                       id = 1003;

    require(softiplimiterTableAdmit(&table, id, &ip1, 1, 10, 100, &result), "stale: first admit failed");
    require(softiplimiterTableAdmit(&table, id, &ip2, 1, 10, 111, &result),
            "stale: stale row should be pruned before rejection");
    require(result.count == 1, "stale: expected one live row after prune");

    const softiplimiter_identity_entry_t *entry = findEntry(&table, id);
    require(entry != NULL && entry->ip_count == 1 && softiplimiterIpKeyEqual(&entry->ips[0].ip_key, &ip2),
            "stale: expected second IP to replace stale row");

    softiplimiter_identity_map_t_drop(&table);
}

static void testPayloadCheckClosesWhenRowMissing(void)
{
    softiplimiter_identity_map_t table = softiplimiter_identity_map_t_with_capacity(4);
    softiplimiter_table_result_t result = {0};
    softiplimiter_ip_key_t       ip = ip4(10, 0, 0, 1);
    hash_t                       id = 1004;

    require(softiplimiterTableAdmit(&table, id, &ip, 1, 10, 100, &result), "payload: admit failed");
    require(! softiplimiterTableTouch(&table, id, &ip, 1, 10, 111, &result),
            "payload: stale row should fail touch");
    require(result.reason == kSoftIpLimiterTableMissingRow, "payload: expected missing row after prune");
    require(findEntry(&table, id) == NULL, "payload: stale-only identifier should be erased");

    require(softiplimiterTableAdmit(&table, id, &ip, 1, 10, 200, &result), "payload: second admit failed");
    softiplimiterTableRelease(&table, id, &ip, 10, 201);
    require(! softiplimiterTableTouch(&table, id, &ip, 1, 10, 202, &result),
            "payload: removed row should fail touch");
    require(result.reason == kSoftIpLimiterTableMissingRow, "payload: expected missing row after release");

    softiplimiter_identity_map_t_drop(&table);
}

static void testTouchRefreshKeepsRowAlive(void)
{
    softiplimiter_identity_map_t table = softiplimiter_identity_map_t_with_capacity(4);
    softiplimiter_table_result_t result = {0};
    softiplimiter_ip_key_t       ip = ip4(10, 0, 0, 1);
    hash_t                       id = 2001;

    require(softiplimiterTableAdmit(&table, id, &ip, 1, 10, 100, &result), "refresh: admit failed");

    // Periodic touches refresh last_seen (atomic store/load round-trip) so the row
    // survives well past the raw tolerance window of 10ms.
    require(softiplimiterTableTouch(&table, id, &ip, 1, 10, 108, &result), "refresh: touch at 108 failed");
    require(softiplimiterTableTouch(&table, id, &ip, 1, 10, 116, &result), "refresh: touch at 116 failed");
    require(softiplimiterTableTouch(&table, id, &ip, 1, 10, 124, &result), "refresh: touch at 124 failed");

    const softiplimiter_identity_entry_t *entry = findEntry(&table, id);
    require(entry != NULL && entry->ip_count == 1, "refresh: row should remain alive after refreshes");
    require(atomicLoadRelaxed(&entry->ips[0].last_seen_ms) == 124, "refresh: last_seen should track the latest touch");

    // Stop refreshing: once now advances past last_seen + tolerance the row expires.
    require(! softiplimiterTableTouch(&table, id, &ip, 1, 10, 200, &result), "refresh: stale row should expire");
    require(result.reason == kSoftIpLimiterTableMissingRow, "refresh: expected missing row after expiry");
    require(findEntry(&table, id) == NULL, "refresh: expired-only identifier should be erased");

    softiplimiter_identity_map_t_drop(&table);
}

int main(void)
{
    testVlessExtraction();
    testTrojanExtraction();
    testAdmissionSameIpRefs();
    testAdmissionRejectsNewIpAtLimit();
    testStaleRowsArePrunedBeforeReject();
    testPayloadCheckClosesWhenRowMissing();
    testTouchRefreshKeepsRowAlive();

    printf("softiplimiter_test: all checks passed\n");
    return 0;
}

