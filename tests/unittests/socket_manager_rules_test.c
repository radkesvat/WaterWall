#include "managers/socket_manager.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void requireEqStr(const char *got, const char *expected, const char *message)
{
    if (strcmp(got, expected) != 0)
    {
        fprintf(stderr, "%s\n  expected: %s\n  got     : %s\n", message, expected, got);
        exit(1);
    }
}

// Rule ranks must order specific-before-wildcard, with interface-scoped rules first inside each tier so that
// a wildcard listener never steals traffic before a more specific listener's redirect rule is installed.
static void testRuleRanks(void)
{
    int specific_iface = socketManagerComputeRedirectRuleRank(true, true);
    int specific       = socketManagerComputeRedirectRuleRank(true, false);
    int wildcard_iface = socketManagerComputeRedirectRuleRank(false, true);
    int wildcard       = socketManagerComputeRedirectRuleRank(false, false);

    require(specific_iface == 0, "rank: specific+interface should be 0");
    require(specific == 1, "rank: specific should be 1");
    require(wildcard_iface == 2, "rank: wildcard+interface should be 2");
    require(wildcard == 3, "rank: wildcard should be 3");

    // Strict specificity ordering.
    require(specific_iface < specific, "rank: specific+iface must precede specific");
    require(specific < wildcard_iface, "rank: specific must precede wildcard+iface");
    require(wildcard_iface < wildcard, "rank: wildcard+iface must precede wildcard");
}

static void testSpecificSinglePort(void)
{
    char cmd[256];
    socketManagerBuildRedirectCommand(
        cmd, sizeof(cmd), "iptables", "WW_TEST_4", "TCP", true, "10.0.0.1", NULL, 443, 443, 12345);
    requireEqStr(cmd,
                 "iptables -t nat -A WW_TEST_4 -p TCP -d 10.0.0.1 --dport 443 -j REDIRECT --to-port 12345",
                 "specific single-port TCP command mismatch");
    require(strstr(cmd, "-A PREROUTING") == NULL, "redirect rules must not be installed directly in PREROUTING");
}

static void testWildcardRange(void)
{
    char cmd[256];
    // Wildcard means: omit -d entirely. Never emit -d 0.0.0.0.
    socketManagerBuildRedirectCommand(
        cmd, sizeof(cmd), "iptables", "WW_TEST_4", "UDP", false, "0.0.0.0", NULL, 1000, 2000, 500);
    requireEqStr(cmd,
                 "iptables -t nat -A WW_TEST_4 -p UDP --dport 1000:2000 -j REDIRECT --to-port 500",
                 "wildcard range UDP command mismatch");
    require(strstr(cmd, "-d ") == NULL, "wildcard command must not contain a -d match");
}

static void testSpecificWithInterface(void)
{
    char cmd[256];
    socketManagerBuildRedirectCommand(
        cmd, sizeof(cmd), "iptables", "WW_TEST_4", "TCP", true, "10.0.0.1", "eth0", 80, 80, 8080);
    requireEqStr(cmd,
                 "iptables -t nat -A WW_TEST_4 -p TCP -i eth0 -d 10.0.0.1 --dport 80 -j REDIRECT --to-port 8080",
                 "specific+interface TCP command mismatch");
}

static void testWildcardWithInterface(void)
{
    char cmd[256];
    socketManagerBuildRedirectCommand(
        cmd, sizeof(cmd), "iptables", "WW_TEST_4", "UDP", false, NULL, "wg0", 53, 53, 5300);
    requireEqStr(cmd,
                 "iptables -t nat -A WW_TEST_4 -p UDP -i wg0 --dport 53 -j REDIRECT --to-port 5300",
                 "wildcard+interface UDP command mismatch");
    require(strstr(cmd, "-d ") == NULL, "wildcard+interface command must not contain a -d match");
    require(strstr(cmd, "-i wg0") != NULL, "wildcard+interface command must contain -i match");
}

static void testIpv6Tool(void)
{
    char cmd[256];
    socketManagerBuildRedirectCommand(
        cmd, sizeof(cmd), "ip6tables", "WW_TEST_6", "TCP", true, "fd00::1", NULL, 443, 443, 9);
    requireEqStr(cmd,
                 "ip6tables -t nat -A WW_TEST_6 -p TCP -d fd00::1 --dport 443 -j REDIRECT --to-port 9",
                 "ipv6 specific TCP command mismatch");
}

static void testEmptyDestTreatedAsWildcard(void)
{
    char cmd[256];
    // has_dest true but empty string must still omit -d (defensive).
    socketManagerBuildRedirectCommand(
        cmd, sizeof(cmd), "iptables", "WW_TEST_4", "TCP", true, "", NULL, 22, 22, 2200);
    requireEqStr(cmd,
                 "iptables -t nat -A WW_TEST_4 -p TCP --dport 22 -j REDIRECT --to-port 2200",
                 "empty-dest command should omit -d");
}

static void testOwnedChainCommands(void)
{
    char cmd[256];

    socketManagerBuildOwnedChainCommand(
        cmd, sizeof(cmd), "iptables", kSocketManagerIptablesCreateChain, "WW_TEST_4");
    requireEqStr(cmd, "iptables -t nat -N WW_TEST_4", "owned chain create command mismatch");

    socketManagerBuildOwnedChainCommand(
        cmd, sizeof(cmd), "iptables", kSocketManagerIptablesAddJump, "WW_TEST_4");
    requireEqStr(cmd, "iptables -t nat -A PREROUTING -j WW_TEST_4", "owned chain jump command mismatch");

    socketManagerBuildOwnedChainCommand(
        cmd, sizeof(cmd), "iptables", kSocketManagerIptablesDeleteJump, "WW_TEST_4");
    requireEqStr(cmd, "iptables -t nat -D PREROUTING -j WW_TEST_4", "owned chain jump deletion mismatch");

    socketManagerBuildOwnedChainCommand(
        cmd, sizeof(cmd), "iptables", kSocketManagerIptablesFlushChain, "WW_TEST_4");
    requireEqStr(cmd, "iptables -t nat -F WW_TEST_4", "owned chain flush must name only WaterWall's chain");

    socketManagerBuildOwnedChainCommand(
        cmd, sizeof(cmd), "iptables", kSocketManagerIptablesDeleteChain, "WW_TEST_4");
    requireEqStr(cmd, "iptables -t nat -X WW_TEST_4", "owned chain deletion must name only WaterWall's chain");
}

static ip_addr_t ipv4Addr(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    ip_addr_t ip;
    memoryZero(&ip, sizeof(ip));
    ip.type = IPADDR_TYPE_V4;
    IP4_ADDR(&ip.u_addr.ip4, a, b, c, d);
    return ip;
}

// The balance hash must keep stickiness separate per local-endpoint class: a source pinned via a wildcard
// listener must not collide with the same source reaching a specific local address (and vice versa), while
// the same (source, specific local addr) must remain stable.
static void testBalanceLocalHash(void)
{
    const hash_t    src = 0xDEADBEEFCAFEBABEULL;
    const ip_addr_t a1  = ipv4Addr(10, 0, 0, 1);
    const ip_addr_t a2  = ipv4Addr(10, 0, 0, 2);

    // Scope = (local addr, local port, tier). Same scope must be stable.
    hash_t base  = socketManagerCombineBalanceLocalHash(src, &a1, 443, 0);
    hash_t base2 = socketManagerCombineBalanceLocalHash(src, &a1, 443, 0);
    require(base == base2, "balance hash: same source+scope must be stable");

    // Every scope component must change the key so a balance group reused across non-identical listeners
    // cannot reuse a pin from a different scope.
    require(base != socketManagerCombineBalanceLocalHash(src, &a2, 443, 0),
            "balance hash: different local address must differ");
    require(base != socketManagerCombineBalanceLocalHash(src, &a1, 8443, 0),
            "balance hash: different local port must differ");
    require(base != socketManagerCombineBalanceLocalHash(src, &a1, 443, 1),
            "balance hash: different dispatch tier must differ");
    require(base != socketManagerCombineBalanceLocalHash(src ^ 0x1ULL, &a1, 443, 0),
            "balance hash: different source must differ");

    // Wildcard tiers 1 and 2 for the same destination must be distinct keys.
    require(socketManagerCombineBalanceLocalHash(src, &a1, 443, 1) !=
                socketManagerCombineBalanceLocalHash(src, &a1, 443, 2),
            "balance hash: wildcard family vs dual-stack tier must differ");
}

// Returns the wildcard dispatch tier (1 or 2) at which a wildcard of the given family serves the destination,
// or -1 if it never does. Mirrors how distribute*Payload/Socket iterate tiers 0..2 in order.
static int wildcardServeTier(bool bind_is_v6_wildcard, bool dest_is_v4)
{
    for (int tier = 1; tier <= 2; ++tier)
    {
        if (socketManagerWildcardMatchesTier(bind_is_v6_wildcard, dest_is_v4, tier))
        {
            return tier;
        }
    }
    return -1;
}

// Wildcard specificity: for IPv4 destinations a 0.0.0.0 wildcard must be preferred over a :: dual-stack
// wildcard regardless of registration order; for IPv6 destinations only :: serves.
static void testWildcardTierSpecificity(void)
{
    const bool kV6 = true, kV4Wild = false;

    // IPv4 destination.
    require(socketManagerWildcardMatchesTier(kV4Wild, true, 1), "v4 dest: 0.0.0.0 must match family tier");
    require(! socketManagerWildcardMatchesTier(kV6, true, 1), "v4 dest: :: must not match family tier");
    require(socketManagerWildcardMatchesTier(kV6, true, 2), "v4 dest: :: must match dual-stack fallback tier");
    require(! socketManagerWildcardMatchesTier(kV4Wild, true, 2), "v4 dest: 0.0.0.0 must not match fallback tier");

    // IPv6 destination.
    require(socketManagerWildcardMatchesTier(kV6, false, 1), "v6 dest: :: must match family tier");
    require(! socketManagerWildcardMatchesTier(kV4Wild, false, 1), "v6 dest: 0.0.0.0 must not serve IPv6");
    require(! socketManagerWildcardMatchesTier(kV4Wild, false, 2), "v6 dest: 0.0.0.0 must never serve IPv6");
    require(! socketManagerWildcardMatchesTier(kV6, false, 2), "v6 dest: :: fallback tier is IPv4-only");

    // Tier 0 (exact) is never a wildcard match.
    require(! socketManagerWildcardMatchesTier(kV6, true, 0), "tier 0 is exact, not wildcard");
    require(! socketManagerWildcardMatchesTier(kV4Wild, true, 0), "tier 0 is exact, not wildcard");

    // The decisive property: 0.0.0.0 outranks :: for IPv4 (lower tier wins) irrespective of order.
    require(wildcardServeTier(kV4Wild, true) == 1, "v4 dest: 0.0.0.0 serves at tier 1");
    require(wildcardServeTier(kV6, true) == 2, "v4 dest: :: serves at tier 2");
    require(wildcardServeTier(kV4Wild, true) < wildcardServeTier(kV6, true),
            "v4 dest: 0.0.0.0 must be preferred over :: dual-stack");

    // IPv6 destination: only :: serves.
    require(wildcardServeTier(kV6, false) == 1, "v6 dest: :: serves at tier 1");
    require(wildcardServeTier(kV4Wild, false) == -1, "v6 dest: 0.0.0.0 never serves");
}

int main(void)
{
    testRuleRanks();
    testBalanceLocalHash();
    testWildcardTierSpecificity();
    testSpecificSinglePort();
    testWildcardRange();
    testSpecificWithInterface();
    testWildcardWithInterface();
    testIpv6Tool();
    testEmptyDestTreatedAsWildcard();
    testOwnedChainCommands();

    printf("socket_manager_rules_test: all tests passed\n");
    return 0;
}
