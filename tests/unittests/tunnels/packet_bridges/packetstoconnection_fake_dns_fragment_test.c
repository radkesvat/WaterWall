/*
 * Covers: packetstoconnection fake dns fragment; the explicit inputs, callbacks and expected results
 * below define this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Checks: Assertion labels include: packetstoconnection_fake_dns_fragment_test; fragmented TCP to the
 * fake-DNS address must be forwarded; fragmented UDP to the fake-DNS address must be dropped
 * address-wide; disabling fake DNS must restore normal fragmented UDP routing
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.packetstoconnection_fake_dns_fragment_unit
 */
#include "PacketsToConnection/structure.h"

#include "test_assert.h"

#define requirePolicy(condition, message) TEST_REQUIRE(TEST_FAILURE_QUICK_EXIT, condition, message)

int main(void)
{
    testCaseSet("packetstoconnection_fake_dns_fragment_test");
    const ip4_addr_p_t fake_addr = {.addr = PP_HTONL(LWIP_MAKEU32(198, 18, 0, 2))};
    ptc_fake_dns_t     dns       = {
                  .listen_addr = {.addr = fake_addr.addr},
                  .enabled     = true,
    };

    requirePolicy(! ptcFakeDnsShouldDropFragment(&dns, &fake_addr, IP_PROTO_TCP, true),
                  "fragmented TCP to the fake-DNS address must be forwarded");
    requirePolicy(ptcFakeDnsShouldDropFragment(&dns, &fake_addr, IP_PROTO_UDP, true),
                  "fragmented UDP to the fake-DNS address must be dropped address-wide");

    dns.enabled = false;
    requirePolicy(! ptcFakeDnsShouldDropFragment(&dns, &fake_addr, IP_PROTO_UDP, true),
                  "disabling fake DNS must restore normal fragmented UDP routing");

    printf("packetstoconnection_fake_dns_fragment_test: all cases passed\n");
    return 0;
}
