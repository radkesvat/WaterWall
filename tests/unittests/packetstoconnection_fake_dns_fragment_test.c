#include "PacketsToConnection/structure.h"

static void requirePolicy(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "packetstoconnection_fake_dns_fragment_test: %s\n", message);
        _Exit(1);
    }
}

int main(void)
{
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
