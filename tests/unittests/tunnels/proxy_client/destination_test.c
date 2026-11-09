/*
 * Covers: shared proxy-client address, port and protocol selection.
 * Setup: ordinary address contexts and a silent network logger; no lines, workers or network I/O.
 * Cases: fixed/context sources, IPv4/IPv6, owned/constant/resolved domains, copied metadata,
 * all protocol-flag combinations and missing context fields with existing partial-mutation behavior.
 * Checks: selected endpoint, independent owned domain storage, protocol normalization and refusal results.
 * Limits: DNS strategy overrides, protocol-specific validation and callback ordering remain in client suites.
 * CTest: waterwall.proxy_client_destination_unit, Debug and Release.
 */
#include "ProxyClientCommon/destination.h"

#include "loggers/network_logger.h"
#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static void setAddress(address_context_t *context, unsigned form, bool configured)
{
    static const char *const domains[] = {"incoming.example", "configured.example"};
    const char              *domain    = domains[configured];
    if (form < 2)
    {
        const char *address =
            form == 0 ? (configured ? "192.0.2.1" : "198.51.100.2") : (configured ? "2001:db8::1" : "2001:db8::2");
        require(addresscontextSetIpAddress(context, address), "test IP setup failed");
    }
    else if (form == 3)
        addresscontextDomainSetConstMem(context, domain, (uint8_t) stringLength(domain));
    else
        addresscontextDomainSetByString(context, domain);
    if (form == 4)
    {
        require(ipaddr_aton(configured ? "203.0.113.1" : "203.0.113.2", &context->ip_address),
                "resolved IP setup failed");
        context->domain_resolved = true;
    }
    context->port                              = configured ? 443 : 5353;
    context->domain_strategy                   = configured ? kDsPreferIpV6 : kDsOnlyIpV4;
    context->optional_flags.detected_protocols = configured ? kAddressContextProtocolTls : kAddressContextProtocolHttp1;
    addresscontextSetOnlyProtocol(context, configured ? IP_PROTO_TCP : IP_PROTO_UDP);
}

static void requireAddress(const address_context_t *actual, const address_context_t *expected)
{
    require(actual->type_ip == expected->type_ip, "selected address type changed");
    require(actual->domain_strategy == expected->domain_strategy, "selected address strategy changed");
    require(actual->optional_flags.detected_protocols == expected->optional_flags.detected_protocols,
            "selected address metadata changed");
    require(actual->domain_constant == expected->domain_constant, "selected domain ownership changed");
    require(actual->domain_resolved == expected->domain_resolved, "selected domain resolution state changed");
    if (expected->type_ip || expected->domain_resolved)
        require(ip_addr_cmp(&actual->ip_address, &expected->ip_address), "selected IP changed");
    if (expected->domain != NULL)
    {
        require(actual->domain != NULL && actual->domain_len == expected->domain_len &&
                    memoryEqual(actual->domain, expected->domain, expected->domain_len + 1U),
                "selected domain changed");
        require(expected->domain_constant ? actual->domain == expected->domain : actual->domain != expected->domain,
                "selected domain storage does not match its ownership");
    }
    else
        require(actual->domain == NULL && actual->domain_len == 0, "IP selection retained a domain");
}

static void requireProtocol(const address_context_t *context, bool udp)
{
    require(context->proto_tcp == ! udp && context->proto_udp == udp && ! context->proto_icmp &&
                ! context->proto_packet,
            "selected transport protocol was not normalized");
}

static void testSourceCombinations(void)
{
    for (unsigned form = 0; form < 5; ++form)
        for (unsigned address_from_context = 0; address_from_context < 2; ++address_from_context)
            for (unsigned port_from_context = 0; port_from_context < 2; ++port_from_context)
                for (unsigned protocol = 0; protocol < 3; ++protocol)
                {
                    address_context_t target = {0}, destination = {0}, expected = {0};
                    setAddress(&target, form, true);
                    setAddress(&destination, form, false);
                    addresscontextCopy(&expected, address_from_context ? &destination : &target);
                    proxy_client_destination_t selection = {
                        .target               = &target,
                        .protocol             = protocol == 0   ? kProxyClientProtocolTcp
                                                : protocol == 1 ? kProxyClientProtocolUdp
                                                                : kProxyClientProtocolDestContext,
                        .address_from_context = address_from_context != 0,
                        .port_from_context    = port_from_context != 0,
                    };
                    require(proxyClientApplyDestination(&destination, &selection, "TestClient"),
                            "valid source combination was refused");
                    requireAddress(&destination, &expected);
                    require(destination.port == (port_from_context ? 5353 : 443), "wrong port source selected");
                    requireProtocol(&destination, protocol != 0);
                    require(target.port == 443 && target.proto_tcp && ! target.proto_udp,
                            "selection changed the configured target");
                    addresscontextReset(&target);
                    requireAddress(&destination, &expected);
                    addresscontextReset(&expected);
                    addresscontextReset(&destination);
                }
}

static void testProtocolFlags(void)
{
    for (unsigned flags = 0; flags < 16; ++flags)
        for (unsigned fixed = 0; fixed < 3; ++fixed)
        {
            address_context_t target = {0}, destination = {0};
            setAddress(&target, 2, true);
            setAddress(&destination, 1, false);
            destination.proto_tcp                = (flags & 1U) != 0;
            destination.proto_udp                = (flags & 2U) != 0;
            destination.proto_icmp               = (flags & 4U) != 0;
            destination.proto_packet             = (flags & 8U) != 0;
            proxy_client_destination_t selection = {
                .target   = &target,
                .protocol = fixed == 0   ? kProxyClientProtocolDestContext
                            : fixed == 1 ? kProxyClientProtocolTcp
                                         : kProxyClientProtocolUdp,
            };
            require(proxyClientApplyDestination(&destination, &selection, "TestClient"),
                    "protocol selection refused a valid target");
            requireProtocol(&destination, fixed == 2 || (fixed == 0 && flags == 2));
            requireAddress(&destination, &target);
            addresscontextReset(&destination);
            addresscontextReset(&target);
        }
}

static void testMissingAddress(void)
{
    for (unsigned form = 0; form < 3; ++form)
    {
        address_context_t target = {0}, destination = {0};
        setAddress(&target, 2, true);
        if (form != 0)
            require(addresscontextSetIpAddress(&destination, form == 1 ? "0.0.0.0" : "::"),
                    "wildcard address setup failed");
        destination.port = 5353;
        addresscontextSetOnlyProtocol(&destination, IP_PROTO_UDP);
        destination.domain_strategy          = kDsOnlyIpV4;
        proxy_client_destination_t selection = {
            .target               = &target,
            .protocol             = kProxyClientProtocolDestContext,
            .address_from_context = true,
            .port_from_context    = true,
        };
        require(! proxyClientApplyDestination(&destination, &selection, "TestClient"),
                "missing context address was accepted");
        require(destination.domain == NULL && destination.type_ip == (form != 0) && destination.port == 5353 &&
                    destination.domain_strategy == kDsOnlyIpV4,
                "missing-address refusal changed the incoming destination");
        requireProtocol(&destination, true);
        addresscontextReset(&destination);
        addresscontextReset(&target);
    }
}

static void testMissingPort(void)
{
    for (unsigned address_from_context = 0; address_from_context < 2; ++address_from_context)
    {
        address_context_t target = {0}, destination = {0}, expected = {0};
        setAddress(&target, 2, true);
        setAddress(&destination, 4, false);
        destination.port = 0;
        addresscontextCopy(&expected, address_from_context ? &destination : &target);
        proxy_client_destination_t selection = {
            .target               = &target,
            .protocol             = kProxyClientProtocolDestContext,
            .address_from_context = address_from_context != 0,
            .port_from_context    = true,
        };
        require(! proxyClientApplyDestination(&destination, &selection, "TestClient"),
                "missing context port was accepted");
        requireAddress(&destination, &expected);
        require(destination.port == expected.port && destination.proto_tcp == expected.proto_tcp &&
                    destination.proto_udp == expected.proto_udp,
                "missing-port refusal changed the existing address-copy ordering");
        addresscontextReset(&expected);
        addresscontextReset(&destination);
        addresscontextReset(&target);
    }
}

static void testPinnedEndpoint(void)
{
    for (unsigned form = 0; form < 5; ++form)
        for (unsigned udp = 0; udp < 2; ++udp)
        {
            address_context_t target = {0}, destination = {0}, expected = {0};
            setAddress(&target, form, true);
            setAddress(&destination, form, false);
            addresscontextSetOnlyProtocol(&destination, udp ? IP_PROTO_UDP : IP_PROTO_TCP);
            addresscontextSetResolverDns(&destination, true);
            addresscontextCopy(&expected, &destination);
            addresscontextSetDestinationPinned(&destination, true);
            proxy_client_destination_t selection = {
                .target = &target, .protocol = udp ? kProxyClientProtocolTcp : kProxyClientProtocolUdp};
            require(proxyClientApplyDestination(&destination, &selection, "TestClient"),
                    "pinned logical DNS endpoint refused");
            requireAddress(&destination, &expected);
            require(destination.port == 5353 && addresscontextIsResolverDns(&destination),
                    "configured proxy endpoint replaced the DNS peer");
            requireProtocol(&destination, udp != 0);
            require(! addresscontextDestinationIsPinned(&destination), "logical proxy did not consume the pin");
            // The next independent selector must retain its fixed endpoint.
            require(proxyClientApplyDestination(&destination, &selection, "OuterClient"),
                    "outer carrier target selection failed");
            requireAddress(&destination, &target);
            require(destination.port == 443 && ! addresscontextIsResolverDns(&destination),
                    "logical DNS pin leaked to the independent outer endpoint");
            addresscontextReset(&expected);
            addresscontextReset(&destination);
            addresscontextReset(&target);
        }
}

int main(void)
{
    initWLibc();
    logger_t *logger = loggerCreate();
    loggerSetLevel(logger, LOG_LEVEL_SILENT);
    setNetworkLogger(logger);
    TEST_RUN_CASE(testSourceCombinations);
    TEST_RUN_CASE(testProtocolFlags);
    TEST_RUN_CASE(testMissingAddress);
    TEST_RUN_CASE(testMissingPort);
    TEST_RUN_CASE(testPinnedEndpoint);
    networkloggerDestroy();
    return 0;
}
