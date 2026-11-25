#pragma once

/**
 * Domain name resolution strategy.
 */
enum domain_strategy
{
    kDsInvalid,    // Invalid or unspecified strategy
    kDsPreferIpV4, // Try IPv4 first, fallback to IPv6
    kDsPreferIpV6, // Try IPv6 first, fallback to IPv4
    kDsOnlyIpV4,   // Use only IPv4 addresses
    kDsOnlyIpV6    // Use only IPv6 addresses
};
