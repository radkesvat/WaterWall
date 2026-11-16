# ping6 ipv6 in ipv4 roundtrip

Uses explicit `ipv6-in-ipv4` mode with mirrored `fd00:1234::1` / `fd00:1234::2`
inner endpoints. The outer IPv4 protocol is 41; IPv6 Next Header is 58.
The existing namespace harness keeps traffic local and bounded. Direct/default
coverage remains in `ping6_new_ip_icmpv6_roundtrip`.

The server enables exact replies while the client retains the false default,
covering asymmetric acknowledgements with fresh application-data requests in both
directions on four packet workers.
