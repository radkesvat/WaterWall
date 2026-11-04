# Router dns config unknown key

A misspelled key inside `dns` (`"mod"` instead of `"mode"`) must stop startup instead of silently keeping core DNS.

Topology: `listener`: TcpListener → `router`; `router`: Router → `direct-connector` (default), rule `protocol: "dns"` → `dns-connector`; `dns-connector`: UdpConnector; `direct-connector`: TcpConnector. Startup is expected to fail, so nothing listens.

Expected log text: `JSON Error: Router->settings->dns->mod : unknown key`.

CTest: `waterwall.router_dns_config_unknown_key`.
