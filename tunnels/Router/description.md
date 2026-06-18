# Router

A layer-4 **rule-based router**. It sits inside a chain like a middle tunnel and,
on the **first upstream payload** of each connection, evaluates an ordered list
of routing rules to decide where the connection should go:

- the **first** rule whose match conditions **all** succeed (logical `AND`) wins,
  and the connection is handed to that rule's `target` node;
- if **no** rule matches, the connection continues to the node's top-level
  `next` — the **default route**.

It is closely related to [`SniffRouter`](../SniffRouter/description.md): they
share the same target-folding and lazy-decision lifecycle. The difference is the
decision input. `SniffRouter` decides purely by sniffing the first bytes (HTTP
`Host` / TLS SNI / reverse handshake), while `Router` decides by matching a
flexible set of **connection facts** (source/destination address, ports, network
type, detected protocol, username, destination domain, …) combined into rules.

> **Implementation status.** Configuration parsing, rule ordering, `AND`
> evaluation, target binding and the full connection lifecycle are complete and
> safe. Matcher status:
>
> - **Functional:** `source-ips`, `destination-ip`, `network`,
>   `destination-domain`, `source-port`, `destination-port` (see notes per field
>   below). `geoip:<cc>` is functional for `source-ips` and `destination-ip`
>   when `geoip-db-path` is configured. `destination-domain` can use a
>   configured sniffed HTTP `Host` or TLS SNI value. `geosite:` patterns are
>   still accepted but never match.
> - **`username` / `password`:** functional, exact and case-sensitive. The
>   authenticating tunnel stores the raw username/password on the line
>   (`lineGetAuthenticatedUsername` / `lineGetAuthenticatedPassword`), so the
>   Router needs no users-table lookup. Population per protocol:
>   - `Socks5Server`: the client-supplied SOCKS username + password.
>   - `TrojanServer` / `VlessServer`: the account name + raw password resolved
>     from the authenticated user in a single locked lookup
>     (`authenticationclientGet...WithProfile`). For Vless these are populated
>     only when an `AuthenticationClient` is used; in local UUID-list mode there
>     is no account name, so only the password (the canonical UUID) is set.
>   Note the username differs in kind by protocol: SOCKS5 exposes the
>   client-typed username, while Trojan/Vless expose the server-side account name.
> - **Stubs that return `true` (do not constrain):** `protocol`, `attributes`.
>   A rule whose only condition is one of these currently matches everything.

## Why this node is easy to misread

The word "router" suggests an immediate, stateless decision, but `Router`
behaves like a **deferred branch selector**:

- It does **not** route at `Init`. It waits for the first upstream payload so
  content-based matchers (e.g. `protocol`) have bytes to inspect. The buffered
  bytes are then **replayed** to the chosen branch with no loss.
- A rule's `target` is **not** a "send and forget" address. Each `target` node is
  **folded into the same chain** during `onChain`, exactly like `SniffRouter`
  routes. That means the target gets a per-line state slot and its **downstream**
  traffic returns back **through** the `Router` to the previous node.
- The top-level `next` is the **default route**, used when no rule matches or
  when no rules are configured. It is a normal upstream continuation, not
  "rule 0".
- Because matching is deferred to the first upstream payload, a flow where the
  **server speaks first** (no initial client bytes) will not be classified and
  will sit until bytes arrive — the same limitation `SniffRouter` has. Put
  `Router` where the client side sends first (the common case).

## How it works

1. Upstream `Init` only initializes the router's own per-line state; it does
   **not** initialize any branch yet.
2. The first upstream payload is buffered and passed to the rule evaluator
   (`routerClassify`).
3. If `sniffing` is enabled, Router first tries to populate destination-domain
   metadata from HTTP Host or TLS SNI. This happens even when no rules are
   configured, because downstream tunnels may still use the routing metadata.
4. Rules are tested **top to bottom in JSON order**. For each rule, every
   configured condition is evaluated and `AND`-combined. The first fully matching
   rule selects its `target`.
5. The chosen branch (rule `target`, or the default `next`) is initialized, and
   the buffered bytes are replayed to it. From then on payloads flow straight
   through to the chosen branch, and downstream traffic returns through the
   router.

## Settings

| key | type | required | description |
|-----|------|----------|-------------|
| `rules` | array | no | ordered list of routing rule objects (see below) |
| `sniffing` | array | no | root-level array of sniffing methods: `http`, `tls`; missing or empty disables sniffing |
| `sniff-even-if-domain-is-already-provided` | boolean | no | default `false`; when `false`, Router does not sniff or overwrite destinations that already have `dest_ctx.domain` |
| `geoip-db-path` | string | only with `geoip:` rules | path to a MaxMind country database used by `geoip:<cc>` tokens |

The node itself must define a top-level `next`; this is the **default route**
used when no rule matches. A `Router` with no `rules` still sends every
connection to `next` (a warning is logged at startup), but if `sniffing` is
enabled it may first inspect the initial payload to fill `dest_ctx.domain`.

### Sniffing

`sniffing` is a root-level setting inside the Router `settings` object, outside
the `rules` array:

```json
{
    "sniffing": ["http", "tls"]
}
```

Supported values are:

- `http` — sniff the HTTP/1 `Host` header.
- `tls` — sniff the TLS ClientHello SNI.

The value must be an array. Missing `sniffing` or an empty array disables
sniffing. Values are parsed case-insensitively, but only `http` and `tls` are
accepted.

By default, Router only sniffs destinations that do not already have a
destination domain. If `dest_ctx.domain` is already populated, Router leaves it
unchanged and evaluates rules using that existing domain. Set
`sniff-even-if-domain-is-already-provided` to `true` only when you intentionally
want Host/SNI to replace an already-domain destination.

Why this default matters: an HTTP `Host` header or TLS SNI is data sent by the
client inside the connection. It is useful for classifying IP-only connections,
such as a transparent proxy flow where the original destination is an IP address
and Router wants to match `destination-domain` rules. But if the destination
context already contains a domain, that domain is usually the endpoint chosen by
an earlier tunnel or configuration parser. Replacing it with client-supplied
Host/SNI can change what a downstream connector resolves and connects to. With
the default `false`, Router treats Host/SNI as extra metadata only for IP-backed
destinations and does not allow it to redirect a domain-backed destination.

When `sniff-even-if-domain-is-already-provided` is `true`, Router will sniff even
if `dest_ctx.domain` is already set. If Host/SNI is found, Router replaces
`dest_ctx.domain` with the sniffed name before evaluating rules. For a
domain-only destination that has no resolved IP, `domain_resolved` stays `false`,
so a downstream connector may DNS-resolve and connect to the sniffed name
instead of the original domain. Enable this only when the chain deliberately
trusts the application-layer Host/SNI more than the destination domain already
stored on the line.

Sniffing happens on the first upstream payload before rules are evaluated. It
also runs when the `rules` array is missing, because sniffing updates the line's
routing metadata before the connection falls through to the default `next`
branch. If a configured sniffer needs more bytes, Router continues using its
existing pending first-payload buffer until the Host/SNI is found, the parser
decides it is not present, or the bounded sniff window is exhausted.

When Host/SNI is found, Router stores it in `dest_ctx.domain`, so
`destination-domain` rules can match an originally IP-only destination. This
does not replace the destination endpoint: the original destination IP, port,
protocol flags and address type are preserved. If the destination is backed by a
concrete IP address, Router marks the observed domain as resolved
(`domain_resolved = true`) so downstream connectors keep using the original IP
instead of resolving the sniffed name again. Wildcard/any IPs such as `0.0.0.0`
or `::` are not treated as resolved destinations. If
`sniff-even-if-domain-is-already-provided` is enabled and the destination is
domain-only with no resolved IP, Router stores the sniffed domain but leaves
`domain_resolved = false`; downstream connectors will resolve that new domain.

### Rule object

Every rule object **must** contain:

| key | type | required | description |
|-----|------|----------|-------------|
| `target` | string | **yes** | name of the node to route to when this rule matches |

…and **at least one** match condition from the table below. Multiple conditions
in the same rule are combined with `AND` (all must match). Unknown keys inside a
rule are ignored with a warning.

| condition | status | accepts | meaning |
|-----------|--------|---------|---------|
| `source-ips` | functional | string or array of strings | matches the line source IP against single IPs, CIDR ranges, or MaxMind country tokens such as `geoip:ir`. A bare IP is a `/32` (or `/128`) host route. Numeric and GeoIP entries are OR-combined inside this field |
| `source-port` | functional | number/string or array | matches `src_ctx.port` — the port the peer connected to (the real local/inbound port, resolved per-connection even on multiport backends; i.e. the destination port in the peer's packets) — against single ports and ranges, e.g. `53`, `443`, `1000-2000` |
| `network` | functional | string or array | matches the `dest_ctx` protocol bit flags; `tcp`, `udp`, `icmp`, `packet`, or combined `tcp,udp` (OR within the field) |
| `protocol` | stub (matches all) | string or array | detected/known protocol, e.g. `http`, `tls`, `quic`, `bittorrent` |
| `attributes` | stub (matches all) | array | reserved for future metadata-based matching (parsed but unused) |
| `destination-ip` | functional | string or array | matches the line destination IP (`dest_ctx`) against single IPs, CIDR ranges, or MaxMind country tokens such as `geoip:us`. Numeric and GeoIP entries are OR-combined inside this field. A domain destination has no IP and does not match |
| `destination-domain` | functional | string or array | matches the line destination domain (`dest_ctx.domain`), case-insensitive: exact (`google.com`), wildcard (`*.google.com`, subdomains only), or `*` (any). `geosite:cn` accepted but never matches yet |
| `username` | functional | string or array | exact, case-sensitive match of the authenticated user's raw username stored on the line. No authenticated username → no match |
| `password` | functional | string or array | exact, case-sensitive match of the authenticated user's raw password stored on the line. No authenticated password → no match |
| `destination-port` | functional | number/string or array | matches the line destination port (`dest_ctx.port`) against single ports and ranges, e.g. `53`, `443`, `1000-2000` |

### Evaluation order

- Rules are evaluated **in the order they appear** in the JSON array. JSON order
  is significant.
- Within a single rule, conditions are an **`AND`**: the rule matches only if
  **every** configured condition matches.
- The **first** matching rule wins; later rules are not consulted.
- If no rule matches, the connection uses the top-level `next` default route.

## Module architecture

Each supported condition is implemented as its **own matcher/parser module** under
`modules/<field>/`, mirroring how `AuthenticationServer` splits each API into its
own module:

```
modules/
  matchers.c            # dispatcher table tying all matchers together
  source_ips/           # one module per condition; each owns:
  source_port/          #   <field>Parse   -> read + validate the field from JSON
  network/              #   <field>Match   -> test the condition
  protocol/             #   <field>Destroy -> free owned memory
  attributes/
  destination_ip/
  destination_domain/
  username/
  destination_port/
```

All matchers share a uniform interface that operates on its own slice of
`router_rule_t`:

```c
router_field_parse_t  <field>Parse  (router_rule_t *rule, const cJSON *rule_json, uint32_t rule_index);
bool                  <field>Match  (const router_rule_t *rule, const router_match_ctx_t *mctx);
void                  <field>Destroy(router_rule_t *rule);
```

`router_match_ctx_t` carries the `line_t` (for routing metadata such as
source/destination address, ports, network type and the authenticated user) and
the buffered first-payload window (for content-based matchers such as
`protocol`). To implement real matching, fill in the relevant `<field>Match`
function — no lifecycle or parsing code needs to change.

`modules/matchers.c` is the single registry of matchers. Adding a new condition
type is: create `modules/<field>/`, then add one row to the `kRouterMatchers`
table.

## Examples

Route by destination domain and port, otherwise fall back to a direct connector:

```json
{
    "name": "router",
    "type": "Router",
    "settings": {
        "geoip-db-path": "/var/lib/GeoLite2-Country.mmdb",
        "sniffing": ["http", "tls"],
        "sniff-even-if-domain-is-already-provided": false,
        "rules": [
            {
                "destination-domain": ["geosite:cn", "*.example.com"],
                "target": "block_or_proxy_cn"
            },
            {
                "network": "udp",
                "destination-port": "443",
                "protocol": "quic",
                "target": "quic_handler"
            },
            {
                "source-ips": ["10.0.0.0/8", "geoip:ir"],
                "target": "lan_path"
            }
        ]
    },
    "next": "default_direct"
}
```

In the second rule above, `network`, `destination-port` and `protocol` are an
`AND`: the connection must be UDP **and** target port 443 **and** be detected as
QUIC for it to be routed to `quic_handler`.

Single-condition rule using a single string value:

```json
{
    "name": "router",
    "type": "Router",
    "settings": {
        "rules": [
            { "username": "alice", "target": "premium_path" }
        ]
    },
    "next": "default_path"
}
```
