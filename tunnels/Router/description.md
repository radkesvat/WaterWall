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
>   below). `geoip:` and `geosite:` patterns are accepted but not implemented yet
>   and never match.
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
- The top-level `next` is the **default route**, used only when no rule matches.
  It is a normal upstream continuation, not "rule 0".
- Because matching is deferred to the first upstream payload, a flow where the
  **server speaks first** (no initial client bytes) will not be classified and
  will sit until bytes arrive — the same limitation `SniffRouter` has. Put
  `Router` where the client side sends first (the common case).

## How it works

1. Upstream `Init` only initializes the router's own per-line state; it does
   **not** initialize any branch yet.
2. The first upstream payload is buffered and passed to the rule evaluator
   (`routerClassify`).
3. Rules are tested **top to bottom in JSON order**. For each rule, every
   configured condition is evaluated and `AND`-combined. The first fully matching
   rule selects its `target`.
4. The chosen branch (rule `target`, or the default `next`) is initialized, and
   the buffered bytes are replayed to it. From then on payloads flow straight
   through to the chosen branch, and downstream traffic returns through the
   router.

## Settings

| key | type | required | description |
|-----|------|----------|-------------|
| `rules` | array | no | ordered list of routing rule objects (see below) |

The node itself must define a top-level `next`; this is the **default route**
used when no rule matches. A `Router` with no `rules` simply forwards everything
to `next` (a warning is logged at startup).

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
| `source-ips` | functional | string or array of strings | matches the line source IP against single IPs and CIDR ranges, e.g. `203.0.113.4`, `0.0.0.0/8`, `fc00::/7`. A bare IP is a `/32` (or `/128`) host route. `geoip:ir` is accepted but never matches yet |
| `source-port` | functional | number/string or array | matches `src_ctx.port` — the port the peer connected to (the real local/inbound port, resolved per-connection even on multiport backends; i.e. the destination port in the peer's packets) — against single ports and ranges, e.g. `53`, `443`, `1000-2000` |
| `network` | functional | string or array | matches the `dest_ctx` protocol bit flags; `tcp`, `udp`, `icmp`, `packet`, or combined `tcp,udp` (OR within the field) |
| `protocol` | stub (matches all) | string or array | detected/known protocol, e.g. `http`, `tls`, `quic`, `bittorrent` |
| `attributes` | stub (matches all) | array | reserved for future metadata-based matching (parsed but unused) |
| `destination-ip` | functional | string or array | matches the line destination IP (`dest_ctx`) against single IPs and CIDR ranges; `geoip:` accepted but never matches yet. A domain destination has no IP and does not match |
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
  network/              #   <field>Match   -> test the condition (stub: returns true)
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
