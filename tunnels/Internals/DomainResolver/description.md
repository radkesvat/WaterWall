<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/domain-resolver.mdx, and both files must keep the same documentation version.
-->

# DomainResolver Node

`DomainResolver` is a middle node that resolves a line's destination domain before forwarding that line's `Init`.

It does not open sockets, transform payload bytes, prepend protocol data, or create new lines. It only reads and updates
`line->routing_context.dest_ctx`. When the destination is already an IP address, it forwards `Init` immediately. When the
destination is a domain, it resolves it on the current worker's c-ares resolver, applies the configured address-selection
strategy, and only then forwards `Init`.

DNS is submitted through Waterwall's line-bound DNS helper, so the temporary line reference and dead-line/shutdown guard
are handled by the shared network layer rather than by this node.

## Typical Placement

Place `DomainResolver` after a node that sets `dest_ctx` and before a node that requires a concrete IP address.

```text
TcpListener <--> Socks5Server <--> DomainResolver <--> TcpConnector
```

It can also be created internally by another tunnel in the same way `UserController` is created internally by server
nodes. This implementation is intentionally standalone; no existing tunnel is rewired to use it yet.

## Configuration Example

```json
{
  "name": "resolve-domain",
  "type": "DomainResolver",
  "next": "outbound",
  "settings": {
    "strategy": "core-settings",
    "verbose": false
  }
}
```

## Settings

- `strategy` `(optional string or integer, default: "core-settings")`
  Controls how a DNS result list is filtered and selected.

  Supported strings:

  - `"core-settings"`
    Use the core `dns.domain-strategy` value from `core.json`.
  - `"accept-dns-returned-order"`
    Use the first IPv4 or IPv6 address returned by DNS.
  - `"prefer-ipv4"`
    Prefer IPv4, fallback to IPv6.
  - `"prefer-ipv6"`
    Prefer IPv6, fallback to IPv4.
  - `"only-ipv4"`
    Accept only IPv4 results.
  - `"only-ipv6"`
    Accept only IPv6 results.

- `verbose` `(optional boolean, default: false)`
  Emit debug DNS logs when a resolve is started. Resolved-address logs use the normal DNS debug log level.

## Lifecycle Behavior

- On upstream `Init`, the node initializes its line state and resolves `dest_ctx.domain` when needed. Success forwards
  `tunnelNextUpStreamInit()`. Failure destroys this node's line state and finishes only the prev/downstream side,
  because the upstream side was never opened.

- On downstream `Init`, it performs the same destination-domain resolution and then forwards
  `tunnelPrevDownStreamInit()`. Failure finishes only the next/upstream side.

- Payloads received from the initiating side while DNS is still pending are queued and replayed after the delayed `Init`.
  The queue is bounded to 1 MiB per line. The byte limit is checked after enqueue, so it may exceed the limit by one
  buffer before overflow closes the side that initiated the unresolved line.

- On `Finish`, the node destroys local line state and propagates `Finish` only when the opposite side had already
  received the delayed `Init`. It never sends a callback back toward the side that just finished it.

## Notes And Caveats

- This is a stream-style middle node, not a packet tunnel.
- It does not use or modify packet-line state.
- It requires no left padding and does not touch `sbuf_t` layout.
- It resolves only the destination address context (`dest_ctx`), not the source context.
- A line whose destination is neither an IP address nor a valid domain is rejected.
