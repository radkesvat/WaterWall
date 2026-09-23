<!--
Documentation version: 159
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/DomainResolver.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/DomainResolver.mdx, and all files must keep the same documentation version.
-->

# DomainResolver Node

`DomainResolver` is a middle node that resolves a line's destination domain before forwarding that line's upstream `Init`.

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
nodes. Protocol clients also use an internal resolver with a target-prepare hook.

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

- Downstream `Init` and upstream `Est` use the constructor defaults that reject unsupported callbacks.
  Payload, Pause/Resume, and Finish retain their ordinary bidirectional meanings.

- Upstream payloads are retained only during DNS, adjacent `Init` reentry, or an older ordered backlog.
  Admission checks both logical bytes and retained allocation charge against 2 MiB per line before enqueue. Overflow closes
  only prev before next `Init`, or both initialized directions afterwards.

- Downstream payloads forward directly once next `Init` has started, including replies during Init itself.

- Transport `Est` forwards as soon as the path opens. DNS backlog drains in FIFO order while the consumer permits it;
  nested input cannot overtake older input. Pause received during DNS remains effective when the adjacent path opens.

- On `Finish`, the node destroys local line state and propagates `Finish` only when the opposite side had already
  received the delayed `Init`. It never sends a callback back toward the side that just finished it.

The first retained input pauses only the initiating source, after FIFO ownership
and accounting are published. This local DNS/order hold is separate from received
Pause permission and does not pause DNS or the transport being initialized. It stays
active through drain callbacks and is released only when the FIFO is empty and the
adjacent consumer permits sending. Reentrant Pause/Resume cannot overtake older
input, clear another pressure reason, or resurrect work after Finish.

## Notes And Caveats

- This is a middle node (`.flags = kNodeFlagSupportsSplice`) that operates within a chain; it cannot be placed as a chain head or chain end.
- It is a transparent middle node (`kNodeLayerAnything`, `SameAsPrev`/`SameAsNext`) that preserves line layer across neighbors.
- It does not use or modify packet-line state.
- It requires no left padding and does not touch `sbuf_t` layout.
- It resolves only the destination address context (`dest_ctx`), not the source context.
- A line whose destination is neither an IP address nor a valid domain is rejected.

## Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagSupportsSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayerAnything` |
| `layer_group_prev_node` | `kNodeLayerSameAsNext` |
| `layer_group_next_node` | `kNodeLayerSameAsPrev` |
| `required_padding_left` | `0` bytes |
