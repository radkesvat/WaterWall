# TunDevice Node

`TunDevice` attaches WaterWall to a TUN interface. It reads IP packets from the virtual network device and forwards them into the chain, and it can also write IP packets from the chain back into the TUN device.

This node is a layer-3 adapter rather than a connection-oriented tunnel.

## What It Does

- Creates and configures a TUN interface.
- Assigns an IP address and subnet mask to that device.
- Brings the device up.
- Reads packets from the device and forwards them to the adjacent chain side.
- Writes packets received from the chain back into the device.
- Recalculates checksums before writing when the line requests it.

Because it is a packet adapter, this node does not create per-connection lines. It uses worker packet lines provided by the chain.

## Typical Placement

`TunDevice` can be placed at either edge of a chain:

- if it is last in the chain, packets read from the TUN device are forwarded to the previous node
- otherwise, packets read from the TUN device are forwarded to the next node

Payload coming from either side and reaching `TunDevice` is written into the TUN interface.

## Configuration Example

```json
{
  "name": "tun0-adapter",
  "type": "TunDevice",
  "settings": {
    "device-name": "tun0",
    "device-ip": "10.10.0.1/24",
    "device-mtu": 1500,
    "dns": ["1.1.1.1", "8.8.8.8"],
    "route-table": "off"
  },
  "next": "next-node-name"
}
```

Full-route example with local ranges excluded:

```json
{
  "name": "tun0-adapter",
  "type": "TunDevice",
  "settings": {
    "device-name": "tun0",
    "device-ip": "10.10.0.1/24",
    "device-mtu": 1500,
    "route-table": "main",
    "route-exclude-cidrs": [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ]
  },
  "next": "next-node-name"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"TunDevice"`.

### `settings`

- `device-name` `(string)`
  Name of the TUN interface to create or open.

- `device-ip` `(string)`
  Interface IP and subnet in CIDR form.
  Example: `"10.10.0.1/24"`

  The current implementation splits this into:
  - device IP address
  - subnet mask length

## Optional `settings` Fields

- `device-mtu` `(integer)`
  MTU to configure on the TUN device.

  Default: global MTU size used by WaterWall.

- `route-table` `(string)`
  Controls native system route installation.

  Default: `"off"`

  Supported values:
  - `"off"`: do not install routes
  - `"main"` or `"auto"`: install routes into the normal platform routing table
  - Linux only: a numeric or named routing table accepted by `ip route`

- `system-route` `(boolean)`
  Convenience switch for full-device routing. If this is `true` and `route-table` is not set, it behaves like `"route-table": "main"`.

  Default: `false`

- `route-cidrs` `(array of strings)`
  CIDRs to route toward the TUN interface when routing is enabled.

  Default: full route for the family of `device-ip`, either `"0.0.0.0/0"` or `"::/0"`.
  Default routes are installed as split `/1` routes so the existing system default route does not need to be replaced.

- `route-exclude-cidrs` `(array of strings)`
  CIDRs to leave out of the routes installed by `route-cidrs`.

  This is useful when `route-cidrs` is global and some local, management, or upstream endpoint ranges must keep using the existing system route.

- `dns` `(array of IPv4 strings)`
  DNS servers to associate with the TUN interface.

  The array must contain one or two valid IPv4 addresses. Hostnames, IPv6
  addresses, empty strings, and more than two entries are rejected during node
  creation.

  `null` is treated the same as leaving the field unset.

  On Linux this requires `systemd-resolved` / `resolvectl`; it sets DNS servers
  with `resolvectl dns` and installs the `~.` routing domain so the configured
  servers are used as the default resolver path while the device is active. On
  Windows this configures static IPv4 DNS servers on the Wintun adapter with
  `netsh`; DNS precedence still follows Windows interface metrics. macOS TUN DNS
  configuration is rejected during node creation; use `post-up-script` /
  `pre-down-script` for platform-specific resolver setup there.

- `loop-protection` `(boolean)`
  Keeps WaterWall's own outbound traffic from being routed back into the TUN
  (a routing loop) when the TUN is a system/full route.

  Default: enabled whenever system routing is enabled (i.e. tracks
  `system-route` / `route-table`), disabled otherwise. Set to `false` to opt out.

  On Windows this is implemented with WinDivert at the **flow** layer: the
  process's own network flows (TCP connections and UDP flows alike) are observed
  and any endpoint that would otherwise be steered into the TUN gets a host
  (`/32` or `/128`) bypass route via the *original* default gateway. The flow
  layer is required because `UdpConnector` sends with unconnected `sendto()` and
  never calls `connect()`, so the socket-layer `CONNECT` event would never fire
  for it. This protects connectors (`TcpConnector`, `UdpConnector`, ...)
  automatically, even when they live in a different chain and connect to dynamic
  endpoints, so manual `route-exclude-cidrs` entries for your upstream server are
  no longer required. On other platforms this option is currently a no-op.

- `post-up-script` `(string)`
  Optional shell command to run after the interface is up and native routes are installed.

- `pre-down-script` `(string)`
  Optional shell command to run before native routes are removed and the interface is brought down.

## Detailed Behavior

### Device setup

During `onPrepare`, `TunDevice`:

- decides which adjacent tunnel should receive packets read from the device
- creates the TUN device
- assigns the configured IP/subnet
- brings the device up
- optionally installs native system routes
- optionally runs `post-up-script`

The actual device creation is deferred until prepare time because the tunnel needs chain context to know which side should receive packets.

### Packet input path

When the TUN device produces a packet:

- the packet is received on a worker
- the tunnel validates the packet format
- only IPv4 packets are currently accepted by this path
- the packet is forwarded through the chosen adjacent tunnel using the worker's packet line

If the device is down, the packet is dropped.

### Packet output path

When payload reaches `TunDevice` from upstream or downstream:

- the payload is treated as an IP packet
- checksum recalculation is performed if the line requests it
- the packet is written to the TUN device

Both upstream and downstream payload handlers write to the same TUN device.

### Checksum behavior

Before writing a packet, `TunDevice` checks line flags:

- if `recalculate_checksum` is set, the packet checksum is recomputed
- full packet checksum recalculation is attempted
- for fragmented IPv4 packets, transport checksum recalculation is skipped automatically and only the IP header checksum is recomputed

### Self-traffic loop protection (Windows)

When the TUN installs itself as the system default route, every outbound packet
of the machine is steered into the TUN -- including WaterWall's own upstream
sockets. Without protection those packets are read back from the TUN and re-sent,
forming a routing loop.

With `loop-protection` enabled (the default in system-route mode), `TunDevice`:

- snapshots the original default gateway/interface per family *before* installing
  the TUN routes,
- opens a WinDivert flow-layer handle (`SNIFF | RECV_ONLY`) filtered to this
  process only, observing its own `FLOW_ESTABLISHED`/`FLOW_DELETED` events (the
  flow layer is observe-only and, unlike the socket layer, reports UDP flows too
  -- essential because `UdpConnector` uses unconnected `sendto()`),
- for each new flow endpoint that the current routing table would send into the
  TUN, installs a host bypass route via the original gateway, reference counted
  per destination and tracked per flow `EndpointId` so an unrelated flow sharing
  the same remote IP cannot tear down a live route,
- removes any remaining bypass routes when the device is brought down.

The `FLOW_ESTABLISHED` event is delivered as the flow is established, so the
bypass route is normally installed before traffic flows; there is a small
inherent race where the very first packet of a brand-new endpoint could enter the
TUN before the route lands (the connection self-heals on retransmit, e.g.
WireGuard's handshake retry). This is the correct trade-off because the flow layer
cannot hold/permit events.

This relies on the bundled, pre-signed WinDivert driver (no extra driver or WFP
callout is required). If WinDivert cannot be loaded, or no original default route
exists, protection stays inactive and the device still works -- you can then fall
back to manual `route-exclude-cidrs`.

### Callback behavior

Most connection-style callbacks such as `init`, `est`, `finish`, `pause`, and `resume` are ignored by this adapter. The important behavior is packet read and packet write.

## Notes And Caveats

- The current receive path only forwards IPv4 packets.
- `device-ip` must be a valid CIDR string.
- On Windows, the implementation requires administrative privileges to load and manage the tunnel driver.
- On macOS, the requested name should be an `utunN` name; if no concrete `utun` unit is requested, macOS assigns the actual interface name.
- Native system route setup is disabled by default. If enabled, routes are removed during destroy in reverse install order.
- DNS setup is optional. If configured, invalid IPv4 values are rejected during node creation and failed platform DNS application stops startup.
- On Windows and macOS, `route-table` values other than `"main"` or `"auto"` are rejected.
- Platform support depends on build and operating system support for TUN devices.
