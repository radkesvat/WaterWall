# WireGuardServer

WireGuardServer authenticates encrypted datagrams from `prev`. Required `mode`
selects raw inner packets or individually managed connections toward `next`.
At `Init`, the server selects UDP from the incoming destination offer.
The UDP ingress is an ordinary UdpListener; endpoints are learned only from
cryptographically authenticated handshake/data messages.

```text
UdpListener -> WireGuardServer(mode=packet) -> TunDevice
UdpListener -> WireGuardServer(mode=connection) -> TcpUdpConnector
```

Both paths carry traffic in both directions. The packet consumer may be any
compatible L3 node; the connection consumer may be a compatible router/transform
leading to an outbound adapter. The node never changes host routes or NAT.
Configured private, public and preshared keys use canonical Base64 encoding of
32 bytes: 44 characters with one trailing `=`.

Packet mode uses static peers, at most 32 active peers. Peer objects require
`publickey` and `allowedips` and accept optional `presharedkey` and
`persistentkeepalive` as on WireGuardClient. Omit peer endpoints: authenticated
traffic supplies the return carrier. All peer ranges must be non-overlapping.
Decrypted source addresses must belong to the authenticated peer's allowed
range. Return destinations select the matching peer.

```json
{
  "nodes": [
    {"name":"udp","type":"UdpListener","settings":{"address":"0.0.0.0","port":51820},"next":"vpn"},
    {"name":"vpn","type":"WireGuardServer","settings":{
      "mode":"packet","privatekey":"EBJOHctLU2w8uteyTE+WU0hruB09Ub0vwVS+Gt9wAls=",
      "peers":[{"publickey":"dDUfRvZSDy8jZBsB4kQflTO+iwlLbR+jgb840fumqUM=","allowedips":"10.50.0.4/30"}]
    },"next":"tun"},
    {"name":"tun","type":"TunDevice","settings":{"device-name":"wg-inner","device-ip":"10.50.0.1/24"}}
  ]
}
```

Configure the TunDevice platform settings as described in its node reference.
Install forwarding, OS routes and any required NAT for the inner subnet using
your deployment's normal network administration. Such host changes are separate
from the WireGuard node.

Connection mode requires `auth-client-node-name`, referencing a separately
configured AuthenticationClient service. Static `peers` and PSK settings are
rejected in this mode. Account WireGuard public keys follow AuthenticationClient's existing credential
convention: the private key is the 32-byte SHA-256 digest of the account password,
and the public key is its X25519 public key. Encode the digest in Base64 for the
client's `privatekey`. `wireguard-allowed-ips` contains the account's unique CIDR; account ids are durable and
nonzero. Authenticated mode supports IPv4 accounts. The account collection
rejects overlapping ranges before publication.

```json
{
  "name":"vpn","type":"WireGuardServer","settings":{
    "mode":"connection",
    "privatekey":"EBJOHctLU2w8uteyTE+WU0hruB09Ub0vwVS+Gt9wAls=",
    "auth-client-node-name":"accounts"
  },"next":"outbound"
}
```

Configure `accounts` as an AuthenticationClient with its ordinary named-service
credentials and transport to AuthenticationServer. `outbound` is a
TcpUdpConnector with destination context settings. The private payload pipeline
is built automatically before indexing:

```text
WireGuardServer -> PacketsToConnection -> user binding -> UserController -> outbound
```

The real server-to-PTC edge is L3. AuthenticationClient is a service reference,
not part of this payload path. Inner TCP connections and UDP associations receive
the resolved stable account handle and owned profile before outbound Init.
Unknown, stale, disabled or expired identities cannot pass anonymously.
PTC supports unfragmented IPv4 TCP/UDP here; IPv6, ICMP and fragment reassembly
are not connection-mode features.

UserController applies connection limits, shared account bandwidth, traffic
quotas, expiry/disable and first-use accounting to inner payload. TCP uses stream
shaping and UDP preserves datagrams. WireGuard handshakes, carrier lines,
keepalives and encrypted overhead consume no inner connection or traffic quota.

An IP limit counts distinct **inner client source IPs with active admitted
connections/associations**, per account across workers. Allowed ranges specify
which sources may be used; unused allowed addresses consume no slots. Many flows
from one source share one IP slot. A second source is denied at IP limit 1 until
the first source's last flow closes/expires. Server/destination IPs and outer
endpoints do not count. Authenticated external roaming preserves the saved inner
IP reservations.

Existing authenticated bindings retain cached account enforcement and may rekey
during explicit control authentication rejection. New peers and every new inner
TCP/UDP Init still require fresh admission, including work delayed across that
rejection. Denying a new flow preserves older eligible flows and their account
reservations. Disablement, expiry, quota and key/range revocation still apply.

Admission is on demand after candidate-key recovery and full protocol proof.
There are at most 32 active/provisional/retiring bindings. Capacity refusal drops
the new handshake without displacing established sessions or truncating the
account table. Candidate failures release their slot immediately.

One owner-worker timer checks installed account generations every 400 ms and
revalidates all active bindings (at most 32 per tick). The next tick observes a
change within 400 ms plus ordinary owner-loop queueing time. Handshakes and new flows
also revalidate. Unchanged refreshes preserve identity continuity, including queued datagrams.
A queued handshake cannot publish credentials whose continuity began after its
intake generation. Usable RAM
cache admission follows AuthenticationClient's outage policy. Key/range changes,
removal/recreation and durable-owner reassignment close affected admission.
Per-worker retirement closes TCP/UDP lines, pre-line protocol state and TCP
closers before range reuse. Deferred input, reverse output and carrier sends
carry non-reusable epochs. A changed range remains reserved until every owner
acknowledges retirement and a fresh handshake validates current authorization.
A failed retirement acknowledgment leaves the affected range closed until node
shutdown; unrelated bindings continue.

Protocol state and timers run on worker 0. UDP ingress lines are borrowed from
UdpListener on their original workers, retaining their exact source and local
endpoint; replies use the same live carrier. Finish detaches it without
reflecting callbacks to its sender. Node shutdown closes admission and timers,
settles queued work, drains borrowed handles via their adapter owners, then
releases keys/helpers. Each node bounds cross-worker packet work to 512 messages
and 8 MiB; excess input/output drops. Packet mode does not apply connection-mode
account management to persistent packet lines.

The server admits at most 1024 live borrowed UDP ingress handles. Excess carrier
Init is refused through its adapter owner. In connection mode,
`udp-idle-timeout-ms` configures association expiry (1–4294967295 ms; default
300000), and the PTC `mtu`/pending-byte settings retain their normal contracts.
Building WireGuardServer requires AuthenticationClient, UserController and
PacketsToConnection. WireGuardClient links WireGuardCommon and supports compatible
datagram-preserving carrier chains, including `UdpOverTcpClient -> TcpConnector`.


Complete runnable core/config pairs are available in the
[WireGuard examples](https://github.com/radkesvat/WaterWall/tree/main/tunnels/WireGuardClient/examples).
