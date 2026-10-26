# Trojan and VLESS sing-box interoperability

Eight short cases run the real WaterWall and checksum-pinned sing-box 1.12.0
executables in private loopback network namespaces. Each protocol has TCP and
UDP cases with WaterWall as client and as server. The role in the test name
always identifies WaterWall's endpoint.

```sh
cmake --preset linux
cmake --build --preset linux -j8
cmake --build --preset linux --target waterwall_vmess_SING_BOX_reference
ctest --preset linux --output-on-failure -j8 -R '^waterwall\.(trojan|vless)_sing_box_'
```

The provisioning target shares the existing VMess peer archive and executable,
and is available when the required Trojan/VLESS nodes are enabled even if both
VMess nodes are disabled. `WATERWALL_VMESS_SING_BOX_REFERENCE` can select an already
provisioned executable. The fixture checks its exact version; no test downloads
peers or contacts public destinations. CMake registers each case only when its
required nodes exist and gives each a 25-second timeout.

`tests/singbox_proxy_interop.py` generates the configurations and owns the
application and destination sockets. A WaterWall client connects to a sing-box
server; a sing-box client uses a direct inbound with a fixed loopback destination
to reach a WaterWall server. TCP carries several exchanges on one connection;
UDP carries one application datagram per request or reply.

Trojan runs over TLS with the existing local fixture certificate. The sing-box
client verifies the certificate and `tls.integration.test` hostname. The
WaterWall TlsClient uses explicit `verify: false` because it has no custom local
CA setting; that role tests TLS composition rather than certificate trust.
VLESS uses base framing, empty flow and `packet_encoding: ""`. Multiplexing is
disabled. Explicit packet encoding prevents sing-box's default XUDP selection.

TCP request/reply size pairs are 1/65536, 8192/8193, 8193/8192 and 65536/1 bytes.
UDP pairs are 1/15000, 0/8193, 8191/8192, 8192/8191, 8193/0 and 15000/1 bytes.
When WaterWall is the server, the second request has 31 bytes instead of zero:
the pinned sing-box direct ingress does not forward empty application requests.
Empty replies are required in both roles, and empty requests are required when
WaterWall is the client. The fixture prints this peer-specific exclusion.

All exchanges require exact contents and complete UDP boundaries, with distinct
request and reply patterns. A bounded, separate readiness token accommodates
UDP startup admission; measured packets are sent once and never retried.
Both processes must remain alive through the workload and exit with their
expected status after explicit shutdown. Failures retain configurations and logs.

The 15000-byte UDP workload is a supported peer size, not a protocol maximum.
The pinned peer uses [16 KiB packet buffers](https://github.com/SagerNet/sing/blob/v0.7.0-beta.2/common/buf/buffer_standard.go)
and reserves protocol headroom inside that storage. Its usable size varies by
direction and protocol, so these cases do not establish near-65 KB
interoperability. WaterWall-pair and native tests retain the larger size checks.
