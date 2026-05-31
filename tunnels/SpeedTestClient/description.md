# SpeedTestClient Node

`SpeedTestClient` is a connection-oriented chain-head speed-test tunnel. It creates normal Waterwall lines, sends framed
speed-test traffic through the next tunnel, validates received data, and prints iperf-style interval and final reports.

It does not open sockets itself and does not generate packet-line traffic. Chain it with existing transports such as
`TcpConnector` or `UdpConnector`.

Common settings:

- `mode`: `tcp` or `udp` (default `tcp`)
- `direction`: `upload`, `download`, or `bidirectional` (default `upload`)
- `duration-ms`: active measurement duration (default `10000`)
- `warmup-ms`: warm-up duration excluded from measured totals (default `0`)
- `report-interval-ms`: interval log cadence (default `1000`)
- `connection-count`: parallel connection count (default `1`)
- `payload-size`: generated payload bytes per frame
- `udp-target-bits-per-sec`, `target-bits-per-sec`, or `target-megabits-per-sec`: optional send pacing
- `json-summary`: print a compact JSON-style final summary
- `terminate-on-complete`: exit Waterwall after all streams finish (default `true`)

