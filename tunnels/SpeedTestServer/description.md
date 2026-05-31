# SpeedTestServer Node

`SpeedTestServer` is the receiving side for `SpeedTestClient`. It is a connection-oriented chain end, not a packet-line
tunnel. It accepts the client's speed-test HELLO, validates upload data, optionally sends download data, prints interval
reports, and returns final sender/receiver summaries.

Common settings:

- `report-interval-ms`: fallback interval log cadence before the client HELLO overrides it (default `1000`)
- `json-summary`: print a compact JSON-style per-stream summary

