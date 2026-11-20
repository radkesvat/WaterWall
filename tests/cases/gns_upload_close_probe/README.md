# GNS upload close probe

The caller writes a 4 MiB upload and closes its socket immediately. The service
must receive every byte in order and then EOF. Three rounds use each of the
direct `GnsClient → GnsServer` chain and the real UDP sandwich.
Both clients set `send-rate` to 8388608 bytes per second, so an upload takes
about half a second and its end is still queued in GNS when the caller
finishes. GameNetworkingSockets sends at a fixed rate; at the default of 262144
one upload would take sixteen seconds.

`waterwall.gns_upload_close_probe` runs through the namespace probe
harness. All endpoints use namespace loopback. The runner owns WaterWall and
retains the private run directory on failure; set
`WATERWALL_TEST_KEEP_RUN_DIR=1` to retain successful artifacts too.

Success requires exact upload bytes and EOF within 15 seconds per round.
Truncation, corruption, missing EOF, timeout, or an early runtime exit fails.

Contract exercised: the borrowed application may die as soon as it sends
Finish; the independently owned client carrier continues accepted GNS output
and the native close within `close-drain-timeout-ms`.
