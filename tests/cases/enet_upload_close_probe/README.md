# ENet upload close probe

The caller writes a 4 MiB upload and closes its socket immediately. The service
must receive every byte in order and then EOF. Three rounds use each of the
direct `EnetClient → EnetServer` chain and the real UDP sandwich.
Both servers set `incoming-bandwidth` to 65536, which gives the client ENet's
smallest reliable window (4,096 bytes), so on the UDP path the upload remains
queued when the caller finishes, independently of loopback socket capacities.

`waterwall.enet_upload_close_probe` runs through the namespace probe
harness. All endpoints use namespace loopback. The runner owns WaterWall and
retains the private run directory on failure; set
`WATERWALL_TEST_KEEP_RUN_DIR=1` to retain successful artifacts too.

Success requires exact upload bytes and EOF within 15 seconds per round.
Truncation, corruption, missing EOF, timeout, or an early runtime exit fails.

Contract exercised: the borrowed application may die as soon as it sends
Finish; the independently owned client carrier continues accepted ENet output
and the native disconnect within `close-drain-timeout-ms`.
