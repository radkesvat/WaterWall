# KCP upload close probe

The caller writes a 4 MiB upload and closes its socket immediately. The service
must receive every byte in order and then EOF. Three rounds use each of the
direct `KcpClient → KcpServer` chain and the real UDP sandwich.
The server advertises a 128-segment KCP receive window so the upload remains
queued when the caller finishes, independently of loopback socket capacities.

`waterwall.kcp_upload_close_probe` runs through the namespace probe
harness. All endpoints use namespace loopback. The runner owns WaterWall and
retains the private run directory on failure; set
`WATERWALL_TEST_KEEP_RUN_DIR=1` to retain successful artifacts too.

Success requires exact upload bytes and EOF within 15 seconds per round.
Truncation, corruption, missing EOF, timeout, or an early runtime exit fails.

Contract exercised: the borrowed application may die as soon as it sends
Finish; the independently owned client carrier continues accepted KCP output
and reliable CLOSE within the negotiated finite drain interval.
