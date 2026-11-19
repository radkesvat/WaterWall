# ireader RTMP engine adaptation

The protocol target uses the MIT-licensed `librtmp` and AMF0 sources from
`ireader/media-server` at `c0463893bc509e65bea9f4f76be68c1f89ccdfcf`.
CMake fetches that revision, copies the required source directories and the
upstream `LICENSE` under `patched-deps/media-server`, and applies the patch to
the copy. The download cache remains pristine.

`0001-bounded-waterwall-profile.patch` adds hooks for encoding 3 negotiation,
correlated command results, asynchronous publication acceptance, raw extended
data, typed chunk output, and immediate transmission failure propagation. It
bounds command decoding and chunk reassembly before the private WaterWall profile
receives messages. Strict AMF0 command decoding requires a complete object
terminator. The profile handles protocol controls using the upstream
serializers. The simple handshake uses bytewise per-call padding generation to
avoid shared `rand()` state and unaligned writes across worker sessions. The S2
reply echoes the client's timestamp and random bytes and records the server's
C1 receive timestamp in its second word.

Only the C RTMP/AMF0 protocol sources are built. WaterWall owns worker context,
socket I/O, TLS, and line lifetime. The optional complex handshake is disabled.
