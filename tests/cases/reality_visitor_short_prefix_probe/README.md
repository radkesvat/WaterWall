# Reality visitor short prefixes

The probe sends the existing short/truncated TLS-like prefixes through the
Reality listener and checks their exact replay to the visitor backend and its
response. Its two-second reader deliberately returns partial data after repeated
socket timeouts; this classification policy remains local.

The namespace harness owns the runtime and private configuration/logs. See
[probe.py](probe.py) for the prefix vectors, deadlines and byte checks.

CTest: `waterwall.reality_visitor_short_prefix_probe`.

Contract exercised: Uses a raw TCP client and instrumented visitor sink to verify an impossible TLS prefix is forwarded before client FIN,
  while plausible one- through four-byte prefixes remain Pending while open and are delivered byte-for-byte before the
  visitor destination receives EOF. An invalid prefix followed by FIN is delivered exactly once.
