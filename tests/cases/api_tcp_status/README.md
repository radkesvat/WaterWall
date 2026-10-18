# api_tcp_status

The namespace probe queries the real read-only AuthenticationClient status operation through a direct TCP stream. Both workers are active. The shared probe checks API framing, FIFO replies and requested accounting. The HTTP case recognizes complete API frames without waiting for HTTP EOF; stream cases cover split prefixes and coalesced requests. Fixture credentials are public test values. No external network is used.

A second loopback endpoint uses a 1024-byte response-envelope cap. Its valid status query must return a bounded `response_too_large` gateway error before publishing any result prefix.
