# api_multiconfig_status

The namespace probe queries the real read-only AuthenticationClient status operation through a TCP endpoint with two loaded logical configurations. Both workers are active. The shared probe checks API framing, FIFO replies and requested accounting. The HTTP case recognizes complete API frames without waiting for HTTP EOF; stream cases cover split prefixes and coalesced requests. Fixture credentials are public test values. No external network is used.
