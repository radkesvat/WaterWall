# TLS lifecycle coverage

TLS and Reality lifecycle fixtures distinguish early transport Est from the
one-shot handshake-completion hook. They verify bounded plaintext FIFO release,
authentication, key/sequence handling and callback-driven close. See
[tlsclient_close_lifecycle_test.c](tlsclient_close_lifecycle_test.c) and the
[Reality client](../reality/reality_close_lifecycle_client.c) and
[server](../reality/reality_close_lifecycle_server.c) fixture modules.
