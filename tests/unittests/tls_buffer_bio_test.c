#include "TlsBufferBio/buffer_bio.h"
#include "tunnel_line_failure_harness.h"

static sbuf_t *input(buffer_pool_t *pool, const void *bytes, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(pool, length, bufferpoolGetLargeBufferPadding(pool));
    sbufWrite(buf, bytes, length);
    sbufSetLength(buf, length);
    return buf;
}

static void caseOwnedBuffers(SSL_CTX *ctx, buffer_pool_t *pool)
{
    twfSetCase("BIO ownership, partial reads, ordering and independent output");
    BIO *bio = tlsbufferbioNew(ctx, pool);
    twfRequire(bio != NULL, "create BIO");
    char bytes[16];
    twfRequire(BIO_read(bio, bytes, sizeof(bytes)) == -1 && BIO_should_read(bio), "empty read retries");

    sbuf_t        *first  = input(pool, "abc", 3);
    sbuf_t        *second = input(pool, "defgh", 5);
    const uint32_t cursor = first->curpos;
    twfRequire(tlsbufferbioFeed(bio, first) && tlsbufferbioFeed(bio, second), "admit fragmented input");
    twfRequire(BIO_ctrl_pending(bio) == 8 && ! BIO_should_retry(bio), "input clears retry and counts bytes");
    twfRequire(tlsbufferbioPeek(bio, bytes, 6) == 6 && memoryCompare(bytes, "abcdef", 6) == 0 &&
                   BIO_ctrl_pending(bio) == 8,
               "routing prefix inspection spans buffers without consuming them");
    twfRequire(BIO_read(bio, bytes, 1) == 1 && bytes[0] == 'a', "partial read");

    sbuf_t *taken = tlsbufferbioTake(bio);
    twfRequire(taken == first && taken->curpos == cursor + 1 && sbufGetLength(taken) == 2 &&
                   memoryCompare(sbufGetRawPtr(taken), "bc", 2) == 0,
               "input is retained without a staging copy or compaction");
    bufferpoolReuseBuffer(pool, taken);
    taken = tlsbufferbioTake(bio);
    twfRequire(taken == second && BIO_ctrl_pending(bio) == 0, "FIFO preserves second input allocation");
    bufferpoolReuseBuffer(pool, taken);

    twfRequire(BIO_write(bio, "abcdef", 6) == 6 && BIO_read(bio, bytes, 2) == 2, "write followed by partial read");
    twfRequire(BIO_write(bio, "ghi", 3) == 3 && BIO_ctrl_pending(bio) == 7,
               "append after partial read counts only unread bytes");
    taken = tlsbufferbioTake(bio);
    twfRequire(taken != NULL && sbufGetLength(taken) == 7 && memoryCompare(sbufGetRawPtr(taken), "cdefghi", 7) == 0,
               "owned output contains ordered unread data");
    twfRequire(sbufGetLeftPadding(taken) >= 64 && sbufGetLeftCapacity(taken) >= 64, "output preserves padding");
    twfRequire(BIO_write(bio, "replacement", 11) == 11, "next output write");
    BIO_free(bio);
    twfRequire(memoryCompare(sbufGetRawPtr(taken), "cdefghi", 7) == 0,
               "transferred output survives subsequent writes and BIO destruction");
    bufferpoolReuseBuffer(pool, taken);
    twfRequireNoLeakedBuffers();
}

static void caseBoundsAndReset(SSL_CTX *ctx, buffer_pool_t *pool)
{
    twfSetCase("BIO byte/entry bounds, refusal ownership, reset and EOF");
    BIO *bio = tlsbufferbioNew(ctx, pool);
    twfRequire(bio != NULL, "create BIO");
    uint8_t block[65536];
    memorySet(block, 0x37, sizeof(block));
    for (size_t i = 0; i < kTlsBufferBioMaxBytes / sizeof(block); ++i)
        twfRequire(tlsbufferbioFeed(bio, input(pool, block, sizeof(block))), "byte limit accepts equality");
    twfRequire(BIO_ctrl_pending(bio) == kTlsBufferBioMaxBytes, "byte limit reached exactly");
    twfRequire(! tlsbufferbioFeed(bio, input(pool, block, 1)), "byte overflow refuses and consumes input");
    twfRequire(BIO_write(bio, block, 1) == -1 && ! BIO_should_retry(bio), "write overflow is terminal");
    twfRequire(BIO_reset(bio) == 1 && BIO_ctrl_pending(bio) == 0, "reset releases full input");
    twfRequireNoLeakedBuffers();

    for (size_t i = 0; i < kTlsBufferBioMaxBuffers; ++i)
        twfRequire(tlsbufferbioFeed(bio, input(pool, block, 1)), "entry limit accepts equality");
    twfRequire(tlsbufferbioFeed(bio, input(pool, block, 0)), "empty input consumes no entry");
    twfRequire(! tlsbufferbioFeed(bio, input(pool, block, 1)), "entry overflow refuses and consumes input");
    twfRequire(BIO_read(bio, block, kTlsBufferBioMaxBuffers) == kTlsBufferBioMaxBuffers,
               "one read spans all tiny input fragments");
    for (size_t i = 0; i < kTlsBufferBioMaxBuffers; ++i)
        twfRequire(block[i] == 0x37, "fragment contents preserved");
    twfRequireNoLeakedBuffers();
    twfRequire(BIO_set_mem_eof_return(bio, 0) == 1 && BIO_read(bio, block, 1) == 0 && ! BIO_should_retry(bio),
               "explicit EOF differs from retry");
    twfRequire(BIO_set_mem_eof_return(bio, -1) == 1 && BIO_read(bio, block, 1) == -1 && BIO_should_read(bio),
               "restore nonblocking retry");
    BIO_free(bio);
}

static void transfer(BIO *source, BIO *destination, buffer_pool_t *pool, bool fragment)
{
    sbuf_t *buf;
    while ((buf = tlsbufferbioTake(source)) != NULL)
    {
        if (! fragment)
        {
            twfRequire(tlsbufferbioFeed(destination, buf), "transfer owned TLS flight");
            continue;
        }
        const uint32_t sizes[] = {1, 2, 5, 17, 4096};
        size_t         step    = 0;
        while (sbufGetLength(buf) > 0)
        {
            uint32_t n = min(sizes[step++ % ARRAY_SIZE(sizes)], sbufGetLength(buf));
            twfRequire(tlsbufferbioFeed(destination, input(pool, sbufGetRawPtr(buf), n)), "fragment TLS flight");
            sbufShiftRight(buf, n);
        }
        bufferpoolReuseBuffer(pool, buf);
    }
}

static void handshakeStep(SSL *ssl)
{
    int result = SSL_do_handshake(ssl);
    if (result != 1)
    {
        int error = SSL_get_error(ssl, result);
        twfRequire(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE, "handshake retry");
    }
}

static void caseTlsRoundtrip(buffer_pool_t *pool, int version)
{
    twfSetCase("real TLS over fragmented and coalesced owned buffers");
    SSL_CTX *client_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX *server_ctx = SSL_CTX_new(TLS_server_method());
    twfRequire(client_ctx != NULL && server_ctx != NULL, "TLS contexts");
    twfRequire(SSL_CTX_set_min_proto_version(client_ctx, version) == 1 &&
                   SSL_CTX_set_max_proto_version(client_ctx, version) == 1 &&
                   SSL_CTX_set_min_proto_version(server_ctx, version) == 1 &&
                   SSL_CTX_set_max_proto_version(server_ctx, version) == 1 &&
                   SSL_CTX_use_certificate_chain_file(server_ctx, TLS_BIO_TEST_CERT_FILE) == 1 &&
                   SSL_CTX_use_PrivateKey_file(server_ctx, TLS_BIO_TEST_KEY_FILE, SSL_FILETYPE_PEM) == 1,
               "TLS configuration");
    SSL *client = SSL_new(client_ctx);
    SSL *server = SSL_new(server_ctx);
    twfRequire(client != NULL && server != NULL, "TLS connections");
    SSL_set_bio(client, tlsbufferbioNew(client_ctx, pool), tlsbufferbioNew(client_ctx, pool));
    SSL_set_bio(server, tlsbufferbioNew(server_ctx, pool), tlsbufferbioNew(server_ctx, pool));
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);
    for (unsigned step = 0; step < 20 && (! SSL_is_init_finished(client) || ! SSL_is_init_finished(server)); ++step)
    {
        handshakeStep(client);
        transfer(SSL_get_wbio(client), SSL_get_rbio(server), pool, true);
        handshakeStep(server);
        transfer(SSL_get_wbio(server), SSL_get_rbio(client), pool, true);
    }
    twfRequire(SSL_is_init_finished(client) && SSL_is_init_finished(server), "fragmented handshake completes");

    uint8_t plaintext[65536];
    uint8_t recovered[sizeof(plaintext)];
    for (size_t i = 0; i < sizeof(plaintext); ++i)
        plaintext[i] = (uint8_t) (i * 17U);
    for (unsigned direction = 0; direction < 2; ++direction)
    {
        SSL *sender   = direction == 0 ? client : server;
        SSL *receiver = direction == 0 ? server : client;
        twfRequire(SSL_write(sender, plaintext, sizeof(plaintext)) == sizeof(plaintext), "multi-record TLS write");
        transfer(SSL_get_wbio(sender), SSL_get_rbio(receiver), pool, direction == 1);
        size_t offset = 0;
        while (offset < sizeof(recovered))
        {
            int n = SSL_read(receiver, recovered + offset, (int) min(sizeof(recovered) - offset, (size_t) 317));
            twfRequire(n > 0, "partial plaintext read");
            offset += (size_t) n;
        }
        twfRequire(memoryCompare(plaintext, recovered, sizeof(plaintext)) == 0, "TLS roundtrip preserves bytes");
    }
    /* Leave unread ciphertext behind to exercise SSL-owned BIO cleanup. */
    twfRequire(SSL_write(client, plaintext, 29) == 29, "final retained record");
    transfer(SSL_get_wbio(client), SSL_get_rbio(server), pool, true);
    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
    twfRequireNoLeakedBuffers();
}

int main(void)
{
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, 65536, 64);
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    twfRequire(ctx != NULL, "create method-owning context");
    caseOwnedBuffers(ctx, env.pool);
    caseBoundsAndReset(ctx, env.pool);
    SSL_CTX_free(ctx);
    caseTlsRoundtrip(env.pool, TLS1_2_VERSION);
    caseTlsRoundtrip(env.pool, TLS1_3_VERSION);
    twfWorkerEnvTeardown(&env);
    return 0;
}
