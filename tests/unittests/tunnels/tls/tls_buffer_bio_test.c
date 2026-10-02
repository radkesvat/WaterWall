/*
 * Covers: Verify owned ciphertext buffers, partial reads, FIFO order, padding, byte/entry limits,
 * reset/EOF and real TLS 1.2/1.3 round trips over fragmented input. The BoringSSL case also verifies
 * direct encryption into reserved pooled output, independent lifetime after `SSL_free()`, partial commit
 * and cancellation, padding callback counts, reservation fallback, partial-write retries, KeyUpdate
 * ordering, injected encryption-failure cleanup and ordinary close-notify. Run these when updating
 * BoringSSL or its local output-buffer patch; the upgrade checklist is in [`tunnels/TlsClient/my
 * notes.txt`](../../../../tunnels/TlsClient/my%20notes.txt).
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseOutputReservation, caseOwnedBuffers, caseBoundsAndReset, caseTlsRoundtrip
 * Checks: Assertion labels include: new record body is aligned; reservation does not publish bytes; commit
 * transfers the encryption destination with onward padding; new cancelable reservation
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tlsclient_buffer_bio_unit; waterwall.tlsserver_buffer_bio_unit
 */
#include "TlsBufferBio/buffer_bio.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"

#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/aead.h>
#include <openssl/err.h>

static bool fail_seal;

int __real_WW_BSSL_EVP_AEAD_CTX_seal_scatter(const EVP_AEAD_CTX *ctx, uint8_t *out, uint8_t *out_tag,
                                             size_t *out_tag_len, size_t max_out_tag_len, const uint8_t *nonce,
                                             size_t nonce_len, const uint8_t *in, size_t in_len,
                                             const uint8_t *extra_in, size_t extra_in_len, const uint8_t *ad,
                                             size_t ad_len);

int __wrap_WW_BSSL_EVP_AEAD_CTX_seal_scatter(const EVP_AEAD_CTX *ctx, uint8_t *out, uint8_t *out_tag,
                                             size_t *out_tag_len, size_t max_out_tag_len, const uint8_t *nonce,
                                             size_t nonce_len, const uint8_t *in, size_t in_len,
                                             const uint8_t *extra_in, size_t extra_in_len, const uint8_t *ad,
                                             size_t ad_len);

int __wrap_WW_BSSL_EVP_AEAD_CTX_seal_scatter(const EVP_AEAD_CTX *ctx, uint8_t *out, uint8_t *out_tag,
                                             size_t *out_tag_len, size_t max_out_tag_len, const uint8_t *nonce,
                                             size_t nonce_len, const uint8_t *in, size_t in_len,
                                             const uint8_t *extra_in, size_t extra_in_len, const uint8_t *ad,
                                             size_t ad_len)
{
    if (fail_seal)
    {
        fail_seal = false;
        OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    return __real_WW_BSSL_EVP_AEAD_CTX_seal_scatter(ctx,
                                                    out,
                                                    out_tag,
                                                    out_tag_len,
                                                    max_out_tag_len,
                                                    nonce,
                                                    nonce_len,
                                                    in,
                                                    in_len,
                                                    extra_in,
                                                    extra_in_len,
                                                    ad,
                                                    ad_len);
}

typedef struct write_probe_s
{
    size_t   attempts;
    size_t   commits;
    size_t   cancels;
    size_t   padding_calls;
    uint8_t *last_output;
    bool     decline;
} write_probe_t;

static uint8_t *reserveOutput(SSL *ssl, size_t capacity, size_t alignment, size_t prefix_len, void *arg)
{
    write_probe_t *probe = arg;
    ++probe->attempts;
    if (probe->decline)
        return NULL;
    probe->last_output = tlsbufferbioReserveWrite(SSL_get_wbio(ssl), capacity, alignment, prefix_len);
    return probe->last_output;
}

static void finishOutput(SSL *ssl, size_t written, void *arg)
{
    write_probe_t *probe = arg;
    if (written == 0)
        ++probe->cancels;
    else
        ++probe->commits;
    tlsbufferbioFinishWrite(SSL_get_wbio(ssl), written);
}

static size_t padRecord(SSL *ssl, uint8_t type, size_t length, size_t maximum, void *arg)
{
    discard        ssl;
    discard        length;
    write_probe_t *probe = arg;
    ++probe->padding_calls;
    return type == SSL3_RT_APPLICATION_DATA ? min(maximum, (size_t) 17) : 0;
}

static void caseOutputReservation(SSL_CTX *ctx, buffer_pool_t *pool)
{
    twfSetCase("reserved output identity, alignment, partial commit and cancellation");
    BIO     *bio = tlsbufferbioNew(ctx, pool);
    uint8_t *out = tlsbufferbioReserveWrite(bio, 1024, 32, 5);
    twfRequire(out != NULL && ((uintptr_t) (out + 5) & 31) == 0, "new record body is aligned");
    twfRequire(BIO_ctrl_pending(bio) == 0, "reservation does not publish bytes");
    memorySet(out, 0x73, 512);
    tlsbufferbioFinishWrite(bio, 512);
    sbuf_t *owned = tlsbufferbioTake(bio);
    twfRequire(sbufGetRawPtr(owned) == out && sbufGetLength(owned) == 512 && sbufGetLeftCapacity(owned) >= 64,
               "commit transfers the encryption destination with onward padding");

    out = tlsbufferbioReserveWrite(bio, 123, 8, 5);
    twfRequire(out != NULL, "new cancelable reservation");
    tlsbufferbioFinishWrite(bio, 0);
    twfRequire(tlsbufferbioTake(bio) == NULL && BIO_ctrl_pending(bio) == 0, "cancel removes the reserved entry");

    twfRequire(BIO_write(bio, "abc", 3) == 3, "ordinary prefix before reservation");
    out = tlsbufferbioReserveWrite(bio, 32, 8, 5);
    twfRequire(out != NULL && BIO_ctrl_pending(bio) == 3, "tail reservation leaves prefix visible");
    memoryCopy(out, "discarded", 9);
    tlsbufferbioFinishWrite(bio, 0);
    uint8_t *again = tlsbufferbioReserveWrite(bio, 32, 8, 5);
    twfRequire(again == out, "cancellation preserves existing tail capacity");
    memoryCopy(again, "def", 3);
    tlsbufferbioFinishWrite(bio, 3);
    sbuf_t *tail = tlsbufferbioTake(bio);
    twfRequire(sbufGetLength(tail) == 6 && memoryCompare(sbufGetRawPtr(tail), "abcdef", 6) == 0,
               "ordinary and reserved writes coalesce in order");
    bufferpoolReuseBuffer(pool, tail);
    BIO_free(bio);
    for (size_t i = 0; i < 512; ++i)
        twfRequire(((uint8_t *) sbufGetRawPtr(owned))[i] == 0x73, "owned output survives BIO destruction");
    bufferpoolReuseBuffer(pool, owned);
    twfRequireNoLeakedBuffers();
}
#endif

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
#ifdef OPENSSL_IS_BORINGSSL
    twfRequire(tlsbufferbioReserveWrite(bio, 1, 8, 5) == NULL && BIO_ctrl_pending(bio) == kTlsBufferBioMaxBytes,
               "reservation respects the byte bound without changing the queue");
#endif
    twfRequire(BIO_reset(bio) == 1 && BIO_ctrl_pending(bio) == 0, "reset releases full input");
    twfRequireNoLeakedBuffers();

    for (size_t i = 0; i < kTlsBufferBioMaxBuffers; ++i)
        twfRequire(tlsbufferbioFeed(bio, input(pool, block, 1)), "entry limit accepts equality");
    twfRequire(tlsbufferbioFeed(bio, input(pool, block, 0)), "empty input consumes no entry");
    twfRequire(! tlsbufferbioFeed(bio, input(pool, block, 1)), "entry overflow refuses and consumes input");
#ifdef OPENSSL_IS_BORINGSSL
    twfRequire(tlsbufferbioReserveWrite(bio, bufferpoolGetLargeBufferSize(pool) + 64U, 8, 5) == NULL &&
                   BIO_ctrl_pending(bio) == kTlsBufferBioMaxBuffers,
               "reservation needing another entry respects the entry bound");
#endif
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
#ifdef OPENSSL_IS_BORINGSSL
    write_probe_t probe = {0};
    SSL_set_record_write_buffer_callbacks(client, reserveOutput, finishOutput, &probe);
    tlsbufferbioEnableDirectWrite(server);
#endif
    for (unsigned step = 0; step < 20 && (! SSL_is_init_finished(client) || ! SSL_is_init_finished(server)); ++step)
    {
        handshakeStep(client);
        transfer(SSL_get_wbio(client), SSL_get_rbio(server), pool, true);
        handshakeStep(server);
        transfer(SSL_get_wbio(server), SSL_get_rbio(client), pool, true);
    }
    twfRequire(SSL_is_init_finished(client) && SSL_is_init_finished(server), "fragmented handshake completes");
#ifdef OPENSSL_IS_BORINGSSL
    twfRequire(probe.attempts == 0, "handshake output uses the ordinary path");
    twfRequire(SSL_set_tls13_record_padding_callback(client, padRecord, &probe, 64) == 1, "install record padding");
#endif

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
#ifdef OPENSSL_IS_BORINGSSL
    twfRequire(probe.commits == 4 && probe.cancels == 0, "each client application record reserves and commits");
    twfRequire(probe.padding_calls == (version == TLS1_3_VERSION ? 4U : 0U), "padding callback runs once per record");

    const size_t committed = probe.commits;
    probe.decline          = true;
    twfRequire(SSL_write(client, plaintext, 33) == 33 && probe.commits == committed,
               "declined reservation copies normally");
    twfRequire(probe.padding_calls == (version == TLS1_3_VERSION ? 5U : 0U), "fallback seals only once");
    transfer(SSL_get_wbio(client), SSL_get_rbio(server), pool, false);
    twfRequire(SSL_read(server, recovered, sizeof(recovered)) == 33 && memoryCompare(plaintext, recovered, 33) == 0,
               "declined reservation preserves application bytes");
    probe.decline = false;

    /* A tiny BIO pair forces partial transport writes. Declining the hook must
     * keep BoringSSL's pending-ciphertext retry, without resealing or reserving
     * again when SSL_write is retried with the original plaintext. */
    BIO *saved_wbio = SSL_get_wbio(client);
    BIO *pair_write = NULL;
    BIO *pair_read  = NULL;
    twfRequire(BIO_up_ref(saved_wbio) == 1 && BIO_new_bio_pair(&pair_write, 32, &pair_read, 32) == 1,
               "create bounded transport for write retries");
    SSL_set0_wbio(client, pair_write);
    probe.decline          = true;
    const size_t attempts  = probe.attempts;
    const size_t pad_calls = probe.padding_calls;
    int          written   = -1;
    for (unsigned step = 0; step < 32 && written < 0; ++step)
    {
        written = SSL_write(client, plaintext, 257);
        if (written < 0)
            twfRequire(SSL_get_error(client, written) == SSL_ERROR_WANT_WRITE, "bounded transport requests retry");
        uint8_t wire[32];
        int     n;
        while ((n = BIO_read(pair_read, wire, sizeof(wire))) > 0)
            twfRequire(tlsbufferbioFeed(SSL_get_rbio(server), input(pool, wire, (uint32_t) n)),
                       "transfer partial write");
    }
    twfRequire(written == 257 && probe.attempts == attempts + 1 &&
                   probe.padding_calls == pad_calls + (version == TLS1_3_VERSION ? 1U : 0U),
               "write retries reuse the sealed record and do not rerun reservation or padding");
    twfRequire(SSL_read(server, recovered, sizeof(recovered)) == 257 && memoryCompare(plaintext, recovered, 257) == 0,
               "partial transport writes decrypt exactly once");
    SSL_set0_wbio(client, saved_wbio);
    BIO_free(pair_read);
    probe.decline = false;

    if (version == TLS1_3_VERSION)
    {
        size_t key_update_attempts = probe.attempts;
        twfRequire(SSL_key_update(client, SSL_KEY_UPDATE_REQUESTED) == 1, "queue KeyUpdate");
        twfRequire(SSL_write(client, plaintext, 97) == 97 && probe.attempts == key_update_attempts,
                   "pending KeyUpdate and application data retain their ordinary ordered path");
        transfer(SSL_get_wbio(client), SSL_get_rbio(server), pool, false);
        twfRequire(SSL_read(server, recovered, sizeof(recovered)) == 97 && memoryCompare(plaintext, recovered, 97) == 0,
                   "decrypt after KeyUpdate");
        twfRequire(SSL_write(server, plaintext, 17) == 17, "flush KeyUpdate acknowledgement with application data");
        transfer(SSL_get_wbio(server), SSL_get_rbio(client), pool, false);
        twfRequire(SSL_read(client, recovered, sizeof(recovered)) == 17 && memoryCompare(plaintext, recovered, 17) == 0,
                   "decrypt after acknowledged KeyUpdate");
    }

    twfRequire(SSL_write(client, plaintext, 29) == 29, "reserved output retained by caller");
    sbuf_t *first = tlsbufferbioTake(SSL_get_wbio(client));
    twfRequire(first != NULL && sbufGetRawPtr(first) == probe.last_output, "SSL encrypted directly into owned output");
    twfRequire(SSL_write(client, plaintext, 71) == 71, "next write while caller retains previous output");
    sbuf_t *second = tlsbufferbioTake(SSL_get_wbio(client));
    twfRequire(second != NULL && second != first && sbufGetRawPtr(second) == probe.last_output,
               "SSL does not reuse transferred output storage");

    const uint32_t live = g_twf_buffers.live_count;
    fail_seal           = true;
    twfRequire(SSL_write(client, plaintext, 11) < 0 && ! fail_seal && probe.cancels == 1,
               "encryption failure cancels its reservation without falling back");
    twfRequire(BIO_ctrl_pending(SSL_get_wbio(client)) == 0 && g_twf_buffers.live_count == live,
               "failed encryption immediately releases unpublished output");
    SSL_free(client);
    client = NULL;
    twfRequire(tlsbufferbioFeed(SSL_get_rbio(server), first) && tlsbufferbioFeed(SSL_get_rbio(server), second),
               "retained ciphertext survives SSL destruction");
    twfRequire(SSL_read(server, recovered, sizeof(recovered)) == 29 && memoryCompare(plaintext, recovered, 29) == 0,
               "first retained record authenticates after SSL destruction");
    twfRequire(SSL_read(server, recovered, sizeof(recovered)) == 71 && memoryCompare(plaintext, recovered, 71) == 0,
               "second retained record authenticates after SSL destruction");
    twfRequire(SSL_shutdown(server) == 0 && BIO_ctrl_pending(SSL_get_wbio(server)) > 0,
               "close-notify remains on the ordinary output path");
#else
    /* Leave unread ciphertext behind to exercise SSL-owned BIO cleanup. */
    twfRequire(SSL_write(client, plaintext, 29) == 29, "final retained record");
    transfer(SSL_get_wbio(client), SSL_get_rbio(server), pool, true);
#endif
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
#ifdef OPENSSL_IS_BORINGSSL
    caseOutputReservation(ctx, env.pool);
#endif
    SSL_CTX_free(ctx);
    caseTlsRoundtrip(env.pool, TLS1_2_VERSION);
    caseTlsRoundtrip(env.pool, TLS1_3_VERSION);
    twfWorkerEnvTeardown(&env);
    return 0;
}
