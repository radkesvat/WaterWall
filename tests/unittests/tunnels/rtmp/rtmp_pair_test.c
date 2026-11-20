#include "rtmp_session.h"

#include "test_assert.h"

#include <string.h>

enum
{
    kClient,
    kServer,
    kPeers,
    kChannelCapacity = 320 * 1024,
    kTransferSize    = 768 * 1024 + 23,
};

typedef struct channel_s
{
    uint8_t bytes[kChannelCapacity];
    size_t  first;
    size_t  end;
} channel_t;

typedef enum negotiation_case_e
{
    kNegotiationNormal,
    kNegotiationDowngradeRequest,
    kNegotiationDowngradeResult,
    kNegotiationWrongTransaction,
    kNegotiationFailedResult,
} negotiation_case_t;

typedef struct pair_s
{
    rtmp_session_t    *peers[kPeers];
    channel_t          channels[kPeers];
    const uint8_t     *expected[kPeers];
    size_t             expected_length[kPeers];
    size_t             received[kPeers];
    uint32_t           timestamp;
    unsigned           bandwidth_edits;
    negotiation_case_t negotiation;
    bool               accept_publication;
    bool               hold_input[kPeers];
    bool               minimum_window;
    bool               negotiation_edited;
} pair_t;

static pair_t  pair;
static uint8_t upload[kTransferSize];
static uint8_t download[kTransferSize];

static void openPair(const char *client_app, const char *client_stream)
{
    memset(&pair, 0, sizeof(pair));
    pair.peers[kClient] = rtmpSessionCreate(false, client_app, client_stream, "rtmp://localhost/waterwall", 16384);
    pair.peers[kServer] = rtmpSessionCreate(true, "waterwall", "tunnel", NULL, 65536);
    TEST_REQUIRE(TEST_FAILURE_EXIT, pair.peers[kClient] && pair.peers[kServer], "create RTMP peers");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpSessionStart(pair.peers[kClient]), "start client handshake");
}

static void closePair(void)
{
    for (size_t i = 0; i < kPeers; ++i)
        rtmpSessionDestroy(pair.peers[i]);
}

static void expectOutput(size_t peer, const uint8_t *expected, size_t length)
{
    pair.expected[peer]        = expected;
    pair.expected_length[peer] = length;
    pair.received[peer]        = 0;
}

static bool deliver(size_t peer, size_t fragment, bool *progress)
{
    channel_t *input = &pair.channels[peer ^ 1U];
    size_t     n     = input->end - input->first;
    if (n == 0 || pair.hold_input[peer])
        return true;
    if (n > fragment)
        n = fragment;
    if (! rtmpSessionQueueCarrier(pair.peers[peer], input->bytes + input->first, n))
        return false;
    input->first += n;
    if (input->first == input->end)
        input->first = input->end = 0;
    *progress = true;
    return true;
}

static void amendWire(size_t peer, uint8_t *wire, size_t n)
{
    if (pair.minimum_window && n == 17 && wire[0] == 2 && wire[6] == 5 && wire[7] == 6 && wire[16] == 0)
    {
        /* Preserve chunk geometry and absolute ACK accounting. */
        const uint8_t minimum_window[4] = {0, 1, 0, 0};
        memcpy(wire + 12, minimum_window, sizeof(minimum_window));
        ++pair.bandwidth_edits;
    }
    if (pair.negotiation == kNegotiationNormal || pair.negotiation_edited || (wire[0] & 63) != 3)
        return;
    if (pair.negotiation == kNegotiationDowngradeRequest && peer != kClient)
        return;
    if (pair.negotiation != kNegotiationDowngradeRequest && peer != kServer)
        return;

    static const uint8_t encoding[] = {'o', 'b', 'j', 'e',  'c',  't', 'E', 'n', 'c', 'o', 'd', 'i',
                                       'n', 'g', 0,   0x40, 0x08, 0,   0,   0,   0,   0,   0};
    static const uint8_t result[]   = {2, 0, 7, '_', 'r', 'e', 's', 'u', 'l', 't', 0, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0};
    static const uint8_t success[]  = "NetConnection.Connect.Success";
    const uint8_t       *pattern    = encoding;
    size_t               length     = sizeof(encoding);
    if (pair.negotiation == kNegotiationWrongTransaction)
    {
        pattern = result;
        length  = sizeof(result);
    }
    if (pair.negotiation == kNegotiationFailedResult)
    {
        pattern = success;
        length  = sizeof(success) - 1;
    }
    for (size_t i = 1; i + length <= n; ++i)
    {
        if (memcmp(wire + i, pattern, length) != 0)
            continue;
        if (pattern == encoding)
            memset(wire + i + 15, 0, 8); /* Valid AMF0 Number with unsupported encoding 0. */
        else if (pattern == result)
            wire[i + 12] = 0xe0; /* Unexpected transaction 0.5. */
        else
            wire[i + length - 1] = 'x'; /* Unsuccessful status of the same length. */
        pair.negotiation_edited = true;
        return;
    }
}

static bool capture(size_t peer)
{
    uint8_t    wire[RTMP_SESSION_WIRE_MAX];
    uint8_t    plain[RTMP_SESSION_DATA_MAX];
    channel_t *output   = &pair.channels[peer];
    bool       progress = false;
    size_t     n;
    while ((n = rtmpSessionTakeWire(pair.peers[peer], wire, sizeof(wire), NULL)) != 0)
    {
        amendWire(peer, wire, n);
        if (n > sizeof(output->bytes) - output->end)
        {
            memmove(output->bytes, output->bytes + output->first, output->end - output->first);
            output->end -= output->first;
            output->first = 0;
        }
        TEST_REQUIRE(TEST_FAILURE_EXIT, n <= sizeof(output->bytes) - output->end, "test channel overflow");
        memcpy(output->bytes + output->end, wire, n);
        output->end += n;
        progress = true;
    }
    while ((n = rtmpSessionTakePlain(pair.peers[peer], plain, sizeof(plain))) != 0)
    {
        TEST_REQUIRE(TEST_FAILURE_EXIT,
                     n <= pair.expected_length[peer] - pair.received[peer],
                     "received unexpected application bytes");
        TEST_EQUAL_BYTES(TEST_FAILURE_EXIT, plain, pair.expected[peer] + pair.received[peer], n, "stream bytes");
        pair.received[peer] += n;
        progress = true;
    }
    return progress;
}

static bool tick(size_t fragment, bool *progress)
{
    ++pair.timestamp;
    *progress = false;
    for (size_t peer = 0; peer < kPeers; ++peer)
    {
        bool stepped = false;
        if (! deliver(peer, fragment, progress) || ! rtmpSessionStep(pair.peers[peer], pair.timestamp, &stepped))
            return false;
        if (pair.accept_publication && peer == kServer && rtmpSessionPublishPending(pair.peers[kServer]))
        {
            TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpSessionAccept(pair.peers[kServer]), "accept pending publication");
            stepped = true;
        }
        bool captured = capture(peer);
        *progress     = *progress || stepped || captured;
    }
    return true;
}

static void pump(size_t fragment)
{
    for (unsigned i = 0; i < 200000; ++i)
    {
        bool progress;
        TEST_REQUIRE(TEST_FAILURE_EXIT, tick(fragment, &progress), "RTMP pair failed during pump");
        if (! progress)
            return;
    }
    TEST_REQUIRE(TEST_FAILURE_EXIT, false, "RTMP pair did not reach a stable state");
}

static void requireComplete(void)
{
    for (size_t i = 0; i < kPeers; ++i)
    {
        TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpSessionIsActive(pair.peers[i]), "RTMP peer is inactive");
        TEST_REQUIRE(TEST_FAILURE_EXIT, ! rtmpSessionHasTxTail(pair.peers[i]), "RTMP peer retained plaintext");
        TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, pair.received[i], pair.expected_length[i], "incomplete application stream");
        TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, pair.channels[i].first, pair.channels[i].end, "wire data remained pending");
    }
}

static void testStartup(void)
{
    static const uint8_t request[] = {
        0xff, 0xfe, 0x01, 0x00, '@', 's', 'e', 't', 'D', 'a', 't', 'a', 'F', 'r', 'a', 'm', 'e'};
    static const uint8_t banner[] = {0x00, 'b', 'a', 'n', 'n', 'e', 'r', 0xff};
    openPair("waterwall", "tunnel");
    expectOutput(kClient, banner, sizeof(banner));
    expectOutput(kServer, request, sizeof(request));
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpSessionQueuePlain(pair.peers[kClient], NULL, 0), "empty app buffer");
    TEST_REQUIRE(
        TEST_FAILURE_EXIT, rtmpSessionQueuePlain(pair.peers[kClient], request, sizeof(request)), "early request");
    pump(1);
    TEST_REQUIRE(
        TEST_FAILURE_EXIT, rtmpSessionPublishPending(pair.peers[kServer]), "validated publication was not pending");
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 ! rtmpSessionIsActive(pair.peers[kServer]),
                 "server activated before publication acceptance");
    TEST_REQUIRE(
        TEST_FAILURE_EXIT, ! rtmpSessionIsActive(pair.peers[kClient]), "client activated before publish success");
    TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, pair.received[kServer], 0, "application data bypassed publication");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpSessionHasTxTail(pair.peers[kClient]), "startup data was lost");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpSessionQueuePlain(pair.peers[kServer], banner, sizeof(banner)), "early banner");
    pair.accept_publication = true;
    pump(1);
    requireComplete();
    closePair();
}

static void feedSetup(rtmp_session_t *session, const uint8_t *bytes, size_t length)
{
    bool progress;
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 rtmpSessionQueueCarrier(session, bytes, length) && rtmpSessionStep(session, 0, &progress) && progress,
                 "process setup input");
}

static void checkWindowBeforeConnect(bool split)
{
    /* Hard Set Peer Bandwidth of 64 KiB on control chunk stream 2. */
    static const uint8_t bandwidth[]       = {2, 0, 0, 0, 0, 0, 5, 6, 0, 0, 0, 0, 0, 1, 0, 0, 0};
    static const size_t  handshake_sizes[] = {1537, 3073, 1536}; /* C0/C1, S0/S1/S2, C2. */
    uint8_t              wire[RTMP_SESSION_WIRE_MAX];
    openPair("waterwall", "tunnel");
    for (size_t i = 0; i < 3; ++i)
    {
        const size_t from = i % 2 == 0 ? kClient : kServer;
        const size_t n    = rtmpSessionTakeWire(pair.peers[from], wire, sizeof(wire), NULL);
        TEST_EQUAL_SIZE(TEST_FAILURE_EXIT, n, handshake_sizes[i], "handshake output size");
        feedSetup(pair.peers[from ^ 1U], wire, n);
    }

    /* Collect only the client's chunked connect command. Its ordinary window
     * controls follow connect and would otherwise supersede the early limit. */
    uint8_t batch[RTMP_SESSION_WIRE_MAX];
    memcpy(batch, bandwidth, sizeof(bandwidth));
    size_t length = sizeof(bandwidth);
    size_t n;
    while ((n = rtmpSessionTakeWire(pair.peers[kClient], wire, sizeof(wire), NULL)) != 0 && (wire[0] & 63) == 3)
    {
        TEST_REQUIRE(TEST_FAILURE_EXIT, n <= sizeof(batch) - length, "setup exceeds input fixture");
        memcpy(batch + length, wire, n);
        length += n;
    }
    TEST_REQUIRE(TEST_FAILURE_EXIT, length > sizeof(bandwidth) && n == 16 && wire[7] == 5, "locate end of connect");
    if (split)
    {
        feedSetup(pair.peers[kServer], batch, sizeof(bandwidth));
        feedSetup(pair.peers[kServer], batch + sizeof(bandwidth), length - sizeof(bandwidth));
    }
    else
    {
        feedSetup(pair.peers[kServer], batch, length);
    }

    uint8_t last_window[4] = {0};
    while ((n = rtmpSessionTakeWire(pair.peers[kServer], wire, sizeof(wire), NULL)) != 0)
    {
        if (n == 16 && wire[0] == 2 && wire[7] == 5)
            memcpy(last_window, wire + 12, sizeof(last_window));
    }
    TEST_EQUAL_BYTES(
        TEST_FAILURE_EXIT, last_window, bandwidth + 12, sizeof(last_window), "final advertised ACK window");
    closePair();
}

static void testEarlyBandwidth(void)
{
    checkWindowBeforeConnect(false);
    checkWindowBeforeConnect(true);
}

/* Xorshift32 with fixed nonzero seeds. Inputs cover all byte values by construction. */
static void fillBytes(uint8_t *data, size_t length, uint32_t seed)
{
    for (size_t i = 0; i < length; ++i)
    {
        seed ^= seed << 13U;
        seed ^= seed >> 17U;
        seed ^= seed << 5U;
        data[i] = (i < 256) ? (uint8_t) i : (uint8_t) seed;
    }
}

static void testDuplexCredit(void)
{
    fillBytes(upload, sizeof(upload), 0x19350001U);
    fillBytes(download, sizeof(download), 0x19350002U);
    openPair("waterwall", "tunnel");
    pair.accept_publication = true;
    pair.minimum_window     = true;
    pump(65536); /* Coalesce startup chunks and handshake/command bytes. */
    TEST_EQUAL_UINT(TEST_FAILURE_EXIT, pair.bandwidth_edits, 2, "did not negotiate minimum credit in both directions");
    requireComplete();

    expectOutput(kClient, download, sizeof(download));
    expectOutput(kServer, upload, sizeof(upload));
    pair.timestamp           = UINT32_MAX - 4U; /* Extended timestamps and wrap while data is sending. */
    pair.hold_input[kClient] = true;            /* Withhold returning ACKs through one full send window. */
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpSessionQueuePlain(pair.peers[kClient], upload, sizeof(upload)), "queue upload");
    pump(8191);
    TEST_REQUIRE(TEST_FAILURE_EXIT, rtmpSessionHasTxTail(pair.peers[kClient]), "send credit did not retain the tail");
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 pair.received[kServer] > 0 && pair.received[kServer] < sizeof(upload),
                 "expected partial delivery with peer ACKs held");

    TEST_REQUIRE(
        TEST_FAILURE_EXIT, rtmpSessionQueuePlain(pair.peers[kServer], download, sizeof(download)), "queue download");
    pair.hold_input[kClient] = false;
    pump(7919);
    requireComplete();
    closePair();
}

static void requireNegotiationRejected(const char *app, const char *stream, negotiation_case_t negotiation)
{
    openPair(app, stream);
    pair.accept_publication = true;
    pair.negotiation        = negotiation;
    bool rejected           = false;
    for (unsigned i = 0; i < 4096; ++i)
    {
        bool progress;
        if (! tick(53, &progress))
        {
            rejected = true;
            break;
        }
        if (! progress)
            break;
    }
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 negotiation == kNegotiationNormal || pair.negotiation_edited,
                 "negotiation fixture did not find the expected command value");
    TEST_REQUIRE(TEST_FAILURE_EXIT, rejected, "RTMP mismatch did not fail");
    TEST_REQUIRE(TEST_FAILURE_EXIT, ! rtmpSessionIsActive(pair.peers[kClient]), "mismatch activated RTMP client");
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 ! rtmpSessionPublishPending(pair.peers[kServer]),
                 "mismatched publication was available for acceptance");
    closePair();
}

static void testProfileMismatch(void)
{
    requireNegotiationRejected("other", "tunnel", kNegotiationNormal);
    requireNegotiationRejected("waterwall", "wrong", kNegotiationNormal);
    requireNegotiationRejected("waterwall", "tunnel", kNegotiationDowngradeRequest);
    requireNegotiationRejected("waterwall", "tunnel", kNegotiationDowngradeResult);
    requireNegotiationRejected("waterwall", "tunnel", kNegotiationWrongTransaction);
    requireNegotiationRejected("waterwall", "tunnel", kNegotiationFailedResult);
}

static void testSessionAdmission(void)
{
    const uint8_t byte = 0xff;
    openPair("waterwall", "tunnel");
    for (unsigned i = 0; i < 1024; ++i)
        TEST_REQUIRE(TEST_FAILURE_EXIT,
                     rtmpSessionQueueCarrier(pair.peers[kServer], &byte, 1),
                     "receive entry budget refused too early");
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 ! rtmpSessionQueueCarrier(pair.peers[kServer], &byte, 1),
                 "receive accepted more than 1024 retained entries");
    bool progress;
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 ! rtmpSessionStep(pair.peers[kServer], 0, &progress),
                 "entry refusal did not fail the stream");
    closePair();

    openPair("waterwall", "tunnel");
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 rtmpSessionQueuePlain(pair.peers[kClient], upload, sizeof(upload)),
                 "transmit byte budget refused too early");
    TEST_REQUIRE(TEST_FAILURE_EXIT,
                 ! rtmpSessionQueuePlain(pair.peers[kClient], upload, 256 * 1024),
                 "transmit accepted more than 1 MiB of retained input");
    TEST_REQUIRE(
        TEST_FAILURE_EXIT, rtmpSessionPeekWire(pair.peers[kClient]) == 0, "failed stream still exposed wire data");
    closePair();
}

int main(void)
{
    TEST_RUN_CASE(testStartup);
    TEST_RUN_CASE(testEarlyBandwidth);
    TEST_RUN_CASE(testDuplexCredit);
    TEST_RUN_CASE(testProfileMismatch);
    TEST_RUN_CASE(testSessionAdmission);
    return 0;
}
