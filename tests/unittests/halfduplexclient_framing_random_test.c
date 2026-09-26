#include "HalfDuplexClient/structure.h"

#include "halfduplex_splice_fixture.h"
#include "tunnel_line_failure_harness.h"

enum
{
    kPairCount         = 2,
    kTestPayloadSize   = 5,
    kTestBufferSize    = 4096,
    kCapturedFrameSize = kHLFDIntroSize + 64000
};

typedef struct client_pair_s
{
    line_t  *main_line;
    line_t  *upload_line;
    line_t  *download_line;
    sbuf_t  *expected_upload;
    uint8_t  upload_frame[kCapturedFrameSize];
    uint8_t  download_intro[kHLFDIntroSize];
    uint32_t upload_length;
    uint32_t download_length;
    uint32_t minimum_upload_padding;
} client_pair_t;

typedef struct client_framing_fixture_s
{
    twf_worker_env_t env;
    tunnel_chain_t  *chain;
    tunnel_t        *halfduplex;
    tunnel_t        *next;
    client_pair_t    pairs[kPairCount];
} client_framing_fixture_t;

static client_framing_fixture_t *g_fixture;

static const uint8_t kRandomKey[32] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
};

static client_pair_t *findPair(line_t *line, bool *is_upload)
{
    for (size_t index = 0; index < ARRAY_SIZE(g_fixture->pairs); ++index)
    {
        client_pair_t *pair = &g_fixture->pairs[index];
        if (line == pair->upload_line)
        {
            *is_upload = true;
            return pair;
        }
        if (line == pair->download_line)
        {
            *is_upload = false;
            return pair;
        }
    }
    return NULL;
}

static void captureFramedPayload(tunnel_t *next, line_t *line, sbuf_t *buf)
{
    twfRequire(g_fixture != NULL && next == g_fixture->next, "HalfDuplexClient used the wrong framing target");

    bool           is_upload = false;
    client_pair_t *pair      = findPair(line, &is_upload);
    twfRequire(pair != NULL, "HalfDuplexClient framed an unknown child line");

    twfRequire(! sbufIsSplice(buf), "combined intro must be ordinary");
    twfRequire(sbufGetLeftCapacity(buf) >= (is_upload ? pair->minimum_upload_padding : 64),
               "output lost onward padding");
    const uint32_t length = sbufGetLength(buf);
    if (is_upload)
    {
        if (pair->expected_upload != NULL)
            twfRequire(buf == pair->expected_upload, "ordinary first payload was unnecessarily copied");
        twfRequire(length <= sizeof(pair->upload_frame), "upload frame exceeded the capture buffer");
        memoryCopy(pair->upload_frame, sbufGetRawPtr(buf), length);
        pair->upload_length = length;
    }
    else
    {
        twfRequire(length <= sizeof(pair->download_intro), "download intro exceeded the capture buffer");
        memoryCopy(pair->download_intro, sbufGetRawPtr(buf), length);
        pair->download_length = length;
    }
    lineReuseBuffer(line, buf);
}

static void initializePair(client_framing_fixture_t *fixture, client_pair_t *pair)
{
    pair->minimum_upload_padding = 64;
    pair->main_line              = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
    pair->upload_line            = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
    pair->download_line          = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);

    halfduplexclient_lstate_t *main_ls     = lineGetState(pair->main_line, fixture->halfduplex);
    halfduplexclient_lstate_t *upload_ls   = lineGetState(pair->upload_line, fixture->halfduplex);
    halfduplexclient_lstate_t *download_ls = lineGetState(pair->download_line, fixture->halfduplex);
    halfduplexclientLinestateInitialize(main_ls, pair->main_line);
    halfduplexclientLinestateInitialize(upload_ls, pair->main_line);
    halfduplexclientLinestateInitialize(download_ls, pair->main_line);

    main_ls->upload_line       = pair->upload_line;
    main_ls->download_line     = pair->download_line;
    upload_ls->upload_line     = pair->upload_line;
    upload_ls->download_line   = pair->download_line;
    download_ls->upload_line   = pair->upload_line;
    download_ls->download_line = pair->download_line;
}

static void fixtureSetup(client_framing_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kTestBufferSize, 64 + kHLFDIntroSize);

    fixture->halfduplex = tunnelCreate(NULL, kTunnelStateSize, kLineStateSize);
    fixture->next       = tunnelCreate(NULL, 0, 0);
    twfRequire(fixture->halfduplex != NULL && fixture->next != NULL, "failed to create framing fixture tunnels");
    tunnelBind(fixture->halfduplex, fixture->next);
    fixture->next->fnPayloadU = captureFramedPayload;

    fixture->chain                      = tunnelchainCreate(1);
    fixture->chain->sum_line_state_size = fixture->halfduplex->lstate_size;
    tunnelchainFinalize(fixture->chain);
    fixture->halfduplex->chain = fixture->chain;

    for (size_t index = 0; index < ARRAY_SIZE(fixture->pairs); ++index)
    {
        initializePair(fixture, &fixture->pairs[index]);
    }
    g_fixture = fixture;
}

static void destroyPair(client_framing_fixture_t *fixture, client_pair_t *pair)
{
    halfduplexclientLinestateDestroy(lineGetState(pair->download_line, fixture->halfduplex));
    halfduplexclientLinestateDestroy(lineGetState(pair->upload_line, fixture->halfduplex));
    halfduplexclientLinestateDestroy(lineGetState(pair->main_line, fixture->halfduplex));
    lineDestroy(pair->download_line);
    lineDestroy(pair->upload_line);
    lineDestroy(pair->main_line);
}

static void fixtureTeardown(client_framing_fixture_t *fixture)
{
    for (size_t index = 0; index < ARRAY_SIZE(fixture->pairs); ++index)
    {
        destroyPair(fixture, &fixture->pairs[index]);
    }
    twfRequireNoLeakedBuffers();
    tunnelchainDestroy(fixture->chain);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->halfduplex);
    g_fixture = NULL;
    twfWorkerEnvTeardown(&fixture->env);
}

static void sendFirstPayload(client_framing_fixture_t *fixture, size_t pair_index, uint8_t marker)
{
    sbuf_t *payload = bufferpoolGetLargeBuffer(fixture->env.pool);
    sbufSetLength(payload, kTestPayloadSize);
    for (uint32_t index = 0; index < kTestPayloadSize; ++index)
    {
        sbufGetMutablePtr(payload)[index] = (uint8_t) (marker + index);
    }
    fixture->pairs[pair_index].expected_upload = payload;
    halfduplexclientTunnelUpStreamPayload(fixture->halfduplex, fixture->pairs[pair_index].main_line, payload);
}

static void caseOrdinaryHeadroom(void)
{
    twfSetCase("HalfDuplexClient reuses ordinary first payload only with enough intro headroom");
    const uint16_t paddings[] = {0, kHLFDIntroSize - 1, kHLFDIntroSize, kHLFDIntroSize + 64};
    const uint32_t lengths[]  = {0, 5, 64000};
    uint8_t        data[64000];
    for (unsigned i = 0; i < sizeof(data); ++i)
        data[i] = (uint8_t) i;
    for (unsigned i = 0; i < ARRAY_SIZE(paddings); ++i)
    {
        for (unsigned j = 0; j < ARRAY_SIZE(lengths); ++j)
        {
            client_framing_fixture_t fixture;
            fixtureSetup(&fixture);
            client_pair_t *pair  = &fixture.pairs[0];
            sbuf_t        *input = twfTrackAcquired(sbufCreateWithPadding(lengths[j], paddings[i]));
            input->curpos        = paddings[i]; // Exercise exact headroom despite allocation padding alignment.
            sbufSetLength(input, lengths[j]);
            memoryCopyLarge(sbufGetMutablePtr(input), data, lengths[j]);
            if (paddings[i] >= kHLFDIntroSize)
            {
                pair->expected_upload        = input;
                pair->minimum_upload_padding = paddings[i] - kHLFDIntroSize;
            }
            halfduplexclientTunnelUpStreamPayload(fixture.halfduplex, pair->main_line, input);
            twfRequire(pair->upload_length == kHLFDIntroSize + lengths[j] &&
                           memoryEqual(pair->upload_frame + kHLFDIntroSize, data, lengths[j]),
                       "ordinary first body changed");
            twfRequire(pair->upload_frame[0] == kHLFDCmdUpload && pair->download_intro[0] == kHLFDCmdDownload &&
                           pair->download_length == kHLFDIntroSize &&
                           memoryEqual(pair->upload_frame + 1, pair->download_intro + 1, kHLFDPairIdSize),
                       "ordinary first intros disagree");
            fixtureTeardown(&fixture);
        }
    }
}

static void requirePairFrame(const client_pair_t *pair, const uint8_t expected_id[kHLFDPairIdSize], uint8_t marker)
{
    twfRequireEqualU32(pair->download_length, kHLFDIntroSize, "download intro length was not exactly 17 bytes");
    twfRequireEqualU32(pair->upload_length,
                       kHLFDIntroSize + kTestPayloadSize,
                       "upload intro and first payload had the wrong framed length");
    twfRequire(pair->download_intro[kHLFDCommandOffset] == kHLFDCmdDownload,
               "download intro did not use the exact download command");
    twfRequire(pair->upload_frame[kHLFDCommandOffset] == kHLFDCmdUpload,
               "upload intro did not use the exact upload command");
    twfRequire(memoryEqual(pair->download_intro + kHLFDPairIdOffset, expected_id, kHLFDPairIdSize),
               "download intro did not carry the expected 128-bit pair ID");
    twfRequire(memoryEqual(pair->upload_frame + kHLFDPairIdOffset, expected_id, kHLFDPairIdSize),
               "upload and download intros did not carry the same 128-bit pair ID");
    for (uint32_t index = 0; index < kTestPayloadSize; ++index)
    {
        twfRequire(pair->upload_frame[kHLFDIntroSize + index] == (uint8_t) (marker + index),
                   "upload framing changed the first user payload");
    }
}

static void caseOnePairConsumesExactlyTwoSecureWords(void)
{
    twfSetCase("HalfDuplexClient one pair uses two secure words and one shared ID");
    client_framing_fixture_t fixture;
    fixtureSetup(&fixture);

    uint8_t expected_id[kHLFDPairIdSize];
    wfrandTestReset(kRandomKey, 3);
    PUT_BE64(expected_id, fastRand64());
    PUT_BE64(expected_id + (kHLFDPairIdSize / 2), fastRand64());
    const uint64_t expected_next = fastRand64();

    wfrandTestReset(kRandomKey, 3);
    sendFirstPayload(&fixture, 0, 0x40);
    requirePairFrame(&fixture.pairs[0], expected_id, 0x40);
    twfRequire(fastRand64() == expected_next, "one logical pair did not consume exactly two fastRand64 words");

    fixtureTeardown(&fixture);
}

static void caseSeparatePairsUseIndependentCSPRNGIds(void)
{
    twfSetCase("HalfDuplexClient separate pairs use unrelated CSPRNG IDs");
    client_framing_fixture_t fixture;
    fixtureSetup(&fixture);

    uint8_t expected_ids[kPairCount][kHLFDPairIdSize];
    wfrandTestReset(kRandomKey, 11);
    for (size_t index = 0; index < kPairCount; ++index)
    {
        PUT_BE64(expected_ids[index], fastRand64());
        PUT_BE64(expected_ids[index] + (kHLFDPairIdSize / 2), fastRand64());
    }
    const uint64_t expected_next = fastRand64();

    wfrandTestReset(kRandomKey, 11);
    sendFirstPayload(&fixture, 0, 0x50);
    sendFirstPayload(&fixture, 1, 0x60);
    requirePairFrame(&fixture.pairs[0], expected_ids[0], 0x50);
    requirePairFrame(&fixture.pairs[1], expected_ids[1], 0x60);
    twfRequire(! memoryEqual(expected_ids[0], expected_ids[1], kHLFDPairIdSize),
               "two logical pairs reused one identifier");
    twfRequire(GET_BE64(expected_ids[1] + (kHLFDPairIdSize / 2)) !=
                       GET_BE64(expected_ids[0] + (kHLFDPairIdSize / 2)) + UINT64_C(1) ||
                   GET_BE64(expected_ids[1]) != GET_BE64(expected_ids[0]),
               "separate pair IDs retained the old adjacent-counter pattern");
    twfRequire(fastRand64() == expected_next, "two logical pairs did not consume exactly four fastRand64 words");

    fixtureTeardown(&fixture);
}

static sbuf_t *expected_direct;
static void    captureDirect(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    twfRequire(buf == expected_direct, "direct path replaced wrapper");
    twfRequire(sbufIsSplice(buf), "direct path materialized input");
    buf = halfduplexTestMaterialize(lineGetBufferPool(line), buf);
    twfRequire(sbufGetLength(buf) == 5 && memoryEqual(sbufGetRawPtr(buf), "later", 5), "direct bytes changed");
    lineReuseBuffer(line, buf);
}

static void caseRepresentations(void)
{
    const uint32_t lengths[]  = {5, 5, 5, 0, 64000};
    const uint16_t prefixes[] = {0, 2, 5, 0, 63000};
    for (unsigned i = 0; i < ARRAY_SIZE(lengths); ++i)
    {
        client_framing_fixture_t fixture;
        fixtureSetup(&fixture);
        uint8_t data[64000];
        for (unsigned j = 0; j < sizeof(data); ++j)
            data[j] = (uint8_t) j;
        halfduplexclientTunnelUpStreamPayload(
            fixture.halfduplex,
            fixture.pairs[0].main_line,
            halfduplexTestBytes(fixture.env.pool, data, lengths[i], true, prefixes[i]));
        client_pair_t *pair = &fixture.pairs[0];
        twfRequire(pair->upload_length == kHLFDIntroSize + lengths[i] &&
                       memoryEqual(pair->upload_frame + kHLFDIntroSize, data, lengths[i]),
                   "splice first body changed");
        twfRequire(pair->download_length == kHLFDIntroSize &&
                       memoryEqual(pair->upload_frame + 1, pair->download_intro + 1, 16),
                   "splice IDs differ");
#if WW_HAVE_SPLICE
        fixture.next->fnPayloadU = captureDirect;
        expected_direct          = halfduplexTestBytes(fixture.env.pool, "later", 5, true, 2);
        halfduplexclientTunnelUpStreamPayload(fixture.halfduplex, pair->main_line, expected_direct);
        fixture.next->fnPayloadD = captureDirect;
        fixture.halfduplex->prev = fixture.next;
        expected_direct          = halfduplexTestBytes(fixture.env.pool, "later", 5, true, 2);
        halfduplexclientTunnelDownStreamPayload(fixture.halfduplex, pair->download_line, expected_direct);
#endif
        fixtureTeardown(&fixture);
    }
}

int main(void)
{
    twfRequire(globalstateInitializeSecureRandom(), "secure random provider initialization failed");
    twfRequire(frandGlobalInit(), "fast random global initialization failed");
    frandInit();

    caseRepresentations();
    caseOrdinaryHeadroom();
    caseOnePairConsumesExactlyTwoSecureWords();
    caseSeparatePairsUseIndependentCSPRNGIds();

    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    puts("halfduplexclient_framing_random_test: all cases passed");
    return 0;
}
