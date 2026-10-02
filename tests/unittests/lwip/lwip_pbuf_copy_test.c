/*
 * Covers: lwip pbuf copy; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Cases: checkPacket
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.lwip_pbuf_copy_unit
 */
#include "wlibc.h"

static uint8_t        source[UINT16_MAX + 64];
static uint8_t        actual[UINT16_MAX + 128];
static uint8_t        expected[sizeof(actual)];
static const unsigned offsets[] = {0, 1, 7, 16, 31, 32, 63};

/* Domain oracle: checks every destination offset against the complete guarded
 * image and reports source/destination/length/copied for this matrix element. */
static void checkPacket(const struct pbuf *packet, unsigned source_offset, uint16_t length)
{
    for (unsigned i = 0; i < ARRAY_SIZE(offsets); ++i)
    {
        const unsigned offset = offsets[i];
        memset(actual, 0xa5, sizeof(actual));
        memset(expected, 0xa5, sizeof(expected));
        memcpy(expected + offset, source + source_offset, length);
        const uint16_t copied = pbufLargeCopyToPtr(packet, actual + offset);
        if (copied != length || memcmp(actual, expected, sizeof(actual)) != 0)
        {
            fprintf(stderr,
                    "pbuf copy mismatch: source=%u destination=%u length=%u copied=%u\n",
                    source_offset,
                    offset,
                    (unsigned) length,
                    (unsigned) copied);
            exit(1);
        }
    }
}

int main(void)
{
    for (size_t i = 0; i < sizeof(source); ++i)
        source[i] = (uint8_t) (i * 131U + i / 251U);

    const uint16_t lengths[] = {0, 1, 31, 63, 64, 65, 127, 128, 511, 512, 513, 1460, 4095, 4096, 65535};
    for (unsigned i = 0; i < ARRAY_SIZE(offsets); ++i)
    {
        const unsigned offset = offsets[i];
        for (unsigned j = 0; j < ARRAY_SIZE(lengths); ++j)
        {
            struct pbuf packet = {.payload = source + offset, .len = lengths[j], .tot_len = lengths[j]};
            checkPacket(&packet, offset, lengths[j]);
        }

        /* A maximum-length packet mixes empty, tiny and large spans. The
         * queued packet must not be visited or copied into caller headroom. */
        const uint16_t span_lengths[]                  = {0, 1, 63, 64, 0, 32767, 32640};
        struct pbuf    spans[ARRAY_SIZE(span_lengths)] = {0};
        struct pbuf    queued                          = {.payload = source, .len = 64, .tot_len = 64};
        uint32_t       consumed                        = 0;
        for (unsigned j = 0; j < ARRAY_SIZE(spans); ++j)
        {
            spans[j].payload = span_lengths[j] != 0 ? source + offset + consumed : NULL;
            spans[j].len     = span_lengths[j];
            spans[j].tot_len = (uint16_t) (UINT16_MAX - consumed);
            spans[j].next    = j + 1 < ARRAY_SIZE(spans) ? &spans[j + 1] : &queued;
            consumed += span_lengths[j];
        }
        checkPacket(spans, offset, UINT16_MAX);

        /* Empty packets and short/inconsistent chains must not consume bytes
         * from a following packet or exceed the advertised destination size. */
        struct pbuf empty = {.next = &queued};
        checkPacket(&empty, offset, 0);
        struct pbuf short_chain = {.payload = source + offset, .len = 63, .tot_len = 100};
        checkPacket(&short_chain, offset, 63);
        struct pbuf clipped = {.payload = source + offset, .len = 65, .tot_len = 64};
        checkPacket(&clipped, offset, 64);
        struct pbuf last  = {.next = &queued, .payload = source + offset + 1, .len = 63, .tot_len = 63};
        struct pbuf first = {.next = &last, .payload = source + offset, .len = 1, .tot_len = 100};
        checkPacket(&first, offset, 64);
    }
    return 0;
}
