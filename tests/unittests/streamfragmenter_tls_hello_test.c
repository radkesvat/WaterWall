#include "StreamFragmenter/structure.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "streamfragmenter TLS portable: %s\n", message);
        exit(1);
    }
}

static bool accepts(const char *json)
{
    cJSON *settings = cJSON_Parse(json);
    require(settings != NULL, "fixture JSON");
    streamfragmenter_tstate_t state  = {0};
    const bool                result = streamfragmenterLoadSettings(&state, settings);
    cJSON_Delete(settings);
    return result;
}

static void configuration(void)
{
    const char *invalid[] = {
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[],\"tls-hello-fragment\":1}",
        "{\"mode\":\"counter\",\"count\":1,\"cuts\":[],\"tls-hello-fragment\":true,\"tls-hello-fragment\":false}",
        "{\"mode\":\"counter\",\"count\":0,\"cuts\":[],\"tls-hello-timeout-ms\":1}",
        "{\"mode\":\"counter\",\"count\":0,\"cuts\":[],\"tls-hello-fragment\":false,\"tls-hello-timeout-ms\":1}",
        "{\"mode\":\"counter\",\"count\":0,\"cuts\":[],\"tls-hello-fragment\":true,\"tls-hello-timeout-ms\":0}",
        "{\"mode\":\"counter\",\"count\":0,\"cuts\":[],\"tls-hello-fragment\":true,\"tls-hello-timeout-ms\":1.5}",
        "{\"mode\":\"counter\",\"count\":0,\"cuts\":[],\"tls-hello-fragment\":true,\"tls-hello-timeout-ms\":"
        "4294967296}",
        "{\"mode\":\"counter\",\"count\":0,\"cuts\":[],\"tls-hello-fragment\":true,\"tls-hello-timeout-ms\":1,\"tls-"
        "hello-timeout-ms\":2}",
    };
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
        require(! accepts(invalid[i]), "invalid setting accepted");
    require(accepts("{\"mode\":\"counter\",\"count\":0,\"cuts\":[],\"tls-hello-fragment\":true,\"tls-hello-timeout-"
                    "ms\":4294967295}"),
            "maximum timeout rejected");
}

static void parserAndRewrite(void)
{
    uint8_t handshake[50] = {1, 0, 0, 46};
    for (uint32_t i = 4; i < sizeof(handshake); ++i)
        handshake[i] = (uint8_t) (i * 13);
    uint8_t wire[60] = {22, 3, 1, 0, 2, handshake[0], handshake[1], 22, 3, 3, 0, 48};
    memoryCopy(wire + 12, handshake + 2, 48);

    streamfragmenter_tls_parser_t parser       = {0};
    unsigned                      header_ready = 0, complete = 0;
    for (uint32_t i = 0; i < sizeof(wire); ++i)
    {
        streamfragmenter_tls_result_t result = streamfragmenterTlsFeed(&parser, wire + i, 1);
        header_ready += result == kStreamFragmenterTlsHeaderReady;
        complete += result == kStreamFragmenterTlsComplete;
        require(result != kStreamFragmenterTlsPassUnchanged, "valid framing rejected");
    }
    require(header_ready == 1 && complete == 1 && parser.handshake_total == sizeof(handshake),
            "cross-record handshake header");

    streamfragmenter_tstate_t settings = {.cut_count = 3, .cuts = {{2, 0, 100}, {3, 0, 100}, {25, 0, 100}}};
    sbuf_t                   *original = sbufCreateWithPadding(sizeof(wire), 64);
    sbuf_t                   *output   = sbufCreateWithPadding(70, 64);
    require(original != NULL && output != NULL, "buffer allocation");
    memoryCopy(sbufGetMutablePtr(original), wire, sizeof(wire));
    sbufSetLength(original, sizeof(wire));
    require(streamfragmenterTlsRewriteLength(original, 7, &settings) == 70, "rewrite length");
    uint32_t mapped[3] = {0};
    require(streamfragmenterTlsRewrite(original, 7, &settings, output, mapped), "rewrite refused");
    require(mapped[0] == 7 && mapped[1] == 13 && mapped[2] == 40, "mapped scheduling endpoints");
    const uint8_t  expected_versions[] = {1, 3, 3, 3};
    const uint16_t expected_lengths[]  = {2, 1, 22, 25};
    uint8_t        recovered[50];
    uint32_t       wire_offset = 0, handshake_offset = 0;
    const uint8_t *bytes = sbufGetRawPtr(output);
    for (size_t i = 0; i < ARRAY_SIZE(expected_lengths); ++i)
    {
        const uint16_t length = ((uint16_t) bytes[wire_offset + 3] << 8) | bytes[wire_offset + 4];
        require(bytes[wire_offset] == 22 && bytes[wire_offset + 1] == 3 &&
                    bytes[wire_offset + 2] == expected_versions[i] && length == expected_lengths[i],
                "record header or original version changed");
        memoryCopy(recovered + handshake_offset, bytes + wire_offset + 5, length);
        wire_offset += 5 + length;
        handshake_offset += length;
    }
    require(wire_offset == sbufGetLength(output) && handshake_offset == sizeof(handshake) &&
                memoryCompare(recovered, handshake, sizeof(handshake)) == 0,
            "handshake transcript changed");
    sbufDestroy(original);
    sbufDestroy(output);

    const uint8_t bad_version[] = {22, 3, 4};
    parser                      = (streamfragmenter_tls_parser_t) {0};
    require(streamfragmenterTlsFeed(&parser, bad_version, sizeof(bad_version)) == kStreamFragmenterTlsPassUnchanged,
            "unsupported version accepted");
    const uint8_t oversized[] = {22, 3, 3, 0, 4, 1, 1, 0, 0};
    parser                    = (streamfragmenter_tls_parser_t) {0};
    require(streamfragmenterTlsFeed(&parser, oversized, 5) == kStreamFragmenterTlsIncomplete &&
                streamfragmenterTlsFeed(&parser, oversized + 5, 4) == kStreamFragmenterTlsPassUnchanged,
            "oversized handshake accepted");
}

int main(void)
{
    configuration();
    parserAndRewrite();
    puts("streamfragmenter TLS portable: passed");
    return 0;
}
