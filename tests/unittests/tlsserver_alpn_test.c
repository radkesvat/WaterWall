#include "TlsServer/structure.h"

#include <stdio.h>
#include <stdlib.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void requireSelected(const unsigned char *out, unsigned char outlen, const char *expected)
{
    size_t expected_len = stringLength(expected);

    require(out != NULL, "ALPN selection returned NULL");
    require(outlen == expected_len, "ALPN selection length changed");
    require(memoryEqual(out, expected, expected_len), "ALPN selection value changed");
}

static void requireNoSelection(int ret, const unsigned char *out, unsigned char outlen, const char *message)
{
    require(ret == SSL_TLSEXT_ERR_NOACK, message);
    require(out == NULL, "ALPN no-overlap selected a protocol");
    require(outlen == 0, "ALPN no-overlap changed output length");
}

static void testLegacyAlpnUsesConfiguredPreference(void)
{
    char h2[]     = "h2";
    char http11[] = "http/1.1";

    struct tlsserver_alpn_item_s alpns[] = {
        {.name = h2, .name_length = 2},
        {.name = http11, .name_length = 8},
    };
    tlsserver_tstate_t ts = {.alpns = alpns, .alpns_length = ARRAY_SIZE(alpns)};

    const unsigned char client_offer[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
        2, 'h', '2',
    };
    const unsigned char *out    = NULL;
    unsigned char        outlen = 0;

    int ret = tlsserverOnAlpnSelect(NULL, &out, &outlen, client_offer, sizeof(client_offer), &ts);

    require(ret == SSL_TLSEXT_ERR_OK, "legacy ALPN selection failed");
    requireSelected(out, outlen, "h2");
}

static void testSelectAlpnUsesConfiguredPreference(void)
{
    char h2[]     = "h2";
    char http11[] = "http/1.1";

    struct tlsserver_alpn_item_s alpns[] = {
        {.name = h2, .name_length = 2},
        {.name = http11, .name_length = 8},
    };
    tlsserver_tstate_t ts = {.select_alpns = alpns, .select_alpns_length = ARRAY_SIZE(alpns)};

    const unsigned char client_offer[] = {
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
        2, 'h', '2',
    };
    const unsigned char *out    = NULL;
    unsigned char        outlen = 0;

    int ret = tlsserverOnAlpnSelect(NULL, &out, &outlen, client_offer, sizeof(client_offer), &ts);

    require(ret == SSL_TLSEXT_ERR_OK, "select ALPN selection failed");
    requireSelected(out, outlen, "h2");
}

static void testDefaultHttp11ProfileSelectsHttp11(void)
{
    char http11[] = "http/1.1";

    struct tlsserver_alpn_item_s alpns[] = {
        {.name = http11, .name_length = 8},
    };
    tlsserver_tstate_t ts = {.select_alpns = alpns, .select_alpns_length = ARRAY_SIZE(alpns)};

    const unsigned char client_offer[] = {
        2, 'h', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', '1',
    };
    const unsigned char *out    = NULL;
    unsigned char        outlen = 0;

    int ret = tlsserverOnAlpnSelect(NULL, &out, &outlen, client_offer, sizeof(client_offer), &ts);

    require(ret == SSL_TLSEXT_ERR_OK, "HTTP/1.1 default profile selection failed");
    requireSelected(out, outlen, "http/1.1");
}

static void testDefaultHttp11ProfileContinuesH2OnlyWithoutAlpn(void)
{
    char http11[] = "http/1.1";

    struct tlsserver_alpn_item_s alpns[] = {
        {.name = http11, .name_length = 8},
    };
    tlsserver_tstate_t ts = {.select_alpns = alpns, .select_alpns_length = ARRAY_SIZE(alpns)};

    const unsigned char  client_offer[] = {2, 'h', '2'};
    const unsigned char *out            = NULL;
    unsigned char        outlen         = 0;

    int ret = tlsserverOnAlpnSelect(NULL, &out, &outlen, client_offer, sizeof(client_offer), &ts);

    requireNoSelection(ret, out, outlen, "HTTP/1.1 default profile did not continue h2-only without ALPN");
}

static void testSelectAlpnNoOverlapContinuesWithoutAlpn(void)
{
    char h2[]     = "h2";
    char http11[] = "http/1.1";

    struct tlsserver_alpn_item_s alpns[] = {
        {.name = h2, .name_length = 2},
        {.name = http11, .name_length = 8},
    };
    tlsserver_tstate_t ts = {.select_alpns = alpns, .select_alpns_length = ARRAY_SIZE(alpns)};

    const unsigned char  client_offer[] = {3, 'f', 'o', 'o'};
    const unsigned char *out            = NULL;
    unsigned char        outlen         = 0;

    int ret = tlsserverOnAlpnSelect(NULL, &out, &outlen, client_offer, sizeof(client_offer), &ts);

    requireNoSelection(ret, out, outlen, "select ALPN no-overlap did not continue without ALPN");
}

static void testLegacyAlpnNoOverlapContinuesWithoutAlpn(void)
{
    char h2[] = "h2";

    struct tlsserver_alpn_item_s alpns[] = {
        {.name = h2, .name_length = 2},
    };
    tlsserver_tstate_t ts = {.alpns = alpns, .alpns_length = ARRAY_SIZE(alpns)};

    const unsigned char  client_offer[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    const unsigned char *out            = NULL;
    unsigned char        outlen         = 0;

    int ret = tlsserverOnAlpnSelect(NULL, &out, &outlen, client_offer, sizeof(client_offer), &ts);

    requireNoSelection(ret, out, outlen, "legacy ALPN no-overlap did not continue without ALPN");
}

int main(void)
{
    testLegacyAlpnUsesConfiguredPreference();
    testSelectAlpnUsesConfiguredPreference();
    testDefaultHttp11ProfileSelectsHttp11();
    testDefaultHttp11ProfileContinuesH2OnlyWithoutAlpn();
    testSelectAlpnNoOverlapContinuesWithoutAlpn();
    testLegacyAlpnNoOverlapContinuesWithoutAlpn();
    return 0;
}
