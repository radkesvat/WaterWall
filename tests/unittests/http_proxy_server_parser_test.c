#include "HttpProxyServer/parser.h"

static void require(bool ok, const char *what)
{
    if (! ok)
    {
        fprintf(stderr, "http proxy parser: %s\n", what);
        exit(1);
    }
}

static unsigned parse(const char *text, bool response, bool head, hps_header_t *h, char *storage)
{
    stringCopy(storage, text);
    return hpsParseHeader(storage, stringLength(storage), response, head, h);
}

static void framing(const char *wire, bool decode, const char *expected)
{
    /* All fragmentation sizes, including every delimiter split. */
    for (size_t step = 1; step <= stringLength(wire); ++step)
    {
        hps_body_t    b = {.kind = kHpsBodyChunked};
        unsigned char retained[1024];
        char          output[1024] = {0};
        size_t        length = 0, written = 0;
        for (size_t offset = 0; offset < stringLength(wire);)
        {
            size_t n = min(step, stringLength(wire) - offset);
            memoryCopy(retained + length, wire + offset, n);
            length += n;
            offset += n;
            for (;;)
            {
                size_t used;
                bool   emit;
                int    result = hpsBodyStep(&b, retained, length, decode, NULL, &used, &emit);
                require(result >= 0, "valid fragmented chunk rejected");
                if (! result)
                    break;
                if (emit)
                {
                    memoryCopy(output + written, retained, used);
                    written += used;
                }
                memoryMove(retained, retained + used, length - used);
                length -= used;
            }
        }
        require(b.kind == kHpsBodyDone && length == 4 && ! memoryCompare(retained, "TAIL", 4), "lost framing tail");
        output[written] = 0;
        require(! stringCompare(output, expected), "streamed bytes changed");
    }
}

int main(void)
{
    hps_header_t h;
    char         storage[32769], rewritten[34000];
    size_t       n;
    const char  *fix_case = getenv("HPS_FIX_CASE");
    if (! fix_case || ! stringCompare(fix_case, "R2"))
    {
        const char *suffixes[] = {"\rIgnored: invalid\r\n\r\n",
                                  "\rIgnored: invalid\r\nContent-Length: 3\r\n\r\n",
                                  "\rIgnored: invalid\r\nProxy-Authorization: Basic dTpw\r\n\r\n",
                                  "\r\nIgnored: suffix\r\n\r\n"};
        for (unsigned response = 0; response < 2; ++response)
            for (size_t i = 0; i < ARRAY_SIZE(suffixes); ++i)
            {
                stringNPrintf(storage,
                              sizeof(storage),
                              "%s%s",
                              response ? "HTTP/1.1 200 OK\r\nX: valid\r\n" : "GET http://a/ HTTP/1.1\r\nHost: a\r\n",
                              suffixes[i]);
                require(hpsParseHeader(storage, stringLength(storage), response != 0, false, &h) == 400,
                        "R2 complete header validation");
            }
    }
    if (! fix_case || ! stringCompare(fix_case, "R4"))
    {
        require(! parse("POST http://a/ HTTP/1.0\r\nHost: a\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n",
                        false,
                        false,
                        &h,
                        storage),
                "R4 HTTP/1.0 ignored expectation");
        require(hpsRewriteHeader(&h, false, true, false, rewritten, sizeof(rewritten), &n) &&
                    strstr(rewritten, "POST / HTTP/1.1\r\n") && strstr(rewritten, "Content-Length: 3\r\n") &&
                    ! strstr(rewritten, "Expect:"),
                "R4 rewrite reactivated expectation");
        const char *expectations[] = {"Expect: unsupported\r\n", "Expect: 100-continue\r\nExpect: 100-continue\r\n"};
        for (unsigned version = 0; version < 2; ++version)
            for (size_t i = 0; i < ARRAY_SIZE(expectations); ++i)
            {
                stringNPrintf(storage,
                              sizeof(storage),
                              "POST http://a/ HTTP/1.%u\r\nHost: a\r\n%s\r\n",
                              version,
                              expectations[i]);
                require(hpsParseHeader(storage, stringLength(storage), false, false, &h) == 417,
                        "invalid expectation accepted");
            }
    }
    require(! parse("PROPFIND http://EXAMPLE.test:8080/a%2Fb?q=%23 HTTP/1.1\r\nHost: other.test\r\n"
                    "Proxy-Authorization: Basic dTpw\r\nAuthorization: Bearer origin\r\nConnection: X-Hop\r\n"
                    "X-Hop: remove\r\nContent-Length: 4\r\n\r\n",
                    false,
                    false,
                    &h,
                    storage),
            "extension method");
    require(! stringCompare(h.authority.host, "example.test") && h.authority.port == 8080, "URI authority wins");
    require(hpsRewriteHeader(&h, false, false, false, rewritten, sizeof(rewritten), &n), "rewrite");
    require(strstr(rewritten, "PROPFIND /a%2Fb?q=%23 HTTP/1.1\r\n") &&
                strstr(rewritten, "Host: example.test:8080\r\n") &&
                strstr(rewritten, "Authorization: Bearer origin\r\n") && ! strstr(rewritten, "Proxy-Authorization") &&
                ! strstr(rewritten, "X-Hop"),
            "forwarding fields");
    const char *bad[] = {
        "GET http://a/ HTTP/1.1\r\n\r\n",
        "GET http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        "GET http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 1, 1\r\n\r\n",
        "GET http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551616\r\n\r\n",
        "GET http://a/ HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "GET http://a/ HTTP/1.1\r\nHost: a\r\n folded: invalid\r\n\r\n",
        "GET http://a/ HTTP/1.1\r\nHost: a\r\nBad : value\r\n\r\n",
        "CONNECT a:443 HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\n",
        "GET http://a/ HTTP/1.1\r\nHost: a\r\nConnection: Content-Length\r\n\r\n",
        "GET http://a/ HTTP/1.1\r\nHost: a\r\nProxy-Authorization: a\r\nProxy-Authorization: b\r\n\r\n"};
    for (size_t i = 0; i < ARRAY_SIZE(bad); ++i)
        require(parse(bad[i], false, false, &h, storage) != 0, bad[i]);
    require(parse("TRACE http://a/ HTTP/1.1\r\nHost: a\r\n\r\n", false, false, &h, storage) == 405, "TRACE");
    require(parse("GET https://a/ HTTP/1.1\r\nHost: a\r\n\r\n", false, false, &h, storage) == 501, "scheme");
    require(parse("GET http://a/ HTTP/2.0\r\nHost: a\r\n\r\n", false, false, &h, storage) == 505, "version");
    require(! parse("OPTIONS * HTTP/1.1\r\nHost: proxy\r\n\r\n", false, false, &h, storage) && h.local_options,
            "OPTIONS *");
    require(! parse("OPTIONS http://a/ HTTP/1.1\r\nHost: a\r\nMax-Forwards: 0\r\n\r\n", false, false, &h, storage) &&
                h.local_options,
            "Max-Forwards zero");
    require(! parse("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n", true, true, &h, storage) &&
                h.body.kind == kHpsBodyDone,
            "HEAD response");
    require(! parse("HTTP/1.1 304 Not Modified\r\nContent-Length: 999\r\n\r\n", true, false, &h, storage) &&
                h.body.kind == kHpsBodyDone,
            "304 response");
    require(! parse("HTTP/1.0 200 OK\r\n\r\n", true, false, &h, storage) && h.body.kind == kHpsBodyEof, "EOF response");
    hps_authority_t a, b;
    require(hpsAuthority("[::1]:123", 9, true, &a) && hpsAuthority("[0:0:0:0:0:0:0:1]:123", 21, true, &b) &&
                hpsAuthorityEqual(&a, &b),
            "IPv6 identity");
    const char *authorities[] = {"127.1:80",
                                 "0127.0.0.1:80",
                                 "0x7f000001:80",
                                 "a@b:80",
                                 "a%2eb:80",
                                 "[::1%lo]:80",
                                 "a:0",
                                 "a:65536",
                                 "a:",
                                 "::1:80",
                                 "a..b:80",
                                 "-a:80"};
    for (size_t i = 0; i < ARRAY_SIZE(authorities); ++i)
        require(! hpsAuthority(authorities[i], stringLength(authorities[i]), true, &a), authorities[i]);
    const char *chunked = "3;foo=\"b\\\"ar\"\r\nabc\r\n2\r\nde\r\n0\r\nX-Checksum: yes\r\n\r\n";
    char        wire[256];
    stringNPrintf(wire, sizeof(wire), "%sTAIL", chunked);
    framing(wire, false, chunked);
    framing(wire, true, "abcde");
    char user[256], pass[256], key[512];
    require(hpsDecodeBasic("Basic dXNlcjpwYXNz", user, pass, key) && ! stringCompare(key, "user:pass"),
            "Basic credentials");
    const char *bad_auth[] = {"Basic dTpw=",
                              "Basic dTpw!!!!",
                              "Basic dTo=",
                              "Basic OnA=",
                              "Basic dToAcA==",
                              "Basic dTpw\n",
                              "Digest dTpw",
                              "Basic dTpxYR=="};
    for (size_t i = 0; i < ARRAY_SIZE(bad_auth); ++i)
        require(! hpsDecodeBasic(bad_auth[i], user, pass, key), bad_auth[i]);
    require(! parse("POST http://a/ HTTP/1.1\r\nHost: a\r\nConnection: X-Hop\r\nTransfer-Encoding: chunked\r\n\r\n",
                    false,
                    false,
                    &h,
                    storage),
            "chunk trailer context");
    hps_body_t body = h.body;
    size_t     used;
    bool       emit;
    require(hpsBodyStep(&body, (const unsigned char *) "0\r\n", 3, false, &h, &used, &emit) == 1, "zero chunk");
    require(hpsBodyStep(&body, (const unsigned char *) "X-Hop: hidden\r\n", 15, false, &h, &used, &emit) == -1,
            "Connection-nominated trailer escaped filtering");
    require(parse("HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\n", true, false, &h, storage) != 0,
            "205 carried content");
    require(parse("GET http://a/%zz HTTP/1.1\r\nHost: a\r\n\r\n", false, false, &h, storage) == 400,
            "malformed escaped path");
    require(! parse("OPTIONS http://a HTTP/1.1\r\nHost: a\r\nMax-Forwards: 1\r\n\r\n", false, false, &h, storage),
            "forwarded OPTIONS");
    require(hpsRewriteHeader(&h, false, false, false, rewritten, sizeof(rewritten), &n) &&
                strstr(rewritten, "OPTIONS * HTTP/1.1") && strstr(rewritten, "Max-Forwards: 0\r\n"),
            "OPTIONS target or hop count");
    stringCopy(storage, "GET http://a/ HTTP/1.1\r\nHost: a\r\n");
    for (unsigned i = 0; i < 128; ++i)
        strcat(storage, "X-Field: value\r\n");
    strcat(storage, "\r\n");
    require(hpsParseHeader(storage, stringLength(storage), false, false, &h) == 431, "field count limit");
    char huge_chunk[kHpsChunkLineLimit + 1];
    memorySet(huge_chunk, '1', sizeof(huge_chunk));
    body = (hps_body_t) {.kind = kHpsBodyChunked};
    require(hpsBodyStep(&body, (const unsigned char *) huge_chunk, sizeof(huge_chunk), false, NULL, &used, &emit) == -1,
            "chunk line limit");
    body                 = (hps_body_t) {.kind = kHpsBodyChunked};
    const char *overflow = "10000000000000000\r\n";
    require(hpsBodyStep(&body, (const unsigned char *) overflow, stringLength(overflow), false, NULL, &used, &emit) ==
                -1,
            "chunk integer overflow");
    body = (hps_body_t) {.kind = kHpsBodyChunked, .chunk_phase = 3};
    for (unsigned i = 0; i < kHpsTrailerFields; ++i)
        require(hpsBodyStep(&body, (const unsigned char *) "X: a\r\n", 6, false, NULL, &used, &emit) == 1,
                "valid trailer count");
    require(hpsBodyStep(&body, (const unsigned char *) "X: a\r\n", 6, false, NULL, &used, &emit) == -1,
            "trailer count limit");
    puts("http_proxy_server_parser: passed");
    return 0;
}
