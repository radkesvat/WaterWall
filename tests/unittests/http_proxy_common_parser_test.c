#include "HttpProxyCommon/parser.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "HTTP proxy common: %s\n", message);
        exit(1);
    }
}

static unsigned parse(const char *wire, hp_response_context_t context, hps_header_t *header)
{
    char   storage[32769];
    size_t length = stringLength(wire);
    require(length < sizeof(storage), "fixture capacity");
    memoryCopy(storage, wire, length + 1);
    return hpParseResponse(storage, length, context, header);
}

int main(void)
{
    hps_header_t header;
    const char  *framing[] = {"Content-Length: 7\r\n",
                              "Transfer-Encoding: chunked\r\n",
                              "Content-Length: 7\r\nTransfer-Encoding: chunked\r\n",
                              "Content-Length: invalid\r\nContent-Length: 99\r\nTransfer-Encoding: gzip\r\n"};
    char         wire[1024];
    for (unsigned status = 200; status < 300; ++status)
        for (size_t i = 0; i < ARRAY_SIZE(framing); ++i)
        {
            stringNPrintf(wire, sizeof(wire), "HTTP/1.1 %u Success\r\n%s\r\n", status, framing[i]);
            require(! parse(wire, kHpResponseToConnect, &header) && header.status == status &&
                        header.body.kind == kHpsBodyDone,
                    "CONNECT success interpreted framing");
        }
    require(parse("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nTransfer-Encoding: chunked\r\n\r\n",
                  kHpResponseOrdinary,
                  &header) != 0,
            "ordinary ambiguous framing accepted");
    require(parse("HTTP/1.1 407 Denied\r\nContent-Length: invalid\r\n\r\n", kHpResponseToConnect, &header) != 0,
            "CONNECT failure bypassed framing");
    require(! parse("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n", kHpResponseToHead, &header) &&
                header.body.kind == kHpsBodyDone,
            "HEAD body admitted");
    require(! parse("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n", kHpResponseOrdinary, &header) &&
                header.body.kind == kHpsBodyFixed && header.body.remaining == 999,
            "fixed body lost");
    const char *invalid[] = {"HTTP/1.0 200 OK\r\n\r\n",
                             "HTTP/2.0 200 OK\r\n\r\n",
                             "HTTP/1.1 101 Switching Protocols\r\n\r\n",
                             "HTTP/1.1 200 OK\r\nUpgrade: websocket\r\n\r\n",
                             "HTTP/1.1 200 OK\r\nContent-Length : 9\r\n\r\n",
                             "HTTP/1.1 200 OK\r\nContent-Length: 9\rInjected: yes\r\n\r\n",
                             "HTTP/1.1 200 OK\r\n Content-Length: 9\r\n\r\n"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
        for (unsigned context = kHpResponseOrdinary; context <= kHpResponseToConnect; ++context)
            require(parse(invalid[i], (hp_response_context_t) context, &header) != 0, invalid[i]);
    char legacy[] = "HTTP/1.0 200 OK\r\n\r\n";
    require(! hpsParseHeader(legacy, sizeof(legacy) - 1, true, false, &header) && header.http10,
            "server HTTP/1.0 admission changed");
    return 0;
}
