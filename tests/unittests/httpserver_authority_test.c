#include "HttpServer/structure.h"

static void expectMatch(const char *expected, const char *actual)
{
    if (! httpserverAuthorityMatchesExpectedHost(expected, actual))
    {
        fprintf(stderr,
                "expected authority match was rejected: expected=%s actual=%s\n",
                expected != NULL ? expected : "<null>",
                actual != NULL ? actual : "<null>");
        exit(1);
    }
}

static void expectMismatch(const char *expected, const char *actual)
{
    if (httpserverAuthorityMatchesExpectedHost(expected, actual))
    {
        fprintf(stderr,
                "expected authority mismatch was accepted: expected=%s actual=%s\n",
                expected != NULL ? expected : "<null>",
                actual != NULL ? actual : "<null>");
        exit(1);
    }
}

int main(void)
{
    expectMatch(NULL, NULL);
    expectMatch("", NULL);

    expectMatch("example.test", "example.test");
    expectMatch("EXAMPLE.TEST", "example.test:8443");
    expectMatch("example.test:8443", "example.test:8443");
    expectMismatch("example.test", "other.test:8443");

    expectMatch("[::1]", "[::1]");
    expectMatch("[::1]", "[::1]:8443");
    expectMatch("[2001:DB8::1]", "[2001:db8::1]:443");
    expectMatch("[::1]:8443", "[::1]:8443");
    expectMismatch("[::1]", "[::2]:8443");
    expectMismatch("[2001:0db8::1]", "[2001:db8::1]");

    expectMismatch("example.test", NULL);
    expectMismatch("[::1]", "[::1");
    expectMismatch("[::1]", "[::1]junk");
    expectMismatch("[::1]", "[::1]:");
    expectMismatch("[::1]", "[::1]:abc");
    expectMismatch("[::1]", "[::1]:65536");
    expectMismatch("example.test", "example.test:80:90");
    expectMismatch("::1", "::1:8443");

    puts("httpserver_authority_test: all cases passed");
    return 0;
}
